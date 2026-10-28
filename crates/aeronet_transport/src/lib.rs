#![cfg_attr(docsrs_aeronet, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
//!
//! ## Feature flags
#![cfg_attr(feature = "document-features", doc = document_features::document_features!())]
// we can't use plain `#![no_std]` here,
// because the `derive(arbitrary::Arbitrary)` macro breaks without `std`
// so we just have to be more careful with using `std` prelude items
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod frag;
pub mod lane;
pub mod limit;
pub mod packet;
pub mod recv;
pub mod rtt;
pub mod sampling;
pub mod send;
pub mod seq_buf;
pub mod size;

#[cfg(feature = "visualizer")]
pub mod visualizer;

pub use aeronet_io as io;
#[cfg(test)]
use typesize::TypeSize;
use {
    aeronet_io::{
        IoSystems, Session,
        connection::{DisconnectReason, Disconnected},
        packet::MtuTooSmall,
    },
    alloc::{boxed::Box, vec::Vec},
    bevy_app::prelude::*,
    bevy_ecs::{prelude::*, schedule::SystemSet},
    bevy_platform::time::Instant,
    bevy_reflect::Reflect,
    core::{num::Saturating, time::Duration},
    derive_more::{Add, AddAssign, Display, Error, Sub, SubAssign},
    lane::{LaneIndex, LaneKind},
    log::warn,
    octs::FixedEncodeLenHint,
    packet::{Acknowledge, FragmentHeader, MessageSeq, PacketHeader},
    recv::TransportRecv,
    rtt::RttEstimator,
    sampling::PacketLossHistory,
    send::TransportSend,
    seq_buf::SeqBuf,
    size::MinSize,
    typesize::derive::TypeSize,
};

/// Sets up the transport layer functionality.
///
/// See [`Transport`].
pub struct AeronetTransportPlugin;

impl Plugin for AeronetTransportPlugin {
    fn build(&self, app: &mut App) {
        app.configure_sets(PreUpdate, (IoSystems::Poll, TransportSystems::Poll).chain())
            .configure_sets(
                PostUpdate,
                (TransportSystems::Flush, IoSystems::Flush).chain(),
            )
            .add_systems(
                PreUpdate,
                (
                    recv::clear_buffers.before(TransportSystems::Poll),
                    (
                        recv::poll,
                        send::disconnect_errored,
                        send::update_send_bytes_config,
                        send::refill_send_bytes,
                        check_memory_limit,
                    )
                        .chain()
                        .in_set(TransportSystems::Poll),
                ),
            )
            .add_systems(PostUpdate, send::flush.in_set(TransportSystems::Flush));
    }
}

/// Manages sending and receiving messages on top of an IO layer.
///
/// The IO layer allows you to send and receive packets (see
/// [`aeronet_io::packet`]), but packets do not provide enough guarantees to be
/// usable for many use cases. [`Transport`] builds on top of packets, allowing
/// you to send and receive messages with more reliabiliy and ordering
/// guarantees via lanes (see [`lane`]).
///
/// # Lifecycle
///
/// After [`Session`] is added to your entity, you should create and add a
/// [`Transport`] component - use a [`On<Add, Session>`] for this. If
/// you are using a crate like `aeronet_replicon`, this step will already be
/// handled for you. You can also add or mutate [`TransportConfig`] at any
/// time during the session lifetime to change its configuration.
///
/// The [`Transport`] itself may disconnect the session prematurely if there
/// is an error such as running out of memory or buffering too many messages.
///
/// # Usage
///
/// - Use [`Transport::send`] to enqueue messages for sending, and to get a key
///   identifying the sent messages
/// - Use [`Transport::recv`]'s [`TransportRecv::msgs`] to drain messages
///   received from the IO layer
/// - Use [`Transport::recv`]'s [`TransportRecv::acks`] to drain message
///   acknowledgements for messages which you have sent out, and that the peer
///   has now acknowledged that they have received.
///
/// The `recv` buffers must be drained on every update, otherwise some may be
/// lost, leading to incorrect behavior, and a warning will be logged.
#[derive(Debug, Component, TypeSize)]
#[require(TransportConfig)]
pub struct Transport {
    // shared
    flushed_packets: SeqBuf<FlushedPacket, 1024>,
    flushed_packets_size: usize,
    packet_loss: PacketLossHistory,
    stats: MessageStats,
    peer_acks: Acknowledge,
    rtt: RttEstimator,
    /// Interface to the receiving half of this transport.
    ///
    /// Use this to read received messages and acknowledgements.
    pub recv: TransportRecv,
    /// Interface to the sending half of this transport.
    ///
    /// Use this to enqueue messages to be sent along this transport.
    pub send: TransportSend,
}

/// User-configurable properties of a [`Transport`].
///
/// If you do not provide this component explicitly, a default config will
/// be created and inserted into the [`Session`].
///
/// This component may be modified over the lifetime of a [`Session`] and the
/// [`Transport`] will be updated accordingly.
#[derive(Debug, Clone, Component, TypeSize, Reflect)]
#[reflect(Component)]
pub struct TransportConfig {
    /// Maximum amount of memory, in bytes, that this [`Transport`] may use for
    /// buffering messages until the [`Session`] is forcibly disconnected.
    ///
    /// By default, this is 4 MiB. Consider tuning this number if you see
    /// connections fail with an out-of-memory error, or you see
    /// [`Transport::memory_used`] is too high (you can use the [`visualizer`]
    /// to see real-time statistics).
    ///
    /// Before rejecting a fragment for insufficient memory, incomplete
    /// unreliable messages are evicted oldest-first until enough space is
    /// available. Reliable messages and the message being extended are
    /// protected.
    pub max_memory_usage: usize,
    /// Maximum time to retain an incomplete message on an unreliable lane,
    /// measured from its first received fragment.
    ///
    /// Expired messages are discarded during receive polling, even when no
    /// packets arrive. Duplicate fragments do not extend this deadline.
    /// Reliable messages never expire, because their acknowledged fragments
    /// may no longer be available on the sender.
    ///
    /// Zero discards incomplete unreliable messages on the next poll or packet.
    ///
    /// By default, this is 5 seconds. The total memory limit still applies.
    pub unreliable_reassembly_timeout: Duration,
    /// How many packet bytes we can flush out to the IO layer per second.
    ///
    /// This can be used to limit the outgoing bandwidth of this transport.
    ///
    /// By default, this is [`usize::MAX`].
    pub tx_bytes_per_sec: usize,
    /// Multiplier for how long it takes for an unacknowledged packet to be
    /// marked as lost on our side.
    ///
    /// Packet loss is computed by calculating how many packets, that we have
    /// sent out, should have been acknowledged by the peer by now (see
    /// [`SessionStatsSample::loss`]). "By now" is defined as
    /// [`Transport::rtt`]'s [`RttEstimator::pto`], multiplied by this config
    /// value.
    ///
    /// If this value is set too low, or below 1, the packet loss value will be
    /// an overestimate, as the peer will not have enough time to respond with
    /// an acknowledgement.
    /// If this value is set too high, the packet loss value will be an
    /// underestimate, as packets which should be reasonably considered "lost"
    /// will not be marked as such.
    ///
    /// By default, this is 1.5.
    ///
    /// [`SessionStatsSample::loss`]: crate::sampling::SessionStatsSample::loss
    pub packet_lost_threshold_factor: f64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_memory_usage: 4 * 1024 * 1024,
            unreliable_reassembly_timeout: Duration::from_secs(5),
            tx_bytes_per_sec: usize::MAX,
            packet_lost_threshold_factor: 1.5,
        }
    }
}

/// Incoming message that a [`Transport`] created from packets received by the
/// IO layer.
#[derive(Debug, TypeSize)]
pub struct RecvMessage {
    /// Lane index on which this message was received.
    pub lane: LaneIndex,
    /// Instant at which the final fragment of this message was received.
    #[typesize(with = crate::size::of_instant)]
    pub recv_at: Instant,
    /// Raw byte data of this message.
    pub payload: Vec<u8>,
}

const FRAG_OVERHEAD: usize = PacketHeader::MAX_ENCODE_LEN + FragmentHeader::MAX_ENCODE_LEN;

impl Transport {
    /// Creates a new transport from an existing [`Session`].
    ///
    /// This should be added to a [`Session`] after it has connected (after the
    /// component is added).
    ///
    /// Also see [`TransportConfig`] for configuration options.
    ///
    /// # Errors
    ///
    /// Errors if the [`Session::min_mtu`] is too small to support messages.
    ///
    /// Since messages take some overhead on the wire (fragmentation, acks,
    /// etc.), packets must be larger than some minimum size to support this.
    ///
    /// # Examples
    ///
    /// ```
    /// use {
    ///     aeronet_io::Session,
    ///     aeronet_transport::{Transport, lane::LaneKind},
    ///     bevy_ecs::prelude::*,
    ///     bevy_platform::time::Instant,
    ///     log::warn,
    /// };
    ///
    /// const LANES: [LaneKind; 1] = [LaneKind::ReliableOrdered];
    ///
    /// fn on_connected(trigger: On<Add, Session>, sessions: Query<&Session>, mut commands: Commands) {
    ///     let entity = trigger.event_target();
    ///     let session = sessions
    ///         .get(entity)
    ///         .expect("we are adding this component to this entity");
    ///     let Ok(transport) = Transport::new(session, LANES, LANES, Instant::now()) else {
    ///         warn!("Failed to create transport for {entity}");
    ///         return;
    ///     };
    ///     commands.entity(entity).insert(transport);
    /// }
    /// ```
    pub fn new(
        session: &Session,
        recv_lanes: impl IntoIterator<Item = LaneKind>,
        send_lanes: impl IntoIterator<Item = LaneKind>,
        now: Instant,
    ) -> Result<Self, MtuTooSmall> {
        let min_mtu = session.min_mtu();
        let max_frag_len = min_mtu
            .checked_sub(FRAG_OVERHEAD)
            .filter(|&len| len > 0)
            .ok_or(MtuTooSmall {
                mtu: min_mtu,
                min: FRAG_OVERHEAD + 1,
            })?;
        let max_frag_len = MinSize::MAX.min_of(max_frag_len);
        Ok(Self {
            flushed_packets: SeqBuf::new_from_fn(|_| FlushedPacket::new(now)),
            flushed_packets_size: 0,
            packet_loss: PacketLossHistory::new(now),
            stats: MessageStats::default(),
            peer_acks: Acknowledge::default(),
            rtt: RttEstimator::default(),
            recv: TransportRecv::new(recv_lanes),
            send: TransportSend::new(max_frag_len, send_lanes),
        })
    }

    /// Gets the total stats gathered up to now.
    #[must_use]
    pub const fn stats(&self) -> MessageStats {
        MessageStats {
            msgs_sent: self.send.msgs_sent,
            ..self.stats
        }
    }

    /// Gets access to the RTT estimator, allowing you to read the current RTT
    /// estimates.
    #[must_use]
    pub const fn rtt(&self) -> &RttEstimator {
        &self.rtt
    }

    /// Gets the number of packets that have been flushed out to the peer, but
    /// we have not received an acknowledgement from the peer for them yet.
    #[must_use]
    pub const fn num_unacked_packets(&self) -> usize {
        self.flushed_packets.len()
    }

    /// Gets how many total bytes of memory this transport is using.
    ///
    /// This is a constant-time estimate, including reserved collection
    /// capacity, fragment metadata and buffered payloads. It is not an exact
    /// allocator measurement (shared outgoing byte allocations may be counted
    /// more than once). Unlike upstream 0.22, unused capacity still counts
    /// toward [`TransportConfig::max_memory_usage`].
    #[must_use]
    #[cfg_attr(
        test,
        expect(
            clippy::missing_panics_doc,
            reason = "only tests assert the allocation cache invariant"
        )
    )]
    pub fn memory_used(&self) -> usize {
        let used = size_of::<Self>()
            + 1024 * (size_of::<u16>() + size_of::<FlushedPacket>())
            + self.flushed_packets_size
            + PacketLossHistory::EXTRA_SIZE
            + self.send.extra_memory_used()
            + self.recv.extra_memory_used();
        #[cfg(test)]
        assert_eq!(
            used,
            self.get_size(),
            "cached allocations differ from the recursive size estimate"
        );
        used
    }

    fn record_flushed_packet(&mut self, seq: packet::PacketSeq, packet: FlushedPacket) {
        let size = packet.extra_memory_used();
        let replaced = self.flushed_packets.replace(seq.0.0, packet);
        size::replace_cached(
            &mut self.flushed_packets_size,
            replaced.extra_memory_used(),
            size,
        );
    }
}

/// System set for scheduling transport layer systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, SystemSet)]
pub enum TransportSystems {
    /// Draining packets from the IO layer and reading out messages; updating
    /// the internal transport state.
    ///
    /// # Ordering
    ///
    /// - [`IoSystems::Poll`]
    /// - **[`TransportSystems::Poll`]**
    Poll,
    /// Draining messages and turning them into packets for the IO layer.
    ///
    /// # Ordering
    ///
    /// - **[`TransportSystems::Flush`]**
    /// - [`IoSystems::Flush`]
    Flush,
}

/// Key which pseudo-uniquely identifies a message that has been sent out via
/// [`TransportSend::push`] on this [`Transport`].
///
/// After pushing a message to the transport, you can use the output of
/// [`TransportRecv::acks`] to read what messages have received acknowledgement
/// from the peer. If you see the same message key that you got from
/// [`TransportSend::push`], that message was acknowledged.
///
/// # Uniqueness
///
/// This key is only unique for a certain period of time, which depends on how
/// quickly you send out messages. Internally, this uses [`Seq`] to track the
/// sequence number of messages, but this can and will overflow eventually as
/// long as you keep sending out messages. Therefore, you should not keep
/// message keys around for a long time. As soon as you receive an ack for a
/// message (or don't receive an ack in a certain period of time), drop the
/// key - it's very likely to have the same key as another message later.
///
/// [`Seq`]: packet::Seq
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TypeSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MessageKey {
    /// Lane index on which the message was sent.
    pub lane: LaneIndex,
    /// Message sequence number.
    pub seq: MessageSeq,
}

/// Statistics for a [`Transport`].
#[derive(Debug, Clone, Copy, Default, TypeSize)] // force `#[derive]` on multiple lines
#[derive(Add, AddAssign, Sub, SubAssign)]
pub struct MessageStats {
    /// Number of messages received into [`TransportRecv::msgs`].
    pub msgs_recv: Saturating<usize>,
    /// Number of messages successfully enqueued via [`TransportSend::push`].
    pub msgs_sent: Saturating<usize>,
    /// Number of packet acknowledgements received.
    pub packet_acks_recv: Saturating<usize>,
    /// Number of message acknowledgements received into
    /// [`TransportRecv::acks`].
    pub msg_acks_recv: Saturating<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TypeSize)]
struct FragmentPath {
    lane_index: LaneIndex,
    msg_seq: MessageSeq,
    frag_index: MinSize,
}

#[derive(Debug, Clone, TypeSize)]
struct FlushedPacket {
    #[typesize(with = crate::size::of_instant)]
    flushed_at: Instant,
    frags: Box<[FragmentPath]>,
}

impl FlushedPacket {
    fn extra_memory_used(&self) -> usize {
        self.frags.len() * size_of::<FragmentPath>()
    }

    fn new(flushed_at: Instant) -> Self {
        Self {
            flushed_at,
            frags: Box::new([]),
        }
    }
}

/// Error in [`DisconnectReason::ByError`] triggered on a [`Session`] when a
/// [`Transport`] exceeds its memory usage limit.
#[derive(Debug, Clone, Display, Error)]
#[display("memory limit exceeded - {used} / {max} bytes")]
pub struct MemoryLimitExceeded {
    /// Number of bytes used.
    pub used: usize,
    /// Maximum number of bytes the transport is allowed to use.
    pub max: usize,
}

fn check_memory_limit(
    mut commands: Commands,
    sessions: Query<(Entity, &Transport, &TransportConfig)>,
) {
    for (entity, transport, config) in &sessions {
        let mem_used = transport.memory_used();
        let mem_max = config.max_memory_usage;
        if mem_used > mem_max {
            warn!("{entity} exceeded memory limit, disconnecting");
            commands.trigger(Disconnected {
                entity,
                reason: DisconnectReason::by_error(MemoryLimitExceeded {
                    used: mem_used,
                    max: mem_max,
                }),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        octs::{Bytes, Read},
    };

    fn checked_flush(transport: &mut Transport, now: Instant, mtu: usize) -> Vec<Bytes> {
        let packets = send::flush_on(transport, now, mtu).collect();
        assert_eq!(transport.memory_used(), transport.get_size());
        packets
    }

    fn checked_recv(transport: &mut Transport, now: Instant, packet: &[u8]) {
        recv::recv_on(transport, &TransportConfig::default(), now, packet).unwrap();
        assert_eq!(transport.memory_used(), transport.get_size());
    }

    #[test]
    fn cached_memory_and_stats_track_reordered_delivery_and_duplicate_acks() {
        let now = Instant::now();
        let mtu = 64;
        let lane = LaneIndex::new(0);
        for kind in [LaneKind::ReliableOrdered, LaneKind::ReliableUnordered] {
            let session = Session::new(now, mtu);
            let mut sender = Transport::new(&session, [kind], [kind], now).unwrap();
            let mut receiver = Transport::new(&session, [kind], [kind], now).unwrap();
            let payloads = [
                Bytes::from(vec![7; 300]),
                Bytes::new(),
                Bytes::from_static(b"last"),
            ];
            for payload in &payloads {
                sender.send.push(lane, payload.clone(), now).unwrap();
                assert_eq!(sender.memory_used(), sender.get_size());
            }
            assert_eq!(sender.stats().msgs_sent.0, payloads.len());
            for packet in checked_flush(&mut sender, now, mtu).iter().rev() {
                checked_recv(&mut receiver, now, packet);
                checked_recv(&mut receiver, now, packet);
            }
            assert_eq!(receiver.stats().msgs_recv.0, payloads.len());
            let mut received = receiver
                .recv
                .msgs
                .drain()
                .map(|msg| msg.payload)
                .collect::<Vec<_>>();
            if kind == LaneKind::ReliableOrdered {
                assert_eq!(
                    received,
                    payloads
                        .iter()
                        .map(|bytes| bytes.to_vec())
                        .collect::<Vec<_>>()
                );
            }
            received.sort();
            let mut expected = payloads
                .iter()
                .map(|bytes| bytes.to_vec())
                .collect::<Vec<_>>();
            expected.sort();
            assert_eq!(received, expected);
            assert_eq!(receiver.memory_used(), receiver.get_size());

            // Keep both original and retransmitted packet metadata alive, then
            // acknowledge the same completed messages through different
            // packets.
            let later = now + sender.rtt.pto();
            let retries = checked_flush(&mut sender, later, mtu);
            for packet in checked_flush(&mut receiver, later, mtu) {
                checked_recv(&mut sender, later, &packet);
            }
            assert_eq!(sender.stats().msg_acks_recv.0, payloads.len());
            assert_eq!(sender.recv.acks.drain().count(), payloads.len());
            for packet in retries {
                checked_recv(&mut receiver, later, &packet);
            }
            assert_eq!(receiver.recv.msgs.drain().count(), 0);
            for packet in checked_flush(&mut receiver, later, mtu) {
                checked_recv(&mut sender, later, &packet);
                checked_recv(&mut sender, later, &packet);
            }
            assert_eq!(sender.stats().msg_acks_recv.0, payloads.len());
            assert_eq!(sender.recv.acks.drain().count(), 0);
            assert_eq!(receiver.stats().msgs_recv.0, payloads.len());
            checked_flush(&mut sender, later, mtu);
            assert_eq!(sender.send.lanes()[0].num_queued_msgs(), 0);
            assert_eq!(sender.memory_used(), sender.get_size());
        }
    }

    #[test]
    fn cached_memory_retires_unreliable_payloads_and_overwritten_packets() {
        let now = Instant::now();
        let session = Session::new(now, 64);
        let lanes = [LaneKind::UnreliableUnordered];
        let mut transport = Transport::new(&session, lanes, lanes, now).unwrap();
        let initial = transport.memory_used();
        let mut full_window_size = 0;
        for index in 0..1100 {
            transport
                .send
                .push(LaneIndex::new(0), Bytes::from_static(b"payload"), now)
                .unwrap();
            assert_eq!(transport.memory_used(), transport.get_size());
            checked_flush(&mut transport, now, 64);
            if index == 1023 {
                full_window_size = transport.memory_used();
            } else if index > 1023 {
                assert_eq!(transport.memory_used(), full_window_size);
            }
        }
        assert!(full_window_size > initial);
        assert_eq!(transport.stats().msgs_sent.0, 1100);
        checked_flush(&mut transport, now, 64);
        assert!(transport.memory_used() < full_window_size);
        assert_eq!(transport.send.lanes()[0].num_queued_msgs(), 0);
    }

    #[test]
    fn cached_memory_survives_partial_drain_and_cross_lane_buffer_clear() {
        let now = Instant::now();
        let session = Session::new(now, 128);
        let lanes = [
            LaneKind::UnreliableUnordered,
            LaneKind::UnreliableSequenced,
            LaneKind::ReliableUnordered,
            LaneKind::ReliableOrdered,
        ];
        let mut sender = Transport::new(&session, lanes, lanes, now).unwrap();
        let mut receiver = Transport::new(&session, lanes, lanes, now).unwrap();
        for lane in 0..4 {
            sender
                .send
                .push(LaneIndex::new(lane), Bytes::from(vec![1; 200]), now)
                .unwrap();
        }
        for packet in checked_flush(&mut sender, now, 128) {
            checked_recv(&mut receiver, now, &packet);
        }
        assert_eq!(
            receiver.recv.msgs.drain().next().unwrap().payload.len(),
            200
        );
        assert_eq!(receiver.memory_used(), receiver.get_size());
        // Dropping a partially consumed drain retires all remaining payloads.
        assert_eq!(receiver.recv.msgs.drain().count(), 0);
        for lane in 0..4 {
            sender
                .send
                .push(LaneIndex::new(lane), Bytes::from(vec![2; 200]), now)
                .unwrap();
        }
        for packet in checked_flush(&mut sender, now, 128) {
            checked_recv(&mut receiver, now, &packet);
        }
        let before = receiver.memory_used();
        let mut app = App::new();
        app.add_systems(PreUpdate, recv::clear_buffers);
        let entity = app.world_mut().spawn(receiver).id();
        app.update();
        let receiver = app.world().get::<Transport>(entity).unwrap();
        assert!(receiver.memory_used() < before);
        assert_eq!(receiver.memory_used(), receiver.get_size());
        assert_eq!(receiver.stats().msgs_recv.0, 8);
    }

    #[test]
    fn extreme_rtt_retries_without_overflow() {
        let now = Instant::now();
        let session = Session::new(now, 64);
        let lanes = [LaneKind::ReliableOrdered];
        let mut transport = Transport::new(&session, lanes, lanes, now).unwrap();
        transport.rtt = RttEstimator::new(Duration::MAX);
        transport
            .send
            .push(LaneIndex::new(0), Bytes::from_static(b"payload"), now)
            .unwrap();
        for _ in 0..2 {
            let mut packet = checked_flush(&mut transport, now, 64).pop().unwrap();
            packet.read::<PacketHeader>().unwrap();
            packet.read::<packet::Fragment>().unwrap();
        }
        assert_eq!(transport.stats().msgs_sent.0, 1);
        assert_eq!(transport.memory_used(), transport.get_size());
    }

    #[test]
    fn new_requires_space_for_fragment_payload() {
        let now = Instant::now();
        let lanes = [LaneKind::ReliableOrdered];

        for mtu in [FRAG_OVERHEAD, FRAG_OVERHEAD - 1, 0] {
            let session = Session::new(now, mtu);
            let Err(err) = Transport::new(&session, lanes, lanes, now) else {
                panic!("MTU {mtu} leaves no room for a fragment payload");
            };
            assert_eq!(err.mtu, mtu);
            assert_eq!(err.min, FRAG_OVERHEAD + 1);
        }

        let session = Session::new(now, FRAG_OVERHEAD + 1);
        let mut transport = Transport::new(&session, lanes, lanes, now).unwrap();
        transport
            .send
            .push(LaneIndex::new(0), octs::Bytes::from_static(b"x"), now)
            .unwrap();
    }
}
