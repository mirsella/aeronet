//! Receiving logic for [`Transport`]s.

use {
    crate::{
        FlushedPacket, MessageKey, RecvMessage, Transport, TransportConfig,
        frag::{FragmentReceiver, ReassembleError},
        lane::{LaneIndex, LaneKind, LaneReliability},
        packet::{Fragment, MessageSeq, PacketHeader, PacketSeq},
        rtt::RttEstimator,
        send::SendLane,
        seq_buf::SeqBuf,
    },
    aeronet_io::{
        Session,
        connection::{DisconnectReason, Disconnected},
    },
    alloc::{boxed::Box, vec::Vec},
    bevy_ecs::prelude::*,
    bevy_platform::{
        collections::{HashMap, HashSet},
        time::Instant,
    },
    core::{iter, num::Saturating, time::Duration},
    derive_more::{Display, Error},
    either::Either,
    log::{trace, warn},
    octs::{Buf, Read},
    typesize::{TypeSize, derive::TypeSize},
};

/// Access to the receiving half of a [`Transport`].
#[derive(Debug, TypeSize)]
pub struct TransportRecv {
    lanes: Box<[RecvLane]>,
    error: Option<RecvError>,
    /// Buffer of received messages.
    ///
    /// This must be drained by the user on every update.
    pub msgs: RecvBuffer<RecvMessage>,
    /// Buffer of received message acknowledgements for messages previously
    /// sent via [`TransportSend::push`].
    ///
    /// This must be drained by the user on every update.
    ///
    /// [`TransportSend::push`]: crate::send::TransportSend::push
    pub acks: RecvBuffer<MessageKey>,
}

/// Buffer storing data received by a [`Transport`].
///
/// This is effectively a wrapper around [`Vec`] which only publicly allows
/// draining elements from it.
#[derive(Debug, TypeSize)]
pub struct RecvBuffer<T: TypeSize>(Vec<T>);

impl TransportRecv {
    pub(crate) fn new(lanes: impl IntoIterator<Item = impl Into<LaneKind>>) -> Self {
        Self {
            lanes: lanes
                .into_iter()
                .map(Into::into)
                .map(RecvLane::new)
                .collect(),
            error: None,
            msgs: RecvBuffer(Vec::new()),
            acks: RecvBuffer(Vec::new()),
        }
    }

    /// Gets access to the state of the receiving-side lanes.
    #[must_use]
    pub const fn lanes(&self) -> &[RecvLane] {
        &self.lanes
    }

    fn expire_unreliable(&mut self, now: Instant, timeout: Duration) {
        for lane in &mut self.lanes {
            if lane.kind().reliability() == LaneReliability::Unreliable {
                lane.frags.expire(now, timeout);
            }
        }
    }
}

impl<T: TypeSize> RecvBuffer<T> {
    /// Drains all items from this buffer.
    pub fn drain(&mut self) -> impl Iterator<Item = T> + '_ {
        self.0.drain(..)
    }
}

/// State of a lane used for receiving incoming messages on a [`Transport`].
#[derive(Debug, Clone, TypeSize)]
pub struct RecvLane {
    frags: FragmentReceiver,
    state: LaneState,
}

#[derive(Debug, Clone, TypeSize)]
enum LaneState {
    UnreliableUnordered,
    UnreliableSequenced {
        pending: MessageSeq,
    },
    ReliableUnordered {
        pending: MessageSeq,
        #[typesize(with = crate::size::of_set)]
        recv_buf: HashSet<MessageSeq>,
    },
    ReliableOrdered {
        pending: MessageSeq,
        #[typesize(with = crate::size::of_map)]
        recv_buf: HashMap<MessageSeq, Vec<u8>>,
    },
}

impl LaneState {
    fn has_received(&self, seq: MessageSeq) -> bool {
        match self {
            Self::UnreliableUnordered => false,
            Self::UnreliableSequenced { pending } => seq < *pending,
            Self::ReliableUnordered { pending, recv_buf } => {
                seq < *pending || recv_buf.contains(&seq)
            }
            Self::ReliableOrdered { pending, recv_buf } => {
                seq < *pending || recv_buf.contains_key(&seq)
            }
        }
    }
}

impl RecvLane {
    fn new(kind: LaneKind) -> Self {
        Self {
            frags: FragmentReceiver::default(),
            state: match kind {
                LaneKind::UnreliableUnordered => LaneState::UnreliableUnordered,
                LaneKind::UnreliableSequenced => LaneState::UnreliableSequenced {
                    pending: MessageSeq::default(),
                },
                LaneKind::ReliableUnordered => LaneState::ReliableUnordered {
                    pending: MessageSeq::default(),
                    recv_buf: HashSet::default(),
                },
                LaneKind::ReliableOrdered => LaneState::ReliableOrdered {
                    pending: MessageSeq::default(),
                    recv_buf: HashMap::default(),
                },
            },
        }
    }

    /// Gets what kind of lane this state represents.
    #[must_use]
    pub const fn kind(&self) -> LaneKind {
        match self.state {
            LaneState::UnreliableUnordered => LaneKind::UnreliableUnordered,
            LaneState::UnreliableSequenced { .. } => LaneKind::UnreliableSequenced,
            LaneState::ReliableUnordered { .. } => LaneKind::ReliableUnordered,
            LaneState::ReliableOrdered { .. } => LaneKind::ReliableOrdered,
        }
    }

    /// Gets the number of messages which are currently being reassembled on
    /// this lane, but have not been fully reassembled yet.
    #[must_use]
    pub fn num_reassembling_msgs(&self) -> usize {
        self.frags.len()
    }

    /// Gets the number of messages which have been received and fully
    /// reassembled, but have not been forwarded to the user yet because some
    /// previous message has not been received yet.
    #[must_use]
    pub fn num_unordered_msgs(&self) -> usize {
        match &self.state {
            LaneState::UnreliableUnordered | LaneState::UnreliableSequenced { .. } => 0,
            LaneState::ReliableUnordered { recv_buf, .. } => recv_buf.len(),
            LaneState::ReliableOrdered { recv_buf, .. } => recv_buf.len(),
        }
    }
}

/// Clears all [`TransportRecv::msgs`] and [`TransportRecv::acks`] buffers,
/// emitting warnings if there were any items left in the buffers.
///
/// The equivalent for [`Transport::send`] does not exist, because the transport
/// layer itself is responsible for draining that buffer.
pub fn clear_buffers(mut sessions: Query<(Entity, &mut Transport)>) {
    for (entity, mut transport) in &mut sessions {
        let len = transport.recv.msgs.0.len();
        if len > 0 {
            warn!(
                "{entity} has {len} received messages which have not been consumed - this \
                 indicates a bug in code above the transport layer"
            );
            transport.recv.msgs.0.clear();
        }

        let len = transport.recv.acks.0.len();
        if len > 0 {
            warn!(
                "{entity} has {len} received acks which have not been consumed - this indicates a \
                 bug in code above the transport layer"
            );
            transport.recv.acks.0.clear();
        }
    }
}

pub(crate) fn poll(
    mut commands: Commands,
    mut sessions: Query<(Entity, &mut Session, &mut Transport, &TransportConfig)>,
) {
    for (entity, mut session, mut transport, config) in &mut sessions {
        for packet in session.recv.drain(..) {
            if recv_on(&mut transport, config, packet.recv_at, &packet.payload).is_err() {
                // Dropping the drain also discards the remaining packets. No
                // more state may be committed after a terminal receive error.
                break;
            }
        }
        transport
            .recv
            .expire_unreliable(Instant::now(), config.unreliable_reassembly_timeout);
        if let Some(err) = &transport.recv.error {
            warn!("{entity} failed to receive packet, disconnecting: {err:?}");
            commands.trigger(Disconnected {
                entity,
                reason: DisconnectReason::by_error(err.clone()),
            });
        }
    }
}

/// Why a packet could not be received by a [`Transport`].
#[derive(Debug, Clone, Display, Error, TypeSize)]
pub enum RecvError {
    /// Packet was too short to contain a packet header.
    #[display("not enough bytes to read header")]
    ReadHeader,
    /// Packet contained an incomplete or invalid fragment.
    #[display("failed to decode fragment")]
    ReadFragment,
    /// Packet specified that it is a message on a lane that we don't have.
    #[display("invalid lane {lane:?}")]
    InvalidLane {
        /// Lane that the message claims it was sent on.
        lane: LaneIndex,
    },
    /// Failed to reassemble the packet's fragments into a message.
    #[display("failed to reassemble fragment: {_0}")]
    Reassemble(ReassembleError),
}

/// Forces a [`Transport`] to receive a packet, attempting to decode it into a
/// message and buffer it.
///
/// This function is advanced and has the potential to screw up the transport
/// state - only use it if you know what you're doing!
///
/// Every update, for all [`Session`] with an associated [`Transport`], the
/// session's buffered received packets are passed to this function along with
/// the paired transport.
///
/// # Errors
///
/// Errors if the packet could not be received, decoded, and made available to
/// the transport. Errors are fatal: the transport will be disconnected during
/// receive polling, including when this function is called outside the plugin.
/// Subsequent calls return the original error without processing more packets.
///
/// A failed packet is not acknowledged, but preceding fragments and peer
/// acknowledgements may already have been committed. Do not retry a failed
/// transport; discard it or let the plugin disconnect it. Harmless duplicate
/// fragments and messages succeed and are acknowledged normally.
pub fn recv_on(
    transport: &mut Transport,
    config: &TransportConfig,
    recv_at: Instant,
    packet: &[u8],
) -> Result<(), RecvError> {
    if let Some(err) = &transport.recv.error {
        return Err(err.clone());
    }

    let result = recv_packet(transport, config, recv_at, packet);
    if let Err(err) = &result {
        transport.recv.error = Some(err.clone());
    }
    result
}

fn recv_packet(
    transport: &mut Transport,
    config: &TransportConfig,
    recv_at: Instant,
    mut packet: &[u8],
) -> Result<(), RecvError> {
    trace!("Receiving packet of length {}", packet.len());

    transport
        .recv
        .expire_unreliable(recv_at, config.unreliable_reassembly_timeout);

    let header = packet
        .read::<PacketHeader>()
        .map_err(|_| RecvError::ReadHeader)?;

    trace!(
        "Received packet header with sequence {} ({} bytes left)",
        header.seq.0.0,
        packet.len()
    );

    transport.recv.acks.0.extend(packet_acks_to_msg_keys(
        &mut transport.flushed_packets,
        &mut transport.send.lanes,
        &mut transport.rtt,
        &mut transport.stats.packet_acks_recv,
        &mut transport.stats.msg_acks_recv,
        recv_at,
        header.acks.seqs(),
    ));

    let mut frag_index = Saturating(0);
    let mut frags_recv = Saturating(0);
    while packet.has_remaining() {
        match recv_frag(transport, config, recv_at, &mut packet) {
            Ok(()) => {
                frags_recv += 1;
                trace!(
                    "Successfully received fragment {} ({} bytes left)",
                    frag_index.0,
                    packet.len()
                );
            }
            Err(err) => {
                trace!(
                    "Failed to receive fragment {} in packet {}: {err:?}",
                    frag_index.0, header.seq.0.0,
                );
                return Err(err);
            }
        }
        frag_index += 1;
    }

    trace!(
        "Finished receiving packet; successfully received {} of {} fragments",
        frags_recv.0, frag_index.0
    );

    // An ACK retires every reliable fragment in this packet on the sender.
    // Only acknowledge after all fragments have been accepted or deduplicated.
    transport.peer_acks.ack(header.seq);
    Ok(())
}

fn packet_acks_to_msg_keys<'s, const N: usize>(
    flushed_packets: &'s mut SeqBuf<FlushedPacket, N>,
    tx_lanes: &'s mut [SendLane],
    rtt: &'s mut RttEstimator,
    packet_acks_recv: &'s mut Saturating<usize>,
    msgs_acks_recv: &'s mut Saturating<usize>,
    recv_at: Instant,
    acked_seqs: impl Iterator<Item = PacketSeq> + 's,
) -> impl Iterator<Item = MessageKey> + 's {
    acked_seqs
        // we now know that our packet with sequence `seq` was acked by the peer
        // let's find what fragments that packet contained when we flushed it out
        .filter_map(move |acked_seq| {
            flushed_packets
                .remove_with(acked_seq.0 .0, FlushedPacket::new(recv_at))
                .map(|packet| (acked_seq, packet))
        })
        .flat_map(move |(acked_seq, packet)| {
            let packet_rtt = recv_at.saturating_duration_since(packet.flushed_at);
            rtt.update(packet_rtt);

            let rtt_now = rtt.get();
            trace!("Got peer ack for packet {} - packet RTT: {packet_rtt:?} / RTT now: {rtt_now:?}", acked_seq.0.0);

            *packet_acks_recv += 1;
            Box::into_iter(packet.frags)
        })
        .filter_map(|frag_path| {
            // for each of those fragments, we'll mark that fragment as acked
            let lane_index = usize::from(frag_path.lane_index.0);
            let lane = tx_lanes
                .get_mut(lane_index)
                .expect("frag path should point into a valid lane index");
            // fallible instead of panicking, because these messages may have already been
            // removed by a previous ack that we received
            let msg = lane.sent_msgs.get_mut(&frag_path.msg_seq)?;
            let frag_opt = msg.frags.get_mut(usize::from(frag_path.frag_index))?;
            // take this fragment out so it stops being resent
            *frag_opt = None;

            // if all the fragments are now acked, then we report that
            // the entire message is now acked
            if msg.frags.iter().all(Option::is_none) {
                *msgs_acks_recv += 1;
                Some(MessageKey {
                    lane: frag_path.lane_index,
                    seq: frag_path.msg_seq
                })
            } else {
                None
            }
        })
}

fn recv_frag(
    transport: &mut Transport,
    config: &TransportConfig,
    recv_at: Instant,
    packet: &mut &[u8],
) -> Result<(), RecvError> {
    let frag = packet
        .read::<Fragment>()
        .map_err(|_| RecvError::ReadFragment)?;
    let lane_index = frag.header.lane;

    let memory_left = config
        .max_memory_usage
        .saturating_sub(transport.memory_used());
    let lane = transport
        .recv
        .lanes
        .get_mut(usize::from(lane_index.0))
        .ok_or(RecvError::InvalidLane { lane: lane_index })?;
    // Check before reassembly, otherwise a late subset of an already completed
    // message would allocate a new buffer which can never complete.
    if lane.state.has_received(frag.header.seq) {
        return Ok(());
    }

    trace!(
        "Receiving fragment on lane {} - message seq {} position {:?}",
        lane_index.0.0, frag.header.seq.0.0, frag.header.position,
    );

    let msg = match lane.frags.reassemble_with_time(
        transport.send.max_frag_len,
        memory_left,
        frag.header.seq,
        frag.header.position,
        &frag.payload,
        Some(recv_at),
    ) {
        Ok(msg) => msg,
        Err(ReassembleError::AlreadyReceivedFrag { .. }) => return Ok(()),
        Err(err) => return Err(RecvError::Reassemble(err)),
    };

    if let Some(msg) = msg {
        let msgs_with_lane =
            recv_on_lane(&mut lane.state, msg, frag.header.seq).map(|msg| RecvMessage {
                lane: lane_index,
                recv_at,
                payload: msg,
            });
        transport.recv.msgs.0.extend(msgs_with_lane);
        trace!("Fragment finished reassembling this message");
    }

    Ok(())
}

fn recv_on_lane(
    lane: &mut LaneState,
    msg: Vec<u8>,
    msg_seq: MessageSeq,
) -> impl Iterator<Item = Vec<u8>> + '_ {
    match lane {
        LaneState::UnreliableUnordered => {
            // always just return the message
            Either::Left(Some(msg))
        }
        LaneState::UnreliableSequenced { pending } => {
            if msg_seq < *pending {
                // msg is older than the message we're expecting to get next,
                // drop it
                Either::Left(None)
            } else {
                // msg is the one we're expecting to get or newer, return it
                *pending = msg_seq + MessageSeq::new(1);
                Either::Left(Some(msg))
            }
        }
        LaneState::ReliableUnordered { pending, recv_buf } => {
            if msg_seq < *pending || !recv_buf.insert(msg_seq) {
                // msg is guaranteed to already be received, drop it
                Either::Left(None)
            } else {
                // here's an example to visualize what this does:
                // msg_seq: 40
                // before insertion: pending_seq: 40, recv_buf: [41, 45]
                // pending_seq: 40, recv_buf: [40, 41, 45]
                while recv_buf.remove(pending) {
                    *pending += MessageSeq::new(1);
                    // iter 1: pending_seq: 41, recv_buf: [41, 45]
                    // iter 2: pending_seq: 42, recv_buf: [45]
                }
                Either::Left(Some(msg))
            }
        }
        LaneState::ReliableOrdered { pending, recv_buf } => {
            if msg_seq < *pending {
                // msg is guaranteed to already be received, drop it
                Either::Left(None)
            } else {
                // almost identical to above, but we also return the
                // messages that we remove
                recv_buf.insert(msg_seq, msg);
                Either::Right(iter::from_fn(move || {
                    let msg = recv_buf.remove(pending)?;
                    *pending += MessageSeq::new(1);
                    Some(msg)
                }))
            }
        }
    }
    .into_iter()
}

#[cfg(test)]
mod tests {
    use {
        super::{LaneState, RecvError, recv_on, recv_on_lane},
        crate::{
            AeronetTransportPlugin, Transport, TransportConfig, TransportSystems,
            frag::ReassembleError,
            lane::{LaneIndex, LaneKind},
            packet::{
                Acknowledge, Fragment, FragmentHeader, FragmentPayload, FragmentPosition,
                MessageSeq, PacketHeader, PacketSeq,
            },
            send::flush_on,
        },
        aeronet_io::{
            AeronetIoPlugin, Session,
            connection::{DisconnectReason, Disconnected},
            packet::{NoClearBuffers, RecvPacket},
        },
        alloc::{vec, vec::Vec},
        bevy_app::{App, PreUpdate},
        bevy_ecs::prelude::*,
        bevy_platform::{collections::HashSet, time::Instant},
        bevy_time::TimePlugin,
        core::time::Duration,
        octs::{Bytes, Write},
    };

    const LANES: [LaneKind; 1] = [LaneKind::ReliableOrdered];
    const LANE: LaneIndex = LaneIndex::new(0);

    fn transport(kind: LaneKind, now: Instant, mtu: usize) -> Transport {
        Transport::new(&Session::new(now, mtu), [kind], [kind], now).unwrap()
    }

    fn fragment(seq: u16, position: FragmentPosition, payload: &[u8]) -> Fragment {
        Fragment {
            header: FragmentHeader {
                lane: LANE,
                seq: MessageSeq::new(seq),
                position,
            },
            payload: FragmentPayload::new(Bytes::copy_from_slice(payload)).unwrap(),
        }
    }

    fn packet(seq: u16, frags: impl IntoIterator<Item = Fragment>) -> Vec<u8> {
        let mut packet = Vec::new();
        packet
            .write(&PacketHeader {
                seq: PacketSeq::new(seq),
                acks: Acknowledge::default(),
            })
            .unwrap();
        for frag in frags {
            packet.write(&frag).unwrap();
        }
        packet
    }

    #[test]
    fn reliable_reassembly_failure_is_terminal_and_not_acked() {
        let now = Instant::now();
        for kind in [LaneKind::ReliableOrdered, LaneKind::ReliableUnordered] {
            let mut sender = transport(kind, now, 1024);
            let mut receiver = transport(kind, now, 1024);
            let key = sender
                .send
                .push(LANE, Bytes::from_static(b"reliable"), now)
                .unwrap();
            let packets = flush_on(&mut sender, now, 1024).collect::<Vec<_>>();
            let mut config = TransportConfig {
                max_memory_usage: receiver.memory_used(),
                ..TransportConfig::default()
            };

            assert!(matches!(
                recv_on(&mut receiver, &config, now, &packets[0]),
                Err(RecvError::Reassemble(ReassembleError::OutOfMemory { .. }))
            ));
            assert!(!receiver.peer_acks.is_acked(PacketSeq::new(0)));
            assert_eq!(receiver.recv.lanes[0].num_reassembling_msgs(), 0);

            // Even if an advanced caller flushes the failed receiver, the
            // sender retains the rejected fragment instead of
            // considering it delivered.
            for ack in flush_on(&mut receiver, now, 1024) {
                recv_on(&mut sender, &TransportConfig::default(), now, &ack).unwrap();
            }
            assert!(
                sender.send.lanes[0].sent_msgs[&key.seq]
                    .frags
                    .iter()
                    .all(Option::is_some)
            );
            assert_eq!(sender.recv.acks.drain().count(), 0);

            config.max_memory_usage = usize::MAX;
            assert!(matches!(
                recv_on(&mut receiver, &config, now, &packets[0]),
                Err(RecvError::Reassemble(ReassembleError::OutOfMemory { .. }))
            ));
            assert!(!receiver.peer_acks.is_acked(PacketSeq::new(0)));
            assert_eq!(receiver.recv.msgs.drain().count(), 0);
        }
    }

    #[test]
    fn partial_packet_failure_stops_receiving_without_acknowledging() {
        let now = Instant::now();
        let mut transport = transport(LaneKind::ReliableOrdered, now, 1024);
        let config = TransportConfig::default();
        let mut partial = packet(0, [fragment(0, FragmentPosition::ZERO_LAST, b"first")]);
        partial.push(0); // truncated second fragment header

        assert!(matches!(
            recv_on(&mut transport, &config, now, &partial),
            Err(RecvError::ReadFragment)
        ));
        assert!(!transport.peer_acks.is_acked(PacketSeq::new(0)));
        let next = packet(1, [fragment(1, FragmentPosition::ZERO_LAST, b"second")]);
        assert!(matches!(
            recv_on(&mut transport, &config, now, &next),
            Err(RecvError::ReadFragment)
        ));
        assert!(!transport.peer_acks.is_acked(PacketSeq::new(1)));
        assert_eq!(
            transport
                .recv
                .msgs
                .drain()
                .map(|msg| msg.payload)
                .collect::<Vec<_>>(),
            [b"first".to_vec()]
        );
    }

    #[test]
    fn plugin_hides_partial_messages_before_downstream_consumers() {
        #[derive(Resource, Default)]
        struct Observed {
            disconnected: bool,
            consumed: usize,
        }

        for injected_before_poll in [false, true] {
            let now = Instant::now();
            let mut session = Session::new(now, 1024);
            let mut transport = transport(LaneKind::ReliableOrdered, now, 1024);
            let config = TransportConfig::default();
            let mut partial = packet(0, [fragment(0, FragmentPosition::ZERO_LAST, b"first")]);
            partial.push(0);
            if injected_before_poll {
                assert!(matches!(
                    recv_on(&mut transport, &config, now, &partial),
                    Err(RecvError::ReadFragment)
                ));
                assert_eq!(transport.recv.msgs.0.len(), 1);
                assert!(session.recv.is_empty());
            } else {
                session.recv.push(RecvPacket {
                    recv_at: now,
                    payload: partial.into(),
                });
            }

            let mut app = App::new();
            app.add_plugins((TimePlugin, AeronetIoPlugin, AeronetTransportPlugin))
                .insert_resource(NoClearBuffers)
                .init_resource::<Observed>()
                .add_systems(
                    PreUpdate,
                    (|mut transports: Query<&mut Transport>, mut observed: ResMut<Observed>| {
                        for mut transport in &mut transports {
                            observed.consumed += transport.recv.msgs.drain().count();
                        }
                    })
                    .after(TransportSystems::Poll),
                );
            let entity = app.world_mut().spawn((session, transport, config)).id();
            app.world_mut().entity_mut(entity).observe(
                |event: On<Disconnected>, mut observed: ResMut<Observed>| {
                    let DisconnectReason::ByError(error) = &event.reason else {
                        panic!("expected receive error");
                    };
                    assert!(matches!(
                        error.downcast_ref::<RecvError>(),
                        Some(RecvError::ReadFragment)
                    ));
                    observed.disconnected = true;
                },
            );
            app.update();
            let observed = app.world().resource::<Observed>();
            assert!(observed.disconnected);
            assert_eq!(observed.consumed, 0);
            assert!(app.world().get_entity(entity).is_err());
        }
    }

    #[test]
    fn plugin_disconnects_on_rejected_reliable_fragment() {
        #[derive(Resource, Default)]
        struct ReceiveDisconnect(bool);

        let now = Instant::now();
        let mut session = Session::new(now, 1024);
        let transport = transport(LaneKind::ReliableOrdered, now, 1024);
        let config = TransportConfig {
            max_memory_usage: transport.memory_used(),
            ..TransportConfig::default()
        };
        session.recv.extend([
            RecvPacket {
                recv_at: now,
                payload: packet(0, [fragment(0, FragmentPosition::ZERO_LAST, b"rejected")]).into(),
            },
            RecvPacket {
                recv_at: now,
                payload: packet(1, []).into(),
            },
        ]);

        let mut app = App::new();
        app.add_plugins((TimePlugin, AeronetIoPlugin, AeronetTransportPlugin))
            .insert_resource(NoClearBuffers)
            .init_resource::<ReceiveDisconnect>();
        let entity = app.world_mut().spawn((session, transport, config)).id();
        app.world_mut().entity_mut(entity).observe(
            |event: On<Disconnected>,
             transports: Query<&Transport>,
             mut disconnected: ResMut<ReceiveDisconnect>| {
                let DisconnectReason::ByError(err) = &event.reason else {
                    panic!("expected receive error");
                };
                assert!(matches!(
                    err.downcast_ref::<RecvError>(),
                    Some(RecvError::Reassemble(ReassembleError::OutOfMemory { .. }))
                ));
                let transport = transports.get(event.entity).unwrap();
                assert!(!transport.peer_acks.is_acked(PacketSeq::new(0)));
                assert!(!transport.peer_acks.is_acked(PacketSeq::new(1)));
                assert!(transport.recv.msgs.0.is_empty());
                disconnected.0 = true;
            },
        );

        app.update();
        assert!(app.world().resource::<ReceiveDisconnect>().0);
        assert!(app.world().get_entity(entity).is_err());
    }

    #[test]
    fn completed_fragmented_duplicates_do_not_allocate() {
        let now = Instant::now();
        let config = TransportConfig::default();
        for kind in [LaneKind::ReliableOrdered, LaneKind::ReliableUnordered] {
            // Sequence 1 remains queued/tracked until missing sequence 0
            // arrives.
            for seq in [0, 1] {
                let mut transport = transport(kind, now, 1024);
                let first = fragment(
                    seq,
                    FragmentPosition::ZERO_NON_LAST,
                    &vec![1; usize::from(transport.send.max_frag_len)],
                );
                let last = fragment(seq, FragmentPosition::last(1u16).unwrap(), b"last");
                recv_on(
                    &mut transport,
                    &config,
                    now,
                    &packet(0, [first.clone(), last.clone()]),
                )
                .unwrap();
                transport.recv.msgs.drain().for_each(drop);
                let memory_used = transport.memory_used();
                let tracked = transport.recv.lanes[0].num_unordered_msgs();

                // Replay only one fragment at a time, not a complete message.
                for (packet_seq, frag) in [(1, first), (2, last)] {
                    recv_on(&mut transport, &config, now, &packet(packet_seq, [frag])).unwrap();
                    assert!(transport.peer_acks.is_acked(PacketSeq::new(packet_seq)));
                    assert_eq!(transport.recv.lanes[0].num_reassembling_msgs(), 0);
                    assert_eq!(transport.recv.lanes[0].num_unordered_msgs(), tracked);
                    assert_eq!(transport.memory_used(), memory_used);
                    assert_eq!(transport.recv.msgs.drain().count(), 0);
                }
            }
        }
    }

    #[test]
    fn reliable_unordered_delivers_one_one_zero_once_each() {
        let now = Instant::now();
        let mut transport = transport(LaneKind::ReliableUnordered, now, 1024);
        let config = TransportConfig::default();
        for (packet_seq, msg_seq) in [(0, 1), (1, 1), (2, 0)] {
            recv_on(
                &mut transport,
                &config,
                now,
                &packet(
                    packet_seq,
                    [fragment(
                        msg_seq,
                        FragmentPosition::ZERO_LAST,
                        &[u8::try_from(msg_seq).unwrap()],
                    )],
                ),
            )
            .unwrap();
        }
        assert_eq!(
            transport
                .recv
                .msgs
                .drain()
                .map(|msg| msg.payload)
                .collect::<Vec<_>>(),
            [vec![1], vec![0]]
        );
        assert_eq!(transport.recv.lanes[0].num_unordered_msgs(), 0);

        // The lane itself also guards its insertion, independently of the
        // pre-reassembly filter.
        let mut lane = LaneState::ReliableUnordered {
            pending: MessageSeq::new(0),
            recv_buf: HashSet::default(),
        };
        assert_eq!(
            recv_on_lane(&mut lane, vec![1], MessageSeq::new(1)).count(),
            1
        );
        assert_eq!(
            recv_on_lane(&mut lane, vec![1], MessageSeq::new(1)).count(),
            0
        );
        assert_eq!(
            recv_on_lane(&mut lane, vec![0], MessageSeq::new(0)).count(),
            1
        );
    }

    #[test]
    fn duplicate_incomplete_fragment_is_harmless() {
        let now = Instant::now();
        let mut transport = transport(LaneKind::ReliableOrdered, now, 1024);
        let config = TransportConfig::default();
        let first_payload = vec![1; usize::from(transport.send.max_frag_len)];
        let first = fragment(0, FragmentPosition::ZERO_NON_LAST, &first_payload);
        for seq in [0, 1] {
            recv_on(&mut transport, &config, now, &packet(seq, [first.clone()])).unwrap();
            assert!(transport.peer_acks.is_acked(PacketSeq::new(seq)));
            assert_eq!(transport.recv.lanes[0].num_reassembling_msgs(), 1);
        }
        recv_on(
            &mut transport,
            &config,
            now,
            &packet(
                2,
                [fragment(0, FragmentPosition::last(1u16).unwrap(), b"last")],
            ),
        )
        .unwrap();
        let mut expected = first_payload;
        expected.extend_from_slice(b"last");
        assert_eq!(
            transport.recv.msgs.drain().next().unwrap().payload,
            expected
        );
        assert_eq!(transport.recv.lanes[0].num_reassembling_msgs(), 0);
    }

    #[test]
    fn reliable_deduplication_respects_sequence_wraparound() {
        let now = Instant::now();
        let config = TransportConfig::default();
        for kind in [LaneKind::ReliableOrdered, LaneKind::ReliableUnordered] {
            let mut transport = transport(kind, now, 1024);
            match &mut transport.recv.lanes[0].state {
                LaneState::ReliableOrdered { pending, .. }
                | LaneState::ReliableUnordered { pending, .. } => {
                    *pending = MessageSeq::new(u16::MAX);
                }
                _ => unreachable!(),
            }
            for (packet_seq, msg_seq) in [(u16::MAX, 0), (0, 0), (1, u16::MAX), (2, u16::MAX)] {
                recv_on(
                    &mut transport,
                    &config,
                    now,
                    &packet(
                        packet_seq,
                        [fragment(
                            msg_seq,
                            FragmentPosition::ZERO_LAST,
                            &msg_seq.to_le_bytes(),
                        )],
                    ),
                )
                .unwrap();
            }
            let expected = if kind == LaneKind::ReliableOrdered {
                [u16::MAX, 0]
            } else {
                [0, u16::MAX]
            };
            assert_eq!(
                transport
                    .recv
                    .msgs
                    .drain()
                    .map(|msg| msg.payload)
                    .collect::<Vec<_>>(),
                expected.map(|seq| seq.to_le_bytes().to_vec())
            );
            assert_eq!(transport.recv.lanes[0].num_reassembling_msgs(), 0);
            assert_eq!(transport.recv.lanes[0].num_unordered_msgs(), 0);
        }
    }

    #[test]
    fn lost_fragment_retransmission_unblocks_reliable_ordered_messages() {
        let now = Instant::now();
        let mtu = 64;
        let config = TransportConfig::default();
        let mut sender = transport(LaneKind::ReliableOrdered, now, mtu);
        let mut receiver = transport(LaneKind::ReliableOrdered, now, mtu);
        let payload = vec![7; usize::from(sender.send.max_frag_len) * 3];
        let first_key = sender.send.push(LANE, payload.clone().into(), now).unwrap();
        let mut packets = flush_on(&mut sender, now, mtu).collect::<Vec<_>>();
        assert!(packets.len() >= 3);
        let lost_packet = packets.remove(0);
        for packet in packets {
            recv_on(&mut receiver, &config, now, &packet).unwrap();
        }

        let later = now + Duration::from_millis(1);
        sender
            .send
            .push(LANE, Bytes::from_static(b"next"), later)
            .unwrap();
        for packet in flush_on(&mut sender, later, mtu) {
            recv_on(&mut receiver, &config, later, &packet).unwrap();
        }
        assert_eq!(receiver.recv.msgs.drain().count(), 0);
        assert_eq!(receiver.recv.lanes[0].num_unordered_msgs(), 1);

        let original_pto = sender.rtt().pto();
        for ack in flush_on(&mut receiver, later, mtu) {
            recv_on(&mut sender, &config, later, &ack).unwrap();
        }
        assert_eq!(
            sender.send.lanes[0].sent_msgs[&first_key.seq]
                .frags
                .iter()
                .filter(|frag| frag.is_some())
                .count(),
            1
        );

        let retry_at = later + original_pto.max(sender.rtt().pto());
        for packet in flush_on(&mut sender, retry_at, mtu) {
            recv_on(&mut receiver, &config, retry_at, &packet).unwrap();
        }
        assert_eq!(
            receiver
                .recv
                .msgs
                .drain()
                .map(|msg| msg.payload)
                .collect::<Vec<_>>(),
            [payload, b"next".to_vec()]
        );
        assert_eq!(receiver.recv.lanes[0].num_reassembling_msgs(), 0);

        // A delayed copy of the lost packet must not reconstruct it again.
        recv_on(&mut receiver, &config, retry_at, &lost_packet).unwrap();
        assert_eq!(receiver.recv.msgs.drain().count(), 0);
        assert_eq!(receiver.recv.lanes[0].num_reassembling_msgs(), 0);
    }

    #[test]
    fn unreliable_reassembly_expires_without_extending_on_duplicates() {
        let now = Instant::now();
        let config = TransportConfig {
            unreliable_reassembly_timeout: Duration::from_secs(2),
            ..TransportConfig::default()
        };
        for kind in [LaneKind::UnreliableUnordered, LaneKind::UnreliableSequenced] {
            let mut transport = transport(kind, now, 1024);
            let first = fragment(
                0,
                FragmentPosition::ZERO_NON_LAST,
                &vec![1; usize::from(transport.send.max_frag_len)],
            );
            recv_on(&mut transport, &config, now, &packet(0, [first.clone()])).unwrap();
            let memory_used = transport.memory_used();
            recv_on(
                &mut transport,
                &config,
                now + Duration::from_secs(1),
                &packet(1, [first]),
            )
            .unwrap();
            assert_eq!(transport.recv.lanes[0].num_reassembling_msgs(), 1);
            recv_on(
                &mut transport,
                &config,
                now + config.unreliable_reassembly_timeout,
                &packet(2, []),
            )
            .unwrap();
            assert_eq!(transport.recv.lanes[0].num_reassembling_msgs(), 0);
            assert!(transport.memory_used() < memory_used);
        }
    }

    #[test]
    fn idle_poll_expires_only_unreliable_reassembly() {
        let now = Instant::now();
        let kinds = [
            LaneKind::UnreliableUnordered,
            LaneKind::UnreliableSequenced,
            LaneKind::ReliableUnordered,
            LaneKind::ReliableOrdered,
        ];
        let session = Session::new(now, 1024);
        let mut transport = Transport::new(&session, kinds, kinds, now).unwrap();
        let config = TransportConfig {
            unreliable_reassembly_timeout: Duration::ZERO,
            ..TransportConfig::default()
        };
        let mut frags = Vec::new();
        for lane in 0..4 {
            let mut frag = fragment(
                0,
                FragmentPosition::ZERO_NON_LAST,
                &vec![1; usize::from(transport.send.max_frag_len)],
            );
            frag.header.lane = LaneIndex::new(lane);
            frags.push(frag);
        }
        recv_on(&mut transport, &config, now, &packet(0, frags)).unwrap();
        assert!(transport.peer_acks.is_acked(PacketSeq::new(0)));

        let mut app = App::new();
        app.add_plugins((TimePlugin, AeronetIoPlugin, AeronetTransportPlugin));
        let entity = app.world_mut().spawn((session, transport, config)).id();
        app.update();
        let transport = app.world().get::<Transport>(entity).unwrap();
        assert_eq!(
            transport
                .recv
                .lanes
                .iter()
                .map(super::RecvLane::num_reassembling_msgs)
                .collect::<Vec<_>>(),
            [0, 0, 1, 1]
        );
        assert!(transport.peer_acks.is_acked(PacketSeq::new(0)));
    }

    #[test]
    fn reliable_fragments_survive_unreliable_expiry_and_traffic_continues() {
        let now = Instant::now();
        let config = TransportConfig::default();
        for unreliable in [LaneKind::UnreliableUnordered, LaneKind::UnreliableSequenced] {
            let session = Session::new(now, 1024);
            let lanes = [unreliable, LaneKind::ReliableOrdered];
            let mut transport = Transport::new(&session, lanes, lanes, now).unwrap();
            let payload = vec![7; usize::from(transport.send.max_frag_len)];
            for lane in 0_u16..2 {
                let mut first = fragment(0, FragmentPosition::ZERO_NON_LAST, &payload);
                first.header.lane = LaneIndex::new(u32::from(lane));
                recv_on(&mut transport, &config, now, &packet(lane, [first])).unwrap();
            }
            let later = now + config.unreliable_reassembly_timeout + Duration::from_secs(1);
            let mut last = fragment(0, FragmentPosition::last(1u16).unwrap(), b"last");
            last.header.lane = LaneIndex::new(1);
            recv_on(&mut transport, &config, later, &packet(2, [last])).unwrap();
            assert_eq!(transport.recv.lanes[0].num_reassembling_msgs(), 0);
            assert_eq!(transport.recv.lanes[1].num_reassembling_msgs(), 0);
            recv_on(
                &mut transport,
                &config,
                later,
                &packet(3, [fragment(1, FragmentPosition::ZERO_LAST, b"fresh")]),
            )
            .unwrap();
            let mut expected = payload;
            expected.extend_from_slice(b"last");
            assert_eq!(
                transport
                    .recv
                    .msgs
                    .drain()
                    .map(|msg| (msg.lane, msg.payload))
                    .collect::<Vec<_>>(),
                [(LaneIndex::new(1), expected), (LANE, b"fresh".to_vec()),]
            );
            assert!(transport.recv.error.is_none());
        }
    }

    #[test]
    fn recv_one_frag() {
        let now = Instant::now();
        let session = Session::new(now, 1024);
        let mut transport = Transport::new(&session, LANES, LANES, now).unwrap();

        let mut packet = Vec::<u8>::new();
        packet
            .write(&PacketHeader {
                seq: PacketSeq::new(0),
                acks: Acknowledge::default(),
            })
            .unwrap();
        packet
            .write(&Fragment {
                header: FragmentHeader {
                    lane: LANE,
                    seq: MessageSeq::new(0),
                    position: FragmentPosition::last(0u16).unwrap(),
                },
                payload: FragmentPayload::new(Bytes::from_static(b"hello world")).unwrap(),
            })
            .unwrap();

        super::recv_on(
            &mut transport,
            &TransportConfig::default(),
            Instant::now(),
            &packet,
        )
        .unwrap();

        {
            let mut msgs = transport.recv.msgs.drain();
            assert!(msgs.next().is_some());
            assert!(msgs.next().is_none());
        }
    }

    #[test]
    fn recv_no_frags() {
        let now = Instant::now();
        let session = Session::new(now, 1024);
        let mut transport = Transport::new(&session, LANES, LANES, now).unwrap();

        let mut packet = Vec::<u8>::new();
        packet
            .write(&PacketHeader {
                seq: PacketSeq::new(0),
                acks: Acknowledge::default(),
            })
            .unwrap();
        // we don't write a fragment here
        // so we must not receive a message

        super::recv_on(
            &mut transport,
            &TransportConfig::default(),
            Instant::now(),
            &packet,
        )
        .unwrap();

        {
            let mut msgs = transport.recv.msgs.drain();
            assert!(msgs.next().is_none());
        }
    }
}
