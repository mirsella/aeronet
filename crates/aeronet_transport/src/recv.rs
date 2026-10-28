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
        size::replace_cached,
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
    lanes_size: usize,
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
pub struct RecvBuffer<T: TypeSize>(Vec<T>, usize);

impl TransportRecv {
    fn unreliable_eviction_candidates(
        &self,
        protected_lane: usize,
        protected_seq: MessageSeq,
    ) -> Vec<(usize, MessageSeq, Instant)> {
        let mut candidates = self
            .lanes
            .iter()
            .enumerate()
            .filter(|(_, lane)| lane.kind().reliability() == LaneReliability::Unreliable)
            .flat_map(|(index, lane)| {
                let protected = (index == protected_lane).then_some(protected_seq);
                lane.frags
                    .eviction_candidates(protected)
                    .map(move |(seq, at)| (index, seq, at))
            })
            .collect::<Vec<_>>();
        candidates.sort_unstable_by_key(|(_, _, at)| *at);
        candidates
    }

    pub(crate) fn new(lanes: impl IntoIterator<Item = impl Into<LaneKind>>) -> Self {
        Self {
            lanes: lanes
                .into_iter()
                .map(Into::into)
                .map(RecvLane::new)
                .collect(),
            error: None,
            lanes_size: 0,
            msgs: RecvBuffer(Vec::new(), 0),
            acks: RecvBuffer(Vec::new(), 0),
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
                let before = lane.extra_memory_used();
                lane.frags.expire(now, timeout);
                replace_cached(&mut self.lanes_size, before, lane.extra_memory_used());
            }
        }
    }

    pub(crate) fn extra_memory_used(&self) -> usize {
        self.lanes.len() * size_of::<RecvLane>()
            + self.lanes_size
            + self.msgs.0.capacity() * size_of::<RecvMessage>()
            + self.msgs.1
            + self.acks.0.capacity() * size_of::<MessageKey>()
    }
}

impl<T: TypeSize> RecvBuffer<T> {
    /// Drains all items from this buffer.
    pub fn drain(&mut self) -> impl Iterator<Item = T> + '_ {
        self.1 = 0;
        self.0.drain(..)
    }
}

impl RecvBuffer<RecvMessage> {
    fn extend_messages(
        &mut self,
        lane: LaneIndex,
        recv_at: Instant,
        msgs: impl Iterator<Item = Vec<u8>>,
    ) -> usize {
        let mut received = 0;
        for payload in msgs {
            replace_cached(&mut self.1, 0, payload.capacity());
            self.0.push(RecvMessage {
                lane,
                recv_at,
                payload,
            });
            received += 1;
        }
        received
    }
}

/// State of a lane used for receiving incoming messages on a [`Transport`].
#[derive(Debug, TypeSize)]
pub struct RecvLane {
    frags: FragmentReceiver,
    state: LaneState,
}

impl Clone for RecvLane {
    fn clone(&self) -> Self {
        let mut state = self.state.clone();
        if let LaneState::ReliableOrdered {
            recv_buf,
            buffered_size,
            ..
        } = &mut state
        {
            *buffered_size = recv_buf.values().map(Vec::capacity).sum();
        }
        Self {
            frags: self.frags.clone(),
            state,
        }
    }
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
        buffered_size: usize,
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
            Self::ReliableOrdered {
                pending, recv_buf, ..
            } => seq < *pending || recv_buf.contains_key(&seq),
        }
    }
}

impl RecvLane {
    fn extra_memory_used(&self) -> usize {
        let state_size = match &self.state {
            LaneState::UnreliableUnordered | LaneState::UnreliableSequenced { .. } => 0,
            LaneState::ReliableUnordered { recv_buf, .. } => {
                recv_buf.capacity() * size_of::<MessageSeq>()
            }
            LaneState::ReliableOrdered {
                recv_buf,
                buffered_size,
                ..
            } => {
                recv_buf.capacity() * (size_of::<MessageSeq>() + size_of::<Vec<u8>>())
                    + buffered_size
            }
        };
        self.frags.extra_memory_used() + state_size
    }

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
                    buffered_size: 0,
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
            transport.recv.msgs.1 = 0;
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
/// A failed packet is not acknowledged and its peer acknowledgements are
/// ignored, but preceding fragments may already have been committed. Do not
/// retry a failed transport; discard it or let the plugin disconnect it.
/// Harmless duplicate fragments and messages succeed and are acknowledged
/// normally.
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

    let mut frag_index = Saturating(0);
    let mut frags_recv = Saturating(0);
    let mut ack_credit = None;
    while packet.has_remaining() {
        match recv_frag(
            transport,
            config,
            recv_at,
            &mut packet,
            &header,
            &mut ack_credit,
        ) {
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
    for seq in header.acks.seqs() {
        transport.packet_loss.ack(seq);
    }
    transport.recv.acks.0.extend(packet_acks_to_msg_keys(
        &mut transport.flushed_packets,
        &mut transport.flushed_packets_size,
        &mut transport.send.lanes,
        &mut transport.send.lanes_size,
        &mut transport.rtt,
        &mut transport.stats.packet_acks_recv,
        &mut transport.stats.msg_acks_recv,
        recv_at,
        header.acks.seqs(),
    ));
    Ok(())
}

fn packet_acks_to_msg_keys<'s, const N: usize>(
    flushed_packets: &'s mut SeqBuf<FlushedPacket, N>,
    flushed_packets_size: &'s mut usize,
    tx_lanes: &'s mut [SendLane],
    tx_lanes_size: &'s mut usize,
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
                .map(|packet| {
                    replace_cached(flushed_packets_size, packet.extra_memory_used(), 0);
                    (acked_seq, packet)
                })
        })
        .flat_map(move |(acked_seq, packet)| {
            let packet_rtt = recv_at.saturating_duration_since(packet.flushed_at);
            rtt.update(packet_rtt);

            let rtt_now = rtt.get();
            trace!("Got peer ack for packet {} - packet RTT: {packet_rtt:?} / RTT now: {rtt_now:?}", acked_seq.0.0);

            *packet_acks_recv += 1;
            Box::into_iter(packet.frags)
        })
        .filter_map(move |frag_path| {
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
            if let Some(frag) = frag_opt.take() {
                let size = frag.extra_size();
                replace_cached(&mut lane.sent_msgs_size, size, 0);
                replace_cached(tx_lanes_size, size, 0);
            }

            // if all the fragments are now acked, then we report that
            // the entire message is now acked
            if !msg.acked && msg.frags.iter().all(Option::is_none) {
                msg.acked = true;
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
    header: &PacketHeader,
    ack_credit: &mut Option<usize>,
) -> Result<(), RecvError> {
    let frag = packet
        .read::<Fragment>()
        .map_err(|_| RecvError::ReadFragment)?;
    let lane_index = frag.header.lane;

    let index = usize::from(lane_index.0);
    let lane = transport
        .recv
        .lanes
        .get(index)
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

    let Some(prepared) = lane
        .frags
        .prepare(
            transport.send.max_frag_len,
            frag.header.seq,
            frag.header.position,
            &frag.payload,
        )
        .map_err(RecvError::Reassemble)?
    else {
        return Ok(());
    };

    let mut memory_left = config
        .max_memory_usage
        .saturating_sub(transport.memory_used());
    if prepared.memory_required > memory_left {
        // Borrow only memory that this packet's ACKs will release after
        // acceptance. Do not commit ACK state if any later fragment
        // rejects the packet.
        let credit = *ack_credit.get_or_insert_with(|| pending_ack_memory(transport, header));
        memory_left = config
            .max_memory_usage
            .saturating_sub(transport.memory_used().saturating_sub(credit));
    }
    if prepared.memory_required > memory_left {
        let candidates = transport
            .recv
            .unreliable_eviction_candidates(index, frag.header.seq);
        for (evict_lane, seq, _) in candidates {
            let lane = transport
                .recv
                .lanes
                .get_mut(evict_lane)
                .expect("candidate came from this lane list");
            let before = lane.extra_memory_used();
            lane.frags.discard(seq);
            replace_cached(
                &mut transport.recv.lanes_size,
                before,
                lane.extra_memory_used(),
            );
            memory_left = config.max_memory_usage.saturating_sub(
                transport
                    .memory_used()
                    .saturating_sub(ack_credit.unwrap_or(0)),
            );
            if prepared.memory_required <= memory_left {
                break;
            }
        }
        if prepared.memory_required > memory_left {
            return Err(RecvError::Reassemble(ReassembleError::OutOfMemory {
                required: prepared.memory_required,
                left: memory_left,
            }));
        }
    }
    let lane = transport
        .recv
        .lanes
        .get_mut(index)
        .expect("lane was validated above");
    let before = lane.extra_memory_used();
    let msg = lane.frags.insert_prepared(prepared, Some(recv_at));

    if let Some(msg) = msg {
        let msgs = recv_on_lane(&mut lane.state, msg, frag.header.seq);
        transport.stats.msgs_recv += transport
            .recv
            .msgs
            .extend_messages(lane_index, recv_at, msgs);
        if let LaneState::UnreliableSequenced { pending } = lane.state {
            lane.frags.discard_before(pending);
        }
        trace!("Fragment finished reassembling this message");
    }
    replace_cached(
        &mut transport.recv.lanes_size,
        before,
        lane.extra_memory_used(),
    );

    Ok(())
}

fn pending_ack_memory(transport: &Transport, header: &PacketHeader) -> usize {
    let mut fragments = HashSet::<_>::default();
    let mut released = 0;
    for seq in header.acks.seqs() {
        let Some(packet) = transport.flushed_packets.get(seq.0.0) else {
            continue;
        };
        released += packet.extra_memory_used();
        for path in &packet.frags {
            // A fragment can have been retransmitted in several acknowledged
            // packets.
            if !fragments.insert(*path) {
                continue;
            }
            let lane = &transport.send.lanes[usize::from(path.lane_index.0)];
            if let Some(fragment) = lane
                .sent_msgs
                .get(&path.msg_seq)
                .and_then(|message| message.frags.get(usize::from(path.frag_index)))
                .and_then(Option::as_ref)
            {
                released += fragment.extra_size();
            }
        }
    }
    released
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
        LaneState::ReliableOrdered {
            pending,
            recv_buf,
            buffered_size,
        } => {
            if msg_seq < *pending {
                // msg is guaranteed to already be received, drop it
                Either::Left(None)
            } else {
                // almost identical to above, but we also return the
                // messages that we remove
                let size = msg.capacity();
                let replaced = recv_buf.insert(msg_seq, msg);
                replace_cached(
                    buffered_size,
                    replaced.as_ref().map_or(0, Vec::capacity),
                    size,
                );
                Either::Right(iter::from_fn(move || {
                    let msg = recv_buf.remove(pending)?;
                    replace_cached(buffered_size, msg.capacity(), 0);
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
        typesize::TypeSize,
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

    fn partial_packet(transport: &Transport, lane: u32, seq: u16, index: u16) -> Vec<u8> {
        let mut frag = fragment(
            seq,
            FragmentPosition::non_last(index).unwrap(),
            &vec![7; usize::from(transport.send.max_frag_len)],
        );
        frag.header.lane = LaneIndex::new(lane);
        packet(seq, [frag])
    }

    #[test]
    fn ack_memory_credit_counts_retransmitted_payload_only_once() {
        use typesize::TypeSize;
        let now = Instant::now();
        let mut sender = transport(LaneKind::ReliableOrdered, now, 1200);
        sender
            .send
            .push(LANE, Bytes::from(vec![7; 1024]), now)
            .unwrap();
        assert_eq!(flush_on(&mut sender, now, 1200).count(), 1);
        let mut header = PacketHeader {
            seq: PacketSeq::new(0),
            acks: Acknowledge::default(),
        };
        header.acks.ack(PacketSeq::new(0));
        let single = super::pending_ack_memory(&sender, &header);
        let retransmit = sender.flushed_packets.get(0).unwrap().clone();
        let metadata = retransmit.frags.extra_size();
        sender.record_flushed_packet(PacketSeq::new(1), retransmit);
        header.acks.ack(PacketSeq::new(1));
        assert_eq!(
            super::pending_ack_memory(&sender, &header),
            single + metadata
        );
    }

    #[test]
    fn piggybacked_acks_release_memory_for_valid_reliable_payloads() {
        let now = Instant::now();
        for kind in [LaneKind::ReliableOrdered, LaneKind::ReliableUnordered] {
            let mut sender = transport(kind, now, 1200);
            let mut peer = transport(kind, now, 1200);
            let key = sender
                .send
                .push(LANE, Bytes::from(vec![7; 1024]), now)
                .unwrap();
            for payload in flush_on(&mut sender, now, 1200) {
                recv_on(&mut peer, &TransportConfig::default(), now, &payload).unwrap();
            }
            let config = TransportConfig {
                max_memory_usage: sender.memory_used(),
                ..TransportConfig::default()
            };
            peer.send.push(LANE, Bytes::from(vec![8; 64]), now).unwrap();
            for payload in flush_on(&mut peer, now, 1200) {
                recv_on(&mut sender, &config, now, &payload).unwrap();
            }
            assert!(sender.memory_used() <= config.max_memory_usage);
            assert_eq!(sender.recv.acks.drain().collect::<Vec<_>>(), [key]);
            let messages = sender.recv.msgs.drain().collect::<Vec<_>>();
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].payload.as_slice(), &[8; 64]);
        }
    }

    #[test]
    fn peer_acks_are_processed_only_after_fragment_acceptance() {
        let now = Instant::now();
        for failure in [None, Some(false), Some(true)] {
            let mut sender = transport(LaneKind::ReliableOrdered, now, 64);
            let mut peer = transport(LaneKind::ReliableOrdered, now, 64);
            let key = sender
                .send
                .push(LANE, Bytes::from_static(b"sent"), now)
                .unwrap();
            for payload in flush_on(&mut sender, now, 64) {
                recv_on(&mut peer, &TransportConfig::default(), now, &payload).unwrap();
            }
            if failure == Some(true) {
                peer.send
                    // Exceed both the released payload and flushed-path metadata.
                    .push(LANE, Bytes::from(vec![8; 32]), now)
                    .unwrap();
            }
            let mut packets = flush_on(&mut peer, now, 64).collect::<Vec<_>>();
            assert_eq!(packets.len(), 1);
            let mut payload = packets.pop().unwrap().to_vec();
            if failure == Some(false) {
                payload.push(0); // truncated fragment after a valid ACK header
            }
            let config = TransportConfig {
                max_memory_usage: sender.memory_used(),
                ..TransportConfig::default()
            };
            let result = recv_on(&mut sender, &config, now, &payload);
            if let Some(out_of_memory) = failure {
                if out_of_memory {
                    assert!(matches!(
                        result,
                        Err(RecvError::Reassemble(ReassembleError::OutOfMemory { .. }))
                    ));
                } else {
                    assert!(matches!(result, Err(RecvError::ReadFragment)));
                }
                assert!(!sender.peer_acks.is_acked(PacketSeq::new(0)));
                assert_eq!(sender.num_unacked_packets(), 1);
                assert_eq!(sender.stats().packet_acks_recv.0, 0);
                assert_eq!(sender.stats().msg_acks_recv.0, 0);
                assert!(
                    sender.send.lanes[0].sent_msgs[&key.seq]
                        .frags
                        .iter()
                        .all(Option::is_some)
                );
                assert_eq!(sender.recv.acks.drain().count(), 0);
            } else {
                result.unwrap();
                assert!(sender.peer_acks.is_acked(PacketSeq::new(0)));
                assert_eq!(sender.num_unacked_packets(), 0);
                assert_eq!(sender.recv.acks.drain().collect::<Vec<_>>(), [key]);
            }
        }
    }

    #[test]
    fn invalid_fragment_does_not_evict_or_allocate() {
        let now = Instant::now();
        let mut transport = transport(LaneKind::UnreliableUnordered, now, 64);
        let config = TransportConfig::default();
        let first = partial_packet(&transport, 0, 0, 3);
        recv_on(&mut transport, &config, now, &first).unwrap();
        let before = transport.memory_used();
        let config = TransportConfig {
            max_memory_usage: before,
            ..config
        };
        let invalid = packet(
            1,
            [fragment(
                1,
                FragmentPosition::non_last(10u16).unwrap(),
                b"bad",
            )],
        );
        assert!(matches!(
            recv_on(&mut transport, &config, now, &invalid),
            Err(RecvError::Reassemble(
                ReassembleError::InvalidPayloadLength { .. }
            ))
        ));
        assert_eq!(transport.recv.lanes[0].num_reassembling_msgs(), 1);
        assert_eq!(transport.memory_used(), before);
        assert_eq!(
            transport.recv.lanes[0]
                .frags
                .eviction_candidates(None)
                .collect::<Vec<_>>(),
            [(MessageSeq::new(0), now)]
        );
        assert!(!transport.peer_acks.is_acked(PacketSeq::new(1)));
    }

    #[test]
    fn pressure_preserves_reliable_delivery_and_completed_retries() {
        let now = Instant::now();
        for kind in [LaneKind::ReliableOrdered, LaneKind::ReliableUnordered] {
            let lanes = [
                LaneKind::UnreliableUnordered,
                LaneKind::UnreliableSequenced,
                kind,
            ];
            let session = Session::new(now, 64);
            let mut sender = Transport::new(&session, lanes, lanes, now).unwrap();
            let mut receiver = Transport::new(&session, lanes, lanes, now).unwrap();
            let reliable = LaneIndex::new(2);
            let payload = vec![9; usize::from(sender.send.max_frag_len) * 4];
            let key = sender
                .send
                .push(reliable, payload.clone().into(), now)
                .unwrap();
            let mut packets = flush_on(&mut sender, now, 64)
                .collect::<Vec<_>>()
                .into_iter();
            let first = packets.next().unwrap(); // last fragment allocates the
            // whole message
            let config = TransportConfig::default();
            recv_on(&mut receiver, &config, now, &first).unwrap();
            let older = partial_packet(&receiver, 0, 0, 3);
            recv_on(&mut receiver, &config, now, &older).unwrap();
            let later = now + Duration::from_millis(1);
            let newer = partial_packet(&receiver, 1, 0, 3);
            recv_on(&mut receiver, &config, later, &newer).unwrap();
            let config = TransportConfig {
                max_memory_usage: receiver.memory_used() + 64,
                ..config
            };
            let incoming = partial_packet(&receiver, 0, 1, 1);
            recv_on(&mut receiver, &config, later, &incoming).unwrap();
            assert!(receiver.memory_used() <= config.max_memory_usage);
            assert_eq!(
                receiver.recv.lanes[0]
                    .frags
                    .eviction_candidates(None)
                    .map(|(seq, _)| seq)
                    .collect::<Vec<_>>(),
                [MessageSeq::new(1)]
            );
            assert_eq!(receiver.recv.lanes[1].num_reassembling_msgs(), 1);
            assert_eq!(receiver.recv.lanes[2].num_reassembling_msgs(), 1);
            for packet in packets {
                recv_on(&mut receiver, &config, later, &packet).unwrap();
            }
            assert_eq!(
                receiver
                    .recv
                    .msgs
                    .drain()
                    .map(|msg| (msg.lane, msg.payload))
                    .collect::<Vec<_>>(),
                [(reliable, payload)]
            );
            assert_eq!(receiver.recv.lanes[2].num_reassembling_msgs(), 0);
            let memory_used = receiver.memory_used();
            let retry_config = TransportConfig {
                max_memory_usage: memory_used + 64,
                ..config
            };
            // No ACKs have reached the sender. A single retried fragment must
            // neither allocate a new reliable buffer nor evict unreliable
            // state.
            let retry_at = later + sender.rtt().pto();
            let retry = flush_on(&mut sender, retry_at, 64).next().unwrap();
            recv_on(&mut receiver, &retry_config, retry_at, &retry).unwrap();
            assert_eq!(receiver.memory_used(), memory_used);
            assert_eq!(receiver.recv.lanes[0].num_reassembling_msgs(), 1);
            assert_eq!(receiver.recv.lanes[1].num_reassembling_msgs(), 1);
            assert_eq!(receiver.recv.lanes[2].num_reassembling_msgs(), 0);
            assert_eq!(receiver.recv.msgs.drain().count(), 0);
            assert!(receiver.recv.error.is_none());
            for ack in flush_on(&mut receiver, retry_at, 64) {
                recv_on(&mut sender, &TransportConfig::default(), retry_at, &ack).unwrap();
            }
            assert!(
                sender.send.lanes[2].sent_msgs[&key.seq]
                    .frags
                    .iter()
                    .all(Option::is_none)
            );
        }
    }

    #[test]
    fn memory_pressure_evicts_multiple_messages_in_age_order() {
        let now = Instant::now();
        let session = Session::new(now, 64);
        let lanes = [LaneKind::UnreliableUnordered; 2];
        let mut transport = Transport::new(&session, lanes, lanes, now).unwrap();
        let config = TransportConfig::default();
        for (lane, seq, at) in [
            (1, 0, now),
            (0, 0, now + Duration::from_millis(1)),
            (1, 1, now + Duration::from_millis(2)),
        ] {
            let packet = partial_packet(&transport, lane, seq, 3);
            recv_on(&mut transport, &config, at, &packet).unwrap();
        }
        let config = TransportConfig {
            max_memory_usage: transport.memory_used() + 64,
            ..config
        };
        let packet = partial_packet(&transport, 0, 1, 6);
        recv_on(
            &mut transport,
            &config,
            now + Duration::from_millis(2),
            &packet,
        )
        .unwrap();
        assert!(transport.memory_used() <= config.max_memory_usage);
        for lane in &transport.recv.lanes {
            assert_eq!(lane.num_reassembling_msgs(), 1);
            assert_eq!(
                lane.frags.eviction_candidates(None).next().unwrap().0,
                MessageSeq::new(1)
            );
        }
    }

    #[test]
    fn pressure_protects_message_being_extended() {
        let now = Instant::now();
        let mut transport = transport(LaneKind::UnreliableUnordered, now, 64);
        let config = TransportConfig::default();
        let first = partial_packet(&transport, 0, 0, 0);
        recv_on(&mut transport, &config, now, &first).unwrap();
        let next = partial_packet(&transport, 0, 1, 3);
        recv_on(
            &mut transport,
            &config,
            now + Duration::from_millis(1),
            &next,
        )
        .unwrap();
        let config = TransportConfig {
            max_memory_usage: transport.memory_used(),
            ..config
        };
        let extend = partial_packet(&transport, 0, 0, 3);
        recv_on(
            &mut transport,
            &config,
            now + Duration::from_millis(2),
            &extend,
        )
        .unwrap();
        assert_eq!(transport.recv.lanes[0].num_reassembling_msgs(), 1);
        assert_eq!(
            transport.recv.lanes[0]
                .frags
                .eviction_candidates(None)
                .collect::<Vec<_>>(),
            [(MessageSeq::new(0), now)]
        );
        let used = transport.memory_used();
        recv_on(&mut transport, &config, now, &first).unwrap();
        assert_eq!(
            transport.memory_used(),
            used,
            "the protected message kept its first fragment"
        );
        assert!(transport.memory_used() <= config.max_memory_usage);
    }

    #[test]
    fn sequenced_delivery_discards_obsolete_partials_across_wraparound() {
        let now = Instant::now();
        let mut transport = transport(LaneKind::UnreliableSequenced, now, 64);
        let config = TransportConfig::default();
        let old = u16::MAX - 1;
        transport.recv.lanes[0].state = LaneState::UnreliableSequenced {
            pending: MessageSeq::new(old),
        };
        for seq in [old, 0] {
            let packet = partial_packet(&transport, 0, seq, 0);
            recv_on(&mut transport, &config, now, &packet).unwrap();
        }
        recv_on(
            &mut transport,
            &config,
            now,
            &packet(1, [fragment(u16::MAX, FragmentPosition::ZERO_LAST, b"new")]),
        )
        .unwrap();
        assert_eq!(transport.recv.msgs.drain().count(), 1);
        assert_eq!(
            transport.recv.lanes[0]
                .frags
                .eviction_candidates(None)
                .map(|(seq, _)| seq)
                .collect::<Vec<_>>(),
            [MessageSeq::new(0)]
        );
        let packet = partial_packet(&transport, 0, old, 0);
        recv_on(&mut transport, &config, now, &packet).unwrap();
        assert_eq!(transport.recv.lanes[0].num_reassembling_msgs(), 1);
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
                let retry_config = TransportConfig {
                    max_memory_usage: memory_used + 64,
                    ..config.clone()
                };
                let tracked = transport.recv.lanes[0].num_unordered_msgs();

                // Replay only one fragment at a time, not a complete message.
                for (packet_seq, frag) in [(1, first), (2, last)] {
                    recv_on(
                        &mut transport,
                        &retry_config,
                        now,
                        &packet(packet_seq, [frag]),
                    )
                    .unwrap();
                    assert!(transport.peer_acks.is_acked(PacketSeq::new(packet_seq)));
                    assert_eq!(transport.recv.lanes[0].num_reassembling_msgs(), 0);
                    assert_eq!(transport.recv.lanes[0].num_unordered_msgs(), tracked);
                    assert_eq!(transport.memory_used(), memory_used);
                    assert_eq!(transport.recv.msgs.drain().count(), 0);
                }
                if seq == 1 {
                    recv_on(
                        &mut transport,
                        &config,
                        now,
                        &packet(3, [fragment(0, FragmentPosition::ZERO_LAST, b"gap")]),
                    )
                    .unwrap();
                    let delivered = transport
                        .recv
                        .msgs
                        .drain()
                        .map(|msg| msg.payload)
                        .collect::<Vec<_>>();
                    if kind == LaneKind::ReliableOrdered {
                        assert_eq!(delivered.len(), 2);
                        assert_eq!(delivered[0], b"gap");
                        let mut expected = vec![1; usize::from(transport.send.max_frag_len)];
                        expected.extend_from_slice(b"last");
                        assert_eq!(delivered[1], expected);
                    } else {
                        assert_eq!(delivered, [b"gap".to_vec()]);
                    }
                    assert_eq!(transport.recv.lanes[0].num_unordered_msgs(), 0);
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
                [
                    first,
                    fragment(0, FragmentPosition::last(1u16).unwrap(), b"last"),
                ],
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
            assert_eq!(transport.memory_used(), transport.get_size());
            for lane in transport.recv.lanes() {
                let cloned = lane.clone();
                assert_eq!(cloned.extra_memory_used(), cloned.extra_size());
            }
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
