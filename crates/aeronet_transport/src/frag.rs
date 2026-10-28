//! Handles splitting large messages into smaller fragments, and reassembling
//! fragments back into messages.
//!
//! Packets are limited in size, usually to ~1000 bytes over a network. To be
//! able to send larger messages, we need a strategy to break down a large
//! message into smaller fragments, and send those fragments as packets over
//! the network (see [`split`]). On the receiving end, we combine these
//! fragments back up in order, and reassemble them into a full message (see
//! [`FragmentReceiver`]).

use {
    crate::{
        packet::{FragmentPayload, FragmentPosition, MessageSeq},
        size::{MinSize, replace_cached},
    },
    alloc::vec::Vec,
    bevy_platform::{collections::HashMap, time::Instant},
    bit_vec::BitVec,
    core::{fmt, iter::FusedIterator, time::Duration},
    derive_more::{Display, Error},
    octs::{Bytes, chunks::ByteChunksExt},
    typesize::derive::TypeSize,
};

/// Splits a message up into smaller fragments, ready to be reassembled by a
/// [`FragmentReceiver`].
///
/// The maximum length that a single fragment's payload will be is determined
/// by `max_frag_len`.
///
/// Fragments will be returned in the opposite order to the fragment's index.
/// For example, if you pass a message which is split into fragments `A, B, C`,
/// the iterator will return them in the order `C, B, A`. This is done to make
/// receiving fragments more efficient, since when the receiver receives `C`
/// (which is marked as the [last fragment]), it will immediately know how many
/// fragments there are in total, and can allocate the right sized buffer to fit
/// this message.
///
/// Note that even if `C` is lost, it will make reassembly slightly less
/// efficient as the receiver will have to resize its buffer when re-receiving
/// `C` later, but the logic will still behave correctly.
///
/// # Errors
///
/// Errors if the message is too big, and will be split into more than
/// [`MinSize::MAX`] number of fragments. Realistically, you should never run
/// into this as long as your messages are of reasonable length.
///
/// # Panics
///
/// Panics if `max_frag_len == 0`.
///
/// [last fragment]: FragmentPosition::is_last
pub fn split(
    max_frag_len: MinSize,
    msg: Bytes,
) -> Result<
    impl ExactSizeIterator<Item = (FragmentPosition, FragmentPayload)>
    + DoubleEndedIterator
    + FusedIterator,
    MessageTooBig,
> {
    assert!(max_frag_len.0 > 0);

    let byte_len = msg.len();
    let iter = msg.byte_chunks(usize::from(max_frag_len));
    let num_frags = iter.len();

    let last_index = num_frags.saturating_sub(1);
    if MinSize::try_from(last_index).is_err() {
        return Err(MessageTooBig {
            byte_len,
            num_frags,
        });
    }

    Ok(iter.enumerate().rev().map(move |(index, payload)| {
        let position = if index == last_index {
            MinSize::try_from(index)
                .ok()
                .and_then(FragmentPosition::last)
        } else {
            MinSize::try_from(index)
                .ok()
                .and_then(FragmentPosition::non_last)
        }
        .expect("we check above that there should not be more than `MinSize::MAX` fragments");

        let payload = FragmentPayload::new(payload).expect(
            "`payload` is a chunk of up to `max_frag_len` bytes, and `max_frag_len` is a \
             `MinSize`, so `payload` should not be bigger than `MinSize`",
        );

        (position, payload)
    }))
}

/// Passed a message to [`split`] which was too long in length, and cannot be
/// represented in [`MinSize::MAX`] number of fragments.
#[derive(Debug, Clone, Display, Error, TypeSize)]
#[display("message too big - byte length: {byte_len}, num frags: {num_frags} / {}", MinSize::MAX.0)]
pub struct MessageTooBig {
    /// How long the message is, in bytes.
    pub byte_len: usize,
    /// How many fragments this message would take up.
    pub num_frags: usize,
}

/// Receives fragments created by [`split`] and reassembles them into full
/// messages.
#[derive(Default, TypeSize)]
pub struct FragmentReceiver {
    #[typesize(with = crate::size::of_map)]
    msgs: HashMap<MessageSeq, MessageBuf>,
    buffered_size: usize,
}

impl Clone for FragmentReceiver {
    fn clone(&self) -> Self {
        let msgs = self.msgs.clone();
        // Cloning Vec/BitVec may shrink their reserved capacity.
        let buffered_size = msgs.values().map(MessageBuf::extra_memory_used).sum();
        Self {
            msgs,
            buffered_size,
        }
    }
}

/// Received an invalid fragment when reassembling fragments into a message.
#[derive(Debug, Clone, PartialEq, Eq, Display, Error, TypeSize)]
pub enum ReassembleError {
    /// Already received a fragment with this index.
    #[display("already received fragment {index}")]
    AlreadyReceivedFrag {
        /// Index of the fragment received.
        index: usize,
    },
    /// Not enough free memory to buffer this fragment up.
    #[display("out of memory - required {required} bytes, {left} bytes left")]
    OutOfMemory {
        /// Bytes of memory required.
        required: usize,
        /// Bytes of memory left.
        left: usize,
    },
    /// Received a fragment which claims to be the last fragment, but we already
    /// received the last fragment.
    #[display("received last fragment {index}, but we already received last fragment {last}")]
    AlreadyReceivedLastFrag {
        /// Index of the fragment received.
        index: usize,
        /// Index of the fragment which is already the last fragment.
        last: usize,
    },
    /// Received a fragment which claims to be the last fragment, but we already
    /// received a (non-last) fragment with a larger index.
    #[display(
        "received last fragment {index}, but we already received fragment {max} with a larger \
         index"
    )]
    InvalidLastFrag {
        /// Index of the fragment received.
        index: usize,
        /// Index of the largest fragment we have received up to now.
        max: usize,
    },
    /// Received a non-last fragment which has an invalid length.
    ///
    /// All non-last fragments must be the same size.
    #[display("non-last fragment {index} has invalid length {len}, expected {expected}")]
    InvalidPayloadLength {
        /// Index of the fragment received.
        index: usize,
        /// Length of the fragment received.
        len: usize,
        /// Expected fragment length.
        expected: usize,
    },
    /// Received a non-last fragment beyond the known end of the message.
    #[display("received fragment {index} beyond last fragment {last}")]
    BeyondLastFrag {
        /// Index of the fragment received.
        index: usize,
        /// Index of the last fragment.
        last: usize,
    },
    /// The fragment's offset and length cannot fit in the address space.
    #[display(
        "fragment {index} with maximum length {max_frag_len} and payload length {len} exceeds \
         addressable memory"
    )]
    FragmentOffsetOverflow {
        /// Index of the fragment received.
        index: usize,
        /// Maximum fragment length used to compute its offset.
        max_frag_len: usize,
        /// Length of the fragment received.
        len: usize,
    },
}

#[derive(Clone, TypeSize)]
struct MessageBuf {
    #[typesize(skip)]
    first_recv_at: Option<Instant>,
    last_frag_index: Option<usize>,
    max_frag_index: usize,
    num_frags_recv: usize,
    #[typesize(with = crate::size::of_bitvec)]
    frag_indices_recv: BitVec,
    payload: Vec<u8>,
}

impl MessageBuf {
    fn extra_memory_used(&self) -> usize {
        self.payload.capacity() + self.frag_indices_recv.capacity() / 8
    }
}

/// Validated fragment layout. Its message must not be modified or evicted
/// between preparation and insertion.
#[derive(Debug)]
pub(crate) struct PreparedFragment<'a> {
    seq: MessageSeq,
    index: usize,
    start: usize,
    end: usize,
    num_indices: usize,
    last: bool,
    payload: &'a [u8],
    pub(crate) memory_required: usize,
}

impl fmt::Debug for FragmentReceiver {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let seqs = self.msgs.keys().collect::<Vec<_>>();
        f.debug_struct("FragmentReceiver")
            .field("msgs", &seqs)
            .field("buffered_size", &self.buffered_size)
            .finish()
    }
}

impl FragmentReceiver {
    pub(crate) fn extra_memory_used(&self) -> usize {
        self.msgs.capacity() * (size_of::<MessageSeq>() + size_of::<MessageBuf>())
            + self.buffered_size
    }

    pub(crate) fn discard_before(&mut self, pending: MessageSeq) {
        self.msgs.retain(|seq, buf| {
            let keep = *seq >= pending;
            if !keep {
                replace_cached(&mut self.buffered_size, buf.extra_memory_used(), 0);
            }
            keep
        });
    }

    pub(crate) fn eviction_candidates(
        &self,
        protected: Option<MessageSeq>,
    ) -> impl Iterator<Item = (MessageSeq, Instant)> + '_ {
        self.msgs.iter().filter_map(move |(seq, msg)| {
            (Some(*seq) != protected)
                .then_some(msg.first_recv_at)
                .flatten()
                .map(|at| (*seq, at))
        })
    }

    pub(crate) fn discard(&mut self, seq: MessageSeq) {
        if let Some(buf) = self.msgs.remove(&seq) {
            replace_cached(&mut self.buffered_size, buf.extra_memory_used(), 0);
        }
    }

    /// Gets the number of messages which are currently being reassembled, but
    /// have not been fully reassembled yet.
    #[must_use]
    pub fn len(&self) -> usize {
        self.msgs.len()
    }

    /// Returns `true` if there are no messages which are currently being
    /// reassembled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }

    pub(crate) fn expire(&mut self, now: Instant, timeout: Duration) {
        self.msgs.retain(|_, buf| {
            let keep = buf
                .first_recv_at
                .is_none_or(|first| now.saturating_duration_since(first) < timeout);
            if !keep {
                replace_cached(&mut self.buffered_size, buf.extra_memory_used(), 0);
            }
            keep
        });
    }

    /// Receives a single message fragment created from [`split`] and attempts
    /// to reassemble it into a full message.
    ///
    /// - `max_frag_len`: maximum length of a single non-last fragment; must be
    ///   the same as the value passed into [`split`]
    /// - `mem_left`: number of bytes of memory left for buffering messages
    /// - `msg_seq`: sequence number of this message; all fragments for a single
    ///   message sequence will be reassembled as one message
    /// - `position`: index + last state of this fragment
    /// - `payload`: fragment payload
    ///
    /// If all fragments of this message have been received, this will return
    /// `Ok(Some(msg))` with ownership of the reassembled message bytes.
    ///
    /// # Memory exhaustion
    ///
    /// One potential attack vector is a malicious sender sending many fragments
    /// of partially-completed messages, but never sending the final fragments,
    /// so the receiver is forced to keep the fragments in memory. To avoid
    /// this, receivers define a memory limit via `mem_left`, and if buffering a
    /// packet will result in using too much memory, this returns a
    /// [`ReassembleError::OutOfMemory`]. This receiver only reports the error;
    /// the transport disconnects rather than acknowledging rejected fragments.
    ///
    /// # Errors
    ///
    /// Errors if the fragment received is unexpected for the current state of
    /// reassembly.
    ///
    /// [`ReassembleError::AlreadyReceivedFrag`] is harmless and can happen due
    /// to duplicate packets or retransmissions. Other errors reject the
    /// fragment without changing the reassembly state. They must not be
    /// ignored when acknowledging reliable fragments.
    ///
    /// # Panics
    ///
    /// Panics if `max_frag_len` is 0.
    pub fn reassemble(
        &mut self,
        max_frag_len: MinSize,
        mem_left: usize,
        msg_seq: MessageSeq,
        position: FragmentPosition,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, ReassembleError> {
        let Some(prepared) = self.prepare(max_frag_len, msg_seq, position, payload)? else {
            // Keep the public 0.21 duplicate result. The transport uses prepare
            // directly and accepts duplicates without allocating or evicting.
            return Err(ReassembleError::AlreadyReceivedFrag {
                index: usize::from(position.index()),
            });
        };
        if prepared.memory_required > mem_left {
            return Err(ReassembleError::OutOfMemory {
                required: prepared.memory_required,
                left: mem_left,
            });
        }
        // Standalone reassembly has no expiry policy and must remain usable
        // without a clock on no_std platforms.
        Ok(self.insert_prepared(prepared, None))
    }

    pub(crate) fn prepare<'a>(
        &self,
        max_frag_len: MinSize,
        msg_seq: MessageSeq,
        position: FragmentPosition,
        payload: &'a [u8],
    ) -> Result<Option<PreparedFragment<'a>>, ReassembleError> {
        assert!(max_frag_len.0 > 0);

        let buf = self.msgs.get(&msg_seq);
        let frag_index = usize::from(position.index());

        // check if this fragment has been received yet
        if buf.is_some_and(|buf| buf.frag_indices_recv.get(frag_index) == Some(true)) {
            return Ok(None);
        }

        // Validate before allocating or changing the buffer. In particular,
        // fragments beyond a known last index must not count towards
        // completion.
        if position.is_last() {
            if let Some(buf) = buf {
                if let Some(last) = buf.last_frag_index {
                    return Err(ReassembleError::AlreadyReceivedLastFrag {
                        index: frag_index,
                        last,
                    });
                }
                if frag_index < buf.max_frag_index {
                    return Err(ReassembleError::InvalidLastFrag {
                        index: frag_index,
                        max: buf.max_frag_index,
                    });
                }
            }
        } else {
            if payload.len() != usize::from(max_frag_len) {
                return Err(ReassembleError::InvalidPayloadLength {
                    index: frag_index,
                    len: payload.len(),
                    expected: usize::from(max_frag_len),
                });
            }
            if let Some(last) = buf.and_then(|buf| buf.last_frag_index)
                && frag_index > last
            {
                return Err(ReassembleError::BeyondLastFrag {
                    index: frag_index,
                    last,
                });
            }
        }

        // Validate the payload range without allocating.
        let overflow = || ReassembleError::FragmentOffsetOverflow {
            index: frag_index,
            max_frag_len: usize::from(max_frag_len),
            len: payload.len(),
        };
        let start = frag_index
            .checked_mul(usize::from(max_frag_len))
            .ok_or_else(overflow)?;
        let end = start.checked_add(payload.len()).ok_or_else(overflow)?;

        // try to resize buffers to make room for this fragment,
        // checking if we have enough memory
        let payload_capacity = buf.map_or(0, |buf| buf.payload.capacity());
        let indices_capacity = buf.map_or(0, |buf| buf.frag_indices_recv.capacity());
        let payload_mem_required = end.saturating_sub(payload_capacity);
        let num_indices = frag_index.checked_add(1).ok_or_else(overflow)?;
        let indices_mem_required = num_indices.saturating_sub(indices_capacity).div_ceil(8);

        let memory_required = payload_mem_required
            .checked_add(indices_mem_required)
            .ok_or_else(overflow)?;
        // we *may* end up reserving more memory than `memory_required`,
        // but this should be sufficient to prevent ridiculously sized allocs
        // and anyway, if we go over the memory limit later, we'll catch it
        // somewhere else
        Ok(Some(PreparedFragment {
            seq: msg_seq,
            index: frag_index,
            start,
            end,
            num_indices,
            last: position.is_last(),
            payload,
            memory_required,
        }))
    }

    pub(crate) fn insert_prepared(
        &mut self,
        frag: PreparedFragment<'_>,
        recv_at: Option<Instant>,
    ) -> Option<Vec<u8>> {
        let buf = self.msgs.entry(frag.seq).or_insert_with(|| MessageBuf {
            first_recv_at: recv_at,
            last_frag_index: None,
            max_frag_index: 0,
            num_frags_recv: 0,
            frag_indices_recv: BitVec::new(),
            payload: Vec::new(),
        });
        let before = buf.extra_memory_used();
        buf.payload.resize(buf.payload.len().max(frag.end), 0);

        let grow_len = frag.num_indices.saturating_sub(buf.frag_indices_recv.len());
        buf.frag_indices_recv.grow(grow_len, false);

        // update some meta stuff depending on if this is the last frag or not
        if frag.last {
            buf.last_frag_index = Some(frag.index);
        }
        buf.payload
            .get_mut(frag.start..frag.end)
            .expect("prepared fragment range fits the resized payload")
            .copy_from_slice(frag.payload);

        // only update the buffer meta once we know there are no more error
        // paths
        buf.frag_indices_recv.set(frag.index, true);
        buf.max_frag_index = buf.max_frag_index.max(frag.index);

        // if we've fully reassembled the message, we can return it now
        if buf
            .last_frag_index
            .is_some_and(|last| buf.num_frags_recv >= last)
        {
            let buf = self.msgs.remove(&frag.seq).expect(
                "we already have a mut ref to the buffer at this key, so we should be able to \
                 remove and take ownership of it",
            );
            replace_cached(&mut self.buffered_size, before, 0);
            Some(buf.payload)
        } else {
            // this happens separately from the other buffer meta update
            // so that the `if` condition above works properly
            buf.num_frags_recv += 1;
            replace_cached(&mut self.buffered_size, before, buf.extra_memory_used());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use {super::*, std::println};

    #[test]
    fn standalone_duplicate_keeps_021_error_without_a_clock() {
        let mut recv = FragmentReceiver::default();
        let seq = MessageSeq::new(0);
        let position = FragmentPosition::ZERO_NON_LAST;
        assert_eq!(
            recv.reassemble(MinSize(4), usize::MAX, seq, position, b"aaaa"),
            Ok(None)
        );
        let before = recv.msgs[&seq].clone();
        assert_eq!(
            recv.reassemble(MinSize(4), 0, seq, position, b"aaaa"),
            Err(ReassembleError::AlreadyReceivedFrag { index: 0 })
        );
        assert!(
            recv.prepare(MinSize(4), seq, position, b"aaaa")
                .unwrap()
                .is_none()
        );
        assert_eq!(recv.msgs[&seq].payload, before.payload);
        assert_eq!(recv.msgs[&seq].frag_indices_recv, before.frag_indices_recv);
        assert!(recv.msgs[&seq].first_recv_at.is_none());
    }

    #[test]
    fn rejected_fragment_does_not_create_a_buffer() {
        let mut recv = FragmentReceiver::default();
        assert!(matches!(
            recv.reassemble(
                MinSize(4),
                0,
                MessageSeq::new(0),
                FragmentPosition::last(1u16).unwrap(),
                b"last",
            ),
            Err(ReassembleError::OutOfMemory { .. })
        ));
        assert!(recv.is_empty());
        assert_eq!(recv.msgs.capacity(), 0);

        assert!(matches!(
            recv.reassemble(
                MinSize(4),
                usize::MAX,
                MessageSeq::new(0),
                FragmentPosition::ZERO_NON_LAST,
                b"bad",
            ),
            Err(ReassembleError::InvalidPayloadLength { .. })
        ));
        assert!(recv.is_empty());
        assert_eq!(recv.msgs.capacity(), 0);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn fragment_offset_overflow_does_not_allocate() {
        let mut recv = FragmentReceiver::default();
        assert!(matches!(
            recv.reassemble(
                MinSize::MAX,
                usize::MAX,
                MessageSeq::new(0),
                FragmentPosition::last(1u16).unwrap(),
                b"last",
            ),
            Err(ReassembleError::FragmentOffsetOverflow { .. })
        ));
        assert!(recv.is_empty());
        assert_eq!(recv.msgs.capacity(), 0);
    }

    #[test]
    fn rejected_fragment_does_not_change_existing_buffer() {
        let mut recv = FragmentReceiver::default();
        let seq = MessageSeq::new(0);
        recv.reassemble(
            MinSize(4),
            usize::MAX,
            seq,
            FragmentPosition::ZERO_NON_LAST,
            b"aaaa",
        )
        .unwrap();
        let before = recv.msgs[&seq].clone();
        assert!(before.first_recv_at.is_none());
        let payload_capacity = recv.msgs[&seq].payload.capacity();
        let indices_capacity = recv.msgs[&seq].frag_indices_recv.capacity();

        assert!(matches!(
            recv.reassemble(
                MinSize(4),
                0,
                seq,
                FragmentPosition::last(100u16).unwrap(),
                b"b"
            ),
            Err(ReassembleError::OutOfMemory { .. })
        ));
        assert!(matches!(
            recv.reassemble(
                MinSize(4),
                usize::MAX,
                seq,
                FragmentPosition::non_last(100u16).unwrap(),
                b"bad"
            ),
            Err(ReassembleError::InvalidPayloadLength { .. })
        ));
        let after = &recv.msgs[&seq];
        assert_eq!(after.payload, before.payload);
        assert_eq!(after.payload.capacity(), payload_capacity);
        assert_eq!(after.frag_indices_recv, before.frag_indices_recv);
        assert_eq!(after.frag_indices_recv.capacity(), indices_capacity);
        assert_eq!(after.last_frag_index, before.last_frag_index);
        assert_eq!(after.max_frag_index, before.max_frag_index);
        assert_eq!(after.num_frags_recv, before.num_frags_recv);
    }

    #[test]
    fn fragments_beyond_last_cannot_complete_a_message() {
        let mut recv = FragmentReceiver::default();
        let seq = MessageSeq::new(0);
        assert_eq!(
            recv.reassemble(
                MinSize(4),
                usize::MAX,
                seq,
                FragmentPosition::last(2u16).unwrap(),
                b"c"
            )
            .unwrap(),
            None
        );
        assert_eq!(
            recv.reassemble(
                MinSize(4),
                usize::MAX,
                seq,
                FragmentPosition::non_last(3u16).unwrap(),
                b"bad!"
            )
            .unwrap_err(),
            ReassembleError::BeyondLastFrag { index: 3, last: 2 }
        );
        assert_eq!(
            recv.reassemble(
                MinSize(4),
                usize::MAX,
                seq,
                FragmentPosition::ZERO_NON_LAST,
                b"aaaa"
            )
            .unwrap(),
            None
        );
        assert_eq!(
            recv.reassemble(
                MinSize(4),
                usize::MAX,
                seq,
                FragmentPosition::non_last(1u16).unwrap(),
                b"bbbb"
            )
            .unwrap(),
            Some(b"aaaabbbbc".to_vec())
        );
        assert!(recv.is_empty());
    }

    #[test]
    fn round_trip() {
        let max_frag_len = MinSize(8);
        let msg = Bytes::from_static(b"hello world! goodbye woorld!");

        let mut iter = split(max_frag_len, msg).unwrap();

        let mut recv = FragmentReceiver::default();
        let mem_left = 30;
        let msg_seq = MessageSeq::new(0);

        let (position, payload) = iter.next().unwrap();
        println!(
            "{:?}",
            recv.reassemble(max_frag_len, mem_left, msg_seq, position, &payload)
                .unwrap()
        );
        let (position, payload) = iter.next().unwrap();
        println!(
            "{:?}",
            recv.reassemble(max_frag_len, mem_left, msg_seq, position, &payload)
                .unwrap()
        );
        let (position, payload) = iter.next().unwrap();
        println!(
            "{:?}",
            recv.reassemble(max_frag_len, mem_left, msg_seq, position, &payload)
                .unwrap()
        );
        let (position, payload) = iter.next().unwrap();
        println!(
            "{:?}",
            recv.reassemble(max_frag_len, mem_left, msg_seq, position, &payload)
                .unwrap()
        );
    }
}
