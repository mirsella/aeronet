//! See [`SessionSamplingPlugin`].

use {
    crate::{MessageStats, Transport, TransportConfig, packet::PacketSeq, seq_buf::SeqBuf},
    aeronet_io::{
        Session,
        packet::{PacketRtt, PacketStats},
    },
    bevy_app::prelude::*,
    bevy_ecs::prelude::*,
    bevy_platform::time::Instant,
    bevy_time::{Real, Time, Timer, TimerMode},
    core::time::Duration,
    derive_more::{Deref, DerefMut},
    ringbuf::{
        HeapRb,
        traits::{Consumer, RingBuffer},
    },
};

/// Periodically samples the state of [`Session`]s to gather statistics on the
/// connection and store them in [`SessionStats`].
///
/// Insert the [`SessionStatsSampling`] resource to override the sampling.
///
/// With this plugin, when [`Transport`] is added to a [`Session`],
/// [`SessionStats`] is automatically added with the capacity defined by
/// [`SessionStatsSampling`].
#[derive(Debug, Clone, Default)]
pub struct SessionSamplingPlugin;

impl Plugin for SessionSamplingPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<SessionStatsSampling>()
            .init_resource::<SamplingTimer>()
            .configure_sets(Update, SampleSessionStats)
            .add_systems(
                Update,
                (
                    update_sampling.run_if(resource_changed::<SessionStatsSampling>),
                    update_stats,
                )
                    .chain()
                    .in_set(SampleSessionStats),
            )
            .add_observer(add_session_stats);
    }
}

/// Configuration for sampling session statistics.
#[derive(Debug, Clone, Copy, Resource)]
pub struct SessionStatsSampling {
    /// Interval to gather samples at.
    pub interval: Duration,
    /// Default maximum number of samples to store for [`Session`]s.
    pub history_cap: usize,
}

impl SessionStatsSampling {
    /// Computes and creates a new sampling configuration.
    ///
    /// - `rate`: how many times to sample per second
    /// - `history_sec`: how many seconds of sample history to keep
    ///
    /// # Panics
    ///
    /// Panics if `rate` or `history_sec` are zero or negative.
    /// Panics if the sampling interval cannot be represented as a
    /// [`Duration`], or if `rate * history_sec` truncates to zero samples.
    #[must_use]
    pub fn new(rate: f64, history_sec: f64) -> Self {
        assert!(rate > 0.0);
        assert!(history_sec > 0.0);
        assert!(rate * history_sec > 0.0);

        let interval = Duration::from_secs_f64(1.0 / rate);
        #[expect(clippy::cast_sign_loss, reason = "`rate * history_sec` > 0.0")]
        #[expect(clippy::cast_possible_truncation, reason = "truncation is acceptable")]
        let history_cap = (rate * history_sec) as usize;
        assert!(history_cap > 0, "history must hold at least one sample");
        Self {
            interval,
            history_cap,
        }
    }

    /// Gets the sample rate, in samples per second.
    #[must_use]
    pub fn rate(&self) -> f64 {
        1.0 / self.interval.as_secs_f64()
    }

    /// Gets the number of seconds of history that are stored.
    #[must_use]
    pub fn history_sec(&self) -> f64 {
        #[expect(clippy::cast_precision_loss, reason = "precision loss is acceptable")]
        let history = self.history_cap as f64 * self.interval.as_secs_f64();
        history
    }
}

impl Default for SessionStatsSampling {
    fn default() -> Self {
        Self::new(10.0, 15.0)
    }
}

/// System set in which [`Session`] statistics are sampled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, SystemSet)]
pub struct SampleSessionStats;

/// Stores [`SessionStatsSample`]s for [`Session`] and [`Transport`] statistics.
///
/// This uses a [`HeapRb`] internally to overwrite old samples, and avoid
/// unbounded growth.
#[derive(Component, Deref, DerefMut)]
pub struct SessionStats(pub HeapRb<SessionStatsSample>);

impl SessionStats {
    /// Creates a new statistics buffer with the given capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HeapRb::new(capacity))
    }

    /// Gets the last sample which has been sampled into this stats buffer.
    #[must_use]
    pub fn last(&self) -> Option<&SessionStatsSample> {
        self.0.iter().next_back()
    }
}

/// Single sample of collected [`Session`] and [`Transport`] statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct SessionStatsSample {
    /// [`PacketRtt`], if it was present on the [`Session`].
    pub packet_rtt: Option<Duration>,
    /// [`Transport::rtt`]'s [`RttEstimator::get`].
    ///
    /// [`RttEstimator::get`]: crate::rtt::RttEstimator::get
    pub msg_rtt: Duration,
    /// [`Transport::rtt`]'s [`RttEstimator::conservative`].
    ///
    /// [`RttEstimator::conservative`]: crate::rtt::RttEstimator::conservative
    pub msg_crtt: Duration,
    /// [`PacketStats`] at the time of sampling.
    pub packets_total: PacketStats,
    /// [`PacketStats`] at the time of sampling, minus the previous sample's
    /// [`SessionStatsSample::packets_total`].
    pub packets_delta: PacketStats,
    /// [`Transport::stats`] at the time of sampling.
    pub msgs_total: MessageStats,
    /// [`Transport::stats`] at the time of sampling, minus the previous
    /// sample's [`SessionStatsSample::msgs_total`].
    pub msgs_delta: MessageStats,
    /// [`Transport::memory_used`] at the time of sampling.
    pub mem_used: usize,
    /// [`TransportConfig::max_memory_usage`] at the time of sampling.
    pub mem_max: usize,
    /// What proportion of packets sent recently are believed to have been lost
    /// in transit.
    ///
    /// If the receiver has not acknowledged a packet within a variable time
    /// threshold (which is a function of the RTT), then they have probably lost
    /// that packet.
    ///
    /// # Algorithm
    ///
    /// We keep a rolling buffer of the 1024 last flushed packets, separately
    /// from retransmission metadata. Once a packet is older than [the PTO]
    /// multiplied by [`TransportConfig::packet_lost_threshold_factor`], we
    /// expect its acknowledgement. Eligible packets without an acknowledgement
    /// count as lost. Late acknowledgements correct the retained outcome.
    ///
    /// Returns zero when no retained packets are old enough to be eligible.
    ///
    /// [the PTO]: crate::rtt::RttEstimator::pto
    pub loss: f64,
}

fn add_session_stats(
    trigger: On<Add, Transport>,
    mut commands: Commands,
    sampling: Res<SessionStatsSampling>,
) {
    let entity = trigger.event_target();
    commands
        .entity(entity)
        .insert(SessionStats::with_capacity(sampling.history_cap));
}

fn update_sampling(
    sampling: Res<SessionStatsSampling>,
    mut timer: ResMut<SamplingTimer>,
    mut sessions: Query<&mut SessionStats>,
) {
    *timer = SamplingTimer(Timer::new(sampling.interval, TimerMode::Repeating));
    for mut stats in &mut sessions {
        *stats = SessionStats::with_capacity(sampling.history_cap);
    }
}

#[derive(Debug, Deref, DerefMut, Resource)]
struct SamplingTimer(Timer);

impl FromWorld for SamplingTimer {
    fn from_world(world: &mut World) -> Self {
        let sampling = world.resource::<SessionStatsSampling>();
        Self(Timer::new(sampling.interval, TimerMode::Repeating))
    }
}

fn update_stats(
    time: Res<Time<Real>>,
    mut timer: ResMut<SamplingTimer>,
    mut sessions: Query<(
        &mut SessionStats,
        &Session,
        Option<&PacketRtt>,
        &Transport,
        &TransportConfig,
    )>,
) {
    timer.tick(time.delta());
    if !timer.just_finished() {
        return;
    }

    let now = Instant::now();
    for (mut stats, session, packet_rtt, transport, transport_config) in &mut sessions {
        let loss = compute_loss(transport, transport_config, now);
        let last_sample = stats.iter().next_back().copied().unwrap_or_default();
        let sample = SessionStatsSample {
            packet_rtt: packet_rtt.map(|rtt| **rtt),
            msg_rtt: transport.rtt().get(),
            msg_crtt: transport.rtt().conservative(),
            packets_total: session.stats,
            packets_delta: session.stats - last_sample.packets_total,
            msgs_total: transport.stats(),
            msgs_delta: transport.stats() - last_sample.msgs_total,
            mem_used: transport.memory_used(),
            mem_max: transport_config.max_memory_usage,
            loss,
        };
        stats.push_overwrite(sample);
    }
}

fn compute_loss(transport: &Transport, config: &TransportConfig, now: Instant) -> f64 {
    let threshold = transport.rtt().pto().as_secs_f64() * config.packet_lost_threshold_factor;
    transport.packet_loss.loss(now, threshold)
}

const LOSS_HISTORY_CAP: u16 = 1024;

/// Separate from retransmission metadata, which is removed as soon as
/// acknowledged.
#[derive(Debug, typesize::derive::TypeSize)]
pub(crate) struct PacketLossHistory {
    packets: SeqBuf<PacketOutcome, 1024>,
    latest: Option<PacketSeq>,
}

#[derive(Debug, typesize::derive::TypeSize)]
struct PacketOutcome {
    #[typesize(with = crate::size::of_instant)]
    flushed_at: Instant,
    acked: bool,
}

impl PacketLossHistory {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            packets: SeqBuf::new_from_fn(|_| PacketOutcome {
                flushed_at: now,
                acked: false,
            }),
            latest: None,
        }
    }

    pub(crate) fn record(&mut self, seq: PacketSeq, now: Instant) {
        self.packets.insert(
            seq.0.0,
            PacketOutcome {
                flushed_at: now,
                acked: false,
            },
        );
        self.latest = Some(seq);
    }

    pub(crate) fn ack(&mut self, seq: PacketSeq) {
        if let Some(packet) = self.packets.get_mut(seq.0.0) {
            packet.acked = true;
        }
    }

    pub(crate) const EXTRA_SIZE: usize =
        LOSS_HISTORY_CAP as usize * (size_of::<u16>() + size_of::<PacketOutcome>());

    fn loss(&self, now: Instant, threshold_sec: f64) -> f64 {
        let Some(latest) = self.latest else {
            return 0.0;
        };
        let mut eligible = 0u32;
        let mut lost = 0u32;
        for offset in 0..LOSS_HISTORY_CAP {
            let seq = latest - PacketSeq::new(offset);
            let Some(packet) = self.packets.get(seq.0.0) else {
                continue;
            };
            if now
                .saturating_duration_since(packet.flushed_at)
                .as_secs_f64()
                >= threshold_sec
            {
                eligible += 1;
                lost += u32::from(!packet.acked);
            }
        }
        if eligible == 0 {
            0.0
        } else {
            f64::from(lost) / f64::from(eligible)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::float_cmp,
        reason = "loss ratios 0, 0.5 and 1 are exactly representable"
    )]
    use {
        super::*,
        crate::packet::{Acknowledge, PacketHeader},
        aeronet_io::Session,
        octs::Write,
    };

    #[test]
    fn one_sample_history() {
        assert_eq!(SessionStatsSampling::new(0.5, 2.0).history_cap, 1);
    }

    #[test]
    #[should_panic(expected = "history must hold at least one sample")]
    fn rejects_history_truncating_to_zero() {
        let _ = SessionStatsSampling::new(0.5, 1.0);
    }

    #[test]
    fn loss_waits_for_packet_age_and_accepts_late_acks() {
        let now = Instant::now();
        let mut history = PacketLossHistory::new(now);
        assert_eq!(history.loss(now, 1.0), 0.0);
        let seq = PacketSeq::new(0);
        history.record(seq, now);
        assert_eq!(history.loss(now, 1.0), 0.0);
        let later = now + Duration::from_secs(1);
        assert_eq!(history.loss(later, 1.0), 1.0);
        history.ack(seq);
        assert_eq!(history.loss(later, 1.0), 0.0);
        history.ack(seq);
        assert_eq!(history.loss(later, 1.0), 0.0);
    }

    #[test]
    fn newer_acks_do_not_hide_older_loss() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut history = PacketLossHistory::new(now);
        for seq in 0..2 {
            history.record(PacketSeq::new(seq), now);
        }
        history.record(PacketSeq::new(2), later);
        history.ack(PacketSeq::new(2));
        history.ack(PacketSeq::new(1));
        assert_eq!(history.loss(later, 1.0), 0.5);
    }

    #[test]
    fn eviction_and_sequence_wrap_preserve_packet_identity() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut history = PacketLossHistory::new(now);
        let first = PacketSeq::new(u16::MAX);
        history.record(first, now);
        assert_eq!(history.loss(later, 1.0), 1.0);
        for offset in 1..=LOSS_HISTORY_CAP {
            history.record(first + PacketSeq::new(offset), later);
        }
        assert_eq!(history.loss(later, 1.0), 0.0);
        history.ack(first);
        assert_eq!(history.loss(later, 0.0), 1.0);
        for offset in 1..=LOSS_HISTORY_CAP {
            history.ack(first + PacketSeq::new(offset));
        }
        assert_eq!(history.loss(later, 0.0), 0.0);
    }

    #[test]
    fn loss_tracks_flushes_and_received_acknowledgements() {
        let now = Instant::now();
        let session = Session::new(now, 1024);
        let lanes = [crate::lane::LaneKind::ReliableOrdered];
        let mut transport = Transport::new(&session, lanes, lanes, now).unwrap();
        let config = TransportConfig {
            packet_lost_threshold_factor: 0.0,
            ..TransportConfig::default()
        };
        assert_eq!(crate::send::flush_on(&mut transport, now, 1024).count(), 1);
        assert_eq!(compute_loss(&transport, &config, now), 1.0);
        let mut acks = Acknowledge::default();
        acks.ack(PacketSeq::new(0));
        let mut packet = Vec::new();
        packet
            .write(PacketHeader {
                seq: PacketSeq::new(0),
                acks,
            })
            .unwrap();
        crate::recv::recv_on(&mut transport, &config, now, &packet).unwrap();
        assert_eq!(transport.num_unacked_packets(), 0);
        assert_eq!(compute_loss(&transport, &config, now), 0.0);
    }
}
