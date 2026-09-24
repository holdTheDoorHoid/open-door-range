//! **Long-running attacks, and the bar that never finishes.**
//!
//! Two drills are about cost rather than about capability, and both of them are
//! ruined by an interface that lets the attack complete.
//!
//! Drill 4.2 shortens the MAC so a forgery finishes while a learner watches.
//! The drill says so in as many words. But a learner who runs it and sees "MAC
//! forged" has *experienced* something that does not happen in the time they
//! just spent, and experience overwrites text. `docs/UI.md` decided the answer:
//! **run the real one on a bar that never finishes.** The shortened attack
//! completes and the drill proceeds; alongside it the genuine computation
//! starts, crawls, and is still going when the tab closes.
//!
//! Drill 1.5 is the same lesson without the trick. It is not a flag at all — it
//! ends on a number, and the number is the wall-clock cost of sweeping the
//! whole credential space at the wire timing the learner chose.
//!
//! # The one place wall-clock time enters
//!
//! [`Task::state`] takes elapsed milliseconds from the caller. That is
//! deliberate and it is the only wall clock anywhere in this workspace: it is
//! not part of the simulation, it exists so the bar crawls at a rate a person
//! can feel, and nothing about a flag depends on it (`site/ENGINE-API.md` §10).
//!
//! # The rates are arithmetic, not drama
//!
//! Every rate here is measured from the engine rather than chosen for effect.
//! The MAC forgery's rate is `MacForger::us_per_attempt`, which is one round
//! trip on the bus the drill is actually running at the baud rate it is
//! actually running at. The sweep's rate is `BruteForcer::us_per_credential`,
//! which is one Wiegand frame plus the settle time at the timing the bench is
//! configured with. Turn the baud rate up and both numbers move, which is the
//! point of letting a learner turn them.

use alloc::string::String;
use alloc::vec::Vec;

/// **A computation that is running because its size is the lesson.**
#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    /// A stable id: `"mac-forge"`, `"wiegand-sweep"`.
    pub id: &'static str,
    /// What the genuine computation is.
    pub label: String,
    /// What the rigged one was, when the drill ran a rigged one.
    pub short_label: String,
    /// Why the number is what it is. Shown under the bar.
    pub note: String,
    /// How many candidates the whole space holds.
    pub total: u128,
    /// How many candidates a second, measured from the engine.
    pub per_second: f64,
    /// Whether the shortened run has already completed.
    pub short_done: bool,
    /// The projected duration, in the engine's own words.
    ///
    /// Duration only. `site/ENGINE-API.md` shows a calendar date beside it, and
    /// the date is the site's to render: this engine has no wall clock and no
    /// epoch, and inventing one here to print "27 March 2035" would be the
    /// engine lying about what it knows.
    pub projected: String,
}

impl Task {
    /// Where the bar is after this many wall-clock milliseconds.
    pub fn state(&self, elapsed_ms: u64) -> TaskState {
        let done_f = (elapsed_ms as f64 / 1000.0) * self.per_second;
        let done = if done_f <= 0.0 {
            0u128
        } else {
            let capped = done_f.min(self.total as f64);
            capped as u128
        };
        let remaining = self.total.saturating_sub(done);
        let fraction = if self.total == 0 {
            1.0
        } else {
            done as f64 / self.total as f64
        };
        let remaining_seconds = if self.per_second > 0.0 {
            remaining as f64 / self.per_second
        } else {
            f64::INFINITY
        };
        TaskState {
            id: self.id,
            label: self.label.clone(),
            short_label: self.short_label.clone(),
            short_done: self.short_done,
            note: self.note.clone(),
            done,
            total: self.total,
            fraction,
            remaining_seconds,
            projected: self.projected.clone(),
        }
    }
}

/// **A snapshot of a long-running task**, shaped for
/// `site/ENGINE-API.md` §10's `TaskState`.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskState {
    /// The task id.
    pub id: &'static str,
    /// The genuine computation's label.
    pub label: String,
    /// The shortened run's label.
    pub short_label: String,
    /// Whether the shortened run finished.
    pub short_done: bool,
    /// Why the number is what it is.
    pub note: String,
    /// Candidates tried so far.
    pub done: u128,
    /// Candidates in the whole space.
    pub total: u128,
    /// `done / total`, between 0 and 1.
    pub fraction: f64,
    /// Seconds of wall clock still to go.
    pub remaining_seconds: f64,
    /// The projected duration in words.
    pub projected: String,
}

impl TaskState {
    /// Whether this task has finished. The genuine ones never do.
    pub fn is_finished(&self) -> bool {
        self.done >= self.total
    }
}

/// The set of tasks a drill starts, if any.
pub type Tasks = Vec<Task>;
