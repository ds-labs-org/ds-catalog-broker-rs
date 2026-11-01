//! SIGINT and SIGTERM, as one reusable stream.
//!
//! The listeners are registered once, by [`Signals::install`], and kept for
//! the life of the process. A signal that arrives between two calls to
//! [`Signals::next`] stays pending on its listener and is returned by the
//! next call, so a second signal sent while the first is being handled is
//! not lost.

#[cfg(unix)]
use tokio::signal::unix::{Signal, SignalKind, signal};

/// The process's SIGINT and SIGTERM listeners.
pub struct Signals {
    #[cfg(unix)]
    interrupt: Option<Signal>,
    #[cfg(unix)]
    terminate: Option<Signal>,
}

impl Signals {
    /// Register the listeners. Must be called inside a Tokio runtime. A
    /// signal that cannot be listened for is logged and never delivered.
    #[cfg(unix)]
    pub fn install() -> Self {
        let listen = |kind: SignalKind, name: &str| match signal(kind) {
            Ok(signal) => Some(signal),
            Err(err) => {
                tracing::error!(error = %err, "cannot listen for {name}");
                None
            }
        };
        Self {
            interrupt: listen(SignalKind::interrupt(), "SIGINT"),
            terminate: listen(SignalKind::terminate(), "SIGTERM"),
        }
    }

    /// Register the listeners. Without Unix signals only Ctrl-C exists, and
    /// it is registered on each call of [`Signals::next`].
    #[cfg(not(unix))]
    pub fn install() -> Self {
        Self {}
    }

    /// Wait for the next SIGINT or SIGTERM and name it.
    #[cfg(unix)]
    pub async fn next(&mut self) -> &'static str {
        async fn recv(signal: &mut Option<Signal>) {
            match signal {
                Some(signal) => {
                    signal.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        }
        tokio::select! {
            () = recv(&mut self.interrupt) => "SIGINT",
            () = recv(&mut self.terminate) => "SIGTERM",
        }
    }

    /// Wait for the next Ctrl-C and name it.
    #[cfg(not(unix))]
    pub async fn next(&mut self) -> &'static str {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "cannot listen for SIGINT");
            std::future::pending::<()>().await;
        }
        "SIGINT"
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn send(signal: &str) {
        let status = std::process::Command::new("kill")
            .args([format!("-{signal}"), std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Two signals sent before the first is consumed are both delivered.
    #[tokio::test]
    async fn a_second_signal_sent_before_the_first_is_handled_is_not_lost() {
        let mut signals = Signals::install();
        send("TERM");
        send("INT");
        let mut seen = vec![signals.next().await, signals.next().await];
        seen.sort_unstable();
        assert_eq!(seen, ["SIGINT", "SIGTERM"]);
    }

    /// Two of the same signal are delivered separately, and with
    /// listeners that live across calls, not collapsed or dropped.
    #[tokio::test]
    async fn a_signal_between_two_waits_is_kept_for_the_second_wait() {
        let mut signals = Signals::install();
        send("TERM");
        assert_eq!(signals.next().await, "SIGTERM");
        send("INT");
        assert_eq!(signals.next().await, "SIGINT");
    }
}
