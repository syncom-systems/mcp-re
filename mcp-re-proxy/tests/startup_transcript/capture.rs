// SPDX-License-Identifier: Apache-2.0
//! Spawning the real proxy and collecting its stderr into a [`Transcript`].

use std::io::BufRead;
use std::io::BufReader;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;
use std::time::Instant;

use super::classify::normalize;
use super::event::Outcome;
use super::event::StartupEvent;
use super::event::Transcript;

/// Deadline for one capture. Generous: a startup that binds and serves is quick, but a
/// freshly linked binary can spend seconds in the loader on a loaded machine.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(90);

/// Run the real `mcp-re-proxy` with `args` and normalize what it reports.
///
/// Handles both shapes of startup uniformly:
///
/// * a config that is REFUSED — the process exits by itself and the transcript ends
///   with [`Outcome::Exited`] carrying the refusal line;
/// * a config that SERVES — the process would run forever, so reaching the serving
///   marker triggers a `SIGTERM` and the drain is captured too.
///
/// `SIGTERM`, not `kill`: the drain path is part of the behaviour being characterized,
/// and `Child::kill` sends `SIGKILL`, which would skip it.
pub fn capture(args: &[String]) -> Transcript {
    let binary = mcp_re_test_paths::resolve_runfile("MCP_RE_PROXY_CLI");
    let mut child = Command::new(&binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", binary.display()));
    let lines = stderr_lines(&mut child);

    let mut observed = Observed::default();
    let deadline = Instant::now() + CAPTURE_TIMEOUT;
    let outcome = loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break Outcome::TimedOut;
        }
        match lines.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => observed.absorb(line, &child),
            Err(RecvTimeoutError::Timeout) => {}
            // The pipe closed: the child is done writing, so reap it.
            Err(RecvTimeoutError::Disconnected) => break observed.finish(&mut child),
        }
    };

    Transcript {
        events: observed.events,
        outcome,
        raw: observed.raw,
    }
}

/// A reader thread feeding a channel: `read_line` on the child's pipe blocks, and the main
/// thread has to stay responsive enough to stop a proxy that has started serving.
fn stderr_lines(child: &mut Child) -> Receiver<String> {
    let stderr = child.stderr.take().expect("stderr is piped");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    rx
}

/// What one capture has seen so far.
#[derive(Default)]
struct Observed {
    raw: Vec<String>,
    events: Vec<StartupEvent>,
    stopped: bool,
}

impl Observed {
    /// Record one stderr line, stopping the proxy the first time it reports serving.
    fn absorb(&mut self, line: String, child: &Child) {
        if let Some(event) = normalize(&line) {
            let serving = event == StartupEvent::FleetServing;
            self.events.push(event);
            // Startup is over; stop it so the drain is observed rather than the harness
            // hanging on a process that will never exit.
            if serving && !self.stopped {
                self.stopped = true;
                send_sigterm(child);
            }
        }
        self.raw.push(line);
    }

    /// Reap the child once its pipe closed and say how the run ended.
    fn finish(&self, child: &mut Child) -> Outcome {
        let status = child.wait().expect("wait for the proxy");
        if self.stopped {
            return Outcome::ServedThenStopped;
        }
        Outcome::Exited {
            success: status.success(),
            refused: self.raw.last().cloned(),
        }
    }
}

/// Ask the proxy to shut down the way an orchestrator does.
fn send_sigterm(child: &Child) {
    // SAFETY: `kill(2)` with a pid this process owns and a valid signal number. The
    // child is still alive here — its stderr pipe has not closed — and the worst case
    // for a race is `ESRCH`, which is ignored.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
}
