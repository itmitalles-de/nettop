//! Terminal input outside the event loop, plus terminal hang-up detection.
//!
//! crossterm's Unix event source retries reads until they would block. A hung-up
//! terminal instead returns end-of-file (or EIO) forever, so `event::poll` and
//! `event::read` never return and spin a core. Reading on a dedicated thread
//! keeps the event loop free to observe termination signals and the hang-up.

use std::{
    io,
    os::fd::{AsRawFd, RawFd},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::Duration,
};

use crossterm::event::{self, Event};

/// Result of waiting for terminal input.
pub enum Input {
    Event(Event),
    Timeout,
    /// The reader failed or stopped; the error explains why.
    Failed(io::Error),
}

/// Keyboard and resize events read by a background thread.
pub struct Events {
    receiver: Receiver<io::Result<Event>>,
}

impl Events {
    /// Start reading terminal events. The thread ends with the process; after
    /// a hang-up it may spin inside crossterm until the event loop exits.
    pub fn start() -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(256);
        thread::Builder::new()
            .name("nettop-input".into())
            .spawn(move || {
                loop {
                    let event = event::read();
                    let failed = event.is_err();
                    if sender.send(event).is_err() || failed {
                        break;
                    }
                }
            })?;
        Ok(Self { receiver })
    }

    pub fn next(&self, timeout: Duration) -> Input {
        match self.receiver.recv_timeout(timeout) {
            Ok(Ok(event)) => Input::Event(event),
            Ok(Err(error)) => Input::Failed(error),
            Err(RecvTimeoutError::Timeout) => Input::Timeout,
            Err(RecvTimeoutError::Disconnected) => Input::Failed(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "terminal input ended",
            )),
        }
    }
}

/// Whether the terminal input was hung up or closed, for example because the
/// terminal window or SSH session went away, waiting at most `timeout` for it.
/// crossterm reads standard input whenever it is a terminal, which interactive
/// mode requires.
pub fn terminal_hung_up(timeout: Duration) -> bool {
    descriptor_hung_up(io::stdin().as_raw_fd(), timeout)
}

fn descriptor_hung_up(fd: RawFd, timeout: Duration) -> bool {
    // No requested events: poll reports only hang-up, error and invalid states.
    let mut descriptor = libc::pollfd {
        fd,
        events: 0,
        revents: 0,
    };
    let timeout = timeout.as_millis().min(i32::MAX as u128) as i32;
    let ready = unsafe { libc::poll(&mut descriptor, 1, timeout) };
    ready > 0 && descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};

    #[test]
    fn closed_peers_are_hang_ups() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        assert!(
            !descriptor_hung_up(reader.as_raw_fd(), Duration::ZERO),
            "open peer"
        );
        drop(writer);
        assert!(
            descriptor_hung_up(reader.as_raw_fd(), Duration::ZERO),
            "closed peer"
        );
    }
}
