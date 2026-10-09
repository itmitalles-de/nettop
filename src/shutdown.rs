//! Cooperative terminal shutdown for externally delivered termination signals.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use signal_hook::{
    SigId,
    consts::{SIGHUP, SIGINT, SIGTERM},
    flag, low_level,
};

/// Keep this guard alive until the terminal has been restored. Handlers only set
/// a flag; the main event loop performs cleanup outside the signal handler.
pub struct SignalGuard {
    requested: Arc<AtomicBool>,
    handlers: Vec<SigId>,
}

impl SignalGuard {
    pub fn new() -> io::Result<Self> {
        let mut guard = Self {
            requested: Arc::new(AtomicBool::new(false)),
            handlers: Vec::with_capacity(3),
        };
        for signal in [SIGTERM, SIGINT, SIGHUP] {
            guard
                .handlers
                .push(flag::register(signal, Arc::clone(&guard.requested))?);
        }
        Ok(guard)
    }

    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::Relaxed)
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for handler in self.handlers.drain(..) {
            low_level::unregister(handler);
        }
    }
}
