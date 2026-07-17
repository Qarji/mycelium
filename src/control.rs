use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub struct SimControl {
    pub running: Arc<AtomicBool>,
    pub restart_requested: Arc<AtomicBool>,
}

impl SimControl {
    pub fn new(start_running: bool) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(start_running)),
            restart_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn run(&self) { self.running.store(true, Ordering::SeqCst); }
    pub fn stop(&self) { self.running.store(false, Ordering::SeqCst); }
    pub fn restart(&self) {
        self.restart_requested.store(true, Ordering::SeqCst);
        self.running.store(true, Ordering::SeqCst);
    }
    pub fn is_running(&self) -> bool { self.running.load(Ordering::SeqCst) }
    pub fn take_restart(&self) -> bool {
        self.restart_requested.swap(false, Ordering::SeqCst)
    }
}