use crate::payload::Payload;
use std::thread;

pub struct RunData {
    pub running_thread: Vec<(thread::JoinHandle<()>, Payload)>,
    pub runonce: Vec<Payload>,
}
