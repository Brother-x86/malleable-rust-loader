use crate::payload::Payload;
use std::thread;

pub struct RunData {
    pub running_thread_payload: Vec<(thread::JoinHandle<()>, Payload)>,
    pub runonce_payload: Vec<Payload>,

    pub running_thread_decoy_update: Vec<(thread::JoinHandle<()>, Payload)>,
    pub runonce_decoy_update: Vec<Payload>,

    pub running_thread_decoy_payload: Vec<(thread::JoinHandle<()>, Payload)>,
    pub runonce_decoy_payload: Vec<Payload>,

    pub loop_nb: u32,
    pub session_id: String,
}
