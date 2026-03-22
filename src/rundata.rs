use crate::payload::PO;
use std::thread;


//#[derive(Clone)]
pub struct RunData {
    pub running_thread_payload: Vec<(thread::JoinHandle<()>, PO)>,
    pub runonce_payload: Vec<PO>,

    pub running_thread_decoy_update: Vec<(thread::JoinHandle<()>, PO)>,
    pub runonce_decoy_update: Vec<PO>,

    pub running_thread_decoy_payload: Vec<(thread::JoinHandle<()>, PO)>,
    pub runonce_decoy_payload: Vec<PO>,

    pub loop_nb: u32,
    pub session_id: String,
}

// Manually implement Clone
impl Clone for RunData {
    fn clone(&self) -> Self {
        RunData {
            running_thread_payload: self
                .running_thread_payload
                .iter()
                .map(|(_, payload)| (dummy_join_handle(), payload.clone()))
                .collect(),

            runonce_payload: self.runonce_payload.clone(),

            running_thread_decoy_update: self
                .running_thread_decoy_update
                .iter()
                .map(|(_, payload)| (dummy_join_handle(), payload.clone()))
                .collect(),

            runonce_decoy_update: self.runonce_decoy_update.clone(),

            running_thread_decoy_payload: self
                .running_thread_decoy_payload
                .iter()
                .map(|(_, payload)| (dummy_join_handle(), payload.clone()))
                .collect(),

            runonce_decoy_payload: self.runonce_decoy_payload.clone(),

            loop_nb: self.loop_nb,
            session_id: self.session_id.clone(),
        }
    }
}

// Crée un thread bidon — à adapter selon ton besoin réel (tu peux même mettre `panic!()` dedans si jamais ça ne doit pas être utilisé)
fn dummy_join_handle() -> thread::JoinHandle<()> {
    thread::spawn(|| {})
}