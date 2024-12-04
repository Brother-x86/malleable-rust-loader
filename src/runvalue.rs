use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ttt {
    pub peer_public_key_bytes: Vec<u8>,
    pub sign_bytes: Vec<u8>,
}
