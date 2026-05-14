use serde::Serialize;

#[derive(Serialize)]
pub struct JsonResponse {
    pub message: String,
}
