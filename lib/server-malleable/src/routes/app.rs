use crate::handlers::handler1::handle_hello;
use crate::handlers::handler1::handle_posto;
use axum::{routing::get,routing::post , Router};

pub fn build_routes() -> Router {
    let app = Router::new().route("/login.php", get(handle_hello))
                                   .route("/login.php", post(handle_posto));
    app
}
