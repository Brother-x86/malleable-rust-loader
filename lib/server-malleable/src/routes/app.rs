use crate::handlers::handle_post::handle_post;
use crate::handlers::handle_get::handle_get;
use axum::{routing::get,routing::post , Router};

pub fn build_routes() -> Router {
    let app = Router::new().route("/login.php", get(handle_get))
                           .route("/login.php", post(handle_post));
    app
}
