use actix_web::{get, post, HttpResponse, HttpServer, Responder};
use std::time::Duration;

pub mod parser;
pub mod test;
pub mod utils;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("hello")
}

#[post("/index")]
async fn index(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

#[actix_web::main]
async fn main1() -> std::io::Result<()> {
    use actix_web::{web, App};
    // println!("hello rust!");

    HttpServer::new(|| {
        App::new()
            .service(hello)
            .service(index)
            .route("/say_hello", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .keep_alive(Duration::from_secs(70))
    .run()
    .await
}

#[tokio::main]
async fn main() {
    test::test().await;
}
