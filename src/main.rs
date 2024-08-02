use actix_web::{get, post, HttpResponse, HttpServer, Responder};
use conf::setting::{CI_MERGE_REQUEST_IID, CI_PROJECT_ID, DIFF_FILES};
use parser::{
    base::{BaseParser, BaseReport},
    sast, sca, secret,
};
use std::{
    env::{self},
    fs,
    time::Duration,
};
use utils::gitlab;

pub mod conf;
pub mod parser;
pub mod test;
pub mod utils;

#[warn(dead_code)]
fn init() {
    std::thread::spawn(move || {
        futures::executor::block_on(async move {
            // RUNTIME
            let commit_hash =
                gitlab::get_mr_commit_hash(CI_PROJECT_ID.as_str(), CI_MERGE_REQUEST_IID.as_str())
                    .await
                    .unwrap();

            DIFF_FILES.lock().unwrap().extend(
                gitlab::get_commit_diff(CI_PROJECT_ID.as_str(), commit_hash.as_str())
                    .await
                    .unwrap(),
            )
        });

        // tokio::task::spawn_blocking(gitlab::get_mr_commit_hash(
        //     CI_PROJECT_ID.as_str(),
        //     CI_MERGE_REQUEST_IID.as_str(),
        // ))
    });
}

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
    // test::test().await;
    // todo!();
    let args: Vec<String> = env::args().collect();

    match args[1].as_str() {
        "sast" => match fs::read_to_string("/works/gl-sast-report.json") {
            Ok(cont) => {
                let mut report = sast::SASTReport::new();
                report.parse(cont.as_str());
                report.report().await
            }
            Err(e) => log::error!("not such file!"),
        },
        "sca" => match fs::read_to_string("/works/gl-dependency-scanning-report.json") {
            Ok(cont) => {
                let mut report = sca::SCAReport::new();
                report.parse(cont.as_str());
                report.report().await
            }
            Err(e) => log::error!("not such file!"),
        },
        "secret" => match fs::read_to_string("/works/gl-secret-detection-report.json") {
            Ok(cont) => {
                let mut report = secret::SecretReport::new();
                report.parse(cont.as_str());
                report.report().await
            }
            Err(e) => log::error!("not such file!"),
        },

        _default => {
            log::error!("not support")
        }
    }
}
