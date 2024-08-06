use parser::{
    base::{BaseParser, BaseReport},
    sast, sca, secret,
};
use std::{
    env::{self},
    fs,
};

pub mod conf;
pub mod parser;
pub mod utils;

#[tokio::main]
async fn main() {
    env_logger::init();
    // test::test().await;
    // todo!();
    let args: Vec<String> = env::args().collect();
    if let 1 = args.len() {
        log::error!("not enough args");
        // println!("not enough args");
        return;
    }

    match args[1].as_str() {
        "sast" => match fs::read_to_string("/works/gl-sast-report.json") {
            Ok(cont) => {
                let mut report = sast::SASTReport::new();
                report.parse(cont.as_str());
                report.report().await;
            }
            Err(_e) => log::error!("not such file!"),
        },
        "sca" => match fs::read_to_string("/works/gl-dependency-scanning-report.json") {
            Ok(cont) => {
                let mut report = sca::SCAReport::new();
                report.parse(cont.as_str());
                report.report().await;
            }
            Err(_e) => log::error!("not such file!"),
        },
        "secret" => match fs::read_to_string("/works/gl-secret-detection-report.json") {
            Ok(cont) => {
                let mut report = secret::SecretReport::new();
                report.parse(cont.as_str());
                report.report().await;
            }
            Err(_e) => log::error!("not such file!"),
        },

        _default => {
            log::error!("not support");
        }
    }
}
