use parser::{
    base::{BaseParser, BaseReport},
    sast, sca, secret,
};
// use utils::llm;
use std::{env, fs};
use tokio;

pub mod conf;
pub mod parser;
pub mod utils;
// pub mod test;


#[tokio::main]
async fn main() {
    env_logger::init();
    // llm::init().await;
    // test::test().await;
    // todo!();
    let args: Vec<String> = env::args().collect();
    if let 1 = args.len() {
        log::error!("not enough args");
        // println!("not enough args");ca
        return;
    }
    let target = env::var_os("TARGET")
        .unwrap_or_default()
        .to_str()
        .unwrap()
        .to_owned();

    match args[1].as_str() {
        "sast" => {
            let fpath = target + "/gl-sast-report.json";
            match fs::read_to_string(fpath.as_str()) {
                Ok(cont) => {
                    let mut report = sast::SASTReport::new();
                    report.get_diffs().await;

                    report.parse(cont.as_str());
                    report.report().await;
                }
                Err(_e) => log::error!("not such file! {fpath}"),
            }
        }
        "sca" => {
            let fpath = target + "/gl-dependency-scanning-report.json";
            match fs::read_to_string(fpath.as_str()) {
                Ok(cont) => {
                    let mut report = sca::SCAReport::new();
                    report.parse(cont.as_str());
                    report.report().await;
                }
                Err(_e) => log::error!("not such file! {fpath}"),
            }
        }
        "secret" => {
            let fpath = target + "/gl-secret-detection-report.json";
            match fs::read_to_string(fpath.as_str()) {
                Ok(cont) => {
                    let mut report = secret::SecretReport::new();
                    report.parse(cont.as_str());
                    report.report().await;
                }
                Err(_e) => log::error!("not such file! {fpath}"),
            }
        }

        _default => {
            log::error!("not support");
        }
    }
}
