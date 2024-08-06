use core::panic;
use std::{cell::RefCell, fs, ops::AddAssign, rc::Rc};

use serde_json::Value;

use crate::conf::setting::{CI_PROJECT_ID, GITLAB_USER_ID};
use crate::parser::base::{BaseParser, BaseReport};
use crate::parser::sast::SASTReport;
use crate::parser::sca::SCAReport;
use crate::parser::secret::SecretReport;
use crate::parser::{sast, sca, secret};
use crate::utils::gitlab;
use lazy_static::*;
use std::io;

enum List {
    Cons(i32, Rc<List>),
    Nil,
}

#[tokio::test]
pub async fn test() {
    // test_rc();
    // test_refcell();
    // let mut sast_report: SASTReport = test_sast_parser().unwrap();
    // sast_report.report().await;

    // let mut sca_report: SCAReport = test_sca_parser();
    // sca_report.report().await;

    // let mut secret_report: SecretReport = test_secret_parser();
    // secret_report.report().await;

    // <SASTReport as BaseReport<sast::SASTVul>>::report(&mut sast_report).await;

    // test_range();

    // test_gitlab_api_list_issue().await;
    // test_gitlab_api_list_issues().await;
    // test_gitlab_api_new_issue(sast_report).await;

    // test_gitlab_get_mr_commit().await;
    // test_gitlab_diff_mr_commit().await;

    // test_gitlab_list_mr_commit().await;
}

fn test_range() {
    for i in vec![1; 8] {
        println!("value: {}", i);
    }
}

fn test_rc() {
    use List::{Cons, Nil};
    let list = Rc::new(Cons(1, Rc::new(Cons(2, Rc::new(Cons(3, Rc::new(Nil)))))));
    let _a = Cons(4, Rc::clone(&list));
    {
        let _b = Cons(5, Rc::clone(&list));
        println!("strong_count: {}", Rc::strong_count(&list));
    }
    println!("strong_count: {}", Rc::strong_count(&list));
}

pub fn test_refcell() {
    let a = Rc::new(RefCell::new(5));
    let b = Rc::clone(&a);

    println!("before: {}", a.take());
    b.borrow_mut().add_assign(20);
    println!("after: {}", a.take());
}

pub fn test_sast_parser() -> io::Result<SASTReport> {
    use crate::parser::sast;
    let content =
        match fs::read_to_string("/Users/lenv/workspace/opple/app-gateway/gl-sast-report.json") {
            Ok(content) => content,
            Err(_) => panic!("cannot not found file"),
        };
    // sast::SASTReport::new();
    // println!("{}", content.as_str());

    let mut report = sast::SASTReport::new();
    report.parse(content.as_str());
    println!("issue: {}", report.to_issue().description);

    Ok(report)
}

pub fn test_sca_parser() -> SCAReport {
    let content = match fs::read_to_string(
        "/Users/lenv/workspace/opple/app-gateway/gl-dependency-scanning-report.json",
    ) {
        Ok(content) => content,
        Err(_) => panic!("cannot not found file"),
    };
    // sast::SASTReport::new();
    // println!("{}", content.as_str());

    let mut report = sca::SCAReport::new();
    report.parse(content.as_str());

    report
}

pub fn test_secret_parser() -> SecretReport {
    let content = match fs::read_to_string(
        // "/Users/lenv/workspace/opple/app-gateway/gl-secret-detection-report.json",
        "/Users/lenv/workspace/opple/app_resource/gl-secret-detection-report.json",
    ) {
        Ok(content) => content,
        Err(_) => panic!("cannot not found file"),
    };
    // sast::SASTReport::new();
    // println!("{}", content.as_str());

    let mut report = secret::SecretReport::new();
    report.parse(content.as_str());

    report
}

#[tokio::test(flavor = "multi_thread")]
pub async fn test_gitlab_api_list_issue() -> io::Result<()> {
    println!("test_gitlab_api");

    println!(
        "project: {}, user: {}",
        CI_PROJECT_ID.as_str(),
        GITLAB_USER_ID.as_str()
    );

    match (gitlab::list_issue(CI_PROJECT_ID.as_str(), GITLAB_USER_ID.as_str(), "sast").await) {
        Ok(cont) => {
            println!("cont: {cont}")
        }
        Err(e) => panic!("error: {}", e),
    }

    Ok(())
}

pub async fn test_gitlab_api_list_issues() {
    println!("test_gitlab_api");

    println!(
        "project: {}, user: {}",
        CI_PROJECT_ID.as_str(),
        GITLAB_USER_ID.as_str()
    );

    match (gitlab::list_issues(CI_PROJECT_ID.as_str(), "SAST").await) {
        Ok(cont) => {
            log::debug!("cont: {cont}");
            let json: Value = serde_json::from_str(cont.as_str()).expect("not valid json format");

            for item in json.as_array().unwrap() {
                let issue_iid: String = item["iid"].to_string();
                println!("issue_iid:{}", issue_iid);
                let _ = gitlab::close_issue(CI_PROJECT_ID.as_str(), issue_iid.as_str()).await;
            }
        }
        Err(e) => panic!("error: {}", e),
    }
}

pub async fn test_gitlab_api_new_issue<T, E>(report: T)
where
    T: BaseParser<E>,
{
    println!("test_gitlab_api");
    // let title: String = format!("{} scan report", report);
    // gitlab::Issue::new(2, , desc)
    let mut issue = report.to_issue();

    match (gitlab::new_issue(&issue).await) {
        Ok(cont) => {
            println!("created new issue: {cont}")
        }
        Err(e) => panic!("error: {}", e),
    }
}

pub async fn test_gitlab_get_mr_commit() {
    match gitlab::get_mr_commit_hash(2, 1).await {
        Ok(body) => println!("{}", body),
        Err(e) => panic!("error: {}", e),
    }
}

pub async fn test_gitlab_list_mr_commit() {
    match gitlab::list_mr_commit(2).await {
        Ok(body) => println!("{}", body),
        Err(e) => panic!("error: {}", e),
    }
}

pub async fn test_gitlab_diff_mr_commit() {
    match gitlab::get_commit_diff(2, "492bc7b14b32b31fa94fe8638727bfd696b6b0e0").await {
        Ok(body) => println!("{:?}", body),
        Err(e) => panic!("error: {}", e),
    }
}

pub async fn test_sast_report() {}
