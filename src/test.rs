use std::{cell::RefCell, fs, ops::AddAssign, rc::Rc};

use crate::parser::base::Parser;
use crate::parser::sast::SASTReport;
use crate::parser::{sast, sca, secret};
use crate::utils::gitlab;

enum List {
    Cons(i32, Rc<List>),
    Nil,
}

pub async fn test() {
    // test_rc();
    // test_refcell();
    let sast_report: SASTReport = test_sast_parser();
    test_range();

    test_gitlab_api_list_issue().await;
    // test_gitlab_api_new_issue(sast_report).await;
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

pub fn test_sast_parser() -> sast::SASTReport {
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

    report
}

pub fn test_sca_parser() {
    let content =
        match fs::read_to_string("/Users/lenv/workspace/opple/app_resource/gl-sast-report.json") {
            Ok(content) => content,
            Err(_) => panic!("cannot not found file"),
        };
    // sast::SASTReport::new();
    println!("{}", content.as_str());

    let mut report = sca::SCAReport::new();
    report.parse(content.as_str());
}

pub fn test_secret_parser() {
    let content = match fs::read_to_string(
        "/Users/lenv/workspace/opple/com_light2_web/gl-secret-detection-report.json",
    ) {
        Ok(content) => content,
        Err(_) => panic!("cannot not found file"),
    };
    // sast::SASTReport::new();
    println!("{}", content.as_str());

    let mut report = secret::SecretReport::new();
    report.parse(content.as_str());
}
// pub fn test_parser() {
//     use crate::parser::sast;
//     let content =
//         match fs::read_to_string("/Users/lenv/workspace/opple/app-gateway/gl-sast-report.json") {
//             Ok(content) => content,
//             Err(_) => panic!("cannot not found file"),
//         };
//     // sast::SASTReport::new();
//     println!("{}", content.as_str());

//     ()
// }

pub async fn test_gitlab_api_list_issue() {
    println!("test_gitlab_api");

    match (gitlab::list_issue(2).await) {
        Ok(cont) => {
            println!("cont: {cont}")
        }
        Err(e) => panic!("error: {}", e),
    }
}

pub async fn test_gitlab_api_new_issue<T, E>(report: T)
where
    T: Parser<E>,
{
    println!("test_gitlab_api");
    // let title: String = format!("{} scan report", report);
    // gitlab::Issue::new(2, , desc)
    let mut issue = report.to_issue();
    issue.project_id = 2;

    match (gitlab::new_issue(&issue).await) {
        Ok(cont) => {
            println!("created new issue: {cont}")
        }
        Err(e) => panic!("error: {}", e),
    }
}
