//! gitlab functions

use std::fmt::Display;

use lazy_static::lazy_static;

use crate::conf::setting::*;
use http::{HeaderMap, HeaderValue};
use reqwest::{Client, Error};
use serde_json::Value;

pub struct Issue {
    pub engine: String,
    pub project_id: String,
    pub title: String,
    pub description: String,
    pub assignee_id: String,
}

impl Issue {
    pub fn new() -> Self {
        Issue {
            engine: String::new(),
            project_id: String::from("-1"),
            title: String::new(),
            description: String::new(),
            assignee_id: GITLAB_USER_ID.to_string(),
        }
    }
}

impl Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        println!("engine: {}\nproject_id: {}\ntitle: {}\nissue: \n{}\n", self.engine, self.project_id, self.title, self.description);
        Ok(())
    }
}

const EXCLUDED_USER_IDS: [&str; 3] = ["1", "61", "113"];

lazy_static! {
    static ref DEFAULT_HEADERS: HeaderMap = {
        let mut m = HeaderMap::new();
        m.insert("PRIVATE-TOKEN", HeaderValue::from_str(GITLAB_TOKEN.as_str()).unwrap());
        m
    };
    // DEFAULT_HEADERS
    static ref GITLAB_CLIENT: Client = Client::builder().default_headers(DEFAULT_HEADERS.clone()).build().unwrap();
}

pub async fn new_issue(issue: &Issue) -> Result<String, Error> {
    println!("new issue....");
    let url = format!(
        "{}/projects/{}/issues",
        GITLAB_URL_PREFIX.to_string(),
        issue.project_id
    )
    .replace('"', "");

    let mut data: Vec<(&str, String)> = Vec::new();
    data.push(("title", issue.title.to_string()));
    data.push(("description", issue.description.to_string()));
    data.push(("labels", ["bug", "sec", issue.engine.as_str()].join(",")));
    if issue.assignee_id != "" && !EXCLUDED_USER_IDS.contains(&issue.assignee_id.as_str()) {
        data.push(("assignee_id", issue.assignee_id.to_string()));
    };

    let body = serde_urlencoded::to_string(data).unwrap();
    println!("new_issue url: {url}, body: {body}, {}", body.len());
    // return Ok(String::new());

    let cont = GITLAB_CLIENT
        .post(format!("{url}"))
        .body(body)
        .send()
        .await?
        .text()
        .await?;

    println!("new_issue resp: {cont}");
    Ok(cont)
}

// 获取issues
pub async fn list_issues<T>(project: &T, label: &T) -> Result<String, Error>
where
    T: ?Sized + std::fmt::Debug,
{
    let url = format!(
        "{}/projects/{:?}/issues?state=opened&labels=sec,{:?}",
        GITLAB_URL_PREFIX.as_str(),
        project,
        label
    )
    .replace('"', "");
    println!("list_issues url: {url}");
    let body = GITLAB_CLIENT.get(url).send().await?.text().await?;

    Ok(body)
}

// 获取issue
pub async fn list_issue<T>(project: &T, assignee: &T, label: &T) -> Result<String, Error>
where
    T: ?Sized + std::fmt::Debug + std::any::Any,
{
    let url = format!(
        "{}/projects/{:?}/issues?state=opened&labels=sec,bug,{:?}&assignee_id={:?}",
        GITLAB_URL_PREFIX.as_str(),
        project,
        label,
        assignee
    )
    .replace('"', "");
    println!("url: {url}, {:?}", project);

    let body = GITLAB_CLIENT.get(url).send().await?.text().await?;

    println!("body = {body:?}");
    Ok(body)
}

// 删除issue
pub async fn delete_issue(project: i32, issue: i32) -> Result<String, Error> {
    let url = format!(
        "{}/projects/{}/issues/{}",
        GITLAB_URL_PREFIX.to_string(),
        project,
        issue
    )
    .replace('"', "");
    println!("delete issue");
    let body = GITLAB_CLIENT.delete(url).send().await?.text().await?;

    Ok(body)
}

// 关闭issue
pub async fn close_issue<T>(project_id: &T, issue_iid: &T) -> Result<String, Error>
where
    T: ?Sized + std::fmt::Debug,
{
    println!("close issue {:?}....", issue_iid);
    let url = format!(
        "{}/projects/{:?}/issues/{:?}?state_event=close",
        GITLAB_URL_PREFIX.to_string(),
        project_id,
        issue_iid
    )
    .replace('"', "");
    let body = GITLAB_CLIENT.put(url).send().await?.text().await?;

    Ok(body)
}

// mr 列表
pub async fn list_mr_commit(project: i32) -> Result<String, Error> {
    // todo!("GET /projects/:id/merge_requests/:merge_request_iid")
    let url = format!(
        "{}/projects/{}/merge_requests",
        GITLAB_URL_PREFIX.to_string(),
        project
    )
    .replace('"', "");

    println!("get_mr_commit: {url}");
    let body = GITLAB_CLIENT.get(url).send().await?.text().await?;

    Ok(body)
}

// 通过mr获取commitid
pub async fn get_mr_commit_hash<T: std::fmt::Debug>(project: T, iid: T) -> Result<String, Error> {
    // todo!("GET /projects/:id/merge_requests/:merge_request_iid")
    let url = format!(
        "{}/projects/{:?}/merge_requests/{:?}",
        GITLAB_URL_PREFIX.to_string(),
        project,
        iid
    )
    .replace('"', "");

    println!("get_mr_commit: {url}");
    let body = GITLAB_CLIENT.get(url).send().await?.text().await?;
    let json: Value = serde_json::from_str(&body).unwrap();
    // let sha: String = json["merge_commit_sha"].as_str().unwrap().to_string();
    let sha: String = json["sha"].as_str().unwrap().to_string();

    Ok(sha)

    // https://docs.gitlab.com/ee/api/merge_requests.html#get-single-mr
}

// 通过commit id获取修改点
pub async fn get_commit_diff<T: std::fmt::Debug>(
    project: T,
    commit_hash: &str,
) -> Result<Vec<(String, String)>, Error> {
    // todo!("GET /projects/:id/repository/commits/:sha/diff")
    // https://docs.gitlab.com/ee/api/commits.html#get-the-diff-of-a-commit
    let url = format!(
        "{}/projects/{:?}/repository/commits/{}/diff",
        GITLAB_URL_PREFIX.to_string(),
        project,
        commit_hash
    )
    .replace('"', "");

    println!("get_mr_commit: {url}");
    let body = GITLAB_CLIENT.get(url).send().await?.text().await?;
    let json: Value = serde_json::from_str(&body).unwrap();
    let mut result: Vec<(String, String)> = vec![];
    // let sha: String = json["head_pipeline"]["sha"].as_str().unwrap().to_string();
    for diff in json.as_array().unwrap() {
        let new_path = diff["new_path"].as_str().unwrap().to_string();
        let diff_cont: String = diff["diff"].as_str().unwrap().to_string();

        result.push((new_path, diff_cont));
    }

    Ok(result)
}

pub async fn list_links<T>(project_id: &T, issue_iid: &T) -> Result<String, Error>
where
    T: ?Sized + std::fmt::Debug,
{
    let url = format!(
        "{}/projects/{:?}/issues/{:?}/links",
        GITLAB_URL_PREFIX.as_str(),
        project_id,
        issue_iid,
    )
    .replace('"', "");
    let body = GITLAB_CLIENT.get(url).send().await?.text().await?;

    Ok(body)
}

pub async fn new_issue_link<T>(project_id: &T, issue_iid: &T) -> Result<String, Error>
where
    T: ?Sized + std::fmt::Debug,
{
    // let url = format!(
    //     "{}/projects/{:?}/issues/{:?}/links",
    //     GITLAB_URL_PREFIX.as_str(),
    //     project_id,
    //     issue_iid,
    // )
    // .replace('"', "");
    todo!("创建issue");
}

// 设置todo为done
pub async fn issue_todo_done<T>(todo_iid: &T) -> Result<String, Error>
where
    T: ?Sized + std::fmt::Debug,
{
    let url = format!(
        "{}/todos/{:?}/mark_as_done",
        GITLAB_URL_PREFIX.as_str(),
        todo_iid
    )
    .replace('\"', "");

    let body = GITLAB_CLIENT.post(url).send().await?.text().await?;

    Ok(body)
}

// mr commit
pub async fn new_mr_comment(comment: String) -> Result<String, Error> {
    let url = format!(
        "{}/projects/{:?}/merge_requests/{:?}/notes",
        GITLAB_URL_PREFIX.as_str(),
        CI_PROJECT_ID.to_owned(),
        CI_MERGE_REQUEST_IID.to_owned()
    )
    .replace('\"', "");

    let resp = GITLAB_CLIENT
        .post(url)
        .body(comment)
        .send()
        .await?
        .text()
        .await?;

    Ok(resp)
}
