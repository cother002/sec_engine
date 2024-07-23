//! gitlab functions

use lazy_static::lazy_static;

use http::{HeaderMap, HeaderValue};
use reqwest::{Client, Error};

pub struct Issue {
    pub project_id: i32,
    pub title: String,
    pub description: String,
}

impl Issue {
    // pub fn new(projectId: i32, title: &str, desc: &str) -> Self {
    //     Issue {
    //         project_id: projectId,
    //         title: String::from(title),
    //         description: String::from(desc),
    //     }
    // }

    pub fn new() -> Self {
        Issue {
            project_id: -1,
            title: String::new(),
            description: String::new(),
        }
    }
}

// const GITLAB_HOST: &str = "http://10.10.10.167/";
const GITLAB_HOST: &str = "http://gitlab.example.com/";
// const GITLAB_HOST: &str = "http://127.0.0.1:8899/";
const GITLAB_TOKEN: &str = "uSqS8qk4DVoozx2h3Vck";

lazy_static! {
    static ref DEFAULT_HEADERS: HeaderMap = {
        let mut m = HeaderMap::new();
        m.insert("PRIVATE-TOKEN", HeaderValue::from_str(GITLAB_TOKEN).unwrap());
        m
    };
    // DEFAULT_HEADERS
    static ref GITLAB_CLIENT: Client = Client::builder().default_headers(DEFAULT_HEADERS.clone()).build().unwrap();
}
// const GITLAB_HOST: &str = "http://127.0.0.1:8899/";

pub async fn new_issue(issue: &Issue) -> Result<String, Error> {
    println!("new issue....");
    let url = format!(
        "{}/api/v4/projects/{}/issues",
        GITLAB_HOST, issue.project_id
    );

    let data = [
        ("title", issue.title.to_string()),
        ("description", issue.description.to_string()),
        ("labels", String::from("bug")),
    ];

    // let data = serde_json::json!(
    //     r#"
    // {
    //     "title": issue.title.to_owned()),
    //     "description": issue.description.to_owned()
    // }"#
    // );
    // let mut data: HashMap<&str, String> = HashMap::new();
    // data.insert("title", issue.title.to_string());
    // data.insert("description", issue.description.to_string());
    let query = serde_urlencoded::to_string(data).unwrap();

    let body = GITLAB_CLIENT
        .post(format!("{url}?{query}"))
        .send()
        .await?
        .text()
        .await?;

    Ok(body)
}

pub async fn list_issue(project: i32) -> Result<String, Error> {
    let url = format!("{}/api/v4/projects/{}/issues", GITLAB_HOST, project);
    let mut header = HeaderMap::new();

    header.append(
        "PRIVATE-TOKEN",
        HeaderValue::from_str(GITLAB_TOKEN).unwrap(),
    );

    let body = GITLAB_CLIENT.get(url).send().await?.text().await?;

    println!("body = {body:?}");
    Ok(body)
}
