#!setting
use lazy_static::lazy_static;
use std::{env, sync::Arc, sync::Mutex};

// const GITLAB_HOST: &str = "http://10.10.10.167/";
const GITLAB_HOST: &str = "https://cbb3-58-247-130-218.ngrok-free.app/";
// const GITLAB_HOST: &str = "http://127.0.0.1:8899/";
// const GITLAB_TOKEN: &str = "vH5ooiCAn6AA53tdpGs9";
// 5Za9qoy5SdFWcfXTueug

const EXCLUDED_USER_IDS: [&str; 3] = ["2", "61", "113"];
const ISSUE_TEMPLATE: &str = "
<!-- sec title -->
## {}
<!-- sec description -->
{}
<!-- vuln table -->
{}
";

lazy_static! {
    pub static ref CI_PROJECT_URL: String = env::var("CI_PROJECT_URL").unwrap_or(String::new());
    pub static ref GITLAB_USER_ID: String = env::var("GITLAB_USER_ID").unwrap_or(String::new());
    pub static ref CI_PROJECT_ID: String = env::var("CI_PROJECT_ID").unwrap_or(String::new());
    pub static ref GITLAB_URL_PREFIX: String = format!("{GITLAB_HOST}/api/v4");
    pub static ref GITLAB_TOKEN: String = env::var("GITLAB_TOKEN").unwrap_or(String::new());
    pub static ref CI_MERGE_REQUEST_IID: String =
        env::var("CI_MERGE_REQUEST_IID").unwrap_or(String::new());
    pub static ref DIFF_FILES: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(vec![]));
}