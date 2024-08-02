use crate::{
    conf::setting::{CI_PROJECT_ID, GITLAB_USER_ID},
    utils::gitlab::{self, Issue},
};

use super::base::{BaseParser, BaseReport};
use serde_json::Value;

#[derive(Debug)]
pub struct SecVul {
    message: String,
    description: String,
    severity: String,
    cve: String,
    location: String,
    // solution: String,
    // owner: RiskOwner,
}

impl SecVul {
    fn to_issue_record(self: &Self) -> String {
        let mut values: Vec<String> = Vec::new();
        values.push(self.message.to_string());
        values.push(self.severity.to_string());
        values.push(self.cve.to_string());
        values.push(self.location.to_string());
        // values.push(self.solution.to_string());
        values.push(self.description.to_string());

        format!("|{}|", values.join("|"))
    }
}

impl From<&Value> for SecVul {
    fn from(value: &Value) -> Self {
        let message = value["name"].to_string().replace("\"", "");
        let description = value["description"].to_string().replace("\"", "");
        let severity = value["severity"].to_string().replace("\"", "");
        let cve = value["cve"]
            .to_string()
            .replace("\"", "")
            .split(":")
            .last()
            .unwrap()
            .to_string();
        let location = value["location"]["file"].to_string().replace("\"", "");
        // let solution = value["solution"].to_string().replace("\"", "");

        SecVul {
            message: message,
            description: description,
            severity: severity,
            cve: cve,
            location: location,
            // solution: solution,
            // owner: todo!(),
        }
    }
}

#[derive(Debug)]
pub struct SecretReport {
    pub engine: String,
    pub(crate) vuls: Vec<SecVul>,
}

impl SecretReport {
    pub fn new() -> Self {
        SecretReport {
            vuls: Vec::new(),
            engine: String::from("Secret"),
        }
    }
}

impl BaseParser<SecVul> for SecretReport {
    fn parse(self: &mut Self, content: &str) -> &Vec<SecVul> {
        let report: Value = serde_json::from_str(content).unwrap();
        if let Some(vulnerabilities) = report["vulnerabilities"].as_array() {
            for vul in vulnerabilities {
                let _vul = SecVul::from(vul);
                self.vuls.push(_vul);
            }
        }
        println!("{:?}", self.vuls);
        &self.vuls
    }

    fn export(self: &Self, excel: &str) -> bool {
        todo!();

        true
    }

    fn to_issue(self: &Self) -> Issue {
        const COLS: [&str; 5] = [
            "title",
            "severity",
            "cve",
            "location",
            // "solution",
            "description",
        ];
        let title = format!("|{}|", COLS.join("|"));
        // let title = "|title|severity||"
        let sep = format!("|{}|", ["--"; COLS.len()].join("|"));
        let mut desc: String = format!("{title}\n{sep}");

        for vul in self.vuls.iter() {
            desc = format!(
                "{}\n{}",
                desc,
                vul.to_issue_record()
                    .trim()
                    .replace("\\n", "<br>")
                    .replace("\n", "<br>")
            );
        }
        let mut issue: Issue = Issue::new();
        issue.engine = self.engine.to_string();
        issue.project_id = CI_PROJECT_ID.to_string();
        issue.title = format!("{} scan report", self.engine);
        issue.description = desc;
        issue
    }

    fn filter(self: &mut Self) -> &Vec<SecVul> {
        &self.vuls
    }
}

impl BaseReport<SecVul> for SecretReport {
    async fn report(self: &mut Self) {
        self.filter();

        if self.vuls.len() < 1 {
            return;
        }

        let body: String = gitlab::list_issue(
            CI_PROJECT_ID.as_str(),
            GITLAB_USER_ID.as_str(),
            self.engine.as_str(),
        )
        .await
        .unwrap();
        let json: Value = serde_json::from_str(body.as_str()).expect("not valid json format");
        let mut issue_iids: Vec<String> = vec![];

        for item in json.as_array().unwrap_or(&Vec::new()) {
            let issue_iid: String = item["iid"].to_string();
            log::debug!("issue_iid:{issue_iid}",);
            let _ = gitlab::close_issue(CI_PROJECT_ID.as_str(), issue_iid.as_str()).await;
            issue_iids.push(issue_iid);
        }

        let _ = gitlab::new_issue(&self.to_issue()).await;
    }
}
