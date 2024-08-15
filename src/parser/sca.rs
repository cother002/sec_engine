// SCA
use crate::conf::setting::*;
use crate::utils::gitlab;
use crate::{parser::base::BaseParser, utils::gitlab::Issue};
use serde_json::Value;

use super::base::BaseReport;
use log::*;

#[derive(Debug)]
pub struct SCAReport {
    pub engine: String,
    pub(crate) vuls: Vec<SCAVul>,
}

#[derive(Debug, Clone)]
pub struct SCAVul {
    message: String,
    description: String,
    severity: String,
    cve: String,
    location: String,
    solution: String,
    dependency_name: String,
    dependency_version: String,
}

impl SCAVul {
    fn to_issue_record(self: &Self) -> String {
        let mut values = vec![];

        values.push(format!(
            "{}:{}",
            self.dependency_name, self.dependency_version
        ));
        values.push(self.severity.to_string());
        values.push(self.cve.to_string());
        values.push(self.location.to_string());
        values.push(self.solution.to_string());
        values.push(self.description.to_string());

        format!("|{}|", values.join("|"))
    }
}

impl From<&Value> for SCAVul {
    fn from(obj: &serde_json::Value) -> Self {
        let message = obj["name"].as_str().unwrap().to_owned();
        let description = obj["description"].as_str().unwrap().to_owned();
        let severity = obj["severity"].as_str().unwrap().to_owned();
        let mut cve = String::new();
        let location = obj["location"]["file"].as_str().unwrap().to_owned();
        let solution = obj["solution"].as_str().unwrap().to_owned();
        let dependency_name = obj["location"]["dependency"]["package"]["name"]
            .as_str()
            .unwrap()
            .to_owned();
        let dependency_version = obj["location"]["dependency"]["version"]
            .as_str()
            .unwrap()
            .to_owned();

        if let Some(identifiers) = obj["identifiers"].as_array() {
            for identifier in identifiers {
                if let Some("cve") = identifier["type"].as_str() {
                    cve = identifier["name"].to_string().replace("\"", "");
                    break;
                }
            }
        }

        SCAVul {
            message: message,
            description: description,
            severity: severity,
            cve: cve,
            location: location,
            solution: solution,
            dependency_name: dependency_name,
            dependency_version: dependency_version,
        }
    }
}

impl SCAReport {
    pub fn new() -> Self {
        SCAReport {
            vuls: vec![],
            engine: String::from("SCA"),
        }
    }
}

impl BaseParser<SCAVul> for SCAReport {
    fn parse(self: &mut Self, content: &str) -> &Vec<SCAVul> {
        let report: Value = serde_json::from_str(content).expect("Failed to parse JSON");
        if let Some(vuls) = report["vulnerabilities"].as_array() {
            for vul in vuls {
                let _vul: SCAVul = SCAVul::from(vul);
                debug!("{:?}", _vul);
                self.vuls.push(_vul);
            }
        }

        &self.vuls
    }

    fn export(self: &Self, excel: &str) -> bool {
        todo!();
    }

    fn to_issue(self: &Self) -> Issue {
        const COLS: [&str; 6] = [
            "dependency",
            "severity",
            "cve",
            "location",
            "solution",
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

        debug!("desc: {}", issue.description);
        issue
    }

    async fn filter(self: &mut Self) -> Vec<SCAVul> {
        self.vuls.clone()
    }
}

impl BaseReport<SCAVul> for SCAReport {
    async fn report(self: &mut Self) {
        self.filter();

        if self.vuls.len() < 1 {
            info!("skip, no sca vuls...");
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
            debug!("issue_iid:{issue_iid}");
            let _ = gitlab::close_issue(CI_PROJECT_ID.as_str(), issue_iid.as_str()).await;
            issue_iids.push(issue_iid);
        }
        // println!("{:?}", issue_iids);

        let _ = gitlab::new_issue(&self.to_issue()).await;
    }
}
