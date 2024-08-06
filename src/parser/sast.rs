// sast

use std::{
    env,
    fmt::{Display, Formatter},
};

use crate::{
    conf::setting::*,
    parser::base::BaseParser,
    utils::gitlab::{self, Issue},
};
use serde_json::Value;

use super::base::BaseReport;

#[derive(Debug)]
pub struct SASTReport {
    pub engine: String,
    pub vuls: Vec<SASTVul>,
}

#[derive(Debug, Clone)]
pub struct SASTVul {
    message: String,
    description: String,
    severity: String,
    cve: String,
    location: String,
    // owner: RiskOwner,
}

impl SASTVul {
    pub fn new() -> Self {
        SASTVul {
            message: String::new(),
            description: String::new(),
            severity: String::new(),
            cve: String::new(),
            location: String::new(),
            // owner: todo!(),
        }
    }

    pub fn to_issue_record(self: &Self) -> String {
        let mut values: Vec<String> = Vec::new();
        values.push(self.message.clone());
        values.push(self.severity.clone());
        values.push(format!(
            "{}",
            self.cve.replace("semgrep_id:find_sec_bugs.", ""),
        ));
        values.push(self.location.clone());
        values.push(self.description.replace("\n", "<br>").clone());

        let result: String = values.join("|");
        // println!("issue: |{result}|");

        format!("|{}|", result)
    }
}

impl From<&Value> for SASTVul {
    fn from(obj: &serde_json::Value) -> Self {
        let message = obj["message"].as_str().unwrap().to_string();
        let description = obj["description"].as_str().unwrap().to_string();
        let severity = obj["severity"].as_str().unwrap().to_string();
        let cve = obj["cve"].as_str().unwrap().to_string();
        // let location = obj["location"]..as_str().unwrap();
        let location_fpath = obj["location"]["file"].as_str().unwrap().to_string();
        let location_lineno = obj["location"]["start_line"].to_string().replace("\"", "");
        let location_href = format!(
            "{}/-/blob/develop/{}",
            CI_PROJECT_URL.as_str(),
            location_fpath
        );

        let location = format!("[{location_fpath}:{location_lineno}]({location_href})");

        let key = "gitlab_url";
        match env::var_os(key) {
            Some(val) => println!("{key}: {val:?}"),
            None => println!("{key} is not defined in the environment."),
        }

        SASTVul {
            message,
            description,
            severity,
            cve,
            location,
            // owner: todo!(),
        }
    }
}

impl SASTReport {
    pub fn new() -> Self {
        SASTReport {
            vuls: vec![],
            engine: String::from("SAST"),
        }
    }
}

impl Display for SASTReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SAST Report:\n- Vulnerabilities: {:?}", self.vuls)
    }
}

impl BaseParser<SASTVul> for SASTReport {
    fn parse(self: &mut Self, content: &str) -> &Vec<SASTVul> {
        let report: Value = serde_json::from_str(content).expect("json format error");
        // let reports = Rc::new(RefCell::new(self));
        if let Some(vulnerabilities) = report["vulnerabilities"].as_array() {
            for vul in vulnerabilities {
                let _vul: SASTVul = SASTVul::from(vul);
                // println!("{:?}", _vul);
                // reports.push(_vul);
                self.vuls.push(_vul);
            }
        }

        &self.vuls
    }

    fn export(self: &Self, excel: &str) -> bool {
        todo!()
    }

    fn to_issue(self: &Self) -> Issue {
        const COLS: [&str; 5] = ["title", "severity", "cve", "location", "description"];
        let title = format!("|{}|", COLS.join("|"));
        let sep = format!("|{}|", ["--"; COLS.len()].join("|"));
        let mut desc: String = format!("{title}\n{sep}");
        let mut issue: Issue = Issue::new();

        for vul in self.vuls.iter() {
            desc = format!("{}\n{}", desc, vul.to_issue_record());
        }

        issue.engine = self.engine.to_string();
        issue.project_id = CI_PROJECT_ID.to_string();
        issue.assignee_id = GITLAB_USER_ID.to_string();
        issue.title = format!("{} scan report", self.engine);
        issue.description = desc.replace("\\n", "\n");
        issue
    }

    fn filter(self: &mut Self) -> &Vec<SASTVul> {
        let mut vuls: Vec<SASTVul> = vec![];
        for vul in &self.vuls {
            if self.is_in_diff(vul.location.as_str()) {
                vuls.push(vul.clone());
            }
        }

        self.vuls.clear();
        self.vuls.extend(vuls);

        &self.vuls
    }
}

impl BaseReport<SASTVul> for SASTReport {
    async fn report(self: &mut Self) {
        // comment for debug
        self.filter();

        if self.vuls.len() < 1 {
            println!("no issue, skip create new issue...");
            return;
        }

        let issue = self.to_issue();
        let _ = gitlab::new_issue(&issue).await;
    }
}
