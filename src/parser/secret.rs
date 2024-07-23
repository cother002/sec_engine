use crate::utils::gitlab::Issue;

use super::base::{Parser, RiskOwner};
use serde_json::Value;

#[derive(Debug)]
pub struct SecVul {
    message: String,
    description: String,
    severity: String,
    cve: String,
    location: String,
    solution: String,
    // owner: RiskOwner,
}

impl SecVul {
    fn to_issue_record(self: &Self) -> String {
        let mut values: Vec<String> = Vec::new();
        values.push(self.message.to_string());
        values.push(self.severity.to_string());
        values.push(self.cve.to_string());
        values.push(self.location.to_string());
        values.push(self.solution.to_string());
        values.push(self.description.to_string());

        format!("|{}|", values.join("|"))
    }
}

impl From<&Value> for SecVul {
    fn from(value: &Value) -> Self {
        let message = value["name"].to_string();
        let description = value["description"].to_string();
        let severity = value["severity"].to_string();
        let cve = value["cve"].to_string();
        let location = value["location"]["file"].to_string();
        let solution = value["solution"].to_string();

        SecVul {
            message: message,
            description: description,
            severity: severity,
            cve: cve,
            location: location,
            solution: solution,
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

impl Parser<SecVul> for SecretReport {
    fn parse(self: &mut Self, content: &str) -> &Vec<SecVul> {
        let report: Value = serde_json::from_str(content).unwrap();
        if let Some(vulnerabilities) = report["vulnerabilities"].as_array() {
            for vul in vulnerabilities {
                let _vul = SecVul::from(vul);
                self.vuls.push(_vul);
            }
        }

        &self.vuls
    }

    fn export(self: &Self, excel: &str) -> bool {
        todo!();

        true
    }

    fn to_issue(self: &Self) -> Issue {
        const COLS: [&str; 6] = [
            "title",
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
            desc = format!("{}\n{}", desc, vul.to_issue_record());
        }

        let mut issue: Issue = Issue::new();
        issue.title = format!("{} scan report", self.engine);
        issue.description = desc;
        issue
    }
}

// type SecretReports = Vec<SecretReport>;
