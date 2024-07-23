// SCA
use crate::{parser::base::Parser, utils::gitlab::Issue};
use serde_json::Value;

#[derive(Debug)]
pub struct SCAReport {
    pub engine: String,
    pub(crate) vuls: Vec<SCAVul>,
}

#[derive(Debug)]
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
        let message = obj["name"].to_string();
        let description = obj["description"].to_string();
        let severity = obj["severity"].to_string();
        let mut cve = obj["cve"].to_string();
        let location = obj["location"]["file"].to_string();
        let solution = obj["solution"].to_string();
        let dependency_name = obj["location"]["dependency"]["package"]["name"].to_string();
        let dependency_version = obj["location"]["dependency"]["version"].to_string();

        if let Some(identifiers) = obj["identifiers"].as_array() {
            for identifier in identifiers {
                if let Some("cve") = identifier["cve"].as_str() {
                    cve = identifier["name"].to_string();
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

impl Parser<SCAVul> for SCAReport {
    fn parse(self: &mut Self, content: &str) -> &Vec<SCAVul> {
        let report: Value = serde_json::from_str(content).expect("Failed to parse JSON");
        if let Some(vuls) = report["vulnerabilities"].as_array() {
            for vul in vuls {
                let _vul: SCAVul = SCAVul::from(vul);
                println!("{:?}", _vul);
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
            desc = format!("{}\n{}", desc, vul.to_issue_record());
        }

        let mut issue: Issue = Issue::new();
        issue.title = format!("{} scan report", self.engine);
        issue.description = desc;
        issue
    }
}
