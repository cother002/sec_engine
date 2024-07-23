// sast

use std::fmt::{Display, Formatter};

use crate::{
    parser::base::{Parser, RiskOwner},
    utils::gitlab::Issue,
};
use serde_json::Value;
use xlsxwriter;

#[derive(Debug)]
pub struct SASTReport {
    pub engine: String,
    pub vuls: Vec<SASTVul>,
}

#[derive(Debug)]
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
            message: todo!(),
            description: todo!(),
            severity: todo!(),
            cve: todo!(),
            location: todo!(),
            // owner: todo!(),
        }
    }

    pub fn to_issue_record(self: &Self) -> String {
        let mut values: Vec<String> = Vec::new();
        values.push(self.message.clone());
        values.push(self.severity.clone());
        values.push(self.cve.clone());
        values.push(self.location.clone());
        values.push(self.description.clone());

        format!("|{}|", values.join("|"))
    }
}

impl From<&Value> for SASTVul {
    fn from(obj: &serde_json::Value) -> Self {
        let message = obj["message"].to_string().replace("\"", "");
        let description = obj["description"].to_string().replace("\"", "");
        let severity = obj["severity"].to_string().replace("\"", "");
        let cve = obj["cve"].to_string().replace("\"", "");
        let location = obj["location"].to_string().replace("\"", "");

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

impl Parser<SASTVul> for SASTReport {
    fn parse(self: &mut Self, content: &str) -> &Vec<SASTVul> {
        let report: Value = serde_json::from_str(content).unwrap();
        // let reports = Rc::new(RefCell::new(self));
        if let Some(vulnerabilities) = report["vulnerabilities"].as_array() {
            for vul in vulnerabilities {
                let _vul: SASTVul = SASTVul::from(vul);
                // println!("{:?}", _vul);
                // reports.push(_vul);
                self.vuls.push(_vul);
            }
        }

        // &self.vuls
        &self.vuls
    }

    fn export(self: &Self, excel: &str) -> bool {
        let workbook = xlsxwriter::Workbook::new(excel).unwrap();
        let mut sheet = workbook.add_worksheet(Some("sheet")).unwrap();
        let mut row = 1;
        for vul in self.vuls.iter() {
            let mut col: u16 = 1;
            _ = sheet.write_string(row, col, vul.message.as_str(), None);
            col += 1;
            _ = sheet.write_string(row, col, vul.cve.as_str(), None);
            col += 1;
            _ = sheet.write_string(row, col, vul.severity.as_str(), None);
            col += 1;
            _ = sheet.write_string(row, col, vul.location.as_str(), None);
            col += 1;
            _ = sheet.write_string(row, col, vul.description.as_str(), None);
            col += 1;
            _ = sheet.write_string(row, col, vul.message.as_str(), None);
            col += 1;
            _ = sheet.write_string(row, col, vul.message.as_str(), None);

            row += 1;
        }

        true
    }

    fn to_issue(self: &Self) -> Issue {
        const COLS: [&str; 5] = ["title", "severity", "cve", "location", "description"];
        let title = format!("|{}|", COLS.join("|"));
        // let title = "|title|severity||"
        let sep = format!("|{}|", ["--"; COLS.len()].join("|"));
        let mut desc: String = format!("{title}\n{sep}");
        let mut issue: Issue = Issue::new();

        for vul in self.vuls.iter() {
            desc = format!("{}\n{}", desc, vul.to_issue_record());
        }

        issue.title = format!("{} scan report", self.engine);
        issue.description = desc;
        issue
    }
}
