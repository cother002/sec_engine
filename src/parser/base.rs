//! parser common trait

use crate::utils::gitlab::Issue;
pub trait Parser<T> {
    fn parse(self: &mut Self, content: &str) -> &Vec<T>;

    fn export(self: &Self, excel: &str) -> bool;

    fn to_issue(self: &Self) -> Issue;
}

#[derive(Debug)]
pub struct RiskOwner {
    name: String,
    email: String,
    service: String,
    url: String,
}

const ISSUE_TEMPLATE: &str = "
<!-- sec title -->
## {}
<!-- sec description -->
{}
<!-- vuln table -->
{}
";
