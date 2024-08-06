//! parser common trait

use crate::{conf::setting::DIFF_FILES, utils::gitlab::Issue};
pub trait BaseParser<T> {
    fn parse(self: &mut Self, content: &str) -> &Vec<T>;
    fn export(self: &Self, excel: &str) -> bool;
    fn to_issue(self: &Self) -> Issue;
    fn filter(self: &mut Self) -> &Vec<T>;
    fn is_in_diff(self: &Self, fpath: &str) -> bool {
        let mut flag = false;
        for (_fpath, _) in DIFF_FILES.lock().unwrap().iter() {
            println!("_path: {}, path: {}", _fpath, fpath);
            if _fpath == fpath {
                flag = true;
                break;
            }
        }

        flag
    }

    fn is_block_user() -> bool {
        true
    }
}

pub trait BaseReport<T> {    
    async fn report(self: &mut Self);
}

#[derive(Debug)]
pub struct RiskOwner {
    name: String,
    email: String,
    service: String,
    url: String,
}
