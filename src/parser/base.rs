//! parser common trait

use crate::{
    conf::setting::{CI_MERGE_REQUEST_IID, CI_PROJECT_ID},
    utils::gitlab::{get_commit_diff, get_mr_commit_hash, Issue},
};
pub trait BaseParser<T> {
    fn parse(self: &mut Self, content: &str) -> &Vec<T>;
    fn export(self: &Self, excel: &str) -> bool;
    fn to_issue(self: &Self) -> Issue;
    async fn filter(self: &mut Self) -> Vec<T>;
    async fn is_in_diff(self: &Self, fpath: &str) -> bool {
        let mut flag = false;
        // let rt = tokio::runtime::Builder::new_current_thread()
        // .enable_all()
        // .build().unwrap();

        // rt.block_on(async  {
        //     let hash = get_mr_commit_hash(CI_PROJECT_ID.to_owned(), CI_MERGE_REQUEST_IID.to_owned()).await.unwrap();
        //     let diff_files = get_commit_diff(CI_PROJECT_ID.to_owned(), hash.as_str()).await.unwrap();
        //     for (_fpath, _) in diff_files.iter() {
        //         println!("_path: {}, path: {}", _fpath, fpath);
        //         if _fpath == fpath {
        //             flag = true;
        //             break;
        //         }
        //     }
        //     flag
        // })

        let hash = get_mr_commit_hash(CI_PROJECT_ID.to_owned(), CI_MERGE_REQUEST_IID.to_owned())
            .await
            .unwrap();
        let diff_files = get_commit_diff(CI_PROJECT_ID.to_owned(), hash.as_str())
            .await
            .unwrap();
        for (_fpath, _) in diff_files.iter() {
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
