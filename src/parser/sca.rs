use std::borrow::Borrow;
use std::cmp::{self, Ordering};
use std::collections::HashMap;
use std::fmt::format;
use std::hash::Hash;

// SCA
use crate::conf::setting::*;
use crate::utils::{gitlab, llm};
use crate::{parser::base::BaseParser, utils::gitlab::Issue};
use serde_json::{json, map, Value};

use super::base::BaseReport;
use super::secret::SecVul;
use log::*;

#[derive(Debug)]
pub struct SCAReport {
    pub engine: String,
    pub(crate) vuls: Vec<SCAVul>,
    pub(crate) merged_vuls: Vec<SCAVul>,
    pub(crate) merged_vuls_map: HashMap<String, Vec<SCAVul>>, // or group map with ai
    pub(crate) cached_vuls_map: HashMap<String, SCAVul>, // for distinct vul map
}

#[derive(Debug, Clone, PartialEq)]
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
    fn get_risk_num(self: &Self) -> i32 {
        let v = match self.severity.to_lowercase().as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            "info" => 0,
            _ => 0,
        };
        
        v
    }

    fn get_risk_cn(self: & Self) -> String {
        let v = match self.severity.to_lowercase().as_str() {
            "critical" => "严重",
            "high" => "高",
            "medium" => "中",
            "low" => "低",
            "info" => "可忽略",
            _ => "可忽略",
        };

        String::from(v)
    }

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
        let description = obj["description"].as_str().unwrap().trim().to_owned();
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
            merged_vuls: vec![],
            merged_vuls_map: HashMap::new(),
            cached_vuls_map: HashMap::new(),
            engine: String::from("SCA"),
        }
    }

    pub fn count_vuln(self: &Self) {
        let mut set: Vec<String> = vec![];
        for vul in self.vuls.iter() {
            if set.contains(&vul.dependency_name.to_string()) {
                continue;
            } else {
                set.push(vul.dependency_name.to_string())
            }
        }

        println!("vul(sca) count: {}", set.len());
    }

    pub async fn opt_descs(self: &mut Self) {
        let sz = self.vuls.len();
        let mut idx = 1;
        for vul in self.vuls.iter_mut() {
            let body = llm::ask_ai(format!("{}, 简化但不丢失这句话的意思，要求输出内容长度最大化缩小, 输出内容长度必须小于原输入内容长度", vul.description).as_str()).await.unwrap();
            let resp: Value = serde_json::from_str(body.as_str()).unwrap();
            let desc: String = resp["choices"][0]["message"]["content"]
                .as_str()
                .unwrap()
                .to_string();
            log::debug!("opted desc: {}", desc);

            if vul.description.len() >= desc.len() {
                println!(
                    "{idx}/{sz} after optzed : org_len: {}, len: {}",
                    vul.description.len(),
                    desc.len()
                );
                vul.description = desc;
            } else {
                println!(
                    "{idx}/{sz} after optzed, skip overwrite: org_len: {}, len: {}",
                    vul.description.len(),
                    desc.len()
                );
            }
            idx += 1
        }
    }

    pub fn group_issue_local(self: &mut Self) -> HashMap<String, Vec<SCAVul>> { 
        println!("group_issue_local调用");
        let mut cached_result: HashMap<String, HashMap<String, SCAVul>> = HashMap::new();
        let mut result: HashMap<String, Vec<SCAVul>> = HashMap::new();
        for vul in self.vuls.iter() {
            // 获取原始vul信息
            let key = vul.location.to_string();
            if let Some(group) = cached_result.get_mut(key.as_str()) {
                // 获取location分组中的map
                if let Some(cached_vul) = group.get(vul.dependency_name.as_str()) {
                    continue;
                } else {
                    let mut new_vul = self.cached_vuls_map.get(vul.dependency_name.as_str()).unwrap().clone();
                    new_vul.location = vul.location.to_string();
                    group.insert(vul.dependency_name.to_string(), new_vul.clone());
                }
            } else {
                let mut group: HashMap<String, SCAVul> = HashMap::new();
                let mut new_vul = self.cached_vuls_map.get(vul.dependency_name.as_str()).unwrap().clone();
                new_vul.location = vul.location.to_string();
                group.insert(vul.dependency_name.to_string(), new_vul.clone());
                cached_result.insert(vul.location.to_string(), group);
            }
        }
        

        for (k, cached_map) in cached_result.iter() {
            let mut vec: Vec<SCAVul> = cached_map.values().map(|v|v.clone()).collect();
            vec.sort_by(|a, b| a.dependency_name.cmp(&b.dependency_name));
            result.insert(k.to_string(), vec);
        }

        self.merged_vuls_map.extend(result.clone());

        result
    }

    pub fn group_issue(self: &mut Self) -> HashMap<String, Vec<SCAVul>> {
        let mut result: HashMap<String, Vec<SCAVul>> = HashMap::new();
        for vul in self.vuls.iter() {
            let key = vul.location.to_string();
            if let Some(v) = result.get_mut(key.as_str()) {
                result.get_mut(key.as_str()).unwrap().push(vul.clone());
            } else {
                let mut vec: Vec<SCAVul> = Vec::new();
                vec.push(vul.clone());

                result.insert(key, vec);
            }
        }

        result
    }

    fn get_prompt(self: &Self, content: &str) -> String {
        // let prompt = "
        //     目的：合并优化text标签中的内容，
        //     输入格式: 每一行均为|dependency|risk|cve|location|solution|description|，代表组件风险以及整改方案
        //     输出格式: 参照表头|dependency|risk|cve|location|solution|description|进行数据填充
        //     输出要求：
        //     1. 每个dependency字段只允许在markdown表格中出现一条记录
        //     2. 内容简单扼要
        //     3. 必须保持示例中输出内容格式
        //     4. 不要额外添加信息
        //     5. 尽可能保持语言简洁，内容不要过长
        //     6. 不需要输出表头
        //     7. dependency字段保持完整，禁止对dependency删减修改

        //     步骤：
        //     1. 从上到下逐行读取
        //     2. 每行解析组件风险，根据dependency字段检查是否为已记录信息，若无记录，则记录相关信息并跳转1执行
        //     3. 若通过dependency查询到为已记录信息，将其中的关键内容（风险(description)与解决方案(solution)）进行合并，并将合并的结果更新到已有的记录里
        //     4. 检查是否已经完全处理所有行，若无，跳到1继续
        //     5. 整理以上内容
        //     6. 反思以上前面步骤生成的内容是否符合要求，如不符合则进行改进再进行输出

        //     示例如下：
        //     输入
        //     |net.minidev/json-smart:1.0|critical|cve-1|pom.xml|upgrade to 1.2|sql inject|
        //     |net.minidev/json-smart:1.0|medium|cve-2|pom.xml|upgrade to 1.3|dos|
        //     |dep2:v1.2|medium|cve-3|pom.xml|upgrade to 1.3|dos|

        //     输出
        //     |net.minidev/json-smart:1.0|critical|cve-2、cve-1|pom.xml|upgrade to 1.3|exist sql inject、dos|
        //     |dep2:v1.2|medium|cve-3|pom.xml|upgrade to 1.3|dos|

        // ";
        let prompt = "
                目的：合并优化text标签中的内容，将同一个组件中的不同风险等级合并，原则为低风险合并到高风险中,修复方案如果有版本高低,原则上保留更新的版本. 操作前需清空上下文
                步骤：
                1. markdown表格输出记录命名为output_table
                2. 自上而下逐行读取输入内容记录，记为org_record
                3. 解析org_record的组件风险，记为pro_record，记录dependency字段
                4. 检查output_table中是否有与pro_record相同的dependency记录。
                - 若无，将pro_record记录加入output_table，跳到步骤1
                5. 若有，将output_table中的记录记为mk_record
                - 合并pro_record与mk_record中的风险描述(description)和解决方案(solution)，更新mk_record
                - 若有多个risk记录，将低风险合并到高风险，新的记录添加到output_table
                6. 检查所有行是否处理完毕，若未完毕，跳到步骤1
                7. 整理合并结果为markdown表格
                8. 输出前检查markdown表格记录，确保每个dependency字段唯一
                - 若有多条记录，将生成的markdown记录作为新输入，清空上下文后跳到步骤1再次合并

                输入格式: 每行均为markdown表格记录，格式为|dependency|risk|cve|location|solution|description|, 其中risk代表风险等级
                输出格式: 参照表头|dependency|risk|cve|location|solution|description|格式填充数据, solution和description尽量翻译为中文
                输出约束：
                1. 每个dependency字段只允许在markdown表格中出现一条记录
                2. 内容简单扼要
                3. 必须保持示例中输出内容格式
                4. 不要额外添加信息
                5. 尽可能保持语言简洁，内容不要过长
                6. 不需要输出表头
                7. dependency字段保持完整，禁止对dependency删减修改

                示例输入:
                |net.minidev/json-smart:1.0|critical|cve-1|pom.xml|upgrade to 1.2|sql inject|
                |net.minidev/json-smart:1.0|medium|cve-2|pom.xml|upgrade to 1.3|dos|
                |dep2:v1.2|medium|cve-3|pom.xml|upgrade to 1.3|dos|

                示例输出:
                |net.minidev/json-smart:1.0|critical|cve-2、cve-1|pom.xml|upgrade to 1.3|exist sql inject、dos|
                |dep2:v1.2|medium|cve-3|pom.xml|upgrade to 1.3|dos|
            ";
        format!("<text>{content}</text>, {}", prompt)
    }

    pub fn merge_issues_local(self: &mut Self) -> HashMap<String, Vec<SCAVul>>{
        println!("merge_issues_local...");
        let issues_map: HashMap<String, Vec<SCAVul>>= HashMap::new();
        let mut cached_issues_map: HashMap<String, SCAVul>= HashMap::new();
        for vul in self.vuls.iter() {
            println!("{}", String::from("-").repeat(0x32));
            let mut new_vul;
            if let Some(cached_vul)= cached_issues_map.get(vul.dependency_name.as_str()) {
                // 已有key，更新合并
                println!("发现已有缓存组件：{}({}), risk: {}", cached_vul.dependency_name.to_string(), cached_vul.get_risk_num(), cached_vul.get_risk_cn());
                println!("待合并处理组件：{}({}), detail: {}", vul.get_risk_cn(), vul.get_risk_num(), vul.to_issue_record());
                let mut cve = cached_vul.cve.to_string();
                new_vul = cached_vul.clone();

                if vul.get_risk_num() >= cached_vul.get_risk_num() { 
                    // println!("{}, {}", cached_vul.to_issue_record(), vul.to_issue_record());
                    println!("发现更高风险，更新risk等级:{}({}) -> {}({})", cached_vul.get_risk_cn(), cached_vul.get_risk_num(), vul.get_risk_cn(), vul.get_risk_num());
                    new_vul.severity = vul.severity.to_string();
                    let mut cached_cves: Vec<String> = cached_vul.cve.to_string().split(",").map(|x|x.to_string()).collect();

                    if !vul.cve.is_empty() { 
                        println!("更新cve: {}; {}", vul.cve, cached_vul.cve);
                        match vul.cve.cmp(&cached_cves[0]) {
                            Ordering::Greater => {
                                let solution = vul.solution.to_string();
                                if let Some(_solution) = solution.get(19..solution.len()-9) {
                                    println!("更新解决方案: {}", _solution.trim());
                                    new_vul.solution = format!("建议升级至{}或更高版本", _solution.trim().to_string());
                                }
                                cached_cves.insert(0, vul.cve.to_string());
                            },
                            Ordering::Equal=> {
                                println!("重复组件跳过, 忽略合并...");
                                continue;
                            },
                            _ => {
                                cached_cves.push(vul.cve.to_string());
                            },
                        } 
                    } 
                    if cached_cves.len() > 3 {
                        cached_cves.sort();
                        println!("cve数量过多，裁剪至3个");
                        cve = cached_cves[0..3].join(",");
                    } else {
                        cve = cached_cves.join(",");
                    } 
                    new_vul.cve = cve;
                    // new_vul.description = format!("{}风险组件, 详情可查看", vul.get_risk_cn());
                    new_vul.description =  format!("{}风险组件, 详情可查看[{}](https://avd.aliyun.com/detail/{}/)", vul.get_risk_cn(), vul.cve, vul.cve);
                }                 
            } else {
                println!("插入新组件: {}, risk: {}, cve: {}", vul.dependency_name, vul.get_risk_cn(), vul.cve);
                let mut solution = String::from("升级到稳定修复版本");
                if let Some(_solution) = vul.solution.get(19..vul.solution.len()-9) {
                    println!("更新解决方案: {}", _solution.trim());
                    solution = format!("建议升级至{}或更高版本", _solution.trim().to_string());
                }
                // map中不存在key
                new_vul = SCAVul{
                    message: vul.message.to_string(),
                    description: format!("{}风险组件, 详情可查看[{}](https://www.cvedetails.com/cve/{}/)", vul.get_risk_cn(), vul.cve, vul.cve),
                    severity: vul.severity.to_string(),
                    cve: vul.cve.to_string(),
                    location: String::from("位置预留，导出报告时填充"),
                    solution: solution,
                    dependency_name: vul.dependency_name.to_string(),
                    dependency_version: vul.dependency_version.to_string(),
                };
            }
            cached_issues_map.insert(vul.dependency_name.to_string(), new_vul.clone());
        }

        for (dep, vul) in cached_issues_map.iter() {
            println!("{}", vul.to_issue_record());
        }
        self.cached_vuls_map.extend(cached_issues_map.clone());

        issues_map
    }

    pub async fn merge_issues(
        self: &mut Self,
        vulMap: HashMap<String, Vec<SCAVul>>,
    ) -> HashMap<String, Vec<SCAVul>> {
        let mut result: HashMap<String, Vec<SCAVul>> = HashMap::new();
        let mut risk_cache_issues: HashMap<String, String> = HashMap::new();
        debug!("merge_issues....");
        for (location, vuls) in vulMap {
            let tmp: Vec<&str> = location.split("/").collect();
            let module: &str = tmp[0];
            let mut tmp_vuls: HashMap<String, Vec<SCAVul>> = HashMap::new();

            println!(
                "----------------------------------{}------------------------------------------",
                location
            );
            // 合并为完整信息并提交ai合并
            let mut issue: String = String::new();
            let mut _issues = vec![];
            for vul in vuls.iter() {
                // let key = format!("{}:{}", vul.dependency_name, vul.dependency_version);
                // issue = format!("{issue}\n{}", vul.to_issue_record());
                _issues.push(vul.to_issue_record());
            }
            _issues.sort();
            issue = _issues.join("\n");

            let content: String = self.get_prompt(issue.as_str());

            let mut resp: String = llm::ask_hg_ai_new(content.as_str()).await.unwrap();
            resp = llm::ask_hg_ai_new(
                self.get_prompt(resp.trim_matches('"').replace("\\n", "\n").as_str())
                    .as_str(),
            )
            .await
            .unwrap();  //// 仅调用一次AI
            debug!("input: {content}");
            println!("resp: {resp}");

            let mut merged_vuls: Vec<SCAVul> = vec![];
            for line in resp.trim_matches('"').split(r"\n") {
                // let [dependency, severity, cve, location, solution, description]: [&str; 6] = line.trim_matches('|').split("|").collect::<Vec<&str>>().as_slice().try_into().unwrap();
                let [_, dependency, severity, cve, location, solution, description, _]: [&str; 8] =
                    line.split("|")
                        .collect::<Vec<&str>>()
                        .as_slice()
                        .try_into()
                        .unwrap();
                // println!("{dependency}; {severity}; {cve}; {location}; {solution}; {description}");

                let [dependency_name, dependency_version] = dependency
                    .split(":")
                    .collect::<Vec<&str>>()
                    .as_slice()
                    .try_into()
                    .unwrap();
                let _vul = SCAVul {
                    message: String::new(),
                    description: description.to_owned(),
                    severity: severity.to_owned(),
                    cve: cve.to_owned(),
                    location: location.to_owned(),
                    solution: solution.to_owned(),
                    dependency_name: dependency_name.to_owned(),
                    dependency_version: dependency_version.to_owned(),
                };
                merged_vuls.push(_vul.clone());
                self.merged_vuls.push(_vul.clone());
            }
            result.insert(location.to_owned(), merged_vuls.clone());
            self.merged_vuls_map
                .insert(location.to_owned(), merged_vuls.clone());

            debug!("-----------------------------------------------------------------------------------------");
        }

        result
    }

    // 
    pub async fn opt_issue(self: &Self, issue: &str) -> String {
        let body = format!("{}, 上述内容为一个markdown格式的sca报告，使用markdown逐行解析记录，分析合并其中相同的组件及其风险，descriptioin可以使用中文优化一下，尽量做到比原始description内容短，并将优化后的markdown文件返回给我, 要求不改变原文件格式，仅优化其中的内容", issue);
        llm::ask_ai(body.as_str()).await.unwrap()
    }
}

impl BaseParser<SCAVul> for SCAReport {
    fn parse(self: &mut Self, content: &str) -> &Vec<SCAVul> {
        let report: Value = serde_json::from_str(content).expect("Failed to parse JSON");
        if let Some(vuls) = report["vulnerabilities"].as_array() {
            for vul in vuls {
                println!("{}", vul.to_string());
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
        const COLS: [&str; 7] = [
            "id",
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
        let header: String = format!("{title}\n{sep}");
        let mut desc: String = String::new();
        let mut idx = 1;
        let mut vuls: &Vec<SCAVul> = &self.vuls;
        if self.merged_vuls_map.len() > 1 {
            //   vuls = &self.merged_vuls;
            // }
            
            for (loc, vuls) in &self.merged_vuls_map {
                idx = 1;
                let sep_start = format!("----------------------------------{loc}------------------------------------------");
                desc = format!("{desc}\n{sep_start}\n{header}");
                for vul in vuls.iter() {
                    desc = format!(
                        "{desc}\n|{idx}{}",
                        vul.to_issue_record()
                            .trim()
                            .replace("\\n", "<br>")
                            .replace("\n", "<br>")
                    );
                    idx += 1;
                }

                desc = format!("{desc}\n\n");
            }
        } else {
            for vul in vuls.iter() {
                desc = format!(
                    "{desc}\n|{idx}{}",
                    vul.to_issue_record()
                        .trim()
                        .replace("\\n", "<br>")
                        .replace("\n", "<br>")
                );
                idx += 1;
            }
        }

        let mut issue: Issue = Issue::new();
        issue.engine = self.engine.to_string();
        issue.project_id = CI_PROJECT_ID.to_string();
        issue.title = format!("{} scan report", self.engine);
        issue.description = format!("<br>报告详情（如果表格中存在重复内容请忽略）如下：<br>\n{desc}");

        debug!("desc: {}", issue.description);
        issue
    }

    async fn filter(self: &mut Self) -> Vec<SCAVul> {
        self.vuls.clone()
    }
}

impl BaseReport<SCAVul> for SCAReport {
    async fn report(self: &mut Self) {
        println!("sca report...");
        self.filter().await;
        self.count_vuln();

        if CI_MERGE_REQUEST_IID.as_str() == "" {
            log::error!("no merge request, skip create issue...");
            return;
        }
        

        //// 用于合并组件风险
        self.merge_issues_local(); // 本地合并

        let mut m = self.group_issue_local();

        // m = self.merge_issues(m).await; // 调用ai合并分支
        for (g, vs) in m.iter() {
            println!(
                "----------------------------------{g}------------------------------------------"
            );
            // println!("group: {}", g);
            for v in vs.iter() {
                println!("{}", v.to_issue_record());
            }
            println!("-----------------------------------------------------------------------------------------");
        }

        // 临时注释开始
        println!("{}", self.to_issue().to_string());

        if self.vuls.len() < 1 {
            info!("skip, no sca vuls...");
            return;
        }
        // 临时注释结束

        //// 调用AI优化组件风险
        // self.opt_descs().await;

        // let body: String = gitlab::list_issue(
        //     CI_PROJECT_ID.as_str(),
        //     GITLAB_USER_ID.as_str(),
        //     self.engine.as_str(),
        // )
        // .await
        // .unwrap();

        //// 输出风险内容
        // let json: Value = serde_json::from_str(body.as_str()).expect("not valid json format");

        // let mut issue_iids: Vec<String> = vec![];
        // for item in json.as_array().unwrap_or(&Vec::new()) {
        //     let issue_iid: String = item["iid"].to_string();
        //     debug!("issue_iid:{issue_iid}");
        //     let _ = gitlab::close_issue(CI_PROJECT_ID.as_str(), issue_iid.as_str()).await;
        //     issue_iids.push(issue_iid);
        // }
        // println!("{:?}", issue_iids);

        // let res = self.opt_issue(&self.to_issue().description.as_str()).await;
        // println!("--------------------------------------------------------------------------------------------------------------------------------------------\nafter issue: {}", res);

        let _ = gitlab::new_issue(&self.to_issue()).await;

        //// ai结果上报
        // let issue = Issue {
        //     engine: self.engine,
        //     project_id: CI_PROJECT_ID.to_string(),
        //     title: issue.title = format!("{} scan report", self.engine),
        //     description: todo!(),
        //     assignee_id: ,
        // }
    }
}
