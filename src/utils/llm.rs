use std::{fmt::Error, time::Duration};

use http::{HeaderMap, HeaderValue};
use lazy_static::lazy_static;
use log::debug;
use reqwest::Client;
use serde_json::json;
use gradio::{PredictionInput, ClientOptions};

use crate::conf::setting::{AI_HOST, AI_TOKEN, HG_AI_CLIENT};


// for huggingface 在线模型
pub async fn init() {
  let client = Box::new(gradio::Client::new("Qwen/Qwen2.5-72B-Instruct", gradio::ClientOptions::default()).await.unwrap());
  // let client = Box::new(gradio::Client::new("Rijgersberg/Qwen2.5-7B-Instruct", gradio::ClientOptions::default()).await.unwrap());
 
  unsafe {
      HG_AI_CLIENT = Some(Box::leak(client));
  }
}

// TODO: 使用llm确认风险是否存在，并提供解决方案
lazy_static! {
    static ref DEFAULT_HEADERS: HeaderMap = {
        let mut m = HeaderMap::new();
        // m.insert("Authorization", HeaderValue::from_str(format!("Bearer {}", AI_TOKEN.as_str()).as_str()).unwrap());
        m.insert("Authorization", HeaderValue::from_str(format!("Bearer F-eIS-KNmrQr-QEFF9x-y8Ry9k1LqMKEKzZaetI6").as_str()).unwrap());
        m.insert("Content-Type", HeaderValue::from_str("application/json").unwrap());
        m
    };
    // DEFAULT_HEADERS
    static ref AI_CLIENT: Client = Client::builder().default_headers(DEFAULT_HEADERS.clone()).timeout(Duration::from_secs(3600)).build().unwrap();
    // static ref HG_AI_CLIENT: gradio::Client = gradio::Client::new_sync("Qwen/Qwen2.5-72B-Instruct", gradio::ClientOptions::default()).unwrap();
}

// const PROMPT: &'static str =  "as a secruity experter, you can analyze source code, verify and check vuln. when i give you a risk report which formatted as markdown table and part of source code, you must read every row, and check where the risk exists, if yes, you can simplify the risk info and translate to chinese, and append a new col named solution which is a well-done suggestion for processing the risk";
const PROMPT: &'static str = "你是一名安全专家Qwen，精通安全的各个方向，包括代码审计、渗透测试、数据安全、安全事件、安全溯源等。你可以深入理解提问问题，并根据问题进行答复，在进行真正应答前，根据提问评估答复内容匹配程度，如果匹配不佳，结合评估的结果重复生成并继续评估和优化，最多重复5轮，以匹配度最高的作为答复真正进行应答。要求使用中文答复，内容简洁无多余空白字符，禁止添加多余内容。";
// const MODEL: &'static str = "gemma2:2b";
const MODEL: &'static str = "qwen2.5:3b-instruct";
// const MODEL: &'static str = "phi3.5:3.8b-mini-instruct-q4_0";
// const MODEL: &'static str = "@cf/qwen/qwen1.5-7b-chat-awq";

// const PREFIX: &'static str = "/v1/chat/completions"; // for cloudflared playground ai platform
const PREFIX: &'static str = "/api/generate"; // for local ollama

pub async fn ask_hg_ai_new(content: &str) -> Result<String, std::fmt::Error> {
  let mut result: String;
  unsafe {
    match HG_AI_CLIENT.as_ref() {
      None => {
        Err(Error)
      }
      Some(client)=> {
        let output = (*client)
          .predict("/model_chat", vec![
              gradio::PredictionInput::from_value(content), 
              // gradio::PredictionInput::from_value("把下文翻译为英语：你好，很高兴认识你"),
              gradio::PredictionInput::from_value(vec![["Hello!", ""]]),
              gradio::PredictionInput::from_value("You are Qwen, created by Alibaba Cloud. You are a helpful assistant."),

            ]
          )
          .await
          .unwrap();

        result = output[1].clone().as_value().unwrap().as_array().unwrap().get(1).unwrap().get(1).unwrap().to_string();
        debug!("Output: {:?}", result);
        Ok(result)
      }
    }
  }
  // unsafe {
  //   let output = HG_AI_CLIENT.unwrap()
  //   .predict_sync("/model_chat", vec![
  //       gradio::PredictionInput::from_value("把下文翻译为英语：你好，很高兴认识你"),
  //       gradio::PredictionInput::from_value(vec![["Hello!", ""]]),
  //       gradio::PredictionInput::from_value("You are Qwen, created by Alibaba Cloud. You are a helpful assistant."),

  //       //// 新测试样本, not working
  //       // gradio::PredictionInput::from_value(_data),
  //       // gradio::PredictionInput::from_value(""),
  //       // gradio::PredictionInput::from_value(1),
  //       // gradio::PredictionInput::from_value("7xa55s9mvb6"),
  //       // gradio::PredictionInput::from_value(14),
  //     ]
  //   )
  //   .unwrap();


  //   result = output[1].clone().as_value().unwrap().as_array().unwrap().get(1).unwrap().get(1).unwrap().to_string();
  //   println!("Output: {:?}", result);
  // }

  // Ok(result)
}

pub async fn ask_hg_ai(content: &str) -> Result<String, std::fmt::Error> {
    let mut url: String = String::from("https://qwen-qwen2-5-72b-instruct.hf.space/call/model_chat");
    let data = json!({
      "data": [
        content,
        [],
        PROMPT
      ],
      "event_data":null,
      "fn_index":0,
      "trigger_id":11,
      "session_hash":"wkhcqgptf"
    });

    let _data = serde_json::to_string(&data).unwrap();

    let event_json = AI_CLIENT.post(url.as_str()).body(_data.to_owned())
    .send().await.unwrap()
    .text().await.unwrap();

    let d: serde_json::Value = serde_json::from_str(&event_json).unwrap();
    let event_id = d["event_id"].to_string();
    println!("response: {event_id}");

    url = format!("{url}/{event_id}");
    
    let resp = AI_CLIENT.get(url).body(_data.to_owned()).send().await.unwrap().text().await.unwrap();

    Ok(resp)
}

pub async fn ask_ai(content: &str) -> Result<String, std::fmt::Error> {
    // let url = format!("{}{PREFIX}", AI_HOST.as_str());
    // let url = format!("{}{PREFIX}", "https://api.cloudflare.com//client/v4/accounts/c5b0a0c59935b38f58043b0589cee642/ai");
    let url = format!("{}{PREFIX}", "https://ollama.pings.us.kg");

    let data = json!({
      "model": MODEL,
      // "messages": [
      //   {
      //     "role": "system",
      //     "content": PROMPT
      //   },
      //   {
      //     "role": "user",
      //     "content": content
      //   }
      // ],
      "prompt": content,
      // "system": PROMPT,
      "stream": false,
      "keep-alive": 600
    });
    log::debug!("ask_ai url: {}", url);

    let resp = AI_CLIENT
        .post(url)
        .body(serde_json::to_string(&data).unwrap())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    log::debug!("response: {resp}");

    Ok(resp)
}
