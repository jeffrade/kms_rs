use std::env;

extern crate kms_rs;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        let keys: serde_json::value::Value = kms_rs::list_keys();
        println!("{}", keys.to_string());
    } else {
        let cmd: &str = &args[1];
        match cmd {
            "describe-key" => {
                let key_id = &args[2];
                let key: serde_json::value::Value = kms_rs::describe_key(key_id);
                println!("{}", key.to_string());
            }
            _ => println!("{} command not supported!", cmd),
        }
    }
}
