use std::env;

extern crate kms_rs;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        let keys: Vec<String> = kms_rs::list_keys();
        println!("{:?}", keys);
    } else {
        let cmd: &str = &args[1];
        match cmd {
            "describe-key" => {
                let key_id = &args[2];
                let key: String = kms_rs::describe_key(key_id);
                println!("{}", key);
            }
            _ => println!("{} command not supported!", cmd),
        }
    }
}
