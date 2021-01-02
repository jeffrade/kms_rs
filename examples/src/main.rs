extern crate clap;
extern crate kms_rs;

// clap examples: https://github.com/clap-rs/clap/blob/33bebeda52b52c6f643b4ed6fa880671ba0ab80a/examples
fn main() {
    let matches = clap::App::new("KmsRsExample")
        .version("0.1.0")
        .author("Jeff Rade <jeffrade@gmail.com>")
        .about("Example command line tool showing usage of kms_rs")
        .subcommand(
            clap::SubCommand::with_name("list-keys")
                .about("Gets a list of all customer master keys (CMKs) in the caller's AWS account and Region.")
        )
        .subcommand(
            clap::SubCommand::with_name("describe-key")
                .about("Provides detailed information about a customer master key (CMK).")
                .arg_from_usage("--key-id=[KEYID] 'metadata for a given key-id'")
        )
        .subcommand(
            clap::SubCommand::with_name("create-key")
                .about("Creates a unique customer managed customer master key (CMK) in your AWS account and Region.")
        )
        .subcommand(
            clap::SubCommand::with_name("schedule-key-deletion")
                .about("Schedules the deletion of a customer master key (CMK). You may provide a waiting period, specified in days, before deletion occurs.")
                .arg_from_usage("--key-id=[KEYID] 'key-id to delete'")
                .arg_from_usage("--pending-window-in-days=[WINDOW_DAYS] 'between 7 and 30 inclusive (defaults to 30)'")
        )
        .subcommand(
            clap::SubCommand::with_name("cancel-key-deletion")
            .about("Cancels the deletion of a customer master key (CMK). When this operation succeeds, the key state of the CMK is Disabled.")
            .arg_from_usage("--key-id=[KEYID] 'key-id to cancel deletion'")
        )
        .subcommand(
            clap::SubCommand::with_name("enable-key")
                .about("Sets the key state to enabled of a customer master key (CMK) to enabled.")
                .arg_from_usage("--key-id=[KEYID] 'key-id to enable'")
        )
        .subcommand(
            clap::SubCommand::with_name("disable-key")
                .about("Sets the key state to disabled of a customer master key (CMK) to enabled.")
                .arg_from_usage("--key-id=[KEYID] 'key-id to disable'")
        )
        .subcommand(
            clap::SubCommand::with_name("generate-data-key")
                .about("foobar")
                .arg_from_usage("--key-id=[KEYID] 'key-id to encrypt with'")
        )
        .subcommand(
            clap::SubCommand::with_name("generate-data-key-without-plaintext")
                .about("barfoo")
                .arg_from_usage("--key-id=[KEYID] 'key-id to encrypt with'")
        )
        .get_matches();

    if matches.subcommand_matches("list-keys").is_some() {
        let keys: serde_json::value::Value = kms_rs::list_keys();
        println!("{}", keys.to_string());
    } else if let Some(matches) = matches.subcommand_matches("generate-data-key") {
        let key_id: &str = matches.value_of("key-id").unwrap();
        let resp: serde_json::value::Value = kms_rs::generate_data_key(key_id, Some("AES_128".to_string()), None);
        println!("{}", resp.to_string());
    } else if let Some(matches) = matches.subcommand_matches("generate-data-key-without-plaintext") {
        let key_id: &str = matches.value_of("key-id").unwrap();
        let resp: serde_json::value::Value = kms_rs::generate_data_key_without_plaintext(key_id, None, Some(196 as i64));
        println!("{}", resp.to_string());
    } else if let Some(matches) = matches.subcommand_matches("describe-key") {
        if matches.is_present("key-id") {
            let key_id: &str = matches.value_of("key-id").unwrap();
            let resp: serde_json::value::Value = kms_rs::describe_key(key_id);
            println!("{}", resp.to_string());
        } else {
            println!("You must provide the key-id arg!");
        }
    } else if matches.subcommand_matches("create-key").is_some() {
        let resp: serde_json::value::Value = kms_rs::create_key();
        println!("{}", resp.to_string());
    } else if let Some(matches) = matches.subcommand_matches("schedule-key-deletion") {
        if matches.is_present("key-id") {
            let key_id: String = matches.value_of("key-id").unwrap().to_string();
            if matches.is_present("pending-window-in-days") {
                match matches
                    .value_of("pending-window-in-days")
                    .unwrap()
                    .parse::<i64>()
                {
                    Ok(days) => {
                        let resp: serde_json::value::Value =
                            kms_rs::schedule_key_deletion(key_id, days);
                        println!("{}", resp.to_string())
                    }
                    Err(value) => println!("Error: {:?}", value),
                }
            } else {
                let resp: serde_json::value::Value =
                    kms_rs::schedule_key_deletion(key_id, 30 as i64);
                println!("{}", resp.to_string())
            }
        } else {
            println!("You must provide the key-id arg!");
        }
    } else if let Some(matches) = matches.subcommand_matches("cancel-key-deletion") {
        if matches.is_present("key-id") {
            let key_id: String = matches.value_of("key-id").unwrap().to_string();
            let resp: serde_json::value::Value = kms_rs::cancel_key_deletion(key_id);
            println!("{}", resp.to_string());
        } else {
            println!("You must provide the key-id arg!");
        }
    } else if let Some(matches) = matches.subcommand_matches("enable-key") {
        if matches.is_present("key-id") {
            let key_id: &str = matches.value_of("key-id").unwrap();
            match kms_rs::enable_key(key_id) {
                Some(resp) => println!("{}", resp.to_string()),
                None => (),
            }
        } else {
            println!("You must provide the key-id arg!");
        }
    } else if let Some(matches) = matches.subcommand_matches("disable-key") {
        if matches.is_present("key-id") {
            let key_id: &str = matches.value_of("key-id").unwrap();
            match kms_rs::disable_key(key_id) {
                Some(resp) => println!("{}", resp.to_string()),
                None => (),
            }
        } else {
            println!("You must provide the key-id arg!");
        }
    } else {
        println!("You must pass a valid command!");
    }
}
