extern crate clap;
extern crate kms_rs;

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
        .get_matches();

    if matches.subcommand_matches("list-keys").is_some() {
        let keys: serde_json::value::Value = kms_rs::list_keys();
        println!("{}", keys.to_string());
    } else if let Some(matches) = matches.subcommand_matches("describe-key") {
        if matches.is_present("key-id") {
            let key_id: &str = matches.value_of("key-id").unwrap();
            let key: serde_json::value::Value = kms_rs::describe_key(key_id);
            println!("{}", key.to_string());
        } else {
            println!("You must provide the key-id arg!");
        }
    } else {
        println!("You must pass a valid command!");
    }
}
