extern crate kms_rs;

fn main() {
    let keys: Vec<String> = kms_rs::list_keys();
    println!("{:?}", keys);
}
