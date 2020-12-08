//! A crate for using AWS KMS

extern crate rusoto_core;

use rusoto_core::Region;
use rusoto_kms::{KeyListEntry, Kms, KmsClient, ListKeysRequest, ListKeysResponse};
use tokio::runtime::Runtime;

/// Gets the list of all Customer Master Keys (CMKs) in current AWS account (defaults to us-east-1).
pub fn list_keys() -> Vec<String> {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(get_keys(get_client()))
}

async fn get_keys(client: KmsClient) -> Vec<String> {
    let request = ListKeysRequest::default();

    let response: ListKeysResponse = client.list_keys(request).await.unwrap();
    parse_key_list_entries(response.keys.unwrap_or_default())
}

fn get_client() -> KmsClient {
    KmsClient::new(Region::UsEast1)
}

fn parse_key_list_entries(key_list: Vec<KeyListEntry>) -> Vec<String> {
    let mut keys_str: Vec<String> = Vec::new();
    for key in key_list {
        let mut key_str: String = String::from(&key.key_arn.unwrap_or_default());
        key_str.push('|');
        key_str.push_str(&key.key_id.unwrap_or_default());
        keys_str.push(key_str);
    }

    keys_str
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_list_entries() {
        let mut mock_key_list: Vec<KeyListEntry> = Vec::new();
        let first_key = KeyListEntry {
            key_arn: Some(String::from(
                "arn:aws:kms:us-east-1:123456789:key/abcd-4321-wxyz",
            )),
            key_id: Some(String::from("abcd-4321-wxyz")),
        };
        let second_key = KeyListEntry {
            key_arn: Some(String::from(
                "arn:aws:kms:us-east-1:123456789:key/efgh-8765-stuv",
            )),
            key_id: Some(String::from("efgh-8765-stuv")),
        };
        mock_key_list.push(first_key);
        mock_key_list.push(second_key);
        assert_eq!(
            parse_key_list_entries(mock_key_list),
            vec![
                "arn:aws:kms:us-east-1:123456789:key/abcd-4321-wxyz|abcd-4321-wxyz",
                "arn:aws:kms:us-east-1:123456789:key/efgh-8765-stuv|efgh-8765-stuv"
            ]
        );
    }
}
