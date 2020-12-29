//! A crate for using AWS KMS
#![allow(non_snake_case)]

extern crate rusoto_core;

use rusoto_core::Region;
use rusoto_kms::{
    CreateKeyRequest, DescribeKeyRequest, KeyListEntry, KeyMetadata, Kms, KmsClient,
    ListKeysRequest, ScheduleKeyDeletionRequest, ScheduleKeyDeletionResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::value::Value;
use tokio::runtime::Runtime;

#[derive(Serialize, Deserialize, Debug)]
struct KmsRsKey {
    KeyId: String,
    KeyArn: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct KmsRsKeyMetadata {
    KeyId: String,
    Arn: String,
    Description: String,
    Enabled: bool,
}

fn get_client() -> KmsClient {
    KmsClient::new(Region::UsEast1)
}

/// Gets the list of all Customer Master Keys (CMKs) in current AWS account (defaults to us-east-1).
pub fn list_keys() -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(get_keys(get_client()))
}

pub fn describe_key(key_id: &str) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(get_key(get_client(), key_id))
}

pub fn create_key() -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(create_key_and_parse(get_client()))
}

pub fn schedule_key_deletion(key_id: String, pending_window_in_days: i64) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(schedule_key_deletion_and_parse(
            get_client(),
            key_id,
            pending_window_in_days,
        ))
}

async fn get_key(client: KmsClient, key_id: &str) -> Value {
    let request = DescribeKeyRequest {
        grant_tokens: None,
        key_id: key_id.to_string(),
    };

    let result = client.describe_key(request).await;

    match result {
        Ok(response) => parse_key_metadata(response.key_metadata.unwrap_or_default()),
        Err(value) => json!(value.to_string()),
    }
}

async fn get_keys(client: KmsClient) -> Value {
    let request = ListKeysRequest::default();

    let result = client.list_keys(request).await;

    match result {
        Ok(response) => parse_key_list_entries(response.keys.unwrap_or_default()),
        Err(value) => json!(value.to_string()),
    }
}

async fn create_key_and_parse(client: KmsClient) -> Value {
    let mut request = CreateKeyRequest::default();
    request.key_usage = Some("ENCRYPT_DECRYPT".to_string()); // default
    request.customer_master_key_spec = Some("SYMMETRIC_DEFAULT".to_string()); // default

    let result = client.create_key(request).await;

    match result {
        Ok(response) => parse_key_metadata(response.key_metadata.unwrap_or_default()),
        Err(value) => json!(value.to_string()),
    }
}

async fn schedule_key_deletion_and_parse(
    client: KmsClient,
    key_id: String,
    pending_window_in_days: i64,
) -> Value {
    let request = ScheduleKeyDeletionRequest {
        key_id: key_id.to_string(),
        pending_window_in_days: Some(pending_window_in_days),
    };

    let result = client.schedule_key_deletion(request).await;

    match result {
        Ok(response) => parse_schedule_deletion_response(response),
        Err(value) => json!(value.to_string()),
    }
}

fn parse_key_list_entries(key_list: Vec<KeyListEntry>) -> Value {
    let mut keys_json: Vec<KmsRsKey> = Vec::new();

    for key in key_list {
        keys_json.push(KmsRsKey {
            KeyId: key.key_id.unwrap_or_default(),
            KeyArn: key.key_arn.unwrap_or_default(),
        });
    }

    json!({ "Keys": &keys_json })
}

fn parse_key_metadata(metatdata: KeyMetadata) -> Value {
    let key_metadata = KmsRsKeyMetadata {
        KeyId: metatdata.key_id,
        Arn: metatdata.arn.unwrap_or_default(),
        Description: metatdata.description.unwrap_or_default(),
        Enabled: metatdata.enabled.unwrap_or_default(),
    };
    json!(&key_metadata)
}

fn parse_schedule_deletion_response(
    schedule_key_deletion_response: ScheduleKeyDeletionResponse,
) -> Value {
    json!({
        "KeyId": schedule_key_deletion_response.key_id.unwrap_or_default(),
        "DeletionDate": schedule_key_deletion_response.deletion_date.unwrap_or_default(),
    })
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
        let actual_output = parse_key_list_entries(mock_key_list);
        let expected_output = json!({ "Keys":
            [
                {
                    "KeyId": "abcd-4321-wxyz",
                    "KeyArn": "arn:aws:kms:us-east-1:123456789:key/abcd-4321-wxyz"
                },
                {
                    "KeyId": "efgh-8765-stuv",
                    "KeyArn": "arn:aws:kms:us-east-1:123456789:key/efgh-8765-stuv"
                }
            ]

        });
        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn test_parse_key_metadata() {
        let mock_key_metadata: KeyMetadata = KeyMetadata {
            arn: Some("arn:aws:kms:us-east-1:123456789:key/abcd-4321-wxyz".to_string()),
            aws_account_id: Some("1234567899".to_string()),
            creation_date: Some(1234567.89),
            custom_key_store_id: Some("".to_string()),
            cloud_hsm_cluster_id: Some("".to_string()),
            customer_master_key_spec: Some("SYMMETRIC_DEFAULT".to_string()),
            deletion_date: Some(1234567.89),
            description: Some(
                "Default master key that protects my EBS volumes when no other key is defined"
                    .to_string(),
            ),
            enabled: Some(true),
            encryption_algorithms: Some(vec!["SYMMETRIC_DEFAULT".to_string()]),
            expiration_model: Some("".to_string()),
            key_id: "abcd-4321-wxyz".to_string(),
            key_manager: Some("".to_string()),
            key_state: Some("Enabled".to_string()),
            key_usage: Some("ENCRYPT_DECRYPT".to_string()),
            origin: Some("AWS_KMS".to_string()),
            signing_algorithms: None,
            valid_to: Some(12345678.90),
        };
        let actual_output = parse_key_metadata(mock_key_metadata);
        let expected_output = json!({
            "KeyId": "abcd-4321-wxyz",
            "Arn": "arn:aws:kms:us-east-1:123456789:key/abcd-4321-wxyz",
            "Description": "Default master key that protects my EBS volumes when no other key is defined",
            "Enabled": true
        });
        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn test_parse_schedule_deletion_response() {
        let mock_key_deletion_response = ScheduleKeyDeletionResponse {
            key_id: Some("abcd-4321-wxyz".to_string()),
            deletion_date: Some(12345678.90),
        };
        let actual_output = parse_schedule_deletion_response(mock_key_deletion_response);
        let expected_output = json!({
            "KeyId": "abcd-4321-wxyz",
            "DeletionDate": 12345678.90
        });
        assert_eq!(actual_output, expected_output);
    }
}
