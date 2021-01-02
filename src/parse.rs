//! Parsing functions to handle Responses from rusoto_kms.
#![allow(non_snake_case)]

use bytes::Bytes;
use rusoto_kms::{
    CancelKeyDeletionResponse, GenerateDataKeyResponse, GenerateDataKeyWithoutPlaintextResponse,
    KeyListEntry, KeyMetadata, ScheduleKeyDeletionResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::value::Value;

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

pub fn key_list_entries(key_list: Vec<KeyListEntry>) -> Value {
    let mut keys_json: Vec<KmsRsKey> = Vec::new();

    for key in key_list {
        keys_json.push(KmsRsKey {
            KeyId: key.key_id.unwrap_or_default(),
            KeyArn: key.key_arn.unwrap_or_default(),
        });
    }

    json!({ "Keys": &keys_json })
}

pub fn key_metadata(metatdata: KeyMetadata) -> Value {
    let key_metadata = KmsRsKeyMetadata {
        KeyId: metatdata.key_id,
        Arn: metatdata.arn.unwrap_or_default(),
        Description: metatdata.description.unwrap_or_default(),
        Enabled: metatdata.enabled.unwrap_or_default(),
    };
    json!(&key_metadata)
}

pub fn schedule_deletion_response(
    schedule_key_deletion_response: ScheduleKeyDeletionResponse,
) -> Value {
    json!({
        "KeyId": schedule_key_deletion_response.key_id.unwrap_or_default(),
        "DeletionDate": schedule_key_deletion_response.deletion_date.unwrap_or_default(),
    })
}

pub fn cancel_deletion_response(response: CancelKeyDeletionResponse) -> Value {
    json!({
        "KeyId": response.key_id.unwrap_or_default(),
    })
}

pub fn data_key_response(response: GenerateDataKeyResponse) -> Value {
    let key_id: Option<String> = response.key_id;
    let ciphertext_blob: Option<String> = bytes_to_base64(response.ciphertext_blob);
    let plaintext: Option<String> = bytes_to_base64(response.plaintext);
    parse_data_key_fields(key_id, ciphertext_blob, plaintext)
}

pub fn data_key_without_plaintext_response(
    response: GenerateDataKeyWithoutPlaintextResponse,
) -> Value {
    let key_id: Option<String> = response.key_id;
    let ciphertext_blob: Option<String> = bytes_to_base64(response.ciphertext_blob);
    parse_data_key_fields(key_id, ciphertext_blob, None)
}

fn parse_data_key_fields(
    key_id: Option<String>,
    ciphertext_blob: Option<String>,
    plaintext: Option<String>,
) -> Value {
    if plaintext.is_some() {
        json!({
            "CiphertextBlob": ciphertext_blob,
            "Plaintext": plaintext,
            "KeyId": key_id,
        })
    } else {
        json!({
            "CiphertextBlob": ciphertext_blob,
            "KeyId": key_id,
        })
    }
}

fn bytes_to_base64(bytes: Option<Bytes>) -> Option<String> {
    if bytes.is_none() {
        None
    } else {
        Some(base64::encode(bytes.unwrap_or_default()))
    }
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
        let actual_output = key_list_entries(mock_key_list);
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
    fn test_key_metadata() {
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
        let actual_output = key_metadata(mock_key_metadata);
        let expected_output = json!({
            "KeyId": "abcd-4321-wxyz",
            "Arn": "arn:aws:kms:us-east-1:123456789:key/abcd-4321-wxyz",
            "Description": "Default master key that protects my EBS volumes when no other key is defined",
            "Enabled": true
        });
        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn test_schedule_deletion_response() {
        let mock_key_deletion_response = ScheduleKeyDeletionResponse {
            key_id: Some("abcd-4321-wxyz".to_string()),
            deletion_date: Some(12345678.90),
        };
        let actual_output = schedule_deletion_response(mock_key_deletion_response);
        let expected_output = json!({
            "KeyId": "abcd-4321-wxyz",
            "DeletionDate": 12345678.90
        });
        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn test_bytes_to_base64() {
        let bytes: Bytes = Bytes::from("abc-1234567890-$()*-_=+");
        let actual: String = bytes_to_base64(Some(bytes)).unwrap();
        let expected: String = "YWJjLTEyMzQ1Njc4OTAtJCgpKi1fPSs=".to_string();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_bytes_to_base64_with_none() {
        let actual: Option<String> = bytes_to_base64(None);
        assert_eq!(None, actual);
    }
}
