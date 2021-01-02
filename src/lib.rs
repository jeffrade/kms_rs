//! A crate (still under construction) for interacting with AWS KMS. Uses [rusoto](https://github.com/rusoto/rusoto) and [tokio](https://github.com/tokio-rs/tokio).

use rusoto_core::Region;
use rusoto_kms::{
    CancelKeyDeletionRequest, CreateKeyRequest, DescribeKeyRequest, DisableKeyRequest,
    EnableKeyRequest, GenerateDataKeyRequest, GenerateDataKeyWithoutPlaintextRequest, Kms,
    KmsClient, ListKeysRequest, ScheduleKeyDeletionRequest,
}; // https://docs.rs/rusoto_kms/0.45.0/rusoto_kms/#structs
use serde_json::json;
use serde_json::value::Value;
use tokio::runtime::Runtime;

mod parse;

fn get_client() -> KmsClient {
    KmsClient::new(Region::UsEast1)
}

/// Gets the list of all Customer Master Keys (CMKs) in current AWS account (defaults to us-east-1).
pub fn list_keys() -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(get_keys(get_client()))
}

/// Provides detailed information about a customer master key (CMK).
pub fn describe_key(key_id: &str) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(get_key(get_client(), key_id))
}

/// Creates a unique customer managed customer master key (CMK) in your AWS account and Region.
pub fn create_key() -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(create_key_and_parse(get_client()))
}

/// Schedules the deletion of a customer master key (CMK). You may provide a waiting period, specified in days, before deletion occurs.
pub fn schedule_key_deletion(key_id: String, pending_window_in_days: i64) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(schedule_key_deletion_and_parse(
            get_client(),
            key_id,
            pending_window_in_days,
        ))
}

/// Cancels the deletion of a customer master key (CMK). When this operation succeeds, the key state of the CMK is Disabled.
pub fn cancel_key_deletion(key_id: String) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(cancel_key_deletion_and_parse(get_client(), key_id))
}

/// Sets the key state to disabled of a customer master key (CMK) to enabled.
pub fn disable_key(key_id: &str) -> Option<Value> {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(disable_key_and_respond(get_client(), key_id))
}

/// Sets the key state to enabled of a customer master key (CMK) to enabled.
pub fn enable_key(key_id: &str) -> Option<Value> {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(enable_key_and_respond(get_client(), key_id))
}

/// Generates a unique symmetric data key for client-side encryption. This operation returns a plaintext copy of the data key and a copy that is encrypted under a customer master key (CMK) that you specify.
pub fn generate_data_key(key_id: &str, key_spec: Option<String>, bytes: Option<i64>) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(generate_data_key_and_parse(
            get_client(),
            key_id,
            key_spec,
            bytes,
        ))
}

/// Generates a unique symmetric data key. This operation returns a data key that is encrypted under a customer master key (CMK) that you specify.
pub fn generate_data_key_without_plaintext(
    key_id: &str,
    key_spec: Option<String>,
    bytes: Option<i64>,
) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(generate_data_key_without_plaintext_and_parse(
            get_client(),
            key_id,
            key_spec,
            bytes,
        ))
}

async fn get_key(client: KmsClient, key_id: &str) -> Value {
    let request = DescribeKeyRequest {
        grant_tokens: None,
        key_id: key_id.to_string(),
    };

    let result = client.describe_key(request).await;

    match result {
        Ok(response) => parse::key_metadata(response.key_metadata.unwrap_or_default()),
        Err(value) => json!(value.to_string()),
    }
}

async fn get_keys(client: KmsClient) -> Value {
    let request = ListKeysRequest::default();

    let result = client.list_keys(request).await;

    match result {
        Ok(response) => parse::key_list_entries(response.keys.unwrap_or_default()),
        Err(value) => json!(value.to_string()),
    }
}

async fn create_key_and_parse(client: KmsClient) -> Value {
    let mut request = CreateKeyRequest::default();
    request.key_usage = Some("ENCRYPT_DECRYPT".to_string()); // default
    request.customer_master_key_spec = Some("SYMMETRIC_DEFAULT".to_string()); // default

    let result = client.create_key(request).await;

    match result {
        Ok(response) => parse::key_metadata(response.key_metadata.unwrap_or_default()),
        Err(value) => json!(value.to_string()),
    }
}

async fn schedule_key_deletion_and_parse(
    client: KmsClient,
    key_id: String,
    pending_window_in_days: i64,
) -> Value {
    let request = ScheduleKeyDeletionRequest {
        key_id,
        pending_window_in_days: Some(pending_window_in_days),
    };

    let result = client.schedule_key_deletion(request).await;

    match result {
        Ok(response) => parse::schedule_deletion_response(response),
        Err(value) => json!(value.to_string()),
    }
}

async fn cancel_key_deletion_and_parse(client: KmsClient, key_id: String) -> Value {
    let request = CancelKeyDeletionRequest { key_id };

    let result = client.cancel_key_deletion(request).await;

    match result {
        Ok(response) => parse::cancel_deletion_response(response),
        Err(value) => json!(value.to_string()),
    }
}

async fn enable_key_and_respond(client: KmsClient, key_id: &str) -> Option<Value> {
    let request = EnableKeyRequest {
        key_id: key_id.to_string(),
    };
    let result = client.enable_key(request).await;

    match result {
        Ok(()) => None, // AWS gives an empty response
        Err(value) => Some(json!(value.to_string())),
    }
}

async fn disable_key_and_respond(client: KmsClient, key_id: &str) -> Option<Value> {
    let request = DisableKeyRequest {
        key_id: key_id.to_string(),
    };
    let result = client.disable_key(request).await;

    match result {
        Ok(()) => None, // AWS gives an empty response
        Err(value) => Some(json!(value.to_string())),
    }
}

async fn generate_data_key_and_parse(
    client: KmsClient,
    key_id: &str,
    key_spec: Option<String>,
    bytes: Option<i64>,
) -> Value {
    let request = GenerateDataKeyRequest {
        encryption_context: None,
        grant_tokens: None,
        key_id: key_id.to_string(),
        key_spec,
        number_of_bytes: bytes,
    };

    let result = client.generate_data_key(request).await;

    match result {
        Ok(response) => parse::data_key_response(response),
        Err(value) => json!(value.to_string()),
    }
}

async fn generate_data_key_without_plaintext_and_parse(
    client: KmsClient,
    key_id: &str,
    key_spec: Option<String>,
    bytes: Option<i64>,
) -> Value {
    let request = GenerateDataKeyWithoutPlaintextRequest {
        encryption_context: None,
        grant_tokens: None,
        key_id: key_id.to_string(),
        key_spec,
        number_of_bytes: bytes,
    };

    let result = client.generate_data_key_without_plaintext(request).await;

    match result {
        Ok(response) => parse::data_key_without_plaintext_response(response),
        Err(value) => json!(value.to_string()),
    }
}
