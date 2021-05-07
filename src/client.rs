//! Module responsible for handling the requests and responses.

use bytes::Bytes;
use rusoto_core::Region;
use rusoto_kms::{
    CancelKeyDeletionRequest, CreateKeyRequest, DecryptRequest, DescribeKeyRequest,
    DisableKeyRequest, EnableKeyRequest, EncryptRequest, GenerateDataKeyPairRequest,
    GenerateDataKeyPairWithoutPlaintextRequest, GenerateDataKeyRequest,
    GenerateDataKeyWithoutPlaintextRequest, GenerateRandomRequest, GetPublicKeyRequest, Kms,
    KmsClient, ListKeysRequest, ScheduleKeyDeletionRequest, SignRequest, VerifyRequest,
}; // https://docs.rs/rusoto_kms/0.45.0/rusoto_kms/#structs
use serde_json::json;
use serde_json::value::Value;
use std::collections::HashMap;
use std::vec::Vec;

use crate::parse;

fn get_client() -> KmsClient {
    KmsClient::new(Region::UsEast1)
}

pub async fn get_key(key_id: &str) -> Value {
    let request = DescribeKeyRequest {
        grant_tokens: None,
        key_id: key_id.to_string(),
    };

    let result = get_client().describe_key(request).await;

    match result {
        Ok(response) => parse::key_metadata(response.key_metadata.unwrap_or_default()),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn get_keys() -> Value {
    let request = ListKeysRequest::default();

    let result = get_client().list_keys(request).await;

    match result {
        Ok(response) => parse::key_list_entries(response.keys.unwrap_or_default()),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn create_key_and_parse() -> Value {
    let mut request = CreateKeyRequest::default();
    request.key_usage = Some("ENCRYPT_DECRYPT".to_string()); // default
    request.customer_master_key_spec = Some("SYMMETRIC_DEFAULT".to_string()); // default

    let result = get_client().create_key(request).await;

    match result {
        Ok(response) => parse::key_metadata(response.key_metadata.unwrap_or_default()),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn schedule_key_deletion_and_parse(key_id: String, pending_window_in_days: i64) -> Value {
    let request = ScheduleKeyDeletionRequest {
        key_id,
        pending_window_in_days: Some(pending_window_in_days),
    };

    let result = get_client().schedule_key_deletion(request).await;

    match result {
        Ok(response) => parse::schedule_deletion_response(response),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn cancel_key_deletion_and_parse(key_id: String) -> Value {
    let request = CancelKeyDeletionRequest { key_id };

    let result = get_client().cancel_key_deletion(request).await;

    match result {
        Ok(response) => parse::cancel_deletion_response(response),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn enable_key_and_respond(key_id: &str) -> Option<Value> {
    let request = EnableKeyRequest {
        key_id: key_id.to_string(),
    };
    let result = get_client().enable_key(request).await;

    match result {
        Ok(()) => None, // AWS gives an empty response
        Err(value) => Some(json!(value.to_string())),
    }
}

pub async fn disable_key_and_respond(key_id: &str) -> Option<Value> {
    let request = DisableKeyRequest {
        key_id: key_id.to_string(),
    };
    let result = get_client().disable_key(request).await;

    match result {
        Ok(()) => None, // AWS gives an empty response
        Err(value) => Some(json!(value.to_string())),
    }
}

pub async fn generate_data_key_and_parse(
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

    let result = get_client().generate_data_key(request).await;

    match result {
        Ok(response) => parse::data_key_response(response),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn generate_data_key_without_plaintext_and_parse(
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

    let result = get_client()
        .generate_data_key_without_plaintext(request)
        .await;

    match result {
        Ok(response) => parse::data_key_without_plaintext_response(response),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn generate_data_key_pair_and_parse(
    key_id: &str,
    key_pair_spec: String,
    encryption_context: Option<HashMap<String, String>>,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    let request = GenerateDataKeyPairRequest {
        encryption_context,
        grant_tokens,
        key_id: key_id.to_string(),
        key_pair_spec,
    };

    let result = get_client().generate_data_key_pair(request).await;

    match result {
        Ok(response) => parse::data_key_pair_response(response),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn generate_data_key_pair_without_plaintext_and_parse(
    key_id: &str,
    key_pair_spec: String,
    encryption_context: Option<HashMap<String, String>>,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    let request = GenerateDataKeyPairWithoutPlaintextRequest {
        encryption_context,
        grant_tokens,
        key_id: key_id.to_string(),
        key_pair_spec,
    };

    let result = get_client()
        .generate_data_key_pair_without_plaintext(request)
        .await;

    match result {
        Ok(response) => parse::data_key_pair_without_plaintext_response(response),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn encrypt(
    key_id: String,
    plaintext: Bytes,
    encryption_context: Option<HashMap<String, String>>,
    encryption_algorithm: Option<String>,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    let request = EncryptRequest {
        key_id,
        plaintext,
        encryption_context,
        encryption_algorithm,
        grant_tokens,
    };

    let result = get_client().encrypt(request).await;

    match result {
        Ok(response) => parse::encrypt_response(response),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn decrypt(
    key_id: Option<String>,
    ciphertext_blob: Bytes,
    encryption_context: Option<HashMap<String, String>>,
    encryption_algorithm: Option<String>,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    let request = DecryptRequest {
        key_id,
        ciphertext_blob,
        encryption_context,
        encryption_algorithm,
        grant_tokens,
    };

    let result = get_client().decrypt(request).await;

    match result {
        Ok(response) => parse::decrypt_response(response),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn sign(
    key_id: String,
    message: Bytes,
    message_type: Option<String>,
    signing_algorithm: String,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    let request = SignRequest {
        key_id,
        message,
        message_type,
        signing_algorithm,
        grant_tokens,
    };

    let result = get_client().sign(request).await;

    match result {
        Ok(response) => parse::sign_response(response),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn verify(
    key_id: String,
    message: Bytes,
    message_type: Option<String>,
    signature: Bytes,
    signing_algorithm: String,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    let request = VerifyRequest {
        key_id,
        message,
        message_type,
        signature,
        signing_algorithm,
        grant_tokens,
    };

    let result = get_client().verify(request).await;

    match result {
        Ok(response) => parse::verify_response(response),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn get_public_key(key_id: String, grant_tokens: Option<Vec<String>>) -> Value {
    let request = GetPublicKeyRequest {
        key_id,
        grant_tokens,
    };

    let result = get_client().get_public_key(request).await;

    match result {
        Ok(response) => parse::get_public_key_response(response),
        Err(value) => json!(value.to_string()),
    }
}

pub async fn generate_random(number_of_bytes: i64, custom_key_store_id: Option<String>) -> Value {
    let request = GenerateRandomRequest {
        number_of_bytes: Some(number_of_bytes),
        custom_key_store_id,
    };

    match get_client().generate_random(request).await {
        Ok(response) => parse::generate_random_response(response),
        Err(err) => json!(err.to_string()),
    }
}
