//! A crate (still under construction) for interacting with AWS KMS. Uses [rusoto](https://github.com/rusoto/rusoto) and [tokio](https://github.com/tokio-rs/tokio).

use bytes::Bytes;
use serde_json::value::Value;
use std::collections::HashMap;
use tokio::runtime::Runtime;

mod client;
mod parse;

/// Gets the list of all Customer Master Keys (CMKs) in current AWS account (defaults to us-east-1).
pub fn list_keys() -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::get_keys())
}

/// Provides detailed information about a customer master key (CMK).
pub fn describe_key(key_id: &str) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::get_key(key_id))
}

/// Creates a unique customer managed customer master key (CMK) in your AWS account and Region.
pub fn create_key() -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::create_key_and_parse())
}

/// Schedules the deletion of a customer master key (CMK). You may provide a waiting period, specified in days, before deletion occurs.
pub fn schedule_key_deletion(key_id: String, pending_window_in_days: i64) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::schedule_key_deletion_and_parse(
            key_id,
            pending_window_in_days,
        ))
}

/// Cancels the deletion of a customer master key (CMK). When this operation succeeds, the key state of the CMK is Disabled.
pub fn cancel_key_deletion(key_id: String) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::cancel_key_deletion_and_parse(key_id))
}

/// Sets the key state to disabled of a customer master key (CMK) to enabled.
pub fn disable_key(key_id: &str) -> Option<Value> {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::disable_key_and_respond(key_id))
}

/// Sets the key state to enabled of a customer master key (CMK) to enabled.
pub fn enable_key(key_id: &str) -> Option<Value> {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::enable_key_and_respond(key_id))
}

/// Generates a unique symmetric data key for client-side encryption. This operation returns a plaintext copy of the data key and a copy that is encrypted under a customer master key (CMK) that you specify.
pub fn generate_data_key(key_id: &str, key_spec: Option<String>, bytes: Option<i64>) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::generate_data_key_and_parse(key_id, key_spec, bytes))
}

/// Generates a unique symmetric data key. This operation returns a data key that is encrypted under a customer master key (CMK) that you specify.
pub fn generate_data_key_without_plaintext(
    key_id: &str,
    key_spec: Option<String>,
    bytes: Option<i64>,
) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::generate_data_key_without_plaintext_and_parse(
            key_id, key_spec, bytes,
        ))
}

/// Generates a unique asymmetric data key pair. The GenerateDataKeyPair operation returns a plaintext public key, a plaintext private key, and a copy of the private key that is encrypted under the symmetric CMK you specify.
pub fn generate_data_key_pair(
    key_id: &str,
    key_pair_spec: String,
    encryption_context: Option<HashMap<String, String>>,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::generate_data_key_pair_and_parse(
            key_id,
            key_pair_spec,
            encryption_context,
            grant_tokens,
        ))
}

/// Generates a unique asymmetric data key pair. The GenerateDataKeyPair-WithoutPlaintext operation returns a plaintext public key and a copy of the private key that is encrypted under the symmetric CMK you specify.
pub fn generate_data_key_pair_without_plaintext(
    key_id: &str,
    key_pair_spec: String,
    encryption_context: Option<HashMap<String, String>>,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::generate_data_key_pair_without_plaintext_and_parse(
            key_id,
            key_pair_spec,
            encryption_context,
            grant_tokens,
        ))
}

/// Encrypts  plaintext  into  ciphertext  by  using  a customer master key (CMK).
pub fn encrypt(
    key_id: String,
    plaintext: Bytes,
    encryption_context: Option<HashMap<String, String>>,
    encryption_algorithm: Option<String>,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::encrypt(
            key_id,
            plaintext,
            encryption_context,
            encryption_algorithm,
            grant_tokens,
        ))
}
