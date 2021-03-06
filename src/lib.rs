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

/// Decrypts ciphertext that was encrypted by a AWS KMS customer master key (CMK) using any of the following operations: Encrypt, GenerateDataKey, GenerateDataKeyPair, GenerateDataKeyWithoutPlaintext, GenerateDataKeyPairWithoutPlaintext
pub fn decrypt(
    key_id: Option<String>,
    ciphertext_blob: Bytes,
    encryption_context: Option<HashMap<String, String>>,
    encryption_algorithm: Option<String>,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::decrypt(
            key_id,
            ciphertext_blob,
            encryption_context,
            encryption_algorithm,
            grant_tokens,
        ))
}

/// Creates a digital signature for a message or message digest by using the private key in an asymmetric CMK. To verify the signature, use the Verify operation, or use the public key in the same asymmetric CMK outside of AWS KMS.
pub fn sign(
    key_id: String,
    message: Bytes,
    message_type: Option<String>,
    signing_algorithm: String,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::sign(
            key_id,
            message,
            message_type,
            signing_algorithm,
            grant_tokens,
        ))
}

/// Verifies a digital signature that was generated by the Sign operation.
pub fn verify(
    key_id: String,
    message: Bytes,
    message_type: Option<String>,
    signature: Bytes,
    signing_algorithm: String,
    grant_tokens: Option<Vec<String>>,
) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::verify(
            key_id,
            message,
            message_type,
            signature,
            signing_algorithm,
            grant_tokens,
        ))
}

/// Returns the public key of an asymmetric CMK. To quickly create a key to test with outside of this lib, run: `aws kms create-key --key-usage ENCRYPT_DECRYPT --customer-master-key-spec RSA_2048`
pub fn get_public_key(key_id: String, grant_tokens: Option<Vec<String>>) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::get_public_key(key_id, grant_tokens))
}

/// Returns a random byte string that is cryptographically secure. By default, the random byte string is generated in AWS KMS. To generate the byte string in the AWS CloudHSM cluster that is associated with a custom key store , specify the custom key store ID.
pub fn generate_random(number_of_bytes: i64, custom_key_store_id: Option<String>) -> Value {
    Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(client::generate_random(
            number_of_bytes,
            custom_key_store_id,
        ))
}
