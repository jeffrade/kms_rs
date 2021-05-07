# kms_rs

### A simple crate for managing keys in AWS Key Management Service (KMS)

_Disclaimer: This project has not been audited and not yet recommended for production environments._

:warning: This project is under construction! :warning: 

Uses [rusoto](https://github.com/rusoto/rusoto).

See [examples](https://github.com/jeffrade/kms_rs/blob/master/examples/src/main.rs) for usage (uses [clap](https://github.com/clap-rs/clap)).

#### Prerequisites
 - An AWS account (sign up [here](https://portal.aws.amazon.com/billing/signup))
 - AWS CLI [installed](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html)

#### As functionality is added, it will be listed below.

 - [Retrieve a list](https://docs.aws.amazon.com/cli/latest/reference/kms/list-keys.html) of all CMK's (Customer Master Keys) in region us-east-1
 - [Describe a single key](https://docs.aws.amazon.com/cli/latest/reference/kms/describe-key.html) given a key-id
 - [Create a key](https://docs.aws.amazon.com/cli/latest/reference/kms/create-key.html) (symmetric only)
 - [Schedule key deletion](https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.html)
 - [Cancel key deletion](https://docs.aws.amazon.com/cli/latest/reference/kms/cancel-key-deletion.html)
 - [Enable a key](https://docs.aws.amazon.com/cli/latest/reference/kms/enable-key.html) given a key-id
 - [Disable a key](https://docs.aws.amazon.com/cli/latest/reference/kms/disable-key.html) given a key-id
 - [Generate a data key](https://docs.aws.amazon.com/cli/latest/reference/kms/generate-data-key.html)
 - [Generate a data key without plaintext](https://docs.aws.amazon.com/cli/latest/reference/kms/generate-data-key-without-plaintext.html)
 - [Generate a data key pair](https://docs.aws.amazon.com/cli/latest/reference/kms/generate-data-key-pair.html)
 - [Generate a data key pair without plaintext](https://docs.aws.amazon.com/cli/latest/reference/kms/generate-data-key-pair-without-plaintext.html)
 - [Encrypt plaintext](https://docs.aws.amazon.com/cli/latest/reference/kms/encrypt.html)
 - [Decrypt ciphertext](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html)
 - [Sign a message](https://docs.aws.amazon.com/cli/latest/reference/kms/sign.html)
 - [Verify a signature](https://docs.aws.amazon.com/cli/latest/reference/kms/verify.html)
 - [Get public key](https://docs.aws.amazon.com/cli/latest/reference/kms/get-public-key.html)
 - [Generate random bytes](https://docs.aws.amazon.com/cli/latest/reference/kms/generate-random.html)

A full list of commands can be found [here](https://docs.aws.amazon.com/cli/latest/reference/kms/index.html#available-commands). Feel free to open an issue to request a command(s) or PR to add them.

#### Note that the following are excludeded from AWS Free Tier:
 - GenerateDataKeyPair
 - GenerateDataKeyPairWithoutPlaintext
 - Sign
 - Verify
 - Encrypt
 - Decrypt
 - GetPublicKey that reference asymmetric CMKs

Because of this, one goal of this crate is to provide you some functionality natively to keep high-volume usage costs down. See the latest costs [here](https://aws.amazon.com/kms/pricing/).

### Future Goals

#### Integration with AWS CloudHSM
 - Add native commands that aren't covered under AWS Free Tier
 - CloudHSM details [here](https://aws.amazon.com/cloudhsm/)
 - Pricing calculation [here](https://aws.amazon.com/cloudhsm/pricing/)

#### Integration with FIPS-140 hardware and software
 - FIPS-140 details [here](https://en.wikipedia.org/wiki/FIPS_140)