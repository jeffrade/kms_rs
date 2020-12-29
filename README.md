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
 - [Delete a key](https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.html)

#### Excluded in AWS Free Tier:
 - GenerateDataKeyPair
 - GenerateDataKeyPairWithoutPlaintext
 - Sign
 - Verify
 - Encrypt
 - Decrypt
 - GetPublicKey that reference asymmetric CMKs

A full list of commands can be found [here](https://docs.aws.amazon.com/cli/latest/reference/kms/index.html#available-commands). One goal of this crate is to provide you some functionality natively to keep high-volume usage costs down. See the latest costs [here](https://aws.amazon.com/kms/pricing/).

### Future Goals

#### Integration with AWS CloudHSM
 - CloudHSM details [here](https://aws.amazon.com/cloudhsm/)
 - Pricing calculation [here](https://aws.amazon.com/cloudhsm/pricing/)

#### Integration with FIPS-140 hardware and software
 - FIPS-140 details [here](https://en.wikipedia.org/wiki/FIPS_140)