# kms_rs

### A simple crate for managing keys in AWS Key Management Service (KMS)

_Disclaimer: This project has not been audited and not recommended for production environments._

:warning: This project is under construction! :warning: 

Uses [rusoto](https://github.com/rusoto/rusoto).

See [examples](https://github.com/jeffrade/kms_rs/blob/master/examples/src/main.rs) for usage.

#### As functionality is added, it will be listed below.

 - [Retrieve a list](https://docs.aws.amazon.com/cli/latest/reference/kms/list-keys.html) of all CMK's (Customer Master Keys) in region us-east-1
 - [Describe a single key](https://docs.aws.amazon.com/cli/latest/reference/kms/describe-key.html) given a key-id