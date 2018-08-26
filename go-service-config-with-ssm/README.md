# go-service-config-with-ssm

This example program demonstrates loading configuration and secret material from AWS Simple Service Manager (SSM).

## On Modern Configuration and Secret Management in AWS

The enclosed application demonstrates the use of SSM parameters for retrieving secret and other sensitive application cofiguration.  SSM is an ideal application configuration storage and last mile delivery solution. It provides:

* First-class API management of key-value data
* Support for both clear String and SecureString types where data is protected transparently by AWS Key Management Service
* Tree-like namespace (path) support
* Parameter versioning
* Auditable history
* Integration with standard actor authentication and access control tooling (IAM)
* Regionalized isolation

SSM parameters provide a simple key-value store that is built directly into the AWS API layer. This makes SSM parameters first-class resources in AWS. There is no need to create a separate DynamoDB table or other data management resource. There is no need to write custom code to work with some custom storage solution. Because they are first-class resources, SSM parameters can be referenced directly from many other AWS services and resources like CloudFormation.

### SSM Parameter Hierarchies for Configuration Collections

SSM parameters should be organized into hierarchies that reflect the organization, deployment stage, project component architecture, and collections of parameters that should be versioned together. That organization is provided by file system tree-like paths. Consider the following example:

Suppose your team (my-team) uses three deployment stages named: `development`, `staging`, and `production`. Further your team is working on a service named, `example-service` and that service requires two string configuration values, `favoriteColor` and `locale` as well as a secret key called `secretKey` that should always be stored encrypted.  Then you might store configuration for that service in a hierarchy like the following:

```
/my-team
 ├ development
 │ └ example-service
 │   └ 2018-08-29.1
 │     ├ secretKey
 │     ├ favoriteColor
 │     └ preferences
 │       └ locale
 ├ staging
 │ └ example-service
 │   ├ 2018-08-25.2
 │   │ ├ secretKey
 │   │ ├ favoriteColor
 │   │ └ preferences
 │   │   └ locale
 │   └ 2018-08-29.1
 │     ├ secretKey
 │     ├ favoriteColor
 │     └ preferences
 │       └ locale
 └ production
   └ example-service
     ├ 2018-08-25.1
     │ ├ secretKey
     │ ├ favoriteColor
     │ └ preferences
     │   └ locale
     ├ 2018-08-25.2
     │ ├ secretKey
     │ ├ favoriteColor
     │ └ preferences
     │   └ locale
     └ 2018-08-29.1
       ├ secretKey
       ├ favoriteColor
       └ preferences
         └ locale
```

In this example multiple versions of the configuration are modeled in the path of individual keys. It uses a path pattern: `/<team>/<stage>/<service>/<version>/` to isolate whole collections of related parameters. The tree is realized in the name of individual parameters so the above tree is a flat set of parameters with the following key names:

```
/my-team/development/example-service/2018-08-29.1/secretKey
/my-team/development/example-service/2018-08-29.1/favoriteColor
/my-team/development/example-service/2018-08-29.1/preferences/locale
/my-team/staging/example-service/2018-08-25.2/secretKey
/my-team/staging/example-service/2018-08-25.2/favoriteColor
/my-team/staging/example-service/2018-08-25.2/preferences/locale
/my-team/staging/example-service/2018-08-29.1/secretKey
/my-team/staging/example-service/2018-08-29.1/favoriteColor
/my-team/staging/example-service/2018-08-29.1/preferences/locale
/my-team/production/example-service/2018-08-25.1/secretKey
/my-team/production/example-service/2018-08-25.1/favoriteColor
/my-team/production/example-service/2018-08-25.1/preferences/locale
/my-team/production/example-service/2018-08-25.2/secretKey
/my-team/production/example-service/2018-08-25.2/favoriteColor
/my-team/production/example-service/2018-08-25.2/preferences/locale
/my-team/production/example-service/2018-08-29.1/secretKey
/my-team/production/example-service/2018-08-29.1/favoriteColor
/my-team/production/example-service/2018-08-29.1/preferences/locale
```

Parameter names do have some constraints documented [here](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-parameter-name-constraints.html) and summarized as follows:

* Parameter names are case sensitive.
* A parameter name must be unique within an AWS Region
* A parameter name can't be prefixed with "aws" or "ssm" (case-insensitive).
* Parameter names can include only the following symbols and letters: a-zA-Z0-9\_.-/
* A parameter name can't include spaces.
* Parameter hierarchies are limited to a maximum depth of fifteen levels.

### Secrets in Configuration

Each SSM parameter has an associated data type. The type can be `String`, `StringList`, or `SecureString`. SSM will use KMS to encrypt and decrypt any parameters with the `SecureString` type. SSM will attempt to use the default KMS key for the account the calling IAM actor is associated with. The example in this project will always use the default key. However, your implementation can use other KMS keys by referencing the key ID when creating and retrieving the parameter data from SSM.

### Secret Handling Best Practices

Secrets should never be written to disk in plaintext. The example included in this repo loads configuration directly from SSM when it starts and never writes that configuration to disk. Other configuration management systems or tooling might use a database to store configuration working sets. Then later realize that configuration before runtime by writing files into a file in an EC2 instance, or into EC2 instance metadata (user data), or by baking it into an AMI or Docker image so that it is available to the software at launch. Those are all bad patterns for any system that handles sensitive and secret data. Strategies that ship configuration data with software deployment artifacts leak that data as those distribution channels often apply very coarse access control mechanisms. Strategies that stage files on an instance or make the data available via EC2 metadata risk leaking secrets to unauthorized processes on the same machine or to other non-root users. 

By keeping secret material plaintext limited to the process memory you can be certain that the only way to expose the secret is by an attacker breaching the memory access boundaries provided by the operating system on the machine. Those attacks are possible in some cases, however they do require a more sophisticated attacker.

### Configuration Access Control

If a user (IAM actor like a user or another identity associated with some policy) has access to a path, then the user can access all levels at or below that path. For example, if a user has permission to access path /a, then the user can also access /a/b. Even if a user has explicitly been denied access in IAM for parameter /a, they can still call the GetParametersByPath API action recursively and view /a/b.

## The Example Service

This example is a simple AES256 encryption service that exposes two endpoints, `/seal` and `/unseal`. The `/seal` endpoint will encrypt the HTTP request body using an internal key and return the encrypted value in an envelope with the following shape: `<base64 ciphertext>:<base64 nonce>`. The `/unseal` endpoint will use an internal key to unseal the contents of an envelope provided in the HTTP request body. If the internal key is rotated (by changing the SSM SecureString parameter value and restarting the service) then the service will not be able to unseal envelopes created with the old configuration.

## Running the Example

#### Initialize the configuration in SSM

```sh
# Generate and write a secure AES256 key into a SecureString SSM parameter.
# Note that the secret value is generated by reading from a secure random
# source and never written to a file in plaintext on this machine.
# Marking it as a SecureString will cause SSM to use the default KMS key
# on this account to encrypt the value at rest.
# Retrieval requires the caller to have read access on both the parameter
# and the KMS key.
aws ssm put-parameter \
  --name /topple-example/component/2018-08-25.1/secretKey \
  --type SecureString \
  --overwrite \
  --value "$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64)" 

# Populate the remaining required parameters
aws ssm put-parameter \
  --name /topple-example/component/2018-08-25.1/favoriteColor \
  --type String \
  --overwrite \
  --value Blue

aws ssm put-parameter \
  --name /topple-example/component/2018-08-25.1/preferences/locale \
  --type String \
  --overwrite \
  --value EN_us 
```

#### Build and run the service

This application uses the default credential and configuration resolution rules for any AWS SDK application. 

```sh
go get github.com/gotopple/go-examples/go-service-config-with-ssm
$GOPATH/bin/go-service-config-with-ssm -config-path /topple-example/component/2018-08-25.1/
```

#### Exercise the service

```sh
# One-liner call the service twice to seal the data, 
# then unseal the envelope and return the original message.
curl -s --data "Hello SSM" http://localhost:8080/seal | \
  curl -s -d @- http://localhost:8080/unseal

# Or DIY seal
curl -s --data "Hello SSM" http://localhost:8080/seal

# and DIY unseal
curl -s --data "<PASTE THE OUTPUT FROM THE SEAL COMMAND>" http://localhost:8080/unseal
```


