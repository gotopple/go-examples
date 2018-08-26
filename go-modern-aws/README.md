# go-modern-aws

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

SSM parameters should be orgnized into heirarchies to reflect your organization, deployment stage, project component architecture, and to model multi-parameter versioning. That organization is provided by file system tree-like paths. Consider the following example:

Suppose your team (my-team) uses three deployment stages named: `development`, `stging`, and `production`. Further your team is working on a service named, `example-service` and that service requires two string configuration values, `favoriteColor` and `locale` as well as a secret key called `secretKey` that should always be stored encrypted.  Then you might store configuration for that service in a hierarchy like the following:

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

### Configuration Access Control

If a user (IAM actor like a user or another identity associated with some policy) has access to a path, then the user can access all levels of that path. For example, if a user has permission to access path /a, then the user can also access /a/b. Even if a user has explicitly been denied access in IAM for parameter /a, they can still call the GetParametersByPath API action recursively and view /a/b.

## The Example Service

This example is a simple AES256 encryption service that exposes two endpoints, `/seal` and `/unseal`. The `/seal` endpoint will encrypt the HTTP request body using an internal key and return the encrypted value in an envelope with the following shape: `<base64 ciphertext>:<base64 nonce>`. The `/unseal` endpoint will use an internal key to unseal the contents of an envelope provided in the HTTP request body. If the internal key is rotated (by changing the SSM SecureString parameter value and restarting the service) then the service will not be able to unseal envelopes created with the old configuration.

## Running the Example

#### Initialize the configuration in SSM

```sh
# Generate and write a secure AES256 key into a SecureString SSM parameter
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

```sh
go build
./go-modern-aws -config-path /topple-example/component/2018-08-25.1/
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


