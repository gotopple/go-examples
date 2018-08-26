# go-modern-aws

This example program demonstrates loading configuration and secret material from AWS Simple Service Manager.

## The Example Service

## Running the Example

#### Initialize the configuration in SSM

```sh
# Generate and write a secure AES256 key into a SecureString SSM parameter
aws ssm put-parameter \
  --name /topple-example/component/v1/secretKey \
  --type SecureString \
  --overwrite \
  --value "$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64)" 

# Populate the remaining required parameters
aws ssm put-parameter \
  --name /topple-example/component/v1/favoriteColor \
  --type String \
  --overwrite \
  --value Blue

aws ssm put-parameter \
  --name /topple-example/component/v1/preferences/locale \
  --type String \
  --overwrite \
  --value EN_us 
```

#### Build and run the service

```sh
go build
./go-modern-aws -config-path /topple-example/component/v1/
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

## Configuration and Secret Management

```
/my-team/mystage/v1
 ├ secretKey
 ├ favoriteColor
 └ preferences
   └ locale
```


