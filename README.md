# serverless-plugin-encrypted

A [Serverless](https://serverless.com/) [plugin](https://serverless.com/framework/docs/providers/aws/guide/plugins/)
 which encrypts Lambda environment variables using an KMS key which is automatically generated for each stage.

## Installation

    yarn add -D getndazn/serverless-plugin-encrypted

or 

    npm install --save-dev getndazn/serverless-plugin-encrypted
    
## Usage
    
```yaml
service: my-service
provider:
  name: aws
  runtime: nodejs8.10
  role: lambda-role
  stage: dev
  region: us-east-1

plugins:
  - serverless-plugin-encrypted
    
custom:
  kmsKeyId: ${self:provider.stage}-my-service

  kmsKeyPolicy: # optional
    Id: ${self:provider.stage}-kms-key-defaut-policy
    Statement:
      - Effect: Allow
        Sid: Allow administration of the key
        Principal:
          AWS: 'arn:aws:iam::<account_id>:root'
        Action:
          - kms:*
        Resource: '*'
      - Effect: 'Allow'
        Sid: 'CI can encrypt at deployment'
        Principal: '*'
        Action:
          - kms:Encrypt
        Resource: '*' 
    Version: '2012-10-17'

  kmsKeyAddRoleStatement: true # optional

  kmsKeyTags: # optional
    myTagKey: myTagValue  

  encrypted:
    SECRET_PASSWORD: ${env:MY_SECRET_PASSWORD}
        
functions:
  my-function:
    handler: index.handler
    environment:
      NOT_SECRET: ${env:NOT_SECRET}
      SECRET_PASSWORD: ${self:custom.encrypted.SECRET_PASSWORD}
```

    $ serverless deploy

The plugin will look for a KMS key with alias `dev-my-service`, and create it if it does not exist.

> NOTE: If `dev-my-service` do not exists, you should set `kmsKeyPolicy`. (See more information bellow)

Then it will go through all `environment` variables within `provider` and each function.  
If it finds an entry in `custom.encrypted` with a matching name it will use the KMS key to encrypt the value 
(eg: `custom.encrypted.SECRET_PASSWORD`) and update the provider and function values.
 
Note: The original values in the provider and functions will be discarded. 
ie `functions.my-function.environment.SECRET_PASSWORD` has been set to `${self:custom.encrypted.SECRET_PASSWORD}` 
in the example above, but it could be anything really, although it is a recommended convention.

## Policy (kmsKeyPolicy)

The key policy to attach to the CMK.

### If you provide a key policy, it must meet the following criteria:

- The key policy must allow the principal that is making the CreateKey request to make a subsequent PutKeyPolicy request on the CMK. This reduces the risk that the CMK becomes unmanageable.

- Each statement in the key policy must contain one or more principals. The principals in the key policy must exist and be visible to AWS KMS. When you create a new AWS principal (for example, an IAM user or role), you might need to enforce a delay before including the new principal in a key policy. The reason for this is that the new principal might not be immediately visible to AWS KMS.

- The key policy size limit is 32 kilobytes (32768 bytes).

> NOTE: If you do not provide a key policy, AWS KMS attaches a default key policy to the CMK. For more information, see [Default Key Policy](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html#key-policy-default) in the ***AWS Key Management Service Developer Guide***.

## Auto Create IAM Role Statement (kmsKeyCreateRoleStatement)

If `kmsKeyAddRoleStatement` is set as `true`, the plugin will auto create and add to the iamRoleStatements the folowing role:

```
  Effect: 'Allow'
  Action: [ 'kms:Decrypt', 'kms:Encrypt' ]
  Resource: kms-key-arn
```