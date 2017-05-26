# serverless-plugin-encrypted

A Serverless plugin which encrypts Lambda environment variables using an KMS key which is automatically generated for each stage

## Installation

    yarn add -D serverless-plugin-encrypted

or 

    npm install --save-dev serverless-plugin-encrypted
    
## Usage
    
```yaml
service: my-service
provider:
  name: aws
  runtime: nodejs6.10
  stage: DEV
  region: ap-southeast-2
  
plugins:
  - serverless-plugin-encrypted
    
custom:
  kmsKeyId: ${self:provider.stage}-my-service
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

The plugin will look for a KMS key with alias `DEV-my-service`, and create it if it does not exist.
Then it will go through all `environment` variables within `provider` and each function.  
If it finds an entry in `custom.encrypted` with a matching name it will use the KMS key to encrypt the value 
(eg: `custom.encrypted.SECRET_PASSWORD`) and update the provider and function values.
 
Note: The original values in the provider and functions will be discarded. 
ie `functions.my-function.environment.SECRET_PASSWORD` has been set to `${self:custom.encrypted.SECRET_PASSWORD}` 
in the example above, but it could be anything really, although it is a recommended convention.
