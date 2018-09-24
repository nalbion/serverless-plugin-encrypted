'use strict';

var fs = require('fs'),
    path = require('path'),
    AWS = require('aws-sdk');

class ServerlessPlugin {
    constructor(serverless, options) {
        this.serverless = serverless;
        this.options = options;

        if (process.env.AWS_TIMEOUT) {
            AWS.config.httpOptions = {timeout: parseInt(process.env.AWS_TIMEOUT)};
        }
        this.configureProxy();

        this.hooks = {
            'before:deploy:createDeploymentArtifacts': this.encryptVars.bind(this)
        };
    }

    encryptVars() {
        this.kms = new AWS.KMS({
            region: this.serverless.service.provider.region
        });

        this.serverless.cli.log('Encrypting Lambda environment variables...');
        return this.ensureKmsKeyExists()
            .then(() => this.encryptVarsIn(this.serverless.service.provider, 'all function'))
            .then(() => Promise.all(
                this.serverless.service.getAllFunctions().map((functionName) => {
                    const functionObject = this.serverless.service.getFunction(functionName);
                    functionObject.awsKmsKeyArn = this.kmsKeyArn;
                    return this.encryptVarsIn(functionObject, functionName);
                })
            ));
    }

    encryptVarsIn(root, name) {
        if (root.environment) {
            const tasks = [];

            for (let key in this.serverless.service.custom.encrypted) {
                // this.serverless.cli.log(`encrypting process.env.${key} for ${name}`);
                if (this.serverless.service.custom.encrypted[key] && key in root.environment) {
                    tasks.push(
                        this.encrypt(this.serverless.service.custom.encrypted[key]).then(encrypted => {
                            this.serverless.cli.log(`encrypted ${key} for ${name}: ${encrypted}`);
                            root.environment[key] = encrypted;
                        })
                    )
                }
            }

            return Promise.all(tasks);
        }
    }

    /**
     * @returns {Promise<string>} KMS Key ID
     */
    ensureKmsKeyExists() {
        const alias = 'alias/' + this.serverless.service.custom.kmsKeyId;
        this.serverless.cli.log(`Checking for KMS key ${this.serverless.service.custom.kmsKeyId}`);

        return new Promise((resolve, reject) => {
            this.kms.describeKey({KeyId: alias}, (err, data) => {
                if (err) {
                    if (err.code != 'NotFoundException') {
                        console.error('failed to query key:', err);
                        reject(err);
                    } else {
                        resolve(false);
                    }
                } else {
                    this.kmsKeyArn = data.KeyMetadata.Arn;
                    this.autoAddIAMRoleStatements.call(this);
                    resolve(data.KeyMetadata.KeyId);
                }
            });
        }).then((keyId) => {
            if (keyId) {
                return keyId;
            } else {
                console.info('got a key, now need account ID...');
                return this.serverless.providers.aws.getAccountId()
                    .then(this.createKmsKey.bind(this))
                    .then(this.createKmsAlias.bind(this, alias));
            }
        }).then(kmsKeyId => {
            this.serverless.cli.log('using KMS key "' + alias + '": ' + kmsKeyId);
            this.kmsKeyId = kmsKeyId;
        });
    }

    /**
     * @returns {Promise<string>} KMS Key ID
     */
    createKmsAlias(alias, kmsKeyId) {
        return new Promise((resolve, reject) => {
            this.kms.createAlias({
                AliasName: alias,
                TargetKeyId: kmsKeyId
            }, (err, data) => {
                if (err) {
                    console.error(err);
                    reject(err);
                } else {
                    resolve(kmsKeyId);
                }
            });
        });
    }

    /**
     * @returns {Promise<string>} KMS Key ID
     */
    createKmsKey(awsAccountId) {
        this.serverless.cli.log('Getting custom KMS Key Policy...');
        let KeyPolicy;
        if (this.serverless.service.custom.kmsKeyPolicy) {
            KeyPolicy = this.serverless.service.custom.kmsKeyPolicy;
            this.serverless.cli.log('Creating KMS key with Policy:\n' + JSON.stringify(KeyPolicy, null, 2));
        } else {
            this.serverless.cli.log('KMS Key Policy not found at custom, will be set the AWS Default Policy!')
        }

        let tags = [{ TagKey: 'Environment', TagValue: this.serverless.service.provider.stage }];
        const { kmsKeyTags } = this.serverless.service.custom;
        if (kmsKeyTags) {
            Object.keys(kmsKeyTags).forEach(key => {
                tags.push({
                    TagKey: key,
                    TagValue: kmsKeyTags[key]
                });
            });
        }
        
        return new Promise((resolve, reject) => {
            this.kms.createKey({
                Policy: KeyPolicy ? JSON.stringify(KeyPolicy) : undefined,
                Description: 'Used to protect secrets used by Lambda functions',
                Tags: tags
            }, (err, data) => {
                if (err) {
                    console.error(err);
                    reject(err);
                } else {
                    this.serverless.cli.log('found key: ' + data.KeyMetadata.KeyId);
                    this.kmsKeyArn = data.KeyMetadata.Arn;

                    this.autoAddIAMRoleStatements.call(this);

                    resolve(data.KeyMetadata.KeyId);
                }
            });
        })
    }

    /** @return Promise<String> */
    encrypt(value) {
        return new Promise((resolve, reject) => {
            this.kms.encrypt({
                Plaintext: value,
                KeyId: this.kmsKeyId,
                EncryptionContext: this.encryptionContext,
                GrantTokens: this.grantTokens
            }, (err, data) => {
                if (err) {
                    console.error('Failed to encrypt config item:', err);
                    console.error('  ...key:', this.kmsKeyId, ', encryptionContext:', this.encryptionContext, '. grantTokens:', this.grantTokens);
                    reject(err);
                } else {
                    resolve(data.CiphertextBlob.toString('base64'));
                    // resolve({ 'encrypted': 'true', 'value': data.CiphertextBlob.toString('base64')});
                }
            });
        });
    }

    autoAddIAMRoleStatements() {
        if (this.serverless.service.custom.kmsKeyAddRoleStatement) {
            this.serverless.service.provider.iamRoleStatements.push({
                Effect: 'Allow',
                Action: [ 'kms:Decrypt', 'kms:Encrypt' ],
                Resource: this.kmsKeyArn
            });
        }
    }

    configureProxy() {
        const proxyAddress = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
        let agent;

        if (proxyAddress) {
            console.info('-------------------------------------------------------');
            console.info('    configuring proxy:', proxyAddress);
            let opts = require('url').parse(proxyAddress);
            opts.secureProtocol = 'TLSv1_method';
            opts.ciphers = 'ALL';

            if (process.env.HTTPS_PROXY) {
                const HttpsProxyAgent = require('https-proxy-agent');
                agent = new HttpsProxyAgent(opts);
            } else {
                agent = require('proxy-agent')(opts);
            }
        } else {
            // work-around DynamoDB network issues - https://github.com/aws/aws-sdk-js/issues/862#issuecomment-218223804
            let https = require('https');
            agent = new https.Agent({
                ciphers: 'ALL',
                secureProtocol: 'TLSv1_method'
            });
        }

        AWS.config.update({
            httpOptions: {
                // proxy: proxyAddress,
                agent: agent
            }
        });
    }
}

module.exports = ServerlessPlugin;
