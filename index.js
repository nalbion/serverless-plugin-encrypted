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
        const KeyPolicy = {
            Version: '2012-10-17',
            Id: 'key-default-1',
            Statement: [{
                Sid: 'Allow administration of the key',
                Effect: 'Allow',
                Principal: { 'AWS': `arn:aws:iam::${awsAccountId}:root` },
                Action: [ 'kms:*' ],
                Resource: '*'
            }, {
                Sid: 'CI can encrypt at deployment',
                Effect: 'Allow',
                Principal: '*',
                Action: 'kms:Encrypt',
                Resource: '*'
            }]
        };

        this.serverless.cli.log('Creating KMS key:\n' + JSON.stringify(KeyPolicy, null, 2));

        return new Promise((resolve, reject) => {
            this.kms.createKey({
                Policy: JSON.stringify(KeyPolicy),
                Description: 'Used to protect secrets used by Lambda functions',
                Tags: [
                    {TagKey: 'Environment', TagValue: this.serverless.service.provider.stage}
                ]
            }, (err, data) => {
                if (err) {
                    console.error(err);
                    reject(err);
                } else {
                    this.serverless.cli.log('found key: ' + data.KeyMetadata.KeyId);
                    this.kmsKeyArn = data.KeyMetadata.Arn;
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
