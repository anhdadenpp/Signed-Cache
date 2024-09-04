import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import crypto from 'crypto';

// Initialize SecretsManagerClient using the imported module
const secretsManagerClient = new SecretsManagerClient({ region: process.env.awsRegion });

// Replacement characters for URL-safe base64 encoding
const replacementChars = { '+': '-', '=': '_', '/': '~' };

// Function to retrieve the key from AWS Secrets Manager
const getKeyFromSecretsManager = async () => {
  try {
    const data = await secretsManagerClient.send(new GetSecretValueCommand({ SecretId: process.env.awsSecretsManagerSecretName }));
    console.log("Private key retrieved");
    return data.SecretString;
  } catch (err) {
    console.log("Get Secret Error", err);
    throw err;
  }
};

// Function to generate signed cookies
export const handler = async (event, context, callback) => {
  let expiration = new Date(event.expiration) / 1000 | 0;
  let cannedPolicy = {
    "Statement": [
      {
        "Resource": event.baseUrl,
        "Condition": {
          "DateLessThan": {
            "AWS:EpochTime": expiration
          }
        }
      }
    ]
  };
  cannedPolicy = JSON.stringify(cannedPolicy);

  let encodedPolicy = Buffer.from(cannedPolicy).toString("base64");
  encodedPolicy = encodedPolicy.replace(/[+=/]/g, m => replacementChars[m]);

  const signer = crypto.createSign('RSA-SHA1');
  signer.update(cannedPolicy);
  let signedPolicy = signer.sign(await getKeyFromSecretsManager(), 'base64');
  signedPolicy = signedPolicy.replace(/[+=/]/g, m => replacementChars[m]);

  const keyPairId = process.env.amazonCloudFrontKeyPairId;

  // Create the signed cookies
  const cookies = {
    "CloudFront-Policy": encodedPolicy,
    "CloudFront-Signature": signedPolicy,
    "CloudFront-Key-Pair-Id": keyPairId
  };

  // Return the signed cookies
  callback(null, { cookies });
};
