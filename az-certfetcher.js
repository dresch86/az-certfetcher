import path from 'path';
import fs from 'fs-extra';
import spawn from 'await-spawn';

import { DefaultAzureCredential } from "@azure/identity";
import { SecretsClient } from "@azure/keyvault-secrets";

const secretName = process.env.SECRET_NAME;
const vaultName = process.env.KEYVAULT_NAME;
const pthExecHome = path.resolve(__dirname);

var installPath = process.env.INSTALL_PATH.trim();
var installName = process.env.INSTALL_NAME.trim();
var sAzurePFX = installPath + path.sep + installName + '.azure.pfx';

async function convertPFXtoPEM() {
    try {
        fs.chmod(sAzurePFX, 0o0640, (err) => {
            if (err) {
                console.error('SECURITY: Failed to change permissions on PFX file!');
                return;
            }
    
            console.log('SUCCESS: The permissions for file [' + sAzurePFX + '] have been changed!');
        });

        let sPrivateKeyPath = installPath + path.sep + installName + '.privkey.pem';
        let sCertificatePath = installPath + path.sep + installName + '.fullchain.pem';
    
        let blPrivKeyRes = await spawn('openssl', ['pkcs12', '-in', sAzurePFX, '-nocerts', '-nodes', '-passin', 'pass:']);
        let blCertificateRes = await spawn('openssl', ['pkcs12', '-in', sAzurePFX, '-nokeys', '-passin', 'pass:']);
    
        if (!(blPrivKeyRes instanceof Error)) {
            let sPrivKeyOutput = blPrivKeyRes.toString();
            let rePrivateKeyPattern = /-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/gm;
            let aPrivKey = sPrivKeyOutput.match(rePrivateKeyPattern);

            let writeStream = fs.createWriteStream(sPrivateKeyPath);
            writeStream.on('error', err => console.error(err));
            writeStream.on('finish', () => 
            {
                fs.chmod(sPrivateKeyPath, 0o0600, (err) => {
                    if (err) {
                        console.error('SECURITY: Failed to change permissions on private key!');
                        return;
                    }
            
                    console.log('SUCCESS: The permissions for file [' + sPrivateKeyPath + '] have been changed!');
                });
            });
            writeStream.write(aPrivKey.join("\n"), 'utf8');
            writeStream.end();
        } else {
            console.log(blPrivKeyRes.stderr.toString('utf8'));
        }
    
        if (!(blCertificateRes instanceof Error)) {
            let sCertificateOutput = blCertificateRes.toString();
            let reCertificatePattern = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/gm;
            let aCertificate = sCertificateOutput.match(reCertificatePattern);

            let writeStream = fs.createWriteStream(sCertificatePath);
            writeStream.on('error', err => console.error(err));
            writeStream.on('finish', () => 
            {
                fs.chmod(sCertificatePath, 0o0644, (err) => {
                    if (err) {
                        console.error('SECURITY: Failed to change permissions on certificate file!');
                        return;
                    }
            
                    console.log('SUCCESS: The permissions for file [' + sCertificatePath + '] have been changed!');
                });
            });
            writeStream.write(aCertificate.reverse().join("\n"), 'utf8');
            writeStream.end();
        } else {
            console.log(blCertificateRes.stderr.toString('utf8'));
        }
    } catch (err) {
        console.error(err);
    }
}

async function main() {
    if (installPath.length > 0) {
        try {
            await fs.ensureDir(installPath, {mode: 0o0755});
            console.log('Directory [' + installPath + '] present!');
        } catch (err) {
            console.error(err);
            return;
        }
    } else {
        installPath = pthExecHome + path.sep + 'ssl';
    }

    if (installName.length < 1) {
        installName = 'az-secret';
    }

    const credential = new DefaultAzureCredential();
    const url = `https://${vaultName}.vault.azure.net`;
    const client = new SecretsClient(url, credential);
    const latestSecret = await client.getSecret(secretName);

    let writeStream = fs.createWriteStream(sAzurePFX);
    writeStream.on('error', err => console.error(err));
    writeStream.on('finish', convertPFXtoPEM);
    writeStream.write(latestSecret.value, 'base64');
    writeStream.end();
}
  
main().catch(e => console.error(e.stack));