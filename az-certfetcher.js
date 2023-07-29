import path from 'path';
import fs from 'fs-extra';
import spawn from 'await-spawn';

import { SecretClient } from "@azure/keyvault-secrets";
import { ManagedIdentityCredential } from '@azure/identity';

const pthExecHome = path.resolve(__dirname);

const cleanPfx = process.env.CLEAN_PFX;
const vaultName = process.env.KEYVAULT_NAME;
const certificateName = process.env.CERTIFICATE_NAME;
const managedIdentityClientId = process.env.AZURE_CLIENT_ID;

const installPath = process.env.INSTALL_PATH.trim();
const sAzurePFX = installPath + path.sep + 'azure.pfx';

async function convertPFXtoPEM() {
    try {
        let sBundlePath = installPath + path.sep + 'bundle.pem';
        let sPrivateKeyPath = installPath + path.sep + 'privkey.pem';
        let sCertificatePath = installPath + path.sep + 'fullchain.pem';
    
        let blPrivKeyRes = await spawn('openssl', ['pkcs12', '-in', sAzurePFX, '-nocerts', '-nodes', '-passin', 'pass:']);
        let blCertificateRes = await spawn('openssl', ['pkcs12', '-in', sAzurePFX, '-nokeys', '-passin', 'pass:']);

        let aPrivKey;
        let aCertificates;
    
        if (!(blPrivKeyRes instanceof Error)) {
            let sPrivKeyOutput = blPrivKeyRes.toString();
            let rePrivateKeyPattern = /-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/gm;
            aPrivKey = sPrivKeyOutput.match(rePrivateKeyPattern);

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
            aCertificates = sCertificateOutput.match(reCertificatePattern);

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
            writeStream.write(aCertificates.join("\n"), 'utf8');
            writeStream.end();
        } else {
            console.log(blCertificateRes.stderr.toString('utf8'));
        }

        if ((aPrivKey.length > 0) && (aCertificates.length > 0)) {
            let writeStream = fs.createWriteStream(sBundlePath);
            writeStream.on('error', err => console.error(err));
            writeStream.on('finish', () => 
            {
                fs.chmod(sBundlePath, 0o0600, (err) => {
                    if (err) {
                        console.error('SECURITY: Failed to change permissions on key/certificate bundle!');
                        return;
                    }
            
                    console.log('SUCCESS: The permissions for file [' + sBundlePath + '] have been changed!');
                });
            });
            writeStream.write([...aCertificates, aPrivKey].join("\n"), 'utf8');
            writeStream.end();
        } else {
            console.error('ERROR: Certificate(s) or private key was not found!');
        }

        if (cleanPfx == 1) {
            fs.removeSync(sAzurePFX);
        } else {
            fs.chmod(sAzurePFX, 0o0640, (err) => {
                if (err) {
                    console.error('SECURITY: Failed to change permissions on PFX file!');
                    return;
                }
        
                console.log('SUCCESS: The permissions for file [' + sAzurePFX + '] have been changed!');
            });
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

    let url = `https://${vaultName}.vault.azure.net`;
    let micCredentialHandler = new ManagedIdentityCredential(managedIdentityClientId);
    let ccCertClientRes = new SecretClient(url, micCredentialHandler);
    let latestCert = (await ccCertClientRes.getSecret(certificateName));

    let writeStream = fs.createWriteStream(sAzurePFX);
    writeStream.on('error', err => console.error(err));
    writeStream.on('finish', convertPFXtoPEM);
    writeStream.write(latestCert.value, 'base64');
    writeStream.end();
}
  
main().catch(e => console.error(e.stack));