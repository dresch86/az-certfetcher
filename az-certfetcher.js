import path from 'path';
import fs from 'fs-extra';

import { DefaultAzureCredential } from "@azure/identity";
import { SecretsClient } from "@azure/keyvault-secrets";

const secretName = process.env.SECRET_NAME;
const vaultName = process.env.KEYVAULT_NAME;
const pthExecHome = path.resolve(__dirname);

var installPath = process.env.INSTALL_PATH.trim();
var installName = process.env.INSTALL_NAME.trim();

const openssl = require('openssl-nodejs');

async function main() {
    if (installPath.length > 0) {
        try {
            await fs.ensureDir(installPath, {mode: 0o0755});
            console.log('Directory [' + installPath + '] created!');
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
    const bCertBuff = Buffer.from(latestSecret.value, 'base64');

    let sPrivateKeyPath = installPath + path.sep + installName + '.privkey.pem';
    let sCertificatePath = installPath + path.sep + installName + '.cert.crt';

    openssl(['pkcs12', '-in', {name: 'bundle.pfx', buffer: bCertBuff}, '-nocerts', '-out', sPrivateKeyPath, '-nodes', '-passin', 'pass:']);
    openssl(['pkcs12', '-in', {name: 'bundle.pfx', buffer: bCertBuff}, '-nokeys', '-out', sCertificatePath, '-passin', 'pass:']);

    fs.chmod(sPrivateKeyPath, 0o0600, (err) => {
        if (err) {
            console.error('SECURITY: Failed to change permissions on private key!');
            return;
        }

        console.log('SUCCESS: The permissions for file ' + sPrivateKeyPath + ' have been changed!');
    });

    fs.chmod(sCertificatePath, 0o0644, (err) => {
        if (err) {
            console.error('SECURITY: Failed to change permissions on certificate file!');
            return;
        }

        console.log('SUCCESS: The permissions for file ' + sCertificatePath + ' have been changed!');
    });
}
  
main().catch(e => console.error(e.stack));