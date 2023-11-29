const forge = require('node-forge');
const fs = require('fs').promises;
const readline = require("readline");

const PASSWORD = "UgbajaGabriel";

const generateSessionKey = () => {
    try {
        return {sessionKey: forge.random.getBytesSync(32), iv: forge.random.getBytesSync(16)};
    } catch (error) {
        throw new Error('Failed to generate session key');
    }
}

const createCertificate = (password) => {
    const keys = forge.pki.rsa.generateKeyPair(1024);
    const cert = forge.pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [
        {
            name: 'commonName',
            value: 'example.org'
        },
        {
            name: 'countryName',
            value: 'US'
        },
        {
            shortName: 'ST',
            value: 'Virginia'
        },
        {
            name: 'localityName',
            value: 'Blacksburg'
        },
        {
            name: 'organizationName',
            value: 'Test'
        },
        {
            shortName: 'OU',
            value: 'Test'
        }];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
        {
            name: 'basicConstraints',
            cA: true
        },
        {
            name: 'keyUsage',
            keyCertSign: true,
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true
        },
        {
            name: 'extKeyUsage',
            serverAuth: true,
            clientAuth: true,
            codeSigning: true,
            emailProtection: true,
            timeStamping: true
        },
        {
            name: 'nsCertType',
            client: true,
            server: true,
            email: true,
            objsign: true,
            sslCA: true,
            emailCA: true,
            objCA: true
        },
        {
            name: 'subjectAltName',
            altNames: [
                {
                    type: 6,
                    value: 'http://example.org/webid#me'
                },
                {
                    type: 7,
                    ip: '127.0.0.1'
                }
            ]
        },
        {
            name: 'subjectKeyIdentifier'
        }]);
    cert.sign(keys.privateKey);

    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], password, {algorithm: "3des"});
    const p12Buffer = forge.asn1.toDer(p12Asn1).getBytes();
    const p12b64 = forge.util.encode64(p12Buffer);
    return p12b64;
};

const getCertificateInBase64 = async () => {
    let cert64
    try {
        cert64 = await fs.readFile('certificates.p12', 'binary')
    } catch (error) {
        cert64 = createCertificate(PASSWORD);
        await fs.writeFile('certificates.p12', cert64);
    }

    return cert64
}

const getKeysFromCert = async () => {
    const cert64 = await getCertificateInBase64()
    const p12Der = forge.util.decode64(cert64);
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, PASSWORD);
    const certBags = p12.getBags({bagType: forge.pki.oids.certBag});
    const cert = certBags[forge.pki.oids.certBag][0];
    const publicKey = cert.cert.publicKey;
    const keyBags = p12.getBags({bagType: forge.pki.oids.pkcs8ShroudedKeyBag});
    const privateKey = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
    return {publicKey, privateKey}
};

const encryptFile = (iv, sessionKey, plainText) => {
    const cipher = forge.cipher.createCipher('AES-CBC', sessionKey);
    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(plainText, 'utf8'));
    cipher.finish();
    return cipher.output;
}

const asymmetricEncrypt = async (data) => {
    const {publicKey} = await getKeysFromCert()
    const encrypted = publicKey.encrypt(data, "RSA-OAEP");
    const encryptedSymmetricKey = forge.util.encode64(encrypted);
    return encryptedSymmetricKey;
};

const decryptData = async ({initVector, key, encryptedMessage}) => {
    try {
        const {privateKey} = await getKeysFromCert()

        const decodedKey = forge.util.decode64(key)
        const decodedIv = forge.util.decode64(initVector)

        const decryptedKey = privateKey.key.decrypt(decodedKey, 'RSA-OAEP');
        const decryptedIv = privateKey.key.decrypt(decodedIv, 'RSA-OAEP');

        const decipher = forge.cipher.createDecipher('AES-CBC', decryptedKey);
        decipher.start({iv: decryptedIv});
        decipher.update(forge.util.createBuffer(encryptedMessage));
        decipher.finish();

        return decipher.output.toString();
    } catch (error) {
        console.error(error)
        throw new Error('Failed to decrypt data');
    }
};

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('Enter the path to the file to encrypt: ', async (filePath) => {
    const fileData = await fs.readFile(filePath);
    const base64FileData = fileData.toString('base64');

    const certificateInBase64 = await getCertificateInBase64();
    console.log("certificate in Base64: ", certificateInBase64);

    const {sessionKey, iv} = generateSessionKey();
    console.log('Session key: ', sessionKey);
    console.log('IV: ', iv);

    const encryptedFileData = encryptFile(iv, sessionKey, base64FileData);
    console.log('Encrypted file data: ', encryptedFileData);

    const encryptedIv = await asymmetricEncrypt(iv);
    console.log("Encrypted IV: ", encryptedIv);

    const encryptedSessionKey = await asymmetricEncrypt(sessionKey);
    console.log("Encrypted Session Key: ", encryptedSessionKey);

    const decryptedFileData = await decryptData({
        initVector: encryptedIv,
        key: encryptedSessionKey,
        encryptedMessage: encryptedFileData,
    });
    console.log("Decrypted file data: ", decryptedFileData);

    // Save the encrypted file
    await fs.writeFile('encryptedFile.txt', encryptedFileData.data, 'utf8');
    // Save the decrypted file
    await fs.writeFile('decryptedFile.txt', Buffer.from(decryptedFileData, 'base64'));

});
