// bip32.js

const bip39 = require('./bip39');
const crypto = require('crypto');
const { ec: EC } = require('elliptic');
const ec = new EC('secp256k1');

// Secp256k1 curve order
const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

/**
 * Generates master key pair and chain code from mnemonic.
 */
function generateMasterKeys(mnemonic, passphrase = '') {
    const seed = bip39.mnemonicToSeed(mnemonic, passphrase);
    const I = crypto.createHmac('sha512', 'Bitcoin Seed').update(seed).digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);

    const IL_int = BigInt('0x' + IL.toString('hex'));
    if (IL_int === 0n || IL_int >= n) {
        throw new Error('Invalid master private key derived from seed.');
    }

    return {
        privateKey: IL,
        chainCode: IR
    };
}

/**
 * Derives a child key from a parent key and chain code at a given index.
 */
function deriveChild(parentPrivateKey, parentChainCode, index) {
    const isHardened = index >= 0x80000000;

    let data;
    if (isHardened) {
        data = Buffer.concat([
            Buffer.from('00', 'hex'),
            parentPrivateKey,
            Buffer.from(index.toString(16).padStart(8, '0'), 'hex')
        ]);
    } else {
        const parentKey = ec.keyFromPrivate(parentPrivateKey);
        const parentPublicKey = Buffer.from(parentKey.getPublic().encodeCompressed('hex'), 'hex');
        data = Buffer.concat([
            parentPublicKey,
            Buffer.from(index.toString(16).padStart(8, '0'), 'hex')
        ]);
    }

    const I = crypto.createHmac('sha512', parentChainCode).update(data).digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);

    const IL_int = BigInt('0x' + IL.toString('hex'));
    const parentPrivateKey_int = BigInt('0x' + parentPrivateKey.toString('hex'));
    const childPrivateKey_int = (IL_int + parentPrivateKey_int) % n;

    const childPrivateKey = Buffer.from(childPrivateKey_int.toString(16).padStart(64, '0'), 'hex');
    const childChainCode = IR;

    return {
        privateKey: childPrivateKey,
        chainCode: childChainCode
    };
}

/**
 * Derives a full HD wallet path like "m/44'/0'/0'/0/0".
 */
function derivePath(masterPrivateKey, masterChainCode, path) {
    const segments = path.split('/');
    if (segments[0] !== 'm') {
        throw new Error('Path must start with m');
    }

    let currentPrivateKey = masterPrivateKey;
    let currentChainCode = masterChainCode;

    for (let i = 1; i < segments.length; i++) {
        const segment = segments[i];
        let index;

        if (segment.endsWith("'")) {
            index = parseInt(segment.slice(0, -1)) + 0x80000000;
        } else {
            index = parseInt(segment);
        }

        const child = deriveChild(currentPrivateKey, currentChainCode, index);
        currentPrivateKey = child.privateKey;
        currentChainCode = child.chainCode;
    }

    return {
        privateKey: currentPrivateKey,
        chainCode: currentChainCode
    };
}

module.exports = {
    generateMasterKeys,
    deriveChild,
    derivePath,
    ec,
    n
};
