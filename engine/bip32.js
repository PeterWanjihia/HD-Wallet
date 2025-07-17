// bip32.js

const bip39 = require('./bip39');
const crypto = require('crypto');
const { ec: EC } = require('elliptic');
const ec = new EC('secp256k1');
const bs58 = require('bs58');

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
 * Converts a private key to its compressed public key.
 */
function privateKeyToPublicKey(privateKey) {
    const keyPair = ec.keyFromPrivate(privateKey);
    return Buffer.from(keyPair.getPublic(true, 'array'));
}

/**
 * Serializes a 32-bit number into a 4-byte big-endian buffer.
 */
function ser32(i) {
    const buf = Buffer.allocUnsafe(4);
    buf.writeUInt32BE(i, 0);
    return buf;
}

/**
 * Validates that a private key is within curve order.
 */
function isValidPrivateKey(privateKey) {
    const keyInt = BigInt('0x' + privateKey.toString('hex'));
    return keyInt !== 0n && keyInt < n;
}

/**
 * Validates that a public key is on curve.
 */
function isValidPublicKey(publicKey) {
    try {
        const key = ec.keyFromPublic(publicKey);
        return key.getPublic().validate();
    } catch (e) {
        return false;
    }
}

/**
 * Derives a child private key from a parent private key.
 */
function deriveChildPrivateKey(parentPrivateKey, parentChainCode, index, hardened) {
    while (true) {
        let data;

        if (hardened) {
            data = Buffer.concat([
                Buffer.from([0x00]),
                parentPrivateKey,
                ser32(index)
            ]);
        } else {
            const parentPublicKey = privateKeyToPublicKey(parentPrivateKey);
            data = Buffer.concat([
                parentPublicKey,
                ser32(index)
            ]);
        }

        const I = crypto.createHmac('sha512', parentChainCode).update(data).digest();
        const IL = I.slice(0, 32);
        const IR = I.slice(32);

        const parseIL = BigInt('0x' + IL.toString('hex'));

        if (parseIL >= n) {
            index += 1;
            continue;
        }

        const k_par = BigInt('0x' + parentPrivateKey.toString('hex'));
        const k_child = (parseIL + k_par) % n;

        if (k_child === 0n) {
            index += 1;
            continue;
        }

        const childPrivateKeyHex = k_child.toString(16).padStart(64, '0');
        const childPrivateKey = Buffer.from(childPrivateKeyHex, 'hex');

        if (!isValidPrivateKey(childPrivateKey)) {
            index += 1;
            continue;
        }

        return {
            privateKey: childPrivateKey,
            chainCode: IR
        };
    }
}

/**
 * Calculates the fingerprint from a private key.
 */
function calculateFingerprint(privateKey) {
    const publicKey = privateKeyToPublicKey(privateKey);
    const sha256 = crypto.createHash('sha256').update(publicKey).digest();
    const ripemd160 = crypto.createHash('ripemd160').update(sha256).digest();
    return ripemd160.slice(0, 4);
}

/**
 * Serializes an extended key (xprv or xpub) into Base58Check format.
 * 
 * @param {Object} params
 * @param {string} params.versionHex - version hex string (xprv: '0488ade4', xpub: '0488b21e')
 * @param {number} params.depth - depth level (0 for master)
 * @param {Buffer} params.parentFingerprint - 4 bytes
 * @param {number} params.childIndex - child index
 * @param {Buffer} params.chainCode - 32 bytes chain code
 * @param {Buffer} params.keyData - 33 bytes key data
 * @returns {string} Base58Check encoded extended key
 */
function serializeExtendedKey({ versionHex, depth, parentFingerprint, childIndex, chainCode, keyData }) {
    // Assemble components
    const version = Buffer.from(versionHex, 'hex');
    const depthBuf = Buffer.from([depth]);
    const indexBuf = Buffer.allocUnsafe(4);
    indexBuf.writeUInt32BE(childIndex, 0);

    const data = Buffer.concat([
        version,
        depthBuf,
        parentFingerprint,
        indexBuf,
        chainCode,
        keyData
    ]);

    // Compute checksum: SHA256(SHA256(data)).slice(0,4)
    const hash1 = crypto.createHash('sha256').update(data).digest();
    const hash2 = crypto.createHash('sha256').update(hash1).digest();
    const checksum = hash2.slice(0, 4);

    // Append checksum
    const extendedKey = Buffer.concat([data, checksum]);

    // Return Base58 encoded extended key
    // return bs58.encode(extendedKey);
    return bs58.default.encode(Buffer.from(extendedKey));

}





// ==========================
// 🔧 TEST USAGE SECTION
// ==========================
const mnemonic = "whisper price example win core side scale lock script air exclude wealth"; // Replace with your test mnemonic
const { privateKey, chainCode } = generateMasterKeys(mnemonic);
const pubKey = privateKeyToPublicKey(privateKey);

console.log("🔑 Master Private Key:", privateKey.toString('hex'));
console.log("🔗 Master Chain Code :", chainCode.toString('hex'));
console.log("🌐 Master Public Key :", pubKey.toString('hex'));

const child0 = deriveChildPrivateKey(privateKey, chainCode, 0, true);
const child1 = deriveChildPrivateKey(privateKey, chainCode, 1, false);

console.log("🔑 Child 0 Private Key (hardened m/0'):", child0.privateKey.toString('hex'));
console.log("🔗 Child 0 Chain Code:", child0.chainCode.toString('hex'));

console.log("🔑 Child 1 Private Key (non-hardened m/1):", child1.privateKey.toString('hex'));
console.log("🔗 Child 1 Chain Code:", child1.chainCode.toString('hex'));

const fingerprint = calculateFingerprint(privateKey);
console.log("🆔 Master Fingerprint:", fingerprint.toString('hex'));

const xprv = serializeExtendedKey({
    versionHex: '0488ade4',
    depth: 0,
    parentFingerprint: Buffer.from([0,0,0,0]),
    childIndex: 0,
    chainCode: chainCode,
    keyData: Buffer.concat([
        Buffer.from([0x00]), // leading 0x00 for private key
        privateKey
    ])
});
console.log("\n\n🔑 Master xprv:", xprv);


// const pubKey = privateKeyToPublicKey(privateKey);

const xpub = serializeExtendedKey({
    versionHex: '0488b21e',
    depth: 0,
    parentFingerprint: Buffer.from([0,0,0,0]),
    childIndex: 0,
    chainCode: chainCode,
    keyData: pubKey // compressed public key
});
console.log("🌐 Master xpub:", xpub);


// ==========================

module.exports = {
    generateMasterKeys,
    privateKeyToPublicKey,
    ser32,
    isValidPrivateKey,
    isValidPublicKey,
    deriveChildPrivateKey,
    calculateFingerprint
};
