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

function privateKeyToPublicKey(privateKey){
    const keyPair = ec.keyFromPrivate(privateKey);
    const compressedPublicKey = Buffer.from(keyPair.getPublic(true,'array'));
    return compressedPublicKey;
}

// ==========================
// 🔧 TEST USAGE SECTION
// ==========================
const mnemonic = "whisper price example win core side scale lock script air exclude wealth"; // Replace with your own test mnemonic
const { privateKey, chainCode } = generateMasterKeys(mnemonic);
const pubKey = privateKeyToPublicKey(privateKey);

console.log("🔑 Master Private Key:", privateKey.toString('hex'));
console.log("🔗 Master Chain Code :", chainCode.toString('hex'));
console.log("🌐 Master Public Key :", pubKey.toString('hex'));

/**
 * Serializes a 32-bit number into a 4-byte big-endian buffer.
 * @param {number} i - 32-bit integer
 * @returns {Buffer}
 */
function ser32(i) {
    const buf = Buffer.allocUnsafe(4);
    buf.writeUInt32BE(i, 0);
    return buf;
}

/**
 * Derives a child private key from parent node.
 * @param {Buffer} parentPrivateKey - 32 bytes
 * @param {Buffer} parentChainCode - 32 bytes
 * @param {number} index - child index
 * @param {boolean} hardened - whether derivation is hardened
 * @returns {Object} - { privateKey: Buffer, chainCode: Buffer }
 */
function isValidPrivateKey(privateKey) {
    const keyInt = BigInt('0x' + privateKey.toString('hex'));
    return keyInt !== 0n && keyInt < n;
}
function isValidPublicKey(publicKey) {
    try {
        const key = ec.keyFromPublic(publicKey);
        const pub = key.getPublic();

        // Optional explicit point validation
        if (!pub.validate()) {
            return false;
        }
        return true;
    } catch (e) {
        return false;
    }
}

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
            index += 1; // Increment index and retry
            continue;
        }

        const k_par = BigInt('0x' + parentPrivateKey.toString('hex'));
        const k_child = (parseIL + k_par) % n;

        if (k_child === 0n) {
            index += 1; // Increment index and retry
            continue;
        }

        const childPrivateKeyHex = k_child.toString(16).padStart(64, '0');
        const childPrivateKey = Buffer.from(childPrivateKeyHex, 'hex');

        // Final validation for sanity
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

const child = deriveChildPrivateKey(privateKey, chainCode, 0, true);
// console.log("🔑 Child Private Key (hardened m/0'):", child.privateKey.toString('hex'));
// console.log("🔗 Child Chain Code:", child.chainCode.toString('hex'));

const child1 = deriveChildPrivateKey(privateKey, chainCode, 0, true);
const child2 = deriveChildPrivateKey(privateKey, chainCode, 1, true);

console.log("🔑 Child 0:", child1.privateKey.toString('hex'));
console.log("🔑 Child 1:", child2.privateKey.toString('hex'));




