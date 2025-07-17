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

