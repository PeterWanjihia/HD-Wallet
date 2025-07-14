const bip39 = require('./bip39');
const crypto = require('crypto');
const { ec: EC } = require('elliptic');
const ec = new EC('secp256k1');


// Generate mnemonic
const mnemonic = bip39.generateMnemonic(128);
console.log("🔑 Generated Mnemonic Phrase:");
console.log(mnemonic);

// Derive seed
const seed = bip39.mnemonicToSeed(mnemonic, '');
console.log("\n🌱 Derived Seed (hex):");
console.log(seed.toString('hex'));

// Generate HMAC-SHA512 from the seed 
const I = crypto.createHmac('sha512','Bitcoin Seed').update(seed).digest();

const IL = I.slice(0,32);
const IR = I.slice(32);

console.log("\n🔑 HMAC-SHA512 Digest (I):");
console.log(I.toString('hex'));

console.log("\n🔑 IL (Master Private Key candidate):");
console.log(IL.toString('hex'));

console.log("\n🔑 IR (Master Chain Code):");
console.log(IR.toString('hex'));

// Convert IL and n to BigInt
const IL_int = BigInt('0x' + IL.toString('hex'));
const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

console.log("\n🔍 Validating IL as master private key...");
console.log("IL as integer:", IL_int.toString());
console.log("n (secp256k1 order):", n.toString());

// Perform checks
if (IL_int === 0n) {
    console.log("❌ IL is zero. Invalid master private key.");
} else if (IL_int >= n) {
    console.log("❌ IL is greater than or equal to n. Invalid master private key.");
} else {
    console.log("✅ IL is valid. Proceeding to derive master public key...");
}

// Create key pair from private key
const key = ec.keyFromPrivate(IL);

// Get public key
const pubKey = key.getPublic();

// Encode compressed
const compressedPubKey = pubKey.encodeCompressed('hex');

// Encode uncompressed
const uncompressedPubKey = pubKey.encode('hex');

console.log("\n🔑 Master Public Key (compressed):");
console.log(compressedPubKey);

console.log("\n🔑 Master Public Key (uncompressed):");
console.log(uncompressedPubKey);
