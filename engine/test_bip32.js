// test_bip32.js

const bip32 = require('./bip32');
const bip39 = require('./bip39');

// Use your provided mnemonic
const mnemonic = "whisper price example win core side scale lock script air exclude wealth";

console.log("🔑 Testing with provided Mnemonic Phrase:");
console.log(mnemonic);

// Derive master keys from your mnemonic
const master = bip32.generateMasterKeys(mnemonic);
console.log("\n🌱 Derived Master Private Key:");
console.log(master.privateKey.toString('hex'));
console.log("\n🌱 Derived Master Chain Code:");
console.log(master.chainCode.toString('hex'));

// Derive first address using BIP44 standard path
const bitcoinPath = "m/44'/0'/0'/0/0";
const firstAddress = bip32.derivePath(master.privateKey, master.chainCode, bitcoinPath);

console.log(`\n🎯 Final result for path ${bitcoinPath}:`);
console.log("Private Key:", firstAddress.privateKey.toString('hex'));
console.log("Chain Code:", firstAddress.chainCode.toString('hex'));

// Generate public key for this address
const key = bip32.ec.keyFromPrivate(firstAddress.privateKey);
const compressedPubKey = key.getPublic().encodeCompressed('hex');
console.log("\n🔑 First address public key (compressed):");
console.log(compressedPubKey);

// Generate a few more addresses
console.log("\n🏠 Generating first 5 addresses:");
for (let i = 0; i < 5; i++) {
    const path = `m/44'/0'/0'/0/${i}`;
    const address = bip32.derivePath(master.privateKey, master.chainCode, path);
    const key = bip32.ec.keyFromPrivate(address.privateKey);
    const pubKey = key.getPublic().encodeCompressed('hex');

    console.log(`\nAddress ${i}:`);
    console.log(`  Path: ${path}`);
    console.log(`  Private Key: ${address.privateKey.toString('hex')}`);
    console.log(`  Public Key (compressed): ${pubKey}`);
}
