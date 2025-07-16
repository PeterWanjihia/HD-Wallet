// test_bip32.js
const bip32 = require('./bip32');
const bip39 = require('./bip39');

// Use your provided mnemonic
const mnemonic = "whisper price example win core side scale lock script air exclude wealth";

console.log("🔑 Testing with provided Mnemonic Phrase:");
console.log(mnemonic);

// Verify mnemonic is valid
console.log("\n✅ Mnemonic validation:", bip39.validateMnemonic(mnemonic));

// Derive master keys from your mnemonic
const master = bip32.generateMasterKeys(mnemonic);
console.log("\n🌱 Derived Master Private Key:");
console.log(master.privateKey.toString('hex'));
console.log("\n🌱 Derived Master Chain Code:");
console.log(master.chainCode.toString('hex'));

// Test Bitcoin path (for comparison)
console.log("\n" + "=".repeat(60));
console.log("🪙 BITCOIN DERIVATION (BIP44 - Coin Type 0)");
console.log("=".repeat(60));

const bitcoinPath = "m/44'/0'/0'/0/0";
const bitcoinAddress = bip32.derivePath(master.privateKey, master.chainCode, bitcoinPath);

console.log(`\n🎯 Bitcoin result for path ${bitcoinPath}:`);
console.log("Private Key:", bitcoinAddress.privateKey.toString('hex'));
console.log("Chain Code:", bitcoinAddress.chainCode.toString('hex'));

const bitcoinKey = bip32.ec.keyFromPrivate(bitcoinAddress.privateKey);
const bitcoinCompressedPubKey = bitcoinKey.getPublic().encodeCompressed('hex');
console.log("Public Key (compressed):", bitcoinCompressedPubKey);

// Test Ethereum path (MetaMask compatible)
console.log("\n" + "=".repeat(60));
console.log("🔷 ETHEREUM DERIVATION (BIP44 - Coin Type 60)");
console.log("=".repeat(60));

const ethereumPath = "m/44'/60'/0'/0/0";
const ethereumAddress = bip32.derivePath(master.privateKey, master.chainCode, ethereumPath);

console.log(`\n🎯 Ethereum result for path ${ethereumPath}:`);
console.log("Private Key:", ethereumAddress.privateKey.toString('hex'));
console.log("Chain Code:", ethereumAddress.chainCode.toString('hex'));

const ethereumKey = bip32.ec.keyFromPrivate(ethereumAddress.privateKey);
const ethereumCompressedPubKey = ethereumKey.getPublic().encodeCompressed('hex');
const ethereumUncompressedPubKey = ethereumKey.getPublic().encode('hex', false);
console.log("Public Key (compressed):", ethereumCompressedPubKey);
console.log("Public Key (uncompressed):", ethereumUncompressedPubKey);

// Generate Ethereum address
const ethAddress = bip32.privateKeyToAddress(ethereumAddress.privateKey);
const ethChecksumAddress = bip32.toChecksumAddress(ethAddress);
console.log("Ethereum Address:", ethAddress);
console.log("Ethereum Address (checksum):", ethChecksumAddress);

// Generate first 5 Ethereum addresses (MetaMask style)
console.log("\n" + "=".repeat(60));
console.log("🏠 GENERATING FIRST 5 ETHEREUM ADDRESSES");
console.log("=".repeat(60));

for (let i = 0; i < 5; i++) {
    const path = `m/44'/60'/0'/0/${i}`;
    const derived = bip32.derivePath(master.privateKey, master.chainCode, path);
    const key = bip32.ec.keyFromPrivate(derived.privateKey);
    const pubKey = key.getPublic().encodeCompressed('hex');
    const address = bip32.privateKeyToAddress(derived.privateKey);
    const checksumAddress = bip32.toChecksumAddress(address);

    console.log(`\n📍 Address ${i}:`);
    console.log(`  Path: ${path}`);
    console.log(`  Private Key: 0x${derived.privateKey.toString('hex')}`);
    console.log(`  Public Key: ${pubKey}`);
    console.log(`  Address: ${checksumAddress}`);
}

// Test the complete wallet generation function
console.log("\n" + "=".repeat(60));
console.log("🎒 COMPLETE WALLET GENERATION TEST");
console.log("=".repeat(60));

const completeWallet = bip32.generateWallet(mnemonic, '', 60, 0, 3);
console.log("\n🔑 Master Keys:");
console.log("Private Key:", completeWallet.master.privateKey);
console.log("Chain Code:", completeWallet.master.chainCode);

console.log("\n🏠 Generated Addresses:");
completeWallet.addresses.forEach((addr, index) => {
    console.log(`\n${index + 1}. ${addr.type.toUpperCase()}`);
    console.log(`   Path: ${addr.path}`);
    console.log(`   Address: ${addr.address}`);
    console.log(`   Private Key: ${addr.privateKey}`);
});

// Test different coin types
console.log("\n" + "=".repeat(60));
console.log("🌍 TESTING DIFFERENT COIN TYPES");
console.log("=".repeat(60));

const coinTypes = [
    { name: 'Bitcoin', type: 0 },
    { name: 'Ethereum', type: 60 },
    { name: 'Litecoin', type: 2 },
    { name: 'Dogecoin', type: 3 }
];

coinTypes.forEach(coin => {
    const path = `m/44'/${coin.type}'/0'/0/0`;
    const derived = bip32.derivePath(master.privateKey, master.chainCode, path);
    
    console.log(`\n${coin.name} (${coin.type}):`);
    console.log(`  Path: ${path}`);
    console.log(`  Private Key: ${derived.privateKey.toString('hex')}`);
    
    if (coin.type === 60) { // Ethereum
        const address = bip32.privateKeyToAddress(derived.privateKey);
        console.log(`  Address: ${bip32.toChecksumAddress(address)}`);
    }
});

// Test hardened vs non-hardened derivation
console.log("\n" + "=".repeat(60));
console.log("🔒 HARDENED VS NON-HARDENED DERIVATION");
console.log("=".repeat(60));

const hardenedPath = "m/44'/60'/0'/0/0";
const nonHardenedPath = "m/44/60/0/0/0";

try {
    const hardened = bip32.derivePath(master.privateKey, master.chainCode, hardenedPath);
    console.log(`\n✅ Hardened path (${hardenedPath}):`);
    console.log(`   Private Key: ${hardened.privateKey.toString('hex')}`);
    
    const nonHardened = bip32.derivePath(master.privateKey, master.chainCode, nonHardenedPath);
    console.log(`\n✅ Non-hardened path (${nonHardenedPath}):`);
    console.log(`   Private Key: ${nonHardened.privateKey.toString('hex')}`);
    
    console.log(`\n🔍 Keys are different: ${hardened.privateKey.toString('hex') !== nonHardened.privateKey.toString('hex')}`);
} catch (error) {
    console.error("Error testing derivation:", error.message);
}

console.log("\n" + "=".repeat(60));
console.log("✨ TESTING COMPLETE!");
console.log("=".repeat(60));