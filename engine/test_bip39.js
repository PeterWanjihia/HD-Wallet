const bip39 = require('./bip39');

// 🔷 Generate mnemonic
const mnemonic = bip39.generateMnemonic(128);
console.log("🔑 Generated Mnemonic Phrase:");
console.log(mnemonic);

// 🔷 Derive seed from mnemonic
const seed = bip39.mnemonicToSeed(mnemonic, '');
console.log("\n🌱 Derived Seed (hex):");
console.log(seed.toString('hex'));
