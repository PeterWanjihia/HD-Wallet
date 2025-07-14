const bip39 = require('./bip39');

// Generate mnemonic
const mnemonic = bip39.generateMnemonic(128);
const seed = bip39.mnemonicToSeed(mnemonic,'');
console.log("🔑 Generated Mnemonic Phrase:");
console.log(mnemonic);

console.log("\n🌱 Derived Seed (hex):");
console.log(seed.toString('hex'));