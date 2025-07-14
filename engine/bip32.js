const bip39 = require('./bip39');
const crypto = require('crypto');

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