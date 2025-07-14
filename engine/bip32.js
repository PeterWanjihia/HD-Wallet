const bip39 = require('./bip39');
const crypto = require('crypto');
const { ec: EC } = require('elliptic');
const ec = new EC('secp256k1');

// Secp256k1 curve order
const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

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

// Convert IL to BigInt for validation
const IL_int = BigInt('0x' + IL.toString('hex'));

console.log("\n🔍 Validating IL as master private key...");
console.log("IL as integer:", IL_int.toString());
console.log("n (secp256k1 order):", n.toString());

// Perform checks
if (IL_int === 0n) {
    console.log("❌ IL is zero. Invalid master private key.");
    process.exit(1);
} else if (IL_int >= n) {
    console.log("❌ IL is greater than or equal to n. Invalid master private key.");
    process.exit(1);
} else {
    console.log("✅ IL is valid. Proceeding to derive master public key...");
}

// Create key pair from private key
const key = ec.keyFromPrivate(IL);
const pubKey = key.getPublic();
const compressedPubKey = pubKey.encodeCompressed('hex');
const uncompressedPubKey = pubKey.encode('hex');

console.log("\n🔑 Master Public Key (compressed):");
console.log(compressedPubKey);
console.log("\n🔑 Master Public Key (uncompressed):");
console.log(uncompressedPubKey);

// Child Key Derivation Function
function deriveChild(parentPrivateKey, parentChainCode, index) {
    console.log(`\n🔄 Deriving child key with index: ${index}`);
    
    // Check if it's hardened derivation
    const isHardened = index >= 0x80000000; // 2^31
    
    let data;
    if (isHardened) {
        // Hardened derivation: 0x00 || parent_private_key || index
        console.log("   Using HARDENED derivation");
        data = Buffer.concat([
            Buffer.from('00', 'hex'),
            parentPrivateKey,
            Buffer.from(index.toString(16).padStart(8, '0'), 'hex')
        ]);
    } else {
        // Non-hardened derivation: parent_public_key || index
        console.log("   Using NON-HARDENED derivation");
        const parentKey = ec.keyFromPrivate(parentPrivateKey);
        const parentPublicKey = Buffer.from(parentKey.getPublic().encodeCompressed('hex'), 'hex');
        data = Buffer.concat([
            parentPublicKey,
            Buffer.from(index.toString(16).padStart(8, '0'), 'hex')
        ]);
    }
    
    // HMAC-SHA512(parent_chain_code, data)
    const I = crypto.createHmac('sha512', parentChainCode).update(data).digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    
    console.log("   IL (child key material):", IL.toString('hex'));
    console.log("   IR (child chain code):", IR.toString('hex'));
    
    // Child private key = (IL + parent_private_key) mod n
    const IL_int = BigInt('0x' + IL.toString('hex'));
    const parentPrivateKey_int = BigInt('0x' + parentPrivateKey.toString('hex'));
    const childPrivateKey_int = (IL_int + parentPrivateKey_int) % n;
    
    // Convert back to buffer
    const childPrivateKey = Buffer.from(childPrivateKey_int.toString(16).padStart(64, '0'), 'hex');
    const childChainCode = IR;
    
    console.log("   Child private key:", childPrivateKey.toString('hex'));
    console.log("   Child chain code:", childChainCode.toString('hex'));
    
    return {
        privateKey: childPrivateKey,
        chainCode: childChainCode
    };
}

// Function to derive a path like m/44'/0'/0'/0/0
function derivePath(masterPrivateKey, masterChainCode, path) {
    console.log(`\n🌳 Deriving path: ${path}`);
    
    // Parse path
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
            // Hardened derivation
            index = parseInt(segment.slice(0, -1)) + 0x80000000;
        } else {
            // Normal derivation
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

// Generate first Bitcoin address using BIP44 path
console.log("\n" + "=".repeat(60));
console.log("🪙 GENERATING FIRST BITCOIN ADDRESS");
console.log("=".repeat(60));

const bitcoinPath = "m/44'/0'/0'/0/0";
const firstAddress = derivePath(IL, IR, bitcoinPath);

console.log(`\n🎯 Final result for path ${bitcoinPath}:`);
console.log("Private Key:", firstAddress.privateKey.toString('hex'));
console.log("Chain Code:", firstAddress.chainCode.toString('hex'));

// Generate the public key for this address
const addressKey = ec.keyFromPrivate(firstAddress.privateKey);
const addressPubKey = addressKey.getPublic();
console.log("Public Key (compressed):", addressPubKey.encodeCompressed('hex'));

// Generate a few more addresses
console.log("\n" + "=".repeat(60));
console.log("🏠 GENERATING MULTIPLE ADDRESSES");
console.log("=".repeat(60));

for (let i = 0; i < 5; i++) {
    const path = `m/44'/0'/0'/0/${i}`;
    const address = derivePath(IL, IR, path);
    const key = ec.keyFromPrivate(address.privateKey);
    const pubKey = key.getPublic();
    
    console.log(`\nAddress ${i}:`);
    console.log(`  Path: ${path}`);
    console.log(`  Private Key: ${address.privateKey.toString('hex')}`);
    console.log(`  Public Key: ${pubKey.encodeCompressed('hex')}`);
}