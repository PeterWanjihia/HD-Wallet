const bip39 = require('./bip39');
const crypto = require('crypto');
const { ec: EC } = require('elliptic');
const { keccak256 } = require('js-sha3');

const ec = new EC('secp256k1');
const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

// ====== Step 1: Use your test mnemonic ======
const mnemonic = 'whisper price example win core side scale lock script air exclude wealth';
console.log("🔑 Testing with provided Mnemonic Phrase:\n" + mnemonic);

// ====== Step 2: Derive seed ======
const seed = bip39.mnemonicToSeed(mnemonic, '');

// ====== Step 3: Generate master private key and chain code ======
const I = crypto.createHmac('sha512','Bitcoin Seed').update(seed).digest();
const IL = I.slice(0,32);
const IR = I.slice(32);

console.log("\n🌱 Master Private Key:");
console.log(IL.toString('hex'));
console.log("\n🌱 Master Chain Code:");
console.log(IR.toString('hex'));

// ====== Step 4: Key derivation functions ======
function deriveChild(parentPrivateKey, parentChainCode, index) {
    const isHardened = index >= 0x80000000;
    let data;

    if (isHardened) {
        data = Buffer.concat([
            Buffer.from([0x00]),
            parentPrivateKey,
            Buffer.from(index.toString(16).padStart(8, '0'), 'hex')
        ]);
    } else {
        const parentKey = ec.keyFromPrivate(parentPrivateKey);
        const parentPublicKey = Buffer.from(parentKey.getPublic().encodeCompressed('hex'), 'hex');
        data = Buffer.concat([
            parentPublicKey,
            Buffer.from(index.toString(16).padStart(8, '0'), 'hex')
        ]);
    }

    const I = crypto.createHmac('sha512', parentChainCode).update(data).digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);

    const IL_int = BigInt('0x' + IL.toString('hex'));
    const parentPrivateKey_int = BigInt('0x' + parentPrivateKey.toString('hex'));
    const childPrivateKey_int = (IL_int + parentPrivateKey_int) % n;

    return {
        privateKey: Buffer.from(childPrivateKey_int.toString(16).padStart(64, '0'), 'hex'),
        chainCode: IR
    };
}

function derivePath(masterPrivateKey, masterChainCode, path) {
    const segments = path.split('/');
    if (segments[0] !== 'm') throw new Error('Path must start with m');

    let privKey = masterPrivateKey;
    let chainCode = masterChainCode;

    for (let i = 1; i < segments.length; i++) {
        const segment = segments[i];
        let index = segment.endsWith("'")
            ? parseInt(segment.slice(0, -1)) + 0x80000000
            : parseInt(segment);
        const child = deriveChild(privKey, chainCode, index);
        privKey = child.privateKey;
        chainCode = child.chainCode;
    }

    return { privateKey: privKey, chainCode };
}

// ====== Step 5: Generate and display multiple Ethereum addresses ======
console.log("\n🏠 Generating first 5 Ethereum addresses:");

for (let i = 0; i < 5; i++) {
    const path = `m/44'/60'/0'/0/${i}`;
    const { privateKey } = derivePath(IL, IR, path);
    const key = ec.keyFromPrivate(privateKey);
    const pubKey = key.getPublic();
    const uncompressedPubKeyHex = pubKey.encode('hex').slice(2); // remove '04' prefix

    const ethAddress = '0x' + keccak256(Buffer.from(uncompressedPubKeyHex, 'hex')).slice(-40);

    console.log(`\nAddress ${i}:`);
    console.log(`  Path: ${path}`);
    console.log(`  Private Key: ${privateKey.toString('hex')}`);
    console.log(`  Public Key (compressed): ${pubKey.encodeCompressed('hex')}`);
    console.log(`  Ethereum Address: ${ethAddress}`);
}
