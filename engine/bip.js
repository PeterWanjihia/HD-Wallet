const crypto = require('crypto');
const fs = require('fs');

/**
 * 🔹 Load BIP39 wordlist as an array
 * Each line becomes an array entry [ "abandon", "ability", ..., "zoo" ]
 */

const wordlist = fs.readFileSync('./wordlist.txt','utf-8').trim().split('\n');

/**
 * 🔹 Generate secure random entropy
 * @param {number} bits - Length of entropy in bits (128 for 12-word mnemonic)
 * @returns {Buffer} entropy bytes
 */

function generateEntropy(bits = 128){
    const entropy = crypto.randomBytes(bits/8);
    return entropy;
}

const entropyBuffer = generateEntropy(128);
console.log("🔷 Raw Entropy Buffer:", entropyBuffer);
console.log("🔷 Entropy as Hex String:", entropyBuffer.toString('hex'));


/**
 * 🔹 Calculate BIP39 checksum bits
 * Steps:
 *   1. SHA256(entropy)
 *   2. Convert hash to binary string
 *   3. Extract first (entropyLength / 32) bits as checksum
 * @param {Buffer} entropyBuffer - Generated entropy bytes
 * @returns {string} checksum bits as a string
 */


function getChecksumBits(entropyBuffer){
    // Convert hash bytes to binary string

    const hash = crypto.createHash('sha256').update(entropyBuffer).digest();
    const hashBits = [...hash].map(b=>b.toString(2).padStart(8,'0')).join('');
    const entropyLength = entropyBuffer.length * 8;
    const checksumLength = entropyLength/32;

    const checkSum = hashBits.slice(0,checksumLength);

    console.log("🔷 SHA256 Hash (hex):", hash.toString('hex'));
    console.log("🔷 SHA256 Hash (binary):", hashBits);
    console.log(`🔷 Checksum (${checksumLength} bits):`, checkSum);
    return  checkSum
}

const checksumBits = getChecksumBits(entropyBuffer);


