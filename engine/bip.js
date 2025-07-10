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

/**
 * 🔹 Convert bytes (Buffer) to binary string
 * @param {Array} bytes - Array of bytes from entropyBuffer
 * @returns {string} binary representation
 */


function bytesToBinary(bytes){
    return bytes.map(b => b.toString(2).padStart(8,'0')).join('');

}

// Convert entropyBuffer to binary string
const entropyBits = bytesToBinary([...entropyBuffer]);

console.log("🔷 Entropy Bits Length:", entropyBits.length);
console.log("🔷 Entropy Bits:", entropyBits);

// Append checksum bits
const bitsWithCheckSum = entropyBits + checksumBits;

console.log("🔷 Checksum Bits:", checksumBits);
console.log("🔷 Combined Bits Length (entropy + checksum):", bitsWithCheckSum.length);
console.log("🔷 Combined Bits:", bitsWithCheckSum);

/**
 * 🔹 Split bits into 11-bit groups and map each to a word in the wordlist
 */

function bitsToMnemonic(bits, wordlist) {
    // Split into 11-bit chunks
    const chunks = bits.match(/.{1,11}/g);

    console.log("🔷 Total Chunks (should equal mnemonic word count):", chunks.length);
    console.log("🔷 Chunks:", chunks);

    // Map each chunk to its word
    const words = chunks.map(binary => {
        const index = parseInt(binary, 2);
        return wordlist[index];
    });

    return words;
}

const mnemonicWords = bitsToMnemonic(bitsWithCheckSum, wordlist);

console.log("🔷 🔑 Your BIP39 Mnemonic Phrase:");
console.log(mnemonicWords.join(' '));
