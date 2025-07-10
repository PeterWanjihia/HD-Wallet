const crypto = require('crypto');
const fs = require('fs');

const wordlist = fs.readFileSync('./wordlist.txt','utf-8').trim().split('\n');

function generateEntropy(bits = 128){
    const entropy = crypto.randomBytes(bits/8);
    return entropy;
}

const entropyBuffer = generateEntropy(128);
console.log("🔷 Raw Entropy Buffer:", entropyBuffer);
console.log("🔷 Entropy as Hex String:", entropyBuffer.toString('hex'));


function getChecksumBits(entropyBuffer){
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


