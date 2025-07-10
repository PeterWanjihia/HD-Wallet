const crypto = require('crypto');
const fs = require('fs');

// Load BIP39 wordlist as array
const wordlist = fs.readFileSync('./wordlist.txt', 'utf-8').trim().split('\n');

function generateEntropy(bits = 128) {
  return crypto.randomBytes(bits / 8);
}

function getChecksumBits(entropyBuffer) {
  const hash = crypto.createHash('sha256').update(entropyBuffer).digest();
  const hashBits = [...hash].map(b => b.toString(2).padStart(8, '0')).join('');
  const entropyLength = entropyBuffer.length * 8;
  const checksumLength = entropyLength / 32;
  return hashBits.slice(0, checksumLength);
}

function bytesToBinary(bytes) {
  return bytes.map(b => b.toString(2).padStart(8, '0')).join('');
}

function bitsToMnemonic(bits) {
  const chunks = bits.match(/.{1,11}/g);
  return chunks.map(binary => wordlist[parseInt(binary, 2)]);
}

function generateMnemonic(bits = 128) {
  const entropyBuffer = generateEntropy(bits);
  const entropyBits = bytesToBinary([...entropyBuffer]);
  const checksumBits = getChecksumBits(entropyBuffer);
  const bitsWithCheckSum = entropyBits + checksumBits;
  const mnemonicWords = bitsToMnemonic(bitsWithCheckSum);
  return mnemonicWords.join(' ');
}

function mnemonicToSeed(mnemonic, passphrase = '') {
  const salt = 'mnemonic' + passphrase;
  return crypto.pbkdf2Sync(mnemonic, salt, 2048, 64, 'sha512');
}

// Export as an object
module.exports = {
  generateEntropy,
  generateMnemonic,
  mnemonicToSeed
};
