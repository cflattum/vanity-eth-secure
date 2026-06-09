/**
 * STEP 2: Combine base key + offset (RUN LOCALLY ONLY)
 *
 * Takes your secret base key and the offset from the GPU,
 * adds them together (mod curve order) to get the final private key.
 *
 * Usage: npx tsx 2-combine-key.ts <offset_hex>
 */

import { ethers } from 'ethers';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const keysDir = join(__dirname, 'keys');
const privkeyFile = join(keysDir, 'base_private_key.hex');
const finalFile = join(keysDir, 'final_private_key.hex');

const offset = process.argv[2];
if (!offset) {
  console.error('Usage: npx tsx 2-combine-key.ts <offset_hex_from_gpu>');
  process.exit(1);
}

if (!existsSync(privkeyFile)) {
  console.error('ERROR: Base private key not found. Run step 1 first.');
  process.exit(1);
}

const baseKeyHex = readFileSync(privkeyFile, 'utf-8').trim();

// secp256k1 curve order
const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

const baseInt = BigInt('0x' + baseKeyHex);
const offsetInt = BigInt('0x' + offset.replace('0x', ''));
const finalInt = ((baseInt + offsetInt) % N + N) % N;

const finalHex = finalInt.toString(16).padStart(64, '0');
const finalWallet = new ethers.Wallet('0x' + finalHex);

writeFileSync(finalFile, finalHex, { mode: 0o600 });

console.log('Final key generated.\n');
console.log('Address:', finalWallet.address);
console.log('Private key saved to:', finalFile);
console.log('\nImport the private key into your wallet:');
console.log(' ', '0x' + finalHex);
console.log('\nThe offset alone is useless without your base key.');
