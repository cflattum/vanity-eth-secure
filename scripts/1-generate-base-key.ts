/**
 * STEP 1: Generate base private key (RUN LOCALLY ONLY)
 *
 * Creates a cryptographically secure random key and outputs the public key.
 * Only the PUBLIC KEY goes to the GPU. Private key stays on your machine.
 */

import { ethers } from 'ethers';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const keysDir = join(__dirname, 'keys');
const privkeyFile = join(keysDir, 'base_private_key.hex');
const pubkeyFile = join(keysDir, 'base_public_key.hex');

if (existsSync(privkeyFile)) {
  console.error('ERROR: Base key already exists at', privkeyFile);
  console.error('Delete it manually if you want to regenerate.');
  process.exit(1);
}

mkdirSync(keysDir, { recursive: true });

const wallet = ethers.Wallet.createRandom();
const privateKey = wallet.privateKey.slice(2);
const rawPubKey = wallet.signingKey.publicKey.slice(4);
const publicKey = rawPubKey.padStart(128, '0');

writeFileSync(privkeyFile, privateKey, { mode: 0o600 });
writeFileSync(pubkeyFile, publicKey, { mode: 0o644 });

console.log('Base key generated.\n');
console.log('Private key:', privkeyFile);
console.log('  DO NOT send this anywhere.\n');
console.log('Public key (send to GPU):');
console.log(' ', publicKey);
console.log('');
console.log('Run the CUDA binary on GPU with:');
console.log(`  ./vanity_eth_cuda -d 0 -lz -p ${publicKey}`);
