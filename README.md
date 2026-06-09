# vanity-eth-secure

CUDA vanity Ethereum address generator with a secure offset mode so your private key never touches the GPU.

Forked from [MrSpike63/vanity-eth-address](https://github.com/MrSpike63/vanity-eth-address) and extended with `-p`/`--public-key` support for safe key generation.

## Why this exists

Most vanity generators output raw private keys, which means whatever machine runs the GPU grind also knows your key. The offset approach fixes that:

1. Generate a random private key locally → derive the public key
2. Send only the public key to the GPU
3. GPU searches from that public key, outputs an offset when it finds a match
4. Combine `private_key + offset (mod N)` locally → final key

The GPU never sees the private key. The offset alone is useless.

## How scoring works

The tool doesn't search for a specific pattern — it just scores addresses by how many zeros they have, and keeps improving until you kill it.

- `-lz` (leading zeros) — scores by consecutive zeros at the start of the address. So `0x00000a...` scores 5.
- `-z` (total zeros) — scores by total zero nibbles anywhere in the address. Good for addresses like `0x000000...000000` where you want zeros at both ends.

It runs continuously and prints whenever it finds a better score. You just let it run until you're happy with what it found and grab the offset.

Each hex digit is 4 bits of entropy, so every additional zero you want roughly 16x's the search time. 10 zeros ≈ minutes, 12 zeros ≈ hours, 14+ zeros ≈ days.

## Build

Needs CUDA toolkit installed.

```bash
nvcc src/main.cu -o vanity_eth_cuda -O2
```

## Usage

**Leading zeros:**
```bash
./vanity_eth_cuda -d 0 -lz
```

**Pattern matching** (hex digits for fixed positions, X for wildcard):
```bash
# Find 0xB00B1E......000
./vanity_eth_cuda -d 0 -m b00b1eXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX000

# Find 0xDEAD......BEEF
./vanity_eth_cuda -d 0 -m deadXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXbeef
```

**Secure offset mode** (combine with any scoring mode):
```bash
# On your local machine — generate base key
npx tsx scripts/1-generate-base-key.ts

# On GPU machine — run the grind with your public key
./vanity_eth_cuda -d 0 -m b00b1eXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX000 -p <128_hex_char_public_key>

# Back on local machine — combine base key + offset
npx tsx scripts/2-combine-key.ts <offset_from_gpu>
```

## Flags

| Flag | Description |
|------|-------------|
| `-d <n>` | GPU device index (required, use multiple `-d` for multi-GPU) |
| `-lz` | Score by leading zeros |
| `-z` | Score by total zeros |
| `-m <pattern>` | Pattern match — 40 char hex pattern, X = wildcard |
| `-p <pubkey>` | Offset mode — 128 hex char uncompressed public key (no 04 prefix) |
| `-w <n>` | Work scale — grid size as power of 2 (default 15 = 32768) |

## Performance

~4-6 GH/s on an H100/H200, roughly 3-4x faster than profanity2's OpenCL implementation.

The speed matters because vanity search is pure brute force — there's no shortcut. You're just hashing billions of public keys per second and checking if the resulting address looks good. Faster GPU = less wall time waiting.

## Scripts

The `scripts/` folder has TypeScript helpers for the offset workflow. They need `ethers` installed (`npm install ethers`).

- `1-generate-base-key.ts` — run locally, generates a random keypair, saves the private key and prints the public key to send to the GPU
- `2-combine-key.ts` — run locally after the GPU finds something, takes the offset and combines it with your base key to produce the final wallet key

## License

MIT (same as upstream)
