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

## Build

Needs CUDA toolkit installed.

```bash
nvcc src/main.cu -o vanity_eth_cuda -O2
```

## Usage

**Normal mode** (private key output, same as upstream):
```bash
./vanity_eth_cuda -d 0 -lz
```

**Secure offset mode:**
```bash
# On your local machine — generate base key
npx tsx scripts/1-generate-base-key.ts

# On GPU machine — run the grind with your public key
./vanity_eth_cuda -d 0 -lz -p <128_hex_char_public_key>

# Back on local machine — combine base key + offset
npx tsx scripts/2-combine-key.ts <offset_from_gpu>
```

## Flags

| Flag | Description |
|------|-------------|
| `-d <n>` | GPU device index (required, use multiple `-d` for multi-GPU) |
| `-lz` | Score by leading zeros |
| `-z` | Score by total zeros |
| `-p <pubkey>` | Offset mode — 128 hex char uncompressed public key (no 04 prefix) |
| `-w <n>` | Work scale — grid size as power of 2 (default 15 = 32768) |

## Performance

~4-6 GH/s on an H100/H200, roughly 3-4x faster than profanity2's OpenCL implementation.

## Scripts

The `scripts/` folder has TypeScript helpers for the offset workflow. They need `ethers` installed (`npm install ethers`).

## License

MIT (same as upstream)
