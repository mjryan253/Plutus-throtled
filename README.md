# Plutus-2

Bitcoin address scanner: generate keys, derive P2PKH addresses, check against a Bloom filter of known funded addresses.

## Variants

| Directory | Description |
|-----------|--------------|
| **WSL/** | Single-GPU iteration for WSL2 (producer on GPU, consumers on CPU). Use with a supported GPU (e.g. GTX 1660). |
| **native-win/** | Dual-GPU native Windows: GTX 1660 for key generation, GTX 760 for address derivation + Bloom check. Requires CUDA 10.2. |
| **native-linux/** | Same codebase as native-win; build and run on Linux with CUDA 10.2 and GTX 1660 + GTX 760. |

See each directory’s README for setup and usage.
