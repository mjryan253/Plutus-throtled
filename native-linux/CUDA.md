# CUDA 10.2 and dual-GPU (native-linux)

Same as **native-win**: this variant uses **two NVIDIA GPUs** (GTX 1660 for key-gen, GTX 760 for Bloom check). Build and run on Linux with CUDA 10.2.

- **Key-gen GPU** (e.g. GTX 1660): device index 0 by default; override with `KEYGEN_GPU` or `--keygen-gpu`.
- **Check GPU** (e.g. GTX 760): device index 1 by default; override with `CHECK_GPU` or `--check-gpu`.

Install CUDA 10.2 and a driver that supports both Kepler (760) and Turing (1660). Then:

```bash
pip install -r requirements.txt
python3 plutus.py verify-gpu   # optional: verify key-gen and Bloom logic
python3 plutus.py --bloom-file /path/to/addresses.bloom
```

See [native-win/CUDA.md](../native-win/CUDA.md) in the repo for full setup (Windows paths; on Linux use your distro’s CUDA 10.2 package or the official runfile).
