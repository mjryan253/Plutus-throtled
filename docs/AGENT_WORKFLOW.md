# AI Agent Workflow

This file is the shared memory for AI agents working on this repository. Refer to it at the start of sessions and append work, decisions, and troubleshooting here.

---

## Context

- **Repo**: Plutus – Bitcoin brute-force scanner. Generates private keys, derives P2PKH addresses, and checks them against a database of known funded addresses.
- **Database**: A bloom filter (primary). Optionally built from raw address list files. Default path: `bloom/addresses.bloom`.
- **Architecture**: GPU (or CPU) **producer** generates key pairs and pushes `(private_key_int, public_key_bytes)` into a **bounded queue**. **CPU consumer threads** pop from the queue, derive the address, check the bloom filter, and on hit verify against the address list and append to `plutus.txt`.
- **Target environment**: WSL2 with Ubuntu; NVIDIA GTX 1660 Ti (compute capability 7.5) for GPU key production when implemented.

---

## Decisions

- **Bloom file** is the primary DB source. Path is configurable via `--bloom-file` or `BLOOM_FILE` env; default `bloom/addresses.bloom`.
- **Build bloom**: `python3 plutus.py build-bloom --address-dir /path/to/addresses --out bloom/addresses.bloom`. README documents how to make a bloom file.
- **Verification on hit** uses the same address list as the bloom: pass `--address-dir` when running the scanner so bloom hits can be confirmed against raw files and written to `plutus.txt`.
- **GPU/CPU split**: Producer and consumers communicate only via a bounded `multiprocessing.Queue` (default maxsize 50000). No shared mutable state beyond the queue. Producer runs in one process; consumers run as threads in the main process (to share the bloom without copying).
- **Default run mode**: NVIDIA GPU + CPU. The producer uses the GPU when `plutus_gpu.gpu_producer` is available (PyCUDA and CUDA toolkit installed); otherwise the CPU producer runs. `pycuda` and `numpy` in requirements.txt are required for the GPU producer. Use `--no-gpu` to force CPU-only key producer.

---

## Conventions

- **Bloom file**: Default path `bloom/addresses.bloom`; override with `--bloom-file` or `BLOOM_FILE`.
- **Address list**: Directory of text files (one address per line, P2PKH starting with `1`). Set via `--address-dir` for building bloom and for verification on hit.
- **CLI flags**: `--bloom-file`, `--address-dir`, `--cpu-count`, `--no-gpu`, `--out` (build-bloom), `--verbose`.
- **Actions**: `run`, `time`, `help`, `test`, `build-bloom`.

---

## Troubleshooting

- **Bloom file not found**: Run `python3 plutus.py build-bloom --address-dir /path/to/addresses --out bloom/addresses.bloom` (or ensure `--bloom-file` points to an existing file and/or provide `--address-dir` so the bloom can be built at startup).
- **CUDA / GPU not found on WSL2**: Check `nvidia-smi`, NVIDIA driver for WSL2, and CUDA toolkit (e.g. 11.x or 12.x). Use `--no-gpu` to run with CPU-only producer.
- **plutus_gpu import fails or producer stays CPU**: Ensure `pycuda` and `numpy` are installed (`pip install -r requirements.txt`). If PyCUDA or CUDA toolkit is missing, `plutus_gpu.gpu_producer` is set to `None` and the scanner falls back to the CPU producer without raising.
- **Queue backpressure**: If the producer is much faster than consumers, the queue fills and the producer blocks. Tune `QUEUE_MAXSIZE` in `plutus.py` or increase `--cpu-count`; if a GPU producer is added, tune its batch size.
- **Verification on hit does nothing**: Ensure `--address-dir` is set when running the scanner so the process can search the address list for confirmed matches.

---

## Session log

Append below: date, what was done, and any new decisions or troubleshooting notes.
