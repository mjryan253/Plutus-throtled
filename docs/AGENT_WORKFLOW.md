# AI Agent Workflow

This file is the shared memory for AI agents working on this repository. **Agents must update this file at the end of every task or session:** refer to it at the start of sessions, and append work, decisions, and troubleshooting here (see Session log below).

---

## Context

- **Repo**: Plutus – Bitcoin brute-force scanner. Generates private keys, derives P2PKH addresses, and checks them against a database of known funded addresses.
- **Database**: A bloom filter (primary). Optionally built from raw address list files. Default path: `bloom/addresses.bloom`.
- **Architecture**: **GPU-only producer** generates key pairs and pushes `(private_key_int, public_key_bytes)` into a **bounded queue**. **CPU consumer threads** pop from the queue, derive the address, check the bloom filter, and on hit verify against the address list and append to `plutus.txt`.
- **Target environment**: WSL2 with Ubuntu; NVIDIA GTX 1660 Ti (compute capability 7.5) for GPU key production when implemented.

---

## Decisions

- **Bloom file** is the primary DB source. Path is configurable via `--bloom-file` or `BLOOM_FILE` env; default `bloom/addresses.bloom`.
- **Build bloom**: `python3 plutus.py build-bloom --address-dir /path/to/addresses --out bloom/addresses.bloom`. README documents how to make a bloom file.
- **Verification on hit** uses the same address list as the bloom: pass `--address-dir` when running the scanner so bloom hits can be confirmed against raw files and written to `plutus.txt`.
- **GPU/CPU split**: Producer and consumers communicate only via a bounded `multiprocessing.Queue` (default maxsize 50000). No shared mutable state beyond the queue. Producer runs in one process; consumers run as threads in the main process (to share the bloom without copying).
- **Key production is GPU-only.** The producer is always `plutus_gpu.gpu_producer`. PyCUDA and an NVIDIA GPU are required; if the GPU producer is unavailable, the program exits with an error. No CPU fallback.

---

## Conventions

- **Bloom file**: Default path `bloom/addresses.bloom`; override with `--bloom-file` or `BLOOM_FILE`.
- **Address list**: Directory of text files (one address per line, P2PKH starting with `1`). Set via `--address-dir` for building bloom and for verification on hit.
- **CLI flags**: `--bloom-file`, `--address-dir`, `--cpu-count`, `--stats`, `--out` (build-bloom), `--verbose`.
- **Actions**: `run`, `time`, `help`, `test`, `build-bloom`.

---

## Troubleshooting

- **Bloom file not found**: Run `python3 plutus.py build-bloom --address-dir /path/to/addresses --out bloom/addresses.bloom` (or ensure `--bloom-file` points to an existing file and/or provide `--address-dir` so the bloom can be built at startup).
- **CUDA / GPU not found on WSL2**: Check `nvidia-smi`, NVIDIA driver for WSL2, and CUDA toolkit (e.g. 11.x or 12.x). Key production is GPU-only; there is no CPU fallback.
- **plutus_gpu import fails**: Ensure `pycuda` and `numpy` are installed (`pip install -r requirements.txt`). If the GPU producer is unavailable, the program exits with an error.
- **Queue backpressure**: If the producer is much faster than consumers, the queue fills and the producer blocks. Tune `QUEUE_MAXSIZE` in `plutus.py` or increase `--cpu-count`; if a GPU producer is added, tune its batch size.
- **Verification on hit does nothing**: Ensure `--address-dir` is set when running the scanner so the process can search the address list for confirmed matches.
- **Invalid bloom file: bad magic (expected b'PLUTUS_BLOOM_v1')**: The file may be in legacy/alternate format with 8-byte magic `PLUTBLOM` instead of 16-byte `PLUTUS_BLOOM_v1`. `BloomFilter.load()` supports both: if the first 8 bytes are `BLOOM_MAGIC_LEGACY = b'PLUTBLOM'`, the rest of the file is treated as the raw bit array with `hash_count=6`. Files like `addresses.bloom` or blockchair-derived blooms may use this format.

---

## Session log

Append below: date, what was done, and any new decisions or troubleshooting notes.

### Debug session: bloom file bad magic (WSL)

- **Issue**: Running `python3 plutus.py --bloom-file addresses.bloom --output results.csv` in WSL raised `ValueError: Invalid bloom file: bad magic (expected b'PLUTUS_BLOOM_v1')`.
- **Hypotheses tested**: (H1) File not created by current Plutus; (H2) file gzip-compressed; (H3) different/older magic; (H4) path resolves to different file in WSL; (H5) file truncated/corrupted.
- **Runtime evidence** (from `.cursor/debug.log`): `first_16_hex`: `504c5554424c4f4d0000803f000000` → first 8 bytes ASCII `PLUTBLOM`, not `PLUTUS_BLOOM_v1`; `file_size`: 133169180. H1 and H3 confirmed; H2, H5 rejected.
- **Fix**: Added legacy bloom format support in `plutus.py`. Constant `BLOOM_MAGIC_LEGACY = b'PLUTBLOM'`. In `BloomFilter.load()`, if the first 8 bytes equal `BLOOM_MAGIC_LEGACY`, seek to byte 8 and treat the remainder as the raw bit array, with `hash_count=6` and size derived from that length. Current format (magic `PLUTUS_BLOOM_v1` + 8-byte header) unchanged.
- **Outcome**: Load succeeds for `addresses.bloom` in WSL; instrumentation removed after user confirmation.

### Implementation: GPU-only producer, --stats visibility, AGENT_WORKFLOW requirement (2025-02-04)

- **Done**:
  1. **GPU-only key production**: Removed `--no-gpu` and CPU producer fallback. Keys are produced only by the GPU; if `gpu_producer` is unavailable, the program exits with an error. Removed `cpu_producer` and legacy `main()` from `plutus.py`. Updated README and AGENT_WORKFLOW to state GPU-only and remove references to `--no-gpu`.
  2. **Lightweight runtime visibility**: Added `--stats` flag. When set, the 1-second status line shows speed, queue depth (when `qsize()` is available), process CPU % (via psutil), and GPU utilization/memory (via pynvml when available). All stats are optional; missing libs or unsupported platforms omit segments. Added `psutil` to requirements.txt; pynvml is optional (commented in requirements).
  3. **AGENT_WORKFLOW requirement**: Reinforced that agents must update this file at the end of every task/session (opening paragraph). Session log entry added for this change set.
- **Decisions**: Key production is GPU-only by design. `--stats` is opt-in to keep default runs unchanged. Queue `qsize()` may be unavailable on some platforms (e.g. macOS); segment is omitted on `NotImplementedError`/`AttributeError`.

### Debug: --stats missing “all cpu threads” (2025-02-04)

- **Issue**: With `--stats`, status line showed only `Speed: X keys/sec | queue: 50000`; user expected to see “all cpu threads checking keys.”
- **Runtime evidence** (`.cursor/debug.log`): `psutil` and `pynvml` not installed → `proc_is_none`: True, `nvml_handle_is_none`: True; segments built were `['Speed: ...', 'queue: 50000']` with no thread count or CPU/GPU.
- **Fix**: (1) Added `threads: N` to the status line when `--stats` (N = consumer thread count from `args.cpu_count`) so the number of CPU threads checking keys is visible without extra deps. (2) When `--stats` is used but psutil or pynvml is missing, print a one-time note: “For full --stats, install: psutil (CPU%), pynvml (GPU).”
- **Outcome**: Post-fix log showed `segments`: `['Speed: 10000 keys/sec', 'threads: 7', 'queue: 50000']`. Instrumentation removed after verification.

### Implementation: Producer/consumer efficiency, nvidia-ml-py (2025-02-04)

- **Done**:
  1. **Batch queue protocol**: Producer ([plutus_gpu.py](plutus_gpu.py)) accumulates keys in a list (batch size 64); when full, `queue.put(batch)`. Consumer ([plutus.py](plutus.py)) `queue.get()` returns a list; loop over batch and process each key (address + bloom). Reduces queue lock traffic. `BATCH_SIZE = 64` in plutus.py; passed via `args_dict['batch_size']`. Consumer accepts single-item batches for compatibility (`if not isinstance(batch, list): batch = [batch]`).
  2. **pynvml → nvidia-ml-py**: Replaced `pynvml` with `nvidia-ml-py` in [requirements.txt](requirements.txt). GPU stats in plutus.py still use `import pynvml` (nvidia-ml-py exposes the pynvml module). Updated “missing” note to “nvidia-ml-py (GPU)” so the deprecation warning goes away when the new package is installed.
  3. **Future work**: Real GPU key generation (CUDA kernel for secp256k1 point addition) is left as a separate, optional project; current producer remains CPU-bound (coincurve) in a separate process.
- **Decisions**: Batch size 64; queue still holds up to QUEUE_MAXSIZE items (now batches). Optional faster secp256k1 library or CUDA key gen can be added later.
