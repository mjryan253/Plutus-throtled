# Plutus Bitcoin Brute Forcer (native-linux)

Same codebase as **native-win**. Build and run on Linux with **CUDA 10.2** and drivers for **GTX 1660** (key-gen) and **GTX 760** (Bloom check). Use `KEYGEN_GPU` and `CHECK_GPU` env vars or `--keygen-gpu` / `--check-gpu` to set device indices.

---

Welcome to Plutus! This tool hunts for Bitcoin wallets that contain funds by generating keys on the GPU, deriving P2PKH addresses, and checking them against a bloom-filter database of known funded addresses. A GPU producer process feeds key pairs into a bounded queue; CPU consumer threads (or the 760 Bloom kernel) check addresses against the bloom and verify hits against the address list.

## Quick Start

Run the scanner against the database. Key production is **GPU-only**; you need PyCUDA and an NVIDIA GPU. CPU consumer threads check addresses against the bloom filter.

```bash
python3 plutus.py
```

With a custom bloom file and address directory for verification on hit:

```bash
python3 plutus.py --bloom-file bloom/addresses.bloom --address-dir /path/to/address/files
```

Using the bloom file in the repo root and writing verified hits to a CSV file in the repo root with stats:

```bash
python3 plutus.py --bloom-file addresses.bloom --output results.csv --stats
```

You need a bloom filter file at `bloom/addresses.bloom` (or pass `--bloom-file`). If the file is missing, provide `--address-dir` so the program can build the bloom at startup. See **Bloom file** below.

## Installation

1.  **Install Python**: You need Python 3.9 or newer. [Download it here](https://www.python.org/downloads/).
2.  **Get the Code**:
    ```bash
    git clone https://github.com/Isaacdelly/Plutus.git plutus
    cd plutus
    ```
3.  **Install Requirements**:
    ```bash
    pip3 install -r requirements.txt
    ```

**Key production is GPU-only.** PyCUDA and an NVIDIA GPU are required to run the scanner. System requirements:
- **NVIDIA driver** – Must support CUDA (e.g. on WSL2 Ubuntu: install the NVIDIA driver for WSL2).
- **CUDA toolkit** – e.g. CUDA 11.x or 12.x; required for PyCUDA. Install on the host (e.g. Ubuntu: `nvidia-cuda-toolkit` or NVIDIA’s official package).
Run `nvidia-smi` to confirm the GPU is visible. If the GPU producer is unavailable, the program exits with an error.

## Bloom file

The database of funded addresses is stored as a **bloom filter** file for fast loading. The script looks for this file at startup.

- **What it is**: A pre-built filter derived from a list of Bitcoin addresses (P2PKH starting with `1`). Loading a bloom file is much faster than scanning raw address files.
- **Default path**: `bloom/addresses.bloom` (relative to the current working directory). Override with `--bloom-file` or the `BLOOM_FILE` environment variable.
- **How to make a bloom file**: From a directory containing one or more text files (one address per line), run:

  ```bash
  python3 plutus.py build-bloom --address-dir /path/to/address/list --out bloom/addresses.bloom
  ```

  If you omit `--out`, the path from `--bloom-file` is used. The same address list (or directory) should be passed as `--address-dir` when running the scanner so that bloom hits can be verified against the real addresses.

- **Verification on hit**: When the bloom filter reports a possible match, the program confirms it by searching the address list given by `--address-dir`. Always pass `--address-dir` when running the scanner if you want hits to be verified and written to `plutus.txt`.

## How It Works

1.  **Producer** (GPU): One process generates key pairs via **Elliptic Curve Point Addition** from a random starting point (`k`, `k+1`, `k+2`...) and pushes `(private_key_int, public_key_bytes)` into a bounded queue.
2.  **Consumers** (CPU): Multiple threads pop key pairs from the queue, derive the Bitcoin address (P2PKH) for each, and check it against the bloom filter.
3.  **Check**: The bloom filter gives a fast possible match; the consumer then verifies against the raw address list (when `--address-dir` is set).
4.  **Save**: If a verified match is found, the private key (hex and WIF), public key, and address are appended to `plutus.txt`.

## Speed

Throughput is determined by the **producer** (GPU key generation) and **consumers** (address derivation + bloom check). The producer runs in one process (GPU); multiple CPU threads consume keys from a bounded queue and check against the bloom filter. On a modern CPU core, address derivation and bloom check take on the order of **~0.000073 seconds** per key; key generation via point addition is faster. Total keys/sec depends on consumer thread count and producer speed (GPU can increase producer throughput when implemented).

## Expected Output

When running normally, you will see the bloom file loading (or building from `--address-dir`), then consumer threads and producer type, followed by a live speed counter:
```
Loading bloom from bloom/addresses.bloom...
DONE
consumer threads: 7, producer: GPU
Speed: 120000 keys/sec
```

If a wallet with money is found, it saves to `plutus.txt`:
```text
hex private key: 5A4F3F...
WIF private key: 5JW4RC...
public key: 04393B...
address: 1Kz2CT...
```

## Parameters & Options

You can customize how Plutus runs using command-line arguments.

### 1. Verbose Mode (`-v` or `--verbose`)
By default, Plutus runs silently and only shows a speed counter. If you want to see every single Bitcoin address being generated in real-time, use this flag.
*   **Usage**: `python3 plutus.py -v 1`
*   **Note**: This significantly slows down the program because printing to the screen takes time.

### 2. CPU Core Count (`-c` or `--cpu-count`)
Plutus uses **all available CPU cores minus one** by default. This ensures your computer remains responsive while the program runs. If you want to use a specific number of cores (or all of them), you can specify it here.
*   **Usage**: `python3 plutus.py -c 4` (Runs on 4 cores)

### 3. Speed Test (`time`)
Want to know how fast your computer generates a single address? Run the speed test.
*   **Usage**: `python3 plutus.py time`

### 4. Help (`help`)
Shows the help menu.
*   **Usage**: `python3 plutus.py help`

### 5. Diagnostic Test (`test`)
Runs a self-check to verify that the cryptographic functions (Private Key -> WIF -> Public Key -> Address) are calculating correctly.
*   **Usage**: `python3 plutus.py test`

### 6. Build bloom file (`build-bloom`)
Builds a bloom filter file from a directory of address list files (one address per line, P2PKH addresses starting with `1`). Use this to create or refresh the database file that the scanner loads.
*   **Usage**: `python3 plutus.py build-bloom --address-dir /path/to/addresses --out bloom/addresses.bloom`

### 7. Bloom file path (`--bloom-file`)
Path to the bloom filter file to load. Default: `bloom/addresses.bloom`, or the value of the `BLOOM_FILE` environment variable.
*   **Usage**: `python3 plutus.py --bloom-file /path/to/addresses.bloom`

### 8. Address directory (`--address-dir`)
Directory containing raw address list files. Used to build the bloom when the bloom file is missing, and to verify bloom hits when running the scanner.
*   **Usage**: `python3 plutus.py --address-dir /path/to/address/files`

### 9. Runtime stats (`--stats`)
Show queue depth, process CPU %, and GPU utilization/memory in the status line (requires `psutil`; optional `pynvml` for GPU stats).
*   **Usage**: `python3 plutus.py --stats`

### 10. Output path (`--output`)
Path where verified hits are appended. Default: `plutus.txt`. If the path ends with `.csv`, hits are written as CSV rows (with a header line when the file is new).
*   **Usage**: `python3 plutus.py --output results.csv`

## Recent Improvements & TODO

<a href="https://github.com/Isaacdelly/Plutus/issues">Create an issue</a> so I can add more stuff to improve