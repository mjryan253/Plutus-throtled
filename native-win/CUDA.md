# CUDA 10.2 and dual-GPU (native-win)

This variant uses **two NVIDIA GPUs** on native Windows:

- **Key-gen GPU** (e.g. GTX 1660): generates key pairs via secp256k1 (CUDA kernel, sm_75).
- **Check GPU** (e.g. GTX 760): address derivation + Bloom filter lookup (CUDA kernels, sm_30).

## Why CUDA 10.2

- **GTX 760** is Kepler (compute capability 3.0). CUDA 10.2 is the last toolkit that supports Kepler; newer CUDA versions dropped it.
- **GTX 1660** is Turing (compute capability 7.5) and is supported by CUDA 10.2.
- A single CUDA 10.2 installation can drive both GPUs.

## Setup

1. **Install CUDA Toolkit 10.2**  
   - [CUDA 10.2 archive](https://developer.nvidia.com/cuda-10.2-download-archive) — choose Windows, x86_64, your Windows version.  
   - Ensure the installer adds CUDA to `PATH` and that `nvcc` is available.

2. **Install a driver that supports both GPUs**  
   - Use a driver version that supports CUDA 10.2 and both Kepler and Turing (see NVIDIA driver release notes).  
   - Run `nvidia-smi` and confirm both the 1660 and 760 are listed.

3. **PyCUDA**  
   - Prefer: `pip install pycuda` and run; if the wheel was built for a different CUDA, it may still work with 10.2.  
   - If you get runtime errors, build PyCUDA against CUDA 10.2:
     - Set `CUDA_PATH` to your CUDA 10.2 install (e.g. `C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v10.2`).
     - Run: `pip install pycuda --no-binary pycuda`.

4. **Device assignment**  
   - By default the script uses device index `0` for key-gen and `1` for check.  
   - If your 1660 and 760 are in a different order, set env vars: `KEYGEN_GPU=0` and `CHECK_GPU=1` (or use the CLI flags if implemented).

## Verifying both GPUs

```bash
nvidia-smi
```

You should see both adapters. In Python:

```python
import pycuda.driver as cuda
cuda.init()
for i in range(cuda.Device.count()):
    dev = cuda.Device(i)
    print(i, dev.name())
```

Use the indices that correspond to your 1660 (key-gen) and 760 (check).

## Optional: P2P transfer (1660 → 760)

If both GPUs are on the same driver and support peer-to-peer access, you can reduce host bandwidth by copying the public-key batch directly from 1660 device memory to 760 device memory instead of going through the host queue. This would require a single-process design where key-gen runs on 1660, then `cudaMemcpyPeerAsync` (or similar) to 760, then the Bloom kernel on 760. The current design uses a separate producer process and a host queue; P2P is left as future work.
