# Checker for native-win: runs on CHECK_GPU (e.g. GTX 760).
# Takes batches of (private_key_int, public_key_bytes), runs address derivation + Bloom check
# on GPU when CUDA kernels are available; otherwise falls back to CPU (same as WSL consumer).

import os
import sys

CHECK_GPU = int(os.environ.get('CHECK_GPU', '1'))

_checker_ctx = None
_check_gpu_bloom_d = None  # device pointer to Bloom bit array
_check_gpu_mod = None
_bloom_size_bits = None
_bloom_hash_count = None
_kernel_available = False

def init_check_gpu(database, plutus_module=None):
    """Select CHECK_GPU device and upload Bloom bit array. plutus_module optional (for future use)."""
    global _checker_ctx, _check_gpu_bloom_d, _bloom_size_bits, _bloom_hash_count, _check_gpu_mod, _kernel_available
    try:
        import pycuda.driver as cuda
        from pycuda.compiler import SourceModule
        cuda.init()
        if CHECK_GPU >= cuda.Device.count():
            return False
        dev = cuda.Device(CHECK_GPU)
        _checker_ctx = dev.make_context()
        bit_array = database.bit_array
        _bloom_size_bits = database.size
        _bloom_hash_count = database.hash_count
        n_bytes = len(bit_array)
        _check_gpu_bloom_d = cuda.mem_alloc(n_bytes)
        cuda.memcpy_htod(_check_gpu_bloom_d, bit_array)
        cu_path = os.path.join(os.path.dirname(__file__), 'cuda', 'bloom_check.cu')
        if os.path.isfile(cu_path):
            with open(cu_path, 'r') as f:
                src = f.read()
            try:
                _check_gpu_mod = SourceModule(src, options=['-arch=sm_30'], no_extern_c=True)
                _kernel_available = True
            except Exception:
                pass
        return True
    except Exception:
        return False

def shutdown_check_gpu():
    global _checker_ctx
    if _checker_ctx is not None:
        try:
            _checker_ctx.pop()
        except Exception:
            pass
        _checker_ctx = None

def check_batch_gpu(batch, database, public_key_to_address_fn):
    """
    Run Bloom check on the batch. batch is list of (private_key_int, public_key_bytes).
    Returns list of indices i where address(batch[i]) is in database.
    When GPU kernel is available, computes addresses on CPU and runs Bloom on GPU.
    Otherwise runs full check on CPU.
    """
    if not batch:
        return []
    if _check_gpu_mod is None or not _kernel_available or _check_gpu_bloom_d is None:
        return check_batch_cpu(batch, database, public_key_to_address_fn)
    return check_batch_gpu_kernel(batch, database, public_key_to_address_fn)

def check_batch_cpu(batch, database, public_key_to_address_fn):
    """Full CPU path: derive address and check Bloom for each key."""
    hits = []
    for i, (_, pub) in enumerate(batch):
        addr = public_key_to_address_fn(pub)
        if addr in database:
            hits.append(i)
    return hits

def check_batch_gpu_kernel(batch, database, public_key_to_address_fn):
    """Compute addresses on CPU, run Bloom kernel on GPU (sm_30)."""
    import pycuda.driver as cuda
    _ensure_numpy()
    n = len(batch)
    max_addr_len = 34
    addr_buf = bytearray(n * max_addr_len)
    for i, (_, pub) in enumerate(batch):
        addr = public_key_to_address_fn(pub)
        addr_bytes = addr.encode('ascii')
        start = i * max_addr_len
        addr_buf[start:start + len(addr_bytes)] = addr_bytes
    hit_buf = bytearray(n)
    try:
        addr_d = cuda.mem_alloc(len(addr_buf))
        hit_d = cuda.mem_alloc(len(hit_buf))
        cuda.memcpy_htod(addr_d, addr_buf)
        cuda.memcpy_htod(hit_d, hit_buf)
        func = _check_gpu_mod.get_function('bloom_check_batch')
        func(
            addr_d,
            cuda.In(numpy.array([n], dtype=numpy.uint32)),
            cuda.In(numpy.array([max_addr_len], dtype=numpy.uint32)),
            _check_gpu_bloom_d,
            cuda.In(numpy.array([_bloom_size_bits], dtype=numpy.uint32)),
            cuda.In(numpy.array([_bloom_hash_count], dtype=numpy.uint32)),
            hit_d,
            grid=(n + 255) // 256,
            block=(256, 1, 1)
        )
        cuda.memcpy_dtoh(hit_buf, hit_d)
    except Exception:
        return check_batch_cpu(batch, database, public_key_to_address_fn)
    hits = [i for i in range(n) if hit_buf[i]]
    return hits

# Lazy numpy for kernel path
numpy = None
def _ensure_numpy():
    global numpy
    if numpy is None:
        import numpy as np
        numpy = np
