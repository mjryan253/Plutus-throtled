# Key-gen producer for native-win: runs on KEYGEN_GPU (e.g. GTX 1660).
# Generates batches of (private_key_int, public_key_bytes) and puts them on the queue.
# Uses CUDA kernel when keygen_secp256k1.cu is available; otherwise falls back to coincurve (CPU).

import os
import sys
import numpy as np

# Device index for key-gen GPU (1660). Override with env KEYGEN_GPU.
KEYGEN_GPU = int(os.environ.get('KEYGEN_GPU', '0'))

gpu_producer = None
_keygen_kernel_available = False

try:
    from coincurve import PrivateKey as CCPrivateKey, PublicKey as CCPublicKey
    GENERATOR_PUBLIC_KEY = CCPrivateKey(int(1).to_bytes(32, 'big')).public_key

    import pycuda.driver as cuda
    from pycuda.compiler import SourceModule

    # Select key-gen device (1660) and init context in the producer process
    cuda.init()
    if KEYGEN_GPU >= cuda.Device.count():
        raise RuntimeError(f'KEYGEN_GPU={KEYGEN_GPU} but only {cuda.Device.count()} GPU(s) available')
    _dev = cuda.Device(KEYGEN_GPU)
    _ctx = _dev.make_context()

    # Try to load CUDA key-gen kernel (sm_75 for 1660)
    _keygen_mod = None
    _keygen_cu_path = os.path.join(os.path.dirname(__file__), 'cuda', 'keygen_secp256k1.cu')
    if os.path.isfile(_keygen_cu_path):
        try:
            with open(_keygen_cu_path, 'r') as f:
                _keygen_src = f.read()
            _keygen_mod = SourceModule(_keygen_src, options=['-arch=sm_75'], no_extern_c=True)
            _keygen_kernel_available = True
        except Exception:
            pass

    def gpu_producer(queue, args):
        """Producer: generates key pairs and puts batches of (private_key_int, public_key_bytes) into queue.
        Uses KEYGEN_GPU device. If CUDA kernel is available, uses it; else uses coincurve (CPU)."""
        try:
            if _keygen_kernel_available and _keygen_mod is not None:
                _producer_cuda(queue, args)
            else:
                _producer_coincurve(queue, args)
        finally:
            try:
                _ctx.pop()
            except Exception:
                pass

    def _producer_coincurve(queue, args):
        """CPU fallback: same logic as WSL plutus_gpu (point addition via coincurve)."""
        batch_size = args.get('batch_size', 65536)
        batch = []
        private_key_int = int.from_bytes(os.urandom(32), 'big')
        current_key = CCPrivateKey(private_key_int.to_bytes(32, 'big'))
        current_pub_key = current_key.public_key
        while True:
            public_key_bytes = current_pub_key.format(compressed=True)
            batch.append((private_key_int, public_key_bytes))
            if len(batch) >= batch_size:
                try:
                    queue.put(batch, block=True, timeout=3600)
                except Exception:
                    break
                batch = []
            current_pub_key = CCPublicKey.combine_keys([current_pub_key, GENERATOR_PUBLIC_KEY])
            private_key_int += 1
        if batch:
            try:
                queue.put(batch, block=True, timeout=3600)
            except Exception:
                pass

    def _producer_cuda(queue, args):
        """Use CUDA kernel on KEYGEN_GPU to generate key pairs (33-byte pubkey, 32-byte privkey per key)."""
        batch_size = int(args.get('batch_size', 65536))
        rnd = os.urandom(16)
        start_lo = int.from_bytes(rnd[8:16], 'big')
        start_hi = int.from_bytes(rnd[0:8], 'big')
        kernel = _keygen_mod.get_function('batch_keygen')
        PUBKEY_LEN = 33
        PRIVKEY_LEN = 32
        pubkeys = cuda.pagelocked_empty((batch_size, PUBKEY_LEN), dtype='uint8')
        privkeys = cuda.pagelocked_empty((batch_size, PRIVKEY_LEN), dtype='uint8')
        d_pub = cuda.mem_alloc(batch_size * PUBKEY_LEN)
        d_priv = cuda.mem_alloc(batch_size * PRIVKEY_LEN)
        while True:
            start_lo_val = start_lo & 0xFFFFFFFFFFFFFFFF
            start_hi_val = start_hi & 0xFFFFFFFFFFFFFFFF
            kernel(cuda.In(np.array([start_lo_val], dtype=np.uint64)),
                   cuda.In(np.array([start_hi_val], dtype=np.uint64)),
                   cuda.In(np.array([batch_size], dtype=np.uint32)),
                   d_pub, d_priv,
                   grid=((batch_size + 255) // 256, 1), block=(256, 1, 1))
            cuda.memcpy_dtoh(pubkeys, d_pub)
            cuda.memcpy_dtoh(privkeys, d_priv)
            batch = []
            for i in range(batch_size):
                priv_int = int.from_bytes(bytes(privkeys[i]), 'big')
                pub_bytes = bytes(pubkeys[i])
                batch.append((priv_int, pub_bytes))
            try:
                queue.put(batch, block=True, timeout=3600)
            except Exception:
                break
            total_lo = start_lo + batch_size
            start_lo = total_lo & 0xFFFFFFFFFFFFFFFF
            start_hi = (start_hi + (total_lo >> 64)) & 0xFFFFFFFFFFFFFFFF
        return

except Exception:
    gpu_producer = None
