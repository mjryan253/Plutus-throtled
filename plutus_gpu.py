# GPU producer for Plutus: generates key pairs for the queue.
# Requires PyCUDA and NVIDIA CUDA toolkit. If PyCUDA/CUDA is missing, gpu_producer is None.

import os

gpu_producer = None

try:
    import pycuda.autoinit  # noqa: F401
    from coincurve import PrivateKey as CCPrivateKey, PublicKey as CCPublicKey

    GENERATOR_PUBLIC_KEY = CCPrivateKey(int(1).to_bytes(32, 'big')).public_key

    def gpu_producer(queue, args):
        """Producer: generates keys via point addition and puts (private_key_int, public_key_bytes) into queue.
        Uses same key-generation loop as CPU producer; can be extended later with a CUDA kernel."""
        private_key_int = int.from_bytes(os.urandom(32), 'big')
        current_key = CCPrivateKey(private_key_int.to_bytes(32, 'big'))
        current_pub_key = current_key.public_key
        while True:
            public_key_bytes = current_pub_key.format(compressed=True)
            try:
                queue.put((private_key_int, public_key_bytes), block=True, timeout=3600)
            except Exception:
                break
            current_pub_key = CCPublicKey.combine_keys([current_pub_key, GENERATOR_PUBLIC_KEY])
            private_key_int += 1

except Exception:
    gpu_producer = None
