# Plutus Bitcoin Brute Forcer
# Made by Isaac Delly
# https://github.com/Isaacdelly/Plutus

from coincurve import PrivateKey as CCPrivateKey, PublicKey as CCPublicKey
import multiprocessing
from multiprocessing import Value
import hashlib
import binascii
import os
import sys
import struct
import threading
import time
import argparse

DEFAULT_BLOOM_FILE = 'bloom/addresses.bloom'
QUEUE_MAXSIZE = 50000
BATCH_SIZE = 64
# native-win dual-GPU: larger batches for 1660 key-gen + 760 checker
BATCH_SIZE_DUAL_GPU = 65536
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BLOOM_MAGIC = b'PLUTUS_BLOOM_v1'
BLOOM_MAGIC_LEGACY = b'PLUTBLOM'  # 8-byte legacy magic (older/alternate format)

GENERATOR_PUBLIC_KEY = CCPrivateKey(int(1).to_bytes(32, 'big')).public_key

class BloomFilter:
    def __init__(self, size_in_mb=256):
        self.size = size_in_mb * 1024 * 1024 * 8
        self.bit_array = bytearray(self.size // 8)
        self.hash_count = 6 

    def get_indices(self, string):
        h = hashlib.sha256(string.encode()).digest()
        indices = []
        for i in range(self.hash_count):
            start = i * 4
            chunk = h[start : start + 4]
            val = int.from_bytes(chunk, 'big')
            indices.append(val % self.size)
        return indices

    def add(self, string):
        for index in self.get_indices(string):
            byte_index = index // 8
            bit_index = index % 8
            self.bit_array[byte_index] |= (1 << bit_index)

    def __contains__(self, string):
        for index in self.get_indices(string):
            byte_index = index // 8
            bit_index = index % 8
            if not (self.bit_array[byte_index] & (1 << bit_index)):
                return False
        return True

    def save(self, path):
        """Write bloom filter to a binary file (header + bit_array)."""
        size_in_mb = len(self.bit_array) * 8 // (1024 * 1024)
        with open(path, 'wb') as f:
            f.write(BLOOM_MAGIC)
            f.write(struct.pack('<II', size_in_mb, self.hash_count))
            f.write(self.bit_array)

    @classmethod
    def load(cls, path):
        """Load bloom filter from file. Raises ValueError if format invalid.
        Supports current format (PLUTUS_BLOOM_v1 + 8-byte header) and legacy format (PLUTBLOM + rest as bit_array)."""
        with open(path, 'rb') as f:
            magic = f.read(len(BLOOM_MAGIC))
            if magic == BLOOM_MAGIC:
                header = f.read(8)
                if len(header) != 8:
                    raise ValueError('Invalid bloom file: truncated header')
                size_in_mb, hash_count = struct.unpack('<II', header)
                bit_array = f.read()
                expected_bytes = size_in_mb * 1024 * 1024 // 8
                if len(bit_array) != expected_bytes:
                    raise ValueError(f'Invalid bloom file: expected {expected_bytes} bytes, got {len(bit_array)}')
                obj = cls(size_in_mb=size_in_mb)
                obj.hash_count = hash_count
                obj.bit_array = bytearray(bit_array)
                obj.size = len(bit_array) * 8
                return obj
            if magic[:len(BLOOM_MAGIC_LEGACY)] == BLOOM_MAGIC_LEGACY:
                f.seek(len(BLOOM_MAGIC_LEGACY))
                bit_array = f.read()
                if len(bit_array) == 0:
                    raise ValueError('Invalid bloom file: legacy format has empty bit_array')
                obj = cls(size_in_mb=256)
                obj.hash_count = 6
                obj.bit_array = bytearray(bit_array)
                obj.size = len(bit_array) * 8
                return obj
            raise ValueError(f'Invalid bloom file: bad magic (expected {BLOOM_MAGIC!r})')

def generate_private_key():
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()

def private_key_to_public_key(private_key):
    pk = CCPrivateKey(bytes.fromhex(private_key))
    return pk.public_key.format(compressed=True)

def public_key_to_address(public_key_bytes):
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    prepend_network_byte = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(prepend_network_byte).digest()).digest()[:4]
    address_bytes = prepend_network_byte + checksum
    value = int.from_bytes(address_bytes, 'big')
    output = []
    while value > 0:
        value, remainder = divmod(value, 58)
        output.append(ALPHABET[remainder])
    for byte in address_bytes:
        if byte == 0: output.append(ALPHABET[0])
        else: break
    return ''.join(output[::-1])

def private_key_to_wif(private_key, compressed=True):
    extended_key = b'\x80' + binascii.unhexlify(private_key)
    if compressed:
        extended_key += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    value = int.from_bytes(final_key, 'big')
    output = []
    while value > 0:
        value, remainder = divmod(value, 58)
        output.append(ALPHABET[remainder])
    for byte in final_key:
        if byte == 0: output.append(ALPHABET[0])
        else: break
    return ''.join(output[::-1])

def build_bloom_from_address_dir(address_dir, size_in_mb=256):
    """Build a BloomFilter from all address files in a directory. Returns (BloomFilter, address_count)."""
    database = BloomFilter(size_in_mb=size_in_mb)
    count = 0
    files = [f for f in os.listdir(address_dir) if os.path.isfile(os.path.join(address_dir, f))]
    total_bytes = sum(os.path.getsize(os.path.join(address_dir, f)) for f in files) or 1
    bytes_read = 0
    for filename in files:
        file_path = os.path.join(address_dir, filename)
        with open(file_path) as file:
            for address in file:
                address = address.strip()
                if address.startswith('1'):
                    database.add(address)
                    count += 1
        bytes_read += os.path.getsize(file_path)
        sys.stdout.write(f"\rProgress: {bytes_read / total_bytes * 100:.2f}%")
        sys.stdout.flush()
    return database, count

def run_build_bloom(args):
    """CLI handler for build-bloom: read addresses from --address-dir, write to --out or --bloom-file."""
    address_dir = args.address_dir
    out_path = args.out or args.bloom_file
    if not address_dir or not os.path.isdir(address_dir):
        print('Error: --address-dir is required and must be an existing directory.')
        sys.exit(-1)
    print(f'Building bloom from {address_dir}...')
    database, count = build_bloom_from_address_dir(address_dir, size_in_mb=256)
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    database.save(out_path)
    print(f'\nSaved to {out_path}')
    print('database size: ' + str(count))

def write_hit(output_path, private_key_hex, wif, public_key_hex, address):
    """Append a verified hit to output_path. If path ends with .csv, write CSV row (with header if new file)."""
    is_csv = output_path.lower().endswith('.csv')
    with open(output_path, 'a') as f:
        if is_csv:
            if f.tell() == 0:
                f.write('hex_private_key,wif_private_key,public_key,address\n')
            f.write(f'{private_key_hex},{wif},{public_key_hex},{address}\n')
        else:
            f.write('hex private key: ' + private_key_hex + '\n' +
                    'WIF private key: ' + wif + '\n' +
                    'public key: ' + public_key_hex + '\n' +
                    'address: ' + address + '\n\n')

def consumer(database, queue, args, counter):
    """Consumer: pops batches of (private_key_int, public_key_bytes) from queue, derives address, checks bloom, verifies on hit."""
    local_counter = 0
    output_path = args.get('output', 'plutus.txt')
    while True:
        try:
            batch = queue.get(block=True, timeout=3600)
        except Exception:
            break
        if not isinstance(batch, list):
            batch = [batch]
        for private_key_int, public_key_bytes in batch:
            address = public_key_to_address(public_key_bytes)
            if args.get('verbose'):
                print(address)
            else:
                local_counter += 1
                if local_counter >= 1000:
                    with counter.get_lock():
                        counter.value += local_counter
                    local_counter = 0
            if address in database:
                private_key_hex = hex(private_key_int)[2:].zfill(64).upper()
                wif = str(private_key_to_wif(private_key_hex, compressed=True))
                public_key_hex = public_key_bytes.hex().upper()
                address_dir = args.get('address_dir') or ''
                found = False
                if address_dir and os.path.isdir(address_dir):
                    for filename in os.listdir(address_dir):
                        file_path = os.path.join(address_dir, filename)
                        if os.path.isfile(file_path):
                            with open(file_path) as file:
                                if address in file.read():
                                    found = True
                                    write_hit(output_path, private_key_hex, wif, public_key_hex, address)
                                    break
                if found:
                    print(f"FOUND: {address}")

def timer():
    start = time.time()
    private_key = generate_private_key()
    public_key_bytes = private_key_to_public_key(private_key)
    public_key_to_address(public_key_bytes)
    end = time.time()
    duration = end - start
    print(f"Time to generate one address: {duration:.6f} seconds")
    print(f"Estimated speed per core: {1/duration:.2f} keys/second")
    sys.exit(0)

def test():
    hex_private_key = "0000000000000000000000000000000000000000000000000000000000000001"
    expected_wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    expected_public_key_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    expected_address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    print(f"Testing with Private Key: {hex_private_key}")
    generated_wif = private_key_to_wif(hex_private_key, compressed=True)
    print(f"Generated WIF: {generated_wif}")
    if generated_wif == expected_wif:
        print("WIF Check: PASS")
    else:
        print(f"WIF Check: FAIL (Expected {expected_wif})")
    public_key_bytes = private_key_to_public_key(hex_private_key)
    generated_public_key_hex = public_key_bytes.hex().upper()
    print(f"Generated Public Key: {generated_public_key_hex}")
    if generated_public_key_hex == expected_public_key_hex:
        print("Public Key Check: PASS")
    else:
        print(f"Public Key Check: FAIL (Expected {expected_public_key_hex})")
    generated_address = public_key_to_address(public_key_bytes)
    print(f"Generated Address: {generated_address}")
    if generated_address == expected_address:
        print("Address Check: PASS")
    else:
        print(f"Address Check: FAIL (Expected {expected_address})")
    sys.exit(0)

def verify_gpu():
    """Verify key-gen (coincurve) sequence and Bloom index formula vs Python."""
    from coincurve import PrivateKey as CCPrivateKey, PublicKey as CCPublicKey
    gen_pub = CCPrivateKey(int(1).to_bytes(32, 'big')).public_key
    print('Verify key-gen (coincurve): start key 1, sequence of 5...')
    for k in range(1, 6):
        pk = CCPrivateKey(k.to_bytes(32, 'big'))
        pub_bytes = pk.public_key.format(compressed=True)
        if k == 1:
            current = gen_pub
        else:
            current = CCPublicKey.combine_keys([current, gen_pub])
        got = current.format(compressed=True)
        if got != pub_bytes:
            print(f'  FAIL at k={k}')
            sys.exit(-1)
        print(f'  k={k} OK')
    print('Key-gen check: PASS')
    print('Verify Bloom index formula (Python)...')
    db = BloomFilter(size_in_mb=1)
    addr = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
    db.add(addr)
    if addr not in db:
        print('  Bloom add/contains FAIL')
        sys.exit(-1)
    pub_in = bytes.fromhex('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')
    got_addr = public_key_to_address(pub_in)
    if got_addr != addr:
        print(f'  Address mismatch: got {got_addr}')
        sys.exit(-1)
    if got_addr not in db:
        print('  Bloom contains FAIL for known address')
        sys.exit(-1)
    print('  Bloom check: PASS')
    print('verify-gpu done.')

if __name__ == '__main__':
    default_cpu_count = multiprocessing.cpu_count()
    if default_cpu_count > 1:
        default_cpu_count -= 1
    parser = argparse.ArgumentParser(description='Plutus Bitcoin Brute Forcer', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', nargs='?', default='run', choices=['run', 'time', 'help', 'test', 'build-bloom', 'verify-gpu'], help='Action to perform')
    parser.add_argument('--verbose', '-v', type=int, choices=[0, 1], default=0, help='Verbose output (0 or 1)')
    parser.add_argument('--cpu-count', '-c', type=int, default=default_cpu_count, help='Number of CPU cores')
    parser.add_argument('--bloom-file', type=str, default=os.environ.get('BLOOM_FILE', DEFAULT_BLOOM_FILE), help='Path to bloom filter file')
    parser.add_argument('--address-dir', type=str, default=None, help='Directory of address list files')
    parser.add_argument('--out', '-o', type=str, default=None, help='Output path for build-bloom')
    parser.add_argument('--output', type=str, default='plutus.txt', help='Path for verified hits')
    parser.add_argument('--stats', action='store_true', help='Show queue depth, process CPU%%, and GPU util/memory in status line')
    parser.add_argument('--keygen-gpu', type=int, default=None, help='Device index for key-gen GPU (default: KEYGEN_GPU env or 0)')
    parser.add_argument('--check-gpu', type=int, default=None, help='Device index for check GPU (default: CHECK_GPU env or 1)')
    args = parser.parse_args()
    if args.action == 'help':
        parser.print_help()
        sys.exit(0)
    if args.action == 'time':
        timer()
    if args.action == 'test':
        test()
    if args.action == 'verify-gpu':
        verify_gpu()
        sys.exit(0)
    if args.action == 'build-bloom':
        run_build_bloom(args)
        sys.exit(0)
    if not (0 < args.cpu_count <= multiprocessing.cpu_count()):
        print(f'Error: cpu_count must be between 1 and {multiprocessing.cpu_count()}')
        sys.exit(-1)
    bloom_file = args.bloom_file
    address_dir = args.address_dir
    if os.path.isfile(bloom_file):
        print(f'Loading bloom from {bloom_file}...')
        database = BloomFilter.load(bloom_file)
        print('DONE')
        count = None
    else:
        if not address_dir or not os.path.isdir(address_dir):
            print(f'Error: bloom file not found at {bloom_file} and --address-dir not provided or invalid.')
            sys.exit(-1)
        print('Building bloom from address files...')
        database, count = build_bloom_from_address_dir(address_dir, size_in_mb=256)
        os.makedirs(os.path.dirname(bloom_file) or '.', exist_ok=True)
        database.save(bloom_file)
        print(f'Saved to {bloom_file}')
        print('DONE')
    if count is not None:
        print('database size: ' + str(count))
    args_dict = vars(args)
    args_dict['address_dir'] = address_dir
    key_queue = multiprocessing.Queue(maxsize=QUEUE_MAXSIZE)
    counter = Value('i', 0)
    keygen_gpu_id = args.keygen_gpu if getattr(args, 'keygen_gpu', None) is not None else int(os.environ.get('KEYGEN_GPU', '0'))
    check_gpu_id = args.check_gpu if getattr(args, 'check_gpu', None) is not None else int(os.environ.get('CHECK_GPU', '1'))
    os.environ['KEYGEN_GPU'] = str(keygen_gpu_id)
    os.environ['CHECK_GPU'] = str(check_gpu_id)
    use_dual_gpu = False
    try:
        from keygen_1660 import gpu_producer as keygen_producer
        import checker_760
        if keygen_producer is not None and hasattr(checker_760, 'init_check_gpu'):
            use_dual_gpu = checker_760.init_check_gpu(database, sys.modules[__name__])
    except Exception:
        keygen_producer = None
    if use_dual_gpu and keygen_producer is not None:
        args_dict['batch_size'] = BATCH_SIZE_DUAL_GPU
        print(f'Dual-GPU: key-gen GPU {keygen_gpu_id} (1660), check GPU {check_gpu_id} (760)')
        producer_process = multiprocessing.Process(target=keygen_producer, args=(key_queue, args_dict))
        producer_process.start()
        proc = None
        nvml_handles = []
        pynvml_mod = None
        if args.stats:
            try:
                import psutil
                proc = psutil.Process()
                proc.cpu_percent()
            except Exception:
                pass
            try:
                import pynvml as _pynvml
                _pynvml.nvmlInit()
                for idx in [keygen_gpu_id, check_gpu_id]:
                    if idx < _pynvml.nvmlDeviceGetCount():
                        nvml_handles.append((idx, _pynvml.nvmlDeviceGetHandleByIndex(idx)))
                pynvml_mod = _pynvml
            except Exception:
                pass
        output_path = args_dict.get('output', 'plutus.txt')
        address_dir_val = args_dict.get('address_dir') or ''
        stop_status = [False]
        def status_loop():
            while not stop_status[0]:
                time.sleep(1)
                with counter.get_lock():
                    rate = counter.value
                    counter.value = 0
                segments = [f"Speed: {rate} keys/sec"]
                if args.stats:
                    try:
                        qs = key_queue.qsize()
                        segments.append(f"queue: {qs}")
                    except (NotImplementedError, AttributeError):
                        pass
                    if proc is not None:
                        try:
                            cpu_pct = proc.cpu_percent(interval=None)
                            segments.append(f"CPU: {cpu_pct:.0f}%")
                        except Exception:
                            pass
                    for idx, h in nvml_handles:
                        try:
                            util = pynvml_mod.nvmlDeviceGetUtilizationRates(h)
                            segments.append(f"GPU{idx}: {util.gpu}%")
                        except Exception:
                            pass
                sys.stdout.write("\r" + " | ".join(segments) + "    ")
                sys.stdout.flush()
        status_thread = threading.Thread(target=status_loop)
        status_thread.daemon = True
        if not args.verbose:
            status_thread.start()
        try:
            while True:
                try:
                    batch = key_queue.get(block=True, timeout=3600)
                except Exception:
                    break
                if not isinstance(batch, list):
                    batch = [batch]
                if not batch:
                    continue
                hits = checker_760.check_batch_gpu(batch, database, public_key_to_address)
                with counter.get_lock():
                    counter.value += len(batch)
                for i in hits:
                    private_key_int, public_key_bytes = batch[i]
                    address = public_key_to_address(public_key_bytes)
                    private_key_hex = hex(private_key_int)[2:].zfill(64).upper()
                    wif = str(private_key_to_wif(private_key_hex, compressed=True))
                    public_key_hex = public_key_bytes.hex().upper()
                    found = False
                    if address_dir_val and os.path.isdir(address_dir_val):
                        for filename in os.listdir(address_dir_val):
                            file_path = os.path.join(address_dir_val, filename)
                            if os.path.isfile(file_path):
                                with open(file_path) as file:
                                    if address in file.read():
                                        found = True
                                        write_hit(output_path, private_key_hex, wif, public_key_hex, address)
                                        break
                    if found:
                        print(f"FOUND: {address}")
        except KeyboardInterrupt:
            print("\nShutting down...")
            stop_status[0] = True
            producer_process.terminate()
            producer_process.join(timeout=5)
        finally:
            stop_status[0] = True
            checker_760.shutdown_check_gpu()
    else:
        try:
            from plutus_gpu import gpu_producer
        except ImportError:
            gpu_producer = None
        if gpu_producer is None:
            print('Error: GPU producer required. Install PyCUDA and ensure an NVIDIA GPU and driver are available.')
            sys.exit(-1)
        args_dict['batch_size'] = BATCH_SIZE
        print('consumer threads: ' + str(args.cpu_count) + ', producer: GPU')
        consumer_threads = []
        for _ in range(args.cpu_count):
            t = threading.Thread(target=consumer, args=(database, key_queue, args_dict, counter))
            t.daemon = True
            t.start()
            consumer_threads.append(t)
        producer_process = multiprocessing.Process(target=gpu_producer, args=(key_queue, args_dict))
        producer_process.start()
        proc = None
        nvml_handle = None
        pynvml_mod = None
        if args.stats:
            try:
                import psutil
                proc = psutil.Process()
                proc.cpu_percent()
            except Exception:
                pass
            try:
                import pynvml as _pynvml
                _pynvml.nvmlInit()
                nvml_handle = _pynvml.nvmlDeviceGetHandleByIndex(0)
                pynvml_mod = _pynvml
            except Exception:
                pass
        if not args.verbose:
            try:
                while True:
                    time.sleep(1)
                    with counter.get_lock():
                        rate = counter.value
                        counter.value = 0
                    segments = [f"Speed: {rate} keys/sec"]
                    if args.stats:
                        segments.append(f"threads: {args.cpu_count}")
                        try:
                            qs = key_queue.qsize()
                            segments.append(f"queue: {qs}")
                        except (NotImplementedError, AttributeError):
                            pass
                        if proc is not None:
                            try:
                                cpu_pct = proc.cpu_percent(interval=None)
                                segments.append(f"CPU: {cpu_pct:.0f}%")
                            except Exception:
                                pass
                        if nvml_handle is not None and pynvml_mod is not None:
                            try:
                                util = pynvml_mod.nvmlDeviceGetUtilizationRates(nvml_handle)
                                mem = pynvml_mod.nvmlDeviceGetMemoryInfo(nvml_handle)
                                segments.append(f"GPU: {util.gpu}% mem: {mem.used // (1024*1024)}/{mem.total // (1024*1024)} MiB")
                            except Exception:
                                pass
                    sys.stdout.write("\r" + " | ".join(segments) + "    ")
                    sys.stdout.flush()
            except KeyboardInterrupt:
                print("\nShutting down...")
                producer_process.terminate()
                producer_process.join(timeout=5)
        else:
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                producer_process.terminate()
                producer_process.join(timeout=5)
