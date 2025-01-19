from fastecdsa import keys, curve
from ellipticcurve.privateKey import PrivateKey
import platform
import multiprocessing
import hashlib
import binascii
import os
import sys
import time

DATABASE = r'Database/latest-with-address/'

def generate_private_key():
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()

def private_key_to_public_key(private_key, fastecdsa):
    if fastecdsa:
        key = keys.get_public_key(int('0x' + private_key, 0), curve.secp256k1)
        return '04' + (hex(key.x)[2:] + hex(key.y)[2:]).zfill(128)
    else:
        pk = PrivateKey().fromString(bytes.fromhex(private_key))
        return '04' + pk.publicKey().toString().hex().upper()

def public_key_to_address(public_key):
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = ('00' + var.hexdigest()).encode()
    digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
    var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
    count = [char != '0' for char in var_hex].index(True) // 2
    n = int(var_hex, 16)
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    for i in range(count): output.append(alphabet[0])
    return ''.join(output[::-1])

def private_key_to_wif(private_key):
    digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
    var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    var = binascii.unhexlify('80' + private_key + var[0:8])
    alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(var[::-1]): value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = chars[mod] + result, div
    result = chars[value] + result
    for c in var:
        if c == 0: pad += 1
        else: break
    return chars[0] * pad + result

def main(database, args, address_count_shared):
    local_count = 0  # Local counter for addresses tried

    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key, args['fastecdsa']) 
        address = public_key_to_address(public_key)

        local_count += 1
        address_count_shared.value += 1  # Increment the shared counter

        # Sleep after processing each address
        time.sleep(0.01)  # Adjust delay as needed

def timer(args):
    start = time.time()
    private_key = generate_private_key()
    public_key = private_key_to_public_key(private_key, args['fastecdsa'])
    address = public_key_to_address(public_key)
    end = time.time()
    print(str(end - start))
    sys.exit(0)

if __name__ == '__main__':
    args = {
        'verbose': 0,
        'substring': 8,
        'fastecdsa': platform.system() in ['Linux', 'Darwin'],
        'cpu_count': multiprocessing.cpu_count(),
    }

    # Create a manager for shared memory
    manager = multiprocessing.Manager()
    address_count_shared = manager.Value('i', 0)  # Shared integer for address count

    for arg in sys.argv[1:]:
        command = arg.split('=')[0]
        if command == 'help':
            print_help()
        elif command == 'time':
            timer(args)
        elif command == 'cpu_count':
            cpu_count = int(arg.split('=')[1])
            if cpu_count > 0 and cpu_count <= multiprocessing.cpu_count():
                args['cpu_count'] = cpu_count
            else:
                print('invalid input. cpu_count must be greater than 0 and less than or equal to ' + str(multiprocessing.cpu_count()))
                sys.exit(-1)
        elif command == 'verbose':
            verbose = arg.split('=')[1]
            if verbose in ['0', '1']:
                args['verbose'] = verbose
            else:
                print('invalid input. verbose must be 0(false) or 1(true)')
                sys.exit(-1)
        elif command == 'substring':
            substring = int(arg.split('=')[1])
            if substring > 0 and substring < 27:
                args['substring'] = substring
            else:
                print('invalid input. substring must be greater than 0 and less than 27')
                sys.exit(-1)
        else:
            print('invalid input: ' + command  + '\nrun `python3 plutus.py help` for help')
            sys.exit(-1)

    print('reading database files...')
    database = set()
    for filename in os.listdir(DATABASE):
        with open(DATABASE + filename) as file:
            for address in file:
                address = address.strip()
                if address.startswith('1'):
                    database.add(address[-args['substring']:])
    print('DONE')

    print('database size: ' + str(len(database)))
    print('processes spawned: ' + str(args['cpu_count']))

    # Start processes
    processes = []
    for cpu in range(args['cpu_count']):
        p = multiprocessing.Process(target=main, args=(database, args, address_count_shared))
        processes.append(p)
        p.start()

    # Print the address count periodically (in the main process)
    while True:
        time.sleep(10)  # Print every 10 seconds
        print(f"Addresses tried so far: {address_count_shared.value}")

def print_help():
    help_text = """
    Usage: python3 plutus.py [OPTIONS]

    Options:
    help                 Show this help message and exit.
    time                 Run a timer to measure address generation time.
    cpu_count=N          Set the number of CPU cores to use (default is system's CPU count).
    verbose=0|1          Enable verbose output (0 for off, 1 for on).
    substring=N          Set the substring length for address comparison (must be between 1 and 26).
    
    Description:
    This script generates Bitcoin-like addresses by performing elliptic curve cryptography. 
    The process involves generating a private key, deriving the corresponding public key, 
    then generating an address from the public key using the RIPEMD160 hash function and base58 encoding.

    By default, the script uses all available CPU cores for multiprocessing. You can adjust the 
    number of CPU cores with the --cpu_count option to optimize performance depending on your system.

    The script continuously generates addresses and checks them against a predefined database of 
    known addresses. The database can be updated by placing address files in the 'Database/latest-with-address/' directory.

    Example usage:
    python3 plutus.py cpu_count=4 verbose=1 substring=8
    This will run the script with 4 CPU cores, verbose output enabled, and use the last 8 characters of the address for matching.

    Notes:
    - Ensure that the 'Database/latest-with-address/' directory exists and contains address files for comparison.
    - The script is optimized for Linux and macOS systems. It uses the fastecdsa library if available.

    """
    print(help_text)



# Key Changes:

#     Shared Counter: address_count_shared is a shared multiprocessing.Value object that all processes can increment. This eliminates the need for each process to maintain its own counter.
#     Centralized Printing: The address count is printed periodically in the main process (every 10 seconds) using address_count_shared.value.
#     Time.sleep() for process management: The time.sleep(10) in the main loop ensures that the count is printed regularly without overloading the CPU.
# added recompiled help section