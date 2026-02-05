/*
 * Bloom filter batch check for Plutus native-win (GTX 760).
 * For each address string: SHA256(address) -> 6 indices -> bit test.
 * Compile with: -arch=sm_30
 */
#include <stdint.h>

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

__constant__ uint32_t k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

__device__ void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
  uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
  int i, j;
  for (i = 0, j = 0; i < 16; i++, j += 4)
    m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) | ((uint32_t)data[j+2] << 8) | (uint32_t)data[j+3];
  for (i = 16; i < 64; i++)
    m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
  a = state[0]; b = state[1]; c = state[2]; d = state[3];
  e = state[4]; f = state[5]; g = state[6]; h = state[7];
  for (i = 0; i < 64; i++) {
    t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
    t2 = EP0(a) + MAJ(a,b,c);
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ void sha256_hash(const uint8_t* msg, int len, uint8_t hash[32]) {
  uint32_t state[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
  uint8_t block[64];
  int i, pos = 0;
  uint64_t bitlen = (uint64_t)len * 8;
  while (len >= 64) {
    for (i = 0; i < 64; i++) block[i] = msg[i];
    sha256_transform(state, block);
    msg += 64; len -= 64;
  }
  for (i = 0; i < len; i++) block[i] = msg[i];
  pos = len;
  block[pos++] = 0x80;
  if (pos > 56) {
    while (pos < 64) block[pos++] = 0;
    sha256_transform(state, block);
    pos = 0;
  }
  while (pos < 56) block[pos++] = 0;
  block[56] = (uint8_t)(bitlen >> 56);
  block[57] = (uint8_t)(bitlen >> 48);
  block[58] = (uint8_t)(bitlen >> 40);
  block[59] = (uint8_t)(bitlen >> 32);
  block[60] = (uint8_t)(bitlen >> 24);
  block[61] = (uint8_t)(bitlen >> 16);
  block[62] = (uint8_t)(bitlen >> 8);
  block[63] = (uint8_t)(bitlen);
  sha256_transform(state, block);
  for (i = 0; i < 8; i++) {
    hash[i*4+0] = (state[i] >> 24) & 0xff;
    hash[i*4+1] = (state[i] >> 16) & 0xff;
    hash[i*4+2] = (state[i] >> 8) & 0xff;
    hash[i*4+3] = state[i] & 0xff;
  }
}

extern "C" {

__global__ void bloom_check_batch(
    const unsigned char* __restrict__ addr_buf,
    uint32_t n,
    uint32_t max_addr_len,
    const unsigned char* __restrict__ bloom_bits,
    uint32_t bloom_size_bits,
    uint32_t bloom_hash_count,
    unsigned char* __restrict__ hit_buf
) {
  uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) return;
  uint8_t digest[32];
  int len = 0;
  const unsigned char* p = addr_buf + i * max_addr_len;
  while (len < (int)max_addr_len && p[len] != 0) len++;
  if (len == 0) { hit_buf[i] = 0; return; }
  sha256_hash(p, len, digest);
  int all_set = 1;
  for (uint32_t h = 0; h < bloom_hash_count && all_set; h++) {
    uint32_t val = ((uint32_t)digest[h*4] << 24) | ((uint32_t)digest[h*4+1] << 16) | ((uint32_t)digest[h*4+2] << 8) | (uint32_t)digest[h*4+3];
    uint32_t idx = val % bloom_size_bits;
    uint32_t byte_idx = idx / 8;
    uint32_t bit_idx = idx % 8;
    if (!(bloom_bits[byte_idx] & (1u << bit_idx))) all_set = 0;
  }
  hit_buf[i] = all_set ? 1 : 0;
}

}
