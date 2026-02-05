/*
 * secp256k1 batch key generation for Plutus (GTX 1660).
 * Real implementation: each thread computes (start + idx)*G and writes
 * compressed public key (33 bytes) + private key (32 bytes).
 * Compile with: -arch=sm_75
 */
#include <stdint.h>

#define NLIMB 8
#define PUBKEY_LEN 33
#define PRIVKEY_LEN 32

/* secp256k1 field prime p = 2^256 - 2^32 - 977 (little-endian 32-bit limbs) */
__constant__ uint32_t SECP_P[NLIMB] = {
  0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
  0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

/* Generator G = (Gx, Gy) (little-endian 32-bit limbs) */
__constant__ uint32_t SECP_GX[NLIMB] = {
  0x16F81798, 0x5B81F259, 0xD928CE2D, 0xDBFC9B02,
  0x070B87CE, 0x9562A055, 0xACBBDCF9, 0x7E66BE79
};
__constant__ uint32_t SECP_GY[NLIMB] = {
  0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
  0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77
};

/* Field element: 8 x uint32, d[0] = LSW */
typedef uint32_t fe_t[NLIMB];

__device__ static void fe_set_zero(fe_t r) {
  for (int i = 0; i < NLIMB; i++) r[i] = 0;
}

__device__ static void fe_set_u64(fe_t r, uint64_t lo, uint64_t hi) {
  r[0] = (uint32_t)(lo);
  r[1] = (uint32_t)(lo >> 32);
  r[2] = (uint32_t)(hi);
  r[3] = (uint32_t)(hi >> 32);
  r[4] = 0; r[5] = 0; r[6] = 0; r[7] = 0;
}

__device__ static void fe_copy(fe_t r, const fe_t a) {
  for (int i = 0; i < NLIMB; i++) r[i] = a[i];
}

__device__ static int fe_is_zero(const fe_t a) {
  uint32_t t = 0;
  for (int i = 0; i < NLIMB; i++) t |= a[i];
  return t == 0;
}

__device__ static int fe_ge_p(const fe_t a) {
  for (int i = NLIMB - 1; i >= 0; i--) {
    if (a[i] < SECP_P[i]) return 0;
    if (a[i] > SECP_P[i]) return 1;
  }
  return 1;
}

__device__ static void fe_add(fe_t r, const fe_t a, const fe_t b) {
  uint64_t c = 0;
  for (int i = 0; i < NLIMB; i++) {
    c += (uint64_t)a[i] + b[i];
    r[i] = (uint32_t)c;
    c >>= 32;
  }
  if (c || fe_ge_p(r)) {
    uint64_t borrow = 0;
    for (int i = 0; i < NLIMB; i++) {
      uint64_t t = (uint64_t)r[i] - SECP_P[i] - borrow;
      r[i] = (uint32_t)t;
      borrow = (t >> 32) ? 1 : 0;
    }
  }
}

__device__ static void fe_sub(fe_t r, const fe_t a, const fe_t b) {
  uint64_t borrow = 0;
  for (int i = 0; i < NLIMB; i++) {
    uint64_t t = (uint64_t)a[i] - b[i] - borrow;
    r[i] = (uint32_t)t;
    borrow = (t >> 32) ? 1 : 0;
  }
  if (borrow) {
    uint64_t c = 0;
    for (int i = 0; i < NLIMB; i++) {
      c += (uint64_t)r[i] + SECP_P[i];
      r[i] = (uint32_t)c;
      c >>= 32;
    }
  }
}

__device__ static void fe_mul(fe_t r, const fe_t a, const fe_t b) {
  uint32_t prod[2 * NLIMB];
  for (int i = 0; i < 2 * NLIMB; i++) prod[i] = 0;
  for (int i = 0; i < NLIMB; i++) {
    uint64_t c = 0;
    for (int j = 0; j < NLIMB; j++) {
      uint64_t t = (uint64_t)a[i] * b[j] + prod[i + j] + c;
      prod[i + j] = (uint32_t)t;
      c = t >> 32;
    }
    prod[i + NLIMB] = (uint32_t)c;
  }
  /* Reduce mod p: 2^256 ≡ 2^32 + 977, so result = lo + hi*977 + (hi<<32) */
  for (int i = 0; i < NLIMB; i++) r[i] = prod[i];
  uint32_t *hi = prod + NLIMB;
  uint64_t carry = 0;
  for (int i = 0; i < NLIMB; i++) {
    carry += (uint64_t)r[i] + (uint64_t)hi[i] * 977u;
    r[i] = (uint32_t)carry;
    carry >>= 32;
  }
  carry += (uint64_t)hi[0];
  for (int i = 1; i < NLIMB; i++) {
    carry += (uint64_t)r[i] + (uint64_t)hi[i];
    r[i] = (uint32_t)carry;
    carry >>= 32;
  }
  uint32_t c = (uint32_t)carry;
  if (c) {
    carry = (uint64_t)c * 977u + r[0];
    r[0] = (uint32_t)carry;
    carry >>= 32;
    for (int i = 1; i < NLIMB; i++) {
      carry += r[i] + (i == 1 ? c : 0);
      r[i] = (uint32_t)carry;
      carry >>= 32;
    }
  }
  while (fe_ge_p(r)) {
    uint64_t borrow = 0;
    for (int i = 0; i < NLIMB; i++) {
      uint64_t t = (uint64_t)r[i] - SECP_P[i] - borrow;
      r[i] = (uint32_t)t;
      borrow = (t >> 32) ? 1 : 0;
    }
  }
}

__device__ static void fe_sqr(fe_t r, const fe_t a) {
  fe_mul(r, a, a);
}

__device__ static void fe_inv(fe_t r, const fe_t a) {
  /* r = a^(p-2) mod p (Fermat) */
  fe_t base;
  fe_copy(base, a);
  fe_t acc;
  acc[0] = 1; for (int i = 1; i < NLIMB; i++) acc[i] = 0;
  /* p-2 = 0xFFFFFFFF...FFFFFD2 (256 bits) */
  uint32_t exp[NLIMB] = {
    0xFFFFFD2D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
  };
  for (int bit = 0; bit < 256; bit++) {
    int limb = bit / 32;
    int shift = bit % 32;
    if ((exp[limb] >> shift) & 1) {
      fe_t t;
      fe_mul(t, acc, base);
      fe_copy(acc, t);
    }
    fe_t t;
    fe_sqr(t, base);
    fe_copy(base, t);
  }
  fe_copy(r, acc);
}

__device__ static void fe_neg(fe_t r, const fe_t a) {
  fe_sub(r, SECP_P, a);
}

/* Point in affine: (x, y) */
typedef struct { fe_t x, y; } point_t;

__device__ static void point_double(point_t *r, const point_t *p) {
  if (fe_is_zero(p->y)) { fe_set_zero(r->x); fe_set_zero(r->y); return; }
  fe_t lam, x2, t1, t2, inv2y;
  fe_sqr(x2, p->x);
  t1[0] = 3; for (int i = 1; i < NLIMB; i++) t1[i] = 0;
  fe_mul(lam, t1, x2);           /* 3*x^2 */
  t1[0] = 2; for (int i = 1; i < NLIMB; i++) t1[i] = 0;
  fe_mul(inv2y, t1, p->y);
  fe_inv(t1, inv2y);
  fe_mul(lam, lam, t1);          /* lambda = 3*x^2 / (2*y) */
  fe_sqr(t1, lam);
  fe_copy(t2, p->x);
  fe_sub(r->x, t1, t2);
  fe_sub(r->x, r->x, t2);       /* x' = lambda^2 - 2*x */
  fe_sub(t1, p->x, r->x);
  fe_mul(t2, lam, t1);
  fe_sub(r->y, t2, p->y);
}

__device__ static void point_add(point_t *r, const point_t *p, const point_t *q) {
  if (fe_is_zero(p->x) && fe_is_zero(p->y)) { fe_copy(r->x, q->x); fe_copy(r->y, q->y); return; }
  if (fe_is_zero(q->x) && fe_is_zero(q->y)) { fe_copy(r->x, p->x); fe_copy(r->y, p->y); return; }
  fe_t dx, dy, inv_dx, lam;
  fe_sub(dx, q->x, p->x);
  fe_sub(dy, q->y, p->y);
  if (fe_is_zero(dx)) {
    if (fe_is_zero(dy)) { point_double(r, p); return; }
    else { fe_set_zero(r->x); fe_set_zero(r->y); return; }
  }
  fe_inv(inv_dx, dx);
  fe_mul(lam, dy, inv_dx);
  fe_t lam2, x3;
  fe_sqr(lam2, lam);
  fe_sub(x3, lam2, p->x);
  fe_sub(r->x, x3, q->x);
  fe_sub(lam2, p->x, r->x);
  fe_mul(dy, lam, lam2);
  fe_sub(r->y, dy, p->y);
}

__device__ static void scalar_mult(point_t *r, const fe_t k) {
  point_t g;
  for (int i = 0; i < NLIMB; i++) { g.x[i] = SECP_GX[i]; g.y[i] = SECP_GY[i]; }
  fe_set_zero(r->x);
  fe_set_zero(r->y);
  for (int bit = 255; bit >= 0; bit--) {
    point_t next;
    point_double(&next, r);
    fe_copy(r->x, next.x);
    fe_copy(r->y, next.y);
    int limb = bit / 32;
    int shift = bit % 32;
    if ((k[limb] >> shift) & 1) {
      point_add(&next, r, &g);
      fe_copy(r->x, next.x);
      fe_copy(r->y, next.y);
    }
  }
}

__device__ static void fe_to_bytes_be(unsigned char *out, const fe_t a) {
  for (int i = NLIMB - 1; i >= 0; i--) {
    uint32_t w = a[i];
    out[0] = (unsigned char)(w >> 24);
    out[1] = (unsigned char)(w >> 16);
    out[2] = (unsigned char)(w >> 8);
    out[3] = (unsigned char)(w);
    out += 4;
  }
}

__device__ static void point_to_compressed(unsigned char *out, const point_t *p) {
  unsigned char prefix = (p->y[0] & 1) ? 0x03 : 0x02;
  out[0] = prefix;
  fe_to_bytes_be(out + 1, p->x);
}

__device__ static void fe_from_u64(fe_t r, uint64_t lo, uint64_t hi) {
  fe_set_u64(r, lo, hi);
}

__device__ static void fe_add_u32(fe_t r, const fe_t a, uint32_t b) {
  uint64_t c = b;
  for (int i = 0; i < NLIMB; i++) {
    c += a[i];
    r[i] = (uint32_t)c;
    c >>= 32;
  }
  if (c || fe_ge_p(r)) {
    uint64_t borrow = 0;
    for (int i = 0; i < NLIMB; i++) {
      uint64_t t = (uint64_t)r[i] - SECP_P[i] - borrow;
      r[i] = (uint32_t)t;
      borrow = (t >> 32) ? 1 : 0;
    }
  }
}

extern "C" {

__global__ void batch_keygen(
    const uint64_t start_priv_lo,
    const uint64_t start_priv_hi,
    const uint32_t count,
    unsigned char* __restrict__ pubkeys_out,
    unsigned char* __restrict__ privkeys_out
) {
  uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= count) return;
  fe_t k;
  uint64_t lo = start_priv_lo + (uint64_t)i;
  uint64_t hi = start_priv_hi;
  if (lo < (uint64_t)i) hi++;
  fe_set_u64(k, lo, hi);
  point_t p;
  scalar_mult(&p, k);
  point_to_compressed(pubkeys_out + i * PUBKEY_LEN, &p);
  fe_to_bytes_be(privkeys_out + i * PRIVKEY_LEN, k);
}

}
