/*  RTMPDump - Diffie-Hellmann Key Exchange
 *  Copyright (C) 2009 Andrej Stepanchuk
 *  Copyright (C) 2009-2010 Howard Chu
 *
 *  This file is part of librtmp.
 *
 *  librtmp is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1,
 *  or (at your option) any later version.
 *
 *  librtmp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with librtmp see the file COPYING.  If not, write to
 *  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA  02110-1301, USA.
 *  http://www.gnu.org/copyleft/lgpl.html
 */

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_POLARSSL
#include <polarssl/dhm.h>
typedef mpi *MP_t;
#define PILI_MP_new(m)            \
    m = malloc(sizeof(mpi)); \
    mpi_init(m, NULL)
#define PILI_MP_set_w(mpi, w) mpi_lset(mpi, w)
#define PILI_MP_cmp(u, v) mpi_cmp_mpi(u, v)
#define PILI_MP_set(u, v) mpi_copy(u, v)
#define PILI_MP_sub_w(mpi, w) mpi_sub_int(mpi, mpi, w)
#define PILI_MP_cmp_1(mpi) mpi_cmp_int(mpi, 1)
#define PILI_MP_modexp(r, y, q, p) mpi_exp_mod(r, y, q, p, NULL)
#define PILI_MP_free(mpi)     \
    mpi_free(mpi, NULL); \
    free(mpi)
#define PILI_MP_gethex(u, hex, res) \
    PILI_MP_new(u);                 \
    res = mpi_read_string(u, 16, hex) == 0
#define PILI_MP_bytes(u) mpi_size(u)
#define PILI_MP_setbin(u, buf, len) mpi_write_binary(u, buf, len)
#define PILI_MP_getbin(u, buf, len) \
    PILI_MP_new(u);                 \
    mpi_read_binary(u, buf, len)

typedef struct PILI_MDH {
    MP_t p;
    MP_t g;
    MP_t pub_key;
    MP_t priv_key;
    long length;
    dhm_context ctx;
} PILI_MDH;

#define PILI_MDH_new() calloc(1, sizeof(PILI_MDH))
#define PILI_MDH_free(vp)           \
    {                          \
        PILI_MDH *dh = vp;          \
        dhm_free(&dh->ctx);    \
        PILI_MP_free(dh->p);        \
        PILI_MP_free(dh->g);        \
        PILI_MP_free(dh->pub_key);  \
        PILI_MP_free(dh->priv_key); \
        free(dh);              \
    }

static int PILI_MDH_generate_key(MDH *dh) {
    unsigned char out[2];
    PILI_MP_set(&dh->ctx.P, dh->p);
    PILI_MP_set(&dh->ctx.G, dh->g);
    dh->ctx.len = 128;
    dhm_make_public(&dh->ctx, 1024, out, 1, havege_rand, &RTMP_TLS_ctx->hs);
    PILI_MP_new(dh->pub_key);
    PILI_MP_new(dh->priv_key);
    PILI_MP_set(dh->pub_key, &dh->ctx.GX);
    PILI_MP_set(dh->priv_key, &dh->ctx.X);
    return 1;
}

static int PILI_MDH_compute_key(uint8_t *secret, size_t len, MP_t pub, MDH *dh) {
    int n = len;
    PILI_MP_set(&dh->ctx.GY, pub);
    dhm_calc_secret(&dh->ctx, secret, &n);
    return 0;
}

#elif defined(USE_GNUTLS)
#include <gcrypt.h>
typedef gcry_mpi_t MP_t;
#define PILI_MP_new(m) m = gcry_mpi_new(1)
#define PILI_MP_set_w(mpi, w) gcry_mpi_set_ui(mpi, w)
#define PILI_MP_cmp(u, v) gcry_mpi_cmp(u, v)
#define PILI_MP_set(u, v) gcry_mpi_set(u, v)
#define PILI_MP_sub_w(mpi, w) gcry_mpi_sub_ui(mpi, mpi, w)
#define PILI_MP_cmp_1(mpi) gcry_mpi_cmp_ui(mpi, 1)
#define PILI_MP_modexp(r, y, q, p) gcry_mpi_powm(r, y, q, p)
#define PILI_MP_free(mpi) gcry_mpi_release(mpi)
#define PILI_MP_gethex(u, hex, res) \
    res = (gcry_mpi_scan(&u, GCRYMPI_FMT_HEX, hex, 0, 0) == 0)
#define PILI_MP_bytes(u) (gcry_mpi_get_nbits(u) + 7) / 8
#define PILI_MP_setbin(u, buf, len) \
    gcry_mpi_print(GCRYMPI_FMT_USG, buf, len, NULL, u)
#define PILI_MP_getbin(u, buf, len) \
    gcry_mpi_scan(&u, GCRYMPI_FMT_USG, buf, len, NULL)

typedef struct PILI_MDH {
    MP_t p;
    MP_t g;
    MP_t pub_key;
    MP_t priv_key;
    long length;
} PILI_MDH;

#define PILI_MDH_new() calloc(1, sizeof(MDH))
#define PILI_MDH_free(dh)                      \
    do {                                  \
        PILI_MP_free(((PILI_MDH *)(dh))->p);        \
        PILI_MP_free(((PILI_MDH *)(dh))->g);        \
        PILI_MP_free(((PILI_MDH *)(dh))->pub_key);  \
        PILI_MP_free(((PILI_MDH *)(dh))->priv_key); \
        free(dh);                         \
    } while (0)

extern MP_t gnutls_calc_dh_secret(MP_t *priv, MP_t g, MP_t p);
extern MP_t gnutls_calc_dh_key(MP_t y, MP_t x, MP_t p);

#define PILI_MDH_generate_key(dh) \
    (dh->pub_key = gnutls_calc_dh_secret(&dh->priv_key, dh->g, dh->p))
static int PILI_MDH_compute_key(uint8_t *secret, size_t len, MP_t pub, MDH *dh) {
    MP_t sec = gnutls_calc_dh_key(pub, dh->priv_key, dh->p);
    if (sec) {
        PILI_MP_setbin(sec, secret, len);
        PILI_MP_free(sec);
        return 0;
    } else
        return -1;
}

#else /* USE_OPENSSL */
#include <openssl/bn.h>
#include <openssl/dh.h>

typedef BIGNUM *MP_t;
#define PILI_MP_new(m) m = BN_new()
#define PILI_MP_set_w(mpi, w) BN_set_word(mpi, w)
#define PILI_MP_cmp(u, v) BN_cmp(u, v)
#define PILI_MP_set(u, v) BN_copy(u, v)
#define PILI_MP_sub_w(mpi, w) BN_sub_word(mpi, w)
#define PILI_MP_cmp_1(mpi) BN_cmp(mpi, BN_value_one())
#define PILI_MP_modexp(r, y, q, p)        \
    do {                             \
        BN_CTX *ctx = BN_CTX_new();  \
        BN_mod_exp(r, y, q, p, ctx); \
        BN_CTX_free(ctx);            \
    } while (0)
#define PILI_MP_free(mpi) BN_free(mpi)
#define PILI_MP_gethex(u, hex, res) res = BN_hex2bn(&u, hex)
#define PILI_MP_bytes(u) BN_num_bytes(u)
#define PILI_MP_setbin(u, buf, len) BN_bn2bin(u, buf)
#define PILI_MP_getbin(u, buf, len) u = BN_bin2bn(buf, len, 0)

#define PILI_MDH DH
#define PILI_MDH_new() DH_new()
#define PILI_MDH_free(dh) DH_free(dh)
#define PILI_MDH_generate_key(dh) DH_generate_key(dh)
#define PILI_MDH_compute_key(secret, seclen, pub, dh) DH_compute_key(secret, pub, dh)

#endif

#include "dhgroups.h"
#include "log.h"

/* RFC 2631, Section 2.1.5, http://www.ietf.org/rfc/rfc2631.txt */
static int PILI_isValidPublicKey(MP_t y, MP_t p, MP_t q) {
    int ret = TRUE;
    MP_t bn;
    assert(y);

    PILI_MP_new(bn);
    assert(bn);

    /* y must lie in [2,p-1] */
    PILI_MP_set_w(bn, 1);
    if (PILI_MP_cmp(y, bn) < 0) {
        PILI_RTMP_Log(PILI_RTMP_LOGERROR, "DH public key must be at least 2");
        ret = FALSE;
        goto failed;
    }

    /* bn = p-2 */
    PILI_MP_set(bn, p);
    PILI_MP_sub_w(bn, 1);
    if (PILI_MP_cmp(y, bn) > 0) {
        PILI_RTMP_Log(PILI_RTMP_LOGERROR, "DH public key must be at most p-2");
        ret = FALSE;
        goto failed;
    }

    /* Verify with Sophie-Germain prime
 *
 * This is a nice test to make sure the public key position is calculated
 * correctly. This test will fail in about 50% of the cases if applied to
 * random data.
 */
    if (q) {
        /* y must fulfill y^q mod p = 1 */
        PILI_MP_modexp(bn, y, q, p);

        if (PILI_MP_cmp_1(bn) != 0) {
            PILI_RTMP_Log(PILI_RTMP_LOGWARNING, "DH public key does not fulfill y^q mod p = 1");
        }
    }

failed:
    PILI_MP_free(bn);
    return ret;
}

static PILI_MDH *PILI_DHInit(int nKeyBits) {
    size_t res;
    PILI_MDH *dh = PILI_MDH_new();

    if (!dh)
        goto failed;

    PILI_MP_new(dh->g);

    if (!dh->g)
        goto failed;

    PILI_MP_gethex(dh->p, P1024, res); /* prime P1024, see dhgroups.h */
    if (!res) {
        goto failed;
    }

    PILI_MP_set_w(dh->g, 2); /* base 2 */

    dh->length = nKeyBits;
    return dh;

failed:
    if (dh)
        PILI_MDH_free(dh);

    return 0;
}

static int PILI_DHGenerateKey(PILI_MDH *dh) {
    size_t res = 0;
    if (!dh)
        return 0;

    while (!res) {
        MP_t q1 = NULL;

        if (!PILI_MDH_generate_key(dh))
            return 0;

        PILI_MP_gethex(q1, Q1024, res);
        assert(res);

        res = PILI_isValidPublicKey(dh->pub_key, dh->p, q1);
        if (!res) {
            PILI_MP_free(dh->pub_key);
            PILI_MP_free(dh->priv_key);
            dh->pub_key = dh->priv_key = 0;
        }

        PILI_MP_free(q1);
    }
    return 1;
}

/* fill pubkey with the public key in BIG ENDIAN order
 * 00 00 00 00 00 x1 x2 x3 .....
 */

static int PILI_DHGetPublicKey(PILI_MDH *dh, uint8_t *pubkey, size_t nPubkeyLen) {
    int len;
    if (!dh || !dh->pub_key)
        return 0;

    len = PILI_MP_bytes(dh->pub_key);
    if (len <= 0 || len > (int)nPubkeyLen)
        return 0;

    memset(pubkey, 0, nPubkeyLen);
    PILI_MP_setbin(dh->pub_key, pubkey + (nPubkeyLen - len), len);
    return 1;
}

#if 0 /* unused */
static int
PILI_DHGetPrivateKey(PILI_MDH *dh, uint8_t *privkey, size_t nPrivkeyLen)
{
  if (!dh || !dh->priv_key)
    return 0;

  int len = PILI_MP_bytes(dh->priv_key);
  if (len <= 0 || len > (int) nPrivkeyLen)
    return 0;

  memset(privkey, 0, nPrivkeyLen);
  PILI_MP_setbin(dh->priv_key, privkey + (nPrivkeyLen - len), len);
  return 1;
}
#endif

/* computes the shared secret key from the private MDH value and the
 * other party's public key (pubkey)
 */
static int PILI_DHComputeSharedSecretKey(PILI_MDH *dh, uint8_t *pubkey, size_t nPubkeyLen,
                                    uint8_t *secret) {
    MP_t q1 = NULL, pubkeyBn = NULL;
    size_t len;
    int res;

    if (!dh || !secret || nPubkeyLen >= INT_MAX)
        return -1;

    PILI_MP_getbin(pubkeyBn, pubkey, nPubkeyLen);
    if (!pubkeyBn)
        return -1;

    PILI_MP_gethex(q1, Q1024, len);
    assert(len);

    if (PILI_isValidPublicKey(pubkeyBn, dh->p, q1))
        res = PILI_MDH_compute_key(secret, nPubkeyLen, pubkeyBn, dh);
    else
        res = -1;

    PILI_MP_free(q1);
    PILI_MP_free(pubkeyBn);

    return res;
}
