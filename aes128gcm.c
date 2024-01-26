#include "aes128gcm.h"

#define GCM_BLOCK_128 (16)
#define IV_LEN        (12)

static void E(
    const uint8_t *K,
    uint8_t *IN,
    uint8_t *OUT)
{
    aes128enc(K, IN, OUT);
}

static void InitH(
    const uint8_t *K,
    uint8_t *H)
{
    memset(H, 0, GCM_BLOCK_128);
    E(K, H, H);
}

static void InitY(uint8_t *Y0, const uint8_t *IV, unsigned long *seqno) 
{
    memcpy(Y0, IV, IV_LEN);
    (*seqno) = 1;
    Y0[GCM_BLOCK_128 - 1] = (*seqno);
}

static void incr(uint8_t *INC, unsigned long *seqno) 
{
    (*seqno) += 1;

    for (int i = 0; i < 4; ++i) {
        INC[GCM_BLOCK_128 - 1 - i] = (*seqno) >> 8 * i & 0xFF;
    }
}

static char leftshift_bit(uint8_t value) 
{    
    return (0x01 << value);
}

static void rightshift(
    uint8_t *V)
{
    uint8_t carry = 0x00;

    for (int i = 0; i < GCM_BLOCK_128; i++) {
        uint8_t tmpV = V[i];

        V[i] >>= 0x01;
        if (carry == 0x01) {
            V[i] |= 0x80;
        }

        carry = tmpV & 0x01;
    }
}

static void xor_block(
    uint8_t *Z, 
    uint8_t *V) 
{
    for (int i = 0; i < GCM_BLOCK_128; i++) {
        Z[i] = Z[i] ^ V[i];
    }
}

static void ENC_GCTR(
    uint8_t *C, 
    const uint8_t *Cntr0,
    const uint8_t *P, 
    const uint8_t *K, 
    const unsigned long P_len,
    unsigned long *seqno)
{
    uint8_t Cntr[GCM_BLOCK_128] = {0};
    uint8_t ECntr[GCM_BLOCK_128] = {0};
    unsigned long P_blknum = (P_len + 15) / GCM_BLOCK_128;

    memcpy(Cntr, Cntr0, GCM_BLOCK_128);

    for (int i = 0; i < P_blknum; i++) {

        E(K, Cntr, ECntr);

        if ((i < P_blknum - 1) || (P_len % GCM_BLOCK_128 == 0)) {
            for (int j = 0; j < GCM_BLOCK_128; j++) {
                 C[(i * GCM_BLOCK_128) + j] = P[(i * GCM_BLOCK_128) + j] ^ ECntr[j];
            }
        } else {
            for (int j = 0; j < (P_len % GCM_BLOCK_128); j++) {
                 C[(i * GCM_BLOCK_128) + j] = P[(i * GCM_BLOCK_128) + j] ^ ECntr[j];
            }
        } 

        incr(Cntr, seqno);
    }    
}

static void GFmult128(
    const uint8_t *H,
    const uint8_t *Y,
    uint8_t *Z)
{
    uint8_t V[GCM_BLOCK_128] = {0};
    uint8_t R = 0xe1; /* R = 1110001 || 0^120 */

    memset(Z, 0, GCM_BLOCK_128);
    memcpy(V, Y, GCM_BLOCK_128);

    for (int i = 0; i < GCM_BLOCK_128; i++) {
        for (int j = 0; j < GCM_BLOCK_128 / 2; j++) {    
            if (H[i] & leftshift_bit(((GCM_BLOCK_128 / 2) - 1) - j)) {
                xor_block(Z, V);
            }
            
            if (V[GCM_BLOCK_128-1] & 0x01) {
                rightshift(V);
                V[0] ^= R;
            } else {
                rightshift(V);
            }
        }
    }
}

static void CreateAC(
    uint8_t *AC, 
    const uint8_t *A, 
    const unsigned long A_len,
    const uint8_t *C, 
    const unsigned long C_len)
{
    uint64_t A_len_bits = A_len * 8;
    uint64_t C_len_bits = C_len * 8;
    unsigned int A_total_len = ((A_len + GCM_BLOCK_128 - 1) / GCM_BLOCK_128) * GCM_BLOCK_128;
    unsigned int C_total_len = ((C_len + GCM_BLOCK_128 - 1) / GCM_BLOCK_128) * GCM_BLOCK_128;
    unsigned int AC_len = A_total_len + C_total_len + GCM_BLOCK_128;
    unsigned int off = 0;

    memset(AC, 0, AC_len);

    /* A(AAD) */
    memcpy(&AC[off], A, A_len);
    memset(&AC[off + A_len], 0x00, (A_total_len - A_len));
    off += A_total_len;

    /* C(CipherText) */
    memcpy(&AC[off], C, C_len);
    memset(&AC[off + C_len], 0x00, (C_total_len - C_len));
    off += C_total_len;

    /* len(A),len(C) */
    for (unsigned int i = 0; i < sizeof(A_len_bits); i++) {
        AC[off + (sizeof(A_len_bits) - 1) - i] = ((A_len_bits >> 8 * i) & 0xFF);
    }

    off += GCM_BLOCK_128 / 2;

    for (unsigned int i = 0; i < sizeof(C_len_bits); i++) {
        AC[off + (sizeof(C_len_bits) - 1) - i] = ((C_len_bits >> 8 * i) & 0xFF);
    }

    off += GCM_BLOCK_128 / 2;
}

static void GHASH(
    const uint8_t *H,
    const uint8_t *AC,
    const unsigned int AC_len,
    uint8_t *OUT)
{
    uint8_t Y[GCM_BLOCK_128] = {0};
    uint8_t Z[GCM_BLOCK_128] = {0};
    unsigned int AC_blknum = AC_len / GCM_BLOCK_128;

    for (int i = 0; i < AC_blknum; i++) {
        uint8_t X[GCM_BLOCK_128] = {0};
        for (int j = 0; j < GCM_BLOCK_128; j++) {
            X[j] = AC[(i * GCM_BLOCK_128) + j];
        }
        
        xor_block(Y, X);
        GFmult128(H, Y, Z);
        memcpy(Y, Z, GCM_BLOCK_128);
    }

    memcpy(OUT, Y, GCM_BLOCK_128);
}

static void GenAuthTag(
    const uint8_t *K,
    const uint8_t *Y0,
    const uint8_t *H,
    const uint8_t *C,
    const unsigned long C_len,
    const uint8_t *A,
    const unsigned long A_len,
    uint8_t *tag)
{
    unsigned long C_blknum = (C_len + GCM_BLOCK_128 - 1) / GCM_BLOCK_128;
    unsigned long A_blknum = (A_len + GCM_BLOCK_128 - 1) / GCM_BLOCK_128;
     unsigned int AC_len = (C_blknum + A_blknum + 1) * GCM_BLOCK_128;
    uint8_t *AC;
    uint8_t GH[GCM_BLOCK_128] = {0};
    unsigned long seqno = 0; /* unuse */

    AC = (uint8_t *)malloc(AC_len);
    if (AC == NULL) {
        printf("out-of-memory\n");
        exit(EXIT_FAILURE);
    }

    /* AC = A + C + len(A) + len(C)  */
    CreateAC(AC, A, A_len, C, C_len);
    GHASH(H, AC, AC_len, GH);
    free(AC);

    ENC_GCTR(tag, Y0, GH, K, GCM_BLOCK_128, &seqno);
}

void aes128gcm(
    const uint8_t *K, 
    const uint8_t *IV, 
    const uint8_t *plaintext,
    const unsigned long plaintext_len,
    const uint8_t* aad,
    const unsigned long aad_len,
    uint8_t *ciphertext,
    uint8_t *tag)
{
    uint8_t H[GCM_BLOCK_128] = {0};
    uint8_t Y[GCM_BLOCK_128] = {0};
    uint8_t Y0[GCM_BLOCK_128] = {0};
    unsigned long seqno = 0;

    /* H = E(K, 0^128) */
    InitH(K, H);

    /* Y0 = IV||0^31-1 if len(IV) == 96, otherwise not supported */
    InitY(Y, IV, &seqno);
    memcpy(Y0, Y, sizeof(Y0));
    incr(Y, &seqno);
    
    /* encryption */
    ENC_GCTR(ciphertext, Y, plaintext, K, plaintext_len, &seqno);
    
    /* tag */
    GenAuthTag(K, Y0, H, ciphertext, plaintext_len, aad, aad_len, tag);
}

