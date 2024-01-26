#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include "aes128.h"
#include "aes128gcm.h"

void hexdump_data(uint8_t *dat, size_t len)
{
    uint32_t line = len > 0 ? ((len - 1) / 16) + 1 : 0;
    int i = 0;

    for (uint32_t l = 0; l < line; l++) {
        /* head address */
        printf("%08x  ", l);

        for (uint32_t li = 0; li < 16; li++) {
            if (i + li < len) {
                printf("%02x ",  dat[i+li]);
            } else {
                printf("   ");
            }

            if ((li+1) % 8 == 0) {
                printf(" ");
            }
        }

        printf("|");
        for (uint32_t li = 0; li < 16; li++) {
            if (i + li < len) {
                if ((0x20 <= (int)dat[i+li]) && ((int)dat[i+li] <= 0x7e)) {
                   printf("%c", dat[i+li]);
                } else {
                   printf(".");
                }
            } else {
               printf(" ");
            }
        }
        printf("|\n");

        i += 16;
    }

    printf("\n");
}

/* Test Case 4 */
const unsigned char K[16] = { 
    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
};

const unsigned char P[] = {
    0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
    0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
    0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
    0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39
};

const unsigned char IV[12]  = {
    0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88
};

const unsigned char A[] = {
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xab,0xad,0xda,0xd2
};

const unsigned char C[]={
    0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
    0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
    0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
    0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91
};

const unsigned char T[] = {
    0x5b,0xc9,0x4f,0xbc,0x32,0x21,0xa5,0xdb,0x94,0xfa,0xe9,0x5a,0xe7,0x12,0x1a,0x47
};

int main(void) 
{
    unsigned char *ciphertext = malloc(sizeof(P));
    unsigned char *tag = malloc(sizeof(T));
    unsigned int len_p = sizeof(P);
    unsigned int len_ad = sizeof(A);

    aes128gcm(K, IV, P, len_p, A, len_ad, ciphertext, tag);

    printf("### TEST\n");
    printf("Cipher-Text : %s\n", !memcmp(ciphertext, C, sizeof(C)) ? "PASS" : "FAIL");
    printf("Auth-Tag    : %s\n", !memcmp(tag, T, sizeof(T)) ? "PASS" : "FAIL");

    printf("--------\n");
    printf("Cipher Text\n");
    hexdump_data(ciphertext, sizeof(P));
    printf("Tag\n");
    hexdump_data(tag, sizeof(T));

    free(ciphertext);
    free(tag);
    return 0;
}
