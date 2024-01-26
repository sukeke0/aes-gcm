
#ifndef _AES128GCM_H_
#define _AES128GCM_H_

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "aes128.h"

extern void aes128gcm(
    const unsigned char *k, 
    const unsigned char *IV, 
    const unsigned char *plaintext, 
    const unsigned long plaintext_len,
    const unsigned char* add,
    const unsigned long aad_len,
    unsigned char *ciphertext,
    unsigned char *tag);

#endif /* _AES128GCM_H_ */

