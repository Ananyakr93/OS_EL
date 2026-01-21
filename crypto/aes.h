/* include/aes.h or crypto/aes.h */
#ifndef ENCFS_AES_H
#define ENCFS_AES_H

#include <stddef.h>

#define AES_GCM_TAG_LENGTH 16
#define AES_GCM_IV_LENGTH  12
#define AES_CTR_IV_LENGTH  16

int aes_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *ciphertext, size_t *ciphertext_len,
                    const unsigned char *key,
                    const unsigned char *iv,
                    unsigned char *tag);

int aes_gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                    unsigned char *plaintext, size_t *plaintext_len,
                    const unsigned char *key,
                    const unsigned char *iv,
                    const unsigned char *tag);

int aes_ctr_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *ciphertext, size_t *ciphertext_len,
                    const unsigned char *key,
                    const unsigned char *iv);

int aes_ctr_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                    unsigned char *plaintext, size_t *plaintext_len,
                    const unsigned char *key,
                    const unsigned char *iv);

#endif
