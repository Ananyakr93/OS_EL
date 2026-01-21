#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <errno.h>

#define AES_GCM_TAG_LENGTH 16
#define AES_GCM_IV_LENGTH 12

int aes_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *ciphertext, size_t *ciphertext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -ENOMEM;
    }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) ||
        !EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EINVAL;
    }
    int len;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EIO;
    }
    *ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EIO;
    }
    *ciphertext_len += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LENGTH, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EIO;
    }
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aes_gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                    unsigned char *plaintext, size_t *plaintext_len,
                    const unsigned char *key, const unsigned char *iv,
                    const unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -ENOMEM;
    }
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) ||
        !EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EINVAL;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LENGTH, (void *)tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EINVAL;
    }
    int len;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EIO;
    }
    *plaintext_len = len;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret <= 0) {
        return -EILSEQ;  /* Tag mismatch */
    }
    *plaintext_len += len;
    return 0;
}

int aes_ctr_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *ciphertext, size_t *ciphertext_len,
                    const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -ENOMEM;
    }
    /* AES-CTR uses 128-bit (16 byte) IV (counter block) typically, or part IV part counter */
    /* OpenSSL EVP_aes_256_ctr takes a 16-byte IV. Ensure caller provides 16 bytes if using this. */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EINVAL;
    }
    int len;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EIO;
    }
    *ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EIO;
    }
    *ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aes_ctr_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                    unsigned char *plaintext, size_t *plaintext_len,
                    const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -ENOMEM;
    }
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EINVAL;
    }
    int len;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EIO;
    }
    *plaintext_len = len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -EIO;
    }
    *plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
