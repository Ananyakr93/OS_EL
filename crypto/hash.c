#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

void compute_sha256(const unsigned char *data, size_t len,
                    unsigned char *out_hash)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int out_len = 0;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out_hash, &out_len);

    EVP_MD_CTX_free(ctx);
}

#include <openssl/sha.h>

void sha256(const unsigned char *data, size_t len,
            unsigned char *out_hash)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out_hash, &ctx);
}

void compute_hmac_sha256(const void *key, size_t key_len,
                         const unsigned char *data, size_t data_len,
                         unsigned char *out_mac)
{
    unsigned int len = 32;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out_mac, &len);
}

int derive_key_pbkdf2(const char *passphrase, const unsigned char *salt, size_t salt_len,
                      int iterations, unsigned char *out_key, size_t key_len)
{
    return PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase),
                             salt, (int)salt_len, iterations,
                             EVP_sha256(), (int)key_len, out_key);
}
