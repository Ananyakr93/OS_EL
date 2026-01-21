#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/evp.h>
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

