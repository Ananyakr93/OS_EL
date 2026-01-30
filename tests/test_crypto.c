#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>
#include <openssl/rand.h>

#include "../crypto/aes.h"
#include "../crypto/hash.h"

/* Test AES-GCM Encrypt/Decrypt Roundtrip */
static void test_aes_gcm_roundtrip(void **state) {
    (void)state;
    unsigned char key[32];
    unsigned char iv[16]; // GCM usually 12 bytes but we allocated 16 in struct
    unsigned char plaintext[4096];
    unsigned char ciphertext[4096];
    unsigned char decrypted[4096];
    unsigned char tag[16];
    
    // Setup random data
    RAND_bytes(key, 32);
    RAND_bytes(iv, 12); // Standard GCM IV length
    RAND_bytes(plaintext, sizeof(plaintext));
    
    size_t enc_len = 0;
    size_t dec_len = 0;
    
    // Encrypt
    int rc = aes_gcm_encrypt(plaintext, sizeof(plaintext), ciphertext, &enc_len, key, iv, tag);
    assert_int_equal(rc, 0);
    assert_int_equal(enc_len, sizeof(plaintext));
    
    // Decrypt
    rc = aes_gcm_decrypt(ciphertext, enc_len, decrypted, &dec_len, key, iv, tag);
    assert_int_equal(rc, 0);
    assert_int_equal(dec_len, sizeof(plaintext));
    
    // Verify content
    assert_memory_equal(plaintext, decrypted, sizeof(plaintext));
}

/* Test SHA256 */
static void test_sha256(void **state) {
    (void)state;
    const char *data = "Hello World";
    unsigned char hash[32];
    
    compute_sha256((unsigned char*)data, strlen(data), hash);
    
    // Known hash for "Hello World"
    // a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
    unsigned char expected[32] = {
        0xa5, 0x91, 0xa6, 0xd4, 0x0b, 0xf4, 0x20, 0x40,
        0x4a, 0x01, 0x17, 0x33, 0xcf, 0xb7, 0xb1, 0x90,
        0xd6, 0x2c, 0x65, 0xbf, 0x0b, 0xcd, 0xa3, 0x2b,
        0x57, 0xb2, 0x77, 0xd9, 0xad, 0x9f, 0x14, 0x6e
    };
    
    assert_memory_equal(hash, expected, 32);
}

/* Test HMAC-SHA256 */
static void test_hmac_sha256(void **state) {
    (void)state;
    const char *key = "key";
    const char *data = "The quick brown fox jumps over the lazy dog";
    unsigned char mac[32];
    
    compute_hmac_sha256((unsigned char*)key, strlen(key), (unsigned char*)data, strlen(data), mac);
    
    // Known HMAC-SHA256: f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
    unsigned char expected[32] = {
        0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
        0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
        0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
        0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8
    };
    
    assert_memory_equal(mac, expected, 32);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_aes_gcm_roundtrip),
        cmocka_unit_test(test_sha256),
        cmocka_unit_test(test_hmac_sha256),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
