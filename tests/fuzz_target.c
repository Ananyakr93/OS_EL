#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "../include/fs/block_meta.h"

/*
 * AFL Fuzz Target
 * Reads data from stdin (AFL input), writes to a temporary meta file,
 * and attempts to load it using load_file_meta.
 */
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    
    char temp_path[] = "/tmp/fuzz_meta_XXXXXX";
    int fd = mkstemp(temp_path);
    if (fd == -1) return 1;

    unsigned char buf[4096];
    ssize_t n;
    while ((n = read(0, buf, sizeof(buf))) > 0) {
        if (write(fd, buf, n) != n) {
            close(fd);
            unlink(temp_path);
            return 1;
        }
    }
    close(fd);

    file_meta_t meta = {0};
    unsigned char dummy_key[32] = {0}; // Fuzzing parser resilience, not crypto validity (integrity check will fail usually, but we want to catch crashes)
    
    // Note: load_file_meta verifies HMAC.
    // If we fuzz random input, HMAC check usually fails early (-EACCES).
    // To fuzz the JSON parser effectively, the input MUST have a valid HMAC appended.
    // However, for general robustness, handling garbage input gracefully (returning error, not crashing) is the goal.
    
    load_file_meta(temp_path, &meta, dummy_key);

    free_file_meta(&meta);
    unlink(temp_path);
    return 0;
}
