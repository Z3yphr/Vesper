// simple_hash.c
// Demonstrates a simple hash (XOR-based) for integration with Python
// Compile with: gcc -shared -o simple_hash.dll -fPIC simple_hash.c (Linux/Mac)
//              cl /LD simple_hash.c (Windows)

#include <stdint.h>

__declspec(dllexport) uint32_t simple_xor_hash(const char* input) {
    uint32_t hash = 0;
    while (*input) {
        hash ^= (uint32_t)(*input);
        input++;
    }
    return hash;
}
