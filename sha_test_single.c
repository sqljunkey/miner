__constant uint h_init[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

__constant uint k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint rotate_r(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

void sha256_calc_chunk(uint* h, __constant uint* k, __global uchar* chunk) {
    uint w[64];
    uint temp[8];

   
    for (int i = 0; i < 16; i++) {
        w[i] = (chunk[i * 4] << 24) |
               (chunk[i * 4 + 1] << 16) |
               (chunk[i * 4 + 2] << 8) |
               (chunk[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint s0 = rotate_r(w[i - 15], 7) ^ rotate_r(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint s1 = rotate_r(w[i - 2], 17) ^ rotate_r(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    // Initialize working variables
    for (int i = 0; i < 8; i++) {
        temp[i] = h[i];
    }

    // Main loop
    for (int i = 0; i < 64; i++) {
        uint S1 = rotate_r(temp[4], 6) ^ rotate_r(temp[4], 11) ^ rotate_r(temp[4], 25);
        uint ch = (temp[4] & temp[5]) ^ (~temp[4] & temp[6]);
        uint temp1 = temp[7] + S1 + ch + k[i] + w[i];
        uint S0 = rotate_r(temp[0], 2) ^ rotate_r(temp[0], 13) ^ rotate_r(temp[0], 22);
        uint maj = (temp[0] & temp[1]) ^ (temp[0] & temp[2]) ^ (temp[1] & temp[2]);
        uint temp2 = S0 + maj;

        temp[7] = temp[6];
        temp[6] = temp[5];
        temp[5] = temp[4];
        temp[4] = temp[3] + temp1;
        temp[3] = temp[2];
        temp[2] = temp[1];
        temp[1] = temp[0];
        temp[0] = temp1 + temp2;
    }

    // Update hash values
    for (int i = 0; i < 8; i++) {
        h[i] += temp[i];
    }
}

__kernel void sha256_kernel(
    __global uchar* input,   // Hexadecimal input as bytes
    uint input_len,          // Length of the input
    __global uchar* output   // Output hash in hexadecimal
) {
    uint h[8];
    for (int i = 0; i < 8; i++) {
        h[i] = h_init[i];
    }

    // Process chunks of 64 bytes
    uint chunk_count = (input_len + 63) / 64;
    for (uint i = 0; i < chunk_count; i++) {
        sha256_calc_chunk(h, k, &input[i * 64]);
    }

    // Convert the hash to hexadecimal
    __constant char* lut = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        uint val = h[i];
        for (int j = 0; j < 4; j++) {
            uchar byte = (val >> ((3 - j) * 8)) & 0xFF;
            output[i * 8 + j * 2] = lut[byte >> 4];
            output[i * 8 + j * 2 + 1] = lut[byte & 0xF];
        }
    }
}
