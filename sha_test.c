

#include<stdio.h>



unsigned long c_strlen(const char *str) {
    unsigned long length = 0;

    while (*str++) { 
        length++;
    }

    return length;
}

void *c_memcpy(void *dest, const void *src, size_t n) {
   
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

   
    while (n--) {
        *d++ = *s++;
    }

    return dest; 
}

void *c_memset(void *dest, int c, size_t n) {
    unsigned char *d = (unsigned char *)dest;

   
    while (n--) {
        *d++ = (unsigned char)c;
    }

    return dest; 
}


struct sha256_buff {
    unsigned long long data_size;
    unsigned int h[8];
    unsigned char last_chunk[64];
    unsigned char chunk_size;
};


void sha256_init(struct sha256_buff* buff) {
    buff->h[0] = 0x6a09e667;
    buff->h[1] = 0xbb67ae85;
    buff->h[2] = 0x3c6ef372;
    buff->h[3] = 0xa54ff53a;
    buff->h[4] = 0x510e527f;
    buff->h[5] = 0x9b05688c;
    buff->h[6] = 0x1f83d9ab;
    buff->h[7] = 0x5be0cd19;
    buff->data_size = 0;
    buff->chunk_size = 0;
}

static const unsigned int k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define rotate_r(val, bits) (val >> bits | val << (32 - bits))

static void sha256_calc_chunk(struct sha256_buff* buff, const unsigned char* chunk) {
    unsigned int w[64];
    unsigned int tv[8];
    unsigned int i;

    for (i=0; i<16; ++i){
        w[i] = (unsigned int) chunk[0] << 24 | (unsigned int) chunk[1] << 16 | (unsigned int) chunk[2] << 8 | (unsigned int) chunk[3];
        chunk += 4;
    }
    
    for (i=16; i<64; ++i){
        unsigned int s0 = rotate_r(w[i-15], 7) ^ rotate_r(w[i-15], 18) ^ (w[i-15] >> 3);
        unsigned int s1 = rotate_r(w[i-2], 17) ^ rotate_r(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    for (i = 0; i < 8; ++i)
        tv[i] = buff->h[i];
    
    for (i=0; i<64; ++i){
        unsigned int S1 = rotate_r(tv[4], 6) ^ rotate_r(tv[4], 11) ^ rotate_r(tv[4], 25);
        unsigned int ch = (tv[4] & tv[5]) ^ (~tv[4] & tv[6]);
        unsigned int temp1 = tv[7] + S1 + ch + k[i] + w[i];
        unsigned int S0 = rotate_r(tv[0], 2) ^ rotate_r(tv[0], 13) ^ rotate_r(tv[0], 22);
        unsigned int maj = (tv[0] & tv[1]) ^ (tv[0] & tv[2]) ^ (tv[1] & tv[2]);
        unsigned int temp2 = S0 + maj;
        
        tv[7] = tv[6];
        tv[6] = tv[5];
        tv[5] = tv[4];
        tv[4] = tv[3] + temp1;
        tv[3] = tv[2];
        tv[2] = tv[1];
        tv[1] = tv[0];
        tv[0] = temp1 + temp2;
    }

    for (i = 0; i < 8; ++i)
        buff->h[i] += tv[i];
}

void sha256_update(struct sha256_buff* buff, const void* data, unsigned long size) {
    const unsigned char* ptr = (const unsigned char*)data;
    buff->data_size += size;
    /* If there is data left in buff, concatenate it to process as new chunk */
    if (size + buff->chunk_size >= 64) {
        unsigned char tmp_chunk[64];
        c_memcpy(tmp_chunk, buff->last_chunk, buff->chunk_size);
        c_memcpy(tmp_chunk + buff->chunk_size, ptr, 64 - buff->chunk_size);
        ptr += (64 - buff->chunk_size);
        size -= (64 - buff->chunk_size);
        buff->chunk_size = 0;
        sha256_calc_chunk(buff, tmp_chunk);
    }
    /* Run over data chunks */
    while (size  >= 64) {
        sha256_calc_chunk(buff, ptr);
        ptr += 64;
        size -= 64; 
    }
    
    /* Save remaining data in buff, will be reused on next call or finalize */
    c_memcpy(buff->last_chunk + buff->chunk_size, ptr, size);
    buff->chunk_size += size;
}

void sha256_finalize(struct sha256_buff* buff) {
    buff->last_chunk[buff->chunk_size] = 0x80;
    buff->chunk_size++;
    c_memset(buff->last_chunk + buff->chunk_size, 0, 64 - buff->chunk_size);

    /* If there isn't enough space to fit int64, pad chunk with zeroes and prepare next chunk */
    if (buff->chunk_size > 56) {
        sha256_calc_chunk(buff, buff->last_chunk);
        c_memset(buff->last_chunk, 0, 64);
    }

    /* Add total size as big-endian int64 x8 */
    unsigned long long size = buff->data_size * 8;
    int i;
    for (i = 8; i > 0; --i) {
        buff->last_chunk[55+i] = size & 255;
        size >>= 8;
    }

    sha256_calc_chunk(buff, buff->last_chunk);
}

void sha256_read(const struct sha256_buff* buff, unsigned char* hash) {
    unsigned int i;
    for (i = 0; i < 8; i++) {
        hash[i*4] = (buff->h[i] >> 24) & 255;
        hash[i*4 + 1] = (buff->h[i] >> 16) & 255;
        hash[i*4 + 2] = (buff->h[i] >> 8) & 255;
        hash[i*4 + 3] = buff->h[i] & 255;
    }
}

static void bin_to_hex(const void* data,unsigned int len, char* out) {
    static const char* const lut = "0123456789abcdef";
    unsigned int i;
    for (i = 0; i < len; ++i){
        unsigned char c = ((const unsigned char*)data)[i];
        out[i*2] = lut[c >> 4];
        out[i*2 + 1] = lut[c & 15];
    }
}

void sha256_read_hex(const struct sha256_buff* buff, char* hex) {
    unsigned char hash[32];
    sha256_read(buff, hash);
    bin_to_hex(hash, 32, hex);
}

void sha256_easy_hash(const void* data, unsigned long size, unsigned char* hash) {
    struct sha256_buff buff;
    sha256_init(&buff);
    sha256_update(&buff, data, size);
    sha256_finalize(&buff);
    sha256_read(&buff, hash);
}

void sha256_easy_hash_hex(const void* data, unsigned long size, char* hex) {
    unsigned char hash[32];
    sha256_easy_hash(data, size, hash);
    bin_to_hex(hash, 32, hex);
}


void sha256_easy_hash_hex_from_hex(const char* hex_input,unsigned long input_len ,char* hex_output) {


   
    if (input_len % 2 != 0) {
        *hex_output = '\0';
        return;
    }

    unsigned long byte_len = input_len / 2; 

   
    unsigned char binary_input[1024];
    
   
    if (byte_len > 1024) {
        *hex_output = '\0'; 
        return;
    }

   
    for (size_t i = 0; i < byte_len; ++i) {
        unsigned int value;
        sscanf(hex_input + i * 2, "%2x", &value);
        binary_input[i] = (unsigned char)value;
    }

   
    struct sha256_buff buff;
    sha256_init(&buff);
    sha256_update(&buff, binary_input, byte_len);
    sha256_finalize(&buff);
    sha256_read_hex(&buff, hex_output);
}





int main(){

    char buffer[65] = {0};
    char final[65] ={0};
    char *hasher = "20000000ec0415bdc39735f6573e175d9341542faca4acfb00015e370000000000000000435bef2408d6434f8f94ec717fa75e1c579e25d08c65a12b1fb9ceba99aca7e21702c070674b553436df46a2000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000";
    
    sha256_easy_hash_hex_from_hex(hasher, strlen(hasher), buffer);
    sha256_easy_hash_hex_from_hex(buffer, strlen(buffer),final);
    
    printf("%s\n",final); 



}
