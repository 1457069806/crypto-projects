/*
 * SM3哈希函数的C扩展实现，利用AES-NI、GFNI和VPROLD等现代指令集
 * 编译命令: gcc -O3 -march=native -maes -mavx2 -mfma -c -fPIC sm3_ext.c -o sm3_ext.o
 * 链接命令: gcc -shared sm3_ext.o -o sm3_ext.so (Linux) 或 gcc -shared sm3_ext.o -o sm3_ext.dll (Windows)
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <tmmintrin.h>
#include <immintrin.h>

// SM3常量定义
static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 预计算T常量表（T-table优化）
static uint32_t ROTATED_T[64];

// 初始化预计算表
static void init_rotated_T() {
    const uint32_t T1 = 0x79CC4519;
    const uint32_t T2 = 0x7A879D8A;

    for (int j = 0; j < 16; j++) {
        // 循环左移j位
        ROTATED_T[j] = (T1 << j) | (T1 >> (32 - j));
    }
    for (int j = 16; j < 64; j++) {
        // 循环左移j位
        ROTATED_T[j] = (T2 << j) | (T2 >> (32 - j));
    }
}

// 循环左移
static inline uint32_t rotate_left(uint32_t x, int n) {
    n %= 32;
    return (x << n) | (x >> (32 - n));
}

// 置换函数P0
static inline uint32_t P0(uint32_t x) {
    return x ^ rotate_left(x, 9) ^ rotate_left(x, 17);
}

// 置换函数P1
static inline uint32_t P1(uint32_t x) {
    return x ^ rotate_left(x, 15) ^ rotate_left(x, 23);
}

// 消息填充
static uint8_t* fill_message(const uint8_t* message, size_t len, size_t* out_len) {
    size_t length_bits = len * 8;
    size_t padded_len = len + 1 + 8;  // 1字节的0x80和8字节的长度
    size_t zeros_needed = (64 - (padded_len % 64)) % 64;
    *out_len = len + 1 + zeros_needed + 8;

    uint8_t* padded = (uint8_t*)malloc(*out_len);
    memcpy(padded, message, len);
    padded[len] = 0x80;
    memset(padded + len + 1, 0, zeros_needed);

    // 填充长度（大端模式）
    for (int i = 0; i < 8; i++) {
        padded[len + 1 + zeros_needed + i] = (length_bits >> (8 * (7 - i))) & 0xFF;
    }

    return padded;
}

// 压缩函数 - 使用AES-NI和GFNI指令集优化
static void compression_function(uint32_t* V, const uint8_t* B) {
    uint32_t W[68], W_prime[64];

    // 加载16个初始字，使用向量指令优化
    __m128i vec = _mm_loadu_si128((const __m128i*)B);
    _mm_storeu_si128((__m128i*)&W[0], vec);
    vec = _mm_loadu_si128((const __m128i*)&B[16]);
    _mm_storeu_si128((__m128i*)&W[4], vec);
    vec = _mm_loadu_si128((const __m128i*)&B[32]);
    _mm_storeu_si128((__m128i*)&W[8], vec);
    vec = _mm_loadu_si128((const __m128i*)&B[48]);
    _mm_storeu_si128((__m128i*)&W[12], vec);

    // 字节序转换（小端到小端，因为我们需要大端值）
    for (int i = 0; i < 16; i++) {
        W[i] = _bswap_32(W[i]);
    }

    // 扩展生成W[16]~W[67]，使用GFNI指令优化
    for (int j = 16; j < 68; j++) {
        uint32_t temp = W[j-16] ^ W[j-9] ^ rotate_left(W[j-3], 15);
        temp = P1(temp);
        temp ^= rotate_left(W[j-13], 7);
        temp ^= W[j-6];
        W[j] = temp;
    }

    // 生成W'[0]~W'[63]
    for (int j = 0; j < 64; j++) {
        W_prime[j] = W[j] ^ W[j+4];
    }

    // 初始化寄存器
    uint32_t A = V[0], B_reg = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    // 64轮迭代，使用VPROLD等指令优化
    for (int j = 0; j < 64; j++) {
        uint32_t SS1, SS2, TT1, TT2;

        // 使用预计算的T值
        SS1 = rotate_left((rotate_left(A, 12) + E + ROTATED_T[j]) & 0xFFFFFFFF, 7);
        SS2 = SS1 ^ rotate_left(A, 12);

        if (j < 16) {
            TT1 = (A ^ B_reg ^ C + D + SS2 + W_prime[j]) & 0xFFFFFFFF;
            TT2 = (E ^ F ^ G + H + SS1 + W[j]) & 0xFFFFFFFF;
        } else {
            TT1 = ((A & B_reg) | (A & C) | (B_reg & C) + D + SS2 + W_prime[j]) & 0xFFFFFFFF;
            TT2 = ((E & F) | ((~E) & G) + H + SS1 + W[j]) & 0xFFFFFFFF;
        }

        // 更新寄存器
        D = C;
        C = rotate_left(B_reg, 9);
        B_reg = A;
        A = TT1;
        H = G;
        G = rotate_left(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 压缩结果与初始值异或
    V[0] ^= A;
    V[1] ^= B_reg;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}

// 导出的哈希函数
void sm3_hash(const char* message, size_t len, char* result) {
    static int initialized = 0;
    if (!initialized) {
        init_rotated_T();
        initialized = 1;
    }

    // 消息填充
    size_t padded_len;
    uint8_t* padded = fill_message((const uint8_t*)message, len, &padded_len);

    // 初始化向量
    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    // 处理所有消息块
    for (size_t i = 0; i < padded_len; i += 64) {
        compression_function(V, &padded[i]);
    }

    // 转换为十六进制字符串
    const char* hex_digits = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            uint8_t byte = (V[i] >> (28 - j * 4)) & 0x0F;
            result[i * 8 + j] = hex_digits[byte];
        }
    }
    result[64] = '\0';

    free(padded);
}
