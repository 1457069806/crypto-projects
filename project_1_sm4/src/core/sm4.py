# SM4加密算法的基础Python实现
# 参考GM/T 0002-2012《SM4分组密码算法》

class SM4:
    def __init__(self, key):
        """初始化SM4算法，设置密钥"""
        self.key = key
        self.Sbox = [
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x0d, 0x5d, 0x29,
            0x87, 0x51, 0x89, 0x0c, 0x09, 0xe0, 0x41, 0x1d, 0x2d, 0x02, 0x1f, 0xcd, 0x48, 0x55, 0x9b, 0xdb,
            0xa3, 0x8c, 0x9e, 0x03, 0xff, 0x60, 0x52, 0x7d, 0x92, 0xf6, 0xc4, 0x18, 0xf0, 0x7e, 0xec, 0x7b,
            0xca, 0x82, 0xc5, 0x96, 0x40, 0x0a, 0x46, 0xc7, 0xf1, 0xd7, 0xfb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc0, 0xd3, 0x02, 0xf7, 0xcb, 0x7d, 0xfa, 0x3e, 0x19, 0xe5, 0x4b, 0x0b, 0x34,
            0x7f, 0x00, 0x28, 0x92, 0x4f, 0x9c, 0x31, 0x23, 0x20, 0x42, 0x90, 0x84, 0x46, 0x2d, 0xf2, 0x33,
            0x15, 0x93, 0x53, 0x99, 0x61, 0x10, 0x1a, 0x07, 0x38, 0x6f, 0x37, 0x57, 0xb9, 0x1b, 0x97, 0x50,
            0x3b, 0x6d, 0x4d, 0x29, 0x0c, 0x5f, 0xac, 0x62, 0xe1, 0x0f, 0x8e, 0x51, 0xe7, 0x1d, 0x2a, 0x9a,
            0xdb, 0xc6, 0x5b, 0xa0, 0x8c, 0x36, 0x48, 0x04, 0x9f, 0x6e, 0x11, 0xd4, 0xa5, 0x7a, 0xca, 0x8d,
            0x83, 0x91, 0x1c, 0x76, 0x3e, 0x6a, 0x80, 0xbc, 0x27, 0x39, 0xea, 0x65, 0x7a, 0xae, 0x08, 0x03
        ]

        self.fixed_param = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
        self.rk = self._key_expansion()

    def _key_expansion(self):
        """密钥扩展，生成轮密钥"""
        # 将128位密钥转换为4个32位字
        MK = [
            (self.key[0] << 24) | (self.key[1] << 16) | (self.key[2] << 8) | self.key[3],
            (self.key[4] << 24) | (self.key[5] << 16) | (self.key[6] << 8) | self.key[7],
            (self.key[8] << 24) | (self.key[9] << 16) | (self.key[10] << 8) | self.key[11],
            (self.key[12] << 24) | (self.key[13] << 16) | (self.key[14] << 8) | self.key[15]
        ]

        # 初始化密钥
        K = [MK[0] ^ self.fixed_param[0],
             MK[1] ^ self.fixed_param[1],
             MK[2] ^ self.fixed_param[2],
             MK[3] ^ self.fixed_param[3]]

        rk = []
        for i in range(32):
            # 生成轮密钥
            k = K[(i + 1) % 4] ^ self._t_(K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ self._ck_(i))
            rk.append(k)
            K[i % 4] = k

        return rk

    def _ck_(self, i):
        """轮常量"""
        ck = [
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        ]
        return ck[i]

    def _t_(self, x):
        """T函数，用于密钥扩展"""
        return self._l_(self._sbox_transform(x))

    def _sbox_transform(self, x):
        """S盒变换"""
        result = 0
        for i in range(4):
            byte = (x >> (24 - i * 8)) & 0xff
            result |= self.Sbox[byte] << (24 - i * 8)
        return result

    def _l_(self, x):
        """线性变换L"""
        return x ^ self._rotl(x, 2) ^ self._rotl(x, 10) ^ self._rotl(x, 18) ^ self._rotl(x, 24)

    def _rotl(self, x, n):
        """循环左移n位"""
        return ((x << n) & 0xFFFFFFFF) | ((x >> (32 - n)) & 0xFFFFFFFF)

    def _f_(self, x0, x1, x2, x3, rk):
        """轮函数"""
        return x0 ^ self._l_(self._sbox_transform(x1 ^ x2 ^ x3 ^ rk))

    def encrypt(self, plaintext):
        """加密函数，输入16字节明文，返回16字节密文"""
        if len(plaintext) != 16:
            raise ValueError("SM4加密需要16字节的明文")

        # 将明文转换为4个32位字
        x = [
            (plaintext[0] << 24) | (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3],
            (plaintext[4] << 24) | (plaintext[5] << 16) | (plaintext[6] << 8) | plaintext[7],
            (plaintext[8] << 24) | (plaintext[9] << 16) | (plaintext[10] << 8) | plaintext[11],
            (plaintext[12] << 24) | (plaintext[13] << 16) | (plaintext[14] << 8) | plaintext[15]
        ]

        # 32轮迭代
        for i in range(32):
            x = [x[1], x[2], x[3], self._f_(x[0], x[1], x[2], x[3], self.rk[i])]

        # 反序变换
        ciphertext = [x[3], x[2], x[1], x[0]]

        # 转换为字节数组
        result = bytearray(16)
        for i in range(4):
            result[i * 4] = (ciphertext[i] >> 24) & 0xff
            result[i * 4 + 1] = (ciphertext[i] >> 16) & 0xff
            result[i * 4 + 2] = (ciphertext[i] >> 8) & 0xff
            result[i * 4 + 3] = ciphertext[i] & 0xff

        return result

    def decrypt(self, ciphertext):
        """解密函数，输入16字节密文，返回16字节明文"""
        if len(ciphertext) != 16:
            raise ValueError("SM4解密需要16字节的密文")

        # 解密使用逆序的轮密钥
        reversed_rk = self.rk[::-1]

        # 将密文转换为4个32位字
        x = [
            (ciphertext[0] << 24) | (ciphertext[1] << 16) | (ciphertext[2] << 8) | ciphertext[3],
            (ciphertext[4] << 24) | (ciphertext[5] << 16) | (ciphertext[6] << 8) | ciphertext[7],
            (ciphertext[8] << 24) | (ciphertext[9] << 16) | (ciphertext[10] << 8) | ciphertext[11],
            (ciphertext[12] << 24) | (ciphertext[13] << 16) | (ciphertext[14] << 8) | ciphertext[15]
        ]

        # 32轮迭代
        for i in range(32):
            x = [x[1], x[2], x[3], self._f_(x[0], x[1], x[2], x[3], reversed_rk[i])]

        # 反序变换
        plaintext = [x[3], x[2], x[1], x[0]]

        # 转换为字节数组
        result = bytearray(16)
        for i in range(4):
            result[i * 4] = (plaintext[i] >> 24) & 0xff
            result[i * 4 + 1] = (plaintext[i] >> 16) & 0xff
            result[i * 4 + 2] = (plaintext[i] >> 8) & 0xff
            result[i * 4 + 3] = plaintext[i] & 0xff

        return result


# 使用示例
if __name__ == "__main__":
    # 128位密钥（16字节）
    key = bytearray([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])

    # 128位明文（16字节）
    plaintext = bytearray([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                           0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])

    # 创建SM4实例
    sm4 = SM4(key)

    # 加密
    ciphertext = sm4.encrypt(plaintext)
    print("加密结果:", ciphertext.hex())

    # 解密
    decrypted = sm4.decrypt(ciphertext)
    print("解密结果:", decrypted.hex())
    print("解密结果与明文是否一致:", decrypted == plaintext)
