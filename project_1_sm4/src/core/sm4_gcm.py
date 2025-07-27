import sys
import os
import timeit
from math import ceil

# 确保项目根目录在Python路径中
current_path = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_path, "../../../"))
sys.path.append(project_root)

from project_1_sm4.src.optimized.sm4_ttable import SM4_TTable


class SM4_GCM:
    """
    SM4-GCM认证加密模式实现
    结合了CTR模式的加密和GHASH函数的认证
    """

    def __init__(self, key, nonce=None, tag_length=16):
        """
        初始化SM4-GCM实例

        参数:
            key: 16字节的SM4密钥
            nonce: 可选的随机数，推荐12字节
            tag_length: 认证标签长度(4-16字节)
        """
        if len(key) != 16:
            raise ValueError("SM4密钥必须是16字节")

        if tag_length < 4 or tag_length > 16 or tag_length % 4 != 0:
            raise ValueError("标签长度必须是4-16字节且为4的倍数")

        self.tag_length = tag_length
        self.sm4 = SM4_TTable(key)  # 使用T-table优化的SM4实现

        # 生成哈希子密钥H
        self.H = self.sm4.encrypt(bytearray(16))

        # 处理nonce
        if nonce is None:
            self.nonce = os.urandom(12)  # 默认12字节nonce
        else:
            self.nonce = nonce
            if len(self.nonce) < 1:
                raise ValueError("nonce长度不能为0")

        # 生成初始计数器
        self.initial_counter = self._generate_initial_counter()

    def _generate_initial_counter(self):
        """生成初始计数器值"""
        if len(self.nonce) == 12:
            # 对于12字节nonce，按照推荐方式生成计数器
            counter = bytearray(16)
            counter[:12] = self.nonce
            counter[15] = 1  # 设置初始计数器为1
            return counter
        else:
            # 对于其他长度nonce，使用GHASH生成计数器
            return self._ghash(self.nonce, bytearray(0))

    def _ghash(self, aad, ciphertext):
        """
        GHASH函数实现 - 用于计算认证标签

        参数:
            aad: 附加认证数据
            ciphertext: 密文
        """
        # 计算AAD和密文的长度(位)
        len_aad = len(aad) * 8
        len_ciphertext = len(ciphertext) * 8

        # 填充AAD到16字节倍数
        padded_aad = aad + bytearray((16 - (len(aad) % 16)) % 16)

        # 填充密文到16字节倍数
        padded_ciphertext = ciphertext + bytearray((16 - (len(ciphertext) % 16)) % 16)

        # 组合数据
        data = padded_aad + padded_ciphertext

        # 添加长度块(64位AAD长度 + 64位密文长度)
        len_block = bytearray(16)
        len_block[8:12] = len_aad.to_bytes(4, byteorder='big')
        len_block[12:16] = len_ciphertext.to_bytes(4, byteorder='big')
        data += len_block

        # 初始化哈希值
        hash_value = bytearray(16)

        # 预计算H的高、低64位用于GHASH优化
        h_low = int.from_bytes(self.H[:8], byteorder='big')
        h_high = int.from_bytes(self.H[8:], byteorder='big')

        # 处理每个16字节块
        for i in range(0, len(data), 16):
            block = data[i:i + 16]

            # 将块转换为两个64位整数
            x_low = int.from_bytes(block[:8], byteorder='big')
            x_high = int.from_bytes(block[8:], byteorder='big')

            # 将哈希值转换为两个64位整数
            y_low = int.from_bytes(hash_value[:8], byteorder='big')
            y_high = int.from_bytes(hash_value[8:], byteorder='big')

            # 异或操作
            xor_low = x_low ^ y_low
            xor_high = x_high ^ y_high

            # 伽罗瓦域乘法优化实现 (GF(2^128))
            product_low, product_high = self._gf128_mul(xor_low, xor_high, h_low, h_high)

            # 更新哈希值
            hash_value[:8] = product_high.to_bytes(8, byteorder='big')
            hash_value[8:] = product_low.to_bytes(8, byteorder='big')

        return hash_value

    def _gf128_mul(self, x_low, x_high, h_low, h_high):
        """
        伽罗瓦域GF(2^128)乘法优化实现
        返回两个64位整数 (低64位, 高64位)
        """
        # 多项式约简使用的不可约多项式: x^128 + x^7 + x^2 + x + 1
        REDUCTION_POLY = 0x87  # x^7 + x^2 + x + 1

        def clmul(a, b):
            """模拟Pclmulqdq指令的64位乘法"""
            result = 0
            a &= 0xFFFFFFFFFFFFFFFF  # 确保是64位
            b &= 0xFFFFFFFFFFFFFFFF
            for i in range(64):
                if (b >> i) & 1:
                    result ^= a << i
            # 返回高64位和低64位
            return (result >> 64) & 0xFFFFFFFFFFFFFFFF, result & 0xFFFFFFFFFFFFFFFF

        # 分解乘法为四个64位乘法 (x = x_high || x_low, h = h_high || h_low)
        # (x_high*h_high) << 128 | (x_high*h_low + x_low*h_high) << 64 | x_low*h_low
        t0_high, t0_low = clmul(x_low, h_low)  # x_low * h_low
        t1_high, t1_low = clmul(x_low, h_high)  # x_low * h_high
        t2_high, t2_low = clmul(x_high, h_low)  # x_high * h_low
        t3_high, t3_low = clmul(x_high, h_high)  # x_high * h_high

        # 组合结果，得到256位中间结果的四个64位部分
        z0 = t0_low
        z1 = t0_high ^ t1_low ^ t2_low
        z2 = t1_high ^ t2_high ^ t3_low
        z3 = t3_high

        # 多项式约简 - 将256位结果约简为128位
        # 处理z3 (最高64位)
        for i in range(63, -1, -1):
            if (z3 >> i) & 1:
                # 计算移位量
                shift = i + 64  # z3是从位192-255
                if shift >= 128:
                    shift -= 128
                    z1 ^= REDUCTION_POLY << shift
                else:
                    z0 ^= REDUCTION_POLY << shift

        # 处理z2中高于128位的部分
        for i in range(63, -1, -1):
            if (z2 >> i) & 1:
                shift = i
                if shift >= 128:
                    shift -= 128
                    z1 ^= REDUCTION_POLY << shift
                elif shift >= 64:
                    shift -= 64
                    z1 ^= REDUCTION_POLY << shift
                else:
                    z0 ^= REDUCTION_POLY << shift

        # 最终结果限制在128位，分为高低两个64位部分
        result_high = z2 & 0xFFFFFFFFFFFFFFFF
        result_low = z0 & 0xFFFFFFFFFFFFFFFF

        return result_low, result_high

    def _increment_counter(self, counter):
        """计数器加1 (大端序)"""
        # 从最后一个字节开始递增
        for i in range(15, -1, -1):
            counter[i] += 1
            if counter[i] != 0:  # 没有进位，完成
                break
        return counter

    def encrypt_and_tag(self, plaintext, aad=b''):
        """
        加密明文并生成认证标签

        参数:
            plaintext: 要加密的明文
            aad: 附加认证数据(不加密但参与认证)

        返回:
            (ciphertext, tag): 密文和认证标签
        """
        # 初始化计数器
        counter = bytearray(self.initial_counter)

        # 计算密文块数
        num_blocks = ceil(len(plaintext) / 16)
        ciphertext = bytearray()

        # CTR模式加密
        for i in range(num_blocks):
            # 加密计数器值得到密钥流
            keystream = self.sm4.encrypt(counter)

            # 递增计数器
            self._increment_counter(counter)

            # 处理当前块
            start = i * 16
            end = start + 16
            block = plaintext[start:end]

            # 与密钥流异或得到密文
            ciphertext_block = bytearray(len(block))
            for j in range(len(block)):
                ciphertext_block[j] = block[j] ^ keystream[j]

            ciphertext.extend(ciphertext_block)

        # 计算认证标签
        tag = self._ghash(aad, ciphertext)

        # 用初始计数器加密标签进行掩码操作
        tag_mask = self.sm4.encrypt(self.initial_counter)
        masked_tag = bytearray(self.tag_length)
        for i in range(self.tag_length):
            masked_tag[i] = tag[i] ^ tag_mask[i]

        return ciphertext, masked_tag

    def decrypt_and_verify(self, ciphertext, tag, aad=b''):
        """
        解密密文并验证认证标签

        参数:
            ciphertext: 要解密的密文
            tag: 要验证的认证标签
            aad: 附加认证数据

        返回:
            plaintext: 解密后的明文

        异常:
            ValueError: 标签验证失败
        """
        if len(tag) != self.tag_length:
            raise ValueError("标签长度不匹配")

        # 验证标签
        computed_tag = self._ghash(aad, ciphertext)
        tag_mask = self.sm4.encrypt(self.initial_counter)

        masked_tag = bytearray(self.tag_length)
        for i in range(self.tag_length):
            masked_tag[i] = computed_tag[i] ^ tag_mask[i]

        # 常数时间比较防止时序攻击
        if not self._constant_time_compare(tag, masked_tag):
            raise ValueError("标签验证失败，数据可能被篡改或密钥不正确")

        # 初始化计数器
        counter = bytearray(self.initial_counter)

        # 计算明文块数
        num_blocks = ceil(len(ciphertext) / 16)
        plaintext = bytearray()

        # CTR模式解密(与加密相同)
        for i in range(num_blocks):
            # 加密计数器值得到密钥流
            keystream = self.sm4.encrypt(counter)

            # 递增计数器
            self._increment_counter(counter)

            # 处理当前块
            start = i * 16
            end = start + 16
            block = ciphertext[start:end]

            # 与密钥流异或得到明文
            plaintext_block = bytearray(len(block))
            for j in range(len(block)):
                plaintext_block[j] = block[j] ^ keystream[j]

            plaintext.extend(plaintext_block)

        return plaintext

    @staticmethod
    def _constant_time_compare(a, b):
        """常数时间比较函数，防止时序攻击"""
        if len(a) != len(b):
            return False

        result = 0
        for x, y in zip(a, b):
            result |= x ^ y

        return result == 0


# 测试与性能评估
if __name__ == "__main__":
    # 测试向量
    key = bytearray([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])

    nonce = bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b])

    # 使用ASCII字符作为测试数据
    plaintext = "This is a test of SM4-GCM mode, used to verify encryption and authentication functions.".encode(
        'utf-8')
    aad = "Additional authenticated data".encode('utf-8')

    # 创建GCM实例
    gcm = SM4_GCM(key, nonce)

    # 加密
    ciphertext, tag = gcm.encrypt_and_tag(plaintext, aad)
    print("加密完成:")
    print(f"密文: {ciphertext.hex()}")
    print(f"认证标签: {tag.hex()}")

    # 解密与验证
    try:
        decrypted = gcm.decrypt_and_verify(ciphertext, tag, aad)
        print("\n解密完成:")
        print(f"明文: {decrypted.decode('utf-8')}")
        print(f"解密结果正确: {decrypted == plaintext}")
    except ValueError as e:
        print(f"解密失败: {e}")


    # 性能测试
    def test_encrypt():
        gcm.encrypt_and_tag(plaintext, aad)


    def test_decrypt():
        gcm.decrypt_and_verify(ciphertext, tag, aad)


    iterations = 1000
    encrypt_time = timeit.timeit(test_encrypt, number=iterations)
    decrypt_time = timeit.timeit(test_decrypt, number=iterations)

    print(f"\n性能测试（{iterations}次）:")
    print(f"加密平均耗时: {(encrypt_time / iterations) * 1000:.4f}毫秒")
    print(f"解密平均耗时: {(decrypt_time / iterations) * 1000:.4f}毫秒")
