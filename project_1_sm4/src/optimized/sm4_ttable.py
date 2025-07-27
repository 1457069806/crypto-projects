# SM4算法的T-table优化实现
# 基于基础实现，通过预计算T表加速加密过程

import sys
import os

current_path = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_path, "../../../"))

# 检查 project_root 是否存在，且包含 project_1_sm4 目录
if os.path.exists(project_root) and os.path.exists(os.path.join(project_root, "project_1_sm4")):
    print(f"项目根目录有效: {project_root}")
    sys.path.append(project_root)
else:
    # 路径无效时，抛出异常或手动修正
    raise FileNotFoundError(
        f"项目根目录拼接错误！\n"
        f"当前拼接路径: {project_root}\n"
        f"预期应包含 project_1_sm4 目录，请检查 os.path.join 的层级（调整 ../ 的数量）。"
    )

# 继续导入...
from project_1_sm4.src.core.sm4 import SM4
import timeit
import itertools


class SM4_TTable(SM4):
    def __init__(self, key):
        """初始化SM4算法，预计算T表"""
        super().__init__(key)

        # 预计算T表 - 合并S盒变换和线性变换L的结果
        # T表大小为256^4 = 4294967296，内存占用过大，因此采用分阶段计算
        # 这里优化为预计算4个字节的S盒结果，每个字节对应256种可能
        self.T0 = [0] * 256
        self.T1 = [0] * 256
        self.T2 = [0] * 256
        self.T3 = [0] * 256

        self._precompute_tables()

    def _precompute_tables(self):
        """预计算T表，将S盒变换和线性变换L的结果合并存储"""
        for i in range(256):
            # 计算单个字节的S盒变换和线性变换
            s = self.Sbox[i]

            # 计算每个字节位置对应的线性变换结果
            # T0对应最高位字节，T1对应次高位，T2对应次低位，T3对应最低位
            val0 = (s << 24)
            self.T0[i] = self._l_(val0)

            val1 = (s << 16)
            self.T1[i] = self._l_(val1)

            val2 = (s << 8)
            self.T2[i] = self._l_(val2)

            val3 = s
            self.T3[i] = self._l_(val3)

    def _t_optimized(self, x):
        """优化的T函数，使用预计算的T表加速计算"""
        # 将32位输入拆分为4个字节
        b0 = (x >> 24) & 0xff
        b1 = (x >> 16) & 0xff
        b2 = (x >> 8) & 0xff
        b3 = x & 0xff

        # 从T表中获取预计算结果并组合
        return self.T0[b0] ^ self.T1[b1] ^ self.T2[b2] ^ self.T3[b3]

    def _f_(self, x0, x1, x2, x3, rk):
        """优化的轮函数，使用T表加速"""
        return x0 ^ self._t_optimized(x1 ^ x2 ^ x3 ^ rk)


# 性能测试与验证
if __name__ == "__main__":
    # 测试向量（来自GM/T 0002-2012标准）
    key = bytearray([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])

    plaintext = bytearray([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                           0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])

    # 标准密文结果
    expected_ciphertext = "681edf34d206965e86b3e94f536e4246"

    # 创建基础实现和优化实现的实例
    sm4_base = SM4(key)
    sm4_ttable = SM4_TTable(key)

    # 验证正确性
    ciphertext_base = sm4_base.encrypt(plaintext)
    ciphertext_ttable = sm4_ttable.encrypt(plaintext)

    print("基础实现加密结果:", ciphertext_base.hex())
    print("T-table优化加密结果:", ciphertext_ttable.hex())
    print("加密结果一致:", ciphertext_base.hex() == ciphertext_ttable.hex())

    # 解密验证
    decrypted_ttable = sm4_ttable.decrypt(ciphertext_ttable)
    print("解密结果与明文一致:", decrypted_ttable == plaintext)


    # 性能测试
    def test_base():
        sm4_base.encrypt(plaintext)


    def test_ttable():
        sm4_ttable.encrypt(plaintext)


    # 执行多次测试以获得更准确的结果
    iterations = 10000
    time_base = timeit.timeit(test_base, number=iterations)
    time_ttable = timeit.timeit(test_ttable, number=iterations)

    print(f"\n性能测试（{iterations}次加密）:")
    print(f"基础实现耗时: {time_base:.4f}秒")
    print(f"T-table优化实现耗时: {time_ttable:.4f}秒")
    print(f"优化后速度提升: {time_base / time_ttable:.2f}倍")
