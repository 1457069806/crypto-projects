import ctypes
import os
import timeit


# 加载共享库
class SM4_ISA:
    def __init__(self, key):
        # 确保密钥长度正确
        if len(key) != 16:
            raise ValueError("SM4密钥必须是16字节")

        self.key = key

        # 加载C扩展库
        current_dir = os.path.dirname(os.path.abspath(__file__))
        lib_path = os.path.join(current_dir, "sm4_isa.so")  # Linux
        if not os.path.exists(lib_path):
            lib_path = os.path.join(current_dir, "sm4_isa.dll")  # Windows

        try:
            self.lib = ctypes.CDLL(lib_path)
        except OSError:
            raise RuntimeError("无法加载SM4指令集优化库，请先编译")

        # 检查CPU指令集支持
        self.lib.check_isa_support.restype = ctypes.c_int
        if not self.lib.check_isa_support():
            raise RuntimeError("当前CPU不支持AESNI、GFNI或VPROLD指令集")

        # 设置函数参数和返回类型
        self.lib.sm4_encrypt_aesni.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte)
        ]

    def encrypt(self, plaintext):
        if len(plaintext) != 16:
            raise ValueError("SM4加密需要16字节的明文")

        ciphertext = bytearray(16)

        # 转换为C类型的指针
        key_ptr = (ctypes.c_ubyte * 16).from_buffer(self.key)
        plaintext_ptr = (ctypes.c_ubyte * 16).from_buffer(plaintext)
        ciphertext_ptr = (ctypes.c_ubyte * 16).from_buffer(ciphertext)

        # 调用加密函数
        self.lib.sm4_encrypt_aesni(key_ptr, plaintext_ptr, ciphertext_ptr)

        return ciphertext


# 编译和测试辅助函数
def compile_library():
    """编译C代码为共享库（需要GCC或MSVC）"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    source_path = os.path.join(current_dir, "sm4_isa.c")

    if os.name == "nt":  # Windows
        # 使用MSVC编译
        cmd = f"cl /LD {source_path} /Fe:sm4_isa.dll"
    else:  # Linux/macOS
        # 使用GCC编译，需要支持AVX2和GFNI
        cmd = f"gcc -shared -fPIC -O3 -march=native {source_path} -o sm4_isa.so"

    print(f"编译命令: {cmd}")
    os.system(cmd)


# 性能测试与验证
if __name__ == "__main__":
    # 先编译共享库
    compile_library()

    # 测试向量
    key = bytearray([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])

    plaintext = bytearray([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                           0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])

    # 创建实例
    try:
        sm4_isa = SM4_ISA(key)

        # 验证加密
        ciphertext = sm4_isa.encrypt(plaintext)
        print("ISA优化加密结果:", ciphertext.hex())


        # 性能测试
        def test_isa():
            sm4_isa.encrypt(plaintext)


        iterations = 100000
        time_isa = timeit.timeit(test_isa, number=iterations)
        print(f"\nISA优化实现（{iterations}次加密）耗时: {time_isa:.4f}秒")

    except Exception as e:
        print(f"测试失败: {str(e)}")
