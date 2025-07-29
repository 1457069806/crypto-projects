import struct

# SM3常量定义
IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]

T = [0x79CC4519] * 16 + [0x7A879D8A] * 48


def rotate_left(x, n):
    """循环左移n位"""
    n = n % 32
    return ((x << n) & 0xFFFFFFFF) | ((x >> (32 - n)) & 0xFFFFFFFF)


def P0(x):
    """置换函数P0"""
    return x ^ rotate_left(x, 9) ^ rotate_left(x, 17)


def P1(x):
    """置换函数P1"""
    return x ^ rotate_left(x, 15) ^ rotate_left(x, 23)


def FF_j(x, y, z, j):
    """布尔函数FF_j"""
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:  # 16 <= j <= 63
        return (x & y) | (x & z) | (y & z)


def GG_j(x, y, z, j):
    """布尔函数GG_j"""
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:  # 16 <= j <= 63
        return (x & y) | ((~x) & z)


def fill_message(message):
    """消息填充，严格按照SM3标准实现"""
    # 转换消息为字节数组
    if isinstance(message, str):
        message = message.encode()
    length_bits = len(message) * 8  # 消息长度(比特)

    # 创建填充后的消息字节数组
    padded = bytearray(message)

    # 填充1位'1'
    padded.append(0x80)

    # 填充0位，直到长度模512等于448
    current_length_bits = len(padded) * 8
    remaining_bits = (448 - current_length_bits) % 512
    if remaining_bits < 0:
        remaining_bits += 512
    zeros_needed = remaining_bits // 8
    padded.extend(b'\x00' * zeros_needed)

    # 填充消息长度(64位，大端模式)
    padded.extend(struct.pack('>Q', length_bits))

    # 验证填充后的长度是否正确
    assert len(padded) * 8 % 512 == 0, "消息填充错误，长度不是512的倍数"
    return padded


def message_extension(B):
    """消息扩展"""
    W = []
    # 将512比特的消息块分为16个32比特字
    for i in range(16):
        W.append(struct.unpack('>I', B[i * 4:(i + 1) * 4])[0])

    # 扩展生成W[16]~W[67]
    for j in range(16, 68):
        val = P1(W[j - 16] ^ W[j - 9] ^ rotate_left(W[j - 3], 15)) ^ rotate_left(W[j - 13], 7) ^ W[j - 6]
        W.append(val & 0xFFFFFFFF)

    # 生成W'[0]~W'[63]
    W_prime = []
    for j in range(64):
        W_prime.append(W[j] ^ W[j + 4])

    return W, W_prime


def compression_function(V, B):
    """压缩函数"""
    # 消息扩展
    W, W_prime = message_extension(B)

    # 初始化寄存器
    A, B_reg, C, D, E, F, G, H = V

    # 64轮迭代
    for j in range(64):
        T_j_rot = rotate_left(T[j], j)
        SS1 = rotate_left((rotate_left(A, 12) + E + T_j_rot) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ rotate_left(A, 12)
        TT1 = (FF_j(A, B_reg, C, j) + D + SS2 + W_prime[j]) & 0xFFFFFFFF
        TT2 = (GG_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF

        # 更新寄存器
        D = C
        C = rotate_left(B_reg, 9)
        B_reg = A
        A = TT1
        H = G
        G = rotate_left(F, 19)
        F = E
        E = P0(TT2)

    # 压缩结果与初始值异或
    new_V = [
        A ^ V[0], B_reg ^ V[1], C ^ V[2], D ^ V[3],
        E ^ V[4], F ^ V[5], G ^ V[6], H ^ V[7]
    ]

    return new_V


def sm3_hash(message):
    """计算SM3哈希值"""
    # 消息填充
    padded_message = fill_message(message)

    # 初始化向量
    V = IV.copy()

    # 按512比特分组处理消息
    for i in range(0, len(padded_message), 64):  # 64字节 = 512比特
        B = padded_message[i:i + 64]
        V = compression_function(V, B)

    # 将结果转换为十六进制字符串
    hash_hex = ''.join(f'{word:08x}' for word in V)
    return hash_hex


# 测试
if __name__ == "__main__":
    test_messages = [
        "abc",
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    ]

    expected_hashes = [
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
    ]

    for msg, expected in zip(test_messages, expected_hashes):
        result = sm3_hash(msg)
        print(f"消息: {repr(msg)}")
        print(f"哈希值: {result}")
        print(f"预期值: {expected}")
        print(f"验证: {'成功' if result == expected else '失败'}")
        print()
