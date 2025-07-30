import random
from gmssl import sm3, func

# SM2推荐曲线参数
p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
G = (Gx, Gy)


def bytes_to_int(b):
    """字节串转整数"""
    return int.from_bytes(b, byteorder='big')


def int_to_bytes(i):
    """整数转32字节串"""
    return i.to_bytes(32, byteorder='big')


def mod_inverse(a, p):
    """模逆运算"""
    return pow(a, p - 2, p)


def point_add(p1, p2):
    """椭圆曲线点加法"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    # 无穷远点判断
    if x1 == x2 and y1 != y2:
        return None

    # 计算斜率
    if x1 != x2:
        lam = ((y2 - y1) * mod_inverse((x2 - x1) % p, p)) % p
    else:
        lam = ((3 * x1 ** 2 + a) * mod_inverse((2 * y1) % p, p)) % p

    # 计算相加结果
    x3 = (lam ** 2 - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p

    return (x3, y3)


def point_mul(k, p):
    """椭圆曲线点乘法（倍点加法实现）"""
    result = None
    current = p
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k = k // 2
    return result


def key_generation():
    """生成SM2密钥对"""
    d = random.randint(1, n - 2)  # 私钥
    Q = point_mul(d, G)  # 公钥（d*G）
    return d, Q


def kdf(z, klen):
    """密钥派生函数"""
    klen = int(klen)
    if klen <= 0:
        return b''

    ct = 1
    rcnt = (klen + 31) // 32  # 计算迭代次数
    zin = z
    ha = []

    for _ in range(rcnt):
        # 每次迭代输入：z + 4字节计数器
        ct_bytes = ct.to_bytes(4, byteorder='big')
        msg = zin + ct_bytes
        # SM3哈希
        hash_val = sm3.sm3_hash(func.bytes_to_list(msg))
        ha.append(hash_val)
        ct += 1

    # 合并哈希结果并截断到指定长度
    h = ''.join(ha)
    return bytes.fromhex(h)[:klen]


def is_on_curve(point):
    """验证点是否在椭圆曲线上"""
    x, y = point
    left = (y * y) % p
    right = (x * x * x + a * x + b) % p
    return left == right


def sm2_encrypt(M, Q):
    """SM2加密算法"""
    # 消息转字节
    M_bytes = M.encode('utf-8')
    msg_len = len(M_bytes)

    # 生成随机数k并计算C1 = k*G
    k = random.randint(1, n - 1)
    C1 = point_mul(k, G)
    if C1 is None:
        raise ValueError("生成C1失败")

    # 计算k*Q得到(x2, y2)
    kQ = point_mul(k, Q)
    if kQ is None:
        raise ValueError("计算k*Q失败")
    x2, y2 = kQ
    x2_bytes = int_to_bytes(x2)
    y2_bytes = int_to_bytes(y2)

    # 密钥派生
    t = kdf(x2_bytes + y2_bytes, msg_len)
    if all(b == 0 for b in t):
        raise ValueError("KDF生成的t全为0")

    # 计算C2 = M ^ t
    C2 = bytes([a ^ b for a, b in zip(M_bytes, t)])

    # 计算C3 = SM3(x2 || M || y2)
    hash_input = x2_bytes + M_bytes + y2_bytes
    C3 = sm3.sm3_hash(func.bytes_to_list(hash_input))

    # 拼接密文：C1 || C3 || C2
    C1_bytes = int_to_bytes(C1[0]) + int_to_bytes(C1[1])
    return C1_bytes + bytes.fromhex(C3) + C2


def sm2_decrypt(C, d):
    """SM2解密算法"""
    # 解析密文组成部分
    c1_len = 64  # C1占64字节（x和y各32字节）
    c3_len = 32  # C3占32字节（SM3哈希结果）

    if len(C) < c1_len + c3_len:
        raise ValueError("密文长度不足")

    C1_bytes = C[:c1_len]
    C3_bytes = C[c1_len:c1_len + c3_len]
    C2_bytes = C[c1_len + c3_len:]
    c2_len = len(C2_bytes)

    # 解析C1点并验证是否在曲线上
    x1 = bytes_to_int(C1_bytes[:32])
    y1 = bytes_to_int(C1_bytes[32:])
    if not is_on_curve((x1, y1)):
        raise ValueError("C1不在曲线上")

    # 计算d*C1得到(x2, y2)
    dC1 = point_mul(d, (x1, y1))
    if dC1 is None:
        raise ValueError("计算d*C1失败")
    x2, y2 = dC1
    x2_bytes = int_to_bytes(x2)
    y2_bytes = int_to_bytes(y2)

    # 密钥派生
    t = kdf(x2_bytes + y2_bytes, c2_len)

    # 计算M' = C2 ^ t
    M_prime = bytes([a ^ b for a, b in zip(C2_bytes, t)])

    # 验证哈希值
    hash_input = x2_bytes + M_prime + y2_bytes
    u = sm3.sm3_hash(func.bytes_to_list(hash_input))
    u_bytes = bytes.fromhex(u)

    if u_bytes != C3_bytes:
        raise ValueError("解密失败：哈希验证不通过")

    return M_prime.decode('utf-8')


def sm2_sign(M, d, user_id=b"1234567812345678"):
    """SM2签名算法"""
    # 计算ZA = SM3(entl || ID || a || b || Gx || Gy || xA || yA)
    entl = len(user_id) * 8  # ID长度（位）
    entl_bytes = entl.to_bytes(2, byteorder='big')

    a_bytes = int_to_bytes(a)
    b_bytes = int_to_bytes(b)
    Gx_bytes = int_to_bytes(Gx)
    Gy_bytes = int_to_bytes(Gy)
    Q = point_mul(d, G)
    xA_bytes = int_to_bytes(Q[0])
    yA_bytes = int_to_bytes(Q[1])

    za_input = entl_bytes + user_id + a_bytes + b_bytes + Gx_bytes + Gy_bytes + xA_bytes + yA_bytes
    ZA = sm3.sm3_hash(func.bytes_to_list(za_input))

    # 计算e = SM3(ZA || M)
    M_bytes = M.encode('utf-8')
    e_input = bytes.fromhex(ZA) + M_bytes
    e = sm3.sm3_hash(func.bytes_to_list(e_input))
    e_int = bytes_to_int(bytes.fromhex(e))

    # 生成签名(r, s)
    while True:
        k = random.randint(1, n - 1)
        kG = point_mul(k, G)
        if kG is None:
            continue
        x1 = kG[0]
        r = (e_int + x1) % n
        if r != 0 and (r + k) % n != 0:
            break

    s = (mod_inverse((1 + d) % n, n) * (k - r * d)) % n
    s = (s + n) % n  # 确保s为正数
    return (r, s)


def sm2_verify(M, signature, Q, user_id=b"1234567812345678"):
    """SM2验签算法"""
    r, s = signature
    # 验证r和s的范围
    if r < 1 or r >= n or s < 1 or s >= n:
        return False

    # 计算ZA（与签名过程相同）
    entl = len(user_id) * 8
    entl_bytes = entl.to_bytes(2, byteorder='big')

    a_bytes = int_to_bytes(a)
    b_bytes = int_to_bytes(b)
    Gx_bytes = int_to_bytes(Gx)
    Gy_bytes = int_to_bytes(Gy)
    xA_bytes = int_to_bytes(Q[0])
    yA_bytes = int_to_bytes(Q[1])

    za_input = entl_bytes + user_id + a_bytes + b_bytes + Gx_bytes + Gy_bytes + xA_bytes + yA_bytes
    ZA = sm3.sm3_hash(func.bytes_to_list(za_input))

    # 计算e（与签名过程相同）
    M_bytes = M.encode('utf-8')
    e_input = bytes.fromhex(ZA) + M_bytes
    e = sm3.sm3_hash(func.bytes_to_list(e_input))
    e_int = bytes_to_int(bytes.fromhex(e))

    # 验证签名
    t = (r + s) % n
    if t == 0:
        return False

    sG = point_mul(s, G)
    tQ = point_mul(t, Q)
    x1y1 = point_add(sG, tQ)
    if x1y1 is None:
        return False
    x1, _ = x1y1

    R = (e_int + x1) % n
    return R == r


# 测试代码
if __name__ == "__main__":
    # 生成密钥对
    d, Q = key_generation()
    print(f"私钥 d: 0x{d:064x}")
    print(f"公钥 Q: (0x{Q[0]:064x}, 0x{Q[1]:064x})")

    # 测试加密解密
    message = "这是一个SM2算法的测试消息"
    print(f"\n原始消息: {message}")

    try:
        ciphertext = sm2_encrypt(message, Q)
        print(f"加密后: {ciphertext.hex()}")

        decrypted_message = sm2_decrypt(ciphertext, d)
        print(f"解密后: {decrypted_message}")
        print(f"解密验证: {message == decrypted_message}")
    except Exception as e:
        print(f"加解密过程出错: {e}")

    # 测试签名验签
    try:
        signature = sm2_sign(message, d)
        print(f"\n签名: (0x{signature[0]:064x}, 0x{signature[1]:064x})")

        verify_result = sm2_verify(message, signature, Q)
        print(f"验签结果: {verify_result}")

        tampered_message = "这是一个被篡改的消息"
        verify_tampered = sm2_verify(tampered_message, signature, Q)
        print(f"篡改消息验签结果: {verify_tampered}")
    except Exception as e:
        print(f"签名验签过程出错: {e}")
