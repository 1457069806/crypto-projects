import random
import secrets
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
    d = secrets.randbelow(n - 1) + 1  # 使用secrets模块生成更安全的随机数
    Q = point_mul(d, G)  # 公钥（d*G）
    return d, Q


def compute_ZA(Q, user_id=b"1234567812345678"):
    """计算ZA = SM3(entl || ID || a || b || Gx || Gy || xA || yA)"""
    entl = len(user_id) * 8  # ID长度（位）
    entl_bytes = entl.to_bytes(2, byteorder='big')

    a_bytes = int_to_bytes(a)
    b_bytes = int_to_bytes(b)
    Gx_bytes = int_to_bytes(Gx)
    Gy_bytes = int_to_bytes(Gy)
    xA_bytes = int_to_bytes(Q[0])
    yA_bytes = int_to_bytes(Q[1])

    za_input = entl_bytes + user_id + a_bytes + b_bytes + Gx_bytes + Gy_bytes + xA_bytes + yA_bytes
    return sm3.sm3_hash(func.bytes_to_list(za_input))


def sm2_sign(M, d, user_id=b"1234567812345678"):
    """SM2签名算法"""
    # 计算ZA
    Q = point_mul(d, G)
    ZA = compute_ZA(Q, user_id)

    # 计算e = SM3(ZA || M)
    M_bytes = M.encode('utf-8')
    e_input = bytes.fromhex(ZA) + M_bytes
    e = sm3.sm3_hash(func.bytes_to_list(e_input))
    e_int = bytes_to_int(bytes.fromhex(e))

    # 生成签名(r, s)
    while True:
        k = secrets.randbelow(n - 1) + 1
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

    # 计算ZA
    ZA = compute_ZA(Q, user_id)

    # 计算e
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


def simulate_fake_signature():
    # 1. 生成虚构用户的密钥对（模拟“目标用户”，与任何真实人物无关）
    fake_d, fake_Q = key_generation()
    print(f"【虚构用户】私钥: 0x{fake_d:064x}")
    print(f"【虚构用户】公钥: (0x{fake_Q[0]:064x}, 0x{fake_Q[1]:064x})")

    # 2. 模拟“攻击者获取两次签名及重复使用的k”
    k = secrets.randbelow(n - 1) + 1  # 被重复使用的随机数k（攻击者已知）
    msg1 = "虚构消息1：Hello World"
    msg2 = "虚构消息2：Crypto Demo"

    # 生成两次签名（复用k，模拟用户操作失误）
    sig1 = generate_sign_with_k(msg1, fake_d, k)
    sig2 = generate_sign_with_k(msg2, fake_d, k)
    r1, s1 = sig1
    r2, s2 = sig2
    print(f"\n【签名1】(r={hex(r1)}, s={hex(s1)}) 对应消息: {msg1}")
    print(f"【签名2】(r={hex(r2)}, s={hex(s2)}) 对应消息: {msg2}")

    # 3. 攻击者推导私钥（利用重复k的漏洞）
    numerator = (s2 - s1) % n
    denominator = (s1 - s2 + r1 - r2) % n
    inv_denominator = mod_inverse(denominator, n)
    leaked_d = (numerator * inv_denominator) % n
    print(f"\n【攻击者推导的私钥】: 0x{leaked_d:064x}")
    print(f"【推导正确性验证】: {leaked_d == fake_d}")

    # 4. 攻击者伪造新消息的签名
    fake_msg = "伪造的虚构消息：This is a demo"
    fake_r, fake_s = sm2_sign(fake_msg, leaked_d)  # 用推导的私钥生成签名
    print(f"\n【伪造的签名】(r={hex(fake_r)}, s={hex(fake_s)}) 对应消息: {fake_msg}")

    # 验证伪造签名的有效性（对虚构公钥而言）
    verify_result = sm2_verify(fake_msg, (fake_r, fake_s), fake_Q)
    print(f"【伪造签名验证结果】: {verify_result}")


def generate_sign_with_k(msg, d, k):
    """用指定的k生成签名（模拟k重复使用场景）"""
    Q = point_mul(d, G)
    ZA = compute_ZA(Q)  # 计算ZA值
    msg_bytes = msg.encode('utf-8')
    e_input = bytes.fromhex(ZA) + msg_bytes
    e = sm3.sm3_hash(func.bytes_to_list(e_input))
    e_int = bytes_to_int(bytes.fromhex(e))

    kG = point_mul(k, G)
    x1 = kG[0]
    r = (e_int + x1) % n
    # 确保r合法
    while r == 0 or (r + k) % n == 0:
        k = secrets.randbelow(n - 1) + 1
        kG = point_mul(k, G)
        x1 = kG[0]
        r = (e_int + x1) % n

    s = (mod_inverse((1 + d) % n, n) * (k - r * d)) % n
    s = (s + n) % n  # 确保s为正数
    return (r, s)


if __name__ == "__main__":
    simulate_fake_signature()

