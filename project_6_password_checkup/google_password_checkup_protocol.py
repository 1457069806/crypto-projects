import hashlib
import random
from ecdsa import NIST256p
from ecdsa.ellipticcurve import Point
from phe import paillier

# 椭圆曲线配置（NIST256p）
curve = NIST256p
curve_fp = curve.curve
generator = curve.generator
order = curve.order


def hash_to_curve(data):
    """将输入哈希到椭圆曲线上的点"""
    while True:
        try:
            hash_int = int.from_bytes(hashlib.sha256(data).digest(), byteorder='big')
            hash_int %= order
            point = hash_int * generator
            return (point.x(), point.y())
        except:
            data += b'_' + random.getrandbits(128).to_bytes(16, byteorder='big')


def scalar_multiply(point, scalar):
    """椭圆曲线点标量乘法：k * P"""
    x, y = point
    point_obj = Point(curve_fp, x, y)
    result_point = scalar * point_obj
    return (result_point.x(), result_point.y())


class Party1:
    def __init__(self):
        self.k1 = random.getrandbits(256) % order
        self.identifiers = set()
        print(f"[P1初始化] 生成私钥k1")

    def add_identifier(self, identifier):
        self.identifiers.add(identifier.encode('utf-8'))

    def step1(self):
        processed = []
        for vid in self.identifiers:
            h_vid = hash_to_curve(vid)
            h_vid_k1 = scalar_multiply(h_vid, self.k1)
            processed.append(h_vid_k1)
        random.shuffle(processed)
        return processed

    def step3(self, z_prime, w_prime, paillier_pub):
        z_set = set(z_prime)
        intersection_enc = []

        for h_wj_k2, enc_t in w_prime:
            h_wj_k1k2 = scalar_multiply(h_wj_k2, self.k1)
            if h_wj_k1k2 in z_set:
                intersection_enc.append(enc_t)

        size = len(intersection_enc)
        sum_enc = None
        if size > 0:
            sum_enc = sum(intersection_enc)
            # 用加密零实现重新随机化
            zero_enc = paillier_pub.encrypt(0)
            sum_enc = sum_enc + zero_enc
        return size, sum_enc


class Party2:
    def __init__(self):
        self.k2 = random.getrandbits(256) % order
        self.leaked_data = {}
        self.paillier_pub, self.paillier_priv = paillier.generate_paillier_keypair()
        print(f"[P2初始化] 生成私钥k2和Paillier密钥对")

    def add_leaked(self, identifier, value):
        self.leaked_data[identifier.encode('utf-8')] = value

    def get_paillier_pub(self):
        return self.paillier_pub

    def step2(self, p1_msg):
        z_prime = [scalar_multiply(point, self.k2) for point in p1_msg]
        random.shuffle(z_prime)

        w_prime = []
        for w, t in self.leaked_data.items():
            h_wj = hash_to_curve(w)
            h_wj_k2 = scalar_multiply(h_wj, self.k2)
            enc_t = self.paillier_pub.encrypt(t)
            w_prime.append((h_wj_k2, enc_t))
        random.shuffle(w_prime)

        return z_prime, w_prime

    def decrypt_sum(self, encrypted_sum):
        return self.paillier_priv.decrypt(encrypted_sum) if encrypted_sum else 0


# 测试协议
def test_protocol():
    print("===== 开始协议测试 =====")

    # 初始化参与方
    p1 = Party1()
    p2 = Party2()

    # 测试输入数据
    test_identifiers = ["user_hash2", "user_hash3", "user_hash4"]
    test_leaked = [("user_hash2", 5), ("user_hash3", 7), ("leaked_hash1", 3)]

    # 添加测试数据
    for identifier in test_identifiers:
        p1.add_identifier(identifier)
    for identifier, value in test_leaked:
        p2.add_leaked(identifier, value)

    print("\n[协议执行中] 正在进行私有交集计算和求和...\n")

    # 执行协议
    p1_msg = p1.step1()
    z_prime, w_prime = p2.step2(p1_msg)
    size, sum_enc = p1.step3(z_prime, w_prime, p2.get_paillier_pub())
    total = p2.decrypt_sum(sum_enc)

    # 输出结果
    print("===== 测试结果 =====")
    print(f"输入标识符数量: {len(test_identifiers)}")
    print(f"输入泄露据数量: {len(test_leaked)}")
    print(f"实际交集大小: {size} (预期: 2)")
    print(f"交集关联值总和: {total} (预期: 12)")
    print("测试结果: " + ("成功" if size == 2 and total == 12 else "失败"))
    print("====================")


if __name__ == "__main__":
    test_protocol()
