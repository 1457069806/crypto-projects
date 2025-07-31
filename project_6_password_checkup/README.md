# Google Password Checkup 协议实现说明

## 项目概述
本项目基于论文《On Deploying Secure Computing: Private Intersection-Sum-with-Cardinality》中的Section 3.1协议，实现了一个安全的私有交集-求和协议（Private Intersection-Sum with Cardinality）。该协议允许两方在不泄露各自私有数据的前提下，计算双方标识符集合的交集大小及交集中关联值的总和，可用于密码泄露检查、广告转化归因等隐私保护场景。


## 协议背景
在密码检查场景中，假设存在两方：
- **P1（用户方）**：持有用户标识符集合（如密码哈希）
- **P2（服务方）**：持有泄露的标识符集合及每个标识符的关联值（如泄露次数）

双方希望在不暴露各自完整数据的前提下，计算：
1. 共同标识符的数量（交集大小）
2. 共同标识符关联值的总和（如总泄露次数）


## 核心数学原理

### 1. 椭圆曲线密码学（ECC）
采用NIST256p椭圆曲线，基于以下数学特性：
- 曲线上的点构成加法群，支持点加法和标量乘法
- 离散对数问题（DLP）：已知点`P`和`k*P`，难以求解`k`
- 生成元`G`：曲线上的一个基准点，所有点可表示为`k*G`（`k`为整数）

### 2. Diffie-Hellman风格双掩码机制
协议通过两次标量乘法实现隐私保护：
- 设`k1`为P1的私钥，`k2`为P2的私钥
- 对于标识符`v`，哈希到曲线得点`H(v)`
- P1计算`H(v)^k1 = k1 * H(v)`（第一次掩码）
- P2计算`H(v)^k1^k2 = k2 * (k1 * H(v))`（第二次掩码）

通过双掩码，双方可在本地验证交集，且无法反推对方的原始数据。

### 3. 同态加密（Paillier）
Paillier加密支持加法同态性：
- 加密操作：`Enc(m1) + Enc(m2) = Enc(m1 + m2)`
- 允许P1在不解密的情况下，对P2加密的关联值进行求和
- 最终由P2解密得到交集总和


## 实现步骤

### 步骤1：初始化与参数设置
1. **曲线与密钥生成**：
   - 双方约定使用NIST256p椭圆曲线（生成元`G`，阶`order`）
   - P1生成私钥`k1 ∈ [1, order-1]`
   - P2生成私钥`k2 ∈ [1, order-1]`
   - P2生成Paillier同态加密密钥对`(pk, sk)`

2. **数据准备**：
   - P1准备标识符集合`V = {v1, v2, ..., vm}`
   - P2准备泄露数据`W = {(w1, t1), (w2, t2), ..., (wn, tn)}`（`ti`为关联值）


### 步骤2：第一轮交互（P1 → P2）
1. P1对每个标识符`vi`执行：
   - 哈希到曲线：`H(vi) = hash_to_curve(vi)`（映射为曲线上的点）
   - 标量乘法（第一次掩码）：`H(vi)^k1 = k1 * H(vi)`
2. P1将处理后的点集打乱顺序，发送给P2


### 步骤3：第二轮交互（P2 → P1）
1. P2处理P1的消息：
   - 对标量乘法（第二次掩码）：`H(vi)^k1^k2 = k2 * (k1 * H(vi))`
   - 打乱顺序后形成集合`Z'`

2. P2处理自身数据：
   - 对每个`(wj, tj)`：
     - 哈希到曲线：`H(wj) = hash_to_curve(wj)`
     - 标量乘法：`H(wj)^k2 = k2 * H(wj)`
     - 加密关联值：`Enc(tj) = pk.encrypt(tj)`
   - 形成集合`W' = {(H(wj)^k2, Enc(tj))}`并打乱顺序

3. P2将`Z'`和`W'`发送给P1


### 步骤4：第三轮交互与结果计算
1. P1计算交集：
   - 对`W'`中每个`(H(wj)^k2, Enc(tj))`：
     - 计算`H(wj)^k1^k2 = k1 * (k2 * H(wj))`
     - 若该点在`Z'`中，则属于交集，保留`Enc(tj)`

2. P1计算总和：
   - 对交集中的加密值求和：`SumEnc = sum(Enc(tj))`
   - 重新随机化（添加加密的0）：`SumEnc' = SumEnc + pk.encrypt(0)`
   - 将`SumEnc'`和交集大小发送给P2

3. P2解密结果：
   - 解密总和：`Sum = sk.decrypt(SumEnc')`
   - 获得交集大小和总和


## 代码实现说明

### 核心类与函数

#### 1. 椭圆曲线操作
```python
# 哈希到椭圆曲线（模拟随机预言机）
def hash_to_curve(data):
    while True:
        hash_int = int.from_bytes(hashlib.sha256(data).digest(), byteorder='big')
        hash_int %= order  # 限制在曲线阶范围内
        point = hash_int * generator  # 生成曲线上的点
        return (point.x(), point.y())

# 标量乘法：k * P
def scalar_multiply(point, scalar):
    x, y = point
    point_obj = Point(curve_fp, x, y)
    result_point = scalar * point_obj
    return (result_point.x(), result_point.y())
```

#### 2. 参与方实现
```python
class Party1:
    def step1(self):
        # 计算H(v_i)^k1并打乱
        processed = [scalar_multiply(hash_to_curve(vid), self.k1) 
                   for vid in self.identifiers]
        random.shuffle(processed)
        return processed

    def step3(self, z_prime, w_prime, paillier_pub):
        # 计算交集并求和
        z_set = set(z_prime)
        intersection_enc = [enc_t for h_wj_k2, enc_t in w_prime 
                          if scalar_multiply(h_wj_k2, self.k1) in z_set]
        sum_enc = sum(intersection_enc) + paillier_pub.encrypt(0)  # 重新随机化
        return len(intersection_enc), sum_enc

class Party2:
    def step2(self, p1_msg):
        # 计算Z'和W'
        z_prime = [scalar_multiply(point, self.k2) for point in p1_msg]
        random.shuffle(z_prime)
        w_prime = [(scalar_multiply(hash_to_curve(w), self.k2), self.paillier_pub.encrypt(t))
                 for w, t in self.leaked_data.items()]
        random.shuffle(w_prime)
        return z_prime, w_prime
```


## 运行指南

### 环境依赖
```bash
pip install ecdsa phe  # 椭圆曲线库和Paillier加密库
```

### 执行命令
```bash
python google_password_checkup_protocol.py
```

### 预期输出
```
===== 开始协议测试 =====
[P1初始化] 生成私钥k1
[P2初始化] 生成私钥k2和Paillier密钥对

[协议执行中] 正在进行私有交集计算和求和...

===== 测试结果 =====
输入标识符数量: 3
输入泄露数据数量: 3
实际交集大小: 2 (预期: 2)
交集关联值总和: 12 (预期: 12)
测试结果: 成功
====================
```


## 安全性说明
- **安全模型**：基于半诚实攻击者假设（双方遵循协议但可能尝试推断信息）
- **隐私保护**：通过双掩码机制，双方仅能获取交集大小和总和，无法推断对方的非交集数据
- **完整性**：椭圆曲线点运算和同态加密确保计算结果正确
