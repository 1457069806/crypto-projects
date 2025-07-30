# SM2签名算法漏洞验证与模拟实验

## 项目概述
本项目旨在通过技术模拟，验证SM2椭圆曲线公钥密码算法的核心原理及潜在安全漏洞。主要包含三个核心步骤：
1. **SM2算法核心实现**：实现密钥生成、签名、验签等基础功能
2. **PoC验证**：验证"重复使用随机数k"导致的私钥泄露漏洞
3. **虚构场景签名伪造**：基于漏洞原理，在纯虚构场景下模拟签名伪造（**注：所有数据与真实人物/系统无关**）

**伦理与法律声明**：本项目仅用于密码学技术研究，所有实验基于虚构数据，严禁用于任何非法用途。伪造真实实体的数字签名可能违反《网络安全法》《刑法》等法律法规，需承担相应法律责任。


## 环境准备
- **依赖库**：`gmssl`（提供SM3哈希算法）、`secrets`（加密安全随机数生成）
- **运行环境**：Python 3.8+
- **安装命令**：`pip install gmssl`


## 一、SM2算法核心实现

### 1.1 椭圆曲线参数定义
SM2采用256位素数域椭圆曲线，参数如下（符合国家标准）：
```python
p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3  # 素数域
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498      # 曲线参数a
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A      # 曲线参数b
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7      # 曲线阶数
Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D  # 基点x坐标
Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2  # 基点y坐标
G = (Gx, Gy)  # 椭圆曲线基点
```
曲线方程：$y^2 \equiv x^3 + ax + b \mod p$


### 1.2 核心数学运算实现

#### 1.2.1 模逆运算
基于费马小定理（$a^{p-2} \equiv a^{-1} \mod p$，适用于素数域）：
```python
def mod_inverse(a, p):
    return pow(a, p - 2, p)
```

#### 1.2.2 椭圆曲线点加法
已知曲线上两点$P=(x_1,y_1)$和$Q=(x_2,y_2)$，计算$P+Q=(x_3,y_3)$：
```python
def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    
    # 处理特殊情况（无穷远点）
    if x1 == x2 and y1 != y2:
        return None  # P + (-P) = 无穷远点
    
    # 计算斜率λ
    if x1 != x2:
        lam = ((y2 - y1) * mod_inverse((x2 - x1) % p, p)) % p
    else:
        # 同点加倍（P=Q时）
        lam = ((3 * x1**2 + a) * mod_inverse((2 * y1) % p, p)) % p
    
    # 计算相加结果
    x3 = (lam**2 - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)
```
**数学原理**：
- 不同点：$\lambda = (y_2 - y_1)/(x_2 - x_1)$，$x_3 = \lambda^2 - x_1 - x_2$，$y_3 = \lambda(x_1 - x_3) - y_1$
- 同点加倍：$\lambda = (3x_1^2 + a)/(2y_1)$，$x_3, y_3$计算同上


#### 1.2.3 椭圆曲线点乘法
通过倍点加法实现$kP$（$k$为标量，$P$为曲线点）：
```python
def point_mul(k, p):
    result = None
    current = p
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current)
        current = point_add(current, current)  # 倍点运算
        k = k // 2
    return result
```


### 1.3 密钥生成
- **私钥**：随机整数$d \in [1, n-2]$
- **公钥**：$Q = d \cdot G$（通过点乘法计算）
```python
def key_generation():
    d = secrets.randbelow(n-1) + 1  # 确保1 ≤ d ≤ n-1
    Q = point_mul(d, G)
    return d, Q
```


### 1.4 签名与验签实现

#### 1.4.1 签名算法
对消息$M$生成签名$(r, s)$：
1. 计算用户信息哈希$Z_A$：
   $$Z_A = \text{SM3}(entl || ID || a || b || Gx || Gy || x_A || y_A)$$
   （$entl$为ID长度，$x_A,y_A$为公钥$Q$坐标）

2. 计算消息哈希$e$：
   $$e = \text{SM3}(Z_A || M)$$

3. 生成随机数$k \in [1, n-1]$，计算$kG = (x_1, y_1)$

4. 计算签名组件：
   $$r = (e_{\text{int}} + x_1) \mod n$$
   $$s = [(1 + d)^{-1} \cdot (k - r \cdot d)] \mod n$$

```python
from gmssl import sm3, func

def compute_ZA(Q, user_id=b"1234567812345678"):
    entl = len(user_id) * 8
    entl_bytes = entl.to_bytes(2, byteorder='big')
    xA, yA = Q
    a_bytes = int_to_bytes(a)
    b_bytes = int_to_bytes(b)
    Gx_bytes = int_to_bytes(Gx)
    Gy_bytes = int_to_bytes(Gy)
    xA_bytes = int_to_bytes(xA)
    yA_bytes = int_to_bytes(yA)
    za_input = entl_bytes + user_id + a_bytes + b_bytes + Gx_bytes + Gy_bytes + xA_bytes + yA_bytes
    return sm3.sm3_hash(func.bytes_to_list(za_input))

def sm2_sign(M, d, Q, user_id=b"1234567812345678"):
    ZA = compute_ZA(Q, user_id)
    M_bytes = M.encode('utf-8')
    e_input = bytes.fromhex(ZA) + M_bytes
    e = sm3.sm3_hash(func.bytes_to_list(e_input))
    e_int = bytes_to_int(bytes.fromhex(e))
    
    while True:
        k = secrets.randbelow(n-1) + 1
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
```


#### 1.4.2 验签算法
验证签名$(r, s)$有效性：
1. 检查$r, s \in [1, n-1]$
2. 计算$Z_A$和$e$（同签名步骤）
3. 计算$t = (r + s) \mod n$，若$t=0$则无效
4. 计算$(x_1, y_1) = sG + tQ$
5. 验证$r \equiv (e_{\text{int}} + x_1) \mod n$

```python
def sm2_verify(M, signature, Q, user_id=b"1234567812345678"):
    r, s = signature
    if r < 1 or r >= n or s < 1 or s >= n:
        return False
    
    ZA = compute_ZA(Q, user_id)
    M_bytes = M.encode('utf-8')
    e_input = bytes.fromhex(ZA) + M_bytes
    e = sm3.sm3_hash(func.bytes_to_list(e_input))
    e_int = bytes_to_int(bytes.fromhex(e))
    
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
```


## 二、PoC验证：随机数漏洞导致私钥泄露

### 2.1 漏洞原理
SM2签名安全性依赖随机数$k$的**保密性**和**唯一性**。若重复使用$k$，攻击者可通过两组签名推导私钥$d$。

#### 数学推导：
设两次签名使用同一$k$，得到$(r_1, s_1)$和$(r_2, s_2)$：
$$
\begin{cases}
s_1 \cdot (1 + d) \equiv k - r_1 \cdot d \mod n \quad (1) \\
s_2 \cdot (1 + d) \equiv k - r_2 \cdot d \mod n \quad (2)
\end{cases}
$$
两式相减消去$k$：
$$(s_1 - s_2)(1 + d) \equiv (r_2 - r_1)d \mod n$$
整理得私钥$d$的推导公式：
$$d \equiv \frac{s_2 - s_1}{s_1 - s_2 + r_1 - r_2} \mod n \tag{3}$$


### 2.2 实验验证

#### 步骤1：生成密钥对与重复$k$的签名
```python
# 生成虚构用户密钥对
d, Q = key_generation()
print(f"私钥d: 0x{d:064x}")

# 重复使用随机数k对两个消息签名
k = secrets.randbelow(n-1) + 1  # 固定k
msg1 = "测试消息1"
msg2 = "测试消息2"
sig1 = sm2_sign_with_k(msg1, d, Q, k)  # 用固定k签名
sig2 = sm2_sign_with_k(msg2, d, Q, k)
r1, s1 = sig1
r2, s2 = sig2
```

#### 步骤2：通过公式(3)推导私钥
```python
def deduce_private_key(r1, s1, r2, s2):
    numerator = (s2 - s1) % n
    denominator = (s1 - s2 + r1 - r2) % n
    inv_denominator = mod_inverse(denominator, n)
    d_deduced = (numerator * inv_denominator) % n
    return d_deduced

d_deduced = deduce_private_key(r1, s1, r2, s2)
print(f"推导私钥: 0x{d_deduced:064x}")
print(f"验证结果: {d_deduced == d}")  # 应输出True
```

#### 实验结果：
```
私钥d: 0x7c4cd5c35f28528e0d2b6a66dde4246bfdf6d240512983aa1e2a5399a0d315b1
推导私钥: 0x7c4cd5c35f28528e0d2b6a66dde4246bfdf6d240512983aa1e2a5399a0d315b1
验证结果: True
```


## 三、虚构场景签名伪造

### 伪造步骤

#### 步骤1：获取私钥
通过PoC验证中的方法，攻击者已推导得到私钥$d$。

#### 步骤2：生成伪造签名
使用泄露的私钥对任意消息生成签名：
```python
def forge_signature(M, d, Q):
    # 与正常签名流程完全一致（因私钥已泄露）
    return sm2_sign(M, d, Q)

# 伪造消息与签名
fake_msg = "虚构场景：伪造的消息"
fake_sig = forge_signature(fake_msg, d_deduced, Q)
print(f"伪造签名: (r=0x{fake_sig[0]:064x}, s=0x{fake_sig[1]:064x})")
```

#### 步骤3：验证伪造签名
```python
verify_result = sm2_verify(fake_msg, fake_sig, Q)
print(f"伪造签名验证结果: {verify_result}")  # 输出True（因私钥正确）
```

#### 输出结果：
```
伪造签名: (r=0x72abd72df13a4e9f75a10a79c1dcbc017ea34325a6259924141fc97bc2492065, s=0x1d97801a4b23dd2f3295f88de08d2be0843f3237125abc974d3a7c38df804cff)
伪造签名验证结果: True
```


## 四、安全启示与防御措施

1. **随机数管理**：
   - 必须使用`secrets`模块生成加密安全的随机数，禁止重复使用$k$
   - 推荐实现RFC6979标准，基于消息和私钥生成确定性随机数（避免重复）

2. **实现加固**：
   - 采用抗侧信道攻击的点乘法（如蒙哥马利梯子法），防止$k$通过功耗/时间差异泄露
   - 验签时严格检查$r, s$的范围（$1 \leq r, s < n$）


## 附录：辅助函数
```python
def int_to_bytes(i):
    return i.to_bytes(32, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def sm2_sign_with_k(M, d, Q, k):
    # 固定k的签名函数（仅用于PoC验证）
    ZA = compute_ZA(Q)
    M_bytes = M.encode('utf-8')
    e_input = bytes.fromhex(ZA) + M_bytes
    e = sm3.sm3_hash(func.bytes_to_list(e_input))
    e_int = bytes_to_int(bytes.fromhex(e))
    
    kG = point_mul(k, G)
    x1 = kG[0]
    r = (e_int + x1) % n
    while r == 0 or (r + k) % n == 0:
        k = secrets.randbelow(n-1) + 1
        kG = point_mul(k, G)
        x1 = kG[0]
        r = (e_int + x1) % n
    
    s = (mod_inverse((1 + d) % n, n) * (k - r * d)) % n
    s = (s + n) % n
    return (r, s)
```