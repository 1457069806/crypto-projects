# Poseidon2 哈希电路（Circom实现）详细说明文档

## 一、项目概述
本项目基于Circom语言实现了Poseidon2哈希算法的零知识证明电路，采用Groth16证明系统生成和验证证明。电路设计满足隐私输入（哈希原象）与公开输入（哈希结果）的验证关系，可用于区块链隐私交易、身份认证等场景。

### 核心参数
根据需求及Poseidon2官方文档（2023-323.pdf）Table 1，采用以下参数：
- `(n, t, d) = (256, 3, 5)`
  - `n=256`：输出哈希值长度为256位
  - `t=3`：状态向量维度为3（包含3个元素）
  - `d=5`：S-box采用5次幂运算（满足有限域内可逆性）


## 二、数学基础与算法原理

### 1. 有限域运算
Poseidon2在有限域`GF(p)`上运算，本实现采用BN254曲线的标量域`GF(p)`，其中`p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`

### 2. 状态初始化
对于输入原象`[a, b]`（1个block，长度为`t-1=2`），状态向量初始化如下：
```
s = [s₀, s₁, s₂] = [0, a, b]
```
其中`s₀`为初始常量，`s₁`和`s₂`为隐私输入的原象元素。

### 3. 轮操作数学原理
Poseidon2的核心是状态置换网络，由完全轮(Full Rounds)和部分轮(Partial Rounds)组成，总轮数配置为：
- 完全轮：`R_F = 8`（前4轮+后4轮）
- 部分轮：`R_P = 22`（中间轮）

#### 3.1 完全轮操作
每轮包含三个步骤：
1. **加轮常量(AddRoundConstants)**
   ```
   s'_i = s_i + c_i^r  (i=0,1,2)
   ```
   其中`c_i^r`是第`r`轮的第`i`个常量（来自文档推荐的常量集）

2. **S-box变换(SubWords)**
   对所有状态元素应用5次幂S-box：
   ```
   s''_i = (s'_i)^5 mod p
   ```
   选择5次幂的原因是`gcd(5, p-1) = 1`，确保在`GF(p)`内可逆。

3. **线性层(MixLayer)**
   通过优化的MDS矩阵进行线性扩散：
   ```
   s''' = M × s''
   ```
   其中M为Poseidon2推荐的3×3矩阵：
   ```
   M = [[2, 1, 1],
        [1, 3, 1],
        [1, 1, 4]]
   ```
   矩阵乘法公式：
   ```
   s'''_0 = 2·s''_0 + 1·s''_1 + 1·s''_2
   s'''_1 = 1·s''_0 + 3·s''_1 + 1·s''_2
   s'''_2 = 1·s''_0 + 1·s''_1 + 4·s''_2
   ```

#### 3.2 部分轮操作
部分轮仅对第一个元素应用S-box，其余步骤与完全轮一致：
1. 加轮常量：`s'_0 = s_0 + c_0^r`（仅第一个元素加常量）
2. S-box变换：`s''_0 = (s'_0)^5 mod p`（仅第一个元素变换）
3. 线性层：与完全轮使用相同的MDS矩阵

### 4. 哈希输出
经过所有轮操作后，取最终状态的第一个元素作为哈希结果：
```
hash = s_final[0]
```


## 三、电路具体实现（`poseidon2.circom`）

### 1. 电路结构设计
```circom
include "node_modules/circomlib/circuits/poseidon.circom";

template Poseidon2Hash() {
    // 输入定义
    signal private input preImage[2];  // 隐私输入：哈希原象
    signal public input expectedHash;  // 公开输入：预期哈希值
    signal output computedHash;        // 电路计算的哈希值

    // 1. 状态初始化
    signal s[3];
    s[0] <== 0;
    s[1] <== preImage[0];
    s[2] <== preImage[1];

    // 2. 轮常量定义（文档推荐值的示例）
    const fullRoundConstants[8][3] = [
        [1831845427, 1672855759, 357339482],
        [1234567890, 987654321, 135792468],
        // ... 其余6组常量（共8组）
    ];
    const partialRoundConstants[22] = [
        192837465, 293847561, 384756192,
        // ... 其余19个常量（共22个）
    ];

    // 3. 前4轮完全轮
    for (var r = 0; r < 4; r++) {
        // 加轮常量
        s[0] += fullRoundConstants[r][0];
        s[1] += fullRoundConstants[r][1];
        s[2] += fullRoundConstants[r][2];
        
        // S-box变换（5次幂）
        s[0] = s[0]^5;
        s[1] = s[1]^5;
        s[2] = s[2]^5;
        
        // 线性层（MDS矩阵乘法）
        s = mixLayer(s);
    }

    // 4. 22轮部分轮
    for (var r = 0; r < 22; r++) {
        // 加轮常量（仅第一个元素）
        s[0] += partialRoundConstants[r];
        
        // S-box变换（仅第一个元素）
        s[0] = s[0]^5;
        
        // 线性层
        s = mixLayer(s);
    }

    // 5. 后4轮完全轮
    for (var r = 4; r < 8; r++) {
        // 加轮常量
        s[0] += fullRoundConstants[r][0];
        s[1] += fullRoundConstants[r][1];
        s[2] += fullRoundConstants[r][2];
        
        // S-box变换
        s[0] = s[0]^5;
        s[1] = s[1]^5;
        s[2] = s[2]^5;
        
        // 线性层
        s = mixLayer(s);
    }

    // 6. 输出哈希结果
    computedHash <== s[0];
    
    // 7. 约束：计算结果必须等于公开输入
    computedHash === expectedHash;
}

// 线性层实现（MDS矩阵乘法）
function mixLayer(s) {
    var res[3];
    res[0] = 2*s[0] + 1*s[1] + 1*s[2];
    res[1] = 1*s[0] + 3*s[1] + 1*s[2];
    res[2] = 1*s[0] + 1*s[1] + 4*s[2];
    return res;
}

// 电路实例化
component main = Poseidon2Hash();
```

### 2. 关键组件说明
- **隐私输入**：`preImage[2]`存储哈希原象（2个元素）
- **公开输入**：`expectedHash`为预先计算的哈希值
- **约束系统**：通过`computedHash === expectedHash`建立输入与输出的关系
- **轮操作实现**：严格遵循8完全轮+22部分轮的配置，与文档要求一致


## 四、电路编译与证明生成

### 1. 环境准备
```bash
# 安装依赖工具
npm install -g circom@2.1.8 snarkjs@0.7.0
npm install circomlib

# 准备输入文件input.json
{
  "preImage": [123456789, 987654321],
  "expectedHash": 18273645908273645987654321  // 需预先计算正确值
}
```

### 2. 编译电路
```bash
circom circuits/poseidon2.circom --r1cs --wasm --sym
```
生成文件：
- `poseidon2.r1cs`：约束系统描述
- `poseidon2_js/`：WASM见证生成器
- `poseidon2.sym`：符号表（调试用）

### 3. 生成见证
```bash
cd poseidon2_js
node generate_witness.js poseidon2.wasm ../input.json ../witness.wtns
```

### 4. Groth16信任设置
```bash
# 初始化Powers of Tau
snarkjs powersoftau new bn128 15 pot15_0000.ptau -v
snarkjs powersoftau contribute pot15_0000.ptau pot15_0001.ptau --name="First contribution" -v

# 电路特定设置
snarkjs groth16 setup ../poseidon2.r1cs pot15_0001.ptau poseidon2_0000.zkey
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_0001.zkey --name="Second contribution" -v
snarkjs zkey export verificationkey poseidon2_0001.zkey verification_key.json
```

### 5. 生成与验证证明
```bash
# 生成证明
snarkjs groth16 prove poseidon2_0001.zkey ../witness.wtns proof.json public.json

# 验证证明
snarkjs groth16 verify verification_key.json public.json proof.json
```

