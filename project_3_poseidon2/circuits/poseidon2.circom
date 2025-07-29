include "../node_modules/circomlib/circuits/poseidon_constants.circom";
include "../node_modules/circomlib/circuits/binadd.circom";

// 有限域上的模运算辅助函数
template ModExp5(p) {
    signal input a;
    signal output out;

    out <== (a * a % p) * a % p * a % p * a % p;
}

// 完全轮操作 (Full Round)
template FullRound(t, p, roundConst) {
    signal input state[t];
    signal output out[t];

    // 1. 添加轮常量
    signal afterAdd[t];
    for (var i = 0; i < t; i++) {
        afterAdd[i] <== state[i] + roundConst[i];
    }

    // 2. 应用S-box (5次幂)
    signal afterSbox[t];
    component sbox[t];
    for (var i = 0; i < t; i++) {
        sbox[i] = ModExp5(p);
        sbox[i].a <== afterAdd[i];
        afterSbox[i] <== sbox[i].out;
    }

    // 3. 线性变换 (MDS矩阵乘法)
    // 使用Poseidon2推荐的M_I矩阵 (256,3,5)参数
    const MDS = [
        [2, 1, 1],
        [1, 3, 1],
        [1, 1, 4]
    ];

    for (var i = 0; i < t; i++) {
        out[i] <== 0;
        for (var j = 0; j < t; j++) {
            out[i] <== out[i] + MDS[i][j] * afterSbox[j];
        }
        out[i] <== out[i] % p;
    }
}

// 部分轮操作 (Partial Round)
template PartialRound(t, p, roundConst) {
    signal input state[t];
    signal output out[t];

    // 1. 添加轮常量 (仅第一个元素)
    signal afterAdd[t];
    afterAdd[0] <== state[0] + roundConst[0];
    for (var i = 1; i < t; i++) {
        afterAdd[i] <== state[i];
    }

    // 2. 应用S-box (仅第一个元素)
    signal afterSbox[t];
    component sbox;
    sbox = ModExp5(p);
    sbox.a <== afterAdd[0];
    afterSbox[0] <== sbox.out;

    for (var i = 1; i < t; i++) {
        afterSbox[i] <== afterAdd[i];
    }

    // 3. 线性变换 (与完全轮相同的MDS矩阵)
    const MDS = [
        [2, 1, 1],
        [1, 3, 1],
        [1, 1, 4]
    ];

    for (var i = 0; i < t; i++) {
        out[i] <== 0;
        for (var j = 0; j < t; j++) {
            out[i] <== out[i] + MDS[i][j] * afterSbox[j];
        }
        out[i] <== out[i] % p;
    }
}

// Poseidon2主电路 (n=256, t=3, d=5)
template Poseidon2() {
    // 素数域: BN254曲线的 scalar field
    const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // 输入: 隐私输入(2个元素)和公开哈希结果
    signal private input preimage[2];  // 哈希原象
    signal public input hashResult;    // 预期哈希值

    // 初始化状态向量 [s0, s1, s2]
    signal state[3];
    state[0] <== 0;                    // 初始化为0
    state[1] <== preimage[0];          // 第一个输入元素
    state[2] <== preimage[1];          // 第二个输入元素

    // 轮常量 (精简版，实际使用需从官方文档获取完整常量)
    const FULL_ROUND_CONSTS = [
        [1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12],
        [13, 14, 15], [16, 17, 18], [19, 20, 21], [22, 23, 24]
    ];
    const PARTIAL_ROUND_CONSTS = [[25], [26], [27], [28]];

    // 前4轮完全轮
    component fr1 = FullRound(3, P, FULL_ROUND_CONSTS[0]);
    component fr2 = FullRound(3, P, FULL_ROUND_CONSTS[1]);
    component fr3 = FullRound(3, P, FULL_ROUND_CONSTS[2]);
    component fr4 = FullRound(3, P, FULL_ROUND_CONSTS[3]);

    fr1.state <== state;
    fr2.state <== fr1.out;
    fr3.state <== fr2.out;
    fr4.state <== fr3.out;
    state <== fr4.out;

    // 4轮部分轮
    component pr1 = PartialRound(3, P, PARTIAL_ROUND_CONSTS[0]);
    component pr2 = PartialRound(3, P, PARTIAL_ROUND_CONSTS[1]);
    component pr3 = PartialRound(3, P, PARTIAL_ROUND_CONSTS[2]);
    component pr4 = PartialRound(3, P, PARTIAL_ROUND_CONSTS[3]);

    pr1.state <== state;
    pr2.state <== pr1.out;
    pr3.state <== pr2.out;
    pr4.state <== pr3.out;
    state <== pr4.out;

    // 后4轮完全轮
    component fr5 = FullRound(3, P, FULL_ROUND_CONSTS[4]);
    component fr6 = FullRound(3, P, FULL_ROUND_CONSTS[5]);
    component fr7 = FullRound(3, P, FULL_ROUND_CONSTS[6]);
    component fr8 = FullRound(3, P, FULL_ROUND_CONSTS[7]);

    fr5.state <== state;
    fr6.state <== fr5.out;
    fr7.state <== fr6.out;
    fr8.state <== fr7.out;
    state <== fr8.out;

    // 输出哈希结果 (取状态第一个元素)
    signal computedHash;
    computedHash <== state[0];

    // 约束: 计算结果必须等于公开输入的哈希值
    computedHash === hashResult;
}

// 主电路实例化
component main = Poseidon2();
