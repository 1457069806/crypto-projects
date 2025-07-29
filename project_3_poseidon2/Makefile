#!/bin/bash

# 电路编译
build:
	mkdir -p build
	circom circuits/poseidon2.circom --r1cs --wasm --sym -o build/

# 生成见证
witness:
	node build/poseidon2_js/generate_witness.js build/poseidon2_js/poseidon2.wasm input.json build/witness.wtns

# 初始化 Powers of Tau
init-ptau:
	snarkjs powersoftau new bn128 12 build/pot12_0000.ptau -v

# 贡献 Powers of Tau
contribute-ptau:
	snarkjs powersoftau contribute build/pot12_0000.ptau build/pot12_0001.ptau --name="First contribution" -v

# 电路信任设置
setup:
	snarkjs groth16 setup build/poseidon2.r1cs build/pot12_0001.ptau build/poseidon2_0000.zkey
	snarkjs zkey contribute build/poseidon2_0000.zkey build/poseidon2_0001.zkey --name="First contribution" -v
	snarkjs zkey export verificationkey build/poseidon2_0001.zkey build/verification_key.json

# 生成证明
prove:
	snarkjs groth16 prove build/poseidon2_0001.zkey build/witness.wtns build/proof.json build/public.json

# 验证证明
verify:
	snarkjs groth16 verify build/verification_key.json build/public.json build/proof.json

# 清理构建文件
clean:
	rm -rf build/

# 完整流程 (需手动确认输入的hashResult正确)
full: build witness setup prove verify

.PHONY: build witness init-ptau contribute-ptau setup prove verify clean full
