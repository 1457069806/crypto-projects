from sm3_optimized import sm3_hash, fill_message, compression_function


def hash_to_state(hash_hex):
    """将SM3哈希值转换为压缩函数状态（8个32位整数）"""
    if len(hash_hex) != 64:
        raise ValueError("SM3哈希值必须为64个十六进制字符")
    return [int(hash_hex[i * 8:(i + 1) * 8], 16) for i in range(8)]


def state_to_hash(state):
    """将压缩函数状态转换为哈希字符串"""
    return ''.join(f"{word:08x}" for word in state)


def length_extension_attack(original_hash, original_len, append_data):
    # 1. 原始哈希 = 处理"原始消息+填充"后的状态，以此为初始状态（关键：已包含原始填充的处理）
    current_state = hash_to_state(original_hash)

    # 2. 计算"原始消息+填充"的总长度（用于确定附加数据的填充起点）
    dummy_original = b'X' * original_len
    padded_original = fill_message(dummy_original)
    original_padded_len = len(padded_original)  # 原始消息+填充的总长度（64的倍数）

    # 3. 计算扩展消息的总长度：原始消息+填充+附加数据
    total_length = original_padded_len + len(append_data)

    # 4. 构造附加数据的正确填充（基于总长度）
    # 模拟一个长度为total_length的消息，其填充即为附加数据需要的填充
    dummy_total = b'Y' * total_length
    total_padded = fill_message(dummy_total)
    # 截取附加数据对应的填充部分（跳过原始消息+填充+附加数据本身）
    append_padding = total_padded[original_padded_len + len(append_data):]

    # 5. 攻击数据 = 附加数据 + 正确填充（仅处理附加部分，不包含原始填充）
    attack_data = append_data + append_padding

    # 6. 分块处理攻击数据（从原始哈希状态开始，与正常计算的后续块对齐）
    for i in range(0, len(attack_data), 64):
        block = attack_data[i:i + 64]
        # 确保块长度为64字节
        if len(block) < 64:
            block += b'\x00' * (64 - len(block))
        current_state = compression_function(current_state, block)

    return state_to_hash(current_state), attack_data


def verify_attack():
    # 原始消息（攻击者不知道）
    secret_message = b"secret_key=123"
    secret_len = len(secret_message)

    # 计算原始消息的哈希（攻击者可见）
    original_hash = sm3_hash(secret_message)
    print(f"原始消息: {secret_message}")
    print(f"原始消息长度: {secret_len} 字节")
    print(f"原始哈希值: {original_hash}\n")

    # 攻击者要附加的数据
    append_data = b"&user=admin&role=root"
    print(f"附加数据: {append_data}")
    print(f"附加数据长度: {len(append_data)} 字节\n")

    # 正常计算方式（仅用于验证）
    # 步骤：原始消息 -> 填充（得到padded_secret） -> 附加数据 -> 整体哈希
    padded_secret = fill_message(secret_message)  # 原始消息+填充（已处理为完整块）
    combined_message = padded_secret + append_data  # 原始块+附加数据
    expected_hash = sm3_hash(combined_message)
    print(f"正常计算的扩展哈希: {expected_hash}")

    # 攻击者执行长度扩展攻击
    attacked_hash, attack_data = length_extension_attack(original_hash, secret_len, append_data)
    print(f"攻击得到的扩展哈希: {attacked_hash}")

    # 验证攻击结果
    if attacked_hash == expected_hash:
        print("\n✅ 长度扩展攻击成功！")
    else:
        print("\n❌ 长度扩展攻击失败！")

    # 块结构对比（验证对齐）
    print("\n块结构对比:")
    # 正常计算的块：原始块（padded_secret） + 附加数据块
    normal_blocks = [padded_secret.hex()[:16]]  # 原始块（已被原始哈希处理）
    normal_blocks += [combined_message[i:i + 64].hex()[:16] for i in
                      range(len(padded_secret), len(combined_message), 64)]

    # 攻击的块：仅附加数据块（与正常计算的附加数据块对齐）
    attack_blocks = [attack_data[i:i + 64].hex()[:16] for i in range(0, len(attack_data), 64)]

    print(f"正常计算块数: {len(normal_blocks)} (含原始块), 攻击块数: {len(attack_blocks)}")
    print(f"原始块（已处理）: {normal_blocks[0]}...")
    for i in range(len(attack_blocks)):
        print(f"附加块 {i + 1}: 正常={normal_blocks[i + 1]}..., 攻击={attack_blocks[i]}...")


if __name__ == "__main__":
    verify_attack()