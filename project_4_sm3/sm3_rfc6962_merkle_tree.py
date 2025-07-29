from sm3_optimized import sm3_hash
import random
from typing import List, Tuple, Optional, Dict


class RFC6962MerkleTree:
    """基于RFC6962标准的Merkle树实现（精简输出版）"""

    def __init__(self, leaves: List[bytes]):
        self.leaves = leaves
        self.leaf_count = len(leaves)
        self.tree = []
        self._build_tree()

    @staticmethod
    def _hash_leaf(data: bytes) -> str:
        return sm3_hash(b'\x00' + data)

    @staticmethod
    def _hash_internal(left_hex: str, right_hex: str) -> str:
        left_bytes = bytes.fromhex(left_hex)
        right_bytes = bytes.fromhex(right_hex)
        return sm3_hash(b'\x01' + left_bytes + right_bytes)

    def _build_tree(self) -> None:
        # 计算叶子层哈希
        leaf_hashes = [self._hash_leaf(leaf) for leaf in self.leaves]
        self.tree.append(leaf_hashes)

        # 逐层计算内部节点
        current_level = leaf_hashes
        while len(current_level) > 1:
            next_level = []
            i = 0
            while i < len(current_level):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                    i += 2
                else:
                    right = left
                    i += 1
                next_level.append(self._hash_internal(left, right))
            current_level = next_level
            self.tree.append(current_level)

    @property
    def root(self) -> str:
        return self.tree[-1][0] if self.tree else ""

    def get_leaf_index(self, leaf_data: bytes) -> Optional[int]:
        target_hash = self._hash_leaf(leaf_data)
        for idx, h in enumerate(self.tree[0]):
            if h == target_hash:
                return idx
        return None

    def get_inclusion_proof(self, index: int) -> List[Tuple[str, bool]]:
        if index < 0 or index >= self.leaf_count:
            return []

        proof = []
        current_idx = index
        for level in range(len(self.tree) - 1):
            current_level = self.tree[level]
            total_nodes = len(current_level)

            is_left = (current_idx % 2 == 0)
            if is_left:
                sibling_idx = current_idx + 1 if current_idx + 1 < total_nodes else current_idx
            else:
                sibling_idx = current_idx - 1

            sibling_hash = current_level[sibling_idx]
            proof.append((sibling_hash, is_left))
            current_idx = current_idx // 2

        return proof

    @staticmethod
    def verify_inclusion(
            leaf_data: bytes,
            proof: List[Tuple[str, bool]],
            root: str,
            index: int,
            total_leaves: int
    ) -> bool:
        current_hash = RFC6962MerkleTree._hash_leaf(leaf_data)
        for sibling_hash, is_left in proof:
            if is_left:
                current_hash = RFC6962MerkleTree._hash_internal(current_hash, sibling_hash)
            else:
                current_hash = RFC6962MerkleTree._hash_internal(sibling_hash, current_hash)
        return current_hash == root

    def get_exclusion_proof(self, target_data: bytes) -> Dict[str, any]:
        target_hash = self._hash_leaf(target_data)
        leaf_hashes = self.tree[0]

        insert_pos = 0
        while insert_pos < self.leaf_count and leaf_hashes[insert_pos] < target_hash:
            insert_pos += 1

        left_idx = insert_pos - 1 if insert_pos > 0 else None
        right_idx = insert_pos if insert_pos < self.leaf_count else None

        return {
            "target_hash": target_hash,
            "insert_pos": insert_pos,
            "left": {
                "index": left_idx,
                "hash": leaf_hashes[left_idx] if left_idx is not None else None,
                "proof": self.get_inclusion_proof(left_idx) if left_idx is not None else []
            },
            "right": {
                "index": right_idx,
                "hash": leaf_hashes[right_idx] if right_idx is not None else None,
                "proof": self.get_inclusion_proof(right_idx) if right_idx is not None else []
            },
            "root": self.root,
            "total_leaves": self.leaf_count,
            "leaf_data_map": {
                left_idx: self.leaves[left_idx] if left_idx is not None else None,
                right_idx: self.leaves[right_idx] if right_idx is not None else None
            }
        }

    @staticmethod
    def verify_exclusion(proof: Dict[str, any]) -> bool:
        # 验证左邻居
        left_valid = True
        left = proof["left"]
        if left["index"] is not None:
            left_data = proof["leaf_data_map"][left["index"]]
            left_valid = RFC6962MerkleTree.verify_inclusion(
                left_data, left["proof"], proof["root"], left["index"], proof["total_leaves"]
            )

        # 验证右邻居
        right_valid = True
        right = proof["right"]
        if right["index"] is not None:
            right_data = proof["leaf_data_map"][right["index"]]
            right_valid = RFC6962MerkleTree.verify_inclusion(
                right_data, right["proof"], proof["root"], right["index"], proof["total_leaves"]
            )

        # 验证哈希顺序和相邻性
        target_hash = proof["target_hash"]
        order_valid = True
        if left["hash"] and left["hash"] >= target_hash:
            order_valid = False
        if right["hash"] and right["hash"] <= target_hash:
            order_valid = False

        adjacent_valid = True
        if left["index"] is not None and right["index"] is not None:
            if right["index"] - left["index"] != 1:
                adjacent_valid = False

        return left_valid and right_valid and order_valid and adjacent_valid


# 测试代码
def test_merkle_tree():
    print("生成10万个叶子节点...")
    num_leaves = 100000
    leaves = [bytes(random.getrandbits(8) for _ in range(32)) for _ in range(num_leaves)]

    print("构建Merkle树...")
    merkle_tree = RFC6962MerkleTree(leaves)
    print(f"树深度: {len(merkle_tree.tree)}, 根哈希: {merkle_tree.root[:16]}...\n")

    # 存在性证明测试
    test_idx = random.randint(0, num_leaves - 1)
    test_leaf = leaves[test_idx]
    inclusion_proof = merkle_tree.get_inclusion_proof(test_idx)
    print(f"存在性证明测试（索引{test_idx}）:")
    inc_result = RFC6962MerkleTree.verify_inclusion(
        test_leaf, inclusion_proof, merkle_tree.root, test_idx, num_leaves
    )
    print(f"存在性验证结果: {'成功' if inc_result else '失败'}\n")

    # 不存在性证明测试
    non_existent_leaf = b"exclusion_test_123456"
    exclusion_proof = merkle_tree.get_exclusion_proof(non_existent_leaf)
    print("不存在性证明测试:")
    exc_result = RFC6962MerkleTree.verify_exclusion(exclusion_proof)
    print(f"不存在性验证结果: {'成功' if exc_result else '失败'}")


if __name__ == "__main__":
    test_merkle_tree()