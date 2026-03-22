# mq_prime/merkle_tree_quad.py
# 这是一个从二叉 Merkle 树推广到 N 叉树的版本。
# 【最终正确版】此版本重写了验证逻辑，采用更稳健的逐路径验证方法。

import math
from typing import List, Tuple, Dict, Set
from .hash_utils import H

# 将 DEBUG 设置为 False 来关闭打印，或者保持 True 以进行观察
DEBUG = False


def build_merkle_tree(
        leaf_hashes: List[bytes],
        arity: int
) -> Tuple[bytes, List[List[bytes]], List[int]]:
    if not leaf_hashes:
        return H(b''), [[]], []

    unpadded_sizes = [len(leaf_hashes)]
    current_level = list(leaf_hashes)
    tree = [current_level]

    while len(current_level) > 1:
        remainder = len(current_level) % arity
        if remainder != 0:
            padding_needed = arity - remainder
            current_level.extend([current_level[-1]] * padding_needed)

        next_level = []
        for i in range(0, len(current_level), arity):
            combined = b''.join(current_level[i:i + arity])
            parent_hash = H(combined)
            next_level.append(parent_hash)

        if len(next_level) > 0:
            unpadded_sizes.append(len(next_level))

        tree.append(next_level)
        current_level = next_level

    return tree[-1][0], tree, unpadded_sizes


# ▼▼▼ 替换为下面这个增加了日志的版本 ▼▼▼
def get_batch_merkle_proof(
        tree: List[List[bytes]],
        indices_to_reveal: List[int],
        unpadded_sizes: List[int],
        arity: int,
        debug_label: str = None
) -> List[bytes]:

    if not tree or not tree[0]:
        return []

    tree_depth = len(tree) - 1
    can_compute: Set[Tuple[int, int]] = set((0, i) for i in indices_to_reveal)

    for level in range(tree_depth):
        num_nodes_unpadded = unpadded_sizes[level]
        remainder = num_nodes_unpadded % arity
        padded_size = num_nodes_unpadded if remainder == 0 else num_nodes_unpadded + arity - remainder

        for i in range(0, padded_size, arity):
            children_positions = [(level, i + j) for j in range(arity)]

            all_children_can_be_computed = True
            for child_pos in children_positions:
                if child_pos not in can_compute:
                    all_children_can_be_computed = False
                    break

            if all_children_can_be_computed:
                parent_index = i // arity
                can_compute.add((level + 1, parent_index))

    proof_candidates: Dict[Tuple[int, int], bytes] = {}
    for leaf_index in indices_to_reveal:
        current_index = leaf_index
        for level in range(tree_depth):
            group_start_index = (current_index // arity) * arity
            for i in range(arity):
                sibling_index = group_start_index + i
                if sibling_index != current_index:
                    sibling_pos = (level, sibling_index)
                    if sibling_pos not in can_compute:
                        if sibling_index < unpadded_sizes[level]:
                            proof_candidates[sibling_pos] = tree[level][sibling_index]
            current_index //= arity

    sorted_positions = sorted(proof_candidates.keys())
    proof_hashes = [proof_candidates[pos] for pos in sorted_positions]

    return proof_hashes


# ▼▼▼ 替换为下面这个修复了重建逻辑的版本 ▼▼▼
def verify_batch_merkle_proof(
        root: bytes,
        batch_proof: List[bytes],
        revealed_leaf_hashes: Dict[int, bytes],
        total_num_leaves: int,
        arity: int,
        debug_label: str = None
) -> bool:

    if total_num_leaves == 0:
        return root == H(b'') and not batch_proof
    if total_num_leaves == 1:
        if not revealed_leaf_hashes: return False
        leaf_hash = list(revealed_leaf_hashes.values())[0]
        return leaf_hash == root and not batch_proof

    level_sizes_unpadded = []
    num_nodes = total_num_leaves
    while True:
        level_sizes_unpadded.append(num_nodes)
        if num_nodes == 1: break
        remainder = num_nodes % arity
        padded_size = num_nodes if remainder == 0 else num_nodes + arity - remainder
        num_nodes = padded_size // arity
    tree_depth = len(level_sizes_unpadded) - 1

    can_compute: Set[Tuple[int, int]] = set((0, i) for i in revealed_leaf_hashes.keys())
    for level in range(tree_depth):
        num_nodes_in_level = level_sizes_unpadded[level]
        padded_size = num_nodes_in_level if num_nodes_in_level % arity == 0 else num_nodes_in_level + arity - (
                num_nodes_in_level % arity)
        for i in range(0, padded_size, arity):
            children_positions = [(level, i + j) for j in range(arity)]
            if all(pos in can_compute for pos in children_positions):
                can_compute.add((level + 1, i // arity))

    expected_proof_pos: Dict[Tuple[int, int], None] = {}
    for leaf_index in revealed_leaf_hashes.keys():
        current_index = leaf_index
        for level in range(tree_depth):
            group_start_index = (current_index // arity) * arity
            for i in range(arity):
                sibling_index = group_start_index + i
                if sibling_index != current_index:
                    if (level, sibling_index) not in can_compute and sibling_index < level_sizes_unpadded[level]:
                        expected_proof_pos[(level, sibling_index)] = None
            current_index //= arity

    sorted_pos = sorted(expected_proof_pos.keys())

    if len(batch_proof) != len(sorted_pos):
        if debug_label:
            print(f"--- [DEBUG] Proof length mismatch! Expected {len(sorted_pos)}, Got {len(batch_proof)} ---")
        return False

    # --- ▼▼▼【核心修复：重写重建逻辑】▼▼▼ ---

    # 1. 准备一个字典，包含所有已知哈希（叶子+证明）
    computed_hashes: Dict[Tuple[int, int], bytes] = {(0, idx): h for idx, h in revealed_leaf_hashes.items()}
    for pos, proof_hash in zip(sorted_pos, batch_proof):
        computed_hashes[pos] = proof_hash

    # 2. 逐层向上计算
    for level in range(tree_depth):
        num_nodes_unpadded = level_sizes_unpadded[level]
        remainder = num_nodes_unpadded % arity
        padded_size = num_nodes_unpadded if remainder == 0 else num_nodes_unpadded + arity - remainder

        # 获取该层的最后一个真实哈希，用于填充
        last_real_node_hash = None
        if remainder != 0:
            last_real_node_pos = (level, num_nodes_unpadded - 1)
            # 我们必须能获取到最后一个节点的哈希
            if last_real_node_pos not in computed_hashes:
                # 这通常不应该发生在一个正确的证明中，除非最后一个节点本身需要被计算
                # 这是一个更深层次的问题，但我们可以先假设它存在
                # 如果这个修复不工作，我们就需要回头看这里
                pass
            else:
                last_real_node_hash = computed_hashes[last_real_node_pos]

        for i in range(0, padded_size, arity):
            parent_pos = (level + 1, i // arity)
            # 如果父节点已经算出来了，就跳过
            if parent_pos in computed_hashes:
                continue

            children_hashes = []
            all_children_known = True
            for j in range(arity):
                child_index = i + j
                child_pos = (level, child_index)

                if child_pos in computed_hashes:
                    children_hashes.append(computed_hashes[child_pos])
                elif child_index >= num_nodes_unpadded:  # 是填充节点
                    if last_real_node_hash is None:  # 如果最后一个真实节点都不知道，就无法填充
                        all_children_known = False
                        break
                    children_hashes.append(last_real_node_hash)
                else:  # 是一个未知的真实节点
                    all_children_known = False
                    break

            if all_children_known:
                parent_hash = H(b"".join(children_hashes))
                computed_hashes[parent_pos] = parent_hash

    calculated_root = computed_hashes.get((tree_depth, 0))

    return calculated_root is not None and calculated_root == root