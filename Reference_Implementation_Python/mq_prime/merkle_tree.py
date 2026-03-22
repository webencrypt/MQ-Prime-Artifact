# mq_prime/merkle_tree.py

from typing import List, Tuple
from .hash_utils import H


def build_merkle_tree(leaf_hashes: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:
    if not leaf_hashes:
        return H(b''), [[]]

    # 创建副本，避免修改原始输入
    current_level = list(leaf_hashes)
    tree = [current_level]

    while len(current_level) > 1:
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])

        next_level = []
        for i in range(0, len(current_level), 2):
            parent_hash = H(current_level[i], current_level[i + 1])
            next_level.append(parent_hash)

        # 将上一层处理后的完整版本（可能是补齐过的）存入树中
        # 注意：上面的 current_level.append 修改了 tree[-1]
        # 下一轮循环前，需要将新生成的 next_level 放入 tree
        tree.append(next_level)
        current_level = next_level

    return tree[-1][0], tree


def get_merkle_proof(tree: List[List[bytes]], leaf_index: int) -> List[bytes]:
    """
    从构建好的默克尔树中获取指定叶子节点的认证路径。

    Args:
        tree: 包含树所有层级的列表。
        leaf_index: 叶子节点的索引。

    Returns:
        一个包含路径上所有兄弟节点哈希的列表。
    """
    proof = []
    current_index = leaf_index
    # 从底层向上遍历
    for level in range(len(tree) - 1):
        # 确定兄弟节点的索引
        if current_index % 2 == 0:
            sibling_index = current_index + 1
        else:
            sibling_index = current_index - 1

        # 确保兄弟节点存在 (处理奇数节点的情况)
        if sibling_index < len(tree[level]):
            proof.append(tree[level][sibling_index])

        # 移动到上一层
        current_index //= 2

    return proof


def verify_merkle_proof(
        root: bytes,
        leaf_hash: bytes,
        proof: List[bytes],
        leaf_index: int
) -> bool:
    """
    验证一个默克尔认证路径是否有效。

    Args:
        root: 树的根哈希。
        leaf_hash: 要验证的叶子节点的哈希。
        proof: 包含路径上所有兄弟节点哈希的列表。
        leaf_index: 叶子节点的索引。

    Returns:
        如果路径有效则返回 True，否则返回 False。
    """
    current_hash = leaf_hash
    current_index = leaf_index

    for sibling_hash in proof:
        if current_index % 2 == 0:
            current_hash = H(current_hash, sibling_hash)
        else:
            current_hash = H(sibling_hash, current_hash)
        current_index //= 2

    return current_hash == root


def get_batch_merkle_proof(tree: List[List[bytes]], indices_to_reveal: List[int]) -> List[bytes]:
    """
    【最终工作且高效版】签名者函数。
    此版本实现了标准的 L-Tree 算法，只提供验证者无法自行推导的、
    经过排序的认证路径上的兄弟节点哈希。
    """
    if not tree or not tree[0]:
        return []

    tree_depth = len(tree) - 1

    # 1. 准确计算出验证者可以自行推导的所有节点 (can_compute set)。
    can_compute = set()
    for i in indices_to_reveal:
        can_compute.add((0, i))

    for level in range(tree_depth):
        num_nodes_in_level = len(tree[level])
        for i in range(0, num_nodes_in_level, 2):
            left_child_pos = (level, i)
            right_child_pos = (level, i + 1)
            if left_child_pos in can_compute and right_child_pos in can_compute:
                parent_index = i // 2
                can_compute.add((level + 1, parent_index))

    # 2. 收集所有必需的兄弟节点。
    proof_candidates = {}  # 使用字典 {(level, index): hash} 来去重并帮助排序
    for leaf_index in indices_to_reveal:
        current_index = leaf_index
        for level in range(tree_depth):
            sibling_index = current_index ^ 1  # 快速计算兄弟索引
            sibling_pos = (level, sibling_index)

            if sibling_pos not in can_compute:
                if sibling_index < len(tree[level]):
                    proof_candidates[sibling_pos] = tree[level][sibling_index]

            current_index //= 2  # 移动到父节点

    # 3. 按位置确定性地排序哈希，这至关重要。
    sorted_positions = sorted(proof_candidates.keys())
    proof_hashes = [proof_candidates[pos] for pos in sorted_positions]

    return proof_hashes


def verify_batch_merkle_proof(
        root: bytes,
        batch_proof: List[bytes],
        revealed_leaf_hashes: dict[int, bytes],
        total_num_leaves: int
) -> bool:
    """
    【最终工作且高效版】验证者函数。
    此版本与签名者执行完全对称的逻辑来确定证明的结构，
    然后用收到的证明数据填充该结构，并最终验证所有路径。
    """
    if total_num_leaves == 0:
        return root == H(b'') and not batch_proof

    tree_depth = (total_num_leaves - 1).bit_length() if total_num_leaves > 0 else 0

    # 1. 验证者必须以与签名者完全相同的方式，自己计算出 can_compute 集合。
    can_compute = set((0, i) for i in revealed_leaf_hashes.keys())

    # 为了正确处理 padding，我们需要知道每层的（补齐后）节点数
    level_sizes = [total_num_leaves]
    size = total_num_leaves
    for _ in range(tree_depth):
        size += (size % 2)
        level_sizes.append(size)
        size //= 2

    for level in range(tree_depth):
        num_nodes_in_level = level_sizes[level]
        for i in range(0, num_nodes_in_level, 2):
            if (level, i) in can_compute and (level, i + 1) in can_compute:
                can_compute.add((level + 1, i // 2))

    # 2. 验证者必须以与签名者完全相同的方式，计算出期望的证明哈希的位置。
    expected_proof_pos = {}
    for leaf_index in revealed_leaf_hashes.keys():
        current_index = leaf_index
        for level in range(tree_depth):
            sibling_index = current_index ^ 1
            if (level, sibling_index) not in can_compute:
                if sibling_index < level_sizes[level]:
                    expected_proof_pos[(level, sibling_index)] = None
            current_index //= 2

    sorted_pos = sorted(expected_proof_pos.keys())

    if len(batch_proof) != len(sorted_pos):
        return False  # 证明长度与期望的不匹配

    # 3. 将收到的证明哈希填充到哈希缓存中。
    all_hashes = {(0, idx): h for idx, h in revealed_leaf_hashes.items()}
    for pos, proof_hash in zip(sorted_pos, batch_proof):
        all_hashes[pos] = proof_hash

    # 4. 现在，有了完整的哈希集，为每个被揭示的叶子验证其路径。
    for leaf_index in revealed_leaf_hashes.keys():
        current_hash = all_hashes[(0, leaf_index)]
        current_index = leaf_index
        for level in range(tree_depth):
            sibling_index = current_index ^ 1

            # 最后一个奇数节点的兄弟是它自己，build_tree 时已复制，
            # verifier 的 all_hashes 中可能没有，需要特殊处理
            if (level, sibling_index) not in all_hashes:
                if sibling_index == current_index + 1 and sibling_index == level_sizes[level]:
                    # This is the node that was added as padding
                    sibling_hash = current_hash
                else:
                    return False  # 需要的哈希不在任何地方
            else:
                sibling_hash = all_hashes.get((level, sibling_index))

            if current_index % 2 == 0:
                current_hash = H(current_hash, sibling_hash)
            else:
                current_hash = H(sibling_hash, current_hash)
            current_index //= 2

            # 将计算出的父节点哈希加入缓存，供其他路径验证时使用
            all_hashes[(level + 1, current_index)] = current_hash

        if current_hash != root:
            return False

    return True