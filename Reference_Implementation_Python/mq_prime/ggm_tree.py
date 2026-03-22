# mq_prime/ggm_tree.py

import math
from .aes_prg import AES_PRG
from .hash_utils import H
from typing import List


class GGMTreeWithCache:
    """
    一个带有内部缓存的GGM树实现，支持动态种子长度 (16/24/32)。
    """

    def __init__(self, seed: bytes, depth: int):
        if not isinstance(seed, bytes):
            raise ValueError("Seed must be a bytes object.")
        # ▼▼▼ 修改：移除硬编码检查，改为由 AES_PRG 检查 ▼▼▼
        self.seed_len = len(seed)
        # ▲▲▲
        if not isinstance(depth, int) or depth < 0:
            raise ValueError("Depth must be a non-negative integer.")

        self.root_seed = seed
        self.depth = depth
        self.num_leaves = 1 << depth

        self.cache = {(0, 0): self.root_seed} if depth > 0 else {}
        if depth == 0 and self.num_leaves == 1:
            self.cache[(0, 0)] = self.root_seed

    def _get_seed(self, level: int, index: int) -> bytes:
        if (level, index) in self.cache:
            return self.cache[(level, index)]

        parent_level = level - 1
        parent_index = index // 2
        parent_seed = self._get_seed(parent_level, parent_index)

        prg = AES_PRG(parent_seed)
        # ▼▼▼ 修改：使用动态长度 ▼▼▼
        seed_left = prg.read(self.seed_len)
        seed_right = prg.read(self.seed_len)
        # ▲▲▲

        self.cache[(level, parent_index * 2)] = seed_left
        self.cache[(level, parent_index * 2 + 1)] = seed_right

        return self.cache[(level, index)]

    def get_leaf(self, index: int) -> bytes:
        if not (0 <= index < self.num_leaves):
            raise ValueError(f"Index {index} is out of bounds.")
        if self.depth == 0:
            return self.root_seed
        return self._get_seed(self.depth, index)

    def populate_all_leaves(self) -> List[bytes]:
        if self.depth == 0:
            return [self.root_seed]

        for level in range(self.depth):
            num_nodes_in_level = 1 << level
            for i in range(num_nodes_in_level):
                parent_seed = self.cache[(level, i)]

                prg = AES_PRG(parent_seed)
                # ▼▼▼ 修改：使用动态长度 ▼▼▼
                seed_left = prg.read(self.seed_len)
                seed_right = prg.read(self.seed_len)
                # ▲▲▲

                self.cache[(level + 1, i * 2)] = seed_left
                self.cache[(level + 1, i * 2 + 1)] = seed_right

        return [self.cache[(self.depth, i)] for i in range(self.num_leaves)]


class GGMTree:
    def __init__(self, seed: bytes, depth: int):
        self.root_seed = seed
        self.depth = depth
        self.num_leaves = 1 << depth
        # ▼▼▼ 修改：记录种子长度 ▼▼▼
        self.seed_len = len(seed)
        # ▲▲▲

    def get_leaf(self, index: int) -> bytes:
        if not (0 <= index < self.num_leaves):
            raise ValueError("Index out of bounds")

        current_seed = self.root_seed
        for i in range(self.depth - 1, -1, -1):
            prg = AES_PRG(current_seed)
            # ▼▼▼ 修改：使用动态长度 ▼▼▼
            seed_left = prg.read(self.seed_len)
            seed_right = prg.read(self.seed_len)
            # ▲▲▲

            bit = (index >> i) & 1
            if bit == 0:
                current_seed = seed_left
            else:
                current_seed = seed_right

        return current_seed

    def get_leaf_seed_and_path(self, index: int) -> tuple:
        if not (0 <= index < self.num_leaves):
            raise ValueError("Index out of bounds")

        current_seed = self.root_seed
        path_seeds = []

        for i in range(self.depth - 1, -1, -1):
            prg = AES_PRG(current_seed)
            # ▼▼▼ 修改：使用动态长度 ▼▼▼
            seed_left = prg.read(self.seed_len)
            seed_right = prg.read(self.seed_len)
            # ▲▲▲

            bit = (index >> i) & 1
            if bit == 0:
                current_seed = seed_left
                path_seeds.append(seed_right)
            else:
                current_seed = seed_right
                path_seeds.append(seed_left)

        return current_seed, list(reversed(path_seeds))


def verify_ggm_path(root_seed: bytes, depth: int, index: int, path: list) -> bytes:
    if len(path) != depth:
        raise ValueError("GGM path length must equal tree depth.")

    current_seed = root_seed
    seed_len = len(root_seed)  # ▼▼▼ 获取长度 ▼▼▼
    path_copy = list(reversed(path))

    for i in range(depth - 1, -1, -1):
        prg = AES_PRG(current_seed)
        # ▼▼▼ 修改：使用动态长度 ▼▼▼
        seed_left = prg.read(seed_len)
        seed_right = prg.read(seed_len)
        # ▲▲▲

        bit = (index >> i) & 1
        sister_seed = path_copy.pop(0)

        if bit == 0:
            current_seed = seed_left
            if sister_seed != seed_right:
                raise ValueError("GGM path verification failed at level {}".format(i))
        else:
            current_seed = seed_right
            if sister_seed != seed_left:
                raise ValueError("GGM path verification failed at level {}".format(i))

    return current_seed


def get_batch_ggm_path(root_seed: bytes, depth: int, indices_to_reveal: list[int]) -> list[bytes]:
    if not indices_to_reveal:
        return []

    seed_len = len(root_seed)  # ▼▼▼ 获取长度 ▼▼▼
    nodes_on_path = set()
    for index in indices_to_reveal:
        nodes_on_path.add((depth, index))
        parent_idx_in_level = index
        for level in range(depth - 1, -1, -1):
            parent_idx_in_level //= 2
            nodes_on_path.add((level, parent_idx_in_level))

    required_sisters = {}
    sorted_nodes_on_path = sorted(list(nodes_on_path))
    computed_seeds = {(0, 0): root_seed}

    for level, node_idx in sorted_nodes_on_path:
        if level >= depth:
            continue

        parent_pos = (level, node_idx)
        if parent_pos not in computed_seeds:
            continue

        parent_seed = computed_seeds[parent_pos]
        prg = AES_PRG(parent_seed)
        # ▼▼▼ 修改：使用动态长度 ▼▼▼
        seed_left = prg.read(seed_len)
        seed_right = prg.read(seed_len)
        # ▲▲▲

        left_child_pos = (level + 1, node_idx * 2)
        right_child_pos = (level + 1, node_idx * 2 + 1)

        computed_seeds[left_child_pos] = seed_left
        computed_seeds[right_child_pos] = seed_right

        if left_child_pos in nodes_on_path and right_child_pos not in nodes_on_path:
            if right_child_pos not in required_sisters:
                required_sisters[right_child_pos] = seed_right

        if right_child_pos in nodes_on_path and left_child_pos not in nodes_on_path:
            if left_child_pos not in required_sisters:
                required_sisters[left_child_pos] = seed_left

    sorted_positions = sorted(required_sisters.keys())
    return [required_sisters[pos] for pos in sorted_positions]


def verify_batch_ggm_path(
        root_seed: bytes,
        depth: int,
        revealed_leaves: dict[int, bytes],
        batch_path: list[bytes]
) -> bool:
    if not revealed_leaves:
        return not batch_path

    seed_len = len(root_seed)  # ▼▼▼ 获取长度 ▼▼▼

    nodes_on_path = set()
    for index in revealed_leaves.keys():
        nodes_on_path.add((depth, index))
        parent_idx_in_level = index
        for level in range(depth - 1, -1, -1):
            parent_idx_in_level //= 2
            nodes_on_path.add((level, parent_idx_in_level))

    expected_sister_pos = {}
    for level, node_idx in sorted(list(nodes_on_path)):
        if level >= depth: continue

        left_child_pos = (level + 1, node_idx * 2)
        right_child_pos = (level + 1, node_idx * 2 + 1)

        if left_child_pos in nodes_on_path and right_child_pos not in nodes_on_path:
            if right_child_pos not in expected_sister_pos:
                expected_sister_pos[right_child_pos] = None
        if right_child_pos in nodes_on_path and left_child_pos not in nodes_on_path:
            if left_child_pos not in expected_sister_pos:
                expected_sister_pos[left_child_pos] = None

    sorted_pos = sorted(expected_sister_pos.keys())

    if len(batch_path) != len(sorted_pos):
        return False

    all_seeds = {(0, 0): root_seed}
    for pos, proof_seed in zip(sorted_pos, batch_path):
        all_seeds[pos] = proof_seed

    q = [(0, 0)]
    visited = set()

    while q:
        level, node_idx = q.pop(0)

        if (level, node_idx) in visited or level >= depth:
            continue
        visited.add((level, node_idx))

        current_seed = all_seeds.get((level, node_idx))
        if current_seed is None:
            return False

        prg = AES_PRG(current_seed)
        # ▼▼▼ 修改：使用动态长度 ▼▼▼
        seed_left = prg.read(seed_len)
        seed_right = prg.read(seed_len)
        # ▲▲▲

        left_pos = (level + 1, node_idx * 2)
        right_pos = (level + 1, node_idx * 2 + 1)

        if left_pos not in all_seeds: all_seeds[left_pos] = seed_left
        if right_pos not in all_seeds: all_seeds[right_pos] = seed_right

        q.append(left_pos)
        q.append(right_pos)

    for index, expected_seed in revealed_leaves.items():
        calculated_seed = all_seeds.get((depth, index))
        if calculated_seed is None or calculated_seed != expected_seed:
            return False

    return True