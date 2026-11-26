import hashlib
import unittest

from prooftask.conformity._registration import inclusion_root


def tree_root(leaves):
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + tree_root(leaves[:split]) + tree_root(leaves[split:])).digest()


def audit_path(leaves, index):
    if len(leaves) == 1:
        return []
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < split:
        return audit_path(leaves[:split], index) + [tree_root(leaves[split:]).hex()]
    return audit_path(leaves[split:], index - split) + [tree_root(leaves[:split]).hex()]


class RegistrationInclusionTests(unittest.TestCase):
    def test_each_leaf_in_balanced_and_unbalanced_trees(self):
        for size in (1, 2, 3, 5, 7, 8, 15, 16, 17):
            leaves = [bytes([n]) for n in range(size)]
            root = tree_root(leaves).hex()
            for index, leaf in enumerate(leaves):
                with self.subTest(size=size, index=index):
                    path = audit_path(leaves, index)
                    self.assertEqual(inclusion_root(leaf, index, size, path), root)
                    with self.assertRaises(ValueError):
                        inclusion_root(leaf, index, size, path + ["00" * 32])
                    if path:
                        with self.assertRaises(ValueError):
                            inclusion_root(leaf, index, size, path[:-1])
