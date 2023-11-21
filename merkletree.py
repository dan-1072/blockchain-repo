import hashlib
import random
import datetime

class MerkleNode:
    '''represents one node made up of the hash of two concatenated child nodes'''
    def __init__(self, left_node, right_node, hash_value): # tree is made by merkle nodes linking to eachother through attributes
        self.left_node = left_node
        self.right_node = right_node
        self.hash = hash_value
    
    def get_hash(self):
        return self.hash
    
class MerkleTree:

    def __init__(self, dataset):
        self.dataset = dataset
        self.tree = self.build_tree()
        self.root = self.get_root()

    def calculate_hash(self, left, right): # may be used to make leaf nodes (left and right are from dataset) or other nodes (L and R are hashes)
        '''takes two elements, converts them to strings, concatenates them, and calculates the hash of this concatenation'''
        hash_input = str(left) + str(right)
        hashed = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
        return hashed

    def build_tree(self):
        '''builds the merkle tree of merkle nodes, providing a merkle root representing the hash of all nodes'''
        leaf_nodes = []
        # add hashed dataset values into leaf level in string form
        for data in self.dataset:
            hash_input = str(data) # convert to string
            hashed_data = hashlib.sha256(hash_input.encode()).hexdigest()
            leaf_nodes.append(hashed_data)

        tree = [leaf_nodes]
        # generate parent nodes from child nodes in previous level
        while len(tree[-1]) > 1: # generate next level until the root is reached  (level of length 1)
            parent_nodes = []
            for node in tree[-1][0:len(tree[-1]):2]: # tree[-1] is the current level of the tree
                left_node = node
                if left_node != tree[-1][-1]: # if left node isnt the last node then there is a right node
                    right_index = tree[-1].index(node) + 1
                    right_node = tree[-1][right_index]
                else:
                    right_node = None
                parent_hash = self.calculate_hash(left_node, right_node)
                parent = MerkleNode(left_node, right_node, parent_hash)
                parent_nodes.append(parent.get_hash())
            tree.append(parent_nodes)
        return(tree)
    
    def get_root(self):
        root = self.tree[-1][0]
        return root
    
    def merkle_proof(self, target_node):
        '''generates the sibling nodes that are in the path the target node takes to the root'''
        target_node = hashlib.sha256(str(target_node).encode('utf-8')).hexdigest() # get target node into its leaf level form
        proof_path = []
        root_reached = False 
        current_level = 0 # index of current level 
        while root_reached == False: # traverse tree from target node to root 
            # pick up sibling nodes during traversal and add to proof path
            for node in self.tree[current_level][0:len(self.tree[current_level]):2]: # look at every other node (first node of a pair) 
                left_node = node
                if self.tree[current_level][-1] != node: # if left node isnt last node in tree
                    right_index = self.tree[current_level].index(left_node) + 1 # one index after left node in the current level
                    right_node = self.tree[current_level][right_index] 
                # check if target node is either of the nodes just defined in the pair
                if left_node == target_node: 
                    proof_path.append(right_node)
                    target_node = self.calculate_hash(left_node, right_node) # target node for next level (hash of child nodes)
                elif right_node == target_node:
                    proof_path.append(left_node)
                    target_node = self.calculate_hash(left_node, right_node) # target node for next level (hash of child nodes)
            if len(self.tree[current_level + 1]) == 1: # if the next level is the root 
                root_reached = True # dont search next level (not needed for proof path)
            else:
                current_level += 1 # search next level
        return proof_path
    
    def verify_proof(self, target_node, proof):
        '''takes a proof path and reconstructs the root with it, comparing the roots to verify if the proof is valid, verifying the target node'''
        target_node = hashlib.sha256(str(target_node).encode('utf-8')).hexdigest() # get target node into its leaf level form
        for node in proof: # contatenate and hash target node with proof node, concatenate and hash the previous hash with next proof node, so on
            current_level = proof.index(node) # works because there is only one sibling node per level in the proof path
            if self.tree[current_level].index(node) % 2 == 0: # all left childs of pairs have even node index in level 
                target_node = self.calculate_hash(node, target_node) # node is left child
            elif self.tree[current_level].index(node) % 2 == 1: # all right childs of pairs have odd node index in level
                target_node = self.calculate_hash(target_node, node) # node is right child
        if target_node == self.root: # check if root generated from proof is equal to actual root
            return True
        else:
            return False

'''Merkle Tree Testing'''

dataset1 = ["Data1", "Data2", "Data3", "Data4", "Data5", "Data6", "Data7","Data8"]
tree1 = MerkleTree(dataset1)
print(tree1.tree)
proof = tree1.merkle_proof("Data3")
print(proof)
print(tree1.verify_proof("Data3", proof))