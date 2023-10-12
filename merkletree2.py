import hashlib
import random
import datetime

def data(): # generate a single item of data (single digit integer)
    data = random.randint(0, 9)
    return data

def dataset(length): # create example dataset of generated data, of desired length
    dataset = []
    while len(dataset) < length:
        dataset.append(data())
    return dataset

def item_transfer(dataset): # remove item from dataset and return item
    length = len(dataset)
    index = random.randint(0, length - 1)
    return dataset.pop(index)

# ^^^ example dataset (implement as OOP) ^^^

class exampleDataset: 
    def __init__(self, length):
        self.dataset = []
        self.length = length # desired length of example dataset

    def data_gen(self): # generate single item of data
            data = random.randint(0, 9)
            return data

    def set(self): # generate dataset 
        while len(self.dataset) < self.length:
            data = self.data_gen()
            self.dataset.append(data)
        return self.dataset
    
    def item_transfer(self): # transfer element out of dataset
        length = len(self.dataset)
        index = random.randint(0, length - 1)
        return self.dataset.pop(index)
    
# example dataset class testing 
class treeNode: # node class to store all transactions individually in nodes
    def __init__(self, dataset):
        self.dataset = dataset
        self.node = []
        self.fill()

    def fill(self): # take one element of data from dataset and form node (hashed)
        self.item = item_transfer(self.dataset)
        self.hash_input = f"{self.item}".encode("utf-8")
        self.hash = hashlib.sha256(self.hash_input).hexdigest()
        self.node.append(self.hash)

    def repr(self): # string representation of node
        return str(self.node[0])

class merkleTree: # data structure class to store transaction data
    # ONLY MERKLE ROOT IS STORED ON CHAIN NETWORK
    def __init__(self, dataset):
        self.dataset = dataset
        self.tree = []
        self.lvl_count = -1
        self.leaf_level = self.leaf_lvl()
        self.merkleRoot = None # why does calling the method not return what it should return (recursive function)
        self.merkle_root()

    def leaf_lvl(self): # generate first level of hashed transactions in pairs 
        if len(self.dataset) % 2 == 0: # check leaf length is even because merkle trees are a form of binary tree
            self.nxt_lvl()
            while len(self.dataset) > 0: # generate leaf nodes, append to leaf level until dataset is empty
                leaf_node = treeNode(self.dataset).repr()
                self.tree[self.lvl_count].append(leaf_node)
        else: # duplicate last element in dataset and add to level to make length even
            duplicate = self.dataset[-1] 
            self.dataset.append(duplicate)
            self.leaf_lvl() 
        return self.tree[0]

    def nxt_lvl(self): # generate next level in tree
            self.nxt = []
            self.tree.append(self.nxt)
            self.lvl_count += 1
            return self.lvl_count # returns incremented lvl count for lvl count reassignment
        
    
    def merkle_root(self):
        transfer = []
        i_count = 0
        for i in self.tree[-1]: # generate parent nodes from child nodes of current level
            i_count += 1
            if i_count % 2 == 0:
                transfer.append([self.tree[-1][(self.tree[-1].index(i))-1], i])
            else:
                pass

        self.nxt_lvl() # generate the next level in tree

        for pair in transfer: # fill next level with the generated parent nodes
            hash_input = (str(pair[0]) + str(pair[1])).encode("utf-8")
            parent_node = hashlib.sha256(hash_input).hexdigest()
            self.tree[self.lvl_count].append(parent_node)
        for pair in transfer:
            transfer.pop(transfer.index(pair)) # empty transfer

        if len(self.tree[-1]) > 1:
            self.merkle_root() # recurisely generate next level

        else: # merkle root has been reached
            root = (self.tree[self.lvl_count][0])
            self.merkleRoot = root
            return root

    def merkle_proof(self): # check efficiently if merkle root belongs to tree given some data (guarentees tree integrity untampered)
        # START WITH A LEAF NODE (requires all the nodes along the path from this leaf node to the root node)
        pass

    def vis_repr(self): # visual representation of tree
        # label each node in tree as f-string using T0, T1, T2, T3 -> H(T0, T1), H(T2, T3) -> H(H(T0, T1), H(T2, T3)) notation
        # assign labelled nodes 
        pass

# testing 
# ds = dataset(8)
# Tree = merkleTree(ds)
# Tree.leaf_lvl()
# Tree.merkle_root()

# testing (imperfect length)
# ds2 = dataset(7)
# Tree2 = merkleTree(ds2)
# Tree2.leaf_lvl()
# Tree2.merkle_root()

# testing (dataset class)
# ds3 = exampleDataset(8).set()
# print(ds3)
# Tree3 = merkleTree(ds3)
# Tree3.leaf_lvl()
# Tree3.merkle_root()

# testing (dataset class uneven dataset)
# ds4 = dataset(7)
# Tree4 = merkleTree(ds4)
# Tree4.leaf_lvl()
# Tree4.merkle_root()

# testing (dataset class not a power of 2 leaf level)
ds5 = exampleDataset(9).set()
Tree5 = merkleTree(ds5)
# # print(list(enumerate(Tree5.tree)))
# for level in Tree5.tree:
#     print(list(enumerate(level)))
# print(Tree5.tree)
print(Tree5.merkleRoot)
# print(Tree5.leaf_level)

# block class


    


# blockchain class



# user class



# node class

# current objectives:
# deal with leaf levels of lengths outside powers of 2, example dataset OOP implementation, merkle proof method, merkle tree vis method
# block class, blockchain class
# transaction class, user class
# transaction format and hash prepping
# RSA function, SHA-256 function

# users generate transactions -> transactions picked up by nodes in network -> transactions sorted into blocks and block uploaded to blockchain network