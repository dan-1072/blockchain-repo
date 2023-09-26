import hashlib
import random

def data():
    data = random.randint(0, 9)
    return data

def dataset(length):
    dataset = []
    while len(dataset) < length:
        dataset.append(data())
    return dataset

def remove(dataset):
    length = len(dataset)
    index = random.randint(0, length)
    return dataset.pop(index)

def item_transfer(dataset):
    length = len(dataset)
    index = random.randint(0, length)
    return dataset.pop(index)

ds = dataset(20)

# ^^^ example dataset ^^^

class Node:
    def __init__(self, dataset):
        self.dataset = dataset
        self.node = []
        self.fill()

    def fill(self):
        self.item = item_transfer(self.dataset)
        self.hash_input = f"{self.item}".encode("utf-8")
        self.hash = hashlib.sha256(self.hash_input).hexdigest()
        self.node.append(self.hash)

    def repr(self):
        return str(self.node[0])

# ^^^ allocate half the dataset to nodes in pairs and represent data in nodes as hashes ^^^

class merkleTree:
    def __init__(self, dataset):
        self.dataset = dataset
        self.tree = []

    def leaf_nodes(self):
        while len(self.dataset) > 0:
            if len(self.dataset) > 1:
                node_pair = [Node(self.dataset).repr(), Node(self.dataset).repr()]
                self.tree.append(node_pair)
            elif len(self.dataset) == 1:
                node1 = Node(self.dataset).repr()
                node2 = f"{node1}"
                node_pair = [node1, node2]
                self.tree.append(node_pair)
    
    def tree_gen(self):
        for pair in self.tree:
            hash_input = pair[0] + pair[1]
            parent_node = hashlib.sha256(hash_input).hexdigest()
        

# tree = [[[1, 2], [1, 2], [1, 2], [1, 2]]]
# lvl_count = 0



# def tree_recursion(tree, lvl_count):
#     if len(tree[lvl_count]) > 1:
#         level = []
#         transfer = []
#         tree.append(level)
#         lvl_count = lvl_count + 1
#         for pair in tree[(lvl_count)]:
#             hash_input = pair[0] + pair[1]
#             parent_node = hashlib.sha256(str(hash_input).encode("utf-8")).hexdigest()
#             transfer.append(parent_node)
#         print(transfer)
#         while len(transfer) > 0: # ! uneven tree case (if its even possible)
#             for i in transfer:
#                 child1 = transfer.pop(transfer.index(i))# ! next element after i does not exist after i is popped, out of range error
#                 child2 = transfer.pop(transfer.index(i)+1)
#                 node_pair = [child1, child2]
#                 print(node_pair)
#                 tree[lvl_count].append(node_pair)
#         tree_recursion(tree, lvl_count)
#     else:
#         return tree[lvl_count][0]

# tree_recursion(tree, lvl_count)


# tree recursion: tree contains lists (levels), leaf level = 0, append all leaf nodes to leaf level, pair up leaf nodes, create nxt lvl, append hashed
# pairs to nxt lvl, create pairs from nxt lvl, hash pairs, append to nxt nxt lvl, repeat until len(n  nxt lvl) = 1

tree = []
lvl_count = -1

def nxt_lvl(tree, lvl_count): # generate next level in tree
    nxt_lvl = []
    tree.append(nxt_lvl)
    lvl_count += 1
    return lvl_count # returns incremented level count for lvl_count reassignment 

def leaf_lvl(tree, leaf_size): # generate initial leaf nodes for first tree level
    nxt_lvl(tree, lvl_count)
    while len(tree[0]) < leaf_size:
        tree[0].append(random.randint(10, 99))

def lvl_fill(tree):
    transfer = []
    i_count = 0
    for i in tree[-1]: # generate parent nodes from child nodes of current level
        i_count += 1
        if i_count % 2 == 0:
            transfer.append([tree[-1][(tree[-1].index(i))-1], i])
        else:
            pass

    nxt_lvl(tree, lvl_count) # generate the next level in tree

    for pair in transfer: # fill next level with the generated parent nodes
        hash_input = (str(pair[0]) + str(pair[1])).encode("utf-8")
        parent_node = hashlib.sha256(hash_input).hexdigest()
        tree[lvl_count].append(parent_node)
    for pair in transfer:
        transfer.pop(transfer.index(pair)) # empty transfer

    if len(tree[-1]) > 1:
        lvl_fill(tree)

    else:
        return tree[-1][0]

    

# generate leaf nodes
# generate next level
# generate parent nodes from leaves
# generate next level
# generate parent nodes from last level
# generate next level 
# recursion 

leaf_lvl(tree, 8)
lvl_fill(tree)

# for each node pair of hashes from transactions, create a hash representing the pair, this is the parent node