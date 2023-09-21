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
        

tree = [[[1, 2], [1, 2], [1, 2], [1, 2]]]
lvl_count = 0
def tree_recursion(tree, lvl_count):
    if len(tree[lvl_count]) > 1:
        level = []
        transfer = []
        tree.append(level)
        lvl_count = lvl_count + 1
        for pair in tree[(lvl_count -1)]:
            hash_input = pair[0] + pair[1]
            parent_node = hashlib.sha256(str(hash_input).encode("utf-8")).hexdigest()
            transfer.append(parent_node)
        while len(transfer) > 0: # ! uneven tree case (if its even possible)
            for i in transfer:
                node_pair = [transfer.pop(transfer.index(i)), transfer.pop(transfer.index(i)+1)] # ! next element after i does not exist after i is popped, out of range error
                print(node_pair)
                tree[lvl_count].append(node_pair)
        tree_recursion(tree, lvl_count)
    else:
        return tree[lvl_count][0]

tree_recursion(tree, lvl_count)



# for each node pair of hashes from transactions, create a hash representing the pair, this is the parent node