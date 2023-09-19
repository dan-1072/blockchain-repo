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

    def generate(self):
        while len(self.dataset) > 0:
            if len(self.dataset) > 1:
                node_pair = [Node(self.dataset).repr(), Node(self.dataset).repr()]
                self.tree.append(node_pair)
            elif len(self.dataset) == 1:
                node1 = Node(self.dataset).repr()
                node2 = f"{node1}"
                node_pair = [node1, node2]
                self.tree.append(node_pair)
        for pair in self.tree:
            hash_input = pair[0] + pair[1]
            

# ^^^ allocate half of the new smaller dataset to the node pairs, represented by a hash using the contatenated hashes of the child nodes ^^^

# ^^^ recursively replicate the process unti a Merkle root is reached, containing the concatenated hashes of the whole tree ^^^