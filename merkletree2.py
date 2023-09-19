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

    def fill(self):
        self.item = item_transfer(self.dataset)
        self.hash_input = f"{self.item}".encode("utf-8")
        self.hash = hashlib.sha256(self.hash_input).hexdigest()
        self.node.append(self.hash)

    def reveal(self):
        print(self.node)

eg_node = Node(ds)
eg_node.fill()
eg_node.reveal()


# ^^^ allocate half the dataset to nodes in pairs and represent data in nodes as hashes ^^^

# ^^^ allocate half of the new smaller dataset to the node pairs, represented by a hash using the contatenated hashes of the child nodes ^^^

# ^^^ recursively replicate the process unti a Merkle root is reached, containing the concatenated hashes of the whole tree ^^^