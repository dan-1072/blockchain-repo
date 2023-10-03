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

# ^^^ example dataset (implement as OOP) ^^^

class Node: # node class to store all transactions individually in nodes
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


class merkleTree:
    def __init__(self, dataset):
        self.dataset = dataset
        self.tree = []
        self.lvl_count = -1

    def leaf_lvl(self): # generate first level of hashed transactions in pairs 
        while len(self.dataset) > 0:
            if len(self.dataset) > 1:
                node_pair = [Node(self.dataset).repr(), Node(self.dataset).repr()]
                self.tree.append(node_pair)
            elif len(self.dataset) == 1:
                node1 = Node(self.dataset).repr()
                node2 = f"{node1}"
                node_pair = [node1, node2]
                self.tree.append(node_pair)
        self.lvl_count += 1
        return self.tree[self.lvl_count]

    def nxt_lvl(self): # generate next level in tree
        self.nxt = []
        self.tree.append(self.nxt)
        self.lvl_count += 1
        return self.lvl_count # returns incremented lvl count for lvl count reassignment
        
    
    def tree_gen(self):
        transfer = []
        i_count = 0
        for i in self.tree[-1]: # generate parent nodes from child nodes of current level
            i_count += 1
            if i_count % 2 == 0:
                transfer.append([self.tree[-1][(self.tree[-1].index(i))-1], i])
            else:
                pass

        self.nxt_lvl(self.tree, self.lvl_count) # generate the next level in tree

        for pair in transfer: # fill next level with the generated parent nodes
            hash_input = (str(pair[0]) + str(pair[1])).encode("utf-8")
            parent_node = hashlib.sha256(hash_input).hexdigest()
            self.tree[self.lvl_count].append(parent_node)
        for pair in transfer:
            transfer.pop(transfer.index(pair)) # empty transfer

        if len(self.tree[-1]) > 1:
            self.tree_gen()

        else:
            return self.tree[-1][0]
        pass

ds = dataset(20)
Tree = merkleTree(ds)
Tree.leaf_lvl()

# tree = []
# lvl_count = -1

# def nxt_lvl(tree, lvl_count): # generate next level in tree
#     nxt_lvl = []
#     tree.append(nxt_lvl)
#     lvl_count += 1
#     return lvl_count # returns incremented level count for lvl_count reassignment 

# def leaf_lvl(tree, leaf_size): # generate initial leaf nodes for first tree level
#     nxt_lvl(tree, lvl_count)
#     while len(tree[0]) < leaf_size:
#         tree[0].append(random.randint(10, 99))

# def lvl_fill(tree):
    # transfer = []
    # i_count = 0
    # for i in tree[-1]: # generate parent nodes from child nodes of current level
    #     i_count += 1
    #     if i_count % 2 == 0:
    #         transfer.append([tree[-1][(tree[-1].index(i))-1], i])
    #     else:
    #         pass

    # nxt_lvl(tree, lvl_count) # generate the next level in tree

    # for pair in transfer: # fill next level with the generated parent nodes
    #     hash_input = (str(pair[0]) + str(pair[1])).encode("utf-8")
    #     parent_node = hashlib.sha256(hash_input).hexdigest()
    #     tree[lvl_count].append(parent_node)
    # for pair in transfer:
    #     transfer.pop(transfer.index(pair)) # empty transfer

    # if len(tree[-1]) > 1:
    #     lvl_fill(tree)

    # else:
    #     return tree[-1][0]