import hashlib
import json
import sys


def largest_power_of_2(n):
    power = 1
    while power * 2 < n:
        power *= 2
    return power

def is_power_of_two(num):
    if num <= 0:
        return False
    else:
        return (num & (num - 1)) == 0

class Node:
    def __init__(self, left, right, hashHex, content, leaves, is_copied=False):
        self.left: Node = left
        self.right: Node = right
        self.hashHex = hashHex
        self.content = content
        self.is_copied = is_copied
        self.parent = None
        self.leaves = leaves
    
    def hash(val):
        return hashlib.sha256(val.encode('utf-8')).hexdigest()
 
    def copy(self):
        return Node(self.left, self.right, self.hashHex, self.content, self.leaves, True)
    
class MerkleTree:
    def __init__(self, contents):
        self.buildTree(contents)
        self.jsonTree = self.printTree()
        self.height =  self.getTreeHeight(self.root)
        self.root
        self.leaves
        self.hashLeaves
        
    def getRootHash(self):
      return self.root.hashHex

    def buildTree(self, contents):
        leaves: list = [Node(None, None, Node.hash(el), el, [Node.hash(el)]) for el in contents]
        hashLeaves: list = [Node.hash(el) for el in contents]
        self.leaves = leaves
        self.hashLeaves = hashLeaves
        self.nodeCount = len(self.leaves)
        
        self.root: Node = self.buildTreeRecursive(leaves)


    def buildTreeRecursive(self, nodes):
        x =  len(nodes) 
        if not is_power_of_two(x):
            leftHalf: int = int(largest_power_of_2(x))
            rightHalf: int = int(x - leftHalf)
        else:
            leftHalf: int = len(nodes) // 2
            rightHalf: int = x - leftHalf
 
        if len(nodes) == 2:
            self.nodeCount+=1
            return Node(nodes[0], nodes[1], Node.hash(nodes[0].hashHex + nodes[1].hashHex), 
                        nodes[0].content+"+"+nodes[1].content, 
                         nodes[0].leaves + nodes[1].leaves)
        elif len(nodes) == 1:
            self.nodeCount+=1
            return nodes[0]

        left: Node = self.buildTreeRecursive(nodes[:leftHalf])
        if left.left:
            left.left.parent = left
        if left.right:
            left.right.parent = left
        right: Node = self.buildTreeRecursive(nodes[-rightHalf:])
        if right.left:
            right.left.parent = right
        if right.right:
            right.right.parent = right
        hashHex: str = Node.hash(left.hashHex + right.hashHex)
        content: str = f'{left.content}+{right.content}'
        current_node = Node(left, right, hashHex, content, left.leaves + right.leaves)
        current_node.left.parent = current_node
        current_node.right.parent = current_node

        self.nodeCount+=1
        return current_node

    
    def printTree(self, current_node=None):
        if not current_node:
            current_node = self.root
        mTree = {'content': current_node.content,
                'hashHex' : current_node.hashHex,
                'parent' : current_node.parent.content if current_node.parent is not None else None,
                #  'leaves' : current_node.leaves,
                'is_copied' : current_node.is_copied }
        if current_node.left:
            mTree.update({'left': self.printTree(current_node.left)})
        else:
            mTree.update({'left': None})
        if current_node.right:
            mTree.update({'right': self.printTree(current_node.right)})
        else:
            mTree.update({'right': None})
        return mTree
    
    def getTreeHeight(self, node):
        if node is None:
            return 0
        else:
            # Compute the height of each subtree
            lheight = self.getTreeHeight(node.left)
            rheight = self.getTreeHeight(node.right)
    
            # Use the larger one
            if lheight > rheight:
                return lheight+1
            else:
                return rheight+1
            

    @classmethod
    def getTreeHeight(cls, node):
        if node is None:
            return 0
        else:
            # Compute the height of each subtree
            lheight = cls.getTreeHeight(node.left)
            rheight = cls.getTreeHeight(node.right)
    
            # Use the larger one
            if lheight > rheight:
                return lheight+1
            else:
                return rheight+1
    
    @classmethod
    def buildJsonTree(cls, file):
        f = open(file)
        mTreeJson = json.load(f)

        cls.leaves = []
        cls.hashLeaves = []
        cls.root: Node = cls.buildJsonTreeRecursive(mTreeJson)
        cls.height = cls.getTreeHeight(cls.root)

        return cls

    @classmethod
    def buildJsonTreeRecursive(cls, mTreeJson):
        if mTreeJson['left'] == None or mTreeJson['right'] == None:
                node = Node(None, None, mTreeJson['hashHex'], mTreeJson['content'], 
                            # mTreeJson['leaves'],
                            mTreeJson['is_copied'])
                cls.leaves.append(node)
                cls.hashLeaves.append(mTreeJson['hashHex'])
                return node
        
        left: Node = cls.buildJsonTreeRecursive(mTreeJson['left'])
        right: Node = cls.buildJsonTreeRecursive(mTreeJson['right'])

        current_node = Node(left, right, mTreeJson['hashHex'], mTreeJson['content'],
                            #  mTreeJson['leaves'], 
                             mTreeJson['is_copied'])
        left.parent = current_node
        right.parent = current_node

        return current_node
    
    def checkInclusion(mTree, iterNode):

        comparator = iterNode.hashHex
        proofs = []
        while iterNode.hashHex != mTree.root.hashHex:
            if iterNode.parent.left.hashHex == comparator:
                proofs.append(iterNode.parent.right.hashHex)
                newHash = iterNode.hashHex + iterNode.parent.right.hashHex
                comparator = hashlib.sha256(newHash.encode('utf-8')).hexdigest()
            elif iterNode.parent.right.hashHex == comparator:
                proofs.append(iterNode.parent.left.hashHex)
                newHash = iterNode.parent.left.hashHex + iterNode.hashHex
                comparator = hashlib.sha256(newHash.encode('utf-8')).hexdigest()
            else:
                print("no")

            iterNode = iterNode.parent

        if mTree.root.hashHex == comparator:
            return proofs
        else:
            return None


def levelOrderTraverse(root, subRoot):
    if root is None:
        return
    queue = []
 
    queue.append(root)
 
    while(len(queue) > 0):
        node = queue.pop(0)

        if node.hashHex == subRoot.hashHex:
            return node
 
        if node.left is not None:
            queue.append(node.left)
 
        if node.right is not None:
            queue.append(node.right)
    
    return None

def consistencyProof(m, k, n, mTree, subTree, proof = []):
    if m == n:
        if mTree.hashHex != subTree.root.hashHex:
            proof.append((mTree.hashHex, mTree.content))
        return
    elif m <= k:
        # """If m <= k, the right subtree entries D[k:n] only exist in the current
        # tree.  We prove that the left subtree entries D[0:k] are consistent
        # and add a commitment to D[k:n]:"""
        n = len(mTree.left.leaves)
        k = largest_power_of_2(n)
        proof.append(mTree.right.hashHex)
        consistencyProof(m, k, n, mTree.left, subTree, proof)
            
    elif m > k:
        # """If m > k, the left subtree entries D[0:k] are identical in both
        # trees.  We prove that the right subtree entries D[k:n] are consistent
        # and add a commitment to D[0:k]."""
        newM = m - k
        n = len(mTree.right.leaves)
        k = largest_power_of_2(n)
        proof.append(mTree.left.hashHex)
        consistencyProof(newM,k, n, mTree.right, subTree)

    return proof

def is_ordered_subset(list1, list2):
    if len(list1) > len(list2):
        return False
    for i in range(len(list1)):
        if list1[i] != list2[i]:
            return False
    return True


def checkConsistency(subTree: MerkleTree, bigTree: MerkleTree):
    leftSubTree = subTree.root.left
    rightSubTree = subTree.root.right

    bigTreeLeft = levelOrderTraverse(bigTree.root, leftSubTree)
    bigTreeRight = levelOrderTraverse(bigTree.root, rightSubTree)
    # while (bigTreeRight is None and rightSubTree.left is not None):
    #     rightSubTree = rightSubTree.left
    #     bigTreeRight = levelOrderTraverse(bigTree.root, rightSubTree)


    m = len(subTree.leaves)
    n = len(bigTree.leaves)
    k = largest_power_of_2(n)

    isSubset = (bigTreeLeft is not None) & (bigTreeRight is not None)
    isOrderedSubset = is_ordered_subset(subTree.root.leaves, bigTree.root.leaves)

    proof = []
    if isSubset & isOrderedSubset:
        proof = consistencyProof(m, k, n, bigTree.root, subTree)
        proof = [subTree.root.hashHex] + proof + [bigTree.root.hashHex]

        # print('yes', proof)
        return ('yes', proof)
    else:
        # print("no")
        return ('no')


