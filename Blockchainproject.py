import hashlib
import time
from typing import List, Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
""

class Block:
    """
    A class representing a single block in the blockchain.

    Attributes:
    - index: Numerical index of the block in the blockchain.
    - transactions: List of transactions included in the block.
    - timestamp: Time when the block was created.
    - previous_hash: Hash of the previous block in the chain.
    - difficulty: Difficulty level for mining the block.
    - nonce: Random value used in mining to find a valid hash.
    - merkle_root: Merkle root of the transactions.
    - hash: Hash of the block.
    """
    def __init__(self, index, transactions, previous_hash, difficulty=2):
        self.index = index
        self.transactions = transactions
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.difficulty = difficulty
        self.nonce = 0
        self.merkle_root = self.compute_merkle_root(transactions)
        self.hash = self.compute_hash()

    def compute_hash(self):
        """
        Computes the hash of the block by hashing its contents.
        """
        block_content = f"{self.index}{self.timestamp}{self.previous_hash}{self.merkle_root}{self.nonce}"
        return hashlib.sha256(block_content.encode()).hexdigest()

    def compute_merkle_root(self, transactions: List[Any]) -> str:
        """
        Computes the Merkle root of the transactions in the block.
        """
        if not transactions:
            return ''

        transaction_hashes = [hashlib.sha256(str(tx).encode()).hexdigest() for tx in transactions]

        def merkle(trans_hashes):
            if len(trans_hashes) == 1:
                return trans_hashes[0]

            if len(trans_hashes) % 2 != 0:
                trans_hashes.append(trans_hashes[-1])

            updated_hashes = [hashlib.sha256((trans_hashes[i] + trans_hashes[i+1]).encode()).hexdigest()
                              for i in range(0, len(trans_hashes), 2)]

            return merkle(updated_hashes)

        return merkle(transaction_hashes)

    def mine_block(self):
        """
        Mines the block by finding a nonce that produces a hash meeting the difficulty criteria.
        """
        target = '0' * self.difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.compute_hash()

class Blockchain:
    """
    A class representing a simple blockchain.

    Attributes:
    - chain: List of blocks that form the blockchain.
    - difficulty: Difficulty level for mining new blocks.
    """
    def __init__(self):
        self.chain = []
        self.difficulty = 2
        self.create_genesis_block()

    def create_genesis_block(self):
        """
        Creates the genesis block and adds it to the blockchain.
        """
        genesis_block = Block(0, [], "0", self.difficulty)
        genesis_block.mine_block()
        self.chain.append(genesis_block)

    def add_new_block(self, transactions):
        """
        Adds a new block with the given transactions to the blockchain.
        Before adding a new block, verify all transactions in it.
        """
        for transaction in transactions:
            if not transaction.verify_transaction(transaction.sender):
                raise Exception("Invalid transaction")
        last_block = self.chain[-1]
        new_block = Block(last_block.index + 1, transactions, last_block.hash, self.difficulty)
        new_block.mine_block()
        self.chain.append(new_block)   
        

    def print_chain(self):
        """
        Prints the contents of each block in the blockchain.
        """
        for block in self.chain:
            print(f"Index: {block.index}, Timestamp: {block.timestamp}, Prev Hash: {block.previous_hash}, "
                  f"Hash: {block.hash}, Difficulty: {block.difficulty}, Nonce: {block.nonce}, "
                  f"Merkle Root: {block.merkle_root}, Transactions: {block.transactions}")


# implement pay-to-public-key-hash (P2PKH) transactions and verify transactions.
#a) Implement pay-to-public-key-hash (P2PKH) transactions.
#b) Use asymmetric cryptography to create digital signatures and verify transactions.
class Transaction:
    "a class define the "
    def __init__(self, sender, recipient, amount):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = None

    def sign_transaction(self, private_key):
        self.signature = private_key.sign(
            self.hash().encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return self.signature

    def verify_transaction(self, public_key):
        try:
            public_key.verify(
                self.signature,
                self.hash().encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    def hash(self):
        sender_hex = self.sender.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        recipient_hex = self.recipient.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        return hashlib.sha256((sender_hex + recipient_hex + str(self.amount)).encode()).hexdigest()

# Example Usage

# 生成 sender1 和 recipient1 的公钥和私钥
sender1_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
sender1 = sender1_private_key.public_key()

recipient1_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
recipient1 = recipient1_private_key.public_key()

# 设置转移的金额
amount1 = 100

sender2_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
sender2 = sender2_private_key.public_key()

recipient2_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
recipient2 = recipient1_private_key.public_key()

# 设置转移的金额
amount2 = 200


blockchain = Blockchain()
transaction1 = Transaction(sender1, recipient1, amount1)
transaction2 = Transaction(sender2, recipient2, amount2)
transaction2.sign_transaction(sender2_private_key)
transaction1.sign_transaction(sender1_private_key)
blockchain.add_new_block([transaction1, transaction2])
blockchain.print_chain()
print("Transaction 1 verified: ", transaction1.verify_transaction(sender1))
print("Transaction 2 verified: ", transaction2.verify_transaction(sender2))

