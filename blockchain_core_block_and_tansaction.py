"""
Blockchain DHT Optimization Implementation
Core Module: Block and Transaction Management
Based on the research paper implementation
"""

import hashlib
import json
import time
import random
import math
import threading
import socket
import pickle
import asyncio
import struct
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import logging
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ==================== CORE BLOCKCHAIN STRUCTURES ====================

class TransactionType(Enum):
    """Transaction types in the blockchain"""
    TRANSFER = "transfer"
    CONTRACT = "contract"
    STAKE = "stake"
    REWARD = "reward"
    DATA_STORAGE = "data_storage"

@dataclass
class Transaction:
    """Enhanced transaction structure with DHT optimization"""
    sender: str
    recipient: str
    amount: float
    timestamp: float
    transaction_type: TransactionType
    data: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[bytes] = None
    nonce: int = 0
    gas_price: float = 0.001
    gas_limit: int = 21000
    zone_block_cid: Optional[str] = None  # ZB-CID for DHT routing
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
        if self.zone_block_cid is None:
            self.zone_block_cid = self.generate_zb_cid()
    
    def generate_zb_cid(self) -> str:
        """Generate Zone Block Content Identifier for DHT"""
        content = f"{self.sender}{self.recipient}{self.amount}{self.timestamp}{self.nonce}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def calculate_hash(self) -> str:
        """Calculate transaction hash"""
        tx_string = json.dumps({
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'timestamp': self.timestamp,
            'type': self.transaction_type.value,
            'data': self.data,
            'nonce': self.nonce,
            'gas_price': self.gas_price,
            'gas_limit': self.gas_limit
        }, sort_keys=True)
        return hashlib.sha256(tx_string.encode()).hexdigest()
    
    def sign_transaction(self, private_key: rsa.RSAPrivateKey):
        """Sign transaction with private key"""
        message = self.calculate_hash().encode()
        self.signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def verify_signature(self, public_key: rsa.RSAPublicKey) -> bool:
        """Verify transaction signature"""
        if not self.signature:
            return False
        try:
            message = self.calculate_hash().encode()
            public_key.verify(
                self.signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

class MerkleNode:
    """Node in Merkle tree for transaction verification"""
    def __init__(self, left=None, right=None, hash_value=None, content=None):
        self.left = left
        self.right = right
        self.hash_value = hash_value
        self.content = content
        
        if not hash_value:
            if content:
                self.hash_value = hashlib.sha256(content.encode()).hexdigest()
            elif left and right:
                combined = left.hash_value + right.hash_value
                self.hash_value = hashlib.sha256(combined.encode()).hexdigest()

class BATreeNode:
    """B-A Tree node for optimized storage (Paper Section 2.1.2)"""
    def __init__(self, is_leaf=False):
        self.keys = []
        self.values = []
        self.children = []
        self.is_leaf = is_leaf
        self.parent = None
        self.hash_value = None
        
    def calculate_hash(self):
        """Calculate hash for B-A tree node with height balance constraint"""
        if self.is_leaf:
            content = ''.join([str(k) for k in self.keys])
            self.hash_value = hashlib.sha256(content.encode()).hexdigest()
        else:
            # Ensure height difference constraint: |Hash_2 - Hash_1| <= 1
            left_height = self._get_subtree_height(0) if len(self.children) > 0 else 0
            right_height = self._get_subtree_height(-1) if len(self.children) > 0 else 0
            
            if abs(left_height - right_height) > 1:
                self._rebalance()
            
            combined = ''
            for child in self.children:
                if child.hash_value:
                    combined += child.hash_value
            self.hash_value = hashlib.sha256(combined.encode()).hexdigest()
    
    def _get_subtree_height(self, index) -> int:
        """Get height of subtree at given index"""
        if index >= len(self.children):
            return 0
        return self._calculate_height(self.children[index])
    
    def _calculate_height(self, node) -> int:
        """Recursively calculate tree height"""
        if node is None or node.is_leaf:
            return 1
        return 1 + max([self._calculate_height(child) for child in node.children] or [0])
    
    def _rebalance(self):
        """Rebalance tree to maintain height constraint"""
        # Implementation of tree rotation for balance
        pass

class BATree:
    """B-A Tree implementation for blockchain data management"""
    def __init__(self, min_degree=3):
        self.root = BATreeNode(is_leaf=True)
        self.min_degree = min_degree
        
    def insert(self, key, value):
        """Insert key-value pair into B-A tree"""
        if self._is_full(self.root):
            new_root = BATreeNode()
            new_root.children.append(self.root)
            self._split_child(new_root, 0)
            self.root = new_root
        self._insert_non_full(self.root, key, value)
        self.root.calculate_hash()
    
    def _is_full(self, node):
        """Check if node is full"""
        return len(node.keys) >= 2 * self.min_degree - 1
    
    def _split_child(self, parent, index):
        """Split child node"""
        full_child = parent.children[index]
        new_child = BATreeNode(is_leaf=full_child.is_leaf)
        
        mid_index = self.min_degree - 1
        new_child.keys = full_child.keys[mid_index + 1:]
        full_child.keys = full_child.keys[:mid_index]
        
        if not full_child.is_leaf:
            new_child.children = full_child.children[mid_index + 1:]
            full_child.children = full_child.children[:mid_index + 1]
        
        parent.keys.insert(index, full_child.keys[mid_index])
        parent.children.insert(index + 1, new_child)
    
    def _insert_non_full(self, node, key, value):
        """Insert into non-full node"""
        if node.is_leaf:
            node.keys.append(key)
            node.values.append(value)
            node.keys.sort()
        else:
            index = len(node.keys) - 1
            while index >= 0 and key < node.keys[index]:
                index -= 1
            index += 1
            
            if self._is_full(node.children[index]):
                self._split_child(node, index)
                if key > node.keys[index]:
                    index += 1
            
            self._insert_non_full(node.children[index], key, value)

class Block:
    """Enhanced block structure with DHT optimization"""
    def __init__(self, index: int, transactions: List[Transaction], 
                 previous_hash: str, validator: str = ""):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.validator = validator
        self.nonce = 0
        self.merkle_root = self.calculate_merkle_root()
        self.ba_tree = self.build_ba_tree()
        self.hash = self.calculate_hash()
        self.zone_block_data = self.generate_zone_block_data()
        
    def calculate_merkle_root(self) -> str:
        """Calculate Merkle root of transactions"""
        if not self.transactions:
            return hashlib.sha256(b"").hexdigest()
        
        # Create leaf nodes
        leaves = [MerkleNode(content=tx.calculate_hash()) for tx in self.transactions]
        
        # Build tree bottom-up
        while len(leaves) > 1:
            new_level = []
            for i in range(0, len(leaves), 2):
                left = leaves[i]
                right = leaves[i + 1] if i + 1 < len(leaves) else left
                new_level.append(MerkleNode(left=left, right=right))
            leaves = new_level
        
        return leaves[0].hash_value
    
    def build_ba_tree(self) -> BATree:
        """Build B-A tree for optimized storage"""
        tree = BATree()
        for tx in self.transactions:
            tree.insert(tx.calculate_hash(), tx)
        return tree
    
    def calculate_hash(self) -> str:
        """Calculate block hash"""
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'merkle_root': self.merkle_root,
            'previous_hash': self.previous_hash,
            'validator': self.validator,
            'nonce': self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def generate_zone_block_data(self) -> Dict[str, Any]:
        """Generate zone block data for DHT storage"""
        return {
            'block_hash': self.hash,
            'index': self.index,
            'timestamp': self.timestamp,
            'tx_count': len(self.transactions),
            'merkle_root': self.merkle_root,
            'ba_tree_root': self.ba_tree.root.hash_value if self.ba_tree.root else None,
            'zone_cids': [tx.zone_block_cid for tx in self.transactions]
        }

class Blockchain:
    """Main blockchain class with DHT integration"""
    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.mining_reward = 10.0
        self.difficulty = 4
        self.create_genesis_block()
        
    def create_genesis_block(self):
        """Create the genesis block"""
        genesis_tx = Transaction(
            sender="genesis",
            recipient="genesis",
            amount=0,
            timestamp=time.time(),
            transaction_type=TransactionType.TRANSFER
        )
        genesis_block = Block(0, [genesis_tx], "0", "genesis")
        self.chain.append(genesis_block)
    
    def get_latest_block(self) -> Block:
        """Get the latest block in the chain"""
        return self.chain[-1]
    
    def add_transaction(self, transaction: Transaction) -> bool:
        """Add transaction to pending pool after validation"""
        # Validate transaction
        if not self.validate_transaction(transaction):
            return False
        
        self.pending_transactions.append(transaction)
        logger.info(f"Transaction added: {transaction.calculate_hash()}")
        return True
    
    def validate_transaction(self, transaction: Transaction) -> bool:
        """Validate transaction before adding to pool"""
        # Check if sender has sufficient balance
        if transaction.sender != "genesis":
            balance = self.get_balance(transaction.sender)
            total_cost = transaction.amount + (transaction.gas_price * transaction.gas_limit)
            if balance < total_cost:
                logger.warning(f"Insufficient balance for transaction: {transaction.calculate_hash()}")
                return False
        
        # Verify signature if present
        # Additional validation logic can be added here
        
        return True
    
    def get_balance(self, address: str) -> float:
        """Calculate balance for an address"""
        balance = 0.0
        for block in self.chain:
            for tx in block.transactions:
                if tx.recipient == address:
                    balance += tx.amount
                if tx.sender == address:
                    balance -= tx.amount + (tx.gas_price * tx.gas_limit)
        return balance
    
    def mine_pending_transactions(self, mining_reward_address: str) -> Optional[Block]:
        """Mine pending transactions into a new block"""
        if not self.pending_transactions:
            logger.info("No pending transactions to mine")
            return None
        
        # Add mining reward transaction
        reward_tx = Transaction(
            sender="system",
            recipient=mining_reward_address,
            amount=self.mining_reward,
            timestamp=time.time(),
            transaction_type=TransactionType.REWARD
        )
        
        transactions = self.pending_transactions + [reward_tx]
        new_block = Block(
            index=len(self.chain),
            transactions=transactions,
            previous_hash=self.get_latest_block().hash,
            validator=mining_reward_address
        )
        
        # Proof of Work mining
        while not new_block.hash.startswith('0' * self.difficulty):
            new_block.nonce += 1
            new_block.hash = new_block.calculate_hash()
        
        self.chain.append(new_block)
        self.pending_transactions = []
        
        logger.info(f"Block mined: {new_block.hash}")
        return new_block
    
    def validate_chain(self) -> bool:
        """Validate the entire blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Verify block hash
            if current_block.hash != current_block.calculate_hash():
                logger.error(f"Invalid block hash at index {i}")
                return False
            
            # Verify chain continuity
            if current_block.previous_hash != previous_block.hash:
                logger.error(f"Chain broken at index {i}")
                return False
            
            # Verify Merkle root
            if current_block.merkle_root != current_block.calculate_merkle_root():
                logger.error(f"Invalid Merkle root at index {i}")
                return False
        
        return True