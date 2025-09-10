"""
DHT (Distributed Hash Table) Implementation using Chord Protocol
Based on paper Section 2.1 and 2.4
"""

import hashlib
import bisect
import threading
import time
import socket
import json
import asyncio
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from collections import OrderedDict
import pickle
import struct
import logging

logger = logging.getLogger(__name__)

class ChordNode:
    """Chord DHT node implementation with full routing capabilities"""
    
    def __init__(self, node_id: str, ip: str, port: int, m_bits: int = 160):
        """
        Initialize Chord node
        m_bits: Size of the identifier space (160 for SHA-1)
        """
        self.node_id = self._hash_key(node_id)
        self.ip = ip
        self.port = port
        self.m_bits = m_bits
        self.max_id = 2 ** m_bits
        
        # Chord routing structures
        self.predecessor: Optional['ChordNode'] = None
        self.successor: Optional['ChordNode'] = self
        self.finger_table: List[Optional['ChordNode']] = [None] * m_bits
        
        # Storage
        self.storage: Dict[str, Any] = {}
        self.zone_blocks: Dict[str, Dict] = {}  # ZB-CID mapped storage
        
        # Successor list for fault tolerance
        self.successor_list: List['ChordNode'] = []
        self.successor_list_size = 5
        
        # Network management
        self.lock = threading.RLock()
        self.running = False
        self.stabilize_interval = 5  # seconds
        self.fix_fingers_interval = 10  # seconds
        
        # Load balancing metrics
        self.load_metrics = {
            'request_count': 0,
            'storage_size': 0,
            'last_update': time.time(),
            'cpu_usage': 0,
            'memory_usage': 0
        }
        
        # Initialize finger table
        self._initialize_finger_table()
    
    def _hash_key(self, key: str) -> int:
        """Generate hash for a given key using SHA-256"""
        hash_value = hashlib.sha256(key.encode()).hexdigest()
        return int(hash_value, 16) % self.max_id
    
    def _initialize_finger_table(self):
        """Initialize finger table entries"""
        for i in range(self.m_bits):
            start = (self.node_id + 2**i) % self.max_id
            self.finger_table[i] = self
    
    def _in_interval(self, value: int, start: int, end: int, 
                     inclusive_start: bool = False, inclusive_end: bool = False) -> bool:
        """Check if value is in the interval on the Chord ring"""
        if start == end:
            return inclusive_start and value == start
        elif start < end:
            if inclusive_start and inclusive_end:
                return start <= value <= end
            elif inclusive_start:
                return start <= value < end
            elif inclusive_end:
                return start < value <= end
            else:
                return start < value < end
        else:  # Interval wraps around
            if inclusive_start and inclusive_end:
                return value >= start or value <= end
            elif inclusive_start:
                return value >= start or value < end
            elif inclusive_end:
                return value > start or value <= end
            else:
                return value > start or value < end
    
    def find_successor(self, key_id: int) -> 'ChordNode':
        """Find the successor node responsible for a given key"""
        # Check if key is between this node and its successor
        if self._in_interval(key_id, self.node_id, self.successor.node_id, 
                           inclusive_start=False, inclusive_end=True):
            return self.successor
        
        # Find closest preceding node
        closest = self._closest_preceding_node(key_id)
        if closest == self:
            return self.successor
        
        # Recursively find successor
        return closest.find_successor(key_id)
    
    def _closest_preceding_node(self, key_id: int) -> 'ChordNode':
        """Find the closest preceding node in the finger table"""
        for i in range(self.m_bits - 1, -1, -1):
            if self.finger_table[i] and \
               self._in_interval(self.finger_table[i].node_id, self.node_id, key_id,
                               inclusive_start=False, inclusive_end=False):
                return self.finger_table[i]
        return self
    
    def join(self, bootstrap_node: Optional['ChordNode'] = None):
        """Join the Chord network"""
        if bootstrap_node:
            # Join existing network
            self.successor = bootstrap_node.find_successor(self.node_id)
            self.predecessor = None
            
            # Update finger table
            self._update_finger_table()
            
            # Transfer keys from successor
            self._transfer_keys()
        else:
            # Create new network
            self.predecessor = self
            self.successor = self
            for i in range(self.m_bits):
                self.finger_table[i] = self
        
        # Start maintenance threads
        self.running = True
        threading.Thread(target=self._stabilize_loop, daemon=True).start()
        threading.Thread(target=self._fix_fingers_loop, daemon=True).start()
        threading.Thread(target=self._check_predecessor_loop, daemon=True).start()
        
        logger.info(f"Node {self.node_id} joined the network")
    
    def _stabilize_loop(self):
        """Periodically stabilize the node"""
        while self.running:
            time.sleep(self.stabilize_interval)
            self.stabilize()
    
    def _fix_fingers_loop(self):
        """Periodically fix finger table entries"""
        while self.running:
            time.sleep(self.fix_fingers_interval)
            self.fix_fingers()
    
    def _check_predecessor_loop(self):
        """Periodically check if predecessor is alive"""
        while self.running:
            time.sleep(self.stabilize_interval * 2)
            self.check_predecessor()
    
    def stabilize(self):
        """Stabilize the node's successor pointer"""
        with self.lock:
            if self.successor:
                # Get successor's predecessor
                x = self.successor.predecessor
                if x and self._in_interval(x.node_id, self.node_id, self.successor.node_id,
                                          inclusive_start=False, inclusive_end=False):
                    self.successor = x
                
                # Notify successor
                self.successor.notify(self)
                
                # Update successor list
                self._update_successor_list()
    
    def notify(self, node: 'ChordNode'):
        """Handle notification from a potential predecessor"""
        with self.lock:
            if not self.predecessor or \
               self._in_interval(node.node_id, self.predecessor.node_id, self.node_id,
                               inclusive_start=False, inclusive_end=False):
                self.predecessor = node
                # Transfer keys that should belong to new predecessor
                self._transfer_keys_to_predecessor()
    
    def fix_fingers(self):
        """Fix random finger table entry"""
        with self.lock:
            i = random.randint(0, self.m_bits - 1)
            start = (self.node_id + 2**i) % self.max_id
            self.finger_table[i] = self.find_successor(start)
    
    def check_predecessor(self):
        """Check if predecessor is still alive"""
        if self.predecessor and not self._ping_node(self.predecessor):
            with self.lock:
                self.predecessor = None
    
    def _ping_node(self, node: 'ChordNode') -> bool:
        """Check if a node is responsive"""
        try:
            # Simple ping implementation
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((node.ip, node.port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _update_finger_table(self):
        """Update entire finger table"""
        for i in range(self.m_bits):
            start = (self.node_id + 2**i) % self.max_id
            self.finger_table[i] = self.find_successor(start)
    
    def _update_successor_list(self):
        """Update the successor list for fault tolerance"""
        with self.lock:
            self.successor_list = []
            current = self.successor
            for _ in range(self.successor_list_size):
                if current and current != self:
                    self.successor_list.append(current)
                    current = current.successor
                else:
                    break
    
    def _transfer_keys(self):
        """Transfer keys from successor when joining"""
        if self.successor and self.successor != self:
            keys_to_transfer = []
            for key, value in self.successor.storage.items():
                key_id = self._hash_key(key)
                if self._in_interval(key_id, self.predecessor.node_id if self.predecessor else 0,
                                   self.node_id, inclusive_start=False, inclusive_end=True):
                    keys_to_transfer.append(key)
            
            for key in keys_to_transfer:
                self.storage[key] = self.successor.storage.pop(key)
                logger.debug(f"Transferred key {key} to node {self.node_id}")
    
    def _transfer_keys_to_predecessor(self):
        """Transfer appropriate keys to new predecessor"""
        if self.predecessor and self.predecessor != self:
            keys_to_transfer = []
            for key, value in self.storage.items():
                key_id = self._hash_key(key)
                if not self._in_interval(key_id, self.predecessor.node_id, self.node_id,
                                        inclusive_start=False, inclusive_end=True):
                    keys_to_transfer.append(key)
            
            for key in keys_to_transfer:
                self.predecessor.storage[key] = self.storage.pop(key)
    
    def store_data(self, key: str, value: Any) -> bool:
        """Store data in the DHT"""
        key_id = self._hash_key(key)
        responsible_node = self.find_successor(key_id)
        
        if responsible_node == self:
            with self.lock:
                self.storage[key] = value
                self.load_metrics['storage_size'] += 1
                self.load_metrics['request_count'] += 1
                logger.info(f"Stored key {key} on node {self.node_id}")
                return True
        else:
            return responsible_node.store_data(key, value)
    
    def retrieve_data(self, key: str) -> Optional[Any]:
        """Retrieve data from the DHT"""
        key_id = self._hash_key(key)
        responsible_node = self.find_successor(key_id)
        
        if responsible_node == self:
            with self.lock:
                self.load_metrics['request_count'] += 1
                return self.storage.get(key)
        else:
            return responsible_node.retrieve_data(key)
    
    def store_zone_block(self, zb_cid: str, block_data: Dict) -> bool:
        """Store zone block data with ZB-CID identifier"""
        key_id = self._hash_key(zb_cid)
        responsible_node = self.find_successor(key_id)
        
        if responsible_node == self:
            with self.lock:
                self.zone_blocks[zb_cid] = block_data
                self.load_metrics['storage_size'] += 1
                logger.info(f"Stored zone block {zb_cid} on node {self.node_id}")
                return True
        else:
            return responsible_node.store_zone_block(zb_cid, block_data)
    
    def retrieve_zone_block(self, zb_cid: str) -> Optional[Dict]:
        """Retrieve zone block data by ZB-CID"""
        key_id = self._hash_key(zb_cid)
        responsible_node = self.find_successor(key_id)
        
        if responsible_node == self:
            with self.lock:
                self.load_metrics['request_count'] += 1
                return self.zone_blocks.get(zb_cid)
        else:
            return responsible_node.retrieve_zone_block(zb_cid)
    
    def leave(self):
        """Leave the Chord network gracefully"""
        self.running = False
        
        with self.lock:
            # Transfer all keys to successor
            if self.successor and self.successor != self:
                for key, value in self.storage.items():
                    self.successor.storage[key] = value
                for zb_cid, block_data in self.zone_blocks.items():
                    self.successor.zone_blocks[zb_cid] = block_data
            
            # Update predecessor's successor
            if self.predecessor and self.predecessor != self:
                self.predecessor.successor = self.successor
            
            # Update successor's predecessor
            if self.successor and self.successor != self:
                self.successor.predecessor = self.predecessor
        
        logger.info(f"Node {self.node_id} left the network")
    
    def get_load_status(self) -> Dict[str, Any]:
        """Get current load status for load balancing"""
        with self.lock:
            self.load_metrics['last_update'] = time.time()
            return self.load_metrics.copy()
    
    def __repr__(self):
        return f"ChordNode(id={self.node_id}, ip={self.ip}:{self.port})"


class DHTNetwork:
    """DHT Network manager for blockchain integration"""
    
    def __init__(self, m_bits: int = 160):
        self.m_bits = m_bits
        self.nodes: List[ChordNode] = []
        self.bootstrap_node: Optional[ChordNode] = None
        self.lock = threading.Lock()
        
    def add_node(self, node_id: str, ip: str, port: int) -> ChordNode:
        """Add a new node to the DHT network"""
        node = ChordNode(node_id, ip, port, self.m_bits)
        
        with self.lock:
            if not self.nodes:
                # First node creates the network
                node.join(None)
                self.bootstrap_node = node
            else:
                # Join existing network
                node.join(self.bootstrap_node)
            
            self.nodes.append(node)
        
        return node
    
    def remove_node(self, node: ChordNode):
        """Remove a node from the DHT network"""
        with self.lock:
            if node in self.nodes:
                node.leave()
                self.nodes.remove(node)
                
                # Update bootstrap node if necessary
                if node == self.bootstrap_node and self.nodes:
                    self.bootstrap_node = self.nodes[0]
    
    def store_blockchain_data(self, key: str, data: Any) -> bool:
        """Store blockchain data in the DHT"""
        if not self.bootstrap_node:
            logger.error("No nodes in the DHT network")
            return False
        
        return self.bootstrap_node.store_data(key, data)
    
    def retrieve_blockchain_data(self, key: str) -> Optional[Any]:
        """Retrieve blockchain data from the DHT"""
        if not self.bootstrap_node:
            logger.error("No nodes in the DHT network")
            return None
        
        return self.bootstrap_node.retrieve_data(key)
    
    def store_zone_block(self, zb_cid: str, block_data: Dict) -> bool:
        """Store zone block in the DHT"""
        if not self.bootstrap_node:
            return False
        
        return self.bootstrap_node.store_zone_block(zb_cid, block_data)
    
    def retrieve_zone_block(self, zb_cid: str) -> Optional[Dict]:
        """Retrieve zone block from the DHT"""
        if not self.bootstrap_node:
            return None
        
        return self.bootstrap_node.retrieve_zone_block(zb_cid)
    
    def get_network_statistics(self) -> Dict[str, Any]:
        """Get network-wide statistics"""
        stats = {
            'total_nodes': len(self.nodes),
            'total_storage': 0,
            'total_requests': 0,
            'node_loads': []
        }
        
        for node in self.nodes:
            load_status = node.get_load_status()
            stats['total_storage'] += load_status['storage_size']
            stats['total_requests'] += load_status['request_count']
            stats['node_loads'].append({
                'node_id': node.node_id,
                'load': load_status
            })
        
        return stats


class LoadBalancer:
    """Load balancing component for DHT nodes (Paper Section 2.4)"""
    
    def __init__(self, dht_network: DHTNetwork):
        self.dht_network = dht_network
        self.threshold_y1 = 0.7  # Overload threshold for creating new node
        self.threshold_y2 = 0.9  # Critical overload threshold
        self.threshold_y3 = 0.5  # Recovery threshold
        self.threshold_y4 = 0.1  # Underutilization threshold
        self.monitoring_interval = 10  # seconds
        self.running = False
        
    def start_monitoring(self):
        """Start load balancing monitoring"""
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
    
    def stop_monitoring(self):
        """Stop load balancing monitoring"""
        self.running = False
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            time.sleep(self.monitoring_interval)
            self._check_load_balance()
    
    def _check_load_balance(self):
        """Check and balance load across nodes"""
        stats = self.dht_network.get_network_statistics()
        
        if not stats['total_nodes']:
            return
        
        avg_load = stats['total_requests'] / stats['total_nodes']
        
        for node_info in stats['node_loads']:
            node_load = node_info['load']['request_count']
            load_ratio = node_load / avg_load if avg_load > 0 else 0
            
            # Find the actual node object
            node = self._find_node_by_id(node_info['node_id'])
            if not node:
                continue
            
            if load_ratio > self.threshold_y2:
                # Y2: Critical overload - node should temporarily exit
                self._handle_critical_overload(node)
            elif load_ratio > self.threshold_y1:
                # Y1: Overload - create diversion node
                self._handle_overload(node)
            elif load_ratio < self.threshold_y4:
                # Y4: Underutilized - consider recycling
                self._handle_underutilization(node)
            elif load_ratio < self.threshold_y3:
                # Y3: Recovered - can rejoin if previously exited
                self._handle_recovery(node)
    
    def _find_node_by_id(self, node_id: int) -> Optional[ChordNode]:
        """Find node by its ID"""
        for node in self.dht_network.nodes:
            if node.node_id == node_id:
                return node
        return None
    
    def _handle_overload(self, node: ChordNode):
        """Handle overloaded node by creating diversion node"""
        logger.warning(f"Node {node.node_id} is overloaded, creating diversion node")
        
        # Create new node to share load
        new_node_id = f"diversion_{node.node_id}_{time.time()}"
        new_node = self.dht_network.add_node(new_node_id, node.ip, node.port + 1000)
        
        # Transfer some keys to new node
        self._redistribute_keys(node, new_node)
    
    def _handle_critical_overload(self, node: ChordNode):
        """Handle critically overloaded node"""
        logger.error(f"Node {node.node_id} is critically overloaded, temporarily removing")
        
        # Temporarily remove node from network
        # Keys will be automatically transferred to successor
        self.dht_network.remove_node(node)
    
    def _handle_underutilization(self, node: ChordNode):
        """Handle underutilized node"""
        if node.successor and node.successor != node:
            successor_load = node.successor.get_load_status()
            
            # Check if successor can handle additional load (Formula 9 from paper)
            if node.load_metrics['request_count'] < 0.1 * successor_load['request_count']:
                logger.info(f"Node {node.node_id} is underutilized, recycling")
                self.dht_network.remove_node(node)
    
    def _handle_recovery(self, node: ChordNode):
        """Handle recovered node"""
        logger.info(f"Node {node.node_id} has recovered from overload")
        # Node can now accept more load
        # Implementation depends on specific recovery actions needed
    
    def _redistribute_keys(self, source_node: ChordNode, target_node: ChordNode):
        """Redistribute keys between nodes for load balancing"""
        with source_node.lock:
            keys = list(source_node.storage.keys())
            num_keys_to_transfer = len(keys) // 2
            
            for i in range(num_keys_to_transfer):
                key = keys[i]
                value = source_node.storage.pop(key)
                target_node.storage[key] = value
            
            # Update load metrics
            source_node.load_metrics['storage_size'] -= num_keys_to_transfer
            target_node.load_metrics['storage_size'] += num_keys_to_transfer