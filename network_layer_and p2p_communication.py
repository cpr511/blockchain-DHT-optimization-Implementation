"""
Network Layer and P2P Communication Module
Complete networking implementation for blockchain
"""

import socket
import threading
import json
import pickle
import struct
import asyncio
import time
import hashlib
import random
from typing import Dict, List, Optional, Tuple, Any, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)

class MessageType(Enum):
    """Types of network messages"""
    TRANSACTION = "transaction"
    BLOCK = "block"
    BLOCK_REQUEST = "block_request"
    CONSENSUS_PROPOSE = "consensus_propose"
    CONSENSUS_VOTE = "consensus_vote"
    DHT_STORE = "dht_store"
    DHT_RETRIEVE = "dht_retrieve"
    DHT_RESPONSE = "dht_response"
    PEER_DISCOVERY = "peer_discovery"
    PEER_LIST = "peer_list"
    SYNC_REQUEST = "sync_request"
    SYNC_RESPONSE = "sync_response"
    HEARTBEAT = "heartbeat"
    NODE_JOIN = "node_join"
    NODE_LEAVE = "node_leave"

@dataclass
class NetworkMessage:
    """Network message structure"""
    message_type: MessageType
    sender: str
    recipient: str
    payload: Any
    timestamp: float = field(default_factory=time.time)
    message_id: str = field(default_factory=lambda: hashlib.sha256(str(time.time()).encode()).hexdigest())
    signature: Optional[bytes] = None
    
    def serialize(self) -> bytes:
        """Serialize message for network transmission"""
        return pickle.dumps({
            'message_type': self.message_type.value,
            'sender': self.sender,
            'recipient': self.recipient,
            'payload': self.payload,
            'timestamp': self.timestamp,
            'message_id': self.message_id,
            'signature': self.signature
        })
    
    @staticmethod
    def deserialize(data: bytes) -> 'NetworkMessage':
        """Deserialize message from network"""
        msg_dict = pickle.loads(data)
        return NetworkMessage(
            message_type=MessageType(msg_dict['message_type']),
            sender=msg_dict['sender'],
            recipient=msg_dict['recipient'],
            payload=msg_dict['payload'],
            timestamp=msg_dict['timestamp'],
            message_id=msg_dict['message_id'],
            signature=msg_dict.get('signature')
        )

class P2PNode:
    """P2P network node with full networking capabilities"""
    
    def __init__(self, node_id: str, host: str, port: int):
        self.node_id = node_id
        self.host = host
        self.port = port
        
        # Network state
        self.peers: Dict[str, Tuple[str, int]] = {}
        self.active_connections: Dict[str, socket.socket] = {}
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        
        # Message handling
        self.message_handlers: Dict[MessageType, Callable] = {}
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.sent_messages: Set[str] = set()
        self.received_messages: Set[str] = set()
        
        # Threading
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.lock = threading.RLock()
        
        # Network statistics
        self.network_stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'connected_peers': 0,
            'uptime': 0,
            'start_time': time.time()
        }
        
        # Peer discovery
        self.bootstrap_nodes: List[Tuple[str, int]] = []
        self.max_peers = 20
        self.peer_discovery_interval = 30  # seconds
        
        # Heartbeat
        self.heartbeat_interval = 10  # seconds
        self.peer_timeout = 30  # seconds
        self.last_heartbeat: Dict[str, float] = {}
    
    def start(self, bootstrap_nodes: List[Tuple[str, int]] = None):
        """Start the P2P node"""
        self.running = True
        self.bootstrap_nodes = bootstrap_nodes or []
        
        # Start server socket
        self._start_server()
        
        # Connect to bootstrap nodes
        if self.bootstrap_nodes:
            self._connect_to_bootstrap_nodes()
        
        # Start background tasks
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        threading.Thread(target=self._peer_discovery_loop, daemon=True).start()
        threading.Thread(target=self._message_processing_loop, daemon=True).start()
        threading.Thread(target=self._cleanup_loop, daemon=True).start()
        
        logger.info(f"P2P node {self.node_id} started on {self.host}:{self.port}")
    
    def stop(self):
        """Stop the P2P node"""
        self.running = False
        
        # Send leave message to peers
        self._broadcast_leave()
        
        # Close all connections
        with self.lock:
            for conn in self.active_connections.values():
                try:
                    conn.close()
                except:
                    pass
            
            if self.server_socket:
                self.server_socket.close()
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        logger.info(f"P2P node {self.node_id} stopped")
    
    def _start_server(self):
        """Start server socket to accept incoming connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        
        # Start accepting connections in background
        threading.Thread(target=self._accept_connections, daemon=True).start()
    
    def _accept_connections(self):
        """Accept incoming connections"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                self.executor.submit(self._handle_client, client_socket, address)
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
    
    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle incoming client connection"""
        try:
            # Receive initial handshake
            data = self._receive_data(client_socket)
            if not data:
                client_socket.close()
                return
            
            message = NetworkMessage.deserialize(data)
            
            if message.message_type == MessageType.NODE_JOIN:
                # New peer joining
                peer_id = message.sender
                peer_info = message.payload
                
                with self.lock:
                    self.peers[peer_id] = (peer_info['host'], peer_info['port'])
                    self.active_connections[peer_id] = client_socket
                    self.last_heartbeat[peer_id] = time.time()
                
                # Send peer list
                self._send_peer_list(peer_id)
                
                logger.info(f"Peer {peer_id} connected from {address}")
            
            # Continue receiving messages
            while self.running:
                data = self._receive_data(client_socket)
                if not data:
                    break
                
                message = NetworkMessage.deserialize(data)
                asyncio.run(self.message_queue.put(message))
                
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            client_socket.close()
            # Remove from active connections
            with self.lock:
                for peer_id, conn in list(self.active_connections.items()):
                    if conn == client_socket:
                        del self.active_connections[peer_id]
                        if peer_id in self.peers:
                            del self.peers[peer_id]
                        break
    
    def _receive_data(self, sock: socket.socket) -> Optional[bytes]:
        """Receive data from socket with length prefix"""
        try:
            # First receive the length (4 bytes)
            length_data = sock.recv(4)
            if not length_data:
                return None
            
            length = struct.unpack('!I', length_data)[0]
            
            # Receive the actual data
            data = b''
            while len(data) < length:
                chunk = sock.recv(min(4096, length - len(data)))
                if not chunk:
                    return None
                data += chunk
            
            self.network_stats['bytes_received'] += len(data)
            return data
            
        except Exception as e:
            logger.error(f"Error receiving data: {e}")
            return None
    
    def _send_data(self, sock: socket.socket, data: bytes) -> bool:
        """Send data to socket with length prefix"""
        try:
            # Send length prefix
            length = len(data)
            sock.sendall(struct.pack('!I', length))
            
            # Send actual data
            sock.sendall(data)
            
            self.network_stats['bytes_sent'] += length
            return True
            
        except Exception as e:
            logger.error(f"Error sending data: {e}")
            return False
    
    def connect_to_peer(self, peer_id: str, host: str, port: int) -> bool:
        """Connect to a specific peer"""
        try:
            # Check if already connected
            if peer_id in self.active_connections:
                return True
            
            # Check max peers limit
            if len(self.peers) >= self.max_peers:
                return False
            
            # Create connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send join message
            join_msg = NetworkMessage(
                message_type=MessageType.NODE_JOIN,
                sender=self.node_id,
                recipient=peer_id,
                payload={'host': self.host, 'port': self.port}
            )
            
            if not self._send_data(sock, join_msg.serialize()):
                sock.close()
                return False
            
            # Add to connections
            with self.lock:
                self.peers[peer_id] = (host, port)
                self.active_connections[peer_id] = sock
                self.last_heartbeat[peer_id] = time.time()
            
            # Start receiving thread
            threading.Thread(
                target=self._handle_peer_messages,
                args=(peer_id, sock),
                daemon=True
            ).start()
            
            logger.info(f"Connected to peer {peer_id} at {host}:{port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_id}: {e}")
            return False
    
    def _handle_peer_messages(self, peer_id: str, sock: socket.socket):
        """Handle messages from a connected peer"""
        try:
            while self.running and peer_id in self.active_connections:
                data = self._receive_data(sock)
                if not data:
                    break
                
                message = NetworkMessage.deserialize(data)
                asyncio.run(self.message_queue.put(message))
                
        except Exception as e:
            logger.error(f"Error handling peer {peer_id} messages: {e}")
        finally:
            # Clean up connection
            with self.lock:
                if peer_id in self.active_connections:
                    del self.active_connections[peer_id]
                if peer_id in self.peers:
                    del self.peers[peer_id]
    
    def send_message(self, recipient: str, message: NetworkMessage) -> bool:
        """Send message to specific peer"""
        # Check for duplicate
        if message.message_id in self.sent_messages:
            return True
        
        with self.lock:
            if recipient not in self.active_connections:
                logger.warning(f"No connection to recipient {recipient}")
                return False
            
            sock = self.active_connections[recipient]
            
        success = self._send_data(sock, message.serialize())
        
        if success:
            self.sent_messages.add(message.message_id)
            self.network_stats['messages_sent'] += 1
        
        return success
    
    def broadcast_message(self, message: NetworkMessage):
        """Broadcast message to all connected peers"""
        with self.lock:
            peers = list(self.active_connections.keys())
        
        for peer_id in peers:
            message.recipient = peer_id
            self.send_message(peer_id, message)
    
    def register_handler(self, message_type: MessageType, handler: Callable):
        """Register message handler"""
        self.message_handlers[message_type] = handler
    
    def _message_processing_loop(self):
        """Process incoming messages"""
        async def process():
            while self.running:
                try:
                    message = await asyncio.wait_for(
                        self.message_queue.get(),
                        timeout=1.0
                    )
                    
                    # Check for duplicate
                    if message.message_id in self.received_messages:
                        continue
                    
                    self.received_messages.add(message.message_id)
                    self.network_stats['messages_received'] += 1
                    
                    # Update heartbeat
                    if message.sender in self.last_heartbeat:
                        self.last_heartbeat[message.sender] = time.time()
                    
                    # Handle message
                    if message.message_type in self.message_handlers:
                        handler = self.message_handlers[message.message_type]
                        self.executor.submit(handler, message)
                    
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
        
        asyncio.run(process())
    
    def _connect_to_bootstrap_nodes(self):
        """Connect to bootstrap nodes"""
        for host, port in self.bootstrap_nodes:
            # Generate peer ID from address
            peer_id = hashlib.sha256(f"{host}:{port}".encode()).hexdigest()[:16]
            self.connect_to_peer(peer_id, host, port)
    
    def _heartbeat_loop(self):
        """Send heartbeat to all peers"""
        while self.running:
            time.sleep(self.heartbeat_interval)
            
            heartbeat_msg = NetworkMessage(
                message_type=MessageType.HEARTBEAT,
                sender=self.node_id,
                recipient="",
                payload={'timestamp': time.time()}
            )
            
            self.broadcast_message(heartbeat_msg)
    
    def _peer_discovery_loop(self):
        """Discover new peers periodically"""
        while self.running:
            time.sleep(self.peer_discovery_interval)
            
            # Request peer lists from connected peers
            discovery_msg = NetworkMessage(
                message_type=MessageType.PEER_DISCOVERY,
                sender=self.node_id,
                recipient="",
                payload={}
            )
            
            self.broadcast_message(discovery_msg)
    
    def _cleanup_loop(self):
        """Clean up inactive connections"""
        while self.running:
            time.sleep(self.peer_timeout)
            
            current_time = time.time()
            inactive_peers = []
            
            with self.lock:
                for peer_id, last_time in self.last_heartbeat.items():
                    if current_time - last_time > self.peer_timeout:
                        inactive_peers.append(peer_id)
            
            for peer_id in inactive_peers:
                self._disconnect_peer(peer_id)
    
    def _disconnect_peer(self, peer_id: str):
        """Disconnect from a peer"""
        with self.lock:
            if peer_id in self.active_connections:
                try:
                    self.active_connections[peer_id].close()
                except:
                    pass
                del self.active_connections[peer_id]
            
            if peer_id in self.peers:
                del self.peers[peer_id]
            
            if peer_id in self.last_heartbeat:
                del self.last_heartbeat[peer_id]
        
        logger.info(f"Disconnected from peer {peer_id}")
    
    def _send_peer_list(self, recipient: str):
        """Send peer list to a node"""
        with self.lock:
            peer_list = list(self.peers.items())
        
        msg = NetworkMessage(
            message_type=MessageType.PEER_LIST,
            sender=self.node_id,
            recipient=recipient,
            payload={'peers': peer_list}
        )
        
        self.send_message(recipient, msg)
    
    def _broadcast_leave(self):
        """Broadcast leave message before shutting down"""
        leave_msg = NetworkMessage(
            message_type=MessageType.NODE_LEAVE,
            sender=self.node_id,
            recipient="",
            payload={'timestamp': time.time()}
        )
        
        self.broadcast_message(leave_msg)
    
    def get_network_stats(self) -> Dict[str, Any]:
        """Get network statistics"""
        with self.lock:
            self.network_stats['connected_peers'] = len(self.active_connections)
            self.network_stats['uptime'] = time.time() - self.network_stats['start_time']
        
        return self.network_stats.copy()


class SyncManager:
    """Blockchain synchronization manager"""
    
    def __init__(self, blockchain, p2p_node: P2PNode):
        self.blockchain = blockchain
        self.p2p_node = p2p_node
        self.syncing = False
        self.sync_progress = 0.0
        self.sync_start_height = 0
        self.sync_target_height = 0
        
        # Register message handlers
        self.p2p_node.register_handler(MessageType.SYNC_REQUEST, self._handle_sync_request)
        self.p2p_node.register_handler(MessageType.SYNC_RESPONSE, self._handle_sync_response)
        self.p2p_node.register_handler(MessageType.BLOCK, self._handle_block)
    
    def start_sync(self):
        """Start blockchain synchronization"""
        if self.syncing:
            return
        
        self.syncing = True
        self.sync_start_height = len(self.blockchain.chain)
        
        # Request sync from all peers
        sync_request = NetworkMessage(
            message_type=MessageType.SYNC_REQUEST,
            sender=self.p2p_node.node_id,
            recipient="",
            payload={
                'current_height': self.sync_start_height,
                'latest_hash': self.blockchain.get_latest_block().hash
            }
        )
        
        self.p2p_node.broadcast_message(sync_request)
        logger.info(f"Started blockchain sync from height {self.sync_start_height}")
    
    def _handle_sync_request(self, message: NetworkMessage):
        """Handle sync request from peer"""
        peer_height = message.payload['current_height']
        peer_hash = message.payload['latest_hash']
        
        our_height = len(self.blockchain.chain)
        
        if our_height > peer_height:
            # Send blocks to peer
            blocks_to_send = self.blockchain.chain[peer_height:]
            
            response = NetworkMessage(
                message_type=MessageType.SYNC_RESPONSE,
                sender=self.p2p_node.node_id,
                recipient=message.sender,
                payload={
                    'blocks': [self._serialize_block(b) for b in blocks_to_send],
                    'total_height': our_height
                }
            )
            
            self.p2p_node.send_message(message.sender, response)
    
    def _handle_sync_response(self, message: NetworkMessage):
        """Handle sync response from peer"""
        blocks_data = message.payload['blocks']
        total_height = message.payload['total_height']
        
        self.sync_target_height = max(self.sync_target_height, total_height)
        
        for block_data in blocks_data:
            block = self._deserialize_block(block_data)
            
            # Validate and add block
            if self._validate_block(block):
                self.blockchain.chain.append(block)
                
                # Update progress
                current_height = len(self.blockchain.chain)
                self.sync_progress = (current_height - self.sync_start_height) / \
                                   (self.sync_target_height - self.sync_start_height)
                
                logger.debug(f"Sync progress: {self.sync_progress:.2%}")
        
        # Check if sync complete
        if len(self.blockchain.chain) >= self.sync_target_height:
            self.syncing = False
            logger.info(f"Blockchain sync completed at height {len(self.blockchain.chain)}")
    
    def _handle_block(self, message: NetworkMessage):
        """Handle new block from network"""
        block_data = message.payload
        block = self._deserialize_block(block_data)
        
        if self._validate_block(block):
            # Add to blockchain
            self.blockchain.chain.append(block)
            
            # Clear pending transactions that are in the block
            block_tx_hashes = {tx.calculate_hash() for tx in block.transactions}
            self.blockchain.pending_transactions = [
                tx for tx in self.blockchain.pending_transactions
                if tx.calculate_hash() not in block_tx_hashes
            ]
            
            logger.info(f"Added new block {block.hash} at height {block.index}")
    
    def _validate_block(self, block) -> bool:
        """Validate a block before adding to chain"""
        # Check previous hash
        if block.index > 0:
            if block.previous_hash != self.blockchain.get_latest_block().hash:
                return False
        
        # Verify block hash
        if block.hash != block.calculate_hash():
            return False
        
        # Verify Merkle root
        if block.merkle_root != block.calculate_merkle_root():
            return False
        
        return True
    
    def _serialize_block(self, block) -> Dict:
        """Serialize block for network transmission"""
        return {
            'index': block.index,
            'timestamp': block.timestamp,
            'transactions': [self._serialize_transaction(tx) for tx in block.transactions],
            'previous_hash': block.previous_hash,
            'validator': block.validator,
            'nonce': block.nonce,
            'hash': block.hash
        }
    
    def _deserialize_block(self, data: Dict):
        """Deserialize block from network data"""
        from blockchain_core import Block, Transaction, TransactionType
        
        transactions = [self._deserialize_transaction(tx_data) for tx_data in data['transactions']]
        
        block = Block(
            index=data['index'],
            transactions=transactions,
            previous_hash=data['previous_hash'],
            validator=data['validator']
        )
        block.timestamp = data['timestamp']
        block.nonce = data['nonce']
        block.hash = data['hash']
        
        return block
    
    def _serialize_transaction(self, tx) -> Dict:
        """Serialize transaction for network"""
        return {
            'sender': tx.sender,
            'recipient': tx.recipient,
            'amount': tx.amount,
            'timestamp': tx.timestamp,
            'transaction_type': tx.transaction_type.value,
            'data': tx.data,
            'nonce': tx.nonce,
            'gas_price': tx.gas_price,
            'gas_limit': tx.gas_limit
        }
    
    def _deserialize_transaction(self, data: Dict):
        """Deserialize transaction from network data"""
        from blockchain_core import Transaction, TransactionType
        
        return Transaction(
            sender=data['sender'],
            recipient=data['recipient'],
            amount=data['amount'],
            timestamp=data['timestamp'],
            transaction_type=TransactionType(data['transaction_type']),
            data=data['data'],
            nonce=data['nonce'],
            gas_price=data['gas_price'],
            gas_limit=data['gas_limit']
        )