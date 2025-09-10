"""
Main Integration Module - Complete Blockchain System with DHT Optimization
This module integrates all components and provides the main execution interface
"""

import os
import sys
import time
import json
import logging
import argparse
import random
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('blockchain_dht.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import all modules (assuming they're in the same directory)
from blockchain_core import (
    Blockchain, Block, Transaction, TransactionType,
    MerkleNode, BATree, BATreeNode
)
from dht_implementation import (
    ChordNode, DHTNetwork, LoadBalancer
)
from consensus_verification import (
    ContributionMechanism, TendermintOptimized,
    TransactionVerificationModel, AuthorizationAuthority,
    SmartContract, SecurityMechanisms,
    ZeroKnowledgeProof
)
from network_integration import (
    P2PNode, NetworkMessage, MessageType, SyncManager
)

class BlockchainNode:
    """Complete blockchain node with all integrated components"""
    
    def __init__(self, node_id: str, host: str, port: int, dht_port: int):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.dht_port = dht_port
        
        # Initialize core components
        self.blockchain = Blockchain()
        self.dht_network = DHTNetwork()
        self.p2p_node = P2PNode(node_id, host, port)
        
        # Initialize consensus and verification
        self.contribution_mechanism = ContributionMechanism()
        self.consensus = TendermintOptimized(node_id, self.contribution_mechanism)
        self.verification_model = TransactionVerificationModel(self.dht_network)
        self.security_mechanisms = SecurityMechanisms()
        
        # Initialize DHT node
        self.dht_node = None
        
        # Initialize sync manager
        self.sync_manager = SyncManager(self.blockchain, self.p2p_node)
        
        # Load balancer
        self.load_balancer = LoadBalancer(self.dht_network)
        
        # Key management
        self.private_key = None
        self.public_key = None
        self._generate_keys()
        
        # Mining configuration
        self.mining = False
        self.mining_thread = None
        
        # Statistics
        self.stats = {
            'transactions_processed': 0,
            'blocks_mined': 0,
            'consensus_rounds': 0,
            'dht_operations': 0
        }
        
        # Register message handlers
        self._register_message_handlers()
    
    def _generate_keys(self):
        """Generate RSA key pair for the node"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def _register_message_handlers(self):
        """Register P2P message handlers"""
        self.p2p_node.register_handler(MessageType.TRANSACTION, self._handle_transaction_message)
        self.p2p_node.register_handler(MessageType.BLOCK, self._handle_block_message)
        self.p2p_node.register_handler(MessageType.CONSENSUS_PROPOSE, self._handle_consensus_propose)
        self.p2p_node.register_handler(MessageType.CONSENSUS_VOTE, self._handle_consensus_vote)
        self.p2p_node.register_handler(MessageType.DHT_STORE, self._handle_dht_store)
        self.p2p_node.register_handler(MessageType.DHT_RETRIEVE, self._handle_dht_retrieve)
    
    def start(self, bootstrap_nodes: List[Tuple[str, int]] = None, validators: List[str] = None):
        """Start the blockchain node"""
        logger.info(f"Starting blockchain node {self.node_id}")
        
        # Start P2P network
        self.p2p_node.start(bootstrap_nodes)
        
        # Initialize DHT node
        self.dht_node = self.dht_network.add_node(self.node_id, self.host, self.dht_port)
        
        # Start load balancer
        self.load_balancer.start_monitoring()
        
        # Start consensus if validators provided
        if validators:
            self.consensus.start_consensus(validators)
        
        # Start blockchain sync
        time.sleep(2)  # Wait for network connections
        self.sync_manager.start_sync()
        
        logger.info(f"Blockchain node {self.node_id} started successfully")
    
    def stop(self):
        """Stop the blockchain node"""
        logger.info(f"Stopping blockchain node {self.node_id}")
        
        # Stop mining
        if self.mining:
            self.stop_mining()
        
        # Stop consensus
        self.consensus.stop_consensus()
        
        # Stop load balancer
        self.load_balancer.stop_monitoring()
        
        # Remove DHT node
        if self.dht_node:
            self.dht_network.remove_node(self.dht_node)
        
        # Stop P2P node
        self.p2p_node.stop()
        
        logger.info(f"Blockchain node {self.node_id} stopped")
    
    def create_transaction(self, recipient: str, amount: float, 
                         tx_type: TransactionType = TransactionType.TRANSFER) -> bool:
        """Create and broadcast a new transaction"""
        try:
            # Create transaction
            tx = Transaction(
                sender=self.node_id,
                recipient=recipient,
                amount=amount,
                timestamp=time.time(),
                transaction_type=tx_type,
                nonce=random.randint(0, 2**32)
            )
            
            # Sign transaction
            tx.sign_transaction(self.private_key)
            
            # Verify transaction security
            if not self.security_mechanisms.verify_transaction_security(tx):
                logger.error("Transaction failed security verification")
                return False
            
            # Verify transaction through verification model
            if not self.verification_model.verify_transaction(tx, self.public_key):
                logger.error("Transaction failed verification model")
                return False
            
            # Store transaction in DHT
            tx_hash = tx.calculate_hash()
            self.dht_network.store_blockchain_data(tx_hash, tx)
            
            # Store zone block data in DHT
            self.dht_network.store_zone_block(tx.zone_block_cid, {
                'tx_hash': tx_hash,
                'sender': tx.sender,
                'recipient': tx.recipient,
                'amount': tx.amount,
                'timestamp': tx.timestamp
            })
            
            # Add to blockchain pending pool
            self.blockchain.add_transaction(tx)
            
            # Broadcast transaction
            tx_message = NetworkMessage(
                message_type=MessageType.TRANSACTION,
                sender=self.node_id,
                recipient="",
                payload=self._serialize_transaction(tx)
            )
            self.p2p_node.broadcast_message(tx_message)
            
            # Update statistics
            self.stats['transactions_processed'] += 1
            self.stats['dht_operations'] += 2
            
            # Update contribution for data upload
            self.contribution_mechanism.record_data_upload(self.node_id)
            
            logger.info(f"Transaction created: {tx_hash}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating transaction: {e}")
            return False
    
    def start_mining(self):
        """Start mining blocks"""
        if self.mining:
            return
        
        self.mining = True
        self.mining_thread = threading.Thread(target=self._mining_loop, daemon=True)
        self.mining_thread.start()
        logger.info(f"Node {self.node_id} started mining")
    
    def stop_mining(self):
        """Stop mining blocks"""
        self.mining = False
        if self.mining_thread:
            self.mining_thread.join(timeout=5)
        logger.info(f"Node {self.node_id} stopped mining")
    
    def _mining_loop(self):
        """Main mining loop"""
        while self.mining:
            if len(self.blockchain.pending_transactions) > 0:
                # Mine new block
                block = self.blockchain.mine_pending_transactions(self.node_id)
                
                if block:
                    # Store block in DHT
                    block_data = block.generate_zone_block_data()
                    for zb_cid in block_data['zone_cids']:
                        self.dht_network.store_zone_block(zb_cid, block_data)
                    
                    # Broadcast block
                    block_message = NetworkMessage(
                        message_type=MessageType.BLOCK,
                        sender=self.node_id,
                        recipient="",
                        payload=self._serialize_block(block)
                    )
                    self.p2p_node.broadcast_message(block_message)
                    
                    # Update statistics
                    self.stats['blocks_mined'] += 1
                    self.stats['dht_operations'] += len(block_data['zone_cids'])
                    
                    # Update contribution
                    self.contribution_mechanism.update_currency(self.node_id, self.blockchain.mining_reward)
                    
                    logger.info(f"Block mined: {block.hash}")
            
            time.sleep(10)  # Wait before next mining attempt
    
    def _handle_transaction_message(self, message: NetworkMessage):
        """Handle incoming transaction message"""
        try:
            tx_data = message.payload
            tx = self._deserialize_transaction(tx_data)
            
            # Verify transaction
            # In real implementation, would need sender's public key
            if self.blockchain.validate_transaction(tx):
                self.blockchain.add_transaction(tx)
                
                # Store in DHT
                self.dht_network.store_blockchain_data(tx.calculate_hash(), tx)
                
                # Update contribution
                self.contribution_mechanism.record_state_allocation(message.sender, True)
                
                logger.debug(f"Received transaction: {tx.calculate_hash()}")
            
        except Exception as e:
            logger.error(f"Error handling transaction message: {e}")
    
    def _handle_block_message(self, message: NetworkMessage):
        """Handle incoming block message"""
        try:
            block_data = message.payload
            block = self._deserialize_block(block_data)
            
            # Validate block
            if self._validate_block(block):
                # Add to blockchain
                self.blockchain.chain.append(block)
                
                # Store in DHT
                for tx in block.transactions:
                    self.dht_network.store_zone_block(tx.zone_block_cid, block.zone_block_data)
                
                # Clear pending transactions
                tx_hashes = {tx.calculate_hash() for tx in block.transactions}
                self.blockchain.pending_transactions = [
                    tx for tx in self.blockchain.pending_transactions
                    if tx.calculate_hash() not in tx_hashes
                ]
                
                logger.info(f"Received block: {block.hash}")
            
        except Exception as e:
            logger.error(f"Error handling block message: {e}")
    
    def _handle_consensus_propose(self, message: NetworkMessage):
        """Handle consensus proposal message"""
        # Forward to consensus mechanism
        # Implementation depends on consensus integration
        pass
    
    def _handle_consensus_vote(self, message: NetworkMessage):
        """Handle consensus vote message"""
        # Forward to consensus mechanism
        # Implementation depends on consensus integration
        pass
    
    def _handle_dht_store(self, message: NetworkMessage):
        """Handle DHT store request"""
        try:
            key = message.payload['key']
            value = message.payload['value']
            
            # Store in DHT
            success = self.dht_network.store_blockchain_data(key, value)
            
            # Send response
            response = NetworkMessage(
                message_type=MessageType.DHT_RESPONSE,
                sender=self.node_id,
                recipient=message.sender,
                payload={'success': success, 'key': key}
            )
            self.p2p_node.send_message(message.sender, response)
            
            self.stats['dht_operations'] += 1
            
        except Exception as e:
            logger.error(f"Error handling DHT store: {e}")
    
    def _handle_dht_retrieve(self, message: NetworkMessage):
        """Handle DHT retrieve request"""
        try:
            key = message.payload['key']
            
            # Retrieve from DHT
            value = self.dht_network.retrieve_blockchain_data(key)
            
            # Send response
            response = NetworkMessage(
                message_type=MessageType.DHT_RESPONSE,
                sender=self.node_id,
                recipient=message.sender,
                payload={'key': key, 'value': value}
            )
            self.p2p_node.send_message(message.sender, response)
            
            self.stats['dht_operations'] += 1
            
        except Exception as e:
            logger.error(f"Error handling DHT retrieve: {e}")
    
    def _validate_block(self, block: Block) -> bool:
        """Validate a block"""
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
    
    def _serialize_transaction(self, tx: Transaction) -> Dict:
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
            'gas_limit': tx.gas_limit,
            'zone_block_cid': tx.zone_block_cid,
            'signature': tx.signature.hex() if tx.signature else None
        }
    
    def _deserialize_transaction(self, data: Dict) -> Transaction:
        """Deserialize transaction from network"""
        tx = Transaction(
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
        tx.zone_block_cid = data.get('zone_block_cid')
        if data.get('signature'):
            tx.signature = bytes.fromhex(data['signature'])
        return tx
    
    def _serialize_block(self, block: Block) -> Dict:
        """Serialize block for network"""
        return {
            'index': block.index,
            'timestamp': block.timestamp,
            'transactions': [self._serialize_transaction(tx) for tx in block.transactions],
            'previous_hash': block.previous_hash,
            'validator': block.validator,
            'nonce': block.nonce,
            'merkle_root': block.merkle_root,
            'hash': block.hash
        }
    
    def _deserialize_block(self, data: Dict) -> Block:
        """Deserialize block from network"""
        transactions = [self._deserialize_transaction(tx_data) for tx_data in data['transactions']]
        
        block = Block(
            index=data['index'],
            transactions=transactions,
            previous_hash=data['previous_hash'],
            validator=data['validator']
        )
        block.timestamp = data['timestamp']
        block.nonce = data['nonce']
        block.merkle_root = data['merkle_root']
        block.hash = data['hash']
        
        return block
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get node statistics"""
        return {
            'node_id': self.node_id,
            'blockchain_height': len(self.blockchain.chain),
            'pending_transactions': len(self.blockchain.pending_transactions),
            'node_stats': self.stats,
            'network_stats': self.p2p_node.get_network_stats(),
            'dht_stats': self.dht_network.get_network_statistics(),
            'contribution': self.contribution_mechanism.calculate_contribution(self.node_id)
        }


class BlockchainSimulator:
    """Simulator for testing the blockchain network"""
    
    def __init__(self, num_nodes: int = 10):
        self.num_nodes = num_nodes
        self.nodes: List[BlockchainNode] = []
        self.base_port = 8000
        self.base_dht_port = 9000
        
    def setup_network(self):
        """Setup the blockchain network"""
        logger.info(f"Setting up network with {self.num_nodes} nodes")
        
        # Create nodes
        for i in range(self.num_nodes):
            node_id = f"node_{i}"
            host = "127.0.0.1"
            port = self.base_port + i
            dht_port = self.base_dht_port + i
            
            node = BlockchainNode(node_id, host, port, dht_port)
            self.nodes.append(node)
        
        # Start nodes with bootstrap connections
        bootstrap_nodes = []
        validators = [f"node_{i}" for i in range(min(4, self.num_nodes))]  # First 4 nodes as validators
        
        for i, node in enumerate(self.nodes):
            node.start(bootstrap_nodes if i > 0 else None, validators)
            
            # Add this node as bootstrap for others
            if i < 3:  # Use first 3 nodes as bootstrap
                bootstrap_nodes.append(("127.0.0.1", port))
            
            time.sleep(0.5)  # Small delay between node starts
        
        logger.info("Network setup complete")
    
    def simulate_transactions(self, num_transactions: int = 100, duration: int = 60):
        """Simulate random transactions between nodes"""
        logger.info(f"Simulating {num_transactions} transactions over {duration} seconds")
        
        start_time = time.time()
        transactions_created = 0
        
        while transactions_created < num_transactions and (time.time() - start_time) < duration:
            # Random sender and recipient
            sender_node = random.choice(self.nodes)
            recipient_id = f"node_{random.randint(0, self.num_nodes - 1)}"
            
            # Random amount
            amount = random.uniform(0.1, 100.0)
            
            # Create transaction
            success = sender_node.create_transaction(
                recipient=recipient_id,
                amount=amount,
                tx_type=random.choice(list(TransactionType))
            )
            
            if success:
                transactions_created += 1
                logger.debug(f"Transaction {transactions_created}/{num_transactions} created")
            
            # Random delay between transactions
            time.sleep(random.uniform(0.1, 1.0))
        
        logger.info(f"Created {transactions_created} transactions")
    
    def start_mining_on_nodes(self, num_miners: int = 3):
        """Start mining on selected nodes"""
        miners = random.sample(self.nodes, min(num_miners, len(self.nodes)))
        
        for node in miners:
            node.start_mining()
            logger.info(f"Mining started on {node.node_id}")
    
    def run_performance_test(self):
        """Run performance test based on paper metrics"""
        logger.info("Starting performance test")
        
        results = {
            'transaction_verification_times': [],
            'consensus_achievement_times': [],
            'network_communication_delays': [],
            'load_balancing_times': [],
            'tps_measurements': []
        }
        
        # Test 1: Transaction Verification Speed
        logger.info("Testing transaction verification speed...")
        for _ in range(10):
            start = time.time()
            node = random.choice(self.nodes)
            success = node.create_transaction(
                recipient=f"node_{random.randint(0, self.num_nodes-1)}",
                amount=random.uniform(1, 100)
            )
            if success:
                verification_time = time.time() - start
                results['transaction_verification_times'].append(verification_time)
        
        # Test 2: Consensus Achievement Time
        logger.info("Testing consensus achievement time...")
        validators = [node.node_id for node in self.nodes[:4]]
        consensus_node = self.nodes[0]
        
        start = time.time()
        consensus_node.consensus.start_consensus(validators)
        time.sleep(10)  # Let consensus run
        consensus_time = time.time() - start
        results['consensus_achievement_times'].append(consensus_time)
        
        # Test 3: Network Communication Delay
        logger.info("Testing network communication delay...")
        for _ in range(10):
            sender = random.choice(self.nodes)
            
            start = time.time()
            test_message = NetworkMessage(
                message_type=MessageType.HEARTBEAT,
                sender=sender.node_id,
                recipient="",
                payload={'test': True}
            )
            sender.p2p_node.broadcast_message(test_message)
            delay = (time.time() - start) * 1000  # Convert to milliseconds
            results['network_communication_delays'].append(delay)
        
        # Test 4: TPS (Transactions Per Second)
        logger.info("Testing TPS...")
        start = time.time()
        tx_count = 0
        test_duration = 10  # seconds
        
        while time.time() - start < test_duration:
            node = random.choice(self.nodes)
            if node.create_transaction(
                recipient=f"node_{random.randint(0, self.num_nodes-1)}",
                amount=random.uniform(1, 100)
            ):
                tx_count += 1
        
        tps = tx_count / test_duration
        results['tps_measurements'].append(tps)
        
        # Print results
        self._print_performance_results(results)
        
        return results
    
    def _print_performance_results(self, results: Dict):
        """Print performance test results"""
        print("\n" + "="*60)
        print("PERFORMANCE TEST RESULTS")
        print("="*60)
        
        if results['transaction_verification_times']:
            avg_verification = sum(results['transaction_verification_times']) / len(results['transaction_verification_times'])
            print(f"Average Transaction Verification Time: {avg_verification:.4f} seconds")
        
        if results['consensus_achievement_times']:
            avg_consensus = sum(results['consensus_achievement_times']) / len(results['consensus_achievement_times'])
            print(f"Average Consensus Achievement Time: {avg_consensus:.2f} seconds")
        
        if results['network_communication_delays']:
            avg_delay = sum(results['network_communication_delays']) / len(results['network_communication_delays'])
            print(f"Average Network Communication Delay: {avg_delay:.2f} milliseconds")
        
        if results['tps_measurements']:
            avg_tps = sum(results['tps_measurements']) / len(results['tps_measurements'])
            print(f"Average TPS: {avg_tps:.2f} transactions/second")
        
        print("="*60 + "\n")
    
    def print_network_status(self):
        """Print current network status"""
        print("\n" + "="*60)
        print("NETWORK STATUS")
        print("="*60)
        
        for node in self.nodes:
            stats = node.get_statistics()
            print(f"\n{node.node_id}:")
            print(f"  Blockchain Height: {stats['blockchain_height']}")
            print(f"  Pending Transactions: {stats['pending_transactions']}")
            print(f"  Connected Peers: {stats['network_stats']['connected_peers']}")
            print(f"  Contribution Score: {stats['contribution']:.4f}")
            print(f"  Transactions Processed: {stats['node_stats']['transactions_processed']}")
            print(f"  Blocks Mined: {stats['node_stats']['blocks_mined']}")
        
        print("="*60 + "\n")
    
    def shutdown(self):
        """Shutdown all nodes"""
        logger.info("Shutting down network")
        
        for node in self.nodes:
            node.stop()
        
        logger.info("Network shutdown complete")


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Blockchain DHT Optimization Implementation')
    parser.add_argument('--nodes', type=int, default=10, help='Number of nodes in the network')
    parser.add_argument('--transactions', type=int, default=100, help='Number of transactions to simulate')
    parser.add_argument('--miners', type=int, default=3, help='Number of mining nodes')
    parser.add_argument('--duration', type=int, default=60, help='Simulation duration in seconds')
    parser.add_argument('--test', action='store_true', help='Run performance tests')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')
    
    args = parser.parse_args()
    
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║     BLOCKCHAIN DHT OPTIMIZATION IMPLEMENTATION            ║
    ║     Based on Research Paper Implementation                ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    # Create simulator
    simulator = BlockchainSimulator(num_nodes=args.nodes)
    
    try:
        # Setup network
        print(f"\n[1] Setting up network with {args.nodes} nodes...")
        simulator.setup_network()
        time.sleep(5)  # Let network stabilize
        
        # Start mining
        print(f"\n[2] Starting mining on {args.miners} nodes...")
        simulator.start_mining_on_nodes(args.miners)
        time.sleep(2)
        
        if args.test:
            # Run performance tests
            print("\n[3] Running performance tests...")
            simulator.run_performance_test()
        
        if args.interactive:
            # Interactive mode
            print("\n[3] Entering interactive mode...")
            interactive_mode(simulator)
        else:
            # Simulation mode
            print(f"\n[3] Simulating {args.transactions} transactions...")
            simulator.simulate_transactions(args.transactions, args.duration)
            
            # Let the network process
            print("\n[4] Processing transactions...")
            time.sleep(10)
            
            # Print final status
            simulator.print_network_status()
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        logger.error(f"Error in simulation: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Shutdown
        print("\n[5] Shutting down network...")
        simulator.shutdown()
        print("\nSimulation complete!")


def interactive_mode(simulator: BlockchainSimulator):
    """Interactive mode for manual testing"""
    print("""
    Interactive Mode Commands:
    - status: Show network status
    - tx <from_node> <to_node> <amount>: Create transaction
    - mine <node>: Start/stop mining on node
    - test: Run performance test
    - stats <node>: Show node statistics
    - quit: Exit
    """)
    
    while True:
        try:
            command = input("\n> ").strip().lower().split()
            
            if not command:
                continue
            
            if command[0] == 'quit':
                break
            
            elif command[0] == 'status':
                simulator.print_network_status()
            
            elif command[0] == 'tx' and len(command) == 4:
                from_idx = int(command[1])
                to_idx = int(command[2])
                amount = float(command[3])
                
                if 0 <= from_idx < len(simulator.nodes) and 0 <= to_idx < len(simulator.nodes):
                    sender = simulator.nodes[from_idx]
                    recipient = f"node_{to_idx}"
                    
                    success = sender.create_transaction(recipient, amount)
                    if success:
                        print(f"Transaction created from node_{from_idx} to {recipient} for {amount}")
                    else:
                        print("Transaction failed")
                else:
                    print("Invalid node index")
            
            elif command[0] == 'mine' and len(command) == 2:
                node_idx = int(command[1])
                if 0 <= node_idx < len(simulator.nodes):
                    node = simulator.nodes[node_idx]
                    if node.mining:
                        node.stop_mining()
                        print(f"Stopped mining on node_{node_idx}")
                    else:
                        node.start_mining()
                        print(f"Started mining on node_{node_idx}")
                else:
                    print("Invalid node index")
            
            elif command[0] == 'test':
                simulator.run_performance_test()
            
            elif command[0] == 'stats' and len(command) == 2:
                node_idx = int(command[1])
                if 0 <= node_idx < len(simulator.nodes):
                    stats = simulator.nodes[node_idx].get_statistics()
                    print(f"\nStatistics for node_{node_idx}:")
                    print(json.dumps(stats, indent=2))
                else:
                    print("Invalid node index")
            
            else:
                print("Invalid command. Type 'quit' to exit.")
        
        except ValueError as e:
            print(f"Invalid input: {e}")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    # Create required directories
    os.makedirs("logs", exist_ok=True)
    os.makedirs("data", exist_ok=True)
    
    # Run main
    main()