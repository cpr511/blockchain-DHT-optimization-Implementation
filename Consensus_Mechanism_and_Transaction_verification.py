"""
Consensus Mechanism and Transaction Verification Module
Based on Paper Section 2.2 and 2.3
"""

import hashlib
import time
import random
import math
import threading
import json
import secrets
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

logger = logging.getLogger(__name__)

class ConsensusState(Enum):
    """Consensus state machine states"""
    NEW_HEIGHT = "new_height"
    PROPOSE = "propose"
    PREVOTE = "prevote"
    PRECOMMIT = "precommit"
    COMMIT = "commit"

class VoteType(Enum):
    """Types of votes in consensus"""
    PREVOTE = "prevote"
    PRECOMMIT = "precommit"

@dataclass
class Vote:
    """Vote structure for consensus mechanism"""
    validator: str
    height: int
    round: int
    vote_type: VoteType
    block_hash: str
    timestamp: float
    signature: Optional[bytes] = None
    
    def calculate_hash(self) -> str:
        """Calculate vote hash"""
        vote_string = json.dumps({
            'validator': self.validator,
            'height': self.height,
            'round': self.round,
            'vote_type': self.vote_type.value,
            'block_hash': self.block_hash,
            'timestamp': self.timestamp
        }, sort_keys=True)
        return hashlib.sha256(vote_string.encode()).hexdigest()

class ContributionMechanism:
    """Implementation of contribution-based consensus (Paper Section 2.3.2)"""
    
    def __init__(self):
        # Weight parameters from the paper
        self.delta_1 = 0.25  # Currency age weight
        self.delta_2 = 0.25  # Data collection weight
        self.delta_3 = 0.25  # State allocation weight
        self.delta_4 = 0.25  # Consensus behavior weight
        
        self.omega = 1.0  # Currency age scaling factor
        self.sigma_1 = 1.0  # Data upload reward
        self.sigma_2 = 2.0  # Negative behavior penalty
        self.gamma_1 = 1.0  # State allocation acceptance weight
        self.gamma_2 = 1.5  # State allocation rejection weight
        self.alpha_1 = 10.0  # Correct vote reward (α₁ >> α₂)
        self.alpha_2 = 0.1  # Malicious vote penalty
        
        # Node contribution records
        self.node_contributions: Dict[str, Dict[str, float]] = {}
    
    def calculate_contribution(self, node_id: str) -> float:
        """Calculate total contribution for a node (Formula 2)"""
        if node_id not in self.node_contributions:
            self._initialize_node_contribution(node_id)
        
        contrib = self.node_contributions[node_id]
        
        A_z = self._calculate_currency_age_contribution(contrib)
        A_x = self._calculate_data_collection_contribution(contrib)
        A_s = self._calculate_state_allocation_contribution(contrib)
        A_a = self._calculate_consensus_behavior_contribution(contrib)
        
        # Formula 2: A_n = δ₁*A_z + δ₂*A_x + δ₃*A_s + δ₄*A_a
        total = (self.delta_1 * A_z + 
                self.delta_2 * A_x + 
                self.delta_3 * A_s + 
                self.delta_4 * A_a)
        
        return max(0, total)  # Contribution cannot be negative
    
    def _initialize_node_contribution(self, node_id: str):
        """Initialize contribution record for a new node"""
        self.node_contributions[node_id] = {
            'currency': 100.0,  # Initial currency
            'currency_time': time.time(),  # Time when currency obtained
            'data_uploads': 0,
            'negative_behaviors': 0,
            'state_acceptances': 0,
            'state_rejections': 0,
            'correct_votes': 0,
            'malicious_votes': 0,
            'total_votes': 0,
            'total_transactions': 0
        }
    
    def _calculate_currency_age_contribution(self, contrib: Dict) -> float:
        """Calculate currency age contribution (Formula 3)"""
        Z_n = contrib['currency']
        r = time.time() - contrib['currency_time']  # Time period
        
        # A_z(Z_n, r) = ω * log(Z_n * r)
        if Z_n * r > 0:
            return self.omega * math.log(Z_n * r)
        return 0
    
    def _calculate_data_collection_contribution(self, contrib: Dict) -> float:
        """Calculate data collection contribution (Formula 4)"""
        M_n_Q = contrib['data_uploads']  # Upload frequency
        M_n_L = contrib['negative_behaviors']  # Negative state count
        
        # A_x(M_n) = σ₁*M_n^Q - σ₂*M_n^L
        return self.sigma_1 * M_n_Q - self.sigma_2 * M_n_L
    
    def _calculate_state_allocation_contribution(self, contrib: Dict) -> float:
        """Calculate state allocation contribution (Formula 5)"""
        R_n_ta = contrib['state_acceptances']  # Acceptance count
        R_n_tg = contrib['state_rejections']  # Rejection count
        
        # A_s(R_n) = γ₁*R_n^ta - γ₂*R_n^tg
        return self.gamma_1 * R_n_ta - self.gamma_2 * R_n_tg
    
    def _calculate_consensus_behavior_contribution(self, contrib: Dict) -> float:
        """Calculate consensus behavior contribution (Formula 6)"""
        L_na = contrib['correct_votes']  # Correct votes
        L_no = contrib['malicious_votes']  # Malicious votes
        R_total = contrib['total_transactions']  # Total transactions
        
        if R_total == 0:
            return 0
        
        # A_a(L_n) = α₁*L_na/R_total - α₂*L_no/R_total
        return self.alpha_1 * (L_na / R_total) - self.alpha_2 * (L_no / R_total)
    
    def update_currency(self, node_id: str, amount: float):
        """Update node's currency holding"""
        if node_id not in self.node_contributions:
            self._initialize_node_contribution(node_id)
        
        self.node_contributions[node_id]['currency'] += amount
        if amount > 0:
            self.node_contributions[node_id]['currency_time'] = time.time()
    
    def record_data_upload(self, node_id: str):
        """Record a data upload by node"""
        if node_id not in self.node_contributions:
            self._initialize_node_contribution(node_id)
        
        self.node_contributions[node_id]['data_uploads'] += 1
    
    def record_negative_behavior(self, node_id: str):
        """Record negative behavior by node"""
        if node_id not in self.node_contributions:
            self._initialize_node_contribution(node_id)
        
        self.node_contributions[node_id]['negative_behaviors'] += 1
    
    def record_state_allocation(self, node_id: str, accepted: bool):
        """Record state allocation result"""
        if node_id not in self.node_contributions:
            self._initialize_node_contribution(node_id)
        
        if accepted:
            self.node_contributions[node_id]['state_acceptances'] += 1
        else:
            self.node_contributions[node_id]['state_rejections'] += 1
    
    def record_vote(self, node_id: str, is_correct: bool):
        """Record voting behavior"""
        if node_id not in self.node_contributions:
            self._initialize_node_contribution(node_id)
        
        self.node_contributions[node_id]['total_votes'] += 1
        if is_correct:
            self.node_contributions[node_id]['correct_votes'] += 1
        else:
            self.node_contributions[node_id]['malicious_votes'] += 1
    
    def get_malicious_ratio(self, node_id: str) -> float:
        """Calculate malicious behavior ratio (Formula 7)"""
        if node_id not in self.node_contributions:
            return 0
        
        contrib = self.node_contributions[node_id]
        L_no = contrib['malicious_votes']
        L_na = contrib['correct_votes']
        
        total = L_no + L_na
        if total == 0:
            return 0
        
        # L = L_no / (L_no + L_na)
        return L_no / total

class TendermintOptimized:
    """Optimized Tendermint consensus with contribution mechanism (Paper Section 2.3)"""
    
    def __init__(self, node_id: str, contribution_mechanism: ContributionMechanism):
        self.node_id = node_id
        self.contribution_mechanism = contribution_mechanism
        
        # Consensus parameters
        self.height = 0
        self.round = 0
        self.step = ConsensusState.NEW_HEIGHT
        self.locked_value = None
        self.locked_round = -1
        self.valid_value = None
        self.valid_round = -1
        
        # Timing parameters (milliseconds)
        self.timeout_propose = 3000
        self.timeout_prevote = 1000
        self.timeout_precommit = 1000
        self.timeout_commit = 1000
        
        # Vote tracking
        self.prevotes: Dict[int, Dict[int, List[Vote]]] = {}  # height -> round -> votes
        self.precommits: Dict[int, Dict[int, List[Vote]]] = {}
        
        # Validator set management
        self.validators: Set[str] = set()
        self.validator_powers: Dict[str, float] = {}
        self.is_proposer = False
        
        # Message buffer
        self.message_buffer: List[Dict] = []
        
        # Thread management
        self.running = False
        self.consensus_thread = None
        self.lock = threading.RLock()
    
    def start_consensus(self, validators: List[str]):
        """Start the consensus mechanism"""
        self.running = True
        self.validators = set(validators)
        
        # Calculate validator powers based on contributions
        self._update_validator_powers()
        
        # Start consensus loop
        self.consensus_thread = threading.Thread(target=self._consensus_loop, daemon=True)
        self.consensus_thread.start()
        
        logger.info(f"Node {self.node_id} started Tendermint consensus")
    
    def stop_consensus(self):
        """Stop the consensus mechanism"""
        self.running = False
        if self.consensus_thread:
            self.consensus_thread.join(timeout=5)
        
        logger.info(f"Node {self.node_id} stopped consensus")
    
    def _update_validator_powers(self):
        """Update validator powers based on contributions"""
        total_contribution = 0
        for validator in self.validators:
            contribution = self.contribution_mechanism.calculate_contribution(validator)
            self.validator_powers[validator] = contribution
            total_contribution += contribution
        
        # Normalize powers
        if total_contribution > 0:
            for validator in self.validators:
                self.validator_powers[validator] /= total_contribution
    
    def _consensus_loop(self):
        """Main consensus loop"""
        while self.running:
            with self.lock:
                if self.step == ConsensusState.NEW_HEIGHT:
                    self._on_new_height()
                elif self.step == ConsensusState.PROPOSE:
                    self._on_propose()
                elif self.step == ConsensusState.PREVOTE:
                    self._on_prevote()
                elif self.step == ConsensusState.PRECOMMIT:
                    self._on_precommit()
                elif self.step == ConsensusState.COMMIT:
                    self._on_commit()
            
            time.sleep(0.1)  # Small delay to prevent busy waiting
    
    def _on_new_height(self):
        """Handle new height state"""
        self.height += 1
        self.round = 0
        self.step = ConsensusState.PROPOSE
        self.locked_value = None
        self.locked_round = -1
        self.valid_value = None
        self.valid_round = -1
        
        # Clear old votes
        if self.height - 1 in self.prevotes:
            del self.prevotes[self.height - 1]
        if self.height - 1 in self.precommits:
            del self.precommits[self.height - 1]
        
        # Select proposer based on contribution-weighted selection
        self._select_proposer()
        
        logger.debug(f"Node {self.node_id} entering height {self.height}")
    
    def _select_proposer(self):
        """Select proposer based on weighted contribution"""
        if not self.validators:
            return
        
        # Update validator powers
        self._update_validator_powers()
        
        # Weighted random selection
        total_power = sum(self.validator_powers.values())
        if total_power == 0:
            # Fallback to random selection
            proposer = random.choice(list(self.validators))
        else:
            # Weighted selection based on contribution
            rand_val = random.random() * total_power
            cumulative = 0
            proposer = None
            
            for validator, power in self.validator_powers.items():
                cumulative += power
                if cumulative >= rand_val:
                    proposer = validator
                    break
        
        self.is_proposer = (proposer == self.node_id)
        
        if self.is_proposer:
            logger.info(f"Node {self.node_id} selected as proposer for height {self.height}")
    
    def _on_propose(self):
        """Handle propose state"""
        if self.is_proposer:
            # Create and broadcast proposal
            proposal = self._create_proposal()
            self._broadcast_proposal(proposal)
        
        # Wait for proposal or timeout
        time.sleep(self.timeout_propose / 1000)
        
        # Move to prevote
        self.step = ConsensusState.PREVOTE
    
    def _on_prevote(self):
        """Handle prevote state"""
        # Vote for proposed block or nil
        vote = self._create_prevote()
        self._broadcast_vote(vote)
        
        # Wait for 2/3+ prevotes
        if self._wait_for_votes(VoteType.PREVOTE, self.timeout_prevote):
            self.step = ConsensusState.PRECOMMIT
        else:
            # Timeout - move to next round
            self.round += 1
            self.step = ConsensusState.PROPOSE
    
    def _on_precommit(self):
        """Handle precommit state"""
        # Check if we have 2/3+ prevotes for a value
        prevote_value = self._get_prevote_value()
        
        if prevote_value:
            # Lock on the value
            self.locked_value = prevote_value
            self.locked_round = self.round
            self.valid_value = prevote_value
            self.valid_round = self.round
            
            # Create and broadcast precommit
            vote = self._create_precommit(prevote_value)
        else:
            # Precommit nil
            vote = self._create_precommit(None)
        
        self._broadcast_vote(vote)
        
        # Wait for 2/3+ precommits
        if self._wait_for_votes(VoteType.PRECOMMIT, self.timeout_precommit):
            self.step = ConsensusState.COMMIT
        else:
            # Timeout - move to next round
            self.round += 1
            self.step = ConsensusState.PROPOSE
    
    def _on_commit(self):
        """Handle commit state"""
        precommit_value = self._get_precommit_value()
        
        if precommit_value:
            # Commit the block
            self._commit_block(precommit_value)
            
            # Record correct vote for contribution
            self.contribution_mechanism.record_vote(self.node_id, True)
            
            # Move to next height
            self.step = ConsensusState.NEW_HEIGHT
        else:
            # No decision - move to next round
            self.round += 1
            self.step = ConsensusState.PROPOSE
    
    def _create_proposal(self) -> Dict:
        """Create a block proposal"""
        # In real implementation, this would create actual block
        return {
            'height': self.height,
            'round': self.round,
            'proposer': self.node_id,
            'block_hash': hashlib.sha256(f"{self.height}:{self.round}:{self.node_id}".encode()).hexdigest(),
            'timestamp': time.time()
        }
    
    def _create_prevote(self) -> Vote:
        """Create a prevote"""
        # Vote for valid value if exists, otherwise nil
        block_hash = self.valid_value if self.valid_value else ""
        
        return Vote(
            validator=self.node_id,
            height=self.height,
            round=self.round,
            vote_type=VoteType.PREVOTE,
            block_hash=block_hash,
            timestamp=time.time()
        )
    
    def _create_precommit(self, value: Optional[str]) -> Vote:
        """Create a precommit"""
        return Vote(
            validator=self.node_id,
            height=self.height,
            round=self.round,
            vote_type=VoteType.PRECOMMIT,
            block_hash=value if value else "",
            timestamp=time.time()
        )
    
    def _broadcast_proposal(self, proposal: Dict):
        """Broadcast proposal to all validators"""
        # In real implementation, this would use network layer
        logger.debug(f"Broadcasting proposal: {proposal}")
    
    def _broadcast_vote(self, vote: Vote):
        """Broadcast vote to all validators"""
        # Store own vote
        if vote.vote_type == VoteType.PREVOTE:
            if self.height not in self.prevotes:
                self.prevotes[self.height] = {}
            if self.round not in self.prevotes[self.height]:
                self.prevotes[self.height][self.round] = []
            self.prevotes[self.height][self.round].append(vote)
        else:
            if self.height not in self.precommits:
                self.precommits[self.height] = {}
            if self.round not in self.precommits[self.height]:
                self.precommits[self.height][self.round] = []
            self.precommits[self.height][self.round].append(vote)
        
        logger.debug(f"Broadcasting {vote.vote_type.value}: {vote.block_hash}")
    
    def _wait_for_votes(self, vote_type: VoteType, timeout_ms: int) -> bool:
        """Wait for 2/3+ votes of given type"""
        start_time = time.time()
        required_power = 2.0 / 3.0
        
        while (time.time() - start_time) * 1000 < timeout_ms:
            votes = self._get_votes(vote_type)
            if self._has_quorum(votes, required_power):
                return True
            time.sleep(0.1)
        
        return False
    
    def _get_votes(self, vote_type: VoteType) -> List[Vote]:
        """Get votes of given type for current height and round"""
        if vote_type == VoteType.PREVOTE:
            if self.height in self.prevotes and self.round in self.prevotes[self.height]:
                return self.prevotes[self.height][self.round]
        else:
            if self.height in self.precommits and self.round in self.precommits[self.height]:
                return self.precommits[self.height][self.round]
        
        return []
    
    def _has_quorum(self, votes: List[Vote], required_power: float) -> bool:
        """Check if votes meet quorum requirement"""
        total_power = 0
        
        for vote in votes:
            if vote.validator in self.validator_powers:
                total_power += self.validator_powers[vote.validator]
        
        return total_power >= required_power
    
    def _get_prevote_value(self) -> Optional[str]:
        """Get value with 2/3+ prevotes"""
        votes = self._get_votes(VoteType.PREVOTE)
        vote_counts = {}
        
        for vote in votes:
            if vote.block_hash:
                if vote.block_hash not in vote_counts:
                    vote_counts[vote.block_hash] = 0
                vote_counts[vote.block_hash] += self.validator_powers.get(vote.validator, 0)
        
        for block_hash, power in vote_counts.items():
            if power >= 2.0 / 3.0:
                return block_hash
        
        return None
    
    def _get_precommit_value(self) -> Optional[str]:
        """Get value with 2/3+ precommits"""
        votes = self._get_votes(VoteType.PRECOMMIT)
        vote_counts = {}
        
        for vote in votes:
            if vote.block_hash:
                if vote.block_hash not in vote_counts:
                    vote_counts[vote.block_hash] = 0
                vote_counts[vote.block_hash] += self.validator_powers.get(vote.validator, 0)
        
        for block_hash, power in vote_counts.items():
            if power >= 2.0 / 3.0:
                return block_hash
        
        return None
    
    def _commit_block(self, block_hash: str):
        """Commit a block to the blockchain"""
        logger.info(f"Node {self.node_id} committed block {block_hash} at height {self.height}")
        
        # Update contribution for successful consensus
        self.contribution_mechanism.record_state_allocation(self.node_id, True)


class ZeroKnowledgeProof:
    """Zero-knowledge proof implementation for transaction verification"""
    
    def __init__(self):
        self.proofs: Dict[str, Dict] = {}
        self.commitments: Dict[str, bytes] = {}
    
    def generate_proof(self, secret: str, public_input: str) -> Dict[str, Any]:
        """Generate zero-knowledge proof"""
        # Hash the secret to create commitment
        commitment = hashlib.sha256((secret + public_input).encode()).digest()
        
        # Generate random challenge
        challenge = secrets.token_bytes(32)
        
        # Calculate response
        response = hashlib.sha256(secret.encode() + challenge).digest()
        
        proof = {
            'commitment': commitment.hex(),
            'challenge': challenge.hex(),
            'response': response.hex(),
            'public_input': public_input,
            'timestamp': time.time()
        }
        
        # Store proof for verification
        proof_id = hashlib.sha256(json.dumps(proof).encode()).hexdigest()
        self.proofs[proof_id] = proof
        self.commitments[proof_id] = commitment
        
        return proof
    
    def verify_proof(self, proof: Dict[str, Any]) -> bool:
        """Verify zero-knowledge proof"""
        try:
            # Reconstruct proof ID
            proof_id = hashlib.sha256(json.dumps(proof).encode()).hexdigest()
            
            # Check if proof exists
            if proof_id not in self.proofs:
                return False
            
            stored_proof = self.proofs[proof_id]
            
            # Verify proof components match
            if (proof['commitment'] != stored_proof['commitment'] or
                proof['challenge'] != stored_proof['challenge'] or
                proof['response'] != stored_proof['response']):
                return False
            
            # Additional verification logic can be added here
            return True
            
        except Exception as e:
            logger.error(f"Error verifying proof: {e}")
            return False


class TransactionVerificationModel:
    """DHT-based transaction verification model (Paper Section 2.2)"""
    
    def __init__(self, dht_network=None):
        self.dht_network = dht_network
        self.zero_knowledge = ZeroKnowledgeProof()
        self.authorization_authority = AuthorizationAuthority()
        self.smart_contracts: Dict[str, 'SmartContract'] = {}
        self.verification_cache: Dict[str, bool] = {}
        self.trust_threshold = 0.7
        
    def verify_transaction(self, transaction: 'Transaction', sender_public_key: rsa.RSAPublicKey) -> bool:
        """Verify transaction using DHT-based model"""
        tx_hash = transaction.calculate_hash()
        
        # Check cache first
        if tx_hash in self.verification_cache:
            return self.verification_cache[tx_hash]
        
        # Step 1: Verify transaction signature
        if not transaction.verify_signature(sender_public_key):
            logger.warning(f"Invalid signature for transaction {tx_hash}")
            self.verification_cache[tx_hash] = False
            return False
        
        # Step 2: Generate zero-knowledge proof
        proof = self.zero_knowledge.generate_proof(
            secret=tx_hash,
            public_input=transaction.sender
        )
        
        # Step 3: Verify authorization through smart contract
        if not self._verify_authorization(transaction, proof):
            logger.warning(f"Authorization failed for transaction {tx_hash}")
            self.verification_cache[tx_hash] = False
            return False
        
        # Step 4: Store verification in DHT
        if self.dht_network:
            verification_data = {
                'tx_hash': tx_hash,
                'verified': True,
                'timestamp': time.time(),
                'proof_id': hashlib.sha256(json.dumps(proof).encode()).hexdigest()
            }
            self.dht_network.store_blockchain_data(tx_hash, verification_data)
        
        # Cache result
        self.verification_cache[tx_hash] = True
        return True
    
    def _verify_authorization(self, transaction: 'Transaction', proof: Dict) -> bool:
        """Verify transaction authorization"""
        # Get trust level for sender
        trust_level = self.authorization_authority.calculate_trust_level(transaction.sender)
        
        # Check if trust level meets threshold
        if trust_level < self.trust_threshold:
            return False
        
        # Verify zero-knowledge proof
        if not self.zero_knowledge.verify_proof(proof):
            return False
        
        # Additional authorization checks
        return self.authorization_authority.authorize_transaction(transaction, trust_level)


class AuthorizationAuthority:
    """Authorization authority for transaction verification"""
    
    def __init__(self):
        self.trust_levels: Dict[str, float] = {}
        self.authorization_lists: Dict[str, List[str]] = {}
        self.encrypted_data: Dict[str, bytes] = {}
        self.keys: Dict[str, rsa.RSAPrivateKey] = {}
        
    def calculate_trust_level(self, address: str) -> float:
        """Calculate trust level for an address"""
        if address not in self.trust_levels:
            # Initialize with base trust level
            self.trust_levels[address] = 0.5
        
        return self.trust_levels[address]
    
    def update_trust_level(self, address: str, delta: float):
        """Update trust level based on behavior"""
        if address not in self.trust_levels:
            self.trust_levels[address] = 0.5
        
        self.trust_levels[address] = max(0, min(1, self.trust_levels[address] + delta))
    
    def authorize_transaction(self, transaction: 'Transaction', trust_level: float) -> bool:
        """Authorize transaction based on trust level"""
        # Different transaction types require different trust levels
        required_trust = {
            'TransactionType.TRANSFER': 0.3,
            'TransactionType.CONTRACT': 0.5,
            'TransactionType.STAKE': 0.6,
            'TransactionType.REWARD': 0.2,
            'TransactionType.DATA_STORAGE': 0.4
        }
        
        tx_type_str = str(transaction.transaction_type)
        required = required_trust.get(tx_type_str, 0.5)
        
        return trust_level >= required
    
    def generate_authorization_list(self, address: str, permissions: List[str]) -> bytes:
        """Generate encrypted authorization list"""
        # Generate key pair if not exists
        if address not in self.keys:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.keys[address] = private_key
        
        # Create authorization list
        auth_list = {
            'address': address,
            'permissions': permissions,
            'timestamp': time.time(),
            'expiry': time.time() + 3600  # 1 hour expiry
        }
        
        # Encrypt the list
        public_key = self.keys[address].public_key()
        encrypted = public_key.encrypt(
            json.dumps(auth_list).encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        self.authorization_lists[address] = permissions
        self.encrypted_data[address] = encrypted
        
        return encrypted
    
    def decrypt_authorization_list(self, address: str, encrypted_data: bytes) -> Optional[Dict]:
        """Decrypt authorization list"""
        if address not in self.keys:
            return None
        
        try:
            decrypted = self.keys[address].decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return json.loads(decrypted.decode())
        except Exception as e:
            logger.error(f"Failed to decrypt authorization list: {e}")
            return None


class SmartContract:
    """Smart contract for automated verification"""
    
    def __init__(self, contract_id: str, code: str):
        self.contract_id = contract_id
        self.code = code
        self.state: Dict[str, Any] = {}
        self.events: List[Dict] = []
        
    def execute(self, function: str, params: Dict) -> Any:
        """Execute smart contract function"""
        # This is a simplified implementation
        # In reality, this would use a proper VM
        
        if function == "verify_authorization":
            return self._verify_authorization(params)
        elif function == "compare_proofs":
            return self._compare_proofs(params)
        else:
            raise ValueError(f"Unknown function: {function}")
    
    def _verify_authorization(self, params: Dict) -> bool:
        """Verify authorization in smart contract"""
        required_fields = ['sender', 'trust_level', 'proof']
        
        for field in required_fields:
            if field not in params:
                return False
        
        # Verification logic
        trust_level = params['trust_level']
        if trust_level < 0.5:
            return False
        
        # Log event
        self.events.append({
            'type': 'authorization_verified',
            'sender': params['sender'],
            'timestamp': time.time()
        })
        
        return True
    
    def _compare_proofs(self, params: Dict) -> bool:
        """Compare zero-knowledge proofs"""
        if 'proof1' not in params or 'proof2' not in params:
            return False
        
        # Compare proof commitments
        return params['proof1']['commitment'] == params['proof2']['commitment']


class SecurityMechanisms:
    """Security mechanisms implementation (Paper Section 2.3.3)"""
    
    def __init__(self):
        self.eclipse_protection = EclipseProtection()
        self.double_spend_protection = DoubleSpendProtection()
        self.selfish_mining_protection = SelfishMiningProtection()
        self.ddos_protection = DDoSProtection()
        self.replay_protection = ReplayProtection()
    
    def verify_transaction_security(self, transaction: 'Transaction') -> bool:
        """Comprehensive security verification"""
        # Check for double spending
        if not self.double_spend_protection.verify(transaction):
            return False
        
        # Check for replay attacks
        if not self.replay_protection.verify(transaction):
            return False
        
        return True


class EclipseProtection:
    """Protection against eclipse attacks"""
    
    def __init__(self):
        self.peer_lists: Dict[str, Set[str]] = {}
        self.update_interval = 3600  # 1 hour
        
    def update_peer_list(self, node_id: str, peers: Set[str]):
        """Update peer list using cryptographically secure selection"""
        # Use secure random function
        secure_random = secrets.SystemRandom()
        
        # Select diverse peers
        new_peers = set()
        for _ in range(min(20, len(peers))):  # Limit to 20 peers
            peer = secure_random.choice(list(peers - new_peers))
            new_peers.add(peer)
        
        self.peer_lists[node_id] = new_peers
    
    def is_eclipse_attempt(self, node_id: str, new_peers: Set[str]) -> bool:
        """Detect potential eclipse attack"""
        if node_id not in self.peer_lists:
            return False
        
        current_peers = self.peer_lists[node_id]
        
        # Check if too many peers are being replaced
        overlap = len(current_peers & new_peers)
        if overlap < len(current_peers) * 0.3:  # Less than 30% overlap
            return True
        
        return False


class DoubleSpendProtection:
    """Protection against double-spending attacks (Formula 5)"""
    
    def __init__(self):
        self.spent_outputs: Set[str] = set()
        self.pending_transactions: Dict[str, 'Transaction'] = {}
        
    def verify(self, transaction: 'Transaction') -> bool:
        """Verify transaction doesn't double-spend"""
        tx_id = transaction.calculate_hash()
        
        # Check if any input is already spent
        for tx_input in transaction.data.get('inputs', []):
            if tx_input in self.spent_outputs:
                logger.warning(f"Double-spend detected: {tx_id}")
                return False
        
        # Formula 5: Σ(δ(TXj, TXi)) = 0
        for pending_tx in self.pending_transactions.values():
            if self._conflicts_with(transaction, pending_tx):
                return False
        
        # Mark outputs as spent
        for tx_input in transaction.data.get('inputs', []):
            self.spent_outputs.add(tx_input)
        
        self.pending_transactions[tx_id] = transaction
        return True
    
    def _conflicts_with(self, tx1: 'Transaction', tx2: 'Transaction') -> bool:
        """Check if two transactions conflict"""
        inputs1 = set(tx1.data.get('inputs', []))
        inputs2 = set(tx2.data.get('inputs', []))
        
        # Transactions conflict if they share any inputs
        return len(inputs1 & inputs2) > 0


class SelfishMiningProtection:
    """Protection against selfish mining (Formula 6)"""
    
    def __init__(self):
        self.base_reward = 10.0  # α
        self.decay_factor = 0.1  # λ
        self.publication_times: Dict[str, float] = {}
        
    def calculate_reward(self, miner_id: str, block_hash: str, 
                        publication_delay: float) -> float:
        """Calculate mining reward with penalty for delayed publication"""
        # Formula 6: β(Mi) = α * e^(-λτ)
        reward = self.base_reward * math.exp(-self.decay_factor * publication_delay)
        
        # Store publication time
        self.publication_times[block_hash] = time.time()
        
        return max(0, reward)  # Reward cannot be negative


class DDoSProtection:
    """DDoS protection with adaptive rate limiting (Formula 7)"""
    
    def __init__(self):
        self.trust_weights: Dict[str, float] = {}
        self.response_times: Dict[str, List[float]] = {}
        self.request_counts: Dict[str, int] = {}
        self.time_window = 60  # 1 minute window
        
    def calculate_rate_limit(self, node_id: str) -> float:
        """Calculate adaptive rate limit for node"""
        # Formula 7: Rmax = (1/Σwi) * Σ(wi/ti)
        
        total_weight = sum(self.trust_weights.values())
        if total_weight == 0:
            return 100  # Default rate limit
        
        weighted_sum = 0
        for nid, weight in self.trust_weights.items():
            if nid in self.response_times and self.response_times[nid]:
                avg_response = sum(self.response_times[nid]) / len(self.response_times[nid])
                weighted_sum += weight / avg_response if avg_response > 0 else 0
        
        return (1 / total_weight) * weighted_sum if weighted_sum > 0 else 100
    
    def check_rate_limit(self, node_id: str) -> bool:
        """Check if node exceeds rate limit"""
        current_time = time.time()
        
        # Initialize if needed
        if node_id not in self.request_counts:
            self.request_counts[node_id] = 0
            self.trust_weights[node_id] = 0.5
            self.response_times[node_id] = []
        
        # Get rate limit
        rate_limit = self.calculate_rate_limit(node_id)
        
        # Check if within limit
        return self.request_counts[node_id] < rate_limit
    
    def record_request(self, node_id: str, response_time: float):
        """Record request and response time"""
        if node_id not in self.response_times:
            self.response_times[node_id] = []
        
        self.response_times[node_id].append(response_time)
        
        # Keep only recent response times
        if len(self.response_times[node_id]) > 100:
            self.response_times[node_id] = self.response_times[node_id][-100:]
        
        self.request_counts[node_id] = self.request_counts.get(node_id, 0) + 1


class ReplayProtection:
    """Protection against replay attacks (Formula 8)"""
    
    def __init__(self):
        self.used_nonces: Set[int] = set()
        self.nonce_window = 1000  # Keep last 1000 nonces
        self.nonce_list: List[int] = []
        
    def verify(self, transaction: 'Transaction') -> bool:
        """Verify transaction nonce hasn't been used"""
        # Formula 8: Ni ∉ {N1, N2, ..., Nm}
        if transaction.nonce in self.used_nonces:
            logger.warning(f"Replay attack detected: nonce {transaction.nonce} already used")
            return False
        
        # Add nonce to used set
        self.used_nonces.add(transaction.nonce)
        self.nonce_list.append(transaction.nonce)
        
        # Maintain window size
        if len(self.nonce_list) > self.nonce_window:
            old_nonce = self.nonce_list.pop(0)
            self.used_nonces.discard(old_nonce)
        
        return True