# Decentralized Identity Management

A comprehensive Clarity smart contract ecosystem for managing decentralized digital identities on Stacks blockchain with professional multi-verifier validation services.

## Features

### Core Identity Management
- Create and manage digital identities (DIDs)
- Add custom attributes to identities  
- Identity verification by authorized admin
- Privacy risk scoring and management
- Recovery address management with multi-signature support
- Delegation system with time-based permissions
- Credential marketplace with dispute resolution
- Query identity information and verification status

### Professional Verification Network (NEW)
- **Multi-Verifier Consensus**: Professional verifiers validate identity claims through consensus
- **Economic Staking**: Verifiers stake STX tokens to participate in the network
- **Reputation System**: Dynamic scoring based on verification accuracy and collaboration
- **Trust Network**: Tracks verifier relationships and agreement rates
- **Dispute Resolution**: Challenge and arbitrate verification decisions
- **Advanced Analytics**: Performance metrics, prediction engine, and network health monitoring

## Smart Contracts

This project consists of three interconnected smart contracts:

### 1. Decentralized-Identity-Management.clar
Core identity management with DID creation, attributes, verification, and credential marketplace.

### 2. IdentityPrivacyScore.clar  
Privacy risk scoring system that monitors exposure events and recommends protective actions.

### 3. IdentityVerificationNetwork.clar (NEW)
Multi-verifier consensus network for professional identity validation with economic incentives.

## Key Contract Functions

### Identity Management Functions
- `create-identity`: Create a new digital identity with DID
- `add-attribute`: Add custom attributes to identity
- `verify-identity`: Verify an identity (admin only)
- `set-recovery-addresses`: Configure multi-signature recovery
- `add-delegation`: Grant time-limited permissions to delegates
- `create-credential`: Issue verifiable credentials
- `list-credential-for-sale`: Create credential marketplace listings

### Privacy Score Functions
- `record-exposure-event`: Log privacy exposure incidents
- `perform-privacy-action`: Take protective actions to improve privacy
- `get-privacy-recommendations`: Get personalized privacy improvement suggestions

### Verification Network Functions (NEW)
- `register-verifier`: Join verification network by staking STX
- `submit-verification-request`: Request professional identity validation
- `submit-verification-vote`: Cast consensus votes on verification requests
- `challenge-verification`: Dispute verification decisions
- `increase-stake`/`withdraw-stake`: Manage verifier stakes

### Analytics & Monitoring
- `get-network-stats`: View verification network statistics
- `calculate-verifier-effectiveness`: Evaluate verifier performance
- `predict-verification-outcome`: Estimate verification likelihood
- `get-network-health`: Monitor overall network decentralization

## Usage Examples

### Basic Identity Management

```clarity
;; Create new identity
(contract-call? .decentralized-identity-management create-identity "did:stx:abc123" "John Doe")

;; Add attribute
(contract-call? .decentralized-identity-management add-attribute "email" "john@example.com")

;; Verify identity (admin only)
(contract-call? .decentralized-identity-management verify-identity "did:stx:abc123")

;; Check verification status
(contract-call? .decentralized-identity-management is-verified "did:stx:abc123")
```

### Privacy Management

```clarity
;; Record privacy exposure event
(contract-call? .identity-privacy-score record-exposure-event "data-breach" "Email exposed in breach")

;; Take privacy protective action
(contract-call? .identity-privacy-score perform-privacy-action "enable-2fa")

;; Get privacy recommendations
(contract-call? .identity-privacy-score get-privacy-recommendations)
```

### Professional Verification Network

```clarity
;; Join as verifier (stake 1000 STX)
(contract-call? .identity-verification-network register-verifier u1000 (list "education" "employment"))

;; Request professional verification
(contract-call? .identity-verification-network submit-verification-request 
  "did:stx:abc123" "education" 0x1234... "https://evidence.com/degree" u500)

;; Vote on verification request
(contract-call? .identity-verification-network submit-verification-vote 
  u1 u1 "Degree certificate valid" u85 u90)

;; Challenge verification decision
(contract-call? .identity-verification-network challenge-verification 
  u1 "Evidence appears fraudulent")

;; Check network statistics
(contract-call? .identity-verification-network get-network-stats)
```

## Development

Built using [Clarinet](https://github.com/hirosystems/clarinet) for Stacks blockchain development.