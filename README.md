# Decentralized Identity Management

A Clarity smart contract for managing decentralized digital identities on Stacks blockchain.

## Features

- Create and manage digital identities
- Add custom attributes to identities
- Identity verification by authorized admin
- Query identity information and verification status

## Contract Functions

### Public Functions

- `create-identity`: Create a new digital identity
- `update-identity`: Update identity information
- `add-attribute`: Add custom attributes to identity
- `verify-identity`: Verify an identity (admin only)

### Read-Only Functions

- `get-identity-by-owner`: Get identity by owner principal
- `get-identity-by-did`: Get identity by DID
- `get-attribute`: Get identity attribute value
- `is-verified`: Check if identity is verified

## Usage Example

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

## Development

Built using [Clarinet](https://github.com/hirosystems/clarinet) for Stacks blockchain development.