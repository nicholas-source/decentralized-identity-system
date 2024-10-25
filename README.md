# Decentralized Identity System

A robust smart contract implementation for managing decentralized identities, credentials, and zero-knowledge proofs on the Stacks blockchain. This system provides a comprehensive framework for digital identity management with built-in security features, reputation tracking, and recovery mechanisms.

## Features

- **Identity Management**

  - Self-sovereign identity registration
  - Secure identity recovery mechanisms
  - Identity status tracking
  - Configurable recovery addresses

- **Credential System**

  - Verifiable credential issuance
  - Credential revocation
  - Expiration management
  - Metadata support

- **Zero-Knowledge Proofs**

  - Proof submission and verification
  - Proof data validation
  - Timestamp tracking
  - Admin-based verification

- **Reputation System**
  - Configurable reputation scores
  - Administrative score updates
  - Score range validation

## Technical Specifications

### Constants

- Minimum reputation score: 0
- Maximum reputation score: 1000
- Minimum expiration blocks: 1
- Maximum metadata length: 256 bytes
- Minimum proof size: 64 bytes

### Error Codes

```clarity
ERR-NOT-AUTHORIZED (1000)        - Unauthorized access attempt
ERR-ALREADY-REGISTERED (1001)    - Identity already exists
ERR-NOT-REGISTERED (1002)        - Identity not found
ERR-INVALID-PROOF (1003)         - Invalid or non-existent proof
ERR-INVALID-CREDENTIAL (1004)    - Invalid credential
ERR-EXPIRED-CREDENTIAL (1005)    - Credential has expired
ERR-REVOKED-CREDENTIAL (1006)    - Credential has been revoked
ERR-INVALID-SCORE (1007)         - Invalid reputation score
ERR-INVALID-INPUT (1008)         - Invalid input parameters
ERR-INVALID-EXPIRATION (1009)    - Invalid expiration time
ERR-INVALID-RECOVERY-ADDRESS (1010) - Invalid recovery address
ERR-INVALID-PROOF-DATA (1011)    - Invalid proof data
```

## Usage

### Identity Registration

```clarity
(register-identity
    identity-hash     ;; (buff 32)
    recovery-addr     ;; (optional principal)
)
```

### Credential Management

```clarity
;; Issue a new credential
(issue-credential
    subject          ;; principal
    claim-hash       ;; (buff 32)
    expiration       ;; uint
    metadata         ;; (string-utf8 256)
)

;; Revoke a credential
(revoke-credential
    issuer           ;; principal
    nonce            ;; uint
)
```

### Zero-Knowledge Proofs

```clarity
;; Submit a proof
(submit-proof
    proof-hash       ;; (buff 32)
    proof-data       ;; (buff 1024)
)

;; Verify a proof (admin only)
(verify-proof
    proof-hash       ;; (buff 32)
)
```

### Recovery Process

```clarity
(initiate-recovery
    identity         ;; principal
    new-hash         ;; (buff 32)
)
```

## Security Features

- Input validation for all public functions
- Strict authorization checks
- Prevention of proof hash collisions
- Protected admin functions
- Secure recovery process
- Credential expiration enforcement

## Read-Only Functions

- `get-identity`: Retrieve identity information
- `get-credential`: Get credential details
- `verify-credential`: Check credential validity
- `get-proof`: Retrieve proof information

## Administrative Functions

- `set-admin`: Update contract administrator
- `update-reputation`: Modify identity reputation scores

## Best Practices

1. Always verify credentials before accepting them
2. Set appropriate expiration times for credentials
3. Use strong hash functions for identity and claim hashes
4. Implement additional off-chain verification when necessary
5. Maintain secure storage of private keys and recovery information

## Future Improvements

- Integration with DID standards
- Enhanced reputation algorithms
- Multi-signature recovery options
- Credential schema validation
- Enhanced privacy features

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
