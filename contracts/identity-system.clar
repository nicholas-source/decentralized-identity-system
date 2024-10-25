;; Decentralized Identity System
;; Version: 1.0.0

(use-trait sip-010-trait 'SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE.sip-010-trait-ft-standard.sip-010-trait)

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u1000))
(define-constant ERR-ALREADY-REGISTERED (err u1001))
(define-constant ERR-NOT-REGISTERED (err u1002))
(define-constant ERR-INVALID-PROOF (err u1003))
(define-constant ERR-INVALID-CREDENTIAL (err u1004))
(define-constant ERR-EXPIRED-CREDENTIAL (err u1005))
(define-constant ERR-REVOKED-CREDENTIAL (err u1006))

;; Data Variables
(define-map identities
    principal
    {
        hash: (buff 32),
        credentials: (list 10 principal),
        reputation-score: uint,
        recovery-address: (optional principal),
        last-updated: uint,
        status: (string-ascii 20)
    }
)

(define-map credentials
    principal
    {
        issuer: principal,
        subject: principal,
        claim-hash: (buff 32),
        expiration: uint,
        revoked: bool,
        metadata: (string-utf8 256)
    }
)

(define-map zero-knowledge-proofs
    (buff 32)
    {
        prover: principal,
        verified: bool,
        timestamp: uint,
        proof-data: (buff 1024)
    }
)

(define-data-var admin principal tx-sender)

;; Implementation

;; Administrative Functions
(define-public (set-admin (new-admin principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
        (ok (var-set admin new-admin))
    )
)