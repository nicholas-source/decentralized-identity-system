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


;; Identity Management
(define-public (register-identity (identity-hash (buff 32)) (recovery-addr (optional principal)))
    (let
        (
            (sender tx-sender)
            (existing-identity (map-get? identities sender))
        )
        (asserts! (is-none existing-identity) ERR-ALREADY-REGISTERED)
        (ok (map-set identities sender {
            hash: identity-hash,
            credentials: (list),
            reputation-score: u100,
            recovery-address: recovery-addr,
            last-updated: block-height,
            status: "ACTIVE"
        }))
    )
)

;; Zero-Knowledge Proof Functions
(define-public (submit-proof (proof-hash (buff 32)) (proof-data (buff 1024)))
    (let
        (
            (sender tx-sender)
            (existing-identity (map-get? identities sender))
        )
        (asserts! (is-some existing-identity) ERR-NOT-REGISTERED)
        (ok (map-set zero-knowledge-proofs proof-hash {
            prover: sender,
            verified: false,
            timestamp: block-height,
            proof-data: proof-data
        }))
    )
)

(define-public (verify-proof (proof-hash (buff 32)))
    (let
        (
            (proof (map-get? zero-knowledge-proofs proof-hash))
            (sender tx-sender)
        )
        (asserts! (is-some proof) ERR-INVALID-PROOF)
        (asserts! (is-eq sender (var-get admin)) ERR-NOT-AUTHORIZED)
        (ok (map-set zero-knowledge-proofs proof-hash 
            (merge (unwrap-panic proof) { verified: true })))
    )
)

;; Credential Management
(define-public (issue-credential 
    (subject principal)
    (claim-hash (buff 32))
    (expiration uint)
    (metadata (string-utf8 256)))
    (let
        (
            (sender tx-sender)
            (credential-id (generate-credential-id sender subject claim-hash))
        )
        (asserts! (map-get? identities sender) ERR-NOT-REGISTERED)
        (asserts! (map-get? identities subject) ERR-NOT-REGISTERED)
        (ok (map-set credentials credential-id {
            issuer: sender,
            subject: subject,
            claim-hash: claim-hash,
            expiration: expiration,
            revoked: false,
            metadata: metadata
        }))
    )
)

(define-public (revoke-credential (credential-id principal))
    (let
        (
            (sender tx-sender)
            (credential (map-get? credentials credential-id))
        )
        (asserts! (is-some credential) ERR-INVALID-CREDENTIAL)
        (asserts! (is-eq sender (get issuer (unwrap-panic credential))) ERR-NOT-AUTHORIZED)
        (ok (map-set credentials credential-id 
            (merge (unwrap-panic credential) { revoked: true })))
    )
)


;; Reputation System
(define-public (update-reputation (subject principal) (score-change int))
    (let
        (
            (sender tx-sender)
            (identity (map-get? identities subject))
        )
        (asserts! (is-eq sender (var-get admin)) ERR-NOT-AUTHORIZED)
        (asserts! (is-some identity) ERR-NOT-REGISTERED)
        (ok (map-set identities subject
            (merge (unwrap-panic identity)
                { reputation-score: (+ (get reputation-score (unwrap-panic identity)) score-change) })))
    )
)

;; Recovery Mechanisms
(define-public (initiate-recovery (identity principal) (new-hash (buff 32)))
    (let
        (
            (sender tx-sender)
            (identity-data (map-get? identities identity))
        )
        (asserts! (is-some identity-data) ERR-NOT-REGISTERED)
        (asserts! (is-some (get recovery-address (unwrap-panic identity-data))) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq sender (unwrap-panic (get recovery-address (unwrap-panic identity-data)))) ERR-NOT-AUTHORIZED)
        (ok (map-set identities identity
            (merge (unwrap-panic identity-data)
                { 
                    hash: new-hash,
                    last-updated: block-height,
                    status: "RECOVERED"
                })))
    )
)

;; Helper Functions
(define-private (generate-credential-id (issuer principal) (subject principal) (claim-hash (buff 32)))
    (sha256 (concat (concat (principal-to-buff issuer) (principal-to-buff subject)) claim-hash))
)


; Getters
(define-read-only (get-identity (identity principal))
    (map-get? identities identity)
)