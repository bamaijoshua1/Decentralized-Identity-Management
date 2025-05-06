
;; title: Decentralized-Identity-Management


(define-data-var admin principal tx-sender)

(define-map identities
  { owner: principal }
  {
    did: (string-ascii 64),
    name: (string-ascii 64),
    verified: bool,
    created-at: uint,
    updated-at: uint
  }
)

(define-map identity-attributes 
  { did: (string-ascii 64), key: (string-ascii 64) }
  { value: (string-ascii 256) }
)

(define-map verifications
  { did: (string-ascii 64) }
  {
    verifier: principal,
    timestamp: uint,
    status: bool
  }
)

(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-EXISTS (err u101))
(define-constant ERR-NOT-FOUND (err u102))
(define-constant ERR-INVALID-INPUT (err u103))

(define-public (create-identity (did (string-ascii 64)) (name (string-ascii 64)))
  (let ((identity {
    did: did,
    name: name,
    verified: false,
    created-at: stacks-block-height,
    updated-at: stacks-block-height
  }))
    ;; (asserts! (is-none (get-identity-by-did did)) ERR-ALREADY-EXISTS)
    (ok (map-insert identities { owner: tx-sender } identity))
  )
)

(define-public (update-identity (name (string-ascii 64)))
  (let ((existing-identity (get-identity-by-owner tx-sender)))
    (match existing-identity
      identity (begin
        (map-set identities 
          { owner: tx-sender }
          (merge identity { 
            name: name,
            updated-at: stacks-block-height
          })
        )
        (ok true)
      )
      (err ERR-NOT-FOUND)
    )
  )
)

(define-public (add-attribute (key (string-ascii 64)) (value (string-ascii 256)))
  (let ((identity (get-identity-by-owner tx-sender)))
    (match identity
      existing (begin
        (map-set identity-attributes
          { did: (get did existing), key: key }
          { value: value }
        )
        (ok true)
      )
      (err ERR-NOT-FOUND)
    )
  )
)

(define-public (verify-identity (did (string-ascii 64)))
  (let ((identity (get-identity-by-did did)))
    (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
    (match identity
      existing (begin
        (map-set identities
          { owner: tx-sender }
          (merge existing { verified: true })
        )
        (map-set verifications
          { did: did }
          {
            verifier: tx-sender,
            timestamp: stacks-block-height,
            status: true
          }
        )
        (ok true)
      )
      ERR-NOT-FOUND
    )
  )
)

(define-read-only (get-identity-by-owner (owner principal))
  (map-get? identities { owner: owner })
)

(define-read-only (get-identity-by-did (did (string-ascii 64)))
  (map-get? identities { owner: tx-sender })
)

(define-read-only (get-attribute (did (string-ascii 64)) (key (string-ascii 64)))
  (map-get? identity-attributes { did: did, key: key })
)

(define-read-only (is-verified (did (string-ascii 64)))
  (match (get-identity-by-did did)
    identity (get verified identity)
    false
  )
)

(define-read-only (get-verification-status (did (string-ascii 64)))
  (match (map-get? verifications { did: did })
    verification (get status verification)
    false
  )
)
(define-read-only (get-identity (did (string-ascii 64)))
  (match (get-identity-by-did did)
    identity (ok identity)
    ERR-NOT-FOUND
  )
)


(define-map recovery-addresses
  { did: (string-ascii 64) }
  { 
    trusted-addresses: (list 3 principal),
    required-confirmations: uint
  }
)

(define-map recovery-requests 
  { did: (string-ascii 64) }
  {
    new-owner: principal,
    confirmations: (list 3 principal),
    request-time: uint
  }
)

(define-public (set-recovery-addresses (trusted-list (list 3 principal)) (required uint))
  (let ((identity (get-identity-by-owner tx-sender)))
    (match identity
      existing (begin
        (map-set recovery-addresses
          { did: (get did existing) }
          { 
            trusted-addresses: trusted-list,
            required-confirmations: required
          }
        )
        (ok true))
      (err ERR-NOT-FOUND)
    )
  )
)

(define-public (initiate-recovery (did (string-ascii 64)) (new-owner principal))
  (let ((recovery-data (map-get? recovery-addresses {did: did})))
    (match recovery-data
      data (begin 
        (map-set recovery-requests
          { did: did }
          {
            new-owner: new-owner,
            confirmations: (list),
            request-time: stacks-block-height
          }
        )
        (ok true))
      (err ERR-NOT-FOUND)
    )
  )
)


(define-map reputation-scores
  { did: (string-ascii 64) }
  {
    score: uint,
    total-verifications: uint,
    last-updated: uint
  }
)

(define-map reputation-events
  { did: (string-ascii 64), event-id: uint }
  {
    verifier: principal,
    points: int,
    timestamp: uint
  }
)

(define-data-var event-nonce uint u0)

(define-public (add-reputation-event (target-did (string-ascii 64)) (points int))
  (let (
    (current-score (default-to 
      { score: u0, total-verifications: u0, last-updated: u0 } 
      (map-get? reputation-scores { did: target-did })))
    (new-event-id (+ (var-get event-nonce) u1))
  )
    (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
    (var-set event-nonce new-event-id)
    (map-set reputation-events
      { did: target-did, event-id: new-event-id }
      {
        verifier: tx-sender,
        points: points,
        timestamp: stacks-block-height
      }
    )
    (map-set reputation-scores
      { did: target-did }
      {
        score: (+ (get score current-score) (to-uint points)),
        total-verifications: (+ (get total-verifications current-score) u1),
        last-updated: stacks-block-height
      }
    )
    (ok true)
  )
)