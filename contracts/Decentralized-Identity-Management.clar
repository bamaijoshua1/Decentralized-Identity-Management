
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