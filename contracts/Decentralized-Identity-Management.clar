
;; title: Decentralized-Identity-Management

(define-map did-documents
  { did: (string-ascii 64) }
  {
    context: (string-ascii 64),
    controller: principal,
    created: uint,
    updated: uint,
    active: bool
  }
)

(define-map did-public-keys
  { did: (string-ascii 64), key-id: (string-ascii 32) }
  {
    key-type: (string-ascii 32),
    public-key: (string-ascii 128),
    purposes: (list 4 (string-ascii 32)),
    created: uint,
    revoked: bool
  }
)

(define-map did-services
  { did: (string-ascii 64), service-id: (string-ascii 32) }
  {
    service-type: (string-ascii 64),
    service-endpoint: (string-ascii 256),
    created: uint,
    active: bool
  }
)

(define-map did-proofs
  { did: (string-ascii 64), proof-id: (string-ascii 32) }
  {
    proof-type: (string-ascii 32),
    proof-purpose: (string-ascii 32),
    verification-method: (string-ascii 64),
    proof-value: (string-ascii 256),
    created: uint,
    expires: uint
  }
)

(define-constant PURPOSE-AUTHENTICATION "authentication")
(define-constant PURPOSE-ASSERTION "assertionMethod")
(define-constant PURPOSE-KEY-AGREEMENT "keyAgreement")
(define-constant PURPOSE-CAPABILITY-INVOCATION "capabilityInvocation")

(define-constant ERR-DID-EXISTS (err u400))
(define-constant ERR-DID-NOT-EXISTS (err u401))
(define-constant ERR-KEY-NOT-FOUND (err u402))
(define-constant ERR-SERVICE-NOT-FOUND (err u403))
(define-constant ERR-PROOF-EXPIRED (err u404))
(define-constant ERR-INVALID-PROOF (err u405))

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

(define-map delegations
  { did: (string-ascii 64), delegate: principal }
  {
    permissions: (list 10 (string-ascii 32)),
    expires-at: uint,
    granted-at: uint,
    active: bool
  }
)

(define-map delegation-nonces
  { did: (string-ascii 64) }
  { nonce: uint }
)

(define-constant PERMISSION-READ-ATTRIBUTES "read-attributes")
(define-constant PERMISSION-UPDATE-PROFILE "update-profile")
(define-constant PERMISSION-ADD-ATTRIBUTES "add-attributes")
(define-constant PERMISSION-MANAGE-RECOVERY "manage-recovery")

(define-constant ERR-DELEGATION-EXPIRED (err u200))
(define-constant ERR-INSUFFICIENT-PERMISSIONS (err u201))
(define-constant ERR-DELEGATION-NOT-FOUND (err u202))

(define-public (grant-delegation 
  (delegate principal) 
  (permissions (list 10 (string-ascii 32))) 
  (duration-blocks uint))
  (let (
    (identity (get-identity-by-owner tx-sender))
    (expires-at (+ stacks-block-height duration-blocks))
  )
    (match identity
      existing (begin
        (map-set delegations
          { did: (get did existing), delegate: delegate }
          {
            permissions: permissions,
            expires-at: expires-at,
            granted-at: stacks-block-height,
            active: true
          }
        )
        (map-set delegation-nonces
          { did: (get did existing) }
          { nonce: (+ (get-delegation-nonce (get did existing)) u1) }
        )
        (ok true)
      )
      (err ERR-NOT-FOUND)
    )
  )
)

(define-public (revoke-delegation (delegate principal))
  (let ((identity (get-identity-by-owner tx-sender)))
    (match identity
      existing (begin
        (map-delete delegations { did: (get did existing), delegate: delegate })
        (ok true)
      )
      (err ERR-NOT-FOUND)
    )
  )
)

(define-public (update-identity-delegated (target-did (string-ascii 64)) (name (string-ascii 64)))
  (let ((delegation-info (get-delegation target-did tx-sender)))
    (asserts! (is-valid-delegation delegation-info PERMISSION-UPDATE-PROFILE) ERR-INSUFFICIENT-PERMISSIONS)
    (match (get-identity-by-did target-did)
      identity (begin
        (map-set identities 
          { owner: (get-identity-owner target-did) }
          (merge identity { 
            name: name,
            updated-at: stacks-block-height
          })
        )
        (ok true)
      )
      ERR-NOT-FOUND
    )
  )
)

(define-public (add-attribute-delegated 
  (target-did (string-ascii 64)) 
  (key (string-ascii 64)) 
  (value (string-ascii 256)))
  (let ((delegation-info (get-delegation target-did tx-sender)))
    (asserts! (is-valid-delegation delegation-info PERMISSION-ADD-ATTRIBUTES) ERR-INSUFFICIENT-PERMISSIONS)
    (map-set identity-attributes
      { did: target-did, key: key }
      { value: value }
    )
    (ok true)
  )
)

(define-read-only (get-delegation (did (string-ascii 64)) (delegate principal))
  (map-get? delegations { did: did, delegate: delegate })
)

(define-read-only (get-delegation-nonce (did (string-ascii 64)))
  (default-to u0 
    (get nonce (map-get? delegation-nonces { did: did }))
  )
)

(define-read-only (is-valid-delegation 
  (delegation-opt (optional {permissions: (list 10 (string-ascii 32)), expires-at: uint, granted-at: uint, active: bool}))
  (required-permission (string-ascii 32)))
  (match delegation-opt
    delegation (and 
      (get active delegation)
      (< stacks-block-height (get expires-at delegation))
      (is-some (index-of (get permissions delegation) required-permission))
    )
    false
  )
)

(define-read-only (get-identity-owner (did (string-ascii 64)))
  (match (fold check-identity-owner (list tx-sender) none)
    owner owner
    tx-sender
  )
)

(define-private (check-identity-owner (owner principal) (acc (optional principal)))
  (match acc
    found acc
    (match (map-get? identities { owner: owner })
      identity (some owner)
      none
    )
  )
)

(define-read-only (get-active-delegations (did (string-ascii 64)))
  (let ((current-nonce (get-delegation-nonce did)))
    (map get-delegation-if-active 
      (list 
        { did: did, delegate: tx-sender }
      )
    )
  )
)

(define-private (get-delegation-if-active (key { did: (string-ascii 64), delegate: principal }))
  (let ((delegation (map-get? delegations key)))
    (match delegation
      del (if (and 
        (get active del)
        (< stacks-block-height (get expires-at del))
      )
        (some del)
        none
      )
      none
    )
  )

)

(define-public (create-did-document (did (string-ascii 64)) (context (string-ascii 64)))
  (let ((existing-doc (map-get? did-documents { did: did })))
    (asserts! (is-none existing-doc) ERR-DID-EXISTS)
    (map-set did-documents
      { did: did }
      {
        context: context,
        controller: tx-sender,
        created: stacks-block-height,
        updated: stacks-block-height,
        active: true
      }
    )
    (ok true)
  )
)

(define-public (update-did-document (did (string-ascii 64)) (context (string-ascii 64)))
  (let ((existing-doc (map-get? did-documents { did: did })))
    (match existing-doc
      doc (begin
        (asserts! (is-eq tx-sender (get controller doc)) ERR-NOT-AUTHORIZED)
        (map-set did-documents
          { did: did }
          (merge doc {
            context: context,
            updated: stacks-block-height
          })
        )
        (ok true)
      )
      ERR-DID-NOT-EXISTS
    )
  )
)

(define-public (deactivate-did-document (did (string-ascii 64)))
  (let ((existing-doc (map-get? did-documents { did: did })))
    (match existing-doc
      doc (begin
        (asserts! (is-eq tx-sender (get controller doc)) ERR-NOT-AUTHORIZED)
        (map-set did-documents
          { did: did }
          (merge doc {
            active: false,
            updated: stacks-block-height
          })
        )
        (ok true)
      )
      ERR-DID-NOT-EXISTS
    )
  )
)

(define-public (add-public-key 
  (did (string-ascii 64)) 
  (key-id (string-ascii 32))
  (key-type (string-ascii 32))
  (public-key (string-ascii 128))
  (purposes (list 4 (string-ascii 32))))
  (let ((existing-doc (map-get? did-documents { did: did })))
    (match existing-doc
      doc (begin
        (asserts! (is-eq tx-sender (get controller doc)) ERR-NOT-AUTHORIZED)
        (asserts! (get active doc) ERR-DID-NOT-EXISTS)
        (map-set did-public-keys
          { did: did, key-id: key-id }
          {
            key-type: key-type,
            public-key: public-key,
            purposes: purposes,
            created: stacks-block-height,
            revoked: false
          }
        )
        (ok true)
      )
      ERR-DID-NOT-EXISTS
    )
  )
)

(define-public (revoke-public-key (did (string-ascii 64)) (key-id (string-ascii 32)))
  (let ((existing-doc (map-get? did-documents { did: did }))
        (existing-key (map-get? did-public-keys { did: did, key-id: key-id })))
    (match existing-doc
      doc (begin
        (asserts! (is-eq tx-sender (get controller doc)) ERR-NOT-AUTHORIZED)
        (match existing-key
          key-data (begin
            (map-set did-public-keys
              { did: did, key-id: key-id }
              (merge key-data { revoked: true })
            )
            (ok true)
          )
          ERR-KEY-NOT-FOUND
        )
      )
      ERR-DID-NOT-EXISTS
    )
  )
)

(define-public (add-service 
  (did (string-ascii 64)) 
  (service-id (string-ascii 32))
  (service-type (string-ascii 64))
  (service-endpoint (string-ascii 256)))
  (let ((existing-doc (map-get? did-documents { did: did })))
    (match existing-doc
      doc (begin
        (asserts! (is-eq tx-sender (get controller doc)) ERR-NOT-AUTHORIZED)
        (asserts! (get active doc) ERR-DID-NOT-EXISTS)
        (map-set did-services
          { did: did, service-id: service-id }
          {
            service-type: service-type,
            service-endpoint: service-endpoint,
            created: stacks-block-height,
            active: true
          }
        )
        (ok true)
      )
      ERR-DID-NOT-EXISTS
    )
  )
)

(define-public (remove-service (did (string-ascii 64)) (service-id (string-ascii 32)))
  (let ((existing-doc (map-get? did-documents { did: did }))
        (existing-service (map-get? did-services { did: did, service-id: service-id })))
    (match existing-doc
      doc (begin
        (asserts! (is-eq tx-sender (get controller doc)) ERR-NOT-AUTHORIZED)
        (match existing-service
          service-data (begin
            (map-set did-services
              { did: did, service-id: service-id }
              (merge service-data { active: false })
            )
            (ok true)
          )
          ERR-SERVICE-NOT-FOUND
        )
      )
      ERR-DID-NOT-EXISTS
    )
  )
)

(define-public (add-proof 
  (did (string-ascii 64)) 
  (proof-id (string-ascii 32))
  (proof-type (string-ascii 32))
  (proof-purpose (string-ascii 32))
  (verification-method (string-ascii 64))
  (proof-value (string-ascii 256))
  (expires-in-blocks uint))
  (let ((existing-doc (map-get? did-documents { did: did })))
    (match existing-doc
      doc (begin
        (asserts! (is-eq tx-sender (get controller doc)) ERR-NOT-AUTHORIZED)
        (asserts! (get active doc) ERR-DID-NOT-EXISTS)
        (map-set did-proofs
          { did: did, proof-id: proof-id }
          {
            proof-type: proof-type,
            proof-purpose: proof-purpose,
            verification-method: verification-method,
            proof-value: proof-value,
            created: stacks-block-height,
            expires: (+ stacks-block-height expires-in-blocks)
          }
        )
        (ok true)
      )
      ERR-DID-NOT-EXISTS
    )
  )
)

(define-public (verify-proof (did (string-ascii 64)) (proof-id (string-ascii 32)))
  (let ((existing-proof (map-get? did-proofs { did: did, proof-id: proof-id })))
    (match existing-proof
      proof-data (begin
        (asserts! (< stacks-block-height (get expires proof-data)) ERR-PROOF-EXPIRED)
        (ok {
          valid: true,
          proof-type: (get proof-type proof-data),
          proof-purpose: (get proof-purpose proof-data),
          verification-method: (get verification-method proof-data),
          created: (get created proof-data),
          expires: (get expires proof-data)
        })
      )
      ERR-INVALID-PROOF
    )
  )
)

(define-read-only (get-did-document (did (string-ascii 64)))
  (map-get? did-documents { did: did })
)

(define-read-only (get-public-key (did (string-ascii 64)) (key-id (string-ascii 32)))
  (map-get? did-public-keys { did: did, key-id: key-id })
)

(define-read-only (get-service (did (string-ascii 64)) (service-id (string-ascii 32)))
  (map-get? did-services { did: did, service-id: service-id })
)

(define-read-only (get-proof (did (string-ascii 64)) (proof-id (string-ascii 32)))
  (map-get? did-proofs { did: did, proof-id: proof-id })
)

(define-read-only (is-did-active (did (string-ascii 64)))
  (match (map-get? did-documents { did: did })
    doc (get active doc)
    false
  )
)

(define-read-only (is-key-valid (did (string-ascii 64)) (key-id (string-ascii 32)))
  (match (map-get? did-public-keys { did: did, key-id: key-id })
    key-data (not (get revoked key-data))
    false
  )
)

(define-read-only (is-service-active (did (string-ascii 64)) (service-id (string-ascii 32)))
  (match (map-get? did-services { did: did, service-id: service-id })
    service-data (get active service-data)
    false
  )
)

(define-read-only (can-authenticate (did (string-ascii 64)) (key-id (string-ascii 32)))
  (match (map-get? did-public-keys { did: did, key-id: key-id })
    key-data (and 
      (not (get revoked key-data))
      (is-some (index-of (get purposes key-data) PURPOSE-AUTHENTICATION))
    )
    false
  )
)


