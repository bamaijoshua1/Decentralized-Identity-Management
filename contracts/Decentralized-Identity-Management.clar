
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

;; Identity Credential Marketplace - Monetized credential ecosystem
(define-map credential-templates
  { template-id: uint }
  {
    issuer: principal,
    template-name: (string-ascii 64),
    description: (string-ascii 256),
    price: uint,
    validity-period: uint,
    active: bool,
    created-at: uint
  }
)

(define-map issued-credentials
  { credential-id: uint }
  {
    template-id: uint,
    issuer: principal,
    holder: principal,
    credential-data: (string-ascii 512),
    issued-at: uint,
    expires-at: uint,
    for-sale: bool,
    sale-price: uint,
    validated: bool
  }
)

(define-map marketplace-listings
  { listing-id: uint }
  {
    credential-id: uint,
    seller: principal,
    price: uint,
    listed-at: uint,
    active: bool
  }
)

(define-map credential-purchases
  { purchase-id: uint }
  {
    credential-id: uint,
    buyer: principal,
    seller: principal,
    amount-paid: uint,
    purchased-at: uint,
    issuer-share: uint
  }
)

(define-map credential-disputes
  { dispute-id: uint }
  {
    credential-id: uint,
    disputer: principal,
    reason: (string-ascii 256),
    status: (string-ascii 32),
    created-at: uint,
    resolved-at: uint
  }
)

(define-data-var template-nonce uint u0)
(define-data-var credential-nonce uint u0)
(define-data-var listing-nonce uint u0)
(define-data-var purchase-nonce uint u0)
(define-data-var dispute-nonce uint u0)
(define-data-var marketplace-fee-percentage uint u5)

(define-constant DISPUTE-STATUS-OPEN "open")
(define-constant DISPUTE-STATUS-RESOLVED "resolved")
(define-constant DISPUTE-STATUS-REJECTED "rejected")

(define-constant ERR-TEMPLATE-NOT-FOUND (err u500))
(define-constant ERR-CREDENTIAL-NOT-FOUND (err u501))
(define-constant ERR-LISTING-NOT-FOUND (err u502))
(define-constant ERR-INSUFFICIENT-PAYMENT (err u503))
(define-constant ERR-CREDENTIAL-EXPIRED (err u504))
(define-constant ERR-NOT-FOR-SALE (err u505))
(define-constant ERR-ALREADY-OWNER (err u506))
(define-constant ERR-DISPUTE-EXISTS (err u507))

;; Create a credential template that others can purchase
(define-public (create-credential-template 
  (template-name (string-ascii 64))
  (description (string-ascii 256))
  (price uint)
  (validity-period uint))
  (let (
    (template-id (+ (var-get template-nonce) u1))
    (identity (get-identity-by-owner tx-sender))
  )
    (match identity
      existing (begin
        (asserts! (get verified existing) ERR-NOT-AUTHORIZED)
        (var-set template-nonce template-id)
        (map-set credential-templates
          { template-id: template-id }
          {
            issuer: tx-sender,
            template-name: template-name,
            description: description,
            price: price,
            validity-period: validity-period,
            active: true,
            created-at: stacks-block-height
          }
        )
        (ok template-id)
      )
      ERR-NOT-FOUND
    )
  )
)

;; Issue a credential to another identity
(define-public (issue-credential 
  (template-id uint)
  (holder principal)
  (credential-data (string-ascii 512)))
  (let (
    (template (map-get? credential-templates { template-id: template-id }))
    (credential-id (+ (var-get credential-nonce) u1))
  )
    (match template
      template-data (begin
        (asserts! (is-eq tx-sender (get issuer template-data)) ERR-NOT-AUTHORIZED)
        (asserts! (get active template-data) ERR-TEMPLATE-NOT-FOUND)
        (var-set credential-nonce credential-id)
        (map-set issued-credentials
          { credential-id: credential-id }
          {
            template-id: template-id,
            issuer: tx-sender,
            holder: holder,
            credential-data: credential-data,
            issued-at: stacks-block-height,
            expires-at: (+ stacks-block-height (get validity-period template-data)),
            for-sale: false,
            sale-price: u0,
            validated: true
          }
        )
        (ok credential-id)
      )
      ERR-TEMPLATE-NOT-FOUND
    )
  )
)

;; List a credential for sale in the marketplace
(define-public (list-credential-for-sale (credential-id uint) (sale-price uint))
  (let (
    (credential (map-get? issued-credentials { credential-id: credential-id }))
    (listing-id (+ (var-get listing-nonce) u1))
  )
    (match credential
      credential-data (begin
        (asserts! (is-eq tx-sender (get holder credential-data)) ERR-NOT-AUTHORIZED)
        (asserts! (< stacks-block-height (get expires-at credential-data)) ERR-CREDENTIAL-EXPIRED)
        (var-set listing-nonce listing-id)
        (map-set issued-credentials
          { credential-id: credential-id }
          (merge credential-data {
            for-sale: true,
            sale-price: sale-price
          })
        )
        (map-set marketplace-listings
          { listing-id: listing-id }
          {
            credential-id: credential-id,
            seller: tx-sender,
            price: sale-price,
            listed-at: stacks-block-height,
            active: true
          }
        )
        (ok listing-id)
      )
      ERR-CREDENTIAL-NOT-FOUND
    )
  )
)

;; Purchase a credential from the marketplace
(define-public (purchase-credential (listing-id uint))
  (let (
    (listing (map-get? marketplace-listings { listing-id: listing-id }))
    (purchase-id (+ (var-get purchase-nonce) u1))
  )
    (match listing
      listing-data (begin
        (asserts! (get active listing-data) ERR-LISTING-NOT-FOUND)
        (let (
          (credential (unwrap! (map-get? issued-credentials { credential-id: (get credential-id listing-data) }) ERR-CREDENTIAL-NOT-FOUND))
          (template (unwrap! (map-get? credential-templates { template-id: (get template-id credential) }) ERR-TEMPLATE-NOT-FOUND))
          (sale-price (get price listing-data))
          (marketplace-fee (/ (* sale-price (var-get marketplace-fee-percentage)) u100))
          (issuer-share (/ (* sale-price u15) u100))
          (seller-amount (- sale-price (+ marketplace-fee issuer-share)))
        )
          (asserts! (not (is-eq tx-sender (get seller listing-data))) ERR-ALREADY-OWNER)
          (asserts! (< stacks-block-height (get expires-at credential)) ERR-CREDENTIAL-EXPIRED)
          (try! (stx-transfer? sale-price tx-sender (get seller listing-data)))
          (try! (stx-transfer? issuer-share (get seller listing-data) (get issuer template)))
          (var-set purchase-nonce purchase-id)
          (map-set issued-credentials
            { credential-id: (get credential-id listing-data) }
            (merge credential {
              holder: tx-sender,
              for-sale: false,
              sale-price: u0
            })
          )
          (map-set marketplace-listings
            { listing-id: listing-id }
            (merge listing-data { active: false })
          )
          (map-set credential-purchases
            { purchase-id: purchase-id }
            {
              credential-id: (get credential-id listing-data),
              buyer: tx-sender,
              seller: (get seller listing-data),
              amount-paid: sale-price,
              purchased-at: stacks-block-height,
              issuer-share: issuer-share
            }
          )
          (ok purchase-id)
        )
      )
      ERR-LISTING-NOT-FOUND
    )
  )
)

;; Validate a credential's authenticity
(define-public (validate-credential (credential-id uint))
  (let ((credential (map-get? issued-credentials { credential-id: credential-id })))
    (match credential
      credential-data (begin
        (asserts! (< stacks-block-height (get expires-at credential-data)) ERR-CREDENTIAL-EXPIRED)
        (ok {
          valid: true,
          issuer: (get issuer credential-data),
          holder: (get holder credential-data),
          issued-at: (get issued-at credential-data),
          expires-at: (get expires-at credential-data)
        })
      )
      ERR-CREDENTIAL-NOT-FOUND
    )
  )
)

;; File a dispute against a credential
(define-public (dispute-credential (credential-id uint) (reason (string-ascii 256)))
  (let (
    (credential (map-get? issued-credentials { credential-id: credential-id }))
    (dispute-id (+ (var-get dispute-nonce) u1))
  )
    (match credential
      credential-data (begin
        (var-set dispute-nonce dispute-id)
        (map-set credential-disputes
          { dispute-id: dispute-id }
          {
            credential-id: credential-id,
            disputer: tx-sender,
            reason: reason,
            status: DISPUTE-STATUS-OPEN,
            created-at: stacks-block-height,
            resolved-at: u0
          }
        )
        (ok dispute-id)
      )
      ERR-CREDENTIAL-NOT-FOUND
    )
  )
)

;; Resolve a credential dispute (admin only)
(define-public (resolve-dispute (dispute-id uint) (resolution (string-ascii 32)))
  (let ((dispute (map-get? credential-disputes { dispute-id: dispute-id })))
    (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
    (match dispute
      dispute-data (begin
        (map-set credential-disputes
          { dispute-id: dispute-id }
          (merge dispute-data {
            status: resolution,
            resolved-at: stacks-block-height
          })
        )
        (ok true)
      )
      ERR-NOT-FOUND
    )
  )
)

;; Deactivate a credential template
(define-public (deactivate-template (template-id uint))
  (let ((template (map-get? credential-templates { template-id: template-id })))
    (match template
      template-data (begin
        (asserts! (is-eq tx-sender (get issuer template-data)) ERR-NOT-AUTHORIZED)
        (map-set credential-templates
          { template-id: template-id }
          (merge template-data { active: false })
        )
        (ok true)
      )
      ERR-TEMPLATE-NOT-FOUND
    )
  )
)

;; Read-only functions for marketplace queries
(define-read-only (get-credential-template (template-id uint))
  (map-get? credential-templates { template-id: template-id })
)

(define-read-only (get-credential (credential-id uint))
  (map-get? issued-credentials { credential-id: credential-id })
)

(define-read-only (get-marketplace-listing (listing-id uint))
  (map-get? marketplace-listings { listing-id: listing-id })
)

(define-read-only (get-purchase-record (purchase-id uint))
  (map-get? credential-purchases { purchase-id: purchase-id })
)

(define-read-only (get-dispute (dispute-id uint))
  (map-get? credential-disputes { dispute-id: dispute-id })
)

(define-read-only (is-credential-valid (credential-id uint))
  (match (map-get? issued-credentials { credential-id: credential-id })
    credential (and 
      (get validated credential)
      (< stacks-block-height (get expires-at credential))
    )
    false
  )
)

(define-read-only (get-marketplace-fee)
  (var-get marketplace-fee-percentage)
)




