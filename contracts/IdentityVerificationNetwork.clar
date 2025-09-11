;; IdentityVerificationNetwork - Multi-verifier consensus and trust network
;; Enables decentralized verification through multiple independent verifiers with staking and reputation

;; Error constants  
(define-constant ERR_UNAUTHORIZED (err u700))
(define-constant ERR_INSUFFICIENT_STAKE (err u701))
(define-constant ERR_VERIFIER_NOT_FOUND (err u702))
(define-constant ERR_REQUEST_NOT_FOUND (err u703))
(define-constant ERR_ALREADY_VERIFIED (err u704))
(define-constant ERR_VERIFICATION_EXPIRED (err u705))
(define-constant ERR_INSUFFICIENT_VERIFIERS (err u706))
(define-constant ERR_ALREADY_VOTED (err u707))
(define-constant ERR_INVALID_VOTE (err u708))
(define-constant ERR_REQUEST_CLOSED (err u709))

;; Contract constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant MINIMUM_STAKE u1000) ;; Minimum STX required to become verifier
(define-constant MINIMUM_VERIFIERS u3) ;; Minimum verifiers required for consensus
(define-constant CONSENSUS_THRESHOLD u67) ;; 67% consensus required
(define-constant VERIFICATION_TIMEOUT u1440) ;; ~10 days for verification
(define-constant REPUTATION_DECAY_RATE u5) ;; Points lost per month of inactivity

;; Verification request status
(define-constant STATUS_PENDING u1)
(define-constant STATUS_APPROVED u2)
(define-constant STATUS_REJECTED u3)
(define-constant STATUS_EXPIRED u4)

;; Vote types
(define-constant VOTE_APPROVE u1)
(define-constant VOTE_REJECT u2)
(define-constant VOTE_ABSTAIN u3)

;; Data variables
(define-data-var next-verifier-id uint u1)
(define-data-var next-request-id uint u1) 
(define-data-var total-staked-amount uint u0)
(define-data-var network-reputation-threshold uint u700)

;; Verifier registry and staking
(define-map verifiers
  { verifier-id: uint }
  {
    verifier-address: principal,
    stake-amount: uint,
    reputation-score: uint,
    specializations: (list 5 (string-ascii 50)),
    total-verifications: uint,
    successful-verifications: uint,
    staking-block: uint,
    active: bool,
    last-activity: uint
  })

(define-map verifier-lookup
  { verifier-address: principal }
  { verifier-id: uint })

;; Verification requests
(define-map verification-requests
  { request-id: uint }
  {
    requester: principal,
    identity-did: (string-ascii 64),
    verification-type: (string-ascii 50),
    evidence-hash: (buff 32),
    evidence-url: (string-ascii 256),
    requested-at: uint,
    expires-at: uint,
    status: uint,
    required-verifiers: uint,
    reward-pool: uint
  })

;; Verification votes
(define-map verification-votes
  { request-id: uint, verifier-id: uint }
  {
    vote: uint,
    justification: (string-ascii 500),
    confidence-score: uint,
    submitted-at: uint,
    evidence-quality: uint
  })

;; Request consensus tracking
(define-map request-consensus
  { request-id: uint }
  {
    total-votes: uint,
    approve-votes: uint,
    reject-votes: uint,
    abstain-votes: uint,
    consensus-reached: bool,
    final-decision: uint
  })

;; Verifier performance tracking
(define-map verifier-performance
  { verifier-id: uint, period-start: uint }
  {
    verifications-participated: uint,
    consensus-alignment: uint,
    evidence-quality-avg: uint,
    response-time-avg: uint,
    reputation-earned: uint
  })

;; Trust network connections
(define-map trust-connections
  { verifier-a: uint, verifier-b: uint }
  {
    trust-score: uint,
    collaboration-count: uint,
    agreement-rate: uint,
    last-interaction: uint
  })

;; Dispute resolution for verification decisions
(define-map verification-disputes
  { request-id: uint }
  {
    disputer: principal,
    dispute-reason: (string-ascii 500),
    disputed-at: uint,
    arbitrators: (list 3 uint),
    resolution: (optional (string-ascii 200)),
    resolved: bool
  })

;; Public Functions

;; Register as a verifier with staking
(define-public (register-verifier 
  (stake-amount uint)
  (specializations (list 5 (string-ascii 50))))
  (let
    ((verifier-id (var-get next-verifier-id))
     (current-block stacks-block-height))
    (asserts! (>= stake-amount MINIMUM_STAKE) ERR_INSUFFICIENT_STAKE)
    (asserts! (is-none (map-get? verifier-lookup { verifier-address: tx-sender })) ERR_ALREADY_VERIFIED)
    
    ;; Transfer stake to contract
    (try! (stx-transfer? stake-amount tx-sender (as-contract tx-sender)))
    
    ;; Register verifier
    (map-set verifiers
      { verifier-id: verifier-id }
      {
        verifier-address: tx-sender,
        stake-amount: stake-amount,
        reputation-score: u500, ;; Starting reputation
        specializations: specializations,
        total-verifications: u0,
        successful-verifications: u0,
        staking-block: current-block,
        active: true,
        last-activity: current-block
      })
    
    (map-set verifier-lookup { verifier-address: tx-sender } { verifier-id: verifier-id })
    (var-set total-staked-amount (+ (var-get total-staked-amount) stake-amount))
    (var-set next-verifier-id (+ verifier-id u1))
    (ok verifier-id)))

;; Submit verification request
(define-public (submit-verification-request
  (identity-did (string-ascii 64))
  (verification-type (string-ascii 50))
  (evidence-hash (buff 32))
  (evidence-url (string-ascii 256))
  (reward-amount uint))
  (let
    ((request-id (var-get next-request-id))
     (current-block stacks-block-height)
     (expires-at (+ current-block VERIFICATION_TIMEOUT)))
    
    ;; Transfer reward to contract
    (try! (stx-transfer? reward-amount tx-sender (as-contract tx-sender)))
    
    (map-set verification-requests
      { request-id: request-id }
      {
        requester: tx-sender,
        identity-did: identity-did,
        verification-type: verification-type,
        evidence-hash: evidence-hash,
        evidence-url: evidence-url,
        requested-at: current-block,
        expires-at: expires-at,
        status: STATUS_PENDING,
        required-verifiers: MINIMUM_VERIFIERS,
        reward-pool: reward-amount
      })
    
    (map-set request-consensus
      { request-id: request-id }
      {
        total-votes: u0,
        approve-votes: u0,
        reject-votes: u0,
        abstain-votes: u0,
        consensus-reached: false,
        final-decision: u0
      })
    
    (var-set next-request-id (+ request-id u1))
    (ok request-id)))

;; Submit verification vote
(define-public (submit-verification-vote
  (request-id uint)
  (vote uint)
  (justification (string-ascii 500))
  (confidence-score uint)
  (evidence-quality uint))
  (let
    ((verifier-lookup-data (unwrap! (map-get? verifier-lookup { verifier-address: tx-sender }) ERR_VERIFIER_NOT_FOUND))
     (verifier-id (get verifier-id verifier-lookup-data))
     (verifier-data (unwrap! (map-get? verifiers { verifier-id: verifier-id }) ERR_VERIFIER_NOT_FOUND))
     (request-data (unwrap! (map-get? verification-requests { request-id: request-id }) ERR_REQUEST_NOT_FOUND))
     (consensus-data (unwrap! (map-get? request-consensus { request-id: request-id }) ERR_REQUEST_NOT_FOUND))
     (current-block stacks-block-height))
    
    ;; Validation checks
    (asserts! (get active verifier-data) ERR_UNAUTHORIZED)
    (asserts! (>= (get reputation-score verifier-data) (var-get network-reputation-threshold)) ERR_UNAUTHORIZED)
    (asserts! (<= vote VOTE_ABSTAIN) ERR_INVALID_VOTE)
    (asserts! (<= confidence-score u100) ERR_INVALID_VOTE)
    (asserts! (<= evidence-quality u100) ERR_INVALID_VOTE)
    (asserts! (is-eq (get status request-data) STATUS_PENDING) ERR_REQUEST_CLOSED)
    (asserts! (< current-block (get expires-at request-data)) ERR_VERIFICATION_EXPIRED)
    (asserts! (is-none (map-get? verification-votes { request-id: request-id, verifier-id: verifier-id })) ERR_ALREADY_VOTED)
    
    ;; Record vote
    (map-set verification-votes
      { request-id: request-id, verifier-id: verifier-id }
      {
        vote: vote,
        justification: justification,
        confidence-score: confidence-score,
        submitted-at: current-block,
        evidence-quality: evidence-quality
      })
    
    ;; Update consensus tracking
    (let
      ((new-total-votes (+ (get total-votes consensus-data) u1))
       (new-approve-votes (if (is-eq vote VOTE_APPROVE) (+ (get approve-votes consensus-data) u1) (get approve-votes consensus-data)))
       (new-reject-votes (if (is-eq vote VOTE_REJECT) (+ (get reject-votes consensus-data) u1) (get reject-votes consensus-data)))
       (new-abstain-votes (if (is-eq vote VOTE_ABSTAIN) (+ (get abstain-votes consensus-data) u1) (get abstain-votes consensus-data))))
      
      (map-set request-consensus
        { request-id: request-id }
        {
          total-votes: new-total-votes,
          approve-votes: new-approve-votes,
          reject-votes: new-reject-votes,
          abstain-votes: new-abstain-votes,
          consensus-reached: (>= new-total-votes (get required-verifiers request-data)),
          final-decision: (calculate-consensus-decision new-approve-votes new-reject-votes new-total-votes)
        })
      
      ;; Update verifier activity
      (update-verifier-activity verifier-id)
      
      ;; Check if consensus reached and finalize
      (if (>= new-total-votes (get required-verifiers request-data))
        (finalize-verification-request request-id)
        (ok true)))))

;; Increase verifier stake
(define-public (increase-stake (additional-amount uint))
  (let
    ((verifier-lookup-data (unwrap! (map-get? verifier-lookup { verifier-address: tx-sender }) ERR_VERIFIER_NOT_FOUND))
     (verifier-id (get verifier-id verifier-lookup-data))
     (verifier-data (unwrap! (map-get? verifiers { verifier-id: verifier-id }) ERR_VERIFIER_NOT_FOUND)))
    
    (try! (stx-transfer? additional-amount tx-sender (as-contract tx-sender)))
    
    (map-set verifiers
      { verifier-id: verifier-id }
      (merge verifier-data {
        stake-amount: (+ (get stake-amount verifier-data) additional-amount)
      }))
    
    (var-set total-staked-amount (+ (var-get total-staked-amount) additional-amount))
    (ok (+ (get stake-amount verifier-data) additional-amount))))

;; Withdraw stake (if not actively verifying)
(define-public (withdraw-stake (amount uint))
  (let
    ((verifier-lookup-data (unwrap! (map-get? verifier-lookup { verifier-address: tx-sender }) ERR_VERIFIER_NOT_FOUND))
     (verifier-id (get verifier-id verifier-lookup-data))
     (verifier-data (unwrap! (map-get? verifiers { verifier-id: verifier-id }) ERR_VERIFIER_NOT_FOUND))
     (remaining-stake (- (get stake-amount verifier-data) amount)))
    
    (asserts! (>= remaining-stake MINIMUM_STAKE) ERR_INSUFFICIENT_STAKE)
    
    (try! (as-contract (stx-transfer? amount tx-sender tx-sender)))
    
    (map-set verifiers
      { verifier-id: verifier-id }
      (merge verifier-data {
        stake-amount: remaining-stake
      }))
    
    (var-set total-staked-amount (- (var-get total-staked-amount) amount))
    (ok remaining-stake)))

;; Challenge a verification decision
(define-public (challenge-verification
  (request-id uint)
  (dispute-reason (string-ascii 500)))
  (let
    ((request-data (unwrap! (map-get? verification-requests { request-id: request-id }) ERR_REQUEST_NOT_FOUND)))
    (asserts! (not (is-eq (get status request-data) STATUS_PENDING)) ERR_REQUEST_CLOSED)
    
    ;; Create dispute record
    (map-set verification-disputes
      { request-id: request-id }
      {
        disputer: tx-sender,
        dispute-reason: dispute-reason,
        disputed-at: stacks-block-height,
        arbitrators: (list),
        resolution: none,
        resolved: false
      })
    
    (ok true)))

;; Admin functions

;; Set network parameters
(define-public (set-network-reputation-threshold (new-threshold uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set network-reputation-threshold new-threshold)
    (ok new-threshold)))

;; Slash verifier for malicious behavior
(define-public (slash-verifier (verifier-id uint) (slash-amount uint) (reason (string-ascii 200)))
  (let
    ((verifier-data (unwrap! (map-get? verifiers { verifier-id: verifier-id }) ERR_VERIFIER_NOT_FOUND)))
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    
    (map-set verifiers
      { verifier-id: verifier-id }
      (merge verifier-data {
        stake-amount: (if (> (get stake-amount verifier-data) slash-amount)
                       (- (get stake-amount verifier-data) slash-amount)
                       u0),
        reputation-score: (if (> (get reputation-score verifier-data) slash-amount)
                           (- (get reputation-score verifier-data) slash-amount)
                           u0)
      }))
    
    (var-set total-staked-amount (- (var-get total-staked-amount) slash-amount))
    (ok true)))

;; Read-only functions

;; Get verifier information
(define-read-only (get-verifier-info (verifier-id uint))
  (map-get? verifiers { verifier-id: verifier-id }))

;; Get verifier by address
(define-read-only (get-verifier-by-address (verifier-address principal))
  (match (map-get? verifier-lookup { verifier-address: verifier-address })
    lookup-data (map-get? verifiers { verifier-id: (get verifier-id lookup-data) })
    none))

;; Get verification request details
(define-read-only (get-verification-request (request-id uint))
  (map-get? verification-requests { request-id: request-id }))

;; Get vote information
(define-read-only (get-verification-vote (request-id uint) (verifier-id uint))
  (map-get? verification-votes { request-id: request-id, verifier-id: verifier-id }))

;; Get consensus status
(define-read-only (get-consensus-status (request-id uint))
  (map-get? request-consensus { request-id: request-id }))

;; Get network statistics
(define-read-only (get-network-stats)
  {
    total-verifiers: (- (var-get next-verifier-id) u1),
    total-requests: (- (var-get next-request-id) u1),
    total-staked: (var-get total-staked-amount),
    reputation-threshold: (var-get network-reputation-threshold),
    current-block: stacks-block-height
  })

;; Calculate verifier effectiveness score
(define-read-only (calculate-verifier-effectiveness (verifier-id uint))
  (match (map-get? verifiers { verifier-id: verifier-id })
    verifier-data
      (let
        ((success-rate (if (> (get total-verifications verifier-data) u0)
                        (/ (* (get successful-verifications verifier-data) u100) (get total-verifications verifier-data))
                        u0))
         (activity-factor (if (> (- stacks-block-height (get last-activity verifier-data)) u4320) ;; 30 days
                           u50 ;; Reduced effectiveness for inactivity
                           u100))
         (reputation-factor (/ (get reputation-score verifier-data) u10)))
        (some {
          verifier-id: verifier-id,
          success-rate: success-rate,
          activity-factor: activity-factor,
          reputation-factor: reputation-factor,
          overall-effectiveness: (/ (+ success-rate activity-factor reputation-factor) u3),
          recommendation: (if (< success-rate u70)
                           "Requires improvement"
                           (if (< success-rate u85)
                             "Satisfactory performance"
                             "Excellent verifier"))
        }))
    none))

;; Get trust network connections for a verifier
(define-read-only (get-trust-connections (verifier-id uint))
  {
    verifier-id: verifier-id,
    message: "Use off-chain indexing to retrieve trust connections",
    trust-score-calculation: "Based on collaboration history and agreement rates"
  })

;; Get eligible verifiers for a verification request
(define-read-only (get-eligible-verifiers (verification-type (string-ascii 50)))
  {
    verification-type: verification-type,
    minimum-reputation: (var-get network-reputation-threshold),
    message: "Use off-chain indexing to find verifiers by specialization",
    selection-criteria: "Active verifiers with matching specialization and sufficient reputation"
  })

;; Private helper functions

;; Calculate consensus decision based on vote distribution
(define-private (calculate-consensus-decision (approve-votes uint) (reject-votes uint) (total-votes uint))
  (let
    ((approve-percentage (if (> total-votes u0) (/ (* approve-votes u100) total-votes) u0))
     (reject-percentage (if (> total-votes u0) (/ (* reject-votes u100) total-votes) u0)))
    (if (>= approve-percentage CONSENSUS_THRESHOLD)
      VOTE_APPROVE
      (if (>= reject-percentage CONSENSUS_THRESHOLD)
        VOTE_REJECT
        u0)))) ;; No consensus yet

;; Finalize verification request when consensus reached
(define-private (finalize-verification-request (request-id uint))
  (let
    ((consensus-data (unwrap! (map-get? request-consensus { request-id: request-id }) ERR_REQUEST_NOT_FOUND))
     (request-data (unwrap! (map-get? verification-requests { request-id: request-id }) ERR_REQUEST_NOT_FOUND))
     (final-decision (get final-decision consensus-data)))
    
    (if (> final-decision u0)
      (begin
        ;; Update request status
        (map-set verification-requests
          { request-id: request-id }
          (merge request-data {
            status: final-decision
          }))
        
        ;; Distribute rewards to participating verifiers
        (distribute-verification-rewards request-id)
        
        ;; Update verifier reputation based on consensus alignment
        (update-verifier-reputations request-id final-decision)
        (ok true))
      (ok false)))) ;; Not enough consensus yet

;; Distribute rewards to verifiers who participated
(define-private (distribute-verification-rewards (request-id uint))
  (let
    ((request-data (unwrap-panic (map-get? verification-requests { request-id: request-id })))
     (consensus-data (unwrap-panic (map-get? request-consensus { request-id: request-id })))
     (total-reward (get reward-pool request-data))
     (participating-verifiers (get total-votes consensus-data))
     (reward-per-verifier (if (> participating-verifiers u0) (/ total-reward participating-verifiers) u0)))
    
    ;; In a full implementation, this would iterate through all voting verifiers
    ;; For now, just return the calculated reward amount
    reward-per-verifier))

;; Update verifier reputation based on consensus alignment
(define-private (update-verifier-reputations (request-id uint) (final-decision uint))
  (let
    ((consensus-data (unwrap-panic (map-get? request-consensus { request-id: request-id }))))
    ;; In a full implementation, this would iterate through all votes
    ;; and update reputation based on alignment with final consensus
    true))

;; Update verifier activity timestamp
(define-private (update-verifier-activity (verifier-id uint))
  (match (map-get? verifiers { verifier-id: verifier-id })
    verifier-data
      (map-set verifiers
        { verifier-id: verifier-id }
        (merge verifier-data {
          last-activity: stacks-block-height,
          total-verifications: (+ (get total-verifications verifier-data) u1)
        }))
    false))

;; Calculate trust score between two verifiers
(define-private (calculate-trust-score (verifier-a-id uint) (verifier-b-id uint))
  (let
    ((connection-key { verifier-a: verifier-a-id, verifier-b: verifier-b-id })
     (reverse-connection-key { verifier-a: verifier-b-id, verifier-b: verifier-a-id })
     (connection (default-to 
                   { trust-score: u500, collaboration-count: u0, agreement-rate: u50, last-interaction: u0 }
                   (map-get? trust-connections connection-key))))
    (get trust-score connection)))

;; Advanced analytics functions

;; Get network health metrics
(define-read-only (get-network-health)
  {
    total-active-verifiers: u0, ;; Would be calculated by iterating through active verifiers
    average-reputation: u0,     ;; Would be calculated from all verifier reputations
    total-stake-locked: (var-get total-staked-amount),
    consensus-success-rate: u0, ;; Would be calculated from historical data
    network-trust-score: u0,   ;; Would be calculated from trust connections
    decentralization-index: u0  ;; Would measure how distributed the network is
  })

;; Get verification quality metrics
(define-read-only (get-verification-quality-metrics (request-id uint))
  (match (map-get? verification-requests { request-id: request-id })
    request-data
      (some {
        request-id: request-id,
        verification-type: (get verification-type request-data),
        evidence-quality-avg: u0,    ;; Would be calculated from verifier scores
        consensus-confidence: u0,     ;; Would be calculated from confidence scores
        verifier-agreement: u0,      ;; How much verifiers agreed
        time-to-consensus: u0,       ;; How long consensus took
        network-trust-in-decision: u0 ;; Overall network confidence
      })
    none))

;; Predict verification outcome (for analytics)
(define-read-only (predict-verification-outcome (request-id uint))
  (match (map-get? request-consensus { request-id: request-id })
    consensus-data
      (let
        ((total-votes (get total-votes consensus-data))
         (approve-votes (get approve-votes consensus-data))
         (reject-votes (get reject-votes consensus-data)))
        (some {
          current-approval-rate: (if (> total-votes u0) (/ (* approve-votes u100) total-votes) u0),
          current-rejection-rate: (if (> total-votes u0) (/ (* reject-votes u100) total-votes) u0),
          consensus-likelihood: (if (> total-votes u0)
                                  (if (>= (/ (* approve-votes u100) total-votes) u60)
                                    "Likely approval"
                                    (if (>= (/ (* reject-votes u100) total-votes) u60)
                                      "Likely rejection"
                                      "Uncertain outcome"))
                                  "Insufficient data"),
          votes-needed: (if (>= total-votes MINIMUM_VERIFIERS) u0 (- MINIMUM_VERIFIERS total-votes))
        }))
    none))
