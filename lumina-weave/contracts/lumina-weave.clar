;; Lumina Weave - Privacy-Preserving Identity Protocol
;; A trust and reputation system with selective credential disclosure

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-unauthorized (err u102))
(define-constant err-already-exists (err u103))
(define-constant err-invalid-trust-score (err u104))
(define-constant err-insufficient-trust (err u105))

;; Data Variables
(define-data-var min-trust-threshold uint u50)

;; Data Maps

;; Identity anchors - maps user principal to identity hash
(define-map identity-anchors
  principal
  {
    identity-hash: (buff 32),
    created-at: uint,
    reputation-score: uint,
    active: bool
  }
)

;; Credentials - encrypted attribute storage
(define-map credentials
  { owner: principal, credential-id: uint }
  {
    credential-hash: (buff 32),
    credential-type: (string-ascii 50),
    issuer: principal,
    issued-at: uint,
    expires-at: uint,
    verified: bool
  }
)

;; Trust relationships between users
(define-map trust-graph
  { from: principal, to: principal }
  {
    trust-score: uint,
    relationship-token: (buff 32),
    established-at: uint,
    last-updated: uint
  }
)

;; Disclosure rings - context-based access control
(define-map disclosure-rings
  { owner: principal, ring-id: uint }
  {
    ring-name: (string-ascii 50),
    min-trust-required: uint,
    members: (list 20 principal)
  }
)

;; Credential counter per user
(define-map credential-counter principal uint)

;; Ring counter per user
(define-map ring-counter principal uint)

;; Read-only functions

(define-read-only (get-identity (user principal))
  (map-get? identity-anchors user)
)

(define-read-only (get-credential (owner principal) (credential-id uint))
  (map-get? credentials { owner: owner, credential-id: credential-id })
)

(define-read-only (get-trust-score (from principal) (to principal))
  (match (map-get? trust-graph { from: from, to: to })
    trust-data (ok (get trust-score trust-data))
    (err err-not-found)
  )
)

(define-read-only (get-disclosure-ring (owner principal) (ring-id uint))
  (map-get? disclosure-rings { owner: owner, ring-id: ring-id })
)

(define-read-only (check-trust-access (accessor principal) (owner principal) (required-trust uint))
  (match (map-get? trust-graph { from: owner, to: accessor })
    trust-data (ok (>= (get trust-score trust-data) required-trust))
    (ok false)
  )
)

;; Public functions

;; Register identity anchor
(define-public (register-identity (identity-hash (buff 32)))
  (let
    (
      (existing-identity (map-get? identity-anchors tx-sender))
    )
    (asserts! (is-none existing-identity) err-already-exists)
    (ok (map-set identity-anchors tx-sender {
      identity-hash: identity-hash,
      created-at: block-height,
      reputation-score: u0,
      active: true
    }))
  )
)

;; Issue credential
(define-public (issue-credential 
  (recipient principal)
  (credential-hash (buff 32))
  (credential-type (string-ascii 50))
  (expires-at uint)
)
  (let
    (
      (current-count (default-to u0 (map-get? credential-counter recipient)))
      (new-id (+ current-count u1))
    )
    (map-set credential-counter recipient new-id)
    (ok (map-set credentials 
      { owner: recipient, credential-id: new-id }
      {
        credential-hash: credential-hash,
        credential-type: credential-type,
        issuer: tx-sender,
        issued-at: block-height,
        expires-at: expires-at,
        verified: true
      }
    ))
  )
)

;; Establish trust relationship
(define-public (establish-trust 
  (target principal)
  (trust-score uint)
  (relationship-token (buff 32))
)
  (begin
    (asserts! (<= trust-score u100) err-invalid-trust-score)
    (ok (map-set trust-graph
      { from: tx-sender, to: target }
      {
        trust-score: trust-score,
        relationship-token: relationship-token,
        established-at: block-height,
        last-updated: block-height
      }
    ))
  )
)

;; Update trust score
(define-public (update-trust-score (target principal) (new-score uint))
  (let
    (
      (existing-trust (map-get? trust-graph { from: tx-sender, to: target }))
    )
    (asserts! (is-some existing-trust) err-not-found)
    (asserts! (<= new-score u100) err-invalid-trust-score)
    (ok (map-set trust-graph
      { from: tx-sender, to: target }
      (merge (unwrap-panic existing-trust) {
        trust-score: new-score,
        last-updated: block-height
      })
    ))
  )
)

;; Create disclosure ring
(define-public (create-disclosure-ring
  (ring-name (string-ascii 50))
  (min-trust-required uint)
  (members (list 20 principal))
)
  (let
    (
      (current-count (default-to u0 (map-get? ring-counter tx-sender)))
      (new-id (+ current-count u1))
    )
    (asserts! (<= min-trust-required u100) err-invalid-trust-score)
    (map-set ring-counter tx-sender new-id)
    (ok (map-set disclosure-rings
      { owner: tx-sender, ring-id: new-id }
      {
        ring-name: ring-name,
        min-trust-required: min-trust-required,
        members: members
      }
    ))
  )
)

;; Update reputation score (simplified - in production would be more complex)
(define-public (update-reputation (user principal) (score-delta int))
  (let
    (
      (identity-data (unwrap! (map-get? identity-anchors user) err-not-found))
      (current-score (get reputation-score identity-data))
      (new-score (if (>= score-delta 0)
        (+ current-score (to-uint score-delta))
        (if (>= current-score (to-uint (* score-delta -1)))
          (- current-score (to-uint (* score-delta -1)))
          u0
        )
      ))
    )
    (ok (map-set identity-anchors user
      (merge identity-data { reputation-score: new-score })
    ))
  )
)

;; Verify credential access
(define-public (verify-credential-access
  (credential-owner principal)
  (credential-id uint)
)
  (let
    (
      (credential (unwrap! (map-get? credentials 
        { owner: credential-owner, credential-id: credential-id }) 
        err-not-found))
      (trust-relationship (unwrap! (map-get? trust-graph 
        { from: credential-owner, to: tx-sender })
        err-unauthorized))
      (trust-score (get trust-score trust-relationship))
    )
    (asserts! (>= trust-score (var-get min-trust-threshold)) err-insufficient-trust)
    (ok true)
  )
)

;; Admin function to update min trust threshold
(define-public (set-min-trust-threshold (new-threshold uint))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (<= new-threshold u100) err-invalid-trust-score)
    (ok (var-set min-trust-threshold new-threshold))
  )
)