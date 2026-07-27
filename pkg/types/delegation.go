package types

// DelegationHop is one signed link in a delegation chain: who delegated, to whom, the
// granted scope, and the delegator's signature. Forging or extending a chain requires
// the delegator's key (PRD FR-13).
type DelegationHop struct {
	Delegator string // principal/agent ID granting authority
	Delegate  string // principal/agent ID receiving it
	Scope     Scope
	Signature []byte // signed by the delegator's key (PRD FR-13)
}

// DelegationChain is the ordered, attenuating record principal -> agent -> sub-agent
// (PRD FR-10). Signature verification and attenuation-only enforcement land in P2
// (FR-11..FR-13); this is the shared shape so P1 passports can already carry an
// (empty) chain.
type DelegationChain struct {
	Hops []DelegationHop
}
