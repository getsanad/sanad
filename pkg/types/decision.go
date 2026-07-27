package types

// Effect is the outcome of a policy decision. The default posture is deny: a passport
// is minted only on an explicit allow (PRD FR-15).
type Effect string

const (
	EffectDeny   Effect = "deny"
	EffectAllow  Effect = "allow"
	EffectReview Effect = "review" // route to human-in-the-loop approval (PRD FR-16)
)

// Decision is returned by the pluggable policy decision point (PDP) given the verified
// identity + delegation context as inputs (PRD FR-14). We ship the hook, not the rules (NG1).
type Decision struct {
	Effect Effect
	Reason string
}

// Allowed reports whether the decision permits minting a passport.
func (d Decision) Allowed() bool { return d.Effect == EffectAllow }
