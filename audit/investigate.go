package audit

import "fmt"

// Report is the answer to "what happened in this action, and who is accountable?" (PRD
// FR-24). IntegrityOK reflects whether the surrounding audit chain still verifies — i.e.
// proof the record has not been tampered with (FR-24/FR-25).
type Report struct {
	PassportID     string   `json:"passport_id"`
	Principal      string   `json:"principal"`
	Agent          string   `json:"agent"`
	Server         string   `json:"server"`
	Action         string   `json:"action"`
	Reason         string   `json:"reason"`
	DelegationPath []string `json:"delegation_path,omitempty"`
	IntegrityOK    bool     `json:"integrity_ok"`
}

// Investigate finds the recorded action for a passport id and returns the full
// accountability picture: the responsible principal, the acting agent, the delegation
// path, and whether the audit record is provably intact (FR-24).
func (l *HashChainLog) Investigate(passportID string) (Report, error) {
	entries := l.Entries()
	intact := VerifyChain(entries) == nil
	for _, e := range entries {
		if e.PassportID == passportID {
			return Report{
				PassportID:     e.PassportID,
				Principal:      e.Principal,
				Agent:          e.Agent,
				Server:         e.Server,
				Action:         e.Action,
				Reason:         e.Reason,
				DelegationPath: e.Delegation,
				IntegrityOK:    intact,
			}, nil
		}
	}
	return Report{}, fmt.Errorf("audit: no record for passport %q", passportID)
}

// ByPrincipal returns every recorded action attributed to a principal (incident triage).
func (l *HashChainLog) ByPrincipal(principalID string) []Entry {
	var out []Entry
	for _, e := range l.Entries() {
		if e.Principal == principalID {
			out = append(out, e)
		}
	}
	return out
}
