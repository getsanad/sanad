// Package config loads the Sanad configuration document — the file an operator edits to
// configure things that do not fit an environment variable.
//
// FORMAT: JSON, deliberately, and not YAML.
//
// The whole repository has two direct dependencies. A YAML parser would be a third, running
// inside the enforcement point, added for one file that is read once at startup; encoding/json
// is in the standard library and costs nothing. It also costs nothing LATER: YAML 1.2 is a
// superset of JSON, so the schema below is already a valid YAML document, and if the project
// ever does adopt a sanad.yaml the decoder changes here, in one function, while every key,
// nesting level and validation message stays exactly as it is. Choosing JSON now is reversible;
// taking the dependency is not.
//
// The one thing JSON genuinely lacks is comments, and a policy file is precisely where an
// operator wants to explain WHY a tool needs approval. That is answered explicitly rather than
// worked around: every object an operator would annotate carries a "note" field, which is
// parsed, logged at startup and otherwise ignored — and unknown fields are REJECTED, so a
// misspelled key ("tool" for "tools") stops the gateway instead of silently dropping the rule
// it was meant to be.
//
// The document is versioned and sectioned:
//
//	{
//	  "version": 1,
//	  "note": "production policy, owned by #security",
//	  "policy": { "servers": { … } }
//	}
//
// Today it carries one section, "policy" (policy.Config). Servers, principal mode, token TTLs
// and storage are planned to join it as sibling sections; each owns its own schema in its own
// package, so adding one touches File and nothing else.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/getsanad/sanad/policy"
)

// Version is the only document version this build understands. A file that does not declare
// it is rejected rather than guessed at: the whole point of the field is that a future
// incompatible schema fails loudly on an old binary instead of being half-read by it.
const Version = 1

// File is the configuration document.
type File struct {
	Version int    `json:"version"`
	Note    string `json:"note,omitempty"`
	// Policy is the authorization section (FR-16). It is a pointer so "absent" is
	// distinguishable from "present but empty" — the first is a mistake, the second is an
	// operator deliberately denying everything, and they deserve different errors.
	Policy *policy.Config `json:"policy"`
}

// Load reads and validates the configuration document at path.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return Parse(data, path)
}

// Parse decodes and validates a configuration document. name is used in error messages only —
// it is the path the operator has to open to fix what is reported.
//
// Decoding is strict: unknown fields are errors, and so is trailing content after the
// document. A configuration file for an enforcement point is the wrong place for the usual
// "ignore what you do not understand" leniency, where a typo reads as an absent rule and an
// absent rule reads as a denial — or, in the other direction, as an allow that was meant to be
// a review.
func Parse(data []byte, name string) (*File, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var file File
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("config %s: %w", name, locate(data, err))
	}
	if dec.More() {
		return nil, fmt.Errorf("config %s: trailing content after the document (one JSON object per file)", name)
	}

	switch {
	case file.Version == 0:
		return nil, fmt.Errorf(`config %s: missing "version"; add "version": %d`, name, Version)
	case file.Version != Version:
		return nil, fmt.Errorf("config %s: version %d is not supported by this build (it understands version %d)",
			name, file.Version, Version)
	case file.Policy == nil:
		return nil, fmt.Errorf(`config %s: no "policy" section; a configuration file that authorizes nothing `+
			`has no effect, so it is more likely a mistake than a deliberate deny-all (which is what running with no file does)`, name)
	}

	if err := file.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", name, err)
	}
	return &file, nil
}

// locate turns a decoder error into one an operator can act on, by naming the line and column
// the byte offset falls on. "invalid character '}' looking for beginning of object key string"
// is a riddle at 3am; the same message with "line 12, column 3" is a fix.
func locate(data []byte, err error) error {
	var offset int64
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		offset = syntax.Offset
	case errors.As(err, &typ):
		offset = typ.Offset
	case errors.Is(err, io.ErrUnexpectedEOF):
		// A truncated document: the decoder ran out of input with brackets still open, and
		// carries no offset of its own, so point at the end — which is where the missing
		// closing brace goes.
		line, col := position(data, int64(len(data)))
		return fmt.Errorf("unexpected end of document at line %d, column %d: a brace or bracket is left unclosed", line, col)
	default:
		// Unknown-field errors already name the field, which is the actionable part.
		return err
	}

	line, col := position(data, offset)
	if typ != nil && typ.Field != "" {
		return fmt.Errorf("line %d, column %d: %q must be a %s, not a %s", line, col, typ.Field, typ.Type, typ.Value)
	}
	return fmt.Errorf("line %d, column %d: %w", line, col, err)
}

// position converts a byte offset into a 1-based line and column.
func position(data []byte, offset int64) (line, col int) {
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	consumed := string(data[:offset])
	line = strings.Count(consumed, "\n") + 1
	col = len(consumed) - strings.LastIndex(consumed, "\n")
	return line, col
}
