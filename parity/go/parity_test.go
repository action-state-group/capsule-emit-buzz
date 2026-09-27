// SPDX-License-Identifier: Apache-2.0

// Package parity is the SECOND-LANGUAGE parity harness. Go is chosen to match
// the sibling adapter (capsule-emit-dapr is a Go repo), so the two-language
// story here is Python (reference) + Go (asserts the same fixtures).
//
// This harness re-derives the record subject from each input event fixture and
// asserts it is byte-for-byte equal to the Python-reference-generated record
// fixture. If Go's SHA-256 over identical content bytes, or its principal_ref
// derivation, disagreed with Python's, these tests would go red.
//
// The derivation logic mirrored here is deliberately tiny (SHA-256 of the
// content bytes; "nostr-pubkey:" + pubkey; keep event_id and semantic_digest
// distinct) precisely because that is all the record subject is. The reference
// of record is the Python code in ../../capsule_emit_buzz; this file must track
// it, and the fixtures are the contract between them.
package parity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type eventFixture struct {
	Profile    string `json:"profile"`
	EventID    string `json:"event_id"`
	Pubkey     string `json:"pubkey"`
	Kind       int    `json:"kind"`
	ContentHex string `json:"content_hex"`
	RelayHint  string `json:"relay_hint,omitempty"`
}

type subject struct {
	EventID        string `json:"event_id"`
	SemanticDigest string `json:"semantic_digest"`
}

type recordFixture struct {
	Profile               string  `json:"profile"`
	Subject               subject `json:"subject"`
	PrincipalRef          string  `json:"principal_ref"`
	PrincipalRefRelayHint string  `json:"principal_ref_relay_hint,omitempty"`
}

// deriveRecord mirrors capsule_emit_buzz.record.record_subject.
func deriveRecord(ev eventFixture) (recordFixture, error) {
	content, err := hex.DecodeString(ev.ContentHex)
	if err != nil {
		return recordFixture{}, err
	}
	sum := sha256.Sum256(content)
	semanticDigest := hex.EncodeToString(sum[:])

	rec := recordFixture{
		Profile: ev.Profile,
		Subject: subject{
			EventID:        ev.EventID,
			SemanticDigest: semanticDigest,
		},
		PrincipalRef: "nostr-pubkey:" + ev.Pubkey,
	}
	if ev.RelayHint != "" {
		rec.PrincipalRefRelayHint = ev.RelayHint
	}
	return rec, nil
}

var positives = []string{"agent_job", "moderation", "release"}

func TestGoDerivationMatchesPythonFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "fixtures")
	for _, name := range positives {
		name := name
		t.Run(name, func(t *testing.T) {
			evBytes, err := os.ReadFile(filepath.Join(root, "events", name+".json"))
			if err != nil {
				t.Fatalf("read event fixture: %v", err)
			}
			var ev eventFixture
			if err := json.Unmarshal(evBytes, &ev); err != nil {
				t.Fatalf("parse event fixture: %v", err)
			}

			got, err := deriveRecord(ev)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}

			wantBytes, err := os.ReadFile(filepath.Join(root, "records", name+".json"))
			if err != nil {
				t.Fatalf("read record fixture: %v", err)
			}
			var want recordFixture
			if err := json.Unmarshal(wantBytes, &want); err != nil {
				t.Fatalf("parse record fixture: %v", err)
			}

			if got != want {
				t.Errorf("record mismatch for %s:\n go     = %+v\n python = %+v", name, got, want)
			}

			// The whole point: the two fields are distinct.
			if got.Subject.EventID == got.Subject.SemanticDigest {
				t.Errorf("%s: event_id and semantic_digest collapsed to one value", name)
			}
		})
	}
}
