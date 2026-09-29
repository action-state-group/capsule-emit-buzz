// SPDX-License-Identifier: Apache-2.0

// Package parity is the second-language parity harness: Python is the
// reference, and this harness asserts the same results from the same files.
//
// For each signed event fixture it recomputes the NIP-01 event id from the
// event's fields with its own serializer (below), and checks it against the
// event's id and the id the Python reference recorded. It checks the semantic
// digest (SHA-256 of the full event exactly as stored) and the principal_ref.
// It also recomputes the ids of the real signed events in
// fixtures/nip01-vectors, which come from another implementation.
package parity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type nostrEvent struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

type meta struct {
	Profile   string `json:"profile"`
	RelayHint string `json:"relay_hint,omitempty"`
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

// nip01String writes s as NIP-01 does: line feed, double quote, backslash,
// carriage return, tab, backspace and form feed are escaped; every other
// character is written as is (unlike encoding/json, which escapes <, >, &
// and U+2028/U+2029).
func nip01String(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// eventID computes the NIP-01 id: sha256([0,pubkey,created_at,kind,tags,content]).
func eventID(ev nostrEvent) string {
	var b strings.Builder
	b.WriteString("[0,")
	nip01String(&b, ev.Pubkey)
	b.WriteString("," + strconv.FormatInt(ev.CreatedAt, 10) + "," + strconv.Itoa(ev.Kind) + ",[")
	for i, tag := range ev.Tags {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('[')
		for j, v := range tag {
			if j > 0 {
				b.WriteByte(',')
			}
			nip01String(&b, v)
		}
		b.WriteByte(']')
	}
	b.WriteString("],")
	nip01String(&b, ev.Content)
	b.WriteByte(']')
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func readJSON(t *testing.T, path string, into any) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return raw
}

var positives = []string{"agent_job", "moderation", "release"}

func TestGoDerivationMatchesPythonFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "fixtures")
	for _, name := range positives {
		name := name
		t.Run(name, func(t *testing.T) {
			var ev nostrEvent
			raw := readJSON(t, filepath.Join(root, "events", name+".json"), &ev)
			var m meta
			readJSON(t, filepath.Join(root, "events", name+".meta.json"), &m)
			var want recordFixture
			readJSON(t, filepath.Join(root, "records", name+".json"), &want)

			if id := eventID(ev); id != ev.ID {
				t.Fatalf("%s: recomputed id %s, event says %s", name, id, ev.ID)
			}
			sum := sha256.Sum256(raw)
			got := recordFixture{
				Profile:               m.Profile,
				Subject:               subject{EventID: ev.ID, SemanticDigest: hex.EncodeToString(sum[:])},
				PrincipalRef:          "nostr-pubkey:" + ev.Pubkey,
				PrincipalRefRelayHint: m.RelayHint,
			}
			if got != want {
				t.Errorf("record mismatch for %s:\n go     = %+v\n python = %+v", name, got, want)
			}
			if got.Subject.EventID == got.Subject.SemanticDigest {
				t.Errorf("%s: event_id and semantic_digest collapsed to one value", name)
			}
		})
	}
}

func TestGoRecomputesRealEventIDs(t *testing.T) {
	var vectors struct {
		Events []nostrEvent `json:"events"`
	}
	readJSON(t, filepath.Join("..", "..", "fixtures", "nip01-vectors", "rust-nostr.json"), &vectors)
	if len(vectors.Events) == 0 {
		t.Fatal("no vectors")
	}
	for _, ev := range vectors.Events {
		if id := eventID(ev); id != ev.ID {
			t.Errorf("recomputed id %s, event says %s", id, ev.ID)
		}
	}
}
