package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func fixture(t *testing.T) (*Ledger, ed25519.PrivateKey) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	m := Manifest{ObserverPublicKey: hex.EncodeToString(pub), Bindings: map[string]Binding{"dest": {Identity: "dest", Artifact: "artifact", Config: "config"}}}
	l := NewLedger("wireproof", m)
	l.Apply(Event{Type: "assign", Epoch: "e1", Policy: "p1", At: 100})
	return l, key
}
func obs(id, c, k string, key ed25519.PrivateKey) Observation {
	v := "X25519MLKEM768"
	if k == "auth" {
		v = "mutual_x509_verified"
	}
	return sign(Observation{ID: id, Connection: c, Handshake: "hand-" + c, Kind: k, Operation: "checkout.pay", Source: "spiffe://wireproof.test/checkout/v1", Destination: "dest", Artifact: "artifact", Config: "config", Issuer: "tls-observer", Value: v, NegotiationEpoch: "e1", ObservedAt: 101}, key)
}
func add(l *Ledger, o Observation) {
	l.Apply(Event{Type: "discover", Connection: o.Connection, At: 102})
	l.Apply(Event{Type: "observe", Observation: &o, At: 103})
	l.Apply(Event{Type: "live", Epoch: "e1", Connection: o.Connection, At: 104, VerifiedAt: 101})
	l.Apply(Event{Type: "appraise", Epoch: "e1", Policy: "p1", Connection: o.Connection, References: []string{o.ID}, At: 105})
}
func assess(l *Ledger, mode string, at int64, pop ...string) *Verdict {
	return l.Apply(Event{Type: "assess", Epoch: l.Epoch, Policy: l.Policy, Mode: mode, At: at, Population: pop})
}
func complete(l *Ledger, key ed25519.PrivateKey) {
	add(l, obs("ke", "c1", "ke", key))
	add(l, obs("auth", "c1", "auth", key))
}
func TestSplitConnectionEvidence(t *testing.T) {
	l, k := fixture(t)
	add(l, obs("ke", "c1", "ke", k))
	add(l, obs("auth", "c2", "auth", k))
	v := assess(l, "reported", 110, "c1", "c2")
	if v.HistoricalStatus != "pending" || v.Known != 2 {
		t.Fatalf("%+v", v)
	}
}
func TestMissingAuthentication(t *testing.T) {
	l, k := fixture(t)
	add(l, obs("ke", "c1", "ke", k))
	if assess(l, "reported", 110, "c1").HistoricalStatus != "pending" {
		t.Fatal("partial confirmed")
	}
}
func TestWrongBinding(t *testing.T) {
	for _, field := range []string{"operation", "artifact", "config", "issuer", "signature"} {
		t.Run(field, func(t *testing.T) {
			l, k := fixture(t)
			o := obs("ke", "c1", "ke", k)
			switch field {
			case "operation":
				o.Operation = "refund.sign"
			case "artifact":
				o.Artifact = "wrong"
			case "config":
				o.Config = "wrong"
			case "issuer":
				o.Issuer = "build-attestor"
			}
			o = sign(o, k)
			if field == "signature" {
				o.Signature = "00"
			}
			add(l, o)
			add(l, obs("auth", "c1", "auth", k))
			if assess(l, "reported", 110, "c1").HistoricalStatus != "pending" || len(l.Rejected) == 0 {
				t.Fatal("bad binding accepted")
			}
		})
	}
}
func TestDuplicateDoesNotRefresh(t *testing.T) {
	l, k := fixture(t)
	complete(l, k)
	original := l.Live["c1"]
	o := obs("ke", "c1", "ke", k)
	l.Apply(Event{Type: "observe", Observation: &o, At: 4_000_000_000})
	if len(l.Facts) != 2 || l.Live["c1"] != original {
		t.Fatal("duplicate changed evidence")
	}
	if assess(l, "reported", 4_000_000_001, "c1").HistoricalStatus != "pending" {
		t.Fatal("stale evidence confirmed")
	}
}
func TestMissingBarrier(t *testing.T) {
	l, k := fixture(t)
	complete(l, k)
	if assess(l, "complete", 110, "c1").HistoricalStatus != "pending" {
		t.Fatal("unclosed")
	}
	l.Apply(Event{Type: "barrier", Epoch: "e1", Population: []string{"c1"}, At: 111})
	if assess(l, "complete", 112, "c1").HistoricalStatus != "confirmed" {
		t.Fatal("closed population did not confirm")
	}
}
func TestHistoryAndReappraisal(t *testing.T) {
	l, k := fixture(t)
	complete(l, k)
	v := assess(l, "reported", 110, "c1")
	before, _ := json.Marshal(*v)
	facts, _ := json.Marshal(l.Facts)
	l.Apply(Event{Type: "invalidate", Epoch: "e1", At: 111})
	l.Apply(Event{Type: "appraise", Epoch: "e1", Policy: "p1", Connection: "c1", References: []string{"ke", "auth"}, At: 112})
	if l.Current != "revoked" {
		t.Fatal("resurrected")
	}
	l.Apply(Event{Type: "assign", Epoch: "e2", Policy: "p2", At: 113})
	l.Apply(Event{Type: "live", Epoch: "e2", Connection: "c1", At: 114})
	l.Apply(Event{Type: "appraise", Epoch: "e2", Policy: "p2", Connection: "c1", References: []string{"ke", "auth"}, At: 115})
	if assess(l, "reported", 116, "c1").HistoricalStatus != "confirmed" {
		t.Fatal("no reappraisal")
	}
	l.Apply(Event{Type: "assess", Epoch: "e1", Policy: "p1", Mode: "reported", Population: []string{"c1"}, At: 117})
	if l.Current != "confirmed" {
		t.Fatal("old assessment changed current epoch")
	}
	after, _ := json.Marshal(l.History[0])
	currentFacts, _ := json.Marshal(l.Facts)
	if string(before) != string(after) || string(facts) != string(currentFacts) {
		t.Fatal("immutable evidence/history changed")
	}
	if !l.Known["c1"] {
		t.Fatal("draining connection erased")
	}
}
func TestPolicyMismatch(t *testing.T) {
	l, k := fixture(t)
	complete(l, k)
	l.Appraisals["e1"] = map[string][]string{}
	l.Apply(Event{Type: "appraise", Epoch: "e1", Policy: "wrong", Connection: "c1", References: []string{"ke", "auth"}})
	if assess(l, "reported", 110, "c1").HistoricalStatus != "pending" {
		t.Fatal("wrong policy accepted")
	}
}
func TestLateCorrectionIsAppendOnly(t *testing.T) {
	l, k := fixture(t)
	complete(l, k)
	assess(l, "reported", 110, "c1")
	o := obs("late-ke", "c1", "ke", k)
	o.Value = "X25519"
	o = sign(o, k)
	l.Apply(Event{Type: "observe", Observation: &o, At: 120})
	if len(l.Corrections) != 1 || l.History[0].HistoricalStatus != "confirmed" {
		t.Fatal("correction missing or destructive")
	}
}
func TestConflictingHandshake(t *testing.T) {
	l, k := fixture(t)
	add(l, obs("ke", "c1", "ke", k))
	o := obs("auth", "c1", "auth", k)
	o.Handshake = "different"
	o = sign(o, k)
	add(l, o)
	if assess(l, "reported", 110, "c1").HistoricalStatus != "pending" {
		t.Fatal("mixed handshakes accepted")
	}
}
func TestBaselineCompleteUnsupported(t *testing.T) {
	l, k := fixture(t)
	l.Engine = "baseline"
	complete(l, k)
	if assess(l, "complete", 110, "c1").HistoricalStatus != "unsupported" {
		t.Fatal("baseline claims full coverage")
	}
}

func TestPartialSubjectCannotDisappear(t *testing.T) {
	l, k := fixture(t)
	complete(l, k)
	add(l, obs("partial", "c2", "ke", k))
	if assess(l, "reported", 110, "c1").HistoricalStatus != "pending" {
		t.Fatal("partial subject dropped")
	}
}

func TestUnappraisedConflictCannotHide(t *testing.T) {
	l, k := fixture(t)
	complete(l, k)
	o := obs("conflict", "c1", "ke", k)
	o.Value = "X25519"
	o = sign(o, k)
	l.Apply(Event{Type: "observe", Observation: &o, At: 106})
	if assess(l, "reported", 110, "c1").HistoricalStatus == "confirmed" {
		t.Fatal("omitted conflict confirmed")
	}
}
func TestDuplicateAssignmentCannotReset(t *testing.T) {
	l, k := fixture(t)
	complete(l, k)
	assess(l, "reported", 110, "c1")
	l.Apply(Event{Type: "assign", Epoch: "e1", Policy: "p2", At: 111})
	if l.Policy != "p1" || l.Current != "confirmed" {
		t.Fatal("epoch rewritten")
	}
	l.Apply(Event{Type: "invalidate", Epoch: "e1", At: 112})
	l.Apply(Event{Type: "assign", Epoch: "e1", Policy: "p1", At: 113})
	if l.Current != "revoked" {
		t.Fatal("invalid epoch resurrected")
	}
}
func TestFutureEvidenceCannotConfirm(t *testing.T) {
	l, k := fixture(t)
	complete(l, k)
	if assess(l, "reported", 100, "c1").HistoricalStatus == "confirmed" {
		t.Fatal("future evidence confirmed")
	}
}
