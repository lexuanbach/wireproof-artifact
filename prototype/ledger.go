package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

type Observation struct {
	ID, Connection, Handshake, Kind, Operation, Source, Destination string
	Artifact, Config, Issuer, Value, NegotiationEpoch, Signature    string
	ObservedAt                                                      int64
}

func payload(o Observation) []byte { o.Signature = ""; b, _ := json.Marshal(o); return b }
func sign(o Observation, key ed25519.PrivateKey) Observation {
	o.Signature = hex.EncodeToString(ed25519.Sign(key, payload(o)))
	return o
}

type Binding struct{ Identity, Artifact, Config string }
type Manifest struct {
	GoVersion, OS, Arch, ExecutableSHA256, ObserverPublicKey string
	StartedAt                                                int64
	Bindings                                                 map[string]Binding
}
type Event struct {
	VerifiedAt                                  int64
	Type, Epoch, Policy, Connection, Mode, Note string
	At                                          int64
	Population, References                      []string
	Observation                                 *Observation
}
type Appraisal struct {
	ID, Epoch, Policy, Mode string
	Cut                     int64
	Population, References  []string
}

type Verdict struct {
	ID, Engine, Epoch, Policy, Mode, HistoricalStatus, CurrentStatus string
	At                                                               int64
	Population, References                                           []string
	Known, Assessed, Unassessed                                      int
	Reason                                                           string
}
type Change struct {
	At                    int64
	Epoch, Status, Reason string
}
type Correction struct {
	At                            int64
	VerdictID, EvidenceID, Reason string
}
type Ledger struct {
	Engine, Epoch, Policy, Current string
	Manifest                       Manifest
	Facts                          map[string]Observation
	Appraisals                     map[string]map[string][]string
	Live                           map[string]int64
	Known                          map[string]bool
	Closed                         map[string]bool
	Invalid                        map[string]bool
	EverConfirmed                  map[string]bool
	AppraisalHistory               []Appraisal
	History                        []Verdict
	Changes                        []Change
	Corrections                    []Correction
	Rejected                       []string
}

const freshness int64 = 2_000_000_000

func NewLedger(engine string, m Manifest) *Ledger {
	return &Ledger{Engine: engine, Manifest: m, Current: "pending", Facts: map[string]Observation{}, Appraisals: map[string]map[string][]string{}, Live: map[string]int64{}, Known: map[string]bool{}, Closed: map[string]bool{}, Invalid: map[string]bool{}, EverConfirmed: map[string]bool{}}
}
func (l *Ledger) change(e Event, s, reason string) {
	if l.Current != s {
		l.Current = s
		l.Changes = append(l.Changes, Change{e.At, l.Epoch, s, reason})
	}
}
func (l *Ledger) valid(o Observation) bool {
	pk, _ := hex.DecodeString(l.Manifest.ObserverPublicKey)
	sig, _ := hex.DecodeString(o.Signature)
	if len(pk) != ed25519.PublicKeySize || !ed25519.Verify(pk, payload(o), sig) || o.Issuer != "tls-observer" {
		return false
	}
	b, ok := l.Manifest.Bindings[o.Destination]
	if !ok || o.Source != "spiffe://wireproof.test/checkout/v1" {
		return false
	}
	if l.Engine == "wireproof" && (o.Operation != "checkout.pay" || o.Artifact != b.Artifact || o.Config != b.Config) {
		return false
	}
	return o.Handshake != "" && (o.Kind == "ke" || o.Kind == "auth")
}
func sortedKeys(m map[string]bool) []string {
	a := []string{}
	for k := range m {
		a = append(a, k)
	}
	sort.Strings(a)
	return a
}
func same(a, b []string) bool {
	a = append([]string{}, a...)
	b = append([]string{}, b...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (l *Ledger) Apply(e Event) *Verdict {
	switch e.Type {
	case "assign":
		if e.Epoch == l.Epoch && l.Epoch != "" {
			if e.Policy != l.Policy {
				l.Rejected = append(l.Rejected, "policy change requires new epoch")
			}
			return nil
		}
		if l.Invalid[e.Epoch] {
			l.Rejected = append(l.Rejected, "reused invalid epoch "+e.Epoch)
			return nil
		}
		if l.Epoch != "" && l.Epoch != e.Epoch {
			l.Invalid[l.Epoch] = true
		}
		l.Epoch = e.Epoch
		l.Policy = e.Policy
		if l.Appraisals[e.Epoch] == nil {
			l.Appraisals[e.Epoch] = map[string][]string{}
		}
		l.change(e, "pending", "new assignment")
	case "discover":
		l.Known[e.Connection] = true
		l.Closed[l.Epoch] = false
		if !l.Invalid[l.Epoch] {
			l.change(e, "pending", "new population member requires assessment")
		}
	case "observe":
		if e.Observation == nil {
			return nil
		}
		o := *e.Observation
		if !l.valid(o) {
			l.Rejected = append(l.Rejected, o.ID)
			return nil
		}
		if old, ok := l.Facts[o.ID]; ok {
			if string(payload(old)) != string(payload(o)) {
				l.Rejected = append(l.Rejected, "conflicting ID "+o.ID)
			}
			return nil
		}
		l.Facts[o.ID] = o
		// A late known violation of the ORIGINAL named population appends a correction.
		if o.Kind == "ke" && o.Value != "X25519MLKEM768" {
			for _, v := range l.History {
				if v.HistoricalStatus == "confirmed" {
					for _, c := range v.Population {
						if c == o.Connection && o.ObservedAt <= v.At {
							l.Corrections = append(l.Corrections, Correction{e.At, v.ID, o.ID, "late contradictory historical evidence"})
						}
					}
				}
			}
		}
	case "live":
		// Liveness is a separate authenticated harness event, not a retransmission.
		if e.Epoch == l.Epoch && !l.Invalid[e.Epoch] {
			if e.VerifiedAt != 0 {
				l.Live[e.Connection] = e.VerifiedAt
			} else {
				l.Live[e.Connection] = e.At
			}
		}
	case "appraise":
		if e.Epoch != l.Epoch || l.Invalid[e.Epoch] || e.Policy != l.Policy {
			l.Rejected = append(l.Rejected, "inactive appraisal "+e.Epoch)
			return nil
		}
		refs := []string{}
		for _, id := range e.References {
			if o, ok := l.Facts[id]; ok && o.Connection == e.Connection {
				refs = append(refs, id)
			} else {
				l.Rejected = append(l.Rejected, "missing dependency "+id)
			}
		}
		l.Appraisals[e.Epoch][e.Connection] = append(l.Appraisals[e.Epoch][e.Connection], refs...)
	case "barrier":
		if e.Epoch == l.Epoch && !l.Invalid[e.Epoch] && same(e.Population, sortedKeys(l.Known)) {
			l.Closed[e.Epoch] = true
		}
	case "invalidate":
		if e.Epoch == l.Epoch {
			l.Invalid[e.Epoch] = true
			l.change(e, "revoked", "assignment invalidated")
		}
	case "assess":
		return l.Assess(e)
	}
	return nil
}
func (l *Ledger) Assess(e Event) *Verdict {
	pop := append([]string{}, e.Population...)
	v := Verdict{ID: fmt.Sprintf("%s-v%d", l.Engine, len(l.History)+1), Engine: l.Engine, Epoch: e.Epoch, Policy: e.Policy, Mode: e.Mode, At: e.At, Population: pop, Known: len(l.Known), Assessed: len(pop), Unassessed: len(l.Known) - len(pop)}
	if v.Unassessed < 0 {
		v.Unassessed = 0
	}
	status, reason := "confirmed", "all applicable evidence joined on each connection"
	if e.Epoch != l.Epoch || l.Invalid[e.Epoch] || e.Policy != l.Policy {
		status = "revoked"
		reason = "inactive epoch"
	} else if e.Mode == "complete" && l.Engine == "baseline" {
		status = "unsupported"
		reason = "baseline does not claim population completeness"
	} else {
		if len(pop) == 0 {
			status = "pending"
			reason = "empty population"
		}
		if e.Mode == "complete" && (!l.Closed[e.Epoch] || !same(pop, sortedKeys(l.Known))) {
			status = "pending"
			reason = "current assessment lacks complete manifest/barrier"
		}
		// A reported population may include extra discovered subjects, but may
		// not silently drop a connection for which accepted partial evidence exists.
		included := map[string]bool{}
		for _, c := range pop {
			included[c] = true
		}
		for _, o := range l.Facts {
			if !included[o.Connection] {
				status = "pending"
				reason = "reported connection omitted from assessment"
			}
		}
		violation := false
		for _, c := range pop {
			found := map[string]bool{}
			hand := ""
			if !l.Known[c] {
				status = "pending"
				reason = "undiscovered subject"
			}
			refs := map[string]bool{}
			for _, id := range l.Appraisals[e.Epoch][c] {
				refs[id] = true
			}
			for id, o := range l.Facts {
				if o.Connection == c && (!refs[id] || o.ObservedAt > e.At) {
					status = "pending"
					reason = "unappraised or future evidence"
				}
			}
			for _, id := range l.Appraisals[e.Epoch][c] {
				o := l.Facts[id]
				v.References = append(v.References, id)
				if hand != "" && hand != o.Handshake {
					status = "pending"
					reason = "incompatible handshake bindings"
				}
				hand = o.Handshake
				found[o.Kind] = true
				if (o.Kind == "ke" && o.Value != "X25519MLKEM768") || (o.Kind == "auth" && o.Value != "mutual_x509_verified") {
					violation = true
				}
			}
			if !found["ke"] || !found["auth"] {
				status = "pending"
				reason = "partial connection evidence"
			}
			if l.Live[c] == 0 || e.At-l.Live[c] > freshness || l.Live[c] > e.At {
				status = "pending"
				reason = "stale or missing liveness"
			}
		}
		if violation {
			status = "blocked"
			reason = "known forbidden value"
			if l.EverConfirmed[e.Epoch] {
				status = "revoked"
			}
			l.Invalid[e.Epoch] = true
		}
	}
	l.AppraisalHistory = append(l.AppraisalHistory, Appraisal{ID: fmt.Sprintf("%s-a%d", l.Engine, len(l.AppraisalHistory)+1), Epoch: e.Epoch, Policy: e.Policy, Mode: e.Mode, Cut: e.At, Population: append([]string{}, v.Population...), References: append([]string{}, v.References...)})
	v.HistoricalStatus = status
	if status != "unsupported" && e.Epoch == l.Epoch {
		l.change(e, status, reason)
	}
	if status == "confirmed" {
		l.EverConfirmed[e.Epoch] = true
	}
	v.CurrentStatus = l.Current
	v.Reason = reason
	l.History = append(l.History, v)
	return &v
}
