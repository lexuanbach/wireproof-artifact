package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type Capture struct {
	Connection, Handshake, Group, Source, Destination, Artifact, Config, ServerBytes string
	ExpectedFailure                                                                  bool
	Error                                                                            string
}
type Check struct {
	Name, Engine, Expected, Actual string
	Pass                           bool
}
type Trial struct {
	Scenario        string
	Repetition      int
	Checks          []Check
	Captures        []Capture
	Error           string
	StaleDurationMS float64
}
type Harness struct {
	Dir, Epoch, Policy string
	Events             []Event
	Wire, Base         *Ledger
	Key                ed25519.PrivateKey
	Trial              Trial
	Sessions           []*Session
}

func (h *Harness) emit(e Event) (*Verdict, *Verdict) {
	if e.At == 0 {
		e.At = time.Now().UnixNano()
	}
	if e.Epoch == "" {
		e.Epoch = h.Epoch
	}
	if e.Policy == "" {
		e.Policy = h.Policy
	}
	h.Events = append(h.Events, e)
	return h.Wire.Apply(e), h.Base.Apply(e)
}
func (h *Harness) check(name, mode, wantW, wantB string, pop ...string) {
	w, b := h.emit(Event{Type: "assess", Mode: mode, Population: pop})
	h.Trial.Checks = append(h.Trial.Checks, Check{name, "wireproof", wantW, w.HistoricalStatus, wantW == w.HistoricalStatus}, Check{name, "baseline", wantB, b.HistoricalStatus, wantB == b.HistoricalStatus})
}
func (h *Harness) live(s *Session) {
	h.emit(Event{Type: "live", Connection: s.ID, VerifiedAt: s.Reply.At})
}
func (h *Harness) deliver(s *Session) {
	r := s.Reply
	for _, kind := range []string{"ke", "auth"} {
		val := r.Group
		if kind == "auth" {
			val = "mutual_x509_verified"
		}
		o := sign(Observation{ID: s.ID + "-" + kind, Connection: s.ID, Handshake: r.Handshake, Kind: kind, Operation: r.Operation, Source: r.Peer, Destination: r.Identity, Artifact: r.Artifact, Config: r.Config, Issuer: "tls-observer", Value: val, NegotiationEpoch: "e1", ObservedAt: r.At}, h.Key)
		h.emit(Event{Type: "observe", Observation: &o})
	}
	h.live(s)
	h.appraise(s)
}
func (h *Harness) appraise(s *Session) {
	h.emit(Event{Type: "appraise", Connection: s.ID, References: []string{s.ID + "-ke", s.ID + "-auth"}})
}
func (h *Harness) barrier() { h.emit(Event{Type: "barrier", Population: sortedKeys(h.Wire.Known)}) }
func (h *Harness) open(pki, id string, p *Process, strict bool) (*Session, error) {
	s, e := connect(pki, h.Dir, id, p, strict)
	cap := Capture{Connection: id, ServerBytes: id + "-server.bin"}
	if e != nil {
		cap.Error = e.Error()
		h.Trial.Captures = append(h.Trial.Captures, cap)
		return nil, e
	}
	r := s.Reply
	cap.Handshake = r.Handshake
	cap.Group = r.Group
	cap.Source = r.Peer
	cap.Destination = r.Identity
	cap.Artifact = r.Artifact
	cap.Config = r.Config
	h.Trial.Captures = append(h.Trial.Captures, cap)
	h.Sessions = append(h.Sessions, s)
	return s, nil
}
func run(out string, n int) error {
	if _, e := os.Stat(out); e == nil {
		return fmt.Errorf("output already exists, choose a new -out")
	}
	if e := os.MkdirAll(out, 0755); e != nil {
		return e
	}
	out, _ = filepath.Abs(out)
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	pki := filepath.Join(out, "test-pki")
	if e = makePKI(pki); e != nil {
		return e
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	os.WriteFile(filepath.Join(out, "observer-public-key.hex"), []byte(hex.EncodeToString(pub)), 0644)
	failed := false
	for _, name := range []string{"hybrid", "fallback", "rollout", "delayed", "stale", "reassignment"} {
		for i := 1; i <= n; i++ {
			dir := filepath.Join(out, fmt.Sprintf("%s-%02d", name, i))
			if e = os.MkdirAll(dir, 0755); e != nil {
				return e
			}
			t := trial(exe, pki, dir, name, i, pub, priv)
			if e = writeJSON(filepath.Join(dir, "trial.json"), t); e != nil {
				return e
			}
			for _, c := range t.Checks {
				if !c.Pass {
					failed = true
				}
			}
			if t.Error != "" {
				failed = true
			}
			fmt.Printf("%s %02d: %d checks, error=%s\n", name, i, len(t.Checks), t.Error)
		}
	}
	if e = replay(out); e != nil {
		return e
	}
	if e = summarize(out); e != nil {
		return e
	}
	if failed {
		return fmt.Errorf("demonstration has failures, retained in %s", out)
	}
	return nil
}
func trial(exe, pki, dir, name string, i int, pub ed25519.PublicKey, priv ed25519.PrivateKey) (result Trial) {
	result = Trial{Scenario: name, Repetition: i}
	old, e := startServer(exe, pki, dir, "old", "X25519")
	if e != nil {
		result.Error = e.Error()
		return
	}
	defer old.Close()
	next, e := startServer(exe, pki, dir, "new", "X25519MLKEM768")
	if e != nil {
		result.Error = e.Error()
		return
	}
	defer next.Close()
	m := Manifest{GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH, ExecutableSHA256: fileHash(exe), ObserverPublicKey: hex.EncodeToString(pub), StartedAt: time.Now().UnixNano(), Bindings: map[string]Binding{}}
	for _, p := range []*Process{old, next} {
		m.Bindings[p.Ready.Identity] = Binding{p.Ready.Identity, p.Ready.Artifact, p.Ready.Config}
	}
	writeJSON(filepath.Join(dir, "manifest.json"), m)
	writeJSON(filepath.Join(dir, "launch.json"), []Ready{old.Ready, next.Ready})
	h := &Harness{Dir: dir, Epoch: "e1", Policy: "p1", Wire: NewLedger("wireproof", m), Base: NewLedger("baseline", m), Key: priv, Trial: result}
	defer func() {
		for _, s := range h.Sessions {
			s.Close()
		}
		f, e := os.Create(filepath.Join(dir, "events.jsonl"))
		if e == nil {
			enc := json.NewEncoder(f)
			for _, ev := range h.Events {
				enc.Encode(ev)
			}
			f.Close()
		} else {
			h.Trial.Error = e.Error()
		}
		result = h.Trial
	}()
	h.emit(Event{Type: "assign"})
	open := func(id string, p *Process, strict bool) *Session {
		s, e := h.open(pki, id, p, strict)
		if e != nil {
			h.Trial.Error = e.Error()
		}
		return s
	}
	discover := func(s *Session) { h.emit(Event{Type: "discover", Connection: s.ID}) }
	switch name {
	case "hybrid":
		c := open("c1", next, true)
		if c == nil {
			return
		}
		discover(c)
		h.deliver(c)
		h.barrier()
		h.check("strict hybrid accepted", "reported", "confirmed", "confirmed", "c1")
		h.check("complete positive", "complete", "confirmed", "unsupported", "c1")
		_, err := h.open(pki, "strict-reject", old, true)
		h.Trial.Captures[len(h.Trial.Captures)-1].ExpectedFailure = true
		h.Trial.Checks = append(h.Trial.Checks, Check{"strict classical rejection", "tls", "handshake rejected", fmt.Sprint(err != nil), err != nil})
	case "fallback":
		c := open("c1", old, false)
		if c == nil {
			return
		}
		discover(c)
		h.deliver(c)
		h.barrier()
		h.check("configured hybrid actual classical", "reported", "blocked", "blocked", "c1")
	case "rollout":
		c1 := open("c1", old, false)
		c2 := open("c2", next, false)
		if c1 == nil || c2 == nil {
			return
		}
		discover(c1)
		discover(c2)
		h.deliver(c2)
		h.check("new instance scope", "reported", "confirmed", "confirmed", "c2")
		h.check("old still unaccounted", "complete", "pending", "unsupported", "c1", "c2")
		h.deliver(c1)
		h.barrier()
		h.check("old classical retained", "reported", "revoked", "revoked", "c1", "c2")
	case "delayed":
		c1 := open("c1", next, false)
		c2 := open("c2", next, false)
		if c1 == nil || c2 == nil {
			return
		}
		discover(c1)
		discover(c2)
		h.deliver(c1)
		h.check("partial same population", "reported", "pending", "pending", "c1", "c2")
		h.check("before barrier", "complete", "pending", "unsupported", "c1", "c2")
		time.Sleep(50 * time.Millisecond)
		h.deliver(c2)
		h.barrier()
		h.check("after delivery", "complete", "confirmed", "unsupported", "c1", "c2")
	case "stale":
		c1 := open("c1", next, false)
		if c1 == nil {
			return
		}
		discover(c1)
		h.deliver(c1)
		h.barrier()
		h.check("initial correct", "reported", "confirmed", "confirmed", "c1")
		c2 := open("c2", old, false)
		if c2 == nil {
			return
		}
		origin := c2.Reply.At
		h.emit(Event{Type: "truth_violation", At: origin, Connection: "c2", Note: "later connection, observer delivery held 50 ms"})
		time.Sleep(50 * time.Millisecond)
		discover(c2)
		h.Trial.StaleDurationMS = float64(h.Events[len(h.Events)-1].At-origin) / 1e6
		h.deliver(c2)
		h.barrier()
		h.check("withdraw after violation", "reported", "revoked", "revoked", "c1", "c2")
	case "reassignment":
		c := open("c1", next, false)
		if c == nil {
			return
		}
		discover(c)
		h.deliver(c)
		h.barrier()
		h.check("initial epoch", "reported", "confirmed", "confirmed", "c1")
		original := c.Reply.Handshake
		h.emit(Event{Type: "invalidate"})
		h.emit(Event{Type: "appraise", Connection: "c1", References: []string{"c1-ke", "c1-auth"}})
		h.check("replay cannot resurrect", "reported", "revoked", "revoked", "c1")
		h.Epoch = "e2"
		h.Policy = "p2"
		h.emit(Event{Type: "assign"})
		if e = c.Ping(); e != nil {
			h.Trial.Error = e.Error()
			return
		}
		h.Trial.Checks = append(h.Trial.Checks, Check{"same handshake reappraised", "tls", original, c.Reply.Handshake, original == c.Reply.Handshake})
		h.live(c)
		h.appraise(c)
		h.barrier()
		h.check("new epoch existing connection", "reported", "confirmed", "confirmed", "c1")
		h.check("new epoch complete", "complete", "confirmed", "unsupported", "c1")
	}
	return
}

type Replay struct {
	WireAppraisals, BaselineAppraisals []Appraisal
	WireHistory, BaselineHistory       []Verdict
	WireChanges, BaselineChanges       []Change
	WireCorrections                    []Correction
	WireRejected, BaselineRejected     []string
}

func replay(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*", "events.jsonl"))
	if len(files) == 0 {
		return fmt.Errorf("no events")
	}
	for _, p := range files {
		var m Manifest
		b, e := os.ReadFile(filepath.Join(filepath.Dir(p), "manifest.json"))
		if e != nil {
			return e
		}
		if e = json.Unmarshal(b, &m); e != nil {
			return e
		}
		w, base := NewLedger("wireproof", m), NewLedger("baseline", m)
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 4096), 1024*1024)
		for sc.Scan() {
			var ev Event
			if e = json.Unmarshal(sc.Bytes(), &ev); e != nil {
				f.Close()
				return e
			}
			w.Apply(ev)
			base.Apply(ev)
		}
		e = sc.Err()
		f.Close()
		if e != nil {
			return e
		}
		var original Trial
		tb, err := os.ReadFile(filepath.Join(filepath.Dir(p), "trial.json"))
		if err != nil {
			return err
		}
		if err = json.Unmarshal(tb, &original); err != nil {
			return err
		}
		wi, bi := 0, 0
		for _, c := range original.Checks {
			var actual string
			if c.Engine == "wireproof" {
				if wi >= len(w.History) {
					return fmt.Errorf("missing wire replay")
				}
				actual = w.History[wi].HistoricalStatus
				wi++
			} else if c.Engine == "baseline" {
				if bi >= len(base.History) {
					return fmt.Errorf("missing baseline replay")
				}
				actual = base.History[bi].HistoricalStatus
				bi++
			} else {
				continue
			}
			if actual != c.Expected {
				return fmt.Errorf("replay mismatch %s %s: %s != %s", p, c.Name, actual, c.Expected)
			}
		}
		if e = writeJSON(filepath.Join(filepath.Dir(p), "replay.json"), Replay{w.AppraisalHistory, base.AppraisalHistory, w.History, base.History, w.Changes, base.Changes, w.Corrections, w.Rejected, base.Rejected}); e != nil {
			return e
		}
	}
	return nil
}

type Counts struct {
	Trials, Checks, Passed, Failures, SuccessfulConnections, StrictRejections int
	StaleDurationMS                                                           []float64
}

func summarize(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*", "trial.json"))
	if len(files) == 0 {
		return fmt.Errorf("no trials")
	}
	totals := map[string]*Counts{}
	for _, p := range files {
		var t Trial
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		if e = json.Unmarshal(b, &t); e != nil {
			return e
		}
		c := totals[t.Scenario]
		if c == nil {
			c = &Counts{}
			totals[t.Scenario] = c
		}
		c.Trials++
		if t.Error != "" {
			c.Failures++
		}
		for _, v := range t.Checks {
			c.Checks++
			if v.Pass {
				c.Passed++
			} else {
				c.Failures++
			}
		}
		for _, v := range t.Captures {
			if v.ExpectedFailure && v.Error != "" {
				c.StrictRejections++
			} else if v.Group != "" {
				c.SuccessfulConnections++
			}
		}
		if t.StaleDurationMS > 0 {
			c.StaleDurationMS = append(c.StaleDurationMS, t.StaleDurationMS)
		}
	}
	if e := writeJSON(filepath.Join(dir, "summary.json"), totals); e != nil {
		return e
	}
	names := []string{}
	for k := range totals {
		names = append(names, k)
	}
	sort.Strings(names)
	var csv, tex strings.Builder
	csv.WriteString("scenario,trials,checks,passed,failures,successful_connections,strict_rejections\n")
	for _, name := range names {
		c := totals[name]
		fmt.Fprintf(&csv, "%s,%d,%d,%d,%d,%d,%d\n", name, c.Trials, c.Checks, c.Passed, c.Failures, c.SuccessfulConnections, c.StrictRejections)
		fmt.Fprintf(&tex, "%s & %d & %d/%d & %d \\\\ \n", name, c.Trials, c.Passed, c.Checks, c.SuccessfulConnections)
	}
	if e := os.WriteFile(filepath.Join(dir, "summary.csv"), []byte(csv.String()), 0644); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, "summary.tex"), []byte(tex.String()), 0644)
}
