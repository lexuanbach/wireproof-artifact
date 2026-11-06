package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

func hash(b []byte) string     { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func fileHash(p string) string { b, e := os.ReadFile(p); fatalIf(e); return hash(b) }
func makePKI(dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "WireProof test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); e != nil {
		return e
	}
	for i, name := range []string{"checkout", "old", "new"} {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		identity := "spiffe://wireproof.test/payment/" + name
		if name == "checkout" {
			identity = "spiffe://wireproof.test/checkout/v1"
		}
		uri, _ := url.Parse(identity)
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: name}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		d, e := x509.CreateCertificate(rand.Reader, cert, root, &k.PublicKey, key)
		if e != nil {
			return e
		}
		kb, e := x509.MarshalECPrivateKey(k)
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(dir, name+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}), 0644); e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600); e != nil {
			return e
		}
	}
	return nil
}

type ServerConfig struct{ Name, Group string }
type Ready struct {
	Address, Identity, Artifact, Config string
	PID                                 int
}
type Request struct{ Connection, Operation string }
type Reply struct {
	Handshake, Group, Peer, Identity, Artifact, Config, Operation string
	Authenticated                                                 bool
	At                                                            int64
}

func group(s string) tls.CurveID {
	if s == "X25519MLKEM768" {
		return tls.X25519MLKEM768
	}
	return tls.X25519
}
func config(pki, name string, groups []tls.CurveID) (*tls.Config, error) {
	cert, e := tls.LoadX509KeyPair(filepath.Join(pki, name+".pem"), filepath.Join(pki, name+".key"))
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(filepath.Join(pki, "ca.pem"))
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("bad CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, ServerName: "localhost", CurvePreferences: groups, SessionTicketsDisabled: true}, nil
}
func serve(args []string) error {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	pki := f.String("pki", "", "test PKI")
	cp := f.String("config", "", "config")
	if e := f.Parse(args); e != nil {
		return e
	}
	data, e := os.ReadFile(*cp)
	if e != nil {
		return e
	}
	var c ServerConfig
	if e = json.Unmarshal(data, &c); e != nil {
		return e
	}
	tc, e := config(*pki, c.Name, []tls.CurveID{group(c.Group)})
	if e != nil {
		return e
	}
	listener, e := tls.Listen("tcp", "127.0.0.1:0", tc)
	if e != nil {
		return e
	}
	defer listener.Close()
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	ready := Ready{listener.Addr().String(), "spiffe://wireproof.test/payment/" + c.Name, fileHash(exe), hash(data), os.Getpid()}
	json.NewEncoder(os.Stdout).Encode(ready)
	for {
		raw, e := listener.Accept()
		if e != nil {
			return e
		}
		go func() {
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(10 * time.Second))
			conn := raw.(*tls.Conn)
			if e := conn.Handshake(); e != nil {
				json.NewEncoder(os.Stderr).Encode(map[string]string{"HandshakeError": e.Error()})
				return
			}
			cs := conn.ConnectionState()
			ekm, e := cs.ExportKeyingMaterial("EXPORTER-WireProof", nil, 32)
			if e != nil {
				return
			}
			peer := ""
			if len(cs.PeerCertificates) > 0 && len(cs.PeerCertificates[0].URIs) > 0 {
				peer = cs.PeerCertificates[0].URIs[0].String()
			}
			dec := json.NewDecoder(conn)
			enc := json.NewEncoder(conn)
			for {
				var req Request
				if e := dec.Decode(&req); e != nil {
					return
				}
				r := Reply{hash(ekm), cs.CurveID.String(), peer, ready.Identity, ready.Artifact, ready.Config, req.Operation, len(cs.VerifiedChains) > 0, time.Now().UnixNano()}
				json.NewEncoder(os.Stderr).Encode(r)
				if e := enc.Encode(r); e != nil {
					return
				}
			}
		}()
	}
}

type Process struct {
	Cmd   *exec.Cmd
	Ready Ready
	Log   *os.File
}

func startServer(exe, pki, dir, name, g string) (*Process, error) {
	cp := filepath.Join(dir, name+"-config.json")
	if e := writeJSON(cp, ServerConfig{name, g}); e != nil {
		return nil, e
	}
	log, e := os.Create(filepath.Join(dir, name+"-server.jsonl"))
	if e != nil {
		return nil, e
	}
	cmd := exec.Command(exe, "serve", "-pki", pki, "-config", cp)
	cmd.Stderr = log
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		log.Close()
		return nil, e
	}
	if e = cmd.Start(); e != nil {
		log.Close()
		return nil, e
	}
	p := &Process{Cmd: cmd, Log: log}
	ch := make(chan error, 1)
	go func() { ch <- json.NewDecoder(pipe).Decode(&p.Ready) }()
	select {
	case e = <-ch:
		if e != nil {
			p.Close()
			return nil, e
		}
	case <-time.After(3 * time.Second):
		p.Close()
		return nil, fmt.Errorf("server startup timeout")
	}
	if p.Ready.Config != fileHash(cp) || p.Ready.Artifact != fileHash(exe) {
		p.Close()
		return nil, fmt.Errorf("launch manifest mismatch")
	}
	return p, nil
}
func (p *Process) Close() {
	if p != nil {
		p.Cmd.Process.Kill()
		p.Cmd.Wait()
		p.Log.Close()
	}
}

type Relay struct {
	Listener net.Listener
	Done     chan struct{}
	mu       sync.Mutex
	peers    []net.Conn
}

func relay(dir, id, target string) (*Relay, error) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	r := &Relay{Listener: ln, Done: make(chan struct{})}
	go func() {
		defer close(r.Done)
		in, e := ln.Accept()
		if e != nil {
			return
		}
		out, e := net.DialTimeout("tcp", target, time.Second)
		if e != nil {
			in.Close()
			return
		}
		r.mu.Lock()
		r.peers = []net.Conn{in, out}
		r.mu.Unlock()
		writeJSON(filepath.Join(dir, id+"-sockets.json"), map[string]string{"Client": in.RemoteAddr().String(), "RelayIn": in.LocalAddr().String(), "RelayOut": out.LocalAddr().String(), "Server": out.RemoteAddr().String()})
		var wg sync.WaitGroup
		copyTo := func(dst, src net.Conn, suffix string) {
			defer wg.Done()
			f, e := os.Create(filepath.Join(dir, id+suffix))
			if e != nil {
				return
			}
			defer f.Close()
			io.Copy(io.MultiWriter(dst, f), src)
			if tcp, ok := dst.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}
		}
		wg.Add(2)
		go copyTo(out, in, "-client.bin")
		go copyTo(in, out, "-server.bin")
		wg.Wait()
		in.Close()
		out.Close()
	}()
	return r, nil
}
func (r *Relay) Close() {
	r.Listener.Close()
	r.mu.Lock()
	for _, c := range r.peers {
		c.Close()
	}
	r.mu.Unlock()
	select {
	case <-r.Done:
	case <-time.After(2 * time.Second):
	}
}

type Session struct {
	Conn  *tls.Conn
	Relay *Relay
	Reply Reply
	ID    string
}

func connect(pki, dir, id string, p *Process, strict bool) (*Session, error) {
	r, e := relay(dir, id, p.Ready.Address)
	if e != nil {
		return nil, e
	}
	groups := []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
	if strict {
		groups = []tls.CurveID{tls.X25519MLKEM768}
	}
	tc, e := config(pki, "checkout", groups)
	if e != nil {
		r.Close()
		return nil, e
	}
	raw, e := net.DialTimeout("tcp", r.Listener.Addr().String(), time.Second)
	if e != nil {
		r.Close()
		return nil, e
	}
	conn := tls.Client(raw, tc)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if e = conn.Handshake(); e != nil {
		conn.Close()
		r.Close()
		return nil, e
	}
	s := &Session{Conn: conn, Relay: r, ID: id}
	if e = s.Ping(); e != nil {
		s.Close()
		return nil, e
	}
	cs := conn.ConnectionState()
	ekm, e := cs.ExportKeyingMaterial("EXPORTER-WireProof", nil, 32)
	if e != nil {
		s.Close()
		return nil, e
	}
	if cs.CurveID.String() != s.Reply.Group || hash(ekm) != s.Reply.Handshake || len(cs.VerifiedChains) == 0 || !s.Reply.Authenticated || s.Reply.Peer != "spiffe://wireproof.test/checkout/v1" || s.Reply.Identity != p.Ready.Identity {
		s.Close()
		return nil, fmt.Errorf("endpoint identity/group mismatch")
	}
	if cs.PeerCertificates[0].URIs[0].String() != p.Ready.Identity {
		s.Close()
		return nil, fmt.Errorf("peer identity mismatch")
	}
	return s, nil
}
func (s *Session) Ping() error {
	if e := json.NewEncoder(s.Conn).Encode(Request{s.ID, "checkout.pay"}); e != nil {
		return e
	}
	// Decoder is per request because the server sends exactly one flushed response.
	return json.NewDecoder(bufio.NewReader(s.Conn)).Decode(&s.Reply)
}
func (s *Session) Close() { s.Conn.Close(); s.Relay.Close() }
