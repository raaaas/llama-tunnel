// llmhub: one public endpoint in front of many tunneled llama-servers.
//
//   - notebooks ask it for a free tunnel port, then register "sr1" + its models
//   - clients (omp, curl, ...) see "sr1/model1" in /v1/models and call it OpenAI-style
//   - every request becomes a JOB that keeps running even if the client drops:
//     the hub sends response headers at once and a keepalive every few seconds
//     (so Cloudflare's ~120s limit never fires) and buffers the output, so a
//     retry of the same request re-attaches instead of starting over.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------- config

type Config struct {
	Listen           string
	ClientKeys       []string
	AdminKey         string
	PortMin, PortMax int
	StateFile        string
	Keepalive        time.Duration // idle time before a keepalive byte is sent
	FirstWait        time.Duration // how long to wait for real upstream headers before committing 200
	JobTTL           time.Duration // how long finished jobs stay in memory
	ReplayWindow     time.Duration // identical request within this window of a finished job gets the stored answer
	OrphanGrace      time.Duration // cancel a job this long after its last client left
	UpstreamTimeout  time.Duration
	MaxBody          int64
	MaxJob           int
}

func envStr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func envInt(k string, d int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return d
}
func envDur(k string, d time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(k)); err == nil {
		return v
	}
	return d
}

func loadConfig() Config {
	var keys []string
	for _, k := range strings.Split(os.Getenv("HUB_API_KEYS"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	return Config{
		Listen:          envStr("HUB_LISTEN", "127.0.0.1:8100"),
		ClientKeys:      keys,
		AdminKey:        os.Getenv("HUB_ADMIN_KEY"),
		PortMin:         envInt("PORT_MIN", 9001),
		PortMax:         envInt("PORT_MAX", 9099),
		StateFile:       envStr("STATE_FILE", "/var/lib/llmhub/state.json"),
		Keepalive:       envDur("KEEPALIVE", 15*time.Second),
		FirstWait:       envDur("FIRST_WAIT", 2*time.Second),
		JobTTL:          envDur("JOB_TTL", 30*time.Minute),
		ReplayWindow:    envDur("REPLAY_WINDOW", 5*time.Minute),
		OrphanGrace:     envDur("ORPHAN_GRACE", 10*time.Minute),
		UpstreamTimeout: envDur("UPSTREAM_TIMEOUT", 3*time.Hour),
		MaxBody:         int64(envInt("MAX_BODY_MB", 64)) << 20,
		MaxJob:          envInt("MAX_JOB_MB", 32) << 20,
	}
}

// ---------------------------------------------------------------- hub state

type Server struct {
	Name     string
	Port     int
	Key      string // llama-server --api-key, injected by the hub, never shown to clients
	Models   []string
	LastSeen time.Time
	Up       bool
	Active   int64
}

func (s *Server) has(m string) bool {
	for _, x := range s.Models {
		if x == m {
			return true
		}
	}
	return false
}

type Hub struct {
	cfg     Config
	mu      sync.Mutex
	servers map[string]*Server
	leases  map[string]int    // server name -> tunnel port (sticky)
	bad     map[int]time.Time // ports to avoid for a while (stale tunnel)
	jobs    map[string]*Job
	byKey   map[string]string // request fingerprint -> job id
	up      *http.Client      // no overall timeout: jobs use contexts
	probeC  *http.Client
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

func newHub(cfg Config) *Hub {
	h := &Hub{
		cfg: cfg, servers: map[string]*Server{}, leases: map[string]int{}, bad: map[int]time.Time{},
		jobs: map[string]*Job{}, byKey: map[string]string{},
		up: &http.Client{Transport: &http.Transport{
			DisableCompression:  true,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     60 * time.Second,
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		}},
		probeC: &http.Client{Timeout: 3 * time.Second},
	}
	if b, err := os.ReadFile(cfg.StateFile); err == nil {
		var st struct {
			Leases map[string]int `json:"leases"`
		}
		if json.Unmarshal(b, &st) == nil && st.Leases != nil {
			h.leases = st.Leases
		}
	}
	return h
}

func (h *Hub) saveLocked() {
	b, _ := json.MarshalIndent(map[string]any{"leases": h.leases}, "", "  ")
	_ = os.MkdirAll(filepath.Dir(h.cfg.StateFile), 0o755)
	tmp := h.cfg.StateFile + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, h.cfg.StateFile)
	}
}

// ---------------------------------------------------------------- auth

func bearer(r *http.Request) string {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return r.Header.Get("x-api-key")
}
func eq(a, b string) bool { return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (h *Hub) isAdmin(r *http.Request) bool { return eq(bearer(r), h.cfg.AdminKey) }
func (h *Hub) clientKey(r *http.Request) (string, bool) {
	k := bearer(r)
	if h.isAdmin(r) {
		return k, true
	}
	for _, c := range h.cfg.ClientKeys {
		if eq(k, c) {
			return k, true
		}
	}
	return "", false
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func apiErr(w http.ResponseWriter, code int, typ, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]any{"message": msg, "type": typ, "code": code}})
}

// ---------------------------------------------------------------- registry endpoints

func (h *Hub) allocate(name string, fresh bool) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if p, ok := h.leases[name]; ok {
		if !fresh {
			return p, nil
		}
		h.bad[p] = now.Add(15 * time.Minute) // old tunnel is probably still half-open
		delete(h.leases, name)
	}
	taken := map[int]bool{}
	for _, p := range h.leases {
		taken[p] = true
	}
	for p := h.cfg.PortMin; p <= h.cfg.PortMax; p++ {
		if taken[p] {
			continue
		}
		if t, ok := h.bad[p]; ok && now.Before(t) {
			continue
		}
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			continue // something else already listens there
		}
		ln.Close()
		h.leases[name] = p
		h.saveLocked()
		return p, nil
	}
	return 0, fmt.Errorf("no free port in %d-%d", h.cfg.PortMin, h.cfg.PortMax)
}

func (h *Hub) handleAllocate(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r) {
		apiErr(w, 401, "auth", "admin key required")
		return
	}
	var in struct {
		Name  string `json:"name"`
		Fresh bool   `json:"fresh"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in) != nil || !nameRe.MatchString(in.Name) {
		apiErr(w, 400, "bad_request", "name must match [A-Za-z0-9_-]{1,32}")
		return
	}
	p, err := h.allocate(in.Name, in.Fresh)
	if err != nil {
		apiErr(w, 503, "no_port", err.Error())
		return
	}
	log.Printf("allocate %s -> %d (fresh=%v)", in.Name, p, in.Fresh)
	writeJSON(w, 200, map[string]any{"name": in.Name, "port": p})
}

func (h *Hub) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r) {
		apiErr(w, 401, "auth", "admin key required")
		return
	}
	var in struct {
		Name   string   `json:"name"`
		Port   int      `json:"port"`
		Key    string   `json:"key"`
		Models []string `json:"models"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in) != nil || !nameRe.MatchString(in.Name) || len(in.Models) == 0 {
		apiErr(w, 400, "bad_request", "need name, port, key, models[]")
		return
	}
	h.mu.Lock()
	if h.leases[in.Name] != in.Port {
		h.mu.Unlock()
		apiErr(w, 409, "port_not_leased", "port is not the one allocated to this name; call /_hub/allocate first")
		return
	}
	s := h.servers[in.Name]
	if s == nil {
		s = &Server{Name: in.Name}
		h.servers[in.Name] = s
	}
	s.Port, s.Key, s.Models, s.LastSeen = in.Port, in.Key, in.Models, time.Now()
	h.mu.Unlock()

	up := h.probe(in.Port, in.Key)
	h.mu.Lock()
	s.Up = up
	h.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "up": up})
}

func (h *Hub) handleRelease(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r) {
		apiErr(w, 401, "auth", "admin key required")
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in)
	h.mu.Lock()
	delete(h.servers, in.Name)
	delete(h.leases, in.Name)
	h.saveLocked()
	h.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (h *Hub) handleServers(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.clientKey(r); !ok {
		apiErr(w, 401, "auth", "invalid api key")
		return
	}
	h.mu.Lock()
	out := []map[string]any{}
	for _, s := range h.servers {
		out = append(out, map[string]any{
			"name": s.Name, "port": s.Port, "models": s.Models, "up": s.Up,
			"active": atomic.LoadInt64(&s.Active), "last_seen": s.LastSeen.Format(time.RFC3339),
		})
	}
	h.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	writeJSON(w, 200, map[string]any{"servers": out})
}

func (h *Hub) handleJobs(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r) {
		apiErr(w, 401, "auth", "admin key required")
		return
	}
	h.mu.Lock()
	out := []map[string]any{}
	for _, j := range h.jobs {
		j.mu.Lock()
		out = append(out, map[string]any{
			"id": j.ID, "model": j.Model, "bytes": len(j.buf), "done": j.done, "failed": j.failed,
			"clients": j.clients, "age_s": int(time.Since(j.created).Seconds()),
		})
		j.mu.Unlock()
	}
	h.mu.Unlock()
	writeJSON(w, 200, map[string]any{"jobs": out})
}

func (h *Hub) handleModels(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.clientKey(r); !ok {
		apiErr(w, 401, "auth", "invalid api key")
		return
	}
	all := r.URL.Query().Get("all") == "1"
	h.mu.Lock()
	names := make([]string, 0, len(h.servers))
	for n := range h.servers {
		names = append(names, n)
	}
	sort.Strings(names)
	data := []map[string]any{}
	for _, n := range names {
		s := h.servers[n]
		if !s.Up && !all {
			continue
		}
		for _, m := range s.Models {
			it := map[string]any{"id": n + "/" + m, "object": "model", "created": s.LastSeen.Unix(), "owned_by": n}
			if all {
				it["status"] = map[bool]string{true: "up", false: "down"}[s.Up]
			}
			data = append(data, it)
		}
	}
	h.mu.Unlock()
	writeJSON(w, 200, map[string]any{"object": "list", "data": data})
}

// ---------------------------------------------------------------- health probing

func (h *Hub) probe(port int, key string) bool {
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/health", port), nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := h.probeC.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode == 200
}

func (h *Hub) probeLoop() {
	for range time.Tick(10 * time.Second) {
		h.mu.Lock()
		list := make([]*Server, 0, len(h.servers))
		for _, s := range h.servers {
			list = append(list, s)
		}
		h.mu.Unlock()
		for _, s := range list {
			h.mu.Lock()
			port, key := s.Port, s.Key
			h.mu.Unlock()
			up := h.probe(port, key)
			h.mu.Lock()
			if up != s.Up {
				log.Printf("server %s up=%v", s.Name, up)
			}
			s.Up = up
			if !up && time.Since(s.LastSeen) > 30*time.Minute {
				delete(h.servers, s.Name) // keep the port lease, drop the listing
			}
			h.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------- jobs

type Job struct {
	ID, Key, Owner, Model, Server string
	stream                        bool
	created                       time.Time
	cancel                        context.CancelFunc

	mu       sync.Mutex
	ch       chan struct{} // closed + replaced on every change
	hdrCh    chan struct{} // closed once upstream headers are known
	status   int
	header   http.Header
	buf      []byte
	done     bool
	failed   bool
	finished time.Time
	clients  int
	orphan   *time.Timer
}

func newJob(key, owner, model, server string, stream bool, cancel context.CancelFunc) *Job {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return &Job{ID: hex.EncodeToString(b), Key: key, Owner: owner, Model: model, Server: server, stream: stream,
		created: time.Now(), cancel: cancel, ch: make(chan struct{}), hdrCh: make(chan struct{})}
}

func (j *Job) notify() { close(j.ch); j.ch = make(chan struct{}) } // caller holds mu

func (j *Job) setHeader(status int, h http.Header) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.status == 0 {
		j.status, j.header = status, h.Clone()
		close(j.hdrCh)
	}
	j.notify()
}
func (j *Job) headers() (int, http.Header, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.status, j.header, j.status != 0
}
func (j *Job) appendBytes(p []byte, max int) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.buf)+len(p) > max {
		return false
	}
	j.buf = append(j.buf, p...)
	j.notify()
	return true
}
func (j *Job) finish() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.done {
		j.done, j.finished = true, time.Now()
		j.notify()
	}
}
func (j *Job) fail(msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.done {
		return
	}
	j.failed = true
	errJSON, _ := json.Marshal(map[string]any{"error": map[string]any{"message": msg, "type": "upstream_error"}})
	if j.status == 0 {
		if j.stream {
			j.status, j.header = 200, http.Header{"Content-Type": {"text/event-stream"}}
		} else {
			j.status, j.header = 502, http.Header{"Content-Type": {"application/json"}}
		}
		close(j.hdrCh)
	}
	if j.stream {
		j.buf = append(j.buf, []byte("data: "+string(errJSON)+"\n\ndata: [DONE]\n\n")...)
	} else if len(j.buf) == 0 {
		j.buf = errJSON
	}
	j.done, j.finished = true, time.Now()
	j.notify()
}
func (j *Job) read(off int) (data []byte, done bool, ch chan struct{}) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if off < len(j.buf) {
		data = j.buf[off:len(j.buf):len(j.buf)] // bytes already in buf are never modified
	}
	return data, j.done, j.ch
}
func (j *Job) reusable(replay time.Duration) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return false
	}
	return !j.done || time.Since(j.finished) < replay
}
func (j *Job) attach() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.clients++
	if j.orphan != nil {
		j.orphan.Stop()
		j.orphan = nil
	}
}
func (j *Job) detach(grace time.Duration) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.clients--
	if j.clients == 0 && !j.done {
		j.orphan = time.AfterFunc(grace, j.cancel) // nobody came back: stop burning the GPU
	}
}

func (h *Hub) runUpstream(ctx context.Context, j *Job, s *Server, path string, body []byte) {
	atomic.AddInt64(&s.Active, 1)
	defer atomic.AddInt64(&s.Active, -1)
	defer j.cancel()
	t0 := time.Now()

	req, _ := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("http://127.0.0.1:%d%s", s.Port, path), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.Key)
	resp, err := h.up.Do(req)
	if err != nil {
		j.fail("upstream: " + err.Error())
		log.Printf("job %s %s failed: %v", j.ID, j.Model, err)
		return
	}
	defer resp.Body.Close()
	j.setHeader(resp.StatusCode, resp.Header)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 && !j.appendBytes(buf[:n], h.cfg.MaxJob) {
			j.fail("response larger than MAX_JOB_MB")
			return
		}
		if err == io.EOF {
			j.finish()
			j.mu.Lock()
			size := len(j.buf)
			j.mu.Unlock()
			log.Printf("job %s %s done: %d bytes in %s", j.ID, j.Model, size, time.Since(t0).Round(time.Second))
			return
		}
		if err != nil {
			j.fail("upstream read: " + err.Error())
			log.Printf("job %s %s read error: %v", j.ID, j.Model, err)
			return
		}
	}
}

func (h *Hub) gcLoop() {
	for range time.Tick(30 * time.Second) {
		h.mu.Lock()
		for id, j := range h.jobs {
			j.mu.Lock()
			old := j.done && time.Since(j.finished) > h.cfg.JobTTL
			j.mu.Unlock()
			if old {
				delete(h.jobs, id)
				if h.byKey[j.Key] == id {
					delete(h.byKey, j.Key)
				}
			}
		}
		h.mu.Unlock()
	}
}

// ---------------------------------------------------------------- routing

func (h *Hub) available() []string { // caller holds mu
	var ids []string
	for n, s := range h.servers {
		if s.Up {
			for _, m := range s.Models {
				ids = append(ids, n+"/"+m)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func (h *Hub) resolve(id string) (*Server, string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if i := strings.Index(id, "/"); i > 0 {
		if s, ok := h.servers[id[:i]]; ok {
			m := id[i+1:]
			if s.Up && s.has(m) {
				return s, m, nil
			}
			return nil, "", fmt.Errorf("server %q is offline or has no model %q. available: %s", s.Name, m, strings.Join(h.available(), ", "))
		}
	}
	var cands []*Server
	for _, s := range h.servers {
		if !s.Up {
			continue
		}
		if id == "" || s.has(id) {
			cands = append(cands, s)
		}
	}
	if id == "" && len(h.available()) != 1 {
		return nil, "", fmt.Errorf("no model given. available: %s", strings.Join(h.available(), ", "))
	}
	if len(cands) == 0 {
		return nil, "", fmt.Errorf("model %q not found. available: %s", id, strings.Join(h.available(), ", "))
	}
	// same model on several notebooks: least busy first
	sort.Slice(cands, func(a, b int) bool {
		x, y := atomic.LoadInt64(&cands[a].Active), atomic.LoadInt64(&cands[b].Active)
		if x != y {
			return x < y
		}
		return cands[a].Name < cands[b].Name
	})
	s := cands[0]
	if id == "" {
		return s, s.Models[0], nil
	}
	return s, id, nil
}

func (h *Hub) handleProxy(w http.ResponseWriter, r *http.Request) {
	apiKey, ok := h.clientKey(r)
	if !ok {
		apiErr(w, 401, "auth", "invalid api key")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/jobs") {
		apiErr(w, 404, "not_found", "unknown path")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.cfg.MaxBody))
	if err != nil {
		apiErr(w, 413, "too_large", err.Error())
		return
	}
	var req map[string]json.RawMessage
	if json.Unmarshal(body, &req) != nil {
		apiErr(w, 400, "bad_request", "body must be a JSON object")
		return
	}
	var model string
	_ = json.Unmarshal(req["model"], &model)
	var stream bool
	_ = json.Unmarshal(req["stream"], &stream)

	srv, real, err := h.resolve(model)
	if err != nil {
		apiErr(w, 404, "model_not_found", err.Error())
		return
	}
	mb, _ := json.Marshal(real)
	req["model"] = mb
	upBody, _ := json.Marshal(req)

	fp := sha256.New()
	fp.Write([]byte(apiKey + "\x00" + r.URL.Path + "\x00"))
	if idem := r.Header.Get("Idempotency-Key"); idem != "" {
		fp.Write([]byte(idem))
	} else {
		fp.Write(body)
	}
	key := hex.EncodeToString(fp.Sum(nil))
	owner := hex.EncodeToString(sha256.New().Sum([]byte(apiKey)))

	var job *Job
	var ctx context.Context
	h.mu.Lock()
	if id, ok := h.byKey[key]; ok && r.Header.Get("X-No-Cache") == "" {
		if c := h.jobs[id]; c != nil && c.reusable(h.cfg.ReplayWindow) {
			job = c
		}
	}
	created := false
	if job == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), h.cfg.UpstreamTimeout)
		job = newJob(key, owner, srv.Name+"/"+real, srv.Name, stream, cancel)
		h.jobs[job.ID], h.byKey[key] = job, job.ID
		created = true
	}
	h.mu.Unlock()

	if created {
		log.Printf("job %s -> %s/%s (stream=%v, %d bytes in)", job.ID, srv.Name, real, stream, len(body))
		go h.runUpstream(ctx, job, srv, r.URL.Path, upBody)
	} else {
		log.Printf("job %s re-attached by a retry", job.ID)
	}
	h.serveJob(w, r, job, 0)
}

func (h *Hub) handleJobResume(w http.ResponseWriter, r *http.Request) {
	apiKey, ok := h.clientKey(r)
	if !ok {
		apiErr(w, 401, "auth", "invalid api key")
		return
	}
	h.mu.Lock()
	j := h.jobs[r.PathValue("id")]
	h.mu.Unlock()
	if j == nil || j.Owner != hex.EncodeToString(sha256.New().Sum([]byte(apiKey))) {
		apiErr(w, 404, "not_found", "no such job (expired, or not yours)")
		return
	}
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	h.serveJob(w, r, j, off)
}

// ---------------------------------------------------------------- streaming to the client

func atBoundary(tail []byte) bool {
	return len(tail) == 0 || bytes.HasSuffix(tail, []byte("\n\n")) || bytes.HasSuffix(tail, []byte("\r\n\r\n"))
}

func (h *Hub) serveJob(w http.ResponseWriter, r *http.Request, j *Job, off int) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	j.attach()
	defer j.detach(h.cfg.OrphanGrace)
	ctx := r.Context()

	// give the upstream a moment to answer with real headers (fast errors keep their status code)
	wait := time.NewTimer(h.cfg.FirstWait)
	select {
	case <-j.hdrCh:
	case <-wait.C:
	case <-ctx.Done():
		wait.Stop()
		return
	}
	wait.Stop()

	w.Header().Set("X-Hub-Job", j.ID)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	status, hdr, known := j.headers()
	synth := !known // we commit 200 before the upstream said anything: that is what defeats the 120s limit
	switch {
	case known:
		ct := hdr.Get("Content-Type")
		if ct == "" {
			ct = "application/json"
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(status)
	case j.stream:
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
	}
	_ = rc.Flush()

	last := time.Now()
	var tail []byte
	write := func(p []byte) bool {
		if _, err := w.Write(p); err != nil {
			return false
		}
		_ = rc.Flush()
		last = time.Now()
		tail = append(tail, p...)
		if len(tail) > 4 {
			tail = tail[len(tail)-4:]
		}
		return true
	}

	tick := time.NewTicker(h.cfg.Keepalive / 2)
	defer tick.Stop()
	for {
		data, done, ch := j.read(off)
		errMode := false
		if synth && j.stream {
			if st, _, k := j.headers(); k && st >= 400 {
				errMode = true // upstream failed after we already said 200: turn its JSON error into an SSE error event
			}
		}
		if errMode {
			if done {
				all, _, _ := j.read(0)
				var c bytes.Buffer
				if json.Compact(&c, all) != nil {
					c.Reset()
					c.WriteString(`{"error":{"message":"upstream error"}}`)
				}
				write([]byte("data: " + c.String() + "\n\ndata: [DONE]\n\n"))
				return
			}
			data = nil
		}
		if len(data) > 0 {
			if !write(data) {
				return
			}
			off += len(data)
			continue
		}
		if done {
			return
		}
		select {
		case <-ch:
		case <-tick.C:
			if time.Since(last) < h.cfg.Keepalive {
				continue
			}
			if j.stream && atBoundary(tail) {
				if !write([]byte(": keepalive\n\n")) {
					return
				}
			} else if !j.stream && synth {
				if !write([]byte(" ")) { // leading whitespace is valid JSON
					return
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// ---------------------------------------------------------------- main

func main() {
	cfg := loadConfig()
	if cfg.AdminKey == "" || len(cfg.ClientKeys) == 0 {
		log.Fatal("set HUB_ADMIN_KEY (notebooks) and HUB_API_KEYS (clients, comma separated)")
	}
	h := newHub(cfg)
	go h.probeLoop()
	go h.gcLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /v1/models", h.handleModels)
	mux.HandleFunc("GET /v1/jobs/{id}", h.handleJobResume)
	mux.HandleFunc("POST /v1/", h.handleProxy)
	mux.HandleFunc("POST /_hub/allocate", h.handleAllocate)
	mux.HandleFunc("POST /_hub/register", h.handleRegister)
	mux.HandleFunc("POST /_hub/release", h.handleRelease)
	mux.HandleFunc("GET /_hub/servers", h.handleServers)
	mux.HandleFunc("GET /_hub/jobs", h.handleJobs)

	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("llmhub on %s | tunnel ports %d-%d | keepalive %s", cfg.Listen, cfg.PortMin, cfg.PortMax, cfg.Keepalive)
	log.Fatal(srv.ListenAndServe())
}
