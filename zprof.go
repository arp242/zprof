// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package zprof serves runtime profiling data.
package zprof

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"zgo.at/zprof/internal/profile"
)

type entry struct {
	Name, Desc   string
	Count        int
	SupportDelta bool
	Disabled     bool
}

var info = map[string]entry{
	"allocs": {
		Name:         "allocs",
		Desc:         "Sampling of past memory allocations.",
		SupportDelta: true,
	},
	"block": {
		Name:         "block",
		Desc:         "Stack traces that led to blocking on synchronization primitives.",
		SupportDelta: true,
	},
	"goroutine": {
		Name:         "goroutine",
		Desc:         "Stack traces of all current goroutines.",
		SupportDelta: true,
	},
	"heap": {
		Name:         "heap",
		Desc:         "Sampling of memory allocations of live objects.",
		SupportDelta: true,
	},
	"mutex": {
		Name:         "mutex",
		Desc:         "Stack traces of holders of contended mutexes.",
		SupportDelta: true,
	},
	"profile": {
		Name:  "profile",
		Count: -1,
		Desc:  "CPU profile.",
	},
	"threadcreate": {
		Name:         "threadcreate",
		Desc:         "Stack traces that led to the creation of new OS threads.",
		SupportDelta: true,
	},
	"trace": {
		Name:  "trace",
		Count: -1,
		Desc:  "A trace of execution of the current program.",
	},
}

// BlockRate remembers the current block profile rate.
//
// There is no way to query the block profile rate; so keep track of it here. If
// you  call SetBlockProfileRate() in your program then you may want to set this
// value as well to ensure the UI is displayed correct.
//
// Use atomic.StoreInt64() and atomic.LoadInt64() to set and get the value.
var BlockRate *int64 = func() *int64 {
	var z int64
	return &z
}()

type Handler struct {
	prefix       string
	user, passwd []byte
	https        bool
}

type HandlerOpt func(*Handler)

var (
	// Prefix sets the prefix to the path you serve the profiles on, for example
	// "/profile".
	Prefix = func(prefix string) HandlerOpt {
		return func(h *Handler) { h.prefix = strings.TrimRight(prefix, "/") }
	}

	// Auth adds HTTP Basic auth.
	Auth = func(user, passwd string) HandlerOpt {
		return func(h *Handler) { h.user, h.passwd = []byte(user), []byte(passwd) }
	}

	// HTTPS enforces using https:// links; this can't always be reliably
	// detected.
	HTTPS = func(https bool) HandlerOpt {
		return func(h *Handler) { h.https = https }
	}
)

// NewHandler creates a new Handler instance.
func NewHandler(opts ...HandlerOpt) Handler {
	h := Handler{}
	for _, o := range opts {
		o(&h)
	}
	return h
}

// Profile starts a new HTTP server on addr to profile this application.
//
// Errors are considered non-fatal, but will be printed to stderr.
// "localhost:6060" will be used if addr is an empty string.
//
// The auth can be used to set up HTTP Basic auth; the format is as
// "user:password". No auth is added if this is an empty string.
func Profile(addr string, opts ...HandlerOpt) {
	if addr == "" {
		addr = "localhost:6060"
	}
	fmt.Fprintln(os.Stderr, "zprof: listening on", addr)
	go func() {
		err := http.ListenAndServe(addr, NewHandler(opts...))
		if err != nil {
			fmt.Fprintln(os.Stderr, "zprof:", err.Error())
		}
	}()
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(h.user) > 0 || len(h.passwd) > 0 {
		w.Header().Set("WWW-Authenticate", `Basic realm="Profiling information", charset="UTF-8"`)
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), h.user) != 1 || subtle.ConstantTimeCompare([]byte(p), h.passwd) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	var (
		name = strings.Trim(strings.TrimPrefix(r.URL.Path, h.prefix), "/")
		err  = withCode(404, errors.New("not found"))
	)
	if r.FormValue("page") != "" {
		name = r.FormValue("page")
	}
	switch r.Method {
	case http.MethodPost:
		switch name {
		case "setrate":
			err = h.SetProfileRates(w, r)
		}
	case http.MethodGet:
		switch name {
		case "":
			err = h.Index(w, r)
		case "profile":
			err = h.Profile(w, r)
		case "symbol":
			err = h.Symbol(w, r)
		case "trace":
			err = h.Trace(w, r)
		case "favicon.ico":
			w.WriteHeader(200)
			err = nil
		default:
			err = h.PProf(name)(w, r)
		}
	}

	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Go-Pprof", "1")
		w.Header().Del("Content-Disposition")

		var codeErr interface {
			Code() int
			Error() string
		}
		code := 500
		if errors.As(err, &codeErr) {
			code = codeErr.Code()
		}

		w.WriteHeader(code)
		fmt.Fprintf(w, err.Error()+"\n")
	}
}

var (
	//go:embed index.gohtml
	index    string
	indexTpl = template.Must(template.New("").Option("missingkey=error").Parse(index))
)

// Index serves an overview of all profiles and metrics.
func (h Handler) Index(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store,no-cache")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	disable := map[string]bool{
		"block": atomic.LoadInt64(BlockRate) == 0,
		"mutex": runtime.SetMutexProfileFraction(-1) == 0,
	}
	profiles := []entry{info["profile"], info["trace"]}
	for _, p := range pprof.Profiles() {
		pp := info[p.Name()]
		pp.Count = p.Count()
		pp.Disabled = disable[p.Name()]
		profiles = append(profiles, pp)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })

	proto := "http://"
	if r.TLS != nil || h.https {
		proto = "https://"
	}
	report := r.Form.Get("report")
	if report == "" {
		report = ReportSVG
	}
	return indexTpl.Execute(w, map[string]interface{}{
		"prefix":    h.prefix,
		"addr":      proto + path.Join(r.Host, r.URL.String()),
		"profiles":  profiles,
		"metrics":   getMetrics(),
		"mutexRate": runtime.SetMutexProfileFraction(-1),
		"blockRate": atomic.LoadInt64(BlockRate),
		"hasGo":     hasGo(),
		"report":    report,
		"seconds":   r.Form.Get("seconds"),
	})
}

var nRepl = strings.NewReplacer("_", "", ",", "")

// SetProfileRates sets the block and mutex profile rates.
func (h Handler) SetProfileRates(w http.ResponseWriter, r *http.Request) error {
	var (
		b, m int
		err  error
	)
	if v := r.FormValue("block"); v != "" {
		b, err = strconv.Atoi(nRepl.Replace(v))
		if err != nil {
			return err
		}
	}
	if v := r.FormValue("mutex"); v != "" {
		m, err = strconv.Atoi(nRepl.Replace(v))
		if err != nil {
			return err
		}
	}

	atomic.StoreInt64(BlockRate, int64(b))
	runtime.SetBlockProfileRate(b)
	runtime.SetMutexProfileFraction(m)

	w.Header().Set("Location", h.prefix)
	w.WriteHeader(303)
	return nil
}

// Profile creates a pprof formatted CPU profile.
//
// Profiling lasts for duration specified in seconds GET parameter, or for 30
// seconds if not specified.
func (h Handler) Profile(w http.ResponseWriter, r *http.Request) error {
	sec, err := getSeconds(r, true)
	if err != nil {
		return err
	}

	// StartCPUProfile will start writing, so set Content-Type here.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="profile"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	err = pprof.StartCPUProfile(w)
	if err != nil {
		return fmt.Errorf("could not enable CPU profiling: %w", err)
	}

	sleep(r, sec)
	pprof.StopCPUProfile()
	return nil
}

// Symbol looks up the program counters listed in the request, responding with a
// table mapping program counters to function names.
func (h Handler) Symbol(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// We have to read the whole POST body before writing any output. Buffer the
	// output here.
	var buf bytes.Buffer

	// We don't know how many symbols we have, but we do have symbol
	// information. pprof only cares whether this number is 0 (no symbols
	// available) or > 0.
	fmt.Fprintf(&buf, "num_symbols: 1\n")

	var b *bufio.Reader
	if r.Method == "POST" {
		b = bufio.NewReader(r.Body)
	} else {
		b = bufio.NewReader(strings.NewReader(r.URL.RawQuery))
	}

	for {
		word, err := b.ReadSlice('+')
		if err == nil {
			word = word[0 : len(word)-1] // trim +
		}
		pc, _ := strconv.ParseUint(string(word), 0, 64)
		if pc != 0 {
			f := runtime.FuncForPC(uintptr(pc))
			if f != nil {
				fmt.Fprintf(&buf, "%#x %s\n", pc, f.Name())
			}
		}

		// Wait until here to check for err; the last symbol will have an err
		// because it doesn't end in +.
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(&buf, "reading request: %v\n", err)
			}
			break
		}
	}

	w.Write(buf.Bytes())
	return nil
}

// Trace shows the execution trace in binary form.
//
// Tracing lasts for duration specified in seconds GET parameter, or for 1
// second if not specified.
func (h Handler) Trace(w http.ResponseWriter, r *http.Request) error {
	sec, err := getSeconds(r, true)
	if err != nil {
		return err
	}

	// trace.Start will start writing, so set Content-Type here.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="trace"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	err = trace.Start(w)
	if err != nil {
		return fmt.Errorf("could not enable tracing: %w", err)
	}

	sleep(r, sec)
	trace.Stop()
	return nil
}

// PProf serves pprof profiles based on the name.
//
// Available profiles: goroutine, threadcreate, heap, allocs, block, mutex
func (h Handler) PProf(name string) func(w http.ResponseWriter, r *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		p := pprof.Lookup(name)
		if p == nil {
			return withCode(404, fmt.Errorf("unknown profile: %s", name))
		}

		if name == "heap" && r.FormValue("gc") != "" {
			runtime.GC()
		}

		sec, err := getSeconds(r, false)
		if err != nil {
			return err
		}
		if sec > 0 {
			return h.deltaProfile(w, r, sec, p)
		}

		return h.serveProfile(w, r, p, nil)
	}
}

func (h Handler) deltaProfile(w http.ResponseWriter, r *http.Request, sec time.Duration, p *pprof.Profile) error {
	if !info[p.Name()].SupportDelta {
		return fmt.Errorf(`seconds: not supported for the profile %s`, p.Name())
	}

	p0, err := collectProfile(p)
	if err != nil {
		return fmt.Errorf("failed to collect profile: %w", err)
	}

	t := time.NewTimer(sec)
	defer t.Stop()

	select {
	case <-t.C:
	case <-r.Context().Done():
		err := r.Context().Err()
		if err == context.DeadlineExceeded {
			return withCode(http.StatusRequestTimeout, err)
		}
		return err
	}

	p1, err := collectProfile(p)
	if err != nil {
		return fmt.Errorf("failed to collect profile: %w", err)
	}
	ts := p1.TimeNanos
	dur := p1.TimeNanos - p0.TimeNanos

	p0.Scale(-1)

	p1, err = profile.Merge([]*profile.Profile{p0, p1})
	if err != nil {
		return fmt.Errorf("failed to compute delta: %w", err)
	}

	p1.TimeNanos = ts // set since we don't know what profile.Merge set for TimeNanos.
	p1.DurationNanos = dur

	return h.serveProfile(w, r, p, p1)
}

func (h Handler) serveProfile(w http.ResponseWriter, r *http.Request, p *pprof.Profile, delta *profile.Profile) error {
	report := r.FormValue("report")
	switch report {
	default:
		return withCode(400, fmt.Errorf("unknown profile report: %q", report))
	case ReportBinary, "":
		w.Header().Set("Content-Type", "application/octet-stream")
		n := p.Name()
		if delta != nil {
			n += "-delta"
		}
		w.Header().Set("Content-Disposition", `attachment; filename="`+n+`"`)

		if delta != nil {
			return delta.Write(w)
		}
		return p.WriteTo(w, 0)
	case ReportDebug:
		if delta != nil {
			return errors.New("Debug is not supported with delta profiles")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		d := 1
		if v := r.FormValue("debug"); v != "" {
			d, _ = strconv.Atoi(v)
		}
		return p.WriteTo(w, d)
	case ReportSVG, ReportTop, ReportTraces:
		ct := "text/plain; charset=utf-8"
		if report == ReportSVG {
			ct = "image/svg+xml; charset=utf-8"
		}

		prof, err := readProfile(report, p, delta)
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", ct)
		w.Write(prof)
		return nil
	}
}

func getSeconds(r *http.Request, must bool) (time.Duration, error) {
	s, err := strconv.ParseInt(r.FormValue("seconds"), 10, 32)
	if err != nil {
		return 0, withCode(400, fmt.Errorf("seconds: %w", err))
	}
	if must && s == 0 {
		return 0, withCode(400, errors.New("seconds: must be set"))
	}

	sec := time.Duration(s) * time.Second

	srv, ok := r.Context().Value(http.ServerContextKey).(*http.Server)
	if ok && srv.WriteTimeout > 0 && sec >= srv.WriteTimeout {
		return 0, withCode(400, fmt.Errorf("profile duration of %s exceeds server's WriteTimeout of %s",
			sec, srv.WriteTimeout))
	}

	return sec, nil
}

func collectProfile(p *pprof.Profile) (*profile.Profile, error) {
	var buf bytes.Buffer
	err := p.WriteTo(&buf, 0)
	if err != nil {
		return nil, err
	}

	ts := time.Now().UnixNano()
	p0, err := profile.Parse(&buf)
	if err != nil {
		return nil, err
	}

	p0.TimeNanos = ts
	return p0, nil
}

func hasGo() bool {
	_, err := exec.LookPath("go")
	return err == nil
}

const (
	ReportBinary = "bin"
	ReportDebug  = "dbg"
	ReportDebug2 = "dbg2"
	ReportTop    = "top"
	ReportTraces = "traces"
	ReportSVG    = "svg"
)

// It's not so easy to call this from Go code as it requires copying quite a few
// internal/* bits from Go to support disassembly.
//
// So just run "go tool pprof"; not perfect as it requires access to the "go"
// binary (which you may not have on your server), but getting around that would
// be rather time-consuming for a small benefit.
//
// TODO: allow passing "-cum"
// TODO: allow passing -sample_index
// TODO: allow filtering.
func readProfile(report string, p *pprof.Profile, delta *profile.Profile) ([]byte, error) {
	bin := os.Args[0]
	if !filepath.IsAbs(bin) {
		var err error
		bin, err = exec.LookPath(bin)
		if err != nil {
			return nil, err
		}
	}

	tmp, err := ioutil.TempFile("", "zprof-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	if delta != nil {
		delta.Write(tmp)
	} else {
		err = p.WriteTo(tmp, 0)
	}
	if err != nil {
		return nil, err
	}
	err = tmp.Close()
	if err != nil {
		return nil, err
	}

	return exec.Command("go", "tool", "pprof", "-"+report, bin, tmp.Name()).CombinedOutput()
}

type metric struct {
	Name, Desc, Unit string
	Cum              bool
	Value            interface{}
}

func getMetrics() []metric {
	descs := metrics.All()
	samples := make([]metrics.Sample, len(descs))
	for i := range samples {
		samples[i].Name = descs[i].Name
	}
	metrics.Read(samples)

	r := make([]metric, 0, len(samples))
	for i, s := range samples {
		sp := strings.SplitN(s.Name, ":", 2)
		n, unit := sp[0], sp[1]
		m := metric{Name: n, Unit: unit, Desc: descs[i].Description, Cum: descs[i].Cumulative}

		switch s.Value.Kind() {
		case metrics.KindUint64:
			v := s.Value.Uint64()
			m.Value = v
			if unit == "bytes" {
				m.Value = fmtByte(v)
			}
		case metrics.KindFloat64:
			m.Value = s.Value.Float64()
		case metrics.KindFloat64Histogram:
			v := medianBucket(s.Value.Float64Histogram())
			m.Value = v
			if unit == "seconds" {
				m.Value = time.Duration(v * 100000)
			}

		default: // This may happen as new metrics get added.
			m.Value = fmt.Sprintf("unexpected metric Kind: %T", s.Value.Kind())
		}
		r = append(r, m)
	}
	return r
}

func medianBucket(h *metrics.Float64Histogram) float64 {
	total := uint64(0)
	for _, count := range h.Counts {
		total += count
	}
	thresh := total / 2
	total = 0
	for i, count := range h.Counts {
		total += count
		if total >= thresh {
			return h.Buckets[i]
		}
	}
	panic("should not happen")
}

func sleep(r *http.Request, d time.Duration) {
	select {
	case <-time.After(d):
	case <-r.Context().Done():
	}
}

var units = []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}

func fmtByte(b uint64) string {
	f := float64(b)
	i := 0
	for ; i < len(units); i++ {
		if f < 1024 {
			return fmt.Sprintf("%.1f%s", f, units[i])
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1f%s", f*1024, units[i-1])
}

type codeErr struct {
	code int
	err  error
}

func (e *codeErr) Code() int             { return e.code }
func (e *codeErr) Unwrap() error         { return e.err }
func (e *codeErr) Error() string         { return strconv.Itoa(e.code) + ": " + e.err.Error() }
func withCode(code int, err error) error { return &codeErr{code: code, err: err} }
