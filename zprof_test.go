// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zprof

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"zgo.at/zprof/internal/profile"
)

func TestHandlers(t *testing.T) {
	tests := []struct {
		path               string
		statusCode         int
		contentType        string
		contentDisposition string
		resp               []byte
	}{
		{"/<script>scripty<script>", http.StatusNotFound, "text/plain; charset=utf-8", "", []byte("404: unknown profile: <script>scripty<script>\n")},
		{"/heap", http.StatusOK, "application/octet-stream", `attachment; filename="heap"`, nil},
		{"/heap?report=dbg", http.StatusOK, "text/plain; charset=utf-8", "", nil},
		{"/profile?seconds=1", http.StatusOK, "application/octet-stream", `attachment; filename="profile"`, nil},
		{"/symbol", http.StatusOK, "text/plain; charset=utf-8", "", nil},
		{"/trace?seconds=1", http.StatusOK, "application/octet-stream", `attachment; filename="trace"`, nil},
		{"/mutex", http.StatusOK, "application/octet-stream", `attachment; filename="mutex"`, nil},
		{"/block?seconds=1", http.StatusOK, "application/octet-stream", `attachment; filename="block-delta"`, nil},
		{"/goroutine?seconds=1", http.StatusOK, "application/octet-stream", `attachment; filename="goroutine-delta"`, nil},
		{"/", http.StatusOK, "text/html; charset=utf-8", "", []byte("Types of profiles available:")},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://example.com"+tt.path, nil)
			w := httptest.NewRecorder()
			NewHandler().ServeHTTP(w, r)

			resp := w.Result()
			if got, want := resp.StatusCode, tt.statusCode; got != want {
				t.Errorf("status code: got %d; want %d", got, want)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("when reading response body, expected non-nil err; got %v", err)
			}
			if got, want := resp.Header.Get("X-Content-Type-Options"), "nosniff"; got != want {
				t.Errorf("X-Content-Type-Options: got %q; want %q", got, want)
			}
			if got, want := resp.Header.Get("Content-Type"), tt.contentType; got != want {
				t.Errorf("Content-Type: got %q; want %q", got, want)
			}
			if got, want := resp.Header.Get("Content-Disposition"), tt.contentDisposition; got != want {
				t.Errorf("Content-Disposition: got %q; want %q", got, want)
			}

			if resp.StatusCode == http.StatusOK {
				return
			}
			if got, want := resp.Header.Get("X-Go-Pprof"), "1"; got != want {
				t.Errorf("X-Go-Pprof: got %q; want %q", got, want)
			}
			if !bytes.Equal(body, tt.resp) {
				t.Errorf("response: got %q; want %q", body, tt.resp)
			}
		})
	}
}

var Sink uint32

func mutexHog1(mu1, mu2 *sync.Mutex, start time.Time, dt time.Duration) {
	atomic.AddUint32(&Sink, 1)
	for time.Since(start) < dt {
		// When using gccgo the loop of mutex operations is
		// not preemptible. This can cause the loop to block a GC,
		// causing the time limits in TestDeltaContentionz to fail.
		// Since this loop is not very realistic, when using
		// gccgo add preemption points 100 times a second.
		t1 := time.Now()
		for time.Since(start) < dt && time.Since(t1) < 10*time.Millisecond {
			mu1.Lock()
			mu2.Lock()
			mu1.Unlock()
			mu2.Unlock()
		}
		if runtime.Compiler == "gccgo" {
			runtime.Gosched()
		}
	}
}

// mutexHog2 is almost identical to mutexHog but we keep them separate
// in order to distinguish them with function names in the stack trace.
// We make them slightly different, using Sink, because otherwise
// gccgo -c opt will merge them.
func mutexHog2(mu1, mu2 *sync.Mutex, start time.Time, dt time.Duration) {
	atomic.AddUint32(&Sink, 2)
	for time.Since(start) < dt {
		// See comment in mutexHog.
		t1 := time.Now()
		for time.Since(start) < dt && time.Since(t1) < 10*time.Millisecond {
			mu1.Lock()
			mu2.Lock()
			mu1.Unlock()
			mu2.Unlock()
		}
		if runtime.Compiler == "gccgo" {
			runtime.Gosched()
		}
	}
}

// mutexHog starts multiple goroutines that runs the given hogger function for the specified duration.
// The hogger function will be given two mutexes to lock & unlock.
func mutexHog(duration time.Duration, hogger func(mu1, mu2 *sync.Mutex, start time.Time, dt time.Duration)) {
	start := time.Now()
	mu1 := new(sync.Mutex)
	mu2 := new(sync.Mutex)
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			hogger(mu1, mu2, start, duration)
		}()
	}
	wg.Wait()
}

func TestDeltaProfile(t *testing.T) {
	rate := runtime.SetMutexProfileFraction(1)
	defer func() {
		runtime.SetMutexProfileFraction(rate)
	}()

	// mutexHog1 will appear in non-delta mutex profile if the mutex profile
	// works.
	mutexHog(20*time.Millisecond, mutexHog1)

	// If mutexHog1 does not appear in the mutex profile, skip this test. Mutex
	// profile is likely not working, so is the delta profile.
	p, err := query("/mutex")
	if err != nil {
		t.Skipf("mutex profile is unsupported: %v", err)
	}

	if !seen(p, "mutexHog1") {
		t.Skipf("mutex profile is not working: %v", p)
	}

	// causes mutexHog2 call stacks to appear in the mutex profile.
	done := make(chan bool)
	go func() {
		for {
			mutexHog(20*time.Millisecond, mutexHog2)
			select {
			case <-done:
				done <- true
				return
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	defer func() { // cleanup the above goroutine.
		done <- true
		<-done // wait for the goroutine to exit.
	}()

	for _, d := range []int{1, 4, 16, 32} {
		endpoint := fmt.Sprintf("/mutex?seconds=%d", d)
		p, err := query(endpoint)
		if err != nil {
			t.Fatalf("failed to query %q: %v", endpoint, err)
		}
		if !seen(p, "mutexHog1") && seen(p, "mutexHog2") && p.DurationNanos > 0 {
			break // pass
		}
		if d == 32 {
			t.Errorf("want mutexHog2 but no mutexHog1 in the profile, and non-zero p.DurationNanos, got %v", p)
		}
	}
	p, err = query("/mutex")
	if err != nil {
		t.Fatalf("failed to query mutex profile: %v", err)
	}
	if !seen(p, "mutexHog1") || !seen(p, "mutexHog2") {
		t.Errorf("want both mutexHog1 and mutexHog2 in the profile, got %v", p)
	}
}

var srv = httptest.NewServer(nil)

func query(endpoint string) (*profile.Profile, error) {
	url := srv.URL + endpoint
	r, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %q: %v", url, err)
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch %q: %v", url, r.Status)
	}

	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read and parse the result from %q: %v", url, err)
	}
	return profile.Parse(bytes.NewBuffer(b))
}

// seen returns true if the profile includes samples whose stacks include the
// specified function name (fname).
func seen(p *profile.Profile, fname string) bool {
	locIDs := map[*profile.Location]bool{}
	for _, loc := range p.Location {
		for _, l := range loc.Line {
			if strings.Contains(l.Function.Name, fname) {
				locIDs[loc] = true
				break
			}
		}
	}
	for _, sample := range p.Sample {
		for _, loc := range sample.Location {
			if locIDs[loc] {
				return true
			}
		}
	}
	return false
}
