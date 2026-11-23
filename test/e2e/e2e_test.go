// Package e2e runs a real tailcat server and client through the relay
// under `wrangler dev`, with the example admission Worker bound to it.
//
// It is slow and needs Node and the repo's npm packages, so it only runs
// with -e2e or DERP_WORKER_E2E=1:
//
//	npm run test:e2e   (or: cd test/e2e && go test -v . -args -e2e)
package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const statsToken = "e2e-stats-token"

var runE2E = flag.Bool("e2e", false, "run the end-to-end test (or set DERP_WORKER_E2E=1)")

func TestRelay(t *testing.T) {
	if !*runE2E && os.Getenv("DERP_WORKER_E2E") != "1" {
		t.Skip("pass -e2e or set DERP_WORKER_E2E=1 to run")
	}
	// Both peers run in this process, so make them use the relay instead of
	// a direct path, and talk plain HTTP to wrangler dev.
	envknob.Setenv("TS_DEBUG_ALWAYS_USE_DERP", "1")
	envknob.Setenv("TS_DEBUG_USE_DERP_HTTP", "1")

	server, client, stranger := key.NewNode(), key.NewNode(), key.NewNode()
	port := startWrangler(t, []key.NodePublic{server.Public(), client.Public()})
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	region := &tailcfg.DERPRegion{
		RegionID:   900,
		RegionCode: "e2e",
		Nodes: []*tailcfg.DERPNode{{
			Name:     "900a",
			RegionID: 900,
			HostName: "127.0.0.1",
			DERPPort: port,
			STUNPort: -1,
		}},
	}
	allow := new(tailcat.KeySet)
	allow.Add(client.Public())
	allow.Add(stranger.Public())
	s := &tailcat.Server{Key: server, Region: region, AllowClient: allow.Contains, Logf: t.Logf}
	defer closeWithin(t, s.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ln, err := s.Listen(ctx, "tcp", ":1")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer closeWithin(t, c.Close)
				io.Copy(c, c)
			}()
		}
	}()
	addr := s.TailcatAddr()

	t.Run("allowed client echoes", func(t *testing.T) {
		c := &tailcat.Client{Server: addr, Key: client, Logf: t.Logf}
		defer closeWithin(t, c.Close)
		if _, err := c.Ping(ctx); err != nil {
			t.Fatalf("ping: %v", err)
		}
		conn, err := c.DialTCPPort(ctx, 1)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		for i := range 5 {
			want := fmt.Sprintf("hello %d\n", i)
			if _, err := io.WriteString(conn, want); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil || got != want {
				t.Fatalf("echo %d: got %q, %v", i, got, err)
			}
		}
	})

	t.Run("stranger is refused by the relay", func(t *testing.T) {
		// The tailcat server would accept this key; only the relay's
		// admission check keeps it out.
		c := &tailcat.Client{Server: addr, Key: stranger, Logf: t.Logf}
		defer closeWithin(t, c.Close)
		pctx, pcancel := context.WithTimeout(ctx, 15*time.Second)
		defer pcancel()
		if _, err := c.Ping(pctx); err == nil {
			t.Fatal("stranger's ping got through the relay")
		}
		if n := stat(t, base, "reject_denied"); n < 1 {
			t.Fatalf("relay counted %d denied clients, want at least 1", n)
		}
	})
}

// stat reads one counter from the relay's /stats, summed over all hours.
func stat(t *testing.T, base, name string) int {
	req, _ := http.NewRequest("GET", base+"/stats", nil)
	req.Header.Set("Authorization", "Bearer "+statsToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	defer res.Body.Close()
	var body struct {
		Rows []struct {
			Name string `json:"name"`
			N    int    `json:"n"`
		} `json:"rows"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("stats: %v", err)
	}
	n := 0
	for _, r := range body.Rows {
		if r.Name == name {
			n += r.N
		}
	}
	return n
}

// startWrangler runs `wrangler dev` with the relay and the example admission
// Worker on a free port and returns the port. The process tree is stopped
// when the test ends.
func startWrangler(t *testing.T, allowed []key.NodePublic) int {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var keys []string
	for _, k := range allowed {
		keys = append(keys, k.String())
	}
	relayCfg := map[string]any{
		"name":               "derp-worker",
		"main":               filepath.ToSlash(filepath.Join(root, "src", "index.ts")),
		"compatibility_date": "2026-10-01",
		"durable_objects":    map[string]any{"bindings": []any{map[string]any{"name": "RELAY", "class_name": "Relay"}}},
		"migrations":         []any{map[string]any{"tag": "v1", "new_sqlite_classes": []string{"Relay"}}},
		"services":           []any{map[string]any{"binding": "ADMISSION", "service": "derp-admission"}},
		"vars":               map[string]any{"STATS_TOKEN": statsToken},
	}
	admissionCfg := map[string]any{
		"name":               "derp-admission",
		"main":               filepath.ToSlash(filepath.Join(root, "examples", "admission", "src", "index.ts")),
		"compatibility_date": "2026-10-01",
		"vars":               map[string]any{"ALLOWED_KEYS": strings.Join(keys, ",")},
	}
	relayPath := writeJSON(t, filepath.Join(dir, "relay.json"), relayCfg)
	admissionPath := writeJSON(t, filepath.Join(dir, "admission.json"), admissionCfg)

	port := freePort(t)
	cmd := exec.Command("node", filepath.Join(root, "node_modules", "wrangler", "bin", "wrangler.js"),
		"dev", "-c", relayPath, "-c", admissionPath,
		"--port", fmt.Sprint(port), "--ip", "127.0.0.1",
		"--persist-to", filepath.Join(dir, "state"))
	cmd.Dir = dir
	logFile, err := os.Create(filepath.Join(dir, "wrangler.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wrangler: %v", err)
	}
	t.Cleanup(func() {
		killTree(cmd)
		cmd.Wait()
		logFile.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logFile.Name())
			t.Logf("wrangler log:\n%s", b)
		}
	})

	deadline := time.Now().Add(90 * time.Second)
	for {
		res, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/derpmap.json", port))
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				return port
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("wrangler dev did not come up on port %d", port)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func writeJSON(t *testing.T, path string, v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// closeWithin calls close but gives up after a few seconds: tailcat's
// Close can block on its network stack, and a hung Close should not hang
// the test.
func closeWithin(t *testing.T, closeFn func() error) {
	done := make(chan struct{})
	go func() {
		closeFn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Log("Close did not return within 5s; moving on")
	}
}
