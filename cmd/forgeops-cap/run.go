package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ykdynamics/forgeops-sdk/capability"
)

// cmdRun builds the scaffolded capability and executes a sample input through
// the SDK's http-runtime contract — the local dev loop.
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	input := fs.String("input", `{"service":"acme"}`, "sample input JSON to execute")
	addr := fs.String("addr", "127.0.0.1:18097", "local capability address")
	dir, flagArgs := splitPositional(args)
	_ = fs.Parse(flagArgs)
	if dir == "" {
		return fmt.Errorf("run needs a project directory containing capability.yaml")
	}

	pkgPath := filepath.Join(dir, "capability.yaml")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", pkgPath, err)
	}
	pkg, errs, err := capability.ValidateDocument(data)
	if err != nil {
		return fmt.Errorf("capability.yaml is not a valid Capability Package: %w", err)
	}
	if len(errs) != 0 {
		return fmt.Errorf("capability.yaml does not conform: %v", errs)
	}
	if !json.Valid([]byte(*input)) {
		return fmt.Errorf("--input is not valid JSON: %s", *input)
	}

	// The local dev loop builds for the machine it is about to RUN the binary
	// on, which is the host by definition — so it is deliberately not the
	// identity recipe in internal/implbuild, which builds for a declared
	// platform with a pinned compiler so its output can be hashed into a
	// manifest. `run` pins nothing and authorizes nothing; keep it that way
	// rather than routing it through the builder, which would mean teaching the
	// builder a "no identity" mode.
	bin := filepath.Join(os.TempDir(), "forgeops-cap-run-"+filepath.Base(dir))
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("build failed: %v\n%s", err, out)
	}
	defer os.Remove(bin)

	// Start the capability; the SDK serves POST /run after /health.
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "CAPABILITY_ADDR="+*addr)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start capability: %w", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	healthy := false
	for i := 0; i < 50; i++ {
		if resp, err := http.Get("http://" + *addr + "/health"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				healthy = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !healthy {
		return fmt.Errorf("capability did not become healthy at %s", *addr)
	}

	// Execute a sample input through the runtime contract (no runtime_url:
	// progress/secret callbacks no-op, which is correct for a local safe read).
	payload, _ := json.Marshal(map[string]any{
		"run_id": "forgeops-cap-local", "input": json.RawMessage(*input),
	})
	resp, err := http.Post("http://"+*addr+"/run", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("execute run: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != 200 {
		var se struct {
			Class   string `json:"class"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &se)
		if se.Message != "" {
			return fmt.Errorf("run failed (%s): %s", se.Class, se.Message)
		}
		return fmt.Errorf("run failed: HTTP %d %s", resp.StatusCode, string(body))
	}

	fmt.Printf("OK: %s@%s executed a sample input\n", pkg.Identity.Key, pkg.Identity.Version)
	fmt.Printf("  input : %s\n", *input)
	fmt.Printf("  output: %s\n", prettyJSON(body))
	return nil
}

func prettyJSON(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) == nil {
		if out, err := json.MarshalIndent(v, "         ", "  "); err == nil {
			return string(out)
		}
	}
	return string(b)
}
