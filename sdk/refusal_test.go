package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// capabilities#68: a capability declining on AUTHORITY grounds is not a fault.
//
// Reporting it as 500/internal made a boundary being enforced indistinguishable
// from a crash — in logs, in metrics, and to a retry policy that treats 5xx as
// transient. This one never will be.
func TestAuthorityRefusalsAreNotInternalErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"undeclared target", RefuseUndeclaredTarget("machine", "someone-elses-machine"), "not a declared target"},
		{"no target named", RefuseUndeclaredTarget("gateway", ""), "is required"},
		{"undeclared egress", RefuseUndeclaredEgress("http://192.0.2.1:9999"), "egress allowlist"},
		{"missing credential", RefuseMissingSecret("PLANT_TOKEN"), "not provisioned on this edge"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(NewHandler(func(context.Context, *Context) (any, error) { return nil, tc.err }))
			defer srv.Close()

			resp, err := http.Post(srv.URL+"/run", "application/json",
				strings.NewReader(`{"run_id":"r1","input":{}}`))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var body struct {
				Error      string `json:"error"`
				ErrorClass string `json:"error_class"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&body)

			if resp.StatusCode/100 == 5 {
				t.Fatalf("an authority refusal must not be a 5xx: got %d — a boundary being enforced would look like a crash", resp.StatusCode)
			}
			if body.ErrorClass != string(ClassRefused) {
				t.Fatalf("error_class = %q, want %q", body.ErrorClass, ClassRefused)
			}
			if !strings.Contains(body.Error, tc.want) {
				t.Fatalf("message %q does not explain the refusal (want %q)", body.Error, tc.want)
			}
		})
	}
}

// A genuine fault is still a fault. Without this the suite would pass for an
// implementation that reported everything as a refusal, which is the opposite
// failure and a worse one: a broken capability would look like a boundary.
func TestGenuineFaultsAreStillInternal(t *testing.T) {
	srv := httptest.NewServer(NewHandler(func(context.Context, *Context) (any, error) {
		return nil, NewError(ClassInternal, "the machine caught fire")
	}))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/run", "application/json", strings.NewReader(`{"run_id":"r1","input":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("a genuine fault must stay 500, got %d", resp.StatusCode)
	}
}

func TestStatusForClassCoversEveryClass(t *testing.T) {
	// Every declared class must have a deliberate status. A class added without
	// one silently becomes a 500, which is exactly the defect #68 is about.
	for _, c := range []ErrorClass{ClassInvalidInput, ClassInvalidOutput, ClassTimeout, ClassDenied, ClassRefused, ClassInternal} {
		got := statusForClass(c)
		if got < 100 || got > 599 {
			t.Fatalf("class %q maps to an invalid status %d", c, got)
		}
		switch c {
		case ClassRefused, ClassDenied:
			if got/100 == 5 {
				t.Fatalf("class %q is a refusal and must not be 5xx, got %d", c, got)
			}
		}
	}
}
