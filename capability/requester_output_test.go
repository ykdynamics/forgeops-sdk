package capability

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/ykdynamics/forgeops-sdk/internal/capsign"
)

// withRequesterOutput adds a contract.requesterOutputSchema to the positive
// fixture (its outputSchema declares restarted and receipt).
func withRequesterOutput(schema string) string {
	return strings.Replace(positive, "  idempotencyKey: receipt\n",
		"  requesterOutputSchema:\n"+schema+"  idempotencyKey: receipt\n", 1)
}

const restartedOnly = `    type: object
    required: [restarted]
    additionalProperties: false
    properties:
      restarted:
        type: boolean
`

// TestRequesterOutputDeclarationOnlyNarrows: the declaration is an object
// schema naming output properties and nothing else; absent is valid and
// proposes nothing.
func TestRequesterOutputDeclarationOnlyNarrows(t *testing.T) {
	if errs := mustValidate(t, positive); len(errs) != 0 {
		t.Fatalf("no declaration must stay valid: %v", errs)
	}
	if errs := mustValidate(t, withRequesterOutput(restartedOnly)); len(errs) != 0 {
		t.Fatalf("a narrowing declaration must be valid: %v", errs)
	}
	cases := []struct {
		name, schema, want string
	}{
		{"not an object", "    type: boolean\n", `"type": "object"`},
		{"names nothing", "    type: object\n    properties: {}\n", "at least one property"},
		{"admits anything else", "    type: object\n    additionalProperties: true\n    properties:\n      restarted:\n        type: boolean\n", "must not admit additional properties"},
		{"widens the output", "    type: object\n    properties:\n      token:\n        type: string\n", `"token", which outputSchema does not declare`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := mustValidate(t, withRequesterOutput(tc.schema))
			found := false
			for _, e := range errs {
				if e.Field == "contract.requesterOutputSchema" && strings.Contains(e.Message, tc.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("want a contract.requesterOutputSchema error mentioning %q, got %v", tc.want, errs)
			}
		})
	}
}

// TestProjectRequesterOutputKeepsOnlyWhatIsDeclared: the projection is the
// declared properties of the result, validated; everything else is dropped;
// anything doubtful yields no output at all.
func TestProjectRequesterOutputKeepsOnlyWhatIsDeclared(t *testing.T) {
	declared, err := Parse([]byte(withRequesterOutput(restartedOnly)))
	if err != nil {
		t.Fatal(err)
	}
	// receipt is part of the output contract but not proposed for disclosure:
	// it stays with the customer.
	got, err := ProjectRequesterOutput(declared, []byte(`{"restarted":true,"receipt":"r-17"}`))
	if err != nil || string(got) != `{"restarted":true}` {
		t.Fatalf("projection = %s, %v; want {\"restarted\":true}", got, err)
	}

	for name, result := range map[string]string{
		"not an object":             `["restarted"]`,
		"declared field wrong type": `{"restarted":"yes","receipt":"r-17"}`,
		"required field missing":    `{"receipt":"r-17"}`,
		"not JSON":                  `restarted`,
		// The result must honour the package's own outputSchema first: an
		// undeclared diagnostics field means this is not the declared answer.
		"outside outputSchema": `{"restarted":true,"receipt":"r-17","debug":"/var/lib/acme: 3 jobs"}`,
	} {
		if out, err := ProjectRequesterOutput(declared, []byte(result)); !errors.Is(err, ErrRequesterOutputInvalid) || out != nil {
			t.Errorf("%s: got %s, %v; want no output and ErrRequesterOutputInvalid", name, out, err)
		}
	}

	undeclared, err := Parse([]byte(positive))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := ProjectRequesterOutput(undeclared, []byte(`{"restarted":true}`)); !errors.Is(err, ErrNoRequesterOutput) || out != nil {
		t.Fatalf("no declaration: got %s, %v; want no output and ErrNoRequesterOutput", out, err)
	}
}

// TestRequesterOutputRejectsNestedStructures: projection is one level deep,
// so a declaration that would let a nested object through whole -- with
// fields it does not name -- is refused, and so is such a value at run time.
func TestRequesterOutputRejectsNestedStructures(t *testing.T) {
	cases := map[string]string{
		"an object property":   "    type: object\n    properties:\n      restarted:\n        type: object\n",
		"an array of objects":  "    type: object\n    properties:\n      restarted:\n        type: array\n        items:\n          type: object\n",
		"an array of no items": "    type: object\n    properties:\n      restarted:\n        type: array\n",
		"an untyped property":  "    type: object\n    properties:\n      restarted: {}\n",
		"an array of arrays":   "    type: object\n    properties:\n      restarted:\n        type: array\n        items:\n          type: array\n",
	}
	for name, schema := range cases {
		t.Run(name, func(t *testing.T) {
			errs := mustValidate(t, withRequesterOutput(schema))
			found := false
			for _, e := range errs {
				if e.Field == "contract.requesterOutputSchema" && strings.Contains(e.Message, `property "restarted"`) {
					found = true
				}
			}
			if !found {
				t.Fatalf("want the nested/untyped property refused, got %v", errs)
			}
		})
	}
	if errs := mustValidate(t, withRequesterOutput("    type: object\n    properties:\n      restarted:\n        type: array\n        items:\n          type: string\n")); len(errs) != 0 {
		t.Fatalf("an array of scalars must be accepted: %v", errs)
	}

	// Defence in depth: a package that bypassed validation still discloses no
	// nested object.
	p := &Package{Contract: Contract{
		OutputSchema:          []byte(`{"type":"object","properties":{"details":{}}}`),
		RequesterOutputSchema: []byte(`{"type":"object","properties":{"details":{}}}`),
	}}
	if out, err := ProjectRequesterOutput(p, []byte(`{"details":{"token":"s3cr3t","ok":true}}`)); !errors.Is(err, ErrRequesterOutputInvalid) || out != nil {
		t.Fatalf("a nested object was projected: %s, %v", out, err)
	}
}

// TestRequesterOutputIsPartOfThePackageIdentity: the declaration is in the
// canonical document, so it is covered by the manifest digest (the revision
// identity a registry and a control plane record) and by the publisher's
// signature over that document. Changing what is proposed for disclosure is a
// new revision, and an existing signature does not cover it.
func TestRequesterOutputIsPartOfThePackageIdentity(t *testing.T) {
	without, err := CanonicalJSON([]byte(positive))
	if err != nil {
		t.Fatal(err)
	}
	with, err := CanonicalJSON([]byte(withRequesterOutput(restartedOnly)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(with), `"requesterOutputSchema"`) {
		t.Fatalf("the canonical document drops the declaration: %s", with)
	}
	if sha256.Sum256(without) == sha256.Sum256(with) {
		t.Fatal("declaring a requester output does not change the manifest digest")
	}

	priv, pubPEM, err := capsign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := capsign.Sign(priv, with)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(doc []byte) bool {
		block, _ := pem.Decode(pubPEM)
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			t.Fatal(err)
		}
		d := sha256.Sum256(doc)
		return ecdsa.VerifyASN1(key.(*ecdsa.PublicKey), d[:], raw)
	}
	if !verify(with) {
		t.Fatal("the signature does not verify over the document it signed")
	}
	widened, err := CanonicalJSON([]byte(withRequesterOutput(strings.Replace(restartedOnly,
		"    properties:\n      restarted:\n        type: boolean\n",
		"    properties:\n      restarted:\n        type: boolean\n      receipt:\n        type: string\n", 1))))
	if err != nil {
		t.Fatal(err)
	}
	if verify(widened) {
		t.Fatal("a signature over one disclosure declaration verifies a wider one")
	}
}
