package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
)

// cmdPublishKey uploads the publisher's P-256 public key to the registry
// (PUT /v1/registry/publishers/{publisher}/key — one-time per publisher).
func cmdPublishKey(args []string) error {
	fs := flag.NewFlagSet("publish-key", flag.ExitOnError)
	registry := fs.String("registry", "", "registry base URL (e.g. https://api.example.com)")
	token := fs.String("token", "", "operator bearer JWT (catalog role)")
	publisher := fs.String("publisher", "", "publisher name")
	pubPath, flagArgs := splitPositional(args)
	_ = fs.Parse(flagArgs)
	if pubPath == "" || *registry == "" || *token == "" || *publisher == "" {
		return fmt.Errorf("publish-key needs <public-key.pem> and --registry/--token/--publisher")
	}
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"public_key": string(pubPEM)})
	req, err := http.NewRequest(http.MethodPut,
		*registry+"/v1/registry/publishers/"+*publisher+"/key", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+*token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("register publisher key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("register publisher key: HTTP %d", resp.StatusCode)
	}
	var key struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	fmt.Printf("publisher %s key registered (fingerprint %s)\n", *publisher, key.Fingerprint)
	return nil
}

// cmdPublish posts a register payload (from `package --register-out`) to the
// registry's POST /v1/registry/capabilities.
func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	registry := fs.String("registry", "", "registry base URL")
	token := fs.String("token", "", "operator bearer JWT (catalog role)")
	payloadPath, flagArgs := splitPositional(args)
	_ = fs.Parse(flagArgs)
	if payloadPath == "" || *registry == "" || *token == "" {
		return fmt.Errorf("publish needs <register.json> and --registry/--token")
	}
	raw, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("read register payload: %w", err)
	}
	if !json.Valid(raw) {
		return fmt.Errorf("register payload is not valid JSON")
	}
	req, err := http.NewRequest(http.MethodPost,
		*registry+"/v1/registry/capabilities", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+*token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return fmt.Errorf("publish: HTTP %d (registry refused the package)", resp.StatusCode)
	}
	var entry map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&entry); err == nil {
		pretty, _ := json.MarshalIndent(entry, "", "  ")
		fmt.Printf("published:\n%s\n", pretty)
		return nil
	}
	fmt.Printf("published (HTTP 201)\n")
	return nil
}
