// admission-webhook serves a Kubernetes ValidatingAdmissionWebhook that checks
// a pod's agent-zone-control/zone annotation against the zone label on the
// namespace it is being admitted into (see internal/webhook). It requires a
// live Kubernetes API server to resolve namespace labels and has not been
// deployed against one in this repository's build environment — see
// docs/architecture.md. internal/webhook's tests cover the validation logic
// itself against a stubbed lookup.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/dias-axx/agent-zone-control/go/internal/webhook"
)

const (
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	serviceAccountCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

type k8sNamespace struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
}

// inClusterZoneLookup resolves a namespace's "zone" label via the in-cluster
// Kubernetes API, using the pod's mounted service account token. Returns
// found=false (not an error) for a namespace with no "zone" label — that is a
// cluster misconfiguration Validate() treats as fail-closed, not this
// function's job to paper over.
func inClusterZoneLookup(apiServerURL string, httpClient *http.Client) webhook.NamespaceZoneLookup {
	return func(namespace string) (string, bool) {
		token, err := os.ReadFile(serviceAccountTokenPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "admission-webhook: reading service account token: %v\n", err)
			return "", false
		}

		req, err := http.NewRequest(http.MethodGet, apiServerURL+"/api/v1/namespaces/"+namespace, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "admission-webhook: building namespace lookup request: %v\n", err)
			return "", false
		}
		req.Header.Set("Authorization", "Bearer "+string(token))

		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "admission-webhook: namespace lookup request failed: %v\n", err)
			return "", false
		}
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil {
				fmt.Fprintf(os.Stderr, "admission-webhook: closing response body: %v\n", closeErr)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "admission-webhook: namespace lookup for %q returned %d: %s\n", namespace, resp.StatusCode, body)
			return "", false
		}

		var ns k8sNamespace
		if err := json.NewDecoder(resp.Body).Decode(&ns); err != nil {
			fmt.Fprintf(os.Stderr, "admission-webhook: decoding namespace %q: %v\n", namespace, err)
			return "", false
		}

		zone, ok := ns.Metadata.Labels["zone"]
		return zone, ok
	}
}

func main() {
	addr := envOr("LISTEN_ADDR", ":8443")
	certFile := envOr("TLS_CERT_FILE", "/etc/webhook/tls.crt")
	keyFile := envOr("TLS_KEY_FILE", "/etc/webhook/tls.key")
	apiServerURL := envOr("KUBERNETES_API_SERVER", "https://kubernetes.default.svc")

	httpClient := &http.Client{}
	if caCert, err := os.ReadFile(serviceAccountCAPath); err == nil {
		pool := tlsCertPoolFromPEM(caCert)
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	}

	http.Handle("/validate", webhook.Handler(inClusterZoneLookup(apiServerURL, httpClient)))
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fmt.Printf("admission-webhook: listening on %s\n", addr)
	if err := http.ListenAndServeTLS(addr, certFile, keyFile, nil); err != nil {
		fmt.Fprintf(os.Stderr, "admission-webhook: %v\n", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func tlsCertPoolFromPEM(pemBytes []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	return pool
}
