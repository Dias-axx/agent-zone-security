// Package webhook implements a minimal Kubernetes ValidatingAdmissionWebhook
// for pods created in an agent zone. It complements
// deploy/k8s/50-kyverno-pod-hardening.yaml rather than replacing it: Kyverno
// covers label provenance; this webhook adds the one check that needs
// namespace context Kyverno's pattern matching does not easily express —
// that a pod's declared zone annotation matches the namespace it is being
// admitted into (registry/agents.yaml + control/validate.py enforce the same
// rule for the human-authored registry; this is the runtime mirror of it).
//
// It intentionally avoids k8s.io/api and k8s.io/apimachinery: only the small
// subset of the AdmissionReview JSON schema this webhook reads/writes is
// modelled here, to keep this module dependency-free and fast to build.
package webhook

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// admissionReview models the fields of admission.k8s.io/v1 AdmissionReview
// this webhook actually reads or writes.
type admissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *admissionRequest  `json:"request,omitempty"`
	Response   *admissionResponse `json:"response,omitempty"`
}

type admissionRequest struct {
	UID       string          `json:"uid"`
	Namespace string          `json:"namespace"`
	Object    admissionObject `json:"object"`
}

type admissionObject struct {
	Metadata struct {
		Annotations map[string]string `json:"annotations"`
		Labels      map[string]string `json:"labels"`
	} `json:"metadata"`
}

type admissionResponse struct {
	UID     string  `json:"uid"`
	Allowed bool    `json:"allowed"`
	Status  *status `json:"status,omitempty"`
}

type status struct {
	Message string `json:"message"`
}

// ZoneAnnotation is the pod annotation this webhook checks against the
// namespace label set by deploy/k8s/00-namespaces.yaml (zone: <name>).
const ZoneAnnotation = "agent-zone-control/zone"

// NamespaceZoneLookup resolves a namespace name to its declared zone label.
// In cmd/admission-webhook this is backed by a real Kubernetes API client;
// tests supply a map.
type NamespaceZoneLookup func(namespace string) (zone string, found bool)

// Validate checks one AdmissionRequest against the zone-match rule. It never
// panics or denies on a lookup failure it cannot attribute to the pod itself —
// a namespace lookup error fails the admission request explicitly (fail
// closed), it does not silently allow.
func Validate(req *admissionRequest, lookupZone NamespaceZoneLookup) admissionResponse {
	zoneAnnotation, hasAnnotation := req.Object.Metadata.Annotations[ZoneAnnotation]
	if !hasAnnotation {
		// No zone annotation declared: nothing for this webhook to check.
		// Absence of the annotation is not itself a violation — most pods in
		// the cluster are not agent pods at all.
		return admissionResponse{UID: req.UID, Allowed: true}
	}

	namespaceZone, found := lookupZone(req.Namespace)
	if !found {
		return admissionResponse{
			UID:     req.UID,
			Allowed: false,
			Status:  &status{Message: fmt.Sprintf("namespace %q has no declared zone label; failing closed", req.Namespace)},
		}
	}

	if zoneAnnotation != namespaceZone {
		return admissionResponse{
			UID:     req.UID,
			Allowed: false,
			Status: &status{Message: fmt.Sprintf(
				"pod annotation %s=%q does not match namespace %q's zone %q",
				ZoneAnnotation, zoneAnnotation, req.Namespace, namespaceZone,
			)},
		}
	}

	return admissionResponse{UID: req.UID, Allowed: true}
}

// Handler returns an http.Handler implementing the webhook's /validate
// endpoint against a live namespace-zone lookup.
func Handler(lookupZone NamespaceZoneLookup) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var review admissionReview
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			http.Error(w, fmt.Sprintf("decode admission review: %v", err), http.StatusBadRequest)
			return
		}
		if review.Request == nil {
			http.Error(w, "admission review missing request", http.StatusBadRequest)
			return
		}

		resp := Validate(review.Request, lookupZone)
		out := admissionReview{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
			Response:   &resp,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}
