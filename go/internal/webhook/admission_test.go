package webhook

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func staticLookup(zones map[string]string) NamespaceZoneLookup {
	return func(namespace string) (string, bool) {
		zone, ok := zones[namespace]
		return zone, ok
	}
}

func TestValidateNoAnnotationAllows(t *testing.T) {
	req := &admissionRequest{UID: "u1", Namespace: "corp-prod"}
	resp := Validate(req, staticLookup(nil))
	if !resp.Allowed {
		t.Errorf("expected allow for a pod with no zone annotation, got denied: %+v", resp)
	}
}

func TestValidateMatchingZoneAllows(t *testing.T) {
	req := &admissionRequest{UID: "u1", Namespace: "agent-restricted"}
	req.Object.Metadata.Annotations = map[string]string{ZoneAnnotation: "agent-restricted"}
	resp := Validate(req, staticLookup(map[string]string{"agent-restricted": "agent-restricted"}))
	if !resp.Allowed {
		t.Errorf("expected allow for matching zone, got denied: %+v", resp)
	}
}

func TestValidateMismatchedZoneDenies(t *testing.T) {
	req := &admissionRequest{UID: "u1", Namespace: "corp-prod"}
	req.Object.Metadata.Annotations = map[string]string{ZoneAnnotation: "agent-restricted"}
	resp := Validate(req, staticLookup(map[string]string{"corp-prod": "corp-prod"}))
	if resp.Allowed {
		t.Error("expected denial for mismatched zone annotation, got allowed")
	}
	if resp.Status == nil || resp.Status.Message == "" {
		t.Error("expected a non-empty denial message")
	}
}

func TestValidateUnknownNamespaceFailsClosed(t *testing.T) {
	req := &admissionRequest{UID: "u1", Namespace: "mystery-namespace"}
	req.Object.Metadata.Annotations = map[string]string{ZoneAnnotation: "agent-restricted"}
	resp := Validate(req, staticLookup(nil))
	if resp.Allowed {
		t.Error("expected fail-closed denial for a namespace with no declared zone, got allowed")
	}
}

func TestHandlerRoundTrip(t *testing.T) {
	handler := Handler(staticLookup(map[string]string{"agent-restricted": "agent-restricted"}))

	body := `{
		"apiVersion": "admission.k8s.io/v1",
		"kind": "AdmissionReview",
		"request": {
			"uid": "abc-123",
			"namespace": "agent-restricted",
			"object": {"metadata": {"annotations": {"agent-zone-control/zone": "agent-restricted"}}}
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var review admissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if review.Response == nil || !review.Response.Allowed {
		t.Fatalf("expected an allowed response, got %+v", review.Response)
	}
	if review.Response.UID != "abc-123" {
		t.Errorf("response UID = %q, want abc-123 (must echo the request UID)", review.Response.UID)
	}
}

func TestHandlerRejectsMissingRequest(t *testing.T) {
	handler := Handler(staticLookup(nil))
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a review with no request", rec.Code)
	}
}
