package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubCaps struct {
	m map[string]bool
}

func (s stubCaps) AsMap() map[string]bool {
	return s.m
}

func TestCapabilitiesHandler_ShapeAndContentType(t *testing.T) {
	stub := stubCaps{m: map[string]bool{"borg": true, "trivy": false}}
	h := CapabilitiesHandler(stub)

	req := httptest.NewRequest("GET", "/api/v1/system/capabilities", nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	if got := rr.Header().Get("Content-Type"); got == "" || got[:16] != "application/json" {
		t.Fatalf("expected Content-Type to start with 'application/json', got %q", got)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if sv, ok := body["schema_version"].(float64); !ok || sv != 1 {
		t.Fatalf("expected schema_version == 1, got %v", sv)
	}

	if b, ok := body["borg"].(bool); !ok || b != true {
		t.Fatalf("expected borg == true, got %v", b)
	}

	if b, ok := body["trivy"].(bool); !ok || b != false {
		t.Fatalf("expected trivy == false, got %v", b)
	}
}
