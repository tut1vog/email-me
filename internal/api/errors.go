package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// Error codes (mirrored in openapi.yaml's Error.error enum).
const (
	CodeInvalidRequest     = "invalid_request"
	CodeUnauthorized       = "unauthorized"
	CodeAgentDisabled      = "agent_disabled"
	CodeSourceIPNotAllowed = "source_ip_not_allowed"
	CodeRecipientNotAllow  = "recipient_not_allowed"
	CodeServiceNotAllowed  = "service_not_allowed"
	CodeEncryptionRequired = "encryption_required"
	CodeSigningRequired    = "signing_required"
	CodeTooLarge           = "message_too_large"
	CodeAttachmentType     = "attachment_type_not_allowed"
	CodeValidation         = "validation_failed"
	CodeRateLimited        = "rate_limited"
	CodeUpstreamFailed     = "upstream_failed"
	CodeSigningUnavailable = "signing_unavailable"
	CodeEncryptionUnavail  = "encryption_unavailable"
	CodeNotFound           = "not_found"
	CodeMethodNotAllowed   = "method_not_allowed"
	CodeInternal           = "internal_error"
)

// AllCodes lists every error code the API can return.
var AllCodes = []string{
	CodeInvalidRequest, CodeUnauthorized, CodeAgentDisabled, CodeSourceIPNotAllowed, CodeRecipientNotAllow,
	CodeServiceNotAllowed, CodeEncryptionRequired, CodeSigningRequired, CodeTooLarge, CodeAttachmentType,
	CodeValidation, CodeRateLimited, CodeUpstreamFailed, CodeSigningUnavailable, CodeEncryptionUnavail, CodeNotFound,
	CodeMethodNotAllowed, CodeInternal,
}

// apiError is an error response. Messages are written for LLM readers: they
// say what went wrong and how to fix it.
type apiError struct {
	Status     int
	Code       string
	Message    string
	Details    map[string]any
	RetryAfter int
	// UpstreamCode is recorded in the audit log for upstream failures.
	UpstreamCode int
}

func (e *apiError) Error() string { return e.Code + ": " + e.Message }

func newErr(status int, code, format string, args ...any) *apiError {
	return &apiError{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

func (e *apiError) with(k string, v any) *apiError {
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	e.Details[k] = v
	return e
}

type errorBody struct {
	Error   string         `json:"error"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
	Docs    string         `json:"docs,omitempty"`
}

func writeError(w http.ResponseWriter, e *apiError) {
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.RetryAfter))
	}
	docs := "/openapi.json"
	if e.Code == CodeUnauthorized || e.Code == CodeNotFound || e.Code == CodeMethodNotAllowed {
		docs = "/"
	}
	writeJSON(w, e.Status, errorBody{Error: e.Code, Message: e.Message, Details: e.Details, Docs: docs})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"error":"internal_error","message":"encoding response"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
	w.Write([]byte("\n"))
}
