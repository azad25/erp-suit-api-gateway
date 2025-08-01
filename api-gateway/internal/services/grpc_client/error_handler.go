// service/grpc_client/error_handler.go
package grpc_client

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"erp-api-gateway/internal/logging"
)

// ErrorHandler handles gRPC error translation and logging
type ErrorHandler struct {
	logger logging.Logger
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger logging.Logger) *ErrorHandler {
	return &ErrorHandler{
		logger: logger,
	}
}

// TranslateGRPCError translates gRPC errors to HTTP status codes
func (eh *ErrorHandler) TranslateGRPCError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, "OK"
	}

	// Extract gRPC status
	st, ok := status.FromError(err)
	if !ok {
		// Not a gRPC error, treat as internal server error
		eh.logger.Error("Non-gRPC error encountered",
			map[string]interface{}{
				"error": err.Error(),
			})
		return http.StatusInternalServerError, "Internal Server Error"
	}

	// Map gRPC codes to HTTP status codes
	switch st.Code() {
	case codes.OK:
		return http.StatusOK, "OK"
	case codes.Canceled:
		return http.StatusRequestTimeout, "Request Canceled"
	case codes.Unknown:
		return http.StatusInternalServerError, "Unknown Error"
	case codes.InvalidArgument:
		return http.StatusBadRequest, "Invalid Argument"
	case codes.DeadlineExceeded:
		return http.StatusRequestTimeout, "Deadline Exceeded"
	case codes.NotFound:
		return http.StatusNotFound, "Not Found"
	case codes.AlreadyExists:
		return http.StatusConflict, "Already Exists"
	case codes.PermissionDenied:
		return http.StatusForbidden, "Permission Denied"
	case codes.ResourceExhausted:
		return http.StatusTooManyRequests, "Resource Exhausted"
	case codes.FailedPrecondition:
		return http.StatusPreconditionFailed, "Failed Precondition"
	case codes.Aborted:
		return http.StatusConflict, "Aborted"
	case codes.OutOfRange:
		return http.StatusBadRequest, "Out of Range"
	case codes.Unimplemented:
		return http.StatusNotImplemented, "Unimplemented"
	case codes.Internal:
		return http.StatusInternalServerError, "Internal Error"
	case codes.Unavailable:
		return http.StatusServiceUnavailable, "Service Unavailable"
	case codes.DataLoss:
		return http.StatusInternalServerError, "Data Loss"
	case codes.Unauthenticated:
		return http.StatusUnauthorized, "Unauthenticated"
	default:
		return http.StatusInternalServerError, "Unknown Error"
	}
}

// LogError logs gRPC errors with appropriate context
func (eh *ErrorHandler) LogError(ctx context.Context, serviceName string, method string, err error) {
	if err == nil {
		return
	}

	fields := map[string]interface{}{
		"service": serviceName,
		"method":  method,
		"error":   err.Error(),
	}

	// Add request ID if available
	if requestID := ctx.Value("request_id"); requestID != nil {
		fields["request_id"] = requestID
	}

	// Add user ID if available
	if userID := ctx.Value("user_id"); userID != nil {
		fields["user_id"] = userID
	}

	// Determine log level based on error type
	if st, ok := status.FromError(err); ok {
		fields["grpc_code"] = st.Code().String()
		
		switch st.Code() {
		case codes.Canceled, codes.DeadlineExceeded:
			eh.logger.Warn("gRPC call timeout", fields)
		case codes.NotFound, codes.InvalidArgument:
			eh.logger.Info("gRPC client error", fields)
		case codes.PermissionDenied, codes.Unauthenticated:
			eh.logger.Warn("gRPC authorization error", fields)
		case codes.Internal, codes.Unknown, codes.DataLoss:
			eh.logger.Error("gRPC server error", fields)
		case codes.Unavailable, codes.ResourceExhausted:
			eh.logger.Warn("gRPC service unavailable", fields)
		default:
			eh.logger.Error("gRPC error", fields)
		}
	} else {
		eh.logger.Error("Non-gRPC error", fields)
	}
}

// IsRetryableError determines if an error should be retried
func (eh *ErrorHandler) IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for circuit breaker errors (not retryable)
	if strings.Contains(err.Error(), "circuit breaker") {
		return false
	}

	// Check gRPC status codes
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted:
			return true
		case codes.Internal:
			// Internal errors might be temporary
			return true
		default:
			return false
		}
	}

	// Check for common network errors
	errorString := strings.ToLower(err.Error())
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"network is unreachable",
		"no route to host",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errorString, pattern) {
			return true
		}
	}

	return false
}

// WrapError wraps an error with additional context
func (eh *ErrorHandler) WrapError(serviceName, method string, err error) error {
	if err == nil {
		return nil
	}

	// If it's already a gRPC status error, preserve it
	if _, ok := status.FromError(err); ok {
		return err
	}

	// Wrap non-gRPC errors
	return status.Errorf(codes.Internal, "service %s method %s failed: %v", serviceName, method, err)
}

// CreateTimeoutError creates a timeout error
func (eh *ErrorHandler) CreateTimeoutError(serviceName, method string) error {
	return status.Errorf(codes.DeadlineExceeded, "timeout calling service %s method %s", serviceName, method)
}

// CreateUnavailableError creates an unavailable error
func (eh *ErrorHandler) CreateUnavailableError(serviceName string) error {
	return status.Errorf(codes.Unavailable, "service %s is unavailable", serviceName)
}