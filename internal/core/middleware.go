package core

import (
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/pkg/metrics"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// loggerMiddleware logs incoming requests and outgoing responses
func (s *Server) loggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Record basic information at request start time using Info level
		startTime := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		// Record basic information for all requests
		logger := s.logger.With(
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("remote_addr", c.Request.RemoteAddr),
			zap.String("user_agent", c.Request.UserAgent()),
		)

		// Extract trace ID from OpenTelemetry context and inject into logger
		span := trace.SpanFromContext(c.Request.Context())
		if span.SpanContext().IsValid() {
			logger = logger.With(zap.String("trace_id", span.SpanContext().TraceID().String()))
		}

		// Use Debug level to record more detailed request information
		if s.logger.Core().Enabled(zap.DebugLevel) {
			headers := make(map[string]string)
			for k, v := range c.Request.Header {
				// Filter out sensitive header information
				if k != "Authorization" && k != "Cookie" {
					headers[k] = strings.Join(v, ", ")
				}
			}

			logger.Debug("request details",
				zap.String("query", query),
				zap.Any("headers", headers),
			)
		}

		// Record request start
		logger.Info("request started")

		// Save logger in context for later use
		c.Set("logger", logger)

		c.Next()

		// Calculate request processing time
		latency := time.Since(startTime)
		statusCode := c.Writer.Status()

		// Choose log level based on status code
		if statusCode >= 500 {
			// Use Error level for server errors
			logger.Error("request completed with server error",
				zap.Int("status", statusCode),
				zap.Int("size", c.Writer.Size()),
				zap.Duration("latency", latency),
				zap.String("client_ip", c.ClientIP()),
			)
		} else if statusCode >= 400 {
			// Use Warn level for client errors
			logger.Warn("request completed with client error",
				zap.Int("status", statusCode),
				zap.Int("size", c.Writer.Size()),
				zap.Duration("latency", latency),
				zap.String("client_ip", c.ClientIP()),
			)
		} else {
			// Use Info level for normal status
			logger.Info("request completed successfully",
				zap.Int("status", statusCode),
				zap.Int("size", c.Writer.Size()),
				zap.Duration("latency", latency),
				zap.String("client_ip", c.ClientIP()),
			)
		}
	}
}

// recoveryMiddleware recovers from panics and returns 500 error
func (s *Server) recoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Get stack information
				stack := make([]byte, 4096)
				length := runtime.Stack(stack, false)

				// Get request related information
				httpRequest := c.Request
				headers := make(map[string]string)
				for k, v := range httpRequest.Header {
					if k != "Authorization" && k != "Cookie" {
						headers[k] = strings.Join(v, ", ")
					}
				}

				// Record panic information with Error level
				s.logger.Error("panic recovered",
					zap.Any("error", err),
					zap.String("path", c.Request.URL.Path),
					zap.String("method", c.Request.Method),
					zap.String("remote_addr", c.Request.RemoteAddr),
					zap.String("client_ip", c.ClientIP()),
					zap.Any("request_headers", headers),
					zap.ByteString("stack", stack[:length]),
				)

				// Return 500 error
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "internal server error",
				})
				c.Abort()
			}
		}()
		c.Next()
	}
}

// corsMiddleware handles CORS configuration
func (s *Server) corsMiddleware(cors *config.CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			c.Next()
			return
		}

		allowed := false
		for _, allowedOrigin := range cors.AllowOrigins {
			if allowedOrigin == "*" || origin == allowedOrigin {
				allowed = true
				c.Header("Access-Control-Allow-Origin", origin)
				break
			}
		}

		if !allowed {
			c.Next()
			return
		}

		if len(cors.AllowMethods) > 0 {
			c.Header("Access-Control-Allow-Methods", strings.Join(cors.AllowMethods, ", "))
		}

		if len(cors.AllowHeaders) > 0 {
			c.Header("Access-Control-Allow-Headers", strings.Join(cors.AllowHeaders, ", "))
		}

		if len(cors.ExposeHeaders) > 0 {
			c.Header("Access-Control-Expose-Headers", strings.Join(cors.ExposeHeaders, ", "))
		}

		if cors.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// EnableTracing attaches OpenTelemetry gin middleware using the given service name.
func (s *Server) EnableTracing(serviceName string) {
	if s == nil || s.router == nil {
		return
	}
	s.router.Use(otelgin.Middleware(serviceName,
		otelgin.WithFilter(func(r *http.Request) bool {
			if r == nil || r.URL == nil {
				return true
			}
			// Skip tracing for health check endpoint
			if r.URL.Path == "/health_check" {
				return false
			}
			// Skip tracing for metrics endpoint (dynamic path)
			if s.metricsPath != "" && r.URL.Path == s.metricsPath {
				return false
			}
			return true
		}),
	))
}

func (s *Server) EnableMetrics(cfg config.MetricsConfig) {
	// If metrics are not enabled, skip configuration
	if !cfg.Enabled {
		return
	}
	m := metrics.New(cfg)
	s.metrics = m
	s.metricsPath = cfg.Path
	s.logger.Info("metrics enabled", zap.String("path", cfg.Path))
	// Register metrics middleware
	s.router.Use(m.Middleware())
	// Register metrics handler
	s.router.GET(cfg.Path, gin.WrapH(m.Handler()))
}
