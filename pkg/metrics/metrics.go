package metrics

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	registry     *prometheus.Registry
	namespace    string
	httpReqCnt   *prometheus.CounterVec
	httpDur      *prometheus.HistogramVec
	httpInfl     *prometheus.GaugeVec
	mcpReqCnt    *prometheus.CounterVec
	mcpReqDur    *prometheus.HistogramVec
	mcpReqInfl   *prometheus.GaugeVec
	toolExecCnt  *prometheus.CounterVec
	toolExecDur  *prometheus.HistogramVec
	toolExecInfl *prometheus.GaugeVec
}

func New(cfg config.MetricsConfig) *Metrics {
	ns := cfg.Namespace
	r := prometheus.NewRegistry()
	// Register standard process and Go collectors
	r.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	r.MustRegister(collectors.NewGoCollector())

	// Register basic HTTP metrics
	httpReqCnt := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "http_requests_total"}, []string{"method", "route", "status"})
	httpDur := prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "http_request_duration_seconds", Buckets: cfg.Buckets}, []string{"method", "route", "status"})
	httpInfl := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "http_requests_inflight"}, []string{"route"})
	r.MustRegister(httpReqCnt, httpDur, httpInfl)

	mcpReqCnt := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "mcp_requests_total"}, []string{"method"})
	mcpReqDur := prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "mcp_request_duration_seconds", Buckets: cfg.Buckets}, []string{"method"})
	mcpReqInfl := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "mcp_requests_inflight"}, []string{"method"})
	r.MustRegister(mcpReqDur, mcpReqCnt, mcpReqInfl)

	toolExecCnt := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "tool_execution_total"}, []string{"tool_name", "status"})
	toolExecDur := prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "tool_execution_duration_seconds", Buckets: cfg.Buckets}, []string{"tool_name", "status"})
	toolExecInfl := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "tool_execution_inflight_requests"}, []string{"tool_name"})
	r.MustRegister(toolExecCnt, toolExecDur, toolExecInfl)

	return &Metrics{
		registry:     r,
		namespace:    ns,
		httpReqCnt:   httpReqCnt,
		httpDur:      httpDur,
		httpInfl:     httpInfl,
		mcpReqCnt:    mcpReqCnt,
		mcpReqDur:    mcpReqDur,
		mcpReqInfl:   mcpReqInfl,
		toolExecCnt:  toolExecCnt,
		toolExecDur:  toolExecDur,
		toolExecInfl: toolExecInfl,
	}
}

func (m *Metrics) McpReqStart(method string) {
	m.mcpReqInfl.WithLabelValues(method).Inc()
}

func (m *Metrics) McpReqDone(method string, since time.Time) {
	m.mcpReqCnt.WithLabelValues(method).Inc()
	m.mcpReqDur.WithLabelValues(method).Observe(time.Since(since).Seconds())
	m.mcpReqInfl.WithLabelValues(method).Dec()
}

func (m *Metrics) ToolExecStart(toolName string) {
	m.toolExecInfl.WithLabelValues(toolName).Inc()
}

func (m *Metrics) ToolExecDone(toolName string, since time.Time, status *string) {
	m.toolExecCnt.WithLabelValues(toolName, *status).Inc()
	m.toolExecDur.WithLabelValues(toolName, *status).Observe(time.Since(since).Seconds())
	m.toolExecInfl.WithLabelValues(toolName).Dec()
}

func (m *Metrics) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		route := c.FullPath()
		if route == "" {
			route = routeFromURL(c.Request.URL.Path)
		}
		m.httpInfl.WithLabelValues(route).Inc()
		start := time.Now()
		c.Next()
		status := httpStatus(c.Writer.Status())
		m.httpReqCnt.WithLabelValues(c.Request.Method, route, status).Inc()
		m.httpDur.WithLabelValues(c.Request.Method, route, status).Observe(time.Since(start).Seconds())
		m.httpInfl.WithLabelValues(route).Dec()
	}
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func routeFromURL(path string) string {
	if strings.HasSuffix(path, "/sse") {
		return "/:prefix/sse"
	}
	if strings.HasSuffix(path, "/message") {
		return "/:prefix/message"
	}
	if strings.HasSuffix(path, "/mcp") {
		return "/:prefix/mcp"
	}
	return path
}

func httpStatus(code int) string { return strconv.Itoa(code) }
