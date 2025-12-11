package metrics

import (
	"net/http"
	"strings"
	"time"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	registry   *prometheus.Registry
	namespace  string
	httpReqCnt *prometheus.CounterVec
	httpDur    *prometheus.HistogramVec
	httpInfl   *prometheus.GaugeVec
}

func New(cfg config.MetricsConfig) *Metrics {
	ns := cfg.Namespace
	r := prometheus.NewRegistry()
	// Register standard process and Go collectors
	r.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	r.MustRegister(collectors.NewGoCollector())

	httpReqCnt := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "http_requests_total"}, []string{"method", "route", "status"})
	httpDur := prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "http_request_duration_seconds", Buckets: cfg.Buckets}, []string{"method", "route", "status"})
	httpInfl := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "http_inflight_requests"}, []string{"route"})

	r.MustRegister(httpReqCnt, httpDur, httpInfl)

	return &Metrics{
		registry:   r,
		namespace:  ns,
		httpReqCnt: httpReqCnt,
		httpDur:    httpDur,
		httpInfl:   httpInfl,
	}
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

func httpStatus(code int) string { return http.StatusText(code) }
