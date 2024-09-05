package api

import (
	"encoding/json"
	"hosts++/internal/config"
	"hosts++/pkg/logger"
	"hosts++/pkg/metrics"
	"net/http"
)

type API struct {
	config  *config.Config
	logger  *logger.Logger
	metrics *metrics.Metrics
}

func New(cfg *config.Config) *API {
	return &API{
		config:  cfg,
		logger:  logger.GetInstance(),
		metrics: metrics.GetInstance(),
	}
}

func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/rules", a.handleRules)
	mux.HandleFunc("/api/rule", a.handleRule)
	mux.HandleFunc("/api/stats", a.handleStats)
}

func (a *API) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := a.config.GetRules()
		json.NewEncoder(w).Encode(rules)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleRule(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var rule config.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "Rule name is required", http.StatusBadRequest)
			return
		}
		a.config.AddRule(name, rule)
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "Rule name is required", http.StatusBadRequest)
			return
		}
		a.config.RemoveRule(name)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := a.metrics.GetStats()
	json.NewEncoder(w).Encode(stats)
}
