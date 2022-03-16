package handlers

import (
	"fmt"
	"net/http"
)

type ForceOrphanedASGsCleanup struct {
	ASGCleanupFunc   func(string) error
	EnableASGSyncing bool
}

func (h *ForceOrphanedASGsCleanup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.EnableASGSyncing {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("ASG syncing has been disabled administratively"))
		return
	}

	container := r.URL.Query().Get("container")
	if container == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("no container specified"))
		return
	}
	if err := h.ASGCleanupFunc(container); err != nil {
		errorMessage := fmt.Sprintf("failed to cleanup ASGs for container %s: %s", container, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(errorMessage))
		return
	}

	w.Write([]byte(fmt.Sprintf("cleaned up ASGs for container %s", container)))
}
