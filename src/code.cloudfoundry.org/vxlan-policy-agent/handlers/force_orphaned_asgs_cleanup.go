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
		// #nosec G104 - ignore errors when writing HTTP responses so we don't spam our logs during a DoS
		w.Write([]byte("ASG syncing has been disabled administratively"))
		return
	}

	container := r.URL.Query().Get("container")
	if container == "" {
		w.WriteHeader(http.StatusBadRequest)
		// #nosec G104 - ignore errors when writing HTTP responses so we don't spam our logs during a DoS
		w.Write([]byte("no container specified"))
		return
	}
	// Deliberately return 200 on cleanup error: cni-wrapper-plugin's cmdDel must not be blocked
	// by a transient cleanup failure — the periodic SyncASGsForContainers poll cycle retries and
	// eventually clears it.
	if err := h.ASGCleanupFunc(container); err != nil {
		w.WriteHeader(http.StatusOK)
		// #nosec G104 - ignore errors when writing HTTP responses so we don't spam our logs during a DoS
		w.Write([]byte(fmt.Sprintf("deferred cleanup of ASGs for container %s: will retry on next poll cycle (%s)", container, err)))
		return
	}

	// #nosec G104 - ignore errors when writing HTTP responses so we don't spam our logs during a DoS
	w.Write([]byte(fmt.Sprintf("cleaned up ASGs for container %s", container)))
}
