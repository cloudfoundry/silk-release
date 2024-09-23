package handlers

import (
	"fmt"
	"net/http"
)

type ForcePolicyPollCycle struct {
	PollCycleFunc func() error
}

func (h *ForcePolicyPollCycle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.PollCycleFunc(); err != nil {
		errorMessage := fmt.Sprintf("failed to force policy poll cycle: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		// #nosec G104 - ignore errors when writing HTTP responses so we don't spam our logs during a DoS
		w.Write([]byte(errorMessage))
		return
	}
}
