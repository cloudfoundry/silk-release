package handlers

import (
	"net/http"
	"fmt"
)

type ForcePolicyPollCycle struct {
	PollCycleFunc func() error
}

func (h *ForcePolicyPollCycle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.PollCycleFunc(); err != nil {
		errorMessage := fmt.Sprintf("failed to force policy poll cycle: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(errorMessage))
		return
	}
}