package common

import (
	"code.cloudfoundry.org/lager/v3/lagerflags"
	"fmt"
	"github.com/pkg/errors"
	"math"
	"net"
	"time"
)

type temporaryError interface {
	Temporary() bool
}

type RetryableFunc[T any] func() (T, error)

func GetLagerConfig() lagerflags.LagerConfig {
	lagerConfig := lagerflags.DefaultLagerConfig()
	lagerConfig.TimeFormat = lagerflags.FormatRFC3339
	return lagerConfig
}

// RetryWithBackoff retries a given function up to maxRetries times, with exponential backoff between attempts.
// interval is the initial interval between retries in milliseconds.
// T is a generic type parameter representing the return type of the function being retried.
// fn is the function to be retried, which returns a value of type T and an error.
func RetryWithBackoff[T any](interval int, maxRetries int, fn RetryableFunc[T]) (T, error) {
	var result T
	var err error
	retryInterval := time.Duration(interval) * time.Millisecond

	for retry := 0; retry < maxRetries; retry++ {
		// Attempt the operation
		result, err = fn()
		if err == nil {
			return result, nil // Success
		}

		// If the error is retryable, wait and retry
		if isRetryableError(err) {
			time.Sleep(time.Duration(math.Pow(2, float64(retry))) * retryInterval)
			continue
		}

		// If error is not retryable, return it immediately
		return result, err
	}

	// Retries exhausted, return the last error
	return result, fmt.Errorf("failed after %d maxRetries: %w", maxRetries, err)
}

func isRetryableError(err error) bool {
	var tempErr temporaryError

	if errors.As(err, &tempErr) {
		return tempErr.Temporary()
	}

	return false
}

func IsIPv6Enabled() bool {
	testAddress := "[::1]:0"

	addr, err := net.ResolveUDPAddr("udp6", testAddress)
	if err != nil {
		return false
	}

	conn, err := net.ListenUDP("udp6", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}
