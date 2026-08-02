package api

import "time"

const (
	timeoutCreateJob = 15 * time.Second
	timeoutSubmit    = 2 * time.Minute
)
