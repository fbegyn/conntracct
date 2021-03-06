package bpf

import "errors"

const (
	errFmtSplitKprobe = "expected string of format 'k(ret)probe/<kernel-symbol>': %s"
	errFmtSymNotFound = "kernel symbol '%s' not found"
	errKernelRelease  = "invalid kernel release version '%s'"
)

var (
	errNotInRange = errors.New("range check did not match any version")

	errProbeStarted    = errors.New("Probe already running")
	errProbeNotStarted = errors.New("Probe is not running")

	errDupConsumer = errors.New("an Consumer with the same name is already registered")
	errNoConsumer  = errors.New("could not find the Consumer to delete")

	errConsumerNil = errors.New("given Consumer is nil")
)
