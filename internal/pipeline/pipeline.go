package pipeline

import (
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/ti-mo/conntracct/internal/sinks"
	"github.com/ti-mo/conntracct/pkg/bpf"
)

// Pipeline is a structure representing the conntracct
// data ingest pipeline.
type Pipeline struct {
	Stats Stats

	init  sync.Once
	start sync.Once

	// Protected by init.
	acctProbe       *bpf.Probe
	acctUpdateChan  chan bpf.Event
	acctDestroyChan chan bpf.Event

	acctSinkMu sync.RWMutex
	acctSinks  []sinks.Sink
}

// Stats holds various statistics and information about the
// data processing pipeline.
type Stats struct {

	// total amount of event structs received from kernel
	EventsTotal uint64 `json:"events_total"`
	// total amount of bytes read from the BPF perf buffer(s)
	AcctBytesTotal uint64 `json:"bytes_total"`

	// update events / bytes
	EventsUpdate    uint64 `json:"events_update"`
	AcctBytesUpdate uint64 `json:"bytes_update"`

	// destroy events / bytes
	EventsDestroy    uint64 `json:"events_destroy"`
	AcctBytesDestroy uint64 `json:"bytes_destroy"`

	// length of the Event queues
	AcctUpdateQueueLen  uint64 `json:"update_queue_length"`
	AcctDestroyQueueLen uint64 `json:"destroy_queue_length"`
}

// New creates a new Pipeline structure.
func New() *Pipeline {
	return &Pipeline{}
}

// RegisterSink registers a sink for accounting data
// to the pipeline.
func (p *Pipeline) RegisterSink(s sinks.Sink) error {

	// Make sure the sink is initialized before using.
	if !s.IsInit() {
		return errSinkNotInit
	}

	// Warn the user about conntrack wait timeouts
	// if the sink consumes destroy events.
	if s.WantDestroy() {
		warnSysctl()
	}

	p.acctSinkMu.Lock()
	defer p.acctSinkMu.Unlock()

	// Add the acctSink to the pipeline.
	p.acctSinks = append(p.acctSinks, s)

	log.Infof("Registered accounting sink '%s' to pipeline", s.Name())

	return nil
}

// GetSinks gets a list of accounting sinks registered to the pipeline.
func (p *Pipeline) GetSinks() []sinks.Sink {

	p.acctSinkMu.RLock()
	defer p.acctSinkMu.RUnlock()

	return p.acctSinks
}

// Stop gracefully tears down all resources of a Pipeline structure.
func (p *Pipeline) Stop() error {
	// Stop the accounting probe.
	return p.acctProbe.Stop()
}
