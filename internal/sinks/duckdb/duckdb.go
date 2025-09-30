package duckdb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"database/sql"

	"github.com/marcboeker/go-duckdb/v2"
	_ "github.com/marcboeker/go-duckdb/v2"
	log "github.com/sirupsen/logrus"

	"github.com/ti-mo/conntracct/internal/config"
	"github.com/ti-mo/conntracct/internal/sinks/types"
	"github.com/ti-mo/conntracct/pkg/bpf"
)

// ClickhouseSink is an accounting sink implementing a ClickHouse client.
// It is only intended for flow archival (completed/destroyed flows).
type DuckDBSink struct {

	// Sink had Init() called on it successfully.
	init bool

	// Sink's configuration object.
	config config.SinkConfig

	// ClickHouse driver connection handle.
	conn *duckdb.Connector

	appender *duckdb.Appender

	// Channel the send workers receive batches on.
	sendChan chan batch

	// Data point batch.
	batchMu sync.Mutex
	batch   batch

	// Sink stats.
	stats types.SinkStats

	// Save all events as time series or only track latest state
	latestValues bool
}

// New returns a new ClickHouse accounting sink.
func New() DuckDBSink {
	return DuckDBSink{}
}

// Init initializes the ClickHouse accounting sink.
func (s *DuckDBSink) Init(sc config.SinkConfig) error {

	if sc.Name == "" {
		return errEmptySinkName
	}

	// Configure default values on the sink configuration.
	sinkDefaults(&sc)

	// Create a ClickHouse client.
	var err error
	s.conn, err = duckdb.NewConnector(sc.Database, nil)
	if err != nil {
		return fmt.Errorf("error creating duckdb connector: %w", err)
	}

	err = s.initDatabase()
	if err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}

	conn, err := s.conn.Connect(context.Background())
	if err != nil {
		return fmt.Errorf("error connecting to duckdb: %w", err)
	}
	defer conn.Close()

	s.appender, err = duckdb.NewAppenderFromConn(conn, "", "flows")
	if err != nil {
		return fmt.Errorf("failed to create appender from connection: %w", err)
	}
	defer s.appender.Close()

	// Start workers.
	s.sendChan = make(chan batch, 64)
	log.WithField("sink", sc.Name).Debugf("configuring batch setup")

	s.newBatch() // initial empty batch

	go s.sendWorker()
	go s.tickWorker(time.Second * 5)

	// Mark the sink as initialized.
	s.init = true

	return nil
}

func (s *DuckDBSink) initDatabase() error {
	db := sql.OpenDB(s.conn)
	defer db.Close()

	// ctx := context.Background()
	// tableName := fmt.Sprintf("%s_flows", s.config.Database)
	// err := s.appender.AppendRow(
	_, err := db.Exec(`
CREATE TABLE flows (
  id INTEGER,
  FlowID integer,
  Hostname VARCHAR,
  State VARCHAR,
  BytesOrig integer,
  BytesRet integer,
  BytesTotal integer,
  PacketsOrig integer,
  PacketsRet integer,
  PacketsTotal integer,
  Connmark integer,
  SrcAddr VARCHAR,
  SrcPort integer,
  DstAddr VARCHAR,
  DstPort integer,
  NetNS VARCHAR,
  ProtoName VARCHAR,
  start timestamp,
  ts timestamp,
)
`)
	if err != nil {
		return fmt.Errorf("query execution failed: %w", err)
	}
	return nil
}

// PushUpdate pushes an update event into the buffer of the ClickHouse accounting sink.
func (s *DuckDBSink) PushUpdate(e bpf.Event) {
	// Wrap the BPF event in a structure to be inserted into the database.
	ce := event{
		State: "established",
		Event: &e,
	}

	s.transformEvent(&ce)
	s.addBatchEvent(&ce)
}

// PushDestroy pushes a destroy event into the buffer of the ClickHouse accounting sink.
func (s *DuckDBSink) PushDestroy(e bpf.Event) {
	// Wrap the BPF event in a structure to be inserted into the database.
	ce := event{
		State: "finished",
		Event: &e,
	}

	s.transformEvent(&ce)
	s.addBatchEvent(&ce)
}

// IsInit returns true if the ClickHouse accounting sink was successfully initialized.
func (s *DuckDBSink) IsInit() bool {
	return s.init
}

// Name returns the ClickHouse sink's name.
func (s *DuckDBSink) Name() string {
	return s.config.Name
}

// Stats returns the ClickHouse accounting sink's statistics structure.
func (s *DuckDBSink) Stats() types.SinkStats {
	return s.stats.Get()
}

// WantUpdate returns true if the ClickHouse sink is configured to accept update events.
func (s *DuckDBSink) WantUpdate() bool {
	return true
}

// WantDestroy returns true if the ClickHouse sink is configured to accept destroy events.
func (s *DuckDBSink) WantDestroy() bool {
	return true
}
