package app

import (
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/redjohn-ai/redjohn/tui/internal/protocol"
)

func sizedModel() Model {
	m := New(nil)
	m.width, m.height = 120, 40
	m.showSplash = false
	return m
}

func TestStateRevisionPreservesStreamedHistory(t *testing.T) {
	m := sizedModel()
	m.snapshot.Events = []protocol.Event{{ID: "proof", Version: 1}}
	m.snapshot.Agents = []protocol.Agent{{ID: "worker", Status: "running"}}
	m.handleEnvelope(testEnvelope(t, "state", protocol.StateUpdate{Revision: 2, State: protocol.Snapshot{ScanState: "running"}}))
	m.handleEnvelope(testEnvelope(t, "state", protocol.StateUpdate{Revision: 1, State: protocol.Snapshot{ScanState: "stale"}}))
	if m.stateRevision != 2 || m.snapshot.ScanState != "running" || len(m.snapshot.Events) != 1 || len(m.snapshot.Agents) != 1 {
		t.Fatalf("stale state replaced newer state or history: %+v", m.snapshot)
	}
}

func TestCollectionBootstrapIsAtomicAndRejectsDuplicateIDs(t *testing.T) {
	m := sizedModel()
	m.snapshot.Events = []protocol.Event{{ID: "old"}}
	first := protocol.CollectionBootstrap{Collection: "events", Revision: 1, Cursor: 0, NextCursor: 1, Items: []json.RawMessage{json.RawMessage(`{"id":"new","version":1}`)}}
	m.handleEnvelope(testEnvelope(t, "collection_bootstrap", first))
	if m.snapshot.Events[0].ID != "old" {
		t.Fatal("partial bootstrap exposed incomplete history")
	}
	last := protocol.CollectionBootstrap{Collection: "events", Revision: 1, Cursor: 1, NextCursor: 2, Done: true, Items: []json.RawMessage{json.RawMessage(`{"id":"new","version":1}`)}}
	m.handleEnvelope(testEnvelope(t, "collection_bootstrap", last))
	if m.snapshot.Events[0].ID != "old" || m.collectionRevisions["events"] != 0 {
		t.Fatal("duplicate bootstrap replaced authoritative history")
	}
	first.Done = true
	m.handleEnvelope(testEnvelope(t, "collection_bootstrap", first))
	if len(m.snapshot.Events) != 1 || m.snapshot.Events[0].ID != "new" || m.collectionRevisions["events"] != 1 {
		t.Fatal("complete bootstrap was not committed")
	}
}

func TestCollectionDeltaRejectsStaleEventsAndRollsBackWholeBatch(t *testing.T) {
	m := sizedModel()
	m.snapshot.Events = []protocol.Event{{ID: "existing", Version: 2}}
	operations := []protocol.CollectionOperation{
		{Op: "upsert", Item: json.RawMessage(`{"id":"new","version":1}`)},
		{Op: "upsert", Item: json.RawMessage(`{"id":"existing","version":1}`)},
	}
	if m.applyCollectionOperations("events", operations) || len(m.snapshot.Events) != 1 || m.snapshot.Events[0].Version != 2 {
		t.Fatal("invalid delta partly changed history")
	}
	operations[1].Item = json.RawMessage(`{"id":"existing","version":3}`)
	if !m.applyCollectionOperations("events", operations) || len(m.snapshot.Events) != 2 || m.snapshot.Events[0].Version != 3 {
		t.Fatal("newer event delta rejected")
	}
}

func TestCollectionGapRequestsOneResyncPerCollection(t *testing.T) {
	connection := &memoryConnection{}
	m := sizedModel()
	m.client = newClient(connection)
	gap := testEnvelope(t, "collection_delta", protocol.CollectionDelta{Collection: "events", BaseRevision: 9, Revision: 10, Done: true})
	cmd := m.handleEnvelope(gap)
	if cmd == nil || m.handleEnvelope(gap) != nil {
		t.Fatal("missing or duplicate collection resync")
	}
	if result, ok := cmd().(sentMsg); !ok || result.err != nil || result.collection != "events" {
		t.Fatalf("invalid resync request: %+v", result)
	}
	envelope, err := m.client.Read()
	if err != nil || envelope.Type != "collection.resync" || string(envelope.Payload) != `{"collection":"events"}` {
		t.Fatalf("wrong resync frame: %+v %v", envelope, err)
	}
}

func TestStopRequiresExplicitConfirmationAndTargetsSelectedAgent(t *testing.T) {
	connection := &memoryConnection{}
	m := sizedModel()
	m.client = newClient(connection)
	m.snapshot.Agents = []protocol.Agent{{ID: "worker", Status: "running"}}
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.modal != modalStop || m.modalChoice != 1 || cmd != nil || connection.Len() != 0 {
		t.Fatal("escape stopped a worker without confirmation")
	}
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if cmd != nil || connection.Len() != 0 || m.modal != modalNone {
		t.Fatal("default cancel choice sent a stop")
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	m = updated.(Model)
	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("confirmed stop did not produce command")
	}
	cmd()
	envelope, err := m.client.Read()
	if err != nil || envelope.Type != "agent.stop" || string(envelope.Payload) != `{"agent_id":"worker"}` {
		t.Fatalf("stop did not target selected worker: %+v %v", envelope, err)
	}
}

func TestTerminalFailureIsFatalAndRestoresExitPath(t *testing.T) {
	for _, msg := range []tea.Msg{
		wireErrMsg{err: io.EOF},
		wireMsg(protocol.Envelope{Version: protocol.Version - 1, Type: "state"}),
	} {
		m := sizedModel()
		updated, cmd := m.Update(msg)
		if updated.(Model).FatalError() == nil || cmd == nil {
			t.Fatal("backend failure was hidden as a successful TUI exit")
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Fatal("backend failure did not close terminal UI")
		}
	}
}

func TestCommandErrorsDoNotAcceptUncorrelatedResults(t *testing.T) {
	client := newClient(&memoryConnection{})
	m := sizedModel()
	m.client = client
	id, err := client.Send("agent.stop", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := testEnvelope(t, "command_result", protocol.CommandResult{Command: "app.quit", OK: false, Error: &protocol.CommandError{Message: "foreign"}})
	result.RequestID = id
	m.handleEnvelope(result)
	if m.errorText != "" {
		t.Fatal("uncorrelated error reached user")
	}
	result = testEnvelope(t, "command_result", protocol.CommandResult{Command: "agent.stop", OK: false, Error: &protocol.CommandError{Code: "command_failed", Message: "worker already exited"}})
	result.RequestID = id
	m.handleEnvelope(result)
	if m.errorText != "worker already exited" {
		t.Fatal("correlated failure did not reach user")
	}
	if _, pending := client.ExpectedCommand(id); pending {
		t.Fatal("completed error cannot be retried")
	}
}

func TestReportCopyCannotEscapeMarkdownFences(t *testing.T) {
	code := "print('owned')\n````\n# injected heading"
	report := vulnerabilityMarkdownReport(map[string]any{"title": "Owned finding", "severity": "high", "poc_script_code": code})
	if !strings.Contains(report, "`````python\n"+code+"\n`````") {
		t.Fatalf("PoC report lost safe fence: %s", report)
	}
}

func TestAgentDeltaPreservesSelectionAcrossReorderingAndDeletion(t *testing.T) {
	m := sizedModel()
	m.snapshot.Agents = []protocol.Agent{{ID: "first"}, {ID: "selected", Status: "running"}}
	m.selectedAgent = 1
	if !m.applyCollectionOperations("agents", []protocol.CollectionOperation{{Op: "delete", ID: "first"}}) {
		t.Fatal("valid delete rejected")
	}
	if m.selectedAgent != 0 || m.selectedAgentID() != "selected" || !reflect.DeepEqual(m.snapshot.Agents, []protocol.Agent{{ID: "selected", Status: "running"}}) {
		t.Fatal("agent selection drifted to another worker")
	}
}
