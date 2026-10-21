package app

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redjohn-ai/redjohn/tui/internal/protocol"
)

// These are transport/protocol contracts with controlled peers, not provider E2E.
type memoryConnection struct{ bytes.Buffer }

func (*memoryConnection) Close() error { return nil }

func testEnvelope(t *testing.T, kind string, payload any) protocol.Envelope {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Envelope{Version: protocol.Version, Type: kind, Payload: raw}
}

func frame(t *testing.T, envelope protocol.Envelope) []byte {
	t.Helper()
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(raw)))
	return append(header, raw...)
}

func TestHandshakeNegotiatesPrivateProtocol(t *testing.T) {
	local, peer := net.Pipe()
	t.Cleanup(func() { local.Close(); peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	backend := make(chan error, 1)
	go func() {
		if err := writeAll(peer, frame(t, testEnvelope(t, "hello", protocol.Hello{Capabilities: protocol.Capabilities}))); err != nil {
			backend <- err
			return
		}
		ready, _, err := newClient(peer).readEnvelope(maxCommandBytes)
		if err == nil && (ready.Type != "ready" || ready.Version != protocol.Version) {
			err = errors.New("client did not acknowledge exact protocol")
		}
		backend <- err
	}()
	if err := newClient(local).Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-backend; err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeRejectsIncompatibleBackend(t *testing.T) {
	for _, kind := range []string{"version", "type", "capabilities"} {
		t.Run(kind, func(t *testing.T) {
			hello := testEnvelope(t, "hello", protocol.Hello{Capabilities: protocol.Capabilities})
			switch kind {
			case "version":
				hello.Version--
			case "type":
				hello.Type = "state"
			case "capabilities":
				hello.Payload = json.RawMessage(`{"capabilities":[]}`)
			}
			connection := &memoryConnection{}
			connection.Write(frame(t, hello))
			if err := newClient(connection).Handshake(); err == nil {
				t.Fatal("incompatible peer activated the client")
			}
			if connection.Len() != 0 {
				t.Fatal("client acknowledged a rejected hello")
			}
		})
	}
}

func TestReadEnforcesSeparateControlAndCollectionLimits(t *testing.T) {
	for _, kind := range []string{"state", "collection_delta", "collection_bootstrap"} {
		t.Run(kind, func(t *testing.T) {
			connection := &memoryConnection{}
			connection.Write(frame(t, testEnvelope(t, kind, map[string]string{"data": strings.Repeat("x", maxCommandBytes)})))
			_, err := newClient(connection).Read()
			if (err != nil) != (kind == "state") {
				t.Fatalf("control/collection limit mismatch: %v", err)
			}
		})
	}
	for _, size := range []uint32{0, maxCollectionBytes + 1, ^uint32(0)} {
		connection := &memoryConnection{}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		connection.Write(header[:])
		if _, err := newClient(connection).Read(); err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("size %d was not rejected before reading a body: %v", size, err)
		}
	}
}

func TestCommandsRemainPendingUntilExactCorrelatedResult(t *testing.T) {
	client := newClient(&memoryConnection{})
	id, err := client.Send("agent.stop", map[string]string{"agent_id": "owned-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send("agent.stop", nil); !errors.Is(err, ErrCommandPending) {
		t.Fatalf("duplicate stop was submitted: %v", err)
	}
	if client.Resolve(id, "app.quit") || client.Resolve("foreign", "agent.stop") {
		t.Fatal("uncorrelated response released a pending command")
	}
	if command, ok := client.ExpectedCommand(id); !ok || command != "agent.stop" {
		t.Fatal("pending command was lost")
	}
	if !client.Resolve(id, "agent.stop") {
		t.Fatal("exact acknowledgement rejected")
	}
	if _, err := client.Send("agent.stop", nil); err != nil {
		t.Fatalf("acknowledged stop could not be retried: %v", err)
	}
}

func TestConcurrentCommandsAreFramedAndDeduplicated(t *testing.T) {
	connection := &memoryConnection{}
	client := newClient(connection)
	var wait sync.WaitGroup
	var accepted int
	var mu sync.Mutex
	for range 20 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := client.Send("agent.stop", nil); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			} else if !errors.Is(err, ErrCommandPending) {
				t.Errorf("unexpected command failure: %v", err)
			}
		}()
	}
	wait.Wait()
	if accepted != 1 {
		t.Fatalf("accepted %d duplicate stops", accepted)
	}
	envelope, _, err := client.readEnvelope(maxCommandBytes)
	if err != nil || envelope.Type != "agent.stop" || connection.Len() != 0 {
		t.Fatalf("concurrent writes corrupted frame: %+v, %v", envelope, err)
	}
}

func TestFailedSendReleasesPendingState(t *testing.T) {
	client := newClient(&memoryConnection{})
	if _, err := client.Send("agent.send_message", strings.Repeat("x", maxCommandBytes)); err == nil {
		t.Fatal("oversize command accepted")
	}
	if _, err := client.Send("agent.send_message", "bounded"); err != nil {
		t.Fatalf("failed send left an unrecoverable pending command: %v", err)
	}
}
