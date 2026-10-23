use crate::protocol::{Envelope, Hello, CAPABILITIES, PROTOCOL_VERSION};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const MAX_COMMAND_BYTES: usize = 64 * 1024;
pub const MAX_COLLECTION_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPendingError {
    pub command: String,
    pub existing_id: String,
}

impl fmt::Display for CommandPendingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "command is already pending: {} ({})",
            self.command, self.existing_id
        )
    }
}

impl std::error::Error for CommandPendingError {}

pub enum TransportStream {
    #[cfg(unix)]
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl TransportStream {
    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            #[cfg(unix)]
            TransportStream::Unix(s) => Ok(TransportStream::Unix(s.try_clone()?)),
            TransportStream::Tcp(s) => Ok(TransportStream::Tcp(s.try_clone()?)),
        }
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            TransportStream::Unix(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)?;
                Ok(())
            }
            TransportStream::Tcp(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)?;
                Ok(())
            }
        }
    }
}

impl Read for TransportStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            TransportStream::Unix(s) => s.read(buf),
            TransportStream::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for TransportStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            TransportStream::Unix(s) => s.write(buf),
            TransportStream::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            TransportStream::Unix(s) => s.flush(),
            TransportStream::Tcp(s) => s.flush(),
        }
    }
}

#[derive(Default)]
struct PendingBook {
    pending: HashMap<String, String>,
    pending_by_key: HashMap<String, String>,
    request_key_by_id: HashMap<String, String>,
}

#[derive(Clone)]
pub struct Client {
    reader: Arc<Mutex<TransportStream>>,
    writer: Arc<Mutex<TransportStream>>,
    seq: Arc<AtomicU64>,
    book: Arc<Mutex<PendingBook>>,
}

impl Client {
    pub fn from_stream(stream: TransportStream) -> io::Result<Self> {
        let writer = stream.try_clone()?;
        Ok(Self {
            reader: Arc::new(Mutex::new(stream)),
            writer: Arc::new(Mutex::new(writer)),
            seq: Arc::new(AtomicU64::new(0)),
            book: Arc::new(Mutex::new(PendingBook::default())),
        })
    }

    #[cfg(unix)]
    pub fn connect_inherited(fd_value: &str) -> Result<Self, String> {
        let fd_num: i32 = fd_value
            .trim()
            .parse::<i32>()
            .map_err(|e| format!("invalid REDJOHN_TUI_FD: {e}"))?;
        if fd_num < 0 {
            return Err(format!("invalid REDJOHN_TUI_FD {fd_num}"));
        }
        // SAFETY: REDJOHN_TUI_FD is an open socketpair descriptor passed exclusively to this child process.
        let stream = unsafe { UnixStream::from_raw_fd(fd_num as RawFd) };
        Self::from_stream(TransportStream::Unix(stream))
            .map_err(|e| format!("open inherited TUI connection: {e}"))
    }

    pub fn connect_from_environment() -> Result<Self, String> {
        #[cfg(unix)]
        if let Ok(fd) = std::env::var("REDJOHN_TUI_FD") {
            std::env::remove_var("REDJOHN_TUI_FD");
            if !fd.trim().is_empty() {
                return Self::connect_inherited(&fd);
            }
        }

        let address = std::env::var("REDJOHN_TUI_ADDR").unwrap_or_default();
        let token = std::env::var("REDJOHN_TUI_TOKEN").unwrap_or_default();
        std::env::remove_var("REDJOHN_TUI_ADDR");
        std::env::remove_var("REDJOHN_TUI_TOKEN");

        if address.trim().is_empty() || token.is_empty() {
            return Err(
                "REDJOHN_TUI_FD or REDJOHN_TUI_ADDR and REDJOHN_TUI_TOKEN are required".to_string(),
            );
        }

        let sock_addr: SocketAddr = address
            .parse()
            .map_err(|e| format!("invalid REDJOHN_TUI_ADDR: {e}"))?;
        let mut stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10))
            .map_err(|e| format!("connect to TUI backend: {e}"))?;
        stream
            .write_all(token.as_bytes())
            .map_err(|e| format!("authenticate to TUI backend: {e}"))?;
        Self::from_stream(TransportStream::Tcp(stream))
            .map_err(|e| format!("clone TUI connection: {e}"))
    }

    fn read_envelope(&self, maximum: usize) -> Result<(Envelope, usize), String> {
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| "reader mutex poisoned".to_string())?;
        let mut header = [0u8; 4];
        reader
            .read_exact(&mut header)
            .map_err(|e| format!("read header: {e}"))?;
        let size = u32::from_be_bytes(header) as usize;
        if size == 0 || size > maximum {
            return Err(format!("invalid TUI IPC message size: {size}"));
        }
        let mut raw = vec![0u8; size];
        reader
            .read_exact(&mut raw)
            .map_err(|e| format!("read body: {e}"))?;
        let envelope: Envelope =
            serde_json::from_slice(&raw).map_err(|e| format!("decode envelope: {e}"))?;
        Ok((envelope, size))
    }

    pub fn read(&self) -> Result<Envelope, String> {
        let (envelope, size) = self.read_envelope(MAX_COLLECTION_BYTES)?;
        if envelope.msg_type != "collection_bootstrap"
            && envelope.msg_type != "collection_delta"
            && size > MAX_COMMAND_BYTES
        {
            return Err(format!(
                "TUI control message exceeds {MAX_COMMAND_BYTES} bytes"
            ));
        }
        Ok(envelope)
    }

    pub fn handshake(&self) -> Result<(), String> {
        {
            let r = self
                .reader
                .lock()
                .map_err(|_| "reader mutex poisoned".to_string())?;
            let _ = r.set_timeout(Some(Duration::from_secs(10)));
        }
        let result = (|| {
            let (envelope, _) = self
                .read_envelope(MAX_COMMAND_BYTES)
                .map_err(|e| format!("read protocol hello: {e}"))?;
            if envelope.version != PROTOCOL_VERSION {
                return Err(format!(
                    "protocol mismatch: backend={} client={}",
                    envelope.version, PROTOCOL_VERSION
                ));
            }
            if envelope.msg_type != "hello" {
                return Err(format!(
                    "protocol handshake expected hello, received {:?}",
                    envelope.msg_type
                ));
            }
            let hello: Hello = serde_json::from_value(envelope.payload)
                .map_err(|e| format!("decode protocol hello: {e}"))?;
            let expected: Vec<String> = CAPABILITIES.iter().map(|s| (*s).to_string()).collect();
            if hello.capabilities != expected {
                return Err("protocol capability mismatch".to_string());
            }
            let ready_payload = serde_json::to_value(Hello {
                capabilities: expected,
            })
            .map_err(|e| format!("encode ready payload: {e}"))?;
            self.send_envelope(
                &Envelope {
                    version: PROTOCOL_VERSION,
                    msg_type: "ready".to_string(),
                    request_id: String::new(),
                    payload: ready_payload,
                },
                MAX_COMMAND_BYTES,
            )
        })();
        {
            if let Ok(r) = self.reader.lock() {
                let _ = r.set_timeout(None);
            }
        }
        result
    }

    fn send_envelope(&self, envelope: &Envelope, maximum: usize) -> Result<(), String> {
        let raw = serde_json::to_vec(envelope).map_err(|e| format!("encode IPC envelope: {e}"))?;
        if raw.len() > maximum {
            return Err(format!("TUI IPC message exceeds {maximum} bytes"));
        }
        let mut framed = Vec::with_capacity(4 + raw.len());
        framed.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        framed.extend_from_slice(&raw);
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| "writer mutex poisoned".to_string())?;
        writer
            .write_all(&framed)
            .map_err(|e| format!("write IPC frame: {e}"))?;
        writer.flush().map_err(|e| format!("flush IPC frame: {e}"))
    }

    fn pending_key(command: &str, payload: &Value) -> String {
        if command == "collection.resync" {
            let col = payload
                .get("collection")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            return format!("{command}:{col}");
        }
        if command == "setup.add_target" {
            let target = payload
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            return format!("{command}:{target}");
        }
        command.to_string()
    }

    pub fn send(&self, command: &str, payload: Value) -> Result<String, String> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let request_id = format!("rs-{seq}");
        let key = Self::pending_key(command, &payload);
        let envelope = Envelope {
            version: PROTOCOL_VERSION,
            msg_type: command.to_string(),
            request_id: request_id.clone(),
            payload,
        };

        let mut book = self
            .book
            .lock()
            .map_err(|_| "pending book poisoned".to_string())?;
        if let Some(existing) = book.pending_by_key.get(&key) {
            return Err(CommandPendingError {
                command: command.to_string(),
                existing_id: existing.clone(),
            }
            .to_string());
        }
        book.pending.insert(request_id.clone(), command.to_string());
        book.pending_by_key.insert(key.clone(), request_id.clone());
        book.request_key_by_id
            .insert(request_id.clone(), key.clone());
        drop(book);

        if let Err(err) = self.send_envelope(&envelope, MAX_COMMAND_BYTES) {
            if let Ok(mut book) = self.book.lock() {
                book.pending.remove(&request_id);
                book.pending_by_key.remove(&key);
                book.request_key_by_id.remove(&request_id);
            }
            return Err(err);
        }
        Ok(request_id)
    }

    pub fn resolve(&self, request_id: &str, command: &str) -> bool {
        if request_id.is_empty() {
            return false;
        }
        let Ok(mut book) = self.book.lock() else {
            return false;
        };
        if book.pending.get(request_id).map(|s| s.as_str()) != Some(command) {
            return false;
        }
        book.pending.remove(request_id);
        if let Some(key) = book.request_key_by_id.remove(request_id) {
            book.pending_by_key.remove(&key);
        }
        true
    }

    pub fn expected_command(&self, request_id: &str) -> Option<String> {
        let book = self.book.lock().ok()?;
        book.pending.get(request_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[cfg(unix)]
    fn make_pair() -> (Client, UnixStream) {
        let (client_sock, server_sock) = UnixStream::pair().expect("unix pair");
        let client = Client::from_stream(TransportStream::Unix(client_sock)).expect("client");
        (client, server_sock)
    }

    #[cfg(unix)]
    fn write_frame(stream: &mut UnixStream, value: &Value) {
        let raw = serde_json::to_vec(value).expect("serialize");
        let mut buf = Vec::with_capacity(4 + raw.len());
        buf.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        buf.extend_from_slice(&raw);
        stream.write_all(&buf).expect("write");
    }

    #[cfg(unix)]
    fn read_frame(stream: &mut UnixStream) -> Value {
        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr).expect("read hdr");
        let len = u32::from_be_bytes(hdr) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).expect("read body");
        serde_json::from_slice(&body).expect("parse json")
    }

    #[cfg(unix)]
    #[test]
    fn test_handshake_success() {
        let (client, mut server) = make_pair();
        let handle = std::thread::spawn(move || {
            write_frame(
                &mut server,
                &json!({
                    "version": 3,
                    "type": "hello",
                    "payload": {
                        "capabilities": CAPABILITIES,
                    }
                }),
            );
            read_frame(&mut server)
        });
        client.handshake().expect("handshake should succeed");
        let reply = handle.join().expect("server thread");
        assert_eq!(reply["version"], 3);
        assert_eq!(reply["type"], "ready");
        assert_eq!(reply["payload"]["capabilities"], json!(CAPABILITIES));
    }

    #[cfg(unix)]
    #[test]
    fn test_handshake_rejects_wrong_version() {
        let (client, mut server) = make_pair();
        write_frame(
            &mut server,
            &json!({
                "version": 2,
                "type": "hello",
                "payload": { "capabilities": CAPABILITIES }
            }),
        );
        let err = client.handshake().expect_err("should fail");
        assert!(err.contains("protocol mismatch"), "got: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn test_pending_command_deduplication_and_resync_keys() {
        let (client, mut server) = make_pair();
        let id1 = client
            .send("agent.stop", json!({"agent_id": "owned-worker"}))
            .expect("first send");
        let dup = client.send("agent.stop", json!({"agent_id": "owned-worker"}));
        assert!(dup.is_err());

        let r1 = client
            .send("collection.resync", json!({"collection": "events"}))
            .expect("resync events");
        let r2 = client
            .send(
                "collection.resync",
                json!({"collection": "vulnerabilities"}),
            )
            .expect("resync vulns");
        assert_ne!(r1, r2);

        let _ = read_frame(&mut server);
        assert!(!client.resolve(&id1, "app.quit"));
        assert!(!client.resolve("foreign", "agent.stop"));
        assert_eq!(client.expected_command(&id1).as_deref(), Some("agent.stop"));
        assert!(client.resolve(&id1, "agent.stop"));
        assert!(client.resolve(&r1, "collection.resync"));
        assert!(client.resolve(&r2, "collection.resync"));
    }

    #[cfg(unix)]
    #[test]
    fn test_read_enforces_separate_control_and_collection_limits() {
        for kind in ["state", "collection_delta", "collection_bootstrap"] {
            let (client, mut server) = make_pair();
            let big = "x".repeat(MAX_COMMAND_BYTES);
            let writer = std::thread::spawn(move || {
                write_frame(
                    &mut server,
                    &json!({
                        "version": 3,
                        "type": kind,
                        "payload": { "data": big }
                    }),
                );
            });
            let res = client.read();
            let _ = writer.join();
            assert_eq!(res.is_err(), kind == "state");
        }
        for bad_size in [0u32, (MAX_COLLECTION_BYTES as u32) + 1, u32::MAX] {
            let (client, mut server) = make_pair();
            server
                .write_all(&bad_size.to_be_bytes())
                .expect("write bad size");
            let err = client.read().expect_err("should reject bad size");
            assert!(err.contains("invalid TUI IPC message size"), "got: {err}");
        }
    }
}
