mod ipc;
mod protocol;
mod render;
mod state;
mod theme;
mod ui;

use crate::ipc::Client;
use crate::protocol::Envelope;
use crate::state::AppState;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as TermEvent, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::sync::mpsc;
use std::time::{Duration, Instant};

enum WireEvent {
    Envelope(Envelope),
    Error(String),
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
}

fn main() {
    let version = std::env::var("REDJOHN_VERSION").ok();
    let client = match Client::connect_from_environment() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("connect to RedJohn backend: {err}");
            std::process::exit(1);
        }
    };
    if let Err(err) = client.handshake() {
        eprintln!("negotiate RedJohn TUI protocol: {err}");
        std::process::exit(1);
    }

    let (tx, rx) = mpsc::channel::<WireEvent>();
    let reader_client = client.clone();
    std::thread::spawn(move || loop {
        match reader_client.read() {
            Ok(env) => {
                if tx.send(WireEvent::Envelope(env)).is_err() {
                    break;
                }
            }
            Err(err) => {
                let _ = tx.send(WireEvent::Error(err));
                break;
            }
        }
    });

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        default_hook(info);
    }));

    if let Err(err) = enable_raw_mode() {
        eprintln!("run TUI: {err}");
        std::process::exit(1);
    }
    let mut stdout = io::stdout();
    if let Err(err) = execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
        let _ = disable_raw_mode();
        eprintln!("run TUI: {err}");
        std::process::exit(1);
    }

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(err) => {
            restore_terminal();
            eprintln!("run TUI: {err}");
            std::process::exit(1);
        }
    };

    let mut app_state = AppState::new(Some(client), version);
    let tick_rate = Duration::from_millis(60);
    let mut last_tick = Instant::now();
    let mut prev_splash = app_state.show_splash;
    let mut prev_ready = app_state.ready;

    loop {
        while let Ok(ev) = rx.try_recv() {
            match ev {
                WireEvent::Envelope(envelope) => app_state.handle_envelope(envelope),
                WireEvent::Error(err) => app_state.handle_wire_error(&err),
            }
            if app_state.quitting {
                break;
            }
        }
        if app_state.quitting {
            break;
        }

        if prev_splash != app_state.show_splash || prev_ready != app_state.ready {
            let _ = terminal.clear();
            prev_splash = app_state.show_splash;
            prev_ready = app_state.ready;
        }

        if let Err(err) = terminal.draw(|f| ui::draw(f, &mut app_state)) {
            app_state.fatal_error = Some(err.to_string());
            break;
        }

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        match event::poll(timeout) {
            Ok(true) => match event::read() {
                Ok(term_ev) => match term_ev {
                    TermEvent::Key(key) if key.kind != KeyEventKind::Release => {
                        app_state.handle_key(key);
                    }
                    TermEvent::Mouse(mouse) => {
                        app_state.handle_mouse(mouse);
                    }
                    TermEvent::Resize(w, h) => {
                        app_state.width = w;
                        app_state.height = h;
                    }
                    _ => {}
                },
                Err(_) => break,
            },
            Ok(false) => {}
            Err(_) => break,
        }

        if last_tick.elapsed() >= tick_rate {
            app_state.tick();
            last_tick = Instant::now();
        }

        if app_state.quitting {
            break;
        }
    }

    restore_terminal();

    if let Some(err) = app_state.fatal_error {
        eprintln!("run TUI: {err}");
        std::process::exit(1);
    }
}
