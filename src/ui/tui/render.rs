//! TUI runtime loop and top-level orchestration.

use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::{CrosstermBackend, Terminal},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tui_big_text::{BigText, PixelSize};

use super::connection;
use super::transfer_panel;
use super::types::{TransferProgress, TuiConfig};
use super::ui::generate_compact_qr;
use crate::server::progress::ProgressTracker;

/// Render and poll interval
const RENDER_INTERVAL: Duration = Duration::from_millis(50);
const COPY_FEEDBACK_DURATION: Duration = Duration::from_millis(1200);

const ACCENT: Color = Color::Rgb(248, 190, 117);
const LOGO_PIXEL_SIZE: PixelSize = PixelSize::Sextant;
const PANEL_SIDE_INSET_WIDE: u16 = 6;
const PANEL_SIDE_INSET_MEDIUM: u16 = 4;

struct LayoutAreas {
    logo: Rect,
    connection: Rect,
    transfer: Rect,
    status: Option<Rect>,
}

fn panel_side_inset(frame_width: u16) -> u16 {
    if frame_width >= 120 {
        PANEL_SIDE_INSET_WIDE
    } else if frame_width >= 80 {
        PANEL_SIDE_INSET_MEDIUM
    } else {
        0
    }
}

fn inset_horizontal(area: Rect, inset: u16) -> Rect {
    if inset == 0 || area.width <= inset.saturating_mul(2) {
        return area;
    }

    Rect {
        x: area.x.saturating_add(inset),
        y: area.y,
        width: area.width.saturating_sub(inset.saturating_mul(2)),
        height: area.height,
    }
}

fn calculate_layout(
    area: Rect,
    has_status: bool,
    show_qr: bool,
    qr_code: &str,
    show_url: bool,
) -> LayoutAreas {
    let connection_height = if show_qr && !qr_code.is_empty() {
        let qr_lines = qr_code.lines().count() as u16;
        if show_url {
            (qr_lines + 7).max(13)
        } else {
            (qr_lines + 3).max(10)
        }
    } else {
        8
    };

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if has_status {
            vec![
                Constraint::Length(1),
                Constraint::Length(6),
                Constraint::Length(connection_height),
                Constraint::Min(4),
                Constraint::Length(3),
            ]
        } else {
            vec![
                Constraint::Length(1),
                Constraint::Length(6),
                Constraint::Length(connection_height),
                Constraint::Min(4),
            ]
        })
        .split(area);

    LayoutAreas {
        logo: main_chunks[1],
        connection: main_chunks[2],
        transfer: main_chunks[3],
        status: if has_status {
            Some(main_chunks[4])
        } else {
            None
        },
    }
}

/// Mutable TUI state mirrored from transfer/status streams.
#[derive(Debug, Default)]
pub struct TuiState {
    pub transfer: TransferProgress,
    pub status_message: Option<String>,
    copy_feedback_expires_at: Option<Instant>,
}

/// Owns TUI runtime, state updates, and frame rendering.
pub struct TransferUI {
    config: TuiConfig,
    state: TuiState,
    tracker: Arc<ProgressTracker>,
    status_rx: watch::Receiver<Option<String>>,
    compact_qr_code: Option<String>,
}

impl TransferUI {
    pub fn new(
        config: TuiConfig,
        tracker: Arc<ProgressTracker>,
        status_rx: watch::Receiver<Option<String>>,
    ) -> Self {
        Self {
            compact_qr_code: generate_compact_qr(&config.url),
            config,
            state: TuiState::default(),
            tracker,
            status_rx,
        }
    }

    /// Main event loop
    pub async fn run(mut self, cancel: CancellationToken) -> io::Result<()> {
        install_panic_hook();

        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Initial render
        terminal.draw(|f| self.render(f))?;

        loop {
            let should_quit = tokio::select! {
                // Check for cancellation
                _ = cancel.cancelled() => {
                    true
                }

                // Status message update
                result = self.status_rx.changed() => {
                    if result.is_ok() {
                        self.state.status_message = self.status_rx.borrow().clone();
                    }
                    false
                }

                // Input polling and render tick
                _ = tokio::time::sleep(RENDER_INTERVAL) => {
                    self.handle_input()?
                }
            };

            if should_quit {
                break;
            }

            // Read latest state from tracker
            self.state.transfer = self.tracker.snapshot();

            // Check if transfer is complete
            if self.state.transfer.is_complete() {
                // Final render to show completed state
                terminal.draw(|f| self.render(f))?;
                // Give a moment to see final state
                tokio::time::sleep(Duration::from_millis(500)).await;
                break;
            }

            terminal.draw(|f| self.render(f))?;
        }

        // Cleanup
        cleanup_terminal(&mut terminal)?;
        Ok(())
    }

    fn copy_feedback_text_style(&self) -> (&'static str, Style) {
        if self
            .state
            .copy_feedback_expires_at
            .is_some_and(|expires_at| Instant::now() <= expires_at)
        {
            return ("copied", Style::default().fg(Color::Green));
        }

        (
            "c copy",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::DIM),
        )
    }

    fn set_copy_feedback(&mut self) {
        self.state.copy_feedback_expires_at = Some(Instant::now() + COPY_FEEDBACK_DURATION);
    }

    /// Check for keyboard input
    fn handle_input(&mut self) -> io::Result<bool> {
        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            return Ok(true);
                        }
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            return Ok(true);
                        }
                        KeyCode::Char('c') => {
                            self.set_copy_feedback();
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(false)
    }

    /// Render the logo at the top of the screen
    fn render_logo(&self, frame: &mut Frame, area: Rect) {
        let logo_area = Rect {
            x: area.x,
            y: area.y.saturating_add(1),
            width: area.width,
            height: area.height.saturating_sub(1),
        };
        let logo = BigText::builder()
            .pixel_size(LOGO_PIXEL_SIZE)
            .lines(vec!["ARCHDROP".into()])
            .style(Style::default().fg(ACCENT))
            .alignment(Alignment::Center)
            .build();
        frame.render_widget(logo, logo_area);
    }

    /// Render the status message bar
    fn render_status(&self, frame: &mut Frame, area: Rect) {
        if let Some(msg) = &self.state.status_message {
            let widget = Paragraph::new(msg.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded),
                );
            frame.render_widget(widget, area);
        }
    }

    /// Render the current state to the terminal
    fn render(&self, frame: &mut Frame) {
        let frame_area = frame.size();
        let areas = calculate_layout(
            frame_area,
            self.state.status_message.is_some(),
            self.config.show_qr,
            &self.config.qr_code,
            self.config.show_url,
        );
        let panel_inset = panel_side_inset(frame_area.width);

        let logo_area = inset_horizontal(areas.logo, panel_inset);
        let connection_area = inset_horizontal(areas.connection, panel_inset);
        let transfer_area = inset_horizontal(areas.transfer, panel_inset);

        self.render_logo(frame, logo_area);
        let (feedback_text, feedback_style) = self.copy_feedback_text_style();
        connection::render_connection_panel(
            frame,
            connection_area,
            &self.config,
            self.compact_qr_code.as_deref(),
            feedback_text,
            feedback_style,
        );
        transfer_panel::render_transfer_panel(
            frame,
            transfer_area,
            &self.state.transfer,
            &self.config.display_files,
            self.config.display_overflow_count,
            &self.config.display_name,
            ACCENT,
        );

        if let Some(status_area) = areas.status {
            self.render_status(frame, inset_horizontal(status_area, panel_inset));
        }
    }
}

/// Install a panic hook that restores the terminal before printing the panic
fn install_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Attempt to restore terminal
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));
}

/// Cleanup terminal state
fn cleanup_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

/// Spawns the TUI task on Tokio.
pub fn spawn_tui(
    config: TuiConfig,
    tracker: Arc<ProgressTracker>,
    status_rx: watch::Receiver<Option<String>>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let ui = TransferUI::new(config, tracker, status_rx);
        ui.run(cancel).await
    })
}
