use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::{CrosstermBackend, Terminal},
    style::{Color, Style},
    text::Span,
    widgets::{Block, BorderType, Borders, Gauge, Paragraph, Widget},
    Frame,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tui_big_text::{BigText, PixelSize};

use super::types::{TransferProgress, TuiConfig};
use crate::server::progress::ProgressTracker;

/// Layout areas for the TUI
struct LayoutAreas {
    logo: Rect,
    connection: Rect,
    transfer: Rect,
    status: Option<Rect>,
}

/// Configuration for responsive layout sizing
struct LayoutConfig {
    pixel_size: PixelSize,
    horizontal_connection: bool,
}

impl LayoutConfig {
    fn for_width(width: u16) -> Self {
        match width {
            w if w >= 100 => Self {
                pixel_size: PixelSize::Sextant,
                horizontal_connection: true,
            },
            w if w >= 60 => Self {
                pixel_size: PixelSize::Quadrant,
                horizontal_connection: true,
            },
            _ => Self {
                pixel_size: PixelSize::Quadrant,
                horizontal_connection: false,
            },
        }
    }
}

/// Render and poll interval
const RENDER_INTERVAL: Duration = Duration::from_millis(50);

const ACCENT: Color = Color::Rgb(248, 190, 117);

/// Mutable state that changes during transfer
#[derive(Debug, Default)]
pub struct TuiState {
    pub transfer: TransferProgress,
    pub status_message: Option<String>,
}

/// Actions the TUI can take
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    None,
    Quit,
}

/// Main TUI controller
pub struct TransferUI {
    config: TuiConfig,
    state: TuiState,
    tracker: Arc<ProgressTracker>,
    status_rx: watch::Receiver<Option<String>>,
}

impl TransferUI {
    pub fn new(
        config: TuiConfig,
        tracker: Arc<ProgressTracker>,
        status_rx: watch::Receiver<Option<String>>,
    ) -> Self {
        Self {
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

        let mut last_render = Instant::now();

        // Initial render
        terminal.draw(|f| self.render(f))?;

        loop {
            let action = tokio::select! {
                // Check for cancellation
                _ = cancel.cancelled() => {
                    Action::Quit
                }

                // Status message update
                result = self.status_rx.changed() => {
                    if result.is_ok() {
                        self.state.status_message = self.status_rx.borrow().clone();
                    }
                    Action::None
                }

                // Input polling and render tick
                _ = tokio::time::sleep(RENDER_INTERVAL) => {
                    self.handle_input()?
                }
            };

            // Handle action
            match action {
                Action::Quit => break,
                Action::None => {}
            }

            // Read latest state from tracker
            self.state.transfer = self.tracker.snapshot();

            // Check if transfer is complete
            if self.is_complete() {
                // Final render to show completed state
                terminal.draw(|f| self.render(f))?;
                // Give a moment to see final state
                tokio::time::sleep(Duration::from_millis(500)).await;
                break;
            }

            // Debounced render
            self.maybe_render(&mut terminal, &mut last_render)?;
        }

        // Cleanup
        cleanup_terminal(&mut terminal)?;
        Ok(())
    }

    /// Render only if enough time has elapsed since last render
    fn maybe_render(
        &self,
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        last_render: &mut Instant,
    ) -> io::Result<()> {
        if last_render.elapsed() >= RENDER_INTERVAL {
            terminal.draw(|f| self.render(f))?;
            *last_render = Instant::now();
        }
        Ok(())
    }

    /// Check for keyboard input
    fn handle_input(&self) -> io::Result<Action> {
        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('c') | KeyCode::Esc => {
                            return Ok(Action::Quit);
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(Action::None)
    }

    /// Check if the transfer is complete
    fn is_complete(&self) -> bool {
        self.state.transfer.is_complete()
    }

    /// Calculate the layout areas based on current state
    fn calculate_layout(&self, area: Rect) -> LayoutAreas {
        let has_status = self.state.status_message.is_some();

        // Size connection panel to fit QR content dynamically
        let connection_height = if self.config.show_qr && !self.config.qr_code.is_empty() {
            let qr_lines = self.config.qr_code.lines().count() as u16;
            qr_lines + 2 // +2 for borders
        } else {
            5 // URL-only mode
        };

        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(if has_status {
                vec![
                    Constraint::Length(1),                 // Top margin
                    Constraint::Length(4),                 // Logo
                    Constraint::Length(connection_height), // Connection (fits QR)
                    Constraint::Min(8),                    // Transfer (grows)
                    Constraint::Length(3),                 // Status
                ]
            } else {
                vec![
                    Constraint::Length(1),                 // Top margin
                    Constraint::Length(4),                 // Logo
                    Constraint::Length(connection_height), // Connection
                    Constraint::Min(8),                    // Transfer
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

    /// Render the logo at the top of the screen
    fn render_logo(&self, frame: &mut Frame, area: Rect, config: &LayoutConfig) {
        let logo = BigText::builder()
            .pixel_size(config.pixel_size)
            .lines(vec!["ARCHDROP".into()])
            .style(Style::default().fg(ACCENT))
            .alignment(Alignment::Center)
            .build();
        frame.render_widget(logo, area);
    }

    /// Render the connection panel
    fn render_connection_panel(&self, frame: &mut Frame, area: Rect, config: &LayoutConfig) {
        let mode = if self.config.is_receiving {
            "Receive"
        } else {
            "Send"
        };
        let transport = format!("{:?}", self.config.transport);
        let title = format!(" {} \u{2022} {} ", mode, transport);

        let block = Block::default()
            .title(Span::styled(title, Style::default().fg(ACCENT)))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        if config.horizontal_connection && self.config.show_qr && self.config.show_url {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                .split(inner);
            self.render_qr(frame, chunks[0]);
            self.render_url(frame, chunks[1]);
        } else if self.config.show_qr {
            self.render_qr(frame, inner);
        } else if self.config.show_url {
            self.render_url(frame, inner);
        }
    }

    fn render_qr(&self, frame: &mut Frame, area: Rect) {
        let qr = Paragraph::new(self.config.qr_code.as_str())
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(qr, area);
    }

    fn render_url(&self, frame: &mut Frame, area: Rect) {
        let hyperlink =
            Hyperlink::new(&self.config.url, &self.config.url).style(Style::default().fg(ACCENT));
        frame.render_widget(hyperlink, area);
    }

    /// Render the transfer progress panel
    fn render_transfer_panel(&self, frame: &mut Frame, area: Rect) {
        let title = format!(
            " Transfer \u{2022} {}/{} complete ",
            self.state.transfer.completed, self.state.transfer.total
        );

        let block = Block::default()
            .title(Span::styled(title, Style::default().fg(ACCENT)))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(inner);

        let path = Paragraph::new(self.config.display_name.as_str())
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(path, chunks[0]);

        self.render_file_list(frame, chunks[1]);
    }

    fn render_file_list(&self, frame: &mut Frame, area: Rect) {
        use super::types::FileStatus;
        let files = &self.state.transfer.files;

        let mut in_progress: Vec<_> = files
            .iter()
            .filter(|f| matches!(f.status, FileStatus::InProgress(_)))
            .collect();
        let failed: Vec<_> = files
            .iter()
            .filter(|f| matches!(f.status, FileStatus::Failed(_)))
            .collect();
        let waiting_count = files
            .iter()
            .filter(|f| matches!(f.status, FileStatus::Waiting))
            .count();

        in_progress.sort_by(|a, b| {
            let pa = match a.status {
                FileStatus::InProgress(p) => p,
                _ => 0.0,
            };
            let pb = match b.status {
                FileStatus::InProgress(p) => p,
                _ => 0.0,
            };
            pb.partial_cmp(&pa).unwrap_or(std::cmp::Ordering::Equal)
        });

        let max_in_progress = 5.min(in_progress.len());
        let overflow = in_progress.len().saturating_sub(5) + waiting_count;

        let mut constraints: Vec<Constraint> = Vec::new();
        for _ in 0..max_in_progress {
            constraints.push(Constraint::Length(1));
        }
        if overflow > 0 {
            constraints.push(Constraint::Length(1));
        }
        for _ in 0..failed.len() {
            constraints.push(Constraint::Length(1));
        }
        if constraints.is_empty() {
            return;
        }

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(area);

        let mut row_idx = 0;

        for file in in_progress.iter().take(max_in_progress) {
            if let FileStatus::InProgress(pct) = file.status {
                self.render_file_progress(frame, rows[row_idx], &file.filename, pct);
                row_idx += 1;
            }
        }

        if overflow > 0 {
            let text = format!("+{} more waiting...", overflow);
            let widget = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
            frame.render_widget(widget, rows[row_idx]);
            row_idx += 1;
        }

        for file in &failed {
            if let FileStatus::Failed(err) = &file.status {
                let text = format!("\u{2717} {}  {}", file.filename, err);
                let widget = Paragraph::new(text).style(Style::default().fg(Color::Red));
                frame.render_widget(widget, rows[row_idx]);
                row_idx += 1;
            }
        }
    }

    fn render_file_progress(&self, frame: &mut Frame, area: Rect, filename: &str, percent: f64) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        let name = Paragraph::new(filename);
        frame.render_widget(name, chunks[0]);

        let gauge = Gauge::default()
            .gauge_style(Style::default().fg(Color::Green))
            .percent(percent.clamp(0.0, 100.0) as u16)
            .label(format!("{:.0}%", percent));
        frame.render_widget(gauge, chunks[1]);
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
        let config = LayoutConfig::for_width(frame.size().width);
        let areas = self.calculate_layout(frame.size());

        self.render_logo(frame, areas.logo, &config);
        self.render_connection_panel(frame, areas.connection, &config);
        self.render_transfer_panel(frame, areas.transfer);

        if let Some(status_area) = areas.status {
            self.render_status(frame, status_area);
        }
    }
}

/// Clickable hyperlink widget using OSC 8 terminal escape sequences.
/// Renders centered text that is clickable in supported terminals.
struct Hyperlink<'a> {
    text: &'a str,
    url: &'a str,
    style: Style,
}

impl<'a> Hyperlink<'a> {
    fn new(text: &'a str, url: &'a str) -> Self {
        Self {
            text,
            url,
            style: Style::default(),
        }
    }

    fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
}

impl Widget for Hyperlink<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Vertically center in available space
        let y = area.y + area.height.saturating_sub(1) / 2;
        let line_area = Rect {
            x: area.x,
            y,
            width: area.width,
            height: 1,
        };

        // Render styled text centered
        Paragraph::new(self.text)
            .style(self.style)
            .alignment(Alignment::Center)
            .render(line_area, buf);

        // Overwrite buffer cells with OSC 8 hyperlink escape sequences.
        // Uses 2-char chunks as workaround for ratatui ANSI width calculation bug.
        let text_width = self.text.chars().count() as u16;
        let start_x = line_area.x + line_area.width.saturating_sub(text_width) / 2;
        let chars: Vec<char> = self.text.chars().collect();
        for (i, chunk) in chars.chunks(2).enumerate() {
            let chunk_text: String = chunk.iter().collect();
            let osc = format!("\x1B]8;;{}\x07{}\x1B]8;;\x07", self.url, chunk_text);
            let x = start_x + (i as u16 * 2);
            if x < area.x + area.width {
                buf.get_mut(x, y).set_symbol(&osc);
            }
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

/// Spawn the TUI in a background task
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
