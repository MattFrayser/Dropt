use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Gauge, Paragraph, Wrap},
    Terminal,
};
use std::{io, time::Duration};
use tokio::sync::watch;

pub struct TransferUI {
    progress: watch::Receiver<f64>, // tokio channel for watching values
    file_name: String,
    file_hash: String,
    qr_code: String,
    url: String,
}

impl TransferUI {
    pub fn new(
        progress: watch::Receiver<f64>,
        file_name: String,
        file_hash: String,
        qr_code: String,
        url: String,
    ) -> Self {
        Self {
            progress,
            file_name,
            file_hash,
            qr_code,
            url,
        }
    }

    pub async fn run(&mut self) -> Result<(), io::Error> {
        enable_raw_mode()?; // switch terminal to raw

        let mut stdout = io::stdout();

        execute!(stdout, EnterAlternateScreen)?;

        // Terminal instance
        let backend = CrosstermBackend::new(stdout); // low level i/o
        let mut terminal = Terminal::new(backend)?; // ui

        loop {
            // read latest progress
            let progress = *self.progress.borrow();

            // Terminal is split into 2 parts
            // left side is text info
            // right side is qr code
            terminal.draw(|f| {
                let sides = Layout::default()
                    .direction(Direction::Horizontal)
                    .margin(2)
                    .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                    .split(f.size());

                let left_side = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(1)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Length(3),
                        Constraint::Length(3),
                        Constraint::Length(100),
                        Constraint::Min(0),
                    ])
                    .split(sides[0]);

                // widgets
                let title = Paragraph::new(format!("Sending: {}", self.file_name))
                    .block(Block::default().borders(Borders::ALL));
                f.render_widget(title, left_side[0]);

                let progress_bar = Gauge::default()
                    .block(Block::default().title("Progress").borders(Borders::ALL))
                    .gauge_style(ratatui::style::Style::default().fg(ratatui::style::Color::Green))
                    .percent(progress as u16);
                f.render_widget(progress_bar, left_side[1]);

                let hash = Paragraph::new(format!("SHA-256: {}", self.file_hash))
                    .block(Block::default().borders(Borders::ALL));
                f.render_widget(hash, left_side[2]);

                // OSC 8 hyperlink format: \x1b]8;;URL\x1b\\TEXT\x1b]8;;\x1b\\
                let url = Paragraph::new(format!("{}", self.url)).wrap(Wrap { trim: false });
                f.render_widget(url, left_side[3]);

                let qr = Paragraph::new(self.qr_code.clone())
                    .block(Block::default().title("Scan").borders(Borders::ALL))
                    .alignment(ratatui::layout::Alignment::Center);
                f.render_widget(qr, sides[1]);
            })?;

            // Check for keypresses (exit)
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('c') => break,
                        KeyCode::Esc => break,
                        _ => {}
                    }
                }
            }

            // Download done
            if progress >= 100.0 {
                break;
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

        Ok(())
    }
}
