use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame, Terminal,
};
use std::{io, time::Duration};
use tokio::{
    sync::watch,
    time::{interval, MissedTickBehavior},
};

// Config for differnt terminal sizes
struct LayoutConfig {
    logo: &'static str,
    horizontal: bool,
}

impl LayoutConfig {
    fn size(width: u16) -> Self {
        match width {
            w if w >= 112 => Self {
                logo: TWO_LINE_LOGO,
                horizontal: true,
            },
            w if w >= 65 => Self {
                logo: ONE_LINE_LOGO,
                horizontal: true,
            },
            _ => Self {
                logo: "ArchDrop",
                horizontal: false,
            },
        }
    }
}

pub struct TransferUI {
    progress: watch::Receiver<f64>,
    file_name: String,
    qr_code: String,
    is_recieving: bool,
    status_message: watch::Receiver<Option<String>>,
}

impl TransferUI {
    pub fn new(
        progress: watch::Receiver<f64>,
        file_name: String,
        qr_code: String,
        is_recieving: bool,
        status_message: watch::Receiver<Option<String>>,
    ) -> Self {
        Self {
            progress,
            file_name,
            qr_code,
            is_recieving,
            status_message,
        }
    }

    pub async fn run(&mut self) -> Result<(), io::Error> {
        // Limit frames on TUI (about 20 FPS)
        // Left unchecked it will kill performance
        let mut render_tick = interval(Duration::from_millis(50));
        render_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // State tracking to avoid unnecessary processing
        let mut last_progress = 0.0;
        let mut current_progress = *self.progress.borrow();
        let mut current_status = self.status_message.borrow().clone();

        loop {
            tokio::select! {
                // Throttle UI updates
                _ = render_tick.tick() => {
                    terminal.draw(|f| {
                        self.render_layout(f, current_progress, current_status.as_deref());
                    })?;

                    // Check input keep UI responsive
                    // Non-blocking poll since inside async
                    if event::poll(Duration::from_millis(0))? {
                        if let Event::Key(key) = event::read()? {
                            match key.code {
                                KeyCode::Char('q') | KeyCode::Char('c') | KeyCode::Esc => break,
                                _ => {}
                            }
                        }
                    }

                    if current_progress >= 100.0 {
                        break;
                    }
                }

                // Data Update (High frequency, cheap)
                Ok(_) = self.progress.changed() => {
                    let new_val = *self.progress.borrow();
                    if new_val != last_progress {
                        current_progress = new_val;
                        last_progress = new_val;
                    }
                }

                // Status Update (Low frequency)
                Ok(_) = self.status_message.changed() => {
                    current_status = self.status_message.borrow().clone();
                }
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

        Ok(())
    }

    // Render layout with correct format for size of terminal
    fn render_layout(&self, f: &mut Frame, progress: f64, status_msg: Option<&str>) {
        let config = LayoutConfig::size(f.size().width);

        let main_areas = self.split_for_status(f.size(), status_msg.is_some());
        let content_area = main_areas[0];

        if config.horizontal {
            self.render_horizontal(f, content_area, progress, &config);
        } else {
            self.render_veritcal(f, content_area, progress, &config);
        }

        if let Some(msg) = status_msg {
            self.render_status_widget(f, msg, main_areas[1]);
        }
    }

    fn split_for_status(&self, area: Rect, has_status: bool) -> Vec<Rect> {
        if has_status {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints(vec![Constraint::Min(0), Constraint::Length(3)])
                .split(area)
                .to_vec()
        } else {
            vec![area]
        }
    }

    fn render_horizontal(&self, f: &mut Frame, area: Rect, progress: f64, config: &LayoutConfig) {
        let sides = Layout::default()
            .direction(Direction::Horizontal)
            .margin(2)
            .constraints(vec![Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        let left = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![Constraint::Length(15), Constraint::Min(0)])
            .split(sides[0]);

        let info = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(vec![
                Constraint::Length(3), // File
                Constraint::Length(3), // Progress
                Constraint::Min(5),
            ])
            .split(left[1]);

        self.render_logo(f, config.logo, left[0]);
        self.render_file_widget(f, info[0]);
        self.render_progress_widget(f, progress, info[1]);
        self.render_qr_widget(f, sides[1]);
    }

    fn render_veritcal(&self, f: &mut Frame, area: Rect, progress: f64, config: &LayoutConfig) {
        let logo_height = if config.logo == ONE_LINE_LOGO { 10 } else { 4 };

        // Full vertical stack - single column
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(vec![
                Constraint::Length(logo_height), // logo
                Constraint::Length(3),           // File
                Constraint::Length(3),           // Progress
                Constraint::Min(15),             // QR
            ])
            .split(area);

        self.render_logo(f, config.logo, chunks[0]);
        self.render_file_widget(f, chunks[1]);
        self.render_progress_widget(f, progress, chunks[2]);
        self.render_qr_widget(f, chunks[3]);
    }

    fn render_logo(&self, f: &mut Frame, logo: &str, area: Rect) {
        let widget = if logo == "ArchDrop" {
            // Normal text gets box around it
            Paragraph::new(logo)
                .block(Block::default().borders(Borders::ALL))
                .alignment(ratatui::layout::Alignment::Center)
        } else {
            Paragraph::new(logo).block(Block::default())
        };

        f.render_widget(widget, area);
    }

    //------------
    // Widgets
    //------------
    fn render_file_widget(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let title = if self.is_recieving {
            "Destination"
        } else {
            "Sending"
        };
        let widget = Paragraph::new(self.file_name.clone())
            .block(Block::default().title(title).borders(Borders::ALL));
        f.render_widget(widget, area);
    }

    fn render_progress_widget(&self, f: &mut Frame, progress: f64, area: ratatui::layout::Rect) {
        // Clamp progress to 0-100 range to avoid panic
        let clamped_progress = progress.clamp(0.0, 100.0) as u16;

        let widget = Gauge::default()
            .block(Block::default().title("Progress").borders(Borders::ALL))
            .gauge_style(ratatui::style::Style::default().fg(ratatui::style::Color::Green))
            .percent(clamped_progress);
        f.render_widget(widget, area);
    }

    fn render_qr_widget(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let widget = Paragraph::new(self.qr_code.clone())
            .block(Block::default().title("Scan").borders(Borders::ALL))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(widget, area);
    }

    fn render_status_widget(&self, f: &mut Frame, msg: &str, area: ratatui::layout::Rect) {
        use ratatui::style::{Color, Modifier, Style};
        let widget = Paragraph::new(msg)
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(widget, area);
    }
}

const ONE_LINE_LOGO: &str = r#"
   _____               .__    ________                        
  /  _  \______   ____ |  |__ \______ \_______  ____ ______  
 /  /_\  \  __ \_/ ___\|  |  \ |    |  \_  __ \/    \\  __ \   
/    |    \ | \/\  \___|   Y  \|    `   \  | \(  ()  )  |_) | 
\____|____/_|    \_____|___|__/_________/__|   \____/|   __/  
                                                     |__|  
"#;

const TWO_LINE_LOGO: &str = r#"
   _____               .__
  /  _  \______   ____ |  |__
 /  /_\  \  __ \_/ ___\|  |  \
/    |    \ | \/\  \___|   Y  \
\____|____/_|    \_____|___|__/
________
\______ \_______  ____ ______
 |    |  \_  __ \/    \\  __ \
 |    `   \  | \(  ()  )  |_) |
 L________/__|   \____/|   __/
                       |__|
"#;
