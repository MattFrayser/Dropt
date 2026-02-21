use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, BorderType, Borders, Gauge, Paragraph},
    Frame,
};

use super::styles::muted_style;
use super::types::{FileProgress, FileStatus, TransferProgress};

const MAX_VISIBLE_FILE_ROWS: usize = 5;
const MAX_VISIBLE_FILE_ROWS_COMPACT: usize = 3;
const MAX_VISIBLE_FILE_ROWS_TIGHT: usize = 2;

#[derive(Debug, Clone, PartialEq)]
struct FileListRow {
    filename: String,
    status_text: String,
    status_color: Color,
    dim_status: bool,
    progress_percent: Option<u16>,
}

pub(crate) fn render_transfer_panel(
    frame: &mut Frame,
    area: Rect,
    transfer: &TransferProgress,
    display_files: &[String],
    display_overflow_count: Option<usize>,
    display_name: &str,
    accent: Color,
) {
    let title = transfer_title(transfer, display_files, display_overflow_count);

    let block = Block::default()
        .title(Span::styled(title, Style::default().fg(accent)))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let max_visible_rows = max_visible_rows_for_area(inner);
    if let Some((rows_data, overflow)) = build_panel_rows(
        transfer,
        display_files,
        display_overflow_count,
        max_visible_rows,
    ) {
        render_rows_with_overflow(frame, inner, &rows_data, overflow);
    } else {
        let path = Paragraph::new(display_name).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(path, inner);
    }
}

fn transfer_title(
    transfer: &TransferProgress,
    display_files: &[String],
    display_overflow_count: Option<usize>,
) -> String {
    if transfer.total > 0 {
        return format!(
            " Transfer • {}/{} complete ",
            transfer.completed, transfer.total
        );
    }

    if !display_files.is_empty() {
        let queued = display_files.len() + display_overflow_count.unwrap_or(0);
        return format!(" Transfer • {} queued ", queued);
    }

    " Transfer ".to_string()
}

fn max_visible_rows_for_area(area: Rect) -> usize {
    if area.height <= 4 {
        MAX_VISIBLE_FILE_ROWS_TIGHT
    } else if area.height <= 6 {
        MAX_VISIBLE_FILE_ROWS_COMPACT
    } else {
        MAX_VISIBLE_FILE_ROWS
    }
}

fn build_visible_file_rows(files: &[FileProgress], limit: usize) -> (Vec<FileListRow>, usize) {
    let rows = files
        .iter()
        .take(limit)
        .map(|file| {
            let (status_text, status_color, dim_status) = match &file.status {
                FileStatus::Waiting => ("waiting...".to_string(), Color::DarkGray, true),
                FileStatus::InProgress(percent) => {
                    (format!("{:.0}%", percent), Color::Green, false)
                }
                FileStatus::Complete => ("complete".to_string(), Color::Green, false),
                FileStatus::Skipped => ("already exists".to_string(), Color::Yellow, false),
                FileStatus::Renamed(_) => ("complete".to_string(), Color::Green, false),
                FileStatus::Overwrote => ("overwrote".to_string(), Color::Yellow, false),
                FileStatus::Failed(_) => ("failed".to_string(), Color::Red, false),
            };

            let progress_percent = match &file.status {
                FileStatus::InProgress(percent) => Some(percent.clamp(0.0, 100.0) as u16),
                _ => None,
            };

            FileListRow {
                filename: file.filename.clone(),
                status_text,
                status_color,
                dim_status,
                progress_percent,
            }
        })
        .collect::<Vec<_>>();

    let overflow = files.len().saturating_sub(limit);
    (rows, overflow)
}

fn waiting_rows(display_files: &[String]) -> Vec<FileListRow> {
    display_files
        .iter()
        .map(|name| FileListRow {
            filename: name.clone(),
            status_text: "waiting...".to_string(),
            status_color: Color::DarkGray,
            dim_status: true,
            progress_percent: None,
        })
        .collect()
}

fn build_panel_rows(
    transfer: &TransferProgress,
    display_files: &[String],
    display_overflow_count: Option<usize>,
    max_visible_rows: usize,
) -> Option<(Vec<FileListRow>, usize)> {
    if transfer.files.is_empty() {
        if display_files.is_empty() {
            return None;
        }

        let mut rows_data = waiting_rows(display_files);
        rows_data.truncate(max_visible_rows);
        let overflow = display_overflow_count.unwrap_or(0);
        Some((rows_data, overflow))
    } else {
        Some(build_visible_file_rows(&transfer.files, max_visible_rows))
    }
}

fn render_rows_with_overflow(
    frame: &mut Frame,
    area: Rect,
    rows_data: &[FileListRow],
    overflow: usize,
) {
    let mut constraints = vec![Constraint::Length(1); rows_data.len()];
    if overflow > 0 {
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
    for row in rows_data {
        render_file_status_row(frame, rows[row_idx], row);
        row_idx += 1;
    }

    if overflow > 0 {
        let text = format!("+{} more", overflow);
        let widget = Paragraph::new(text).style(muted_style());
        frame.render_widget(widget, rows[row_idx]);
    }
}

fn render_file_status_row(frame: &mut Frame, area: Rect, row: &FileListRow) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(72), Constraint::Percentage(28)])
        .split(area);

    let name = Paragraph::new(row.filename.as_str());
    frame.render_widget(name, chunks[0]);

    if let Some(percent) = row.progress_percent {
        let gauge = Gauge::default()
            .gauge_style(Style::default().fg(Color::Green))
            .percent(percent)
            .label(format!("{}%", percent));
        frame.render_widget(gauge, chunks[1]);
        return;
    }

    let mut status_style = Style::default().fg(row.status_color);
    if row.dim_status {
        status_style = status_style.add_modifier(Modifier::DIM);
    }
    let status = Paragraph::new(row.status_text.as_str())
        .style(status_style)
        .alignment(Alignment::Right);
    frame.render_widget(status, chunks[1]);
}

#[cfg(test)]
mod tests {
    use super::build_visible_file_rows;
    use ratatui::style::Color;

    use crate::ui::tui::types::{FileProgress, FileStatus};

    fn waiting_file(name: &str) -> FileProgress {
        FileProgress {
            filename: name.to_string(),
            status: FileStatus::Waiting,
        }
    }

    fn skipped_file(name: &str) -> FileProgress {
        FileProgress {
            filename: name.to_string(),
            status: FileStatus::Skipped,
        }
    }

    #[test]
    fn builds_vertical_rows_with_waiting_status_text() {
        let files = vec![waiting_file("text1.txt"), waiting_file("test2.txt")];
        let (rows, overflow) = build_visible_file_rows(&files, 5);

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].filename, "text1.txt");
        assert_eq!(rows[0].status_text, "waiting...");
        assert_eq!(rows[1].filename, "test2.txt");
        assert_eq!(rows[1].status_text, "waiting...");
        assert_eq!(overflow, 0);
    }

    #[test]
    fn caps_rows_at_five_and_reports_overflow() {
        let files = vec![
            waiting_file("a.txt"),
            waiting_file("b.txt"),
            waiting_file("c.txt"),
            waiting_file("d.txt"),
            waiting_file("e.txt"),
            waiting_file("f.txt"),
            waiting_file("g.txt"),
        ];
        let (rows, overflow) = build_visible_file_rows(&files, 5);

        assert_eq!(rows.len(), 5);
        assert_eq!(rows[4].filename, "e.txt");
        assert_eq!(overflow, 2);
    }

    #[test]
    fn skipped_rows_render_skipped_status_text() {
        let files = vec![skipped_file("clip.mov")];
        let (rows, overflow) = build_visible_file_rows(&files, 5);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status_text, "already exists");
        assert_eq!(rows[0].status_color, Color::Yellow);
        assert_eq!(overflow, 0);
    }

    #[test]
    fn renamed_row_shows_complete_status_and_green() {
        let files = vec![FileProgress {
            filename: "report (1).pdf".to_string(),
            status: FileStatus::Renamed("report (1).pdf".to_string()),
        }];
        let (rows, _) = build_visible_file_rows(&files, 5);

        assert_eq!(rows[0].filename, "report (1).pdf");
        assert_eq!(rows[0].status_text, "complete");
        assert_eq!(rows[0].status_color, Color::Green);
    }

    #[test]
    fn overwrote_row_shows_yellow_overwrote_status() {
        let files = vec![FileProgress {
            filename: "report.pdf".to_string(),
            status: FileStatus::Overwrote,
        }];
        let (rows, _) = build_visible_file_rows(&files, 5);

        assert_eq!(rows[0].status_text, "overwrote");
        assert_eq!(rows[0].status_color, Color::Yellow);
    }
}
