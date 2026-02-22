use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::Span,
    widgets::{Block, BorderType, Borders, Paragraph},
};

use super::hyperlink::Hyperlink;
use super::styles::muted_style;
use super::types::TuiConfig;

const SCAN_LABEL_RIGHT_NUDGE: u16 = 1;
const SECTION_SIDE_INSET_WIDE: u16 = 2;
const SECTION_SIDE_INSET_NARROW: u16 = 1;
const SECTION_SIDE_INSET_THRESHOLD: u16 = 72;
const ACCENT: Color = Color::Rgb(248, 190, 117);
const URL_COLOR: Color = Color::Rgb(245, 245, 245);

pub(crate) fn render_connection_panel(
    frame: &mut Frame,
    area: Rect,
    config: &TuiConfig,
    compact_qr_code: Option<&str>,
    feedback_text: &str,
    feedback_style: Style,
) {
    let mode = if config.is_receiving {
        "Receive"
    } else {
        "Send"
    };
    let transport = format!("{:?}", config.transport);
    let title = format!(" {} • {} ", mode, transport);

    let block = Block::default()
        .title(Span::styled(title, Style::default().fg(ACCENT)))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(inner);

    let side_inset = if inner.width >= SECTION_SIDE_INSET_THRESHOLD {
        SECTION_SIDE_INSET_WIDE
    } else {
        SECTION_SIDE_INSET_NARROW
    };

    let content = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(side_inset),
            Constraint::Min(0),
            Constraint::Length(side_inset),
        ])
        .split(body[1])[1];

    if config.show_qr && config.show_url {
        let stacked = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(content);

        render_qr_section(frame, stacked[0], &config.qr_code, compact_qr_code, ACCENT);

        let divider = Paragraph::new("─".repeat(stacked[1].width as usize)).style(muted_style());
        frame.render_widget(divider, stacked[1]);

        render_open_section(
            frame,
            stacked[2],
            stacked[3],
            stacked[4],
            &config.url,
            feedback_text,
            feedback_style,
        );
    } else if config.show_qr {
        render_qr_section(frame, content, &config.qr_code, compact_qr_code, ACCENT);
    } else if config.show_url {
        let url_only = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(content);
        render_open_section(
            frame,
            url_only[0],
            url_only[1],
            url_only[2],
            &config.url,
            feedback_text,
            feedback_style,
        );
    }
}

fn render_qr_section(
    frame: &mut Frame,
    area: Rect,
    qr_code: &str,
    compact_qr_code: Option<&str>,
    accent: Color,
) {
    let scan_only = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    let Some(qr_variant) = select_qr_variant(scan_only[1], qr_code, compact_qr_code) else {
        render_scan_label(frame, scan_only[0], scan_only[1], 1, accent);
        render_qr_too_small(frame, scan_only[1]);
        return;
    };

    render_scan_label(frame, scan_only[0], scan_only[1], qr_variant.width, accent);
    render_qr_text(frame, scan_only[1], qr_variant.text);
}

fn render_open_section(
    frame: &mut Frame,
    label_area: Rect,
    url_area: Rect,
    feedback_area: Rect,
    url: &str,
    feedback_text: &str,
    feedback_style: Style,
) {
    let open_label = Paragraph::new("Open")
        .style(Style::default().fg(ACCENT))
        .alignment(Alignment::Left);
    frame.render_widget(open_label, label_area);

    render_url(frame, url_area, url, URL_COLOR);

    let feedback = Paragraph::new(feedback_text)
        .style(feedback_style)
        .alignment(Alignment::Left);
    frame.render_widget(feedback, feedback_area);
}

fn render_scan_label(
    frame: &mut Frame,
    label_area: Rect,
    qr_area: Rect,
    qr_width: u16,
    accent: Color,
) {
    let qr_width = qr_width.max(1);
    let offset = qr_area.width.saturating_sub(qr_width) / 2;
    let label_x = label_area
        .x
        .saturating_add(offset.min(label_area.width.saturating_sub(1)))
        .saturating_add(SCAN_LABEL_RIGHT_NUDGE.min(label_area.width.saturating_sub(1)));
    let label_width = label_area
        .width
        .saturating_sub(label_x.saturating_sub(label_area.x))
        .max(1);
    let area = Rect {
        x: label_x,
        y: label_area.y,
        width: label_width,
        height: 1,
    };

    let scan_label = Paragraph::new("Scan")
        .style(Style::default().fg(accent))
        .alignment(Alignment::Left);
    frame.render_widget(scan_label, area);
}
fn render_qr_text(frame: &mut Frame, area: Rect, qr_text: &str) {
    let qr = Paragraph::new(qr_text).alignment(Alignment::Center);
    frame.render_widget(qr, area);
}

struct QrVariant<'a> {
    text: &'a str,
    width: u16,
}

fn select_qr_variant<'a>(
    area: Rect,
    qr_code: &'a str,
    compact_qr_code: Option<&'a str>,
) -> Option<QrVariant<'a>> {
    let (primary_width, primary_height) = qr_text_dimensions(qr_code);
    if primary_width <= area.width && primary_height <= area.height {
        return Some(QrVariant {
            text: qr_code,
            width: primary_width,
        });
    }

    let (compact_width, compact_height) = compact_qr_code
        .map(qr_text_dimensions)
        .unwrap_or((u16::MAX, u16::MAX));
    if compact_width <= area.width && compact_height <= area.height {
        return Some(QrVariant {
            text: compact_qr_code.unwrap_or(qr_code),
            width: compact_width,
        });
    }

    None
}

fn render_qr_too_small(frame: &mut Frame, area: Rect) {
    let msg = Paragraph::new(":( terminal too small for qr code")
        .style(muted_style())
        .alignment(Alignment::Center);
    frame.render_widget(msg, area);
}

fn render_url(frame: &mut Frame, area: Rect, url: &str, url_color: Color) {
    let display_url = middle_ellipsis(url, area.width as usize);
    let hyperlink = Hyperlink::new(&display_url, url).style(Style::default().fg(url_color));
    frame.render_widget(hyperlink, area);
}

fn qr_text_dimensions(qr_text: &str) -> (u16, u16) {
    let width = qr_text
        .lines()
        .map(|line| line.chars().count() as u16)
        .max()
        .unwrap_or(0);
    let height = qr_text.lines().count() as u16;
    (width, height)
}

fn middle_ellipsis(text: &str, max_width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();

    if max_width == 0 {
        return String::new();
    }

    if len <= max_width {
        return text.to_string();
    }

    if max_width <= 3 {
        return ".".repeat(max_width);
    }

    let keep = max_width - 3;
    let left = keep.div_ceil(2);
    let right = keep / 2;

    let start: String = chars.iter().take(left).collect();
    let end: String = chars.iter().skip(len - right).collect();
    format!("{}...{}", start, end)
}
