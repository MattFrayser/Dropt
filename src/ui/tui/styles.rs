use ratatui::style::{Color, Modifier, Style};

pub(super) fn muted_style() -> Style {
    Style::default()
        .fg(Color::DarkGray)
        .add_modifier(Modifier::DIM)
}
