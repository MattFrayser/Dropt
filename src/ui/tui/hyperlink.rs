use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Rect},
    style::Style,
    widgets::{Paragraph, Widget},
};

pub(crate) struct Hyperlink<'a> {
    text: &'a str,
    url: &'a str,
    style: Style,
}

impl<'a> Hyperlink<'a> {
    pub(crate) fn new(text: &'a str, url: &'a str) -> Self {
        Self {
            text,
            url,
            style: Style::default(),
        }
    }

    pub(crate) fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
}

impl Widget for Hyperlink<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let y = area.y;
        let line_area = Rect {
            x: area.x,
            y,
            width: area.width,
            height: 1,
        };

        Paragraph::new(self.text)
            .style(self.style)
            .alignment(Alignment::Left)
            .render(line_area, buf);

        let text_width = self.text.chars().count() as u16;
        let start_x = line_area.x;
        let chars: Vec<char> = self.text.chars().collect();
        for (i, chunk) in chars.chunks(2).enumerate() {
            let chunk_text: String = chunk.iter().collect();
            let osc = format!("\x1B]8;;{}\x07{}\x1B]8;;\x07", self.url, chunk_text);
            let x = start_x + (i as u16 * 2);
            if x < area.x + area.width && (i as u16 * 2) < text_width {
                buf.get_mut(x, y).set_symbol(&osc);
            }
        }
    }
}
