use crate::{
    policy::{BUILDS, POLICY_DATE},
    scan::ScanReport,
};
use clap::ValueEnum;
use std::io::{self, IsTerminal};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Color {
    Auto,
    Always,
    Never,
}

pub struct Ui {
    color: bool,
}

impl Ui {
    pub fn new(color: Color) -> Self {
        let color = match color {
            Color::Always => true,
            Color::Never => false,
            Color::Auto => io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        };
        Self { color }
    }

    pub(crate) fn paint(&self, text: &str, code: &str) -> String {
        let text = safe_text(text);
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text
        }
    }

    pub fn banner(&self) {
        let logo = [
            " █████╗ ███╗   ██╗ █████╗ ████████╗ ██████╗ ██╗     ██╗   ██╗",
            "██╔══██╗████╗  ██║██╔══██╗╚══██╔══╝██╔═══██╗██║     ╚██╗ ██╔╝",
            "███████║██╔██╗ ██║███████║   ██║   ██║   ██║██║      ╚████╔╝ ",
            "██╔══██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██║       ╚██╔╝  ",
            "██║  ██║██║ ╚████║██║  ██║   ██║   ╚██████╔╝███████╗   ██║   ",
            "╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝   ╚═╝   ",
        ];
        println!();
        println!(
            "  {}  {}{}",
            self.paint("◆", "38;5;81"),
            self.paint("A N A T O L Y   /   SECURITY RESEARCH", "38;5;250"),
            self.paint(&format!("      v{}", env!("CARGO_PKG_VERSION")), "38;5;245")
        );
        println!();
        for (line, tone) in logo.iter().zip([159, 123, 87, 45, 39, 33]) {
            println!("  {}", self.logo_line(line, tone));
        }
        println!();
        println!(
            "  {}  {}  {}",
            self.paint("PHP EXPOSURE INTELLIGENCE", "1;38;5;81"),
            self.paint("/", "38;5;239"),
            self.paint("PHP2SHELL · CVE-2026-109618 / 109619", "38;5;245")
        );
        println!(
            "  {}\n",
            self.paint(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                "38;5;238"
            )
        );
    }

    /// Separate the illuminated faces from their recessed bevels in the wordmark.
    fn logo_line(&self, line: &str, tone: u8) -> String {
        if !self.color {
            return line.to_owned();
        }
        let mut rendered = String::new();
        let mut previous = None;
        for character in line.chars() {
            let face = character == '█';
            if character != ' ' && previous != Some(face) {
                rendered.push_str(&format!("\x1b[38;5;{}m", if face { tone } else { 24 }));
                previous = Some(face);
            }
            rendered.push(character);
        }
        rendered.push_str("\x1b[0m");
        rendered
    }

    pub fn builds(&self) {
        println!("  UPSTREAM PATCH MATRIX  /  reviewed {POLICY_DATE}\n");
        println!("  BRANCH    LAST AFFECTED    FIX FLOOR");
        for b in BUILDS {
            println!(
                "  {:<9} {:<16} {}",
                b.branch,
                b.last_affected,
                self.paint(b.fix_floor, "32")
            );
        }
        println!("\n  PHP <= 8.1: unsupported; migrate. Future branches: unreviewed.");
        println!("  Floors are version indicators, not exploit profiles or package verification.");
        println!("  Confirm complete vendor patches and restart every PHP worker.");
    }

    pub fn report(&self, index: usize, total: usize, report: &ScanReport) {
        crate::scan_view::render(self, index, total, report);
    }

    pub fn summary(&self, summary: &crate::analysis::Summary) {
        crate::scan_view::summary(self, summary);
    }

    /// Render structured mode results using the same bounded rails as scan cards.
    pub fn details(&self, title: &str, value: &serde_json::Value) {
        println!(
            "  {}",
            self.paint(&format!("╭{}╮", "─".repeat(74)), "38;5;24")
        );
        crate::scan_view::paragraph(self, title, "1;38;5;81");
        self.detail_fields(value, 0);
        println!(
            "  {}\n",
            self.paint(&format!("╰{}╯", "─".repeat(74)), "38;5;24")
        );
    }

    fn detail_fields(&self, value: &serde_json::Value, depth: usize) {
        use crate::scan_view::{field, paragraph};
        match value {
            serde_json::Value::Object(fields) => {
                for (key, value) in fields {
                    let label = key.replace('_', " ");
                    if value.is_object() || value.is_array() {
                        paragraph(self, &label.to_uppercase(), "38;5;81");
                        if depth < 16 {
                            self.detail_fields(value, depth + 1);
                        } else {
                            paragraph(self, "Nested data retained in JSON export.", "38;5;245");
                        }
                    } else {
                        let text = value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_owned);
                        if label.chars().count() > 20 {
                            paragraph(self, &format!("{label}: {text}"), "38;5;252");
                        } else {
                            field(self, &label, &text, "38;5;252");
                        }
                    }
                }
            }
            serde_json::Value::Array(items) => {
                if items.is_empty() {
                    paragraph(self, "None recorded", "38;5;245");
                }
                for item in items {
                    if item.is_object() {
                        paragraph(self, "", "38;5;245");
                    }
                    self.detail_fields(item, depth + 1);
                }
            }
            value => paragraph(self, value.as_str().unwrap_or("unknown"), "38;5;252"),
        }
    }
}

/// Neutralize terminal controls, including ESC and bidi formatting, in remote values.
pub fn safe_text(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                ' '
            } else {
                c
            }
        })
        .collect()
}
