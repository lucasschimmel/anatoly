use crate::{
    scan::ScanReport,
    scan_view::{field, line, paragraph},
    ui::Ui,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn render(ui: &Ui, report: &ScanReport) {
    if report.tls.is_empty() && report.waf.is_empty() {
        return;
    }
    line(ui, "", "38;5;245");
    paragraph(ui, "TRANSPORT / TLS & EDGE OBSERVATIONS", "1;38;5;81");
    for tls in &report.tls {
        field(ui, "TLS peer", &tls.source, "38;5;252");
        field(ui, "Certificate", &tls.status, "38;5;252");
        if let Some(subject) = &tls.subject {
            field(ui, "Subject", subject, "38;5;245");
        }
        if let Some(issuer) = &tls.issuer {
            field(ui, "Issuer", issuer, "38;5;245");
        }
        if let Some(expiry) = tls.not_after_unix {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            field(
                ui,
                "Expiry",
                &format!(
                    "Unix {expiry} / approximately {} days remaining",
                    (expiry - now) / 86_400
                ),
                "38;5;245",
            );
        }
        field(
            ui,
            "TLS protocol",
            tls.protocol
                .as_deref()
                .unwrap_or("not reported by native TLS backend"),
            "38;5;245",
        );
    }
    for marker in report.waf.iter().take(8) {
        field(ui, &marker.product, &marker.signal, "38;5;221");
    }
    paragraph(
        ui,
        "Peer metadata can describe an edge or proxy. Vendor markers do not prove WAF enforcement or protection against PHP2Shell.",
        "38;5;245",
    );
}
