use anatoly::ui::Color;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "anatoly",
    version,
    about = "Assess PHP2Shell exposure using bounded HTTP evidence."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    /// ANSI color mode; auto respects redirected output and NO_COLOR.
    #[arg(long, value_enum, default_value = "auto", global = true)]
    pub color: Color,
    /// Suppress the decorative header.
    #[arg(long, global = true)]
    pub no_banner: bool,
    /// Emit one complete JSON report on stdout.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Display tool version and advisory snapshot.
    Version,
    /// Show upstream fixed releases.
    Builds,
    /// Show research sources and implementation credits.
    Credits,
    /// Discover PHP releases, evidence, and PHP2Shell exposure.
    Scan(Box<ScanArgs>),
    /// Discover public PHP diagnostics and information disclosures.
    Exposure(Box<ScanArgs>),
    /// Inspect response security headers and recognized session cookies.
    Headers(Box<ScanArgs>),
    /// Repeat bounded scans and display only meaningful changes.
    Watch(Box<WatchArgs>),
    /// Compare two saved aggregate scan reports without network access.
    Compare {
        before: PathBuf,
        after: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Generate a self-contained HTML report without network access.
    Report {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value = "html")]
        format: ReportFormat,
    },
    /// Evaluate a saved report against optional JSON rules.
    Policy {
        input: PathBuf,
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Explain the evidence and limitations in a saved report.
    Explain { input: PathBuf },
    /// Validate scan settings and local HTTP client setup without requests.
    Doctor(Box<ScanArgs>),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ReportFormat {
    Html,
    Csv,
    Sarif,
}

#[derive(Args)]
pub struct WatchArgs {
    #[command(flatten)]
    pub scan: ScanArgs,
    /// Seconds between completed rounds (no overlapping scans).
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u32).range(1..=86_400))]
    pub interval: u32,
    /// Finite number of rounds; interrupt the process to stop earlier.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=1000))]
    pub iterations: u16,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Quick,
    #[default]
    Balanced,
    Thorough,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailOn {
    #[default]
    Any,
    Affected,
    Error,
    Never,
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("input").args(["targets", "url", "list"]).required(true).multiple(true)))]
pub struct ScanArgs {
    /// Extra request header, repeatable. Values are never exported. One origin only.
    #[arg(
        short = 'H',
        long = "header",
        allow_hyphen_values = true,
        help_heading = "HTTP transport"
    )]
    pub header: Vec<String>,
    /// Read a complete Name: value header from an environment variable; repeatable.
    #[arg(long, help_heading = "HTTP transport")]
    pub header_env: Vec<String>,
    /// Read HTTP Basic user:password from an environment variable; never print it.
    #[arg(long, help_heading = "HTTP transport")]
    pub basic_auth_env: Option<String>,
    /// Map HOST:IP without changing Host/SNI; repeatable. Requires --no-proxy.
    #[arg(long, help_heading = "HTTP transport")]
    pub resolve: Vec<String>,
    /// Append at most 64 diagnostic paths from a file (64 KiB max).
    #[arg(long, help_heading = "Analysis")]
    pub wordlist: Option<PathBuf>,
    /// Add one benign query-marker request within the shared target budget.
    #[arg(long, help_heading = "Analysis")]
    pub waf_probe: bool,
    /// Export scan/exposure findings as CSV to a new file.
    #[arg(long, help_heading = "Output and CI")]
    pub csv: Option<PathBuf>,
    /// Export scan/exposure findings as SARIF 2.1.0 to a new file.
    #[arg(long, help_heading = "Output and CI")]
    pub sarif: Option<PathBuf>,
    /// Absolute HTTP(S) URLs.
    pub targets: Vec<String>,
    /// Target URL; repeatable alternative to positional URLs.
    #[arg(short, long, help_heading = "Targets and scope")]
    pub url: Vec<String>,
    /// One URL per line; blank and # comment lines ignored.
    #[arg(short, long, help_heading = "Targets and scope")]
    pub list: Option<PathBuf>,
    /// Restrict every supplied target to an exact hostname; repeatable, no wildcards/ports.
    #[arg(long, help_heading = "Targets and scope")]
    pub allow_host: Vec<String>,
    /// Exclude an absolute path prefix from targets, discovery and redirects; repeatable.
    #[arg(long, help_heading = "Targets and scope")]
    pub exclude_path: Vec<String>,
    /// Reject HTTP targets before sending any request.
    #[arg(long, help_heading = "Targets and scope")]
    pub https_only: bool,
    /// Maximum distinct input URLs, checked before any request.
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u16).range(1..=256), help_heading = "Targets and scope")]
    pub max_targets: u16,
    /// quick: supplied URL only; balanced: normal discovery; thorough: extended discovery.
    #[arg(
        long,
        value_enum,
        default_value = "balanced",
        help_heading = "Analysis"
    )]
    pub profile: Profile,
    /// Add known public diagnostic/metadata paths; default request budget becomes 32.
    #[arg(long, help_heading = "Analysis")]
    pub deep: bool,
    /// Application responses to sample (profile defaults: 1/3/5).
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=5), help_heading = "Analysis")]
    pub samples: Option<u8>,
    /// Probe only supplied URLs; disable fixed and linked path discovery.
    #[arg(long, help_heading = "Analysis")]
    pub no_discover: bool,
    /// Skip following disclosed diagnostic links, keeping configured paths.
    #[arg(long, help_heading = "Analysis")]
    pub no_linked_discovery: bool,
    /// Omit cookie-shape hypotheses while retaining explicit version proofs.
    #[arg(long, help_heading = "Analysis")]
    pub no_cookie_hints: bool,
    /// Keep explicit version evidence, suppress all weak hypotheses.
    #[arg(long, help_heading = "Analysis")]
    pub no_hypotheses: bool,
    /// Replace default diagnostic paths; repeatable, same origin only.
    #[arg(long, help_heading = "Analysis")]
    pub diagnostic_path: Vec<String>,
    /// Requests per target including redirects (profile defaults: 4/8/32).
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=32), help_heading = "Budgets and pacing")]
    pub max_requests: Option<u16>,
    /// Per-request timeout in seconds, including body reading.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u16).range(1..=120), help_heading = "Budgets and pacing")]
    pub timeout: u16,
    /// Connection timeout in seconds, also bounded by request/target timeouts.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u16).range(1..=120), help_heading = "Budgets and pacing")]
    pub connect_timeout: u16,
    /// Total HTTP phase per target in seconds, including pacing and redirects.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u16).range(1..=3600), help_heading = "Budgets and pacing")]
    pub target_timeout: u16,
    /// Minimum spacing in milliseconds (quick:500, balanced/thorough:150).
    #[arg(long, value_parser = clap::value_parser!(u16).range(0..=5000), help_heading = "Budgets and pacing")]
    pub delay_ms: Option<u16>,
    /// Upper request rate per target; cannot weaken --delay-ms.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=100), help_heading = "Budgets and pacing")]
    pub rate_limit: Option<u16>,
    /// Maximum bytes retained from each response body.
    #[arg(long, default_value_t = 262_144, value_parser = clap::value_parser!(u32).range(1024..=1_048_576), help_heading = "Budgets and pacing")]
    pub max_body: u32,
    /// Maximum followed redirects in one request chain (default:5).
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=10), conflicts_with = "no_redirects", help_heading = "HTTP transport")]
    pub max_redirects: Option<u8>,
    /// Return the initial redirect response without following it.
    #[arg(long, help_heading = "HTTP transport")]
    pub no_redirects: bool,
    /// HTTP(S) proxy without credentials, path or query, e.g. http://127.0.0.1:8080.
    #[arg(long, conflicts_with = "no_proxy", help_heading = "HTTP transport")]
    pub proxy: Option<String>,
    /// Disable environment/system proxy selection.
    #[arg(long, help_heading = "HTTP transport")]
    pub no_proxy: bool,
    /// Public PEM root certificate to add to normal TLS trust; no private keys.
    #[arg(long, help_heading = "HTTP transport")]
    pub ca_cert: Option<PathBuf>,
    /// Write full JSON to a new file; existing files are never overwritten.
    #[arg(short, long, help_heading = "Output and CI")]
    pub output: Option<PathBuf>,
    /// Emit target events as JSON lines, then a summary event.
    #[arg(long, conflicts_with_all = ["json", "summary_only", "dry_run"], help_heading = "Output and CI")]
    pub jsonl: bool,
    /// Show only the final human summary; exports still contain complete reports.
    #[arg(long, conflicts_with_all = ["json", "dry_run"], help_heading = "Output and CI")]
    pub summary_only: bool,
    /// any:normal exits; affected:ignore unknown; error:transport only; never:0 after scan.
    #[arg(
        long,
        value_enum,
        default_value = "any",
        help_heading = "Output and CI"
    )]
    pub fail_on: FailOn,
    /// Validate all settings and print a redacted plan; send no HTTP requests.
    #[arg(long, help_heading = "Output and CI")]
    pub dry_run: bool,
}
