mod client;
mod config;
mod domain;
mod pipeline;
mod progress;
mod whitelist;

use clap::Parser;
use config::AppConfig;
use std::process;

#[derive(Parser)]
#[command(name = "pihole-optimizer")]
#[command(version = "3.0.0")]
#[command(about = "Pi-hole Blocklist Optimizer v3.0 — Downloads, optimizes, and organizes Pi-hole blocklists")]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "blocklists.conf")]
    config: String,

    /// Whitelist file path
    #[arg(short, long, default_value = "whitelist.txt")]
    whitelist: String,

    /// Base output directory for individual lists
    #[arg(short, long, default_value = "pihole_blocklists")]
    base_dir: String,

    /// Production output directory for combined lists
    #[arg(short, long, default_value = "pihole_blocklists_prod")]
    prod_dir: String,

    /// Number of concurrent downloads (1-16)
    #[arg(short, long, default_value_t = 4)]
    threads: usize,

    /// HTTP request timeout in seconds
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Skip downloading (use existing local files)
    #[arg(long)]
    skip_download: bool,

    /// Skip creating production lists
    #[arg(long)]
    skip_optimize: bool,

    /// Disable incremental updates (force full re-download)
    #[arg(long)]
    no_incremental: bool,

    /// Dry run mode (show what would happen without doing it)
    #[arg(long)]
    dry_run: bool,

    /// Disable subdomain matching in whitelist
    #[arg(long)]
    no_whitelist_subdomain: bool,

    /// Generate detailed whitelist match report
    #[arg(long)]
    whitelist_report: bool,

    /// Verbose logging (debug level)
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode (errors only)
    #[arg(short, long)]
    quiet: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let log_level = if cli.verbose {
        log::LevelFilter::Debug
    } else if cli.quiet {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "{} - {} - {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();

    let config = AppConfig {
        config_file: cli.config,
        whitelist_file: cli.whitelist,
        base_dir: cli.base_dir,
        prod_dir: cli.prod_dir,
        threads: cli.threads.clamp(1, 16),
        timeout: if cli.timeout == 0 { 30 } else { cli.timeout },
        skip_download: cli.skip_download,
        skip_optimize: cli.skip_optimize,
        incremental: !cli.no_incremental,
        dry_run: cli.dry_run,
        quiet: cli.quiet,
        verbose: cli.verbose,
        whitelist_subdomain: !cli.no_whitelist_subdomain,
        whitelist_report: cli.whitelist_report,
    };

    if !config.quiet {
        println!();
        println!("{}", "=".repeat(60));
        println!("{:>35}", "PI-HOLE BLOCKLIST OPTIMIZER v3.0");
        println!("{}", "=".repeat(60));
        println!();
    }

    let mut manager = match pipeline::BlocklistManager::new(config) {
        Ok(m) => m,
        Err(e) => {
            log::error!("{e:#}");
            process::exit(1);
        }
    };

    if let Err(e) = manager.run().await {
        log::error!("{e:#}");
        process::exit(1);
    }
}
