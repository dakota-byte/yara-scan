use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Serialize;
use walkdir::WalkDir;
use yara_x::{Compiler, Scanner};

#[derive(Parser, Debug)]
#[command(
    name = "triage-scanner",
    about = "Multi-threaded YARA scanner for filesystem triage"
)]
struct Cli {
    /// File or directory to scan
    target: PathBuf,

    /// YARA rule file or directory of .yar/.yara files
    #[arg(short, long)]
    rules: PathBuf,

    /// Number of worker threads (defaults to number of CPUs)
    #[arg(short = 'j', long)]
    threads: Option<usize>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Suppress progress output on stderr
    #[arg(short, long)]
    quiet: bool,

    /// Skip files larger than this many bytes (default: 100 MiB)
    #[arg(long, default_value_t = 100 * 1024 * 1024)]
    max_size: u64,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Serialize)]
struct Match {
    file: String,
    rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
}

#[derive(Serialize)]
struct Report {
    target: String,
    rules_loaded: usize,
    files_scanned: usize,
    matches: Vec<Match>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    if let Some(n) = cli.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .context("failed to configure thread pool")?;
    }

    let rules = load_rules(&cli.rules, cli.quiet)?;
    let rules_loaded = rules.iter().count();

    let files: Vec<PathBuf> = WalkDir::new(&cli.target)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    let files_scanned = files.len();

    let bar = if cli.quiet {
        ProgressBar::hidden()
    } else {
        let bar = ProgressBar::new(files_scanned as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} scanning [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        bar
    };

    let matches: Vec<Match> = files
        .par_iter()
        .flat_map_iter(|path| {
            let found = scan_file(&rules, path, cli.max_size);
            bar.inc(1);
            found
        })
        .collect();

    bar.finish_and_clear();

    let report = Report {
        target: cli.target.display().to_string(),
        rules_loaded,
        files_scanned,
        matches,
    };

    match cli.format {
        OutputFormat::Text => print_text(&report),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    Ok(if report.matches.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn load_rules(path: &Path, quiet: bool) -> Result<yara_x::Rules> {
    let mut sources: Vec<PathBuf> = Vec::new();
    if path.is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let p = entry.path();
            if p.is_file() {
                if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                    if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara") {
                        sources.push(p.to_path_buf());
                    }
                }
            }
        }
    } else {
        sources.push(path.to_path_buf());
    }

    if sources.is_empty() {
        anyhow::bail!("no YARA rule files found at {}", path.display());
    }

    // First pass: find which files compile on their own. Community rulesets
    // routinely contain files that reference undefined external variables or
    // modules we haven't enabled; we skip those rather than aborting.
    let mut good: Vec<(PathBuf, String)> = Vec::new();
    let mut skipped = 0usize;

    let bar = if quiet {
        ProgressBar::hidden()
    } else {
        let bar = ProgressBar::new(sources.len() as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} compiling rules [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        bar
    };

    for src in &sources {
        bar.inc(1);
        let content = match std::fs::read_to_string(src) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("warning: skipping {}: {e}", src.display());
                skipped += 1;
                continue;
            }
        };

        let mut probe = Compiler::new();
        match probe.add_source(content.as_str()) {
            Ok(_) => good.push((src.clone(), content)),
            Err(e) => {
                eprintln!("warning: skipping {}: {}", src.display(), first_line(&e.to_string()));
                skipped += 1;
            }
        }
    }

    if good.is_empty() {
        anyhow::bail!(
            "no usable rules loaded from {} ({} file(s) skipped)",
            path.display(),
            skipped
        );
    }

    // Second pass: compile all the good files together into one ruleset.
    let mut compiler = Compiler::new();
    for (src, content) in &good {
        compiler
            .add_source(content.as_str())
            .with_context(|| format!("failed to compile rules from {}", src.display()))?;
    }

    let rules = compiler.build();
    bar.finish_and_clear();
    if !quiet {
        eprintln!(
            "loaded {} rule(s) from {} file(s), skipped {} file(s)",
            rules.iter().count(),
            good.len(),
            skipped
        );
    }

    Ok(rules)
}

fn scan_file(rules: &yara_x::Rules, path: &Path, max_size: u64) -> Vec<Match> {
    // Skip files above the size cap without reading them into memory.
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > max_size {
            return Vec::new();
        }
    }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let mut scanner = Scanner::new(rules);
    let results = match scanner.scan(&data) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    results
        .matching_rules()
        .map(|r| {
            let mut description = None;
            let mut author = None;
            let mut severity = None;

            for (key, value) in r.metadata() {
                let text = meta_value_to_string(&value);
                match key {
                    "description" => description = Some(text),
                    "author" => author = Some(text),
                    "severity" => severity = Some(text),
                    _ => {}
                }
            }

            Match {
                file: path.display().to_string(),
                rule: r.identifier().to_string(),
                description,
                author,
                severity,
            }
        })
        .collect()
}

/// Render a YARA-X metadata value as a plain string.
fn meta_value_to_string(value: &yara_x::MetaValue) -> String {
    match value {
        yara_x::MetaValue::Integer(i) => i.to_string(),
        yara_x::MetaValue::Float(f) => f.to_string(),
        yara_x::MetaValue::Bool(b) => b.to_string(),
        yara_x::MetaValue::String(s) => s.to_string(),
        yara_x::MetaValue::Bytes(b) => format!("{b:?}"),
    }
}

/// Return the first line of a (possibly multi-line) error message.
fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or("").trim()
}

fn print_text(report: &Report) {
    let n = report.matches.len();

    if n == 0 {
        println!(
            "\n{}  {}",
            "CLEAN".green().bold(),
            format!("no matches in {}", report.target).dimmed()
        );
    } else {
        println!(
            "\n{}  {} match(es) in {}",
            "ALERT".red().bold(),
            n.to_string().red().bold(),
            report.target
        );
        println!("{}", "─".repeat(60).dimmed());

        for m in &report.matches {
            println!(
                "  {} {}",
                "▸".red().bold(),
                m.rule.bold()
            );
            println!("    {} {}", "file:".dimmed(), m.file);
            if let Some(sev) = &m.severity {
                println!("    {} {}", "severity:".dimmed(), sev.yellow());
            }
            if let Some(desc) = &m.description {
                println!("    {} {}", "desc:".dimmed(), desc);
            }
            if let Some(author) = &m.author {
                println!("    {} {}", "author:".dimmed(), author);
            }
            println!();
        }
    }

    println!("{}", "─".repeat(60).dimmed());
    println!(
        "  {} {}   {} {}   {} {}",
        "rules:".dimmed(),
        report.rules_loaded.to_string().cyan(),
        "files:".dimmed(),
        report.files_scanned.to_string().cyan(),
        "matches:".dimmed(),
        if n == 0 {
            n.to_string().green()
        } else {
            n.to_string().red().bold()
        },
    );
}
