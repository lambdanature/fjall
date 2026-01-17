// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! CLI tool for interacting with fjall databases

// TODO: remove these and fix the warnings instead
#![allow(unused_imports)]
#![allow(unused)]

use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use humansize::{SizeFormatter, BINARY};
use path_clean::PathClean;
use pretty_hex::{HexConfig, PrettyHex};
use rustyline::DefaultEditor;
use std::collections::HashMap;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    prelude::*,
    registry::Registry,
};
use typed_path::{TypedPath, TypedPathBuf};

macro_rules! die {
    ($fmt:literal, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
        std::process::exit(1);
    }};

    ($msg:literal) => {{
        eprintln!($msg);
        std::process::exit(1);
    }};

    () => {{
        eprintln!("Program terminated unexpectedly");
        std::process::exit(1);
    }};
}

// There are multiple relevant crates, but this should suffice
macro_rules! pluralize {
    // Case 1: Word and Count (Simple "s" suffix)
    ($word:expr, $count:expr) => {
        if $count == 1 {
            $word.to_string()
        } else {
            format!("{}s", $word)
        }
    };

    // Case 2: Singular, Plural, and Count (Explicit forms)
    ($singular:expr, $plural:expr, $count:expr) => {
        if $count == 1 {
            $singular.to_string()
        } else {
            $plural.to_string()
        }
    };
}

#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

pub fn init_tracing(quiet: bool, verbose: u8) -> (bool, LevelFilter) {
    let is_verbose = !quiet && verbose > 0;

    let level_filter = if quiet {
        LevelFilter::ERROR
    } else {
        match verbose {
            0 => LevelFilter::WARN,
            1 => LevelFilter::INFO,
            2 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        }
    };

    // Bridge log crate macros to tracing (for library code that uses log::*)
    tracing_log::LogTracer::init().expect("Failed to set log tracer");

    let registry = Registry::default();

    let env_filter = EnvFilter::builder()
        .with_default_directive(level_filter.into())
        .with_env_var("FJALL_LOG")
        .from_env_lossy()
        .add_directive(
            "rustyline=warn"
                .parse()
                .expect("Failed to parse rustyline directive"),
        );

    let subscriber = registry.with(env_filter).with(
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .compact(),
    );

    if tracing::subscriber::set_global_default(subscriber).is_err() {
        die!("INTERNAL ERROR: setting default tracing::subscriber failed");
    }

    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing_panic::panic_hook(info);
        prev_hook(info); // daisy-chain to old panic hook
    }));

    (is_verbose, level_filter)
}

fn parse_size_as_u32(s: &str) -> Result<u32, String> {
    let cfg = parse_size::Config::new().with_binary();
    cfg.parse_size(s)
        .map(|size| size as u32)
        .map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ShellMode {
    Unix,
    Windows,
}

// static DEFAULT_KV_SEPARATION_OPTIONS: LazyLock<KvSeparationOptions> =
//     LazyLock::new(|| KvSeparationOptions::default());
// static DEFAULT_SEPARATION_THRESHOLD: LazyLock<String> = LazyLock::new(|| {
//     SizeFormatter::new(DEFAULT_KV_SEPARATION_OPTIONS.separation_threshold, BINARY).to_string()
// });

/// CLI tool for interacting with fjall databases
#[derive(Parser, Debug)]
#[command(name = "fjall")]
#[command(about = "CLI tool for interacting with fjall databases")]
struct ToolArgs {
    /// Suppress all output except for errors. This overrides the -v flag.
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Turn on verbose output. Supply -v multiple times to increase verbosity.
    #[arg(short, long, action = ArgAction::Count, global = true)]
    verbose: u8,

    /// Path to the fjall db directory (will be created if it doesn't exist)
    fjall_path: PathBuf,

    /// Shell mode, use shortcut -W to set Windows mode
    #[arg(
        long,
        short = 'M',
        global = true,
        default_value_if("windows", "true", Some("windows")),
        default_value_if("unix", "false", Some("unix")),
        default_value = "unix",
        overrides_with("windows"),
        overrides_with("unix")
    )]
    mode: ShellMode,

    /// Windows shell mode (\ as path separator and PowerShell-style escaping / quoting)
    #[arg(short = 'W', long, global = true)]
    windows: bool,

    /// Unix shell mode (/ as path separator and Shell-style escaping / quoting)
    #[arg(short = 'U', long, global = true)]
    unix: bool,
    /// Command to run (if omitted, starts interactive shell)
    #[command(subcommand)]
    command: Option<ToolCommand>,
}

#[derive(Subcommand, Debug, Clone)]
enum ToolCommand {
    // TODO: Copy (cp), Move (mv): transactional Copy + Del
    // TODO: Scan/Del: Ability to glob keys in addition to prefix scan
    /// Get the value for a key
    #[command(visible_alias = "cat")]
    Get {
        /// The key to look up
        key: String,

        /// Output value as hex bytes
        #[arg(short = 'C', long)]
        hex: bool,
    },
    /// Set a key-value pair
    Set {
        /// The key to set
        key: String,
        /// The value to store
        value: String,
    },
    /// Delete a key
    #[command(visible_alias = "rm")]
    Del {
        /// The key to delete
        key: String,

        /// Recursively delete all keys with this prefix
        #[arg(short, long)]
        recursive: bool,

        /// Print each key as it's deleted
        #[arg(short = 'p', long = "print")]
        print_keys: bool,

        /// Force deletion (required to delete an entire keyspace)
        #[arg(short, long)]
        force: bool,
    },
    /// List all keys, optionally filtered by prefix
    #[command(visible_alias = "list", visible_alias = "ls")]
    Scan {
        /// Optional prefix to filter keys
        prefix: Option<String>,

        /// Show internal key fields (seqno, value_type)
        #[arg(short = 'l', long = "long")]
        long: bool,

        /// Ignored (no hidden keys exist)
        #[arg(short = 'a', long = "all", hide = true)]
        _all: bool,
    },
    #[command(hide = true, alias = "ll", alias = "la")]
    ScanLong {
        /// Optional prefix to filter keys
        prefix: Option<String>,
    },
    /// List keys in a range [start, end)
    Range {
        /// Start of the range (inclusive)
        start: String,
        /// End of the range (exclusive)
        end: String,
    },
    /// Count the number of items
    Count,
    /// Flush memtable to disk
    Flush,
    /// Run major compaction
    Compact {
        /// Paths to keyspaces to compact (defaults to current keyspace)
        #[arg(conflicts_with = "all")]
        paths: Vec<String>,

        /// Compact all keyspaces
        #[arg(short, long, conflicts_with = "paths")]
        all: bool,
    },
    /// Show db statistics
    Info,
}

// Internal shell commands, include all external tool commands
#[derive(Parser, Debug)]
#[command(name = "")]
#[command(no_binary_name = true)]
#[command(disable_version_flag = true)]
#[command(help_template = "
{version}

Available Commands:

{subcommands}

Use `help COMMAND` or `COMMAND --help` for more details.

")]

struct ShellArgs {
    #[command(subcommand)]
    command: ShellCommand,
}

// Shell commands (including ones not available from CLI)
#[derive(Subcommand, Debug, Clone)]
enum ShellCommand {
    #[command(flatten)]
    ToolCmd(ToolCommand),

    /// Exit the current shell (with implicit flush)
    #[command(visible_alias = "quit")]
    Exit,
    /// Abort the curent shell (without flush)
    Abort,
    /// Begin a new batch (transaction)
    Begin,
    /// Commit the current batch
    Commit,
    /// Rollback (discard) the current batch
    Rollback,
    /// Print current working directory
    Pwd,
    /// Change current working directory
    Cd {
        /// Path to change to (absolute or relative)
        path: Option<String>,
    },
    /// Create a keyspace (mkdir)
    Mkdir {
        /// Path to create (first component is the keyspace name)
        path: String,
    },
}

/// A pending operation in a batch
#[derive(Debug, Clone)]
enum BatchOp {
    Set { key: String, value: String },
    Del { key: String },
}

/// A batch of pending operations
#[derive(Debug, Default)]
struct Batch {
    /// Operations in order they were added
    ops: Vec<BatchOp>,
    /// Current state of keys in the batch (for reads)
    state: HashMap<String, Option<String>>,
}

/// Encapsulates a database path buffer and associated keyspace information.
#[derive(Debug, Clone)]
struct DbPathBuf {
    /// The underlying path (like cwd)
    path: TypedPathBuf,
    /// The corresponding keyspace
    keyspace: Option<String>,
    /// The corresponding prefix within the keyspace
    prefix: Option<String>,
}

impl DbPathBuf {
    pub fn new_root(mode: ShellMode) -> Self {
        Self {
            path: match mode {
                ShellMode::Windows => TypedPathBuf::from_windows("\\"),
                ShellMode::Unix => TypedPathBuf::from_unix("/"),
            },
            keyspace: None,
            prefix: None,
        }
    }

    /// Construct a new DbPathBuf, extracting the keyspace component if present.
    pub fn new(path: &str, mode: ShellMode) -> Self {
        let path = match mode {
            ShellMode::Windows => TypedPathBuf::from_windows(path),
            ShellMode::Unix => TypedPathBuf::from_unix(path),
        };
        let path = path.normalize();

        let keyspace = Self::extract_keyspace(&path);
        let prefix = Self::extract_prefix(&path);
        Self {
            path,
            keyspace,
            prefix,
        }
    }

    pub fn join_str(&self, other: &str) -> Self {
        let other_path = if self.path.is_windows() {
            TypedPathBuf::from_windows(other)
        } else {
            TypedPathBuf::from_unix(other)
        };
        let path = self.path.join(other_path).normalize();
        let keyspace = Self::extract_keyspace(&path);
        let prefix = Self::extract_prefix(&path);
        Self {
            path: path,
            keyspace,
            prefix,
        }
    }

    /// Extract keyspace name from a path, if any (first normal/filename component)
    fn extract_keyspace(path: &TypedPathBuf) -> Option<String> {
        path.components().find_map(|c| match c {
            typed_path::TypedComponent::Unix(typed_path::UnixComponent::Normal(name))
            | typed_path::TypedComponent::Windows(typed_path::WindowsComponent::Normal(name)) => {
                Some(String::from_utf8_lossy(name).into_owned())
            }
            _ => None,
        })
    }

    /// Extract the prefix from a path, which is everything after the first element joined by path separator.
    /// For example, `/keyspace1/key1/key2` would return `key1/key2`.
    pub fn extract_prefix(path: &TypedPathBuf) -> Option<String> {
        let components: Vec<_> = path.components().collect();

        // Find the index of the first normal component
        let first_normal_idx = components.iter().position(|c| {
            matches!(
                c,
                typed_path::TypedComponent::Unix(typed_path::UnixComponent::Normal(_))
                    | typed_path::TypedComponent::Windows(typed_path::WindowsComponent::Normal(_))
            )
        })?;

        // Collect all normal components after the first one
        let remaining: Vec<_> =
            components
                .iter()
                .skip(first_normal_idx + 1)
                .filter_map(|c| match c {
                    typed_path::TypedComponent::Unix(typed_path::UnixComponent::Normal(name))
                    | typed_path::TypedComponent::Windows(typed_path::WindowsComponent::Normal(
                        name,
                    )) => Some(String::from_utf8_lossy(name).into_owned()),
                    _ => None,
                })
                .collect();

        if remaining.is_empty() {
            None
        } else {
            let separator = if path.is_windows() { "\\" } else { "/" };
            Some(remaining.join(separator))
        }
    }

    /// Update both the path and current keyspace and prefix.
    pub fn set_path(&mut self, path: TypedPathBuf) {
        self.path = path.clone();
        self.keyspace = Self::extract_keyspace(&path);
        self.prefix = Self::extract_prefix(&path);
    }

    /// Return the contained TypedPathBuf (like cwd).
    pub fn path(&self) -> &TypedPathBuf {
        &self.path
    }

    /// Return the current keyspace (if any) as a string reference.
    pub fn keyspace(&self) -> Option<&str> {
        self.keyspace.as_deref()
    }
}

struct ShellSession {
    path: PathBuf,
    db: Database,
    cwd: DbPathBuf,
    mode: ShellMode,
    keyspace_cache: HashMap<String, Keyspace>,
}

impl ShellSession {
    fn open(path: PathBuf, mode: ShellMode) -> Result<Self, fjall::Error> {
        let db = Database::builder(&path).open()?;
        Ok(Self {
            path,
            db,
            cwd: DbPathBuf::new_root(mode),
            mode,
            keyspace_cache: HashMap::new(),
        })
    }

    /// Get or open a keyspace, using the cache if available.
    ///
    /// # Errors
    ///
    /// Returns error if the keyspace cannot be opened.
    fn get_or_create_keyspace(&mut self, name: &str) -> Result<&Keyspace, fjall::Error> {
        if !self.keyspace_cache.contains_key(name) {
            let keyspace = self
                .db
                .keyspace(name, || KeyspaceCreateOptions::default())?;
            self.keyspace_cache.insert(name.to_string(), keyspace);
        }
        Ok(self.keyspace_cache.get(name).unwrap())
    }

    /// Get an existing keyspace, using the cache if available.
    /// Fails if the keyspace does not exist.
    ///
    /// # Errors
    ///
    /// Returns error if the keyspace does not exist or cannot be opened.
    fn get_existing_keyspace(&mut self, name: &str) -> Result<&Keyspace, fjall::Error> {
        // TODO: This has a race condition (TOCTOU - Time-of-Check to Time-of-Use)
        //       if the keyspace is created elsewhere between the check and the creation
        if !self.keyspace_cache.contains_key(name) {
            if !self.db.keyspace_exists(name) {
                return Err(fjall::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("keyspace '{}' does not exist", name),
                )));
            }
            let keyspace = self
                .db
                .keyspace(name, || KeyspaceCreateOptions::default())?;
            self.keyspace_cache.insert(name.to_string(), keyspace);
        }
        Ok(self.keyspace_cache.get(name).unwrap())
    }
}

fn print_info(session: &mut ShellSession) {
    let db = &session.db;

    println!("=== Database Information ===");
    println!("Path: {}", session.path.display());

    // Configuration
    println!("\n=== Configuration ===");
    let cache_capacity = db.cache_capacity();
    println!(
        "Cache capacity: {}",
        SizeFormatter::new(cache_capacity, BINARY)
    );
    println!("Worker threads: {}", db.config.worker_threads());
    println!(
        "Max journaling size: {}",
        SizeFormatter::new(db.config.max_journaling_size_in_bytes(), BINARY)
    );
    println!(
        "Journal compression: {:?}",
        db.config.journal_compression_type()
    );
    if let Some(max_write_buffer) = db.config.max_write_buffer_size_in_bytes() {
        println!(
            "Max write buffer size: {}",
            SizeFormatter::new(max_write_buffer, BINARY)
        );
    } else {
        println!("Max write buffer size: unlimited");
    }
    println!(
        "Manual journal persist: {}",
        db.config.manual_journal_persist()
    );

    // Statistics
    println!("\n=== Statistics ===");
    let write_buffer_size = db.write_buffer_size();
    println!(
        "Write buffer size: {}",
        SizeFormatter::new(write_buffer_size, BINARY)
    );
    println!("Outstanding flushes: {}", db.outstanding_flushes());
    println!("Active compactions: {}", db.active_compactions());
    println!("Compactions completed: {}", db.compactions_completed());
    let time_compacting = db.time_compacting();
    if time_compacting.as_secs() > 0 {
        println!(
            "Time spent compacting: {:.2}s",
            time_compacting.as_secs_f64()
        );
    } else {
        println!(
            "Time spent compacting: {:.2}ms",
            time_compacting.as_millis()
        );
    }

    // Sequence numbers
    println!("\n=== Sequence Numbers ===");
    println!("Current seqno: {}", db.seqno());
    println!("Visible seqno: {}", db.visible_seqno());

    // Journal information
    println!("\n=== Journal ===");
    println!("Journal count: {}", db.journal_count());
    match db.journal_disk_space() {
        Ok(size) => {
            println!("Journal disk space: {}", SizeFormatter::new(size, BINARY));
        }
        Err(e) => {
            println!("Journal disk space: Error: {}", e);
        }
    }

    // Total disk space
    println!("\n=== Disk Usage ===");
    match db.disk_space() {
        Ok(size) => {
            println!("Total disk space: {}", SizeFormatter::new(size, BINARY));
        }
        Err(e) => {
            println!("Total disk space: Error: {}", e);
        }
    }

    // Keyspace information
    println!("\n=== Keyspaces ===");
    let keyspace_count = db.keyspace_count();
    println!("Keyspace count: {}", keyspace_count);

    if keyspace_count > 0 {
        // Collect keyspace names first to avoid holding db reference
        let keyspace_names: Vec<String> = db
            .list_keyspace_names()
            .iter()
            .filter_map(|name| {
                let name_str = std::str::from_utf8(name.as_bytes()).ok()?;
                if db.keyspace_exists(name_str) {
                    Some(name_str.to_string())
                } else {
                    None
                }
            })
            .collect();

        // Now iterate and use the cache without holding db reference
        for name_str in keyspace_names {
            match session.get_or_create_keyspace(&name_str) {
                Ok(ks) => {
                    let disk_space = ks.disk_space();
                    let approx_len = ks.approximate_len();
                    println!(
                        "  {}: disk_space={}, approximate_len={}",
                        name_str,
                        SizeFormatter::new(disk_space, BINARY),
                        approx_len
                    );
                }
                Err(e) => {
                    println!("  {}: Error accessing keyspace: {}", name_str, e);
                }
            }
        }
    }
}

fn handle_get(session: &mut ShellSession, key: &str, hex: bool) {
    // Resolve target path using the same logic as handle_cd
    let target_path = session.cwd.join_str(key);

    let Some(keyspace_name) = target_path.keyspace().map(|s| s.to_string()) else {
        eprintln!(
            "Error: no keyspace selected (use 'cd <keyspace>' first, \
                   or provide an path containing a keyspace name)"
        );
        return;
    };

    // The key is the prefix portion of the resolved path
    let Some(full_key) = target_path.prefix.clone() else {
        eprintln!("Error: no key specified within keyspace {}", keyspace_name);
        return;
    };

    let keyspace = match session.get_existing_keyspace(&keyspace_name) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error: cannot open keyspace '{}': {}", keyspace_name, e);
            return;
        }
    };

    match keyspace.get(&full_key) {
        Ok(Some(value)) => {
            if hex {
                // Force hex output
                let cfg = HexConfig {
                    title: false,
                    width: 16,
                    group: 8,
                    ..HexConfig::default()
                };
                println!("{:?}", value.hex_conf(cfg));
            } else {
                // Try to print as UTF-8 string, fall back to hex representation
                match std::str::from_utf8(&value) {
                    Ok(s) => println!("{}", s),
                    Err(_) => {
                        let cfg = HexConfig {
                            title: false,
                            width: 16,
                            group: 8,
                            ..HexConfig::default()
                        };
                        println!("{:?}", value.hex_conf(cfg));
                    }
                }
            }
        }
        Ok(None) => {
            eprintln!(
                "Key '{}' not found in keyspace '{}'",
                full_key, keyspace_name
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}

fn handle_set(session: &mut ShellSession, key: &str, value: &str, flush: bool) {
    // Resolve target path using the same logic as handle_get
    let target_path = session.cwd.join_str(key);

    let Some(keyspace_name) = target_path.keyspace().map(|s| s.to_string()) else {
        eprintln!(
            "Error: no keyspace selected (use 'cd <keyspace>' first, \
                   or provide a path containing a keyspace name)"
        );
        return;
    };

    // The key is the prefix portion of the resolved path
    let Some(full_key) = target_path.prefix.clone() else {
        eprintln!("Error: no key specified within keyspace {}", keyspace_name);
        return;
    };

    let keyspace = match session.get_existing_keyspace(&keyspace_name) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error: cannot open keyspace '{}': {}", keyspace_name, e);
            return;
        }
    };

    match keyspace.insert(&full_key, value) {
        Ok(()) => {
            if flush {
                match session.db.persist(PersistMode::SyncAll) {
                    Ok(()) => println!("OK"),
                    Err(e) => eprintln!("Error: insert succeeded but flush failed: {}", e),
                }
            } else {
                println!("OK");
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}

fn handle_del(
    session: &mut ShellSession,
    key: &str,
    recursive: bool,
    print_keys: bool,
    force: bool,
    flush: bool,
) {
    // Resolve target path using the same logic as handle_get
    let target_path = session.cwd.join_str(key);

    let Some(keyspace_name) = target_path.keyspace().map(|s| s.to_string()) else {
        eprintln!(
            "Error: no keyspace selected (use 'cd <keyspace>' first, \
                   or provide a path containing a keyspace name)"
        );
        return;
    };

    // The key is the prefix portion of the resolved path
    let full_key = target_path.prefix.clone();

    // If no key specified, check if we should delete the entire keyspace
    if full_key.is_none() {
        if force {
            // Refuse to delete the current keyspace
            if session
                .cwd
                .keyspace()
                .map(|s| s == keyspace_name)
                .unwrap_or(false)
            {
                eprintln!(
                    "Error: cannot delete current keyspace '{}'.\n\
                     Hint: Use 'cd /' to leave the keyspace first.",
                    keyspace_name
                );
                return;
            }

            // Delete the entire keyspace
            // First, remove from cache to get ownership
            let keyspace = match session.keyspace_cache.remove(&keyspace_name) {
                Some(ks) => ks,
                None => {
                    // Not in cache, try to open it first
                    match session.get_existing_keyspace(&keyspace_name) {
                        Ok(_) => {
                            // Now remove from cache
                            session.keyspace_cache.remove(&keyspace_name).unwrap()
                        }
                        Err(e) => {
                            eprintln!("Error: cannot open keyspace '{}': {}", keyspace_name, e);
                            return;
                        }
                    }
                }
            };

            match session.db.delete_keyspace(keyspace) {
                Ok(()) => {
                    if print_keys {
                        println!("DEL KEYSPACE {}", keyspace_name);
                    }
                    println!("OK (deleted keyspace '{}')", keyspace_name);
                }
                Err(e) => {
                    eprintln!(
                        "Error: failed to delete keyspace '{}': {}",
                        keyspace_name, e
                    );
                }
            }
        } else {
            eprintln!(
                "Error: no key specified within keyspace '{}'.\n\
                 Hint: Use --force (-f) to delete the entire keyspace.",
                keyspace_name
            );
        }
        return;
    }

    let full_key = full_key.unwrap();

    let keyspace = match session.get_existing_keyspace(&keyspace_name) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error: cannot open keyspace '{}': {}", keyspace_name, e);
            return;
        }
    };

    if recursive {
        // Collect all keys with this prefix first to avoid borrowing issues
        let keys_to_delete: Vec<Vec<u8>> = keyspace
            .prefix(&full_key)
            .filter_map(|guard| guard.key().ok().map(|k| k.to_vec()))
            .collect();

        if keys_to_delete.is_empty() {
            println!("OK (no keys matched prefix '{}')", full_key);
        } else {
            let mut deleted = 0;
            let mut errors = 0;

            for k in &keys_to_delete {
                match keyspace.remove(k.as_slice()) {
                    Ok(()) => {
                        if print_keys {
                            println!("DEL {}", String::from_utf8_lossy(k));
                        }
                        deleted += 1;
                    }
                    Err(e) => {
                        eprintln!(
                            "Error: failed to delete key '{}': {}",
                            String::from_utf8_lossy(k),
                            e
                        );
                        errors += 1;
                    }
                }
            }

            if errors == 0 {
                println!(
                    "OK (deleted {} {})",
                    deleted,
                    if deleted == 1 { "key" } else { "keys" }
                );
            } else {
                println!(
                    "PARTIAL (deleted {} {}, {} failed)",
                    deleted,
                    if deleted == 1 { "key" } else { "keys" },
                    errors
                );
            }
        }
    } else {
        // Delete single key
        match keyspace.remove(&full_key) {
            Ok(()) => {
                if print_keys {
                    println!("DEL {}", full_key);
                }
                println!("OK");
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                return;
            }
        }
    }

    if flush {
        if let Err(e) = session.db.persist(PersistMode::SyncAll) {
            eprintln!("Error: delete succeeded but flush failed: {}", e);
        }
    }
}

fn handle_scan(session: &mut ShellSession, path: Option<&str>, long: bool) {
    // Resolve target path - use provided path or current directory
    let target_path = if let Some(p) = path {
        session.cwd.join_str(p)
    } else {
        session.cwd.clone()
    };

    let Some(keyspace_name) = target_path.keyspace().map(|s| s.to_string()) else {
        // At root level - list keyspaces
        handle_scan_root(session, long);
        return;
    };

    // The prefix is the path portion after the keyspace (may be None for full scan)
    let key_prefix = target_path.prefix.clone();

    let keyspace = match session.get_existing_keyspace(&keyspace_name) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error: cannot open keyspace '{}': {}", keyspace_name, e);
            return;
        }
    };

    if long {
        handle_scan_keyspace_long(&keyspace, key_prefix.as_deref());
    } else {
        handle_scan_keyspace(&keyspace, key_prefix.as_deref());
    }
}

fn handle_scan_root(session: &ShellSession, long: bool) {
    let db = &session.db;
    let keyspace_names: Vec<String> = db
        .list_keyspace_names()
        .iter()
        .filter_map(|name| {
            let name_str = std::str::from_utf8(name.as_bytes()).ok()?;
            if db.keyspace_exists(name_str) {
                Some(name_str.to_string())
            } else {
                None
            }
        })
        .collect();

    if long {
        for name in &keyspace_names {
            // Try to get keyspace info for long mode
            match db.keyspace(name, KeyspaceCreateOptions::default) {
                Ok(ks) => {
                    let disk_space = ks.disk_space();
                    let approx_len = ks.approximate_len();
                    let kv_sep = if ks.is_kv_separated() { " [blob]" } else { "" };
                    println!(
                        "{}/  disk={}, ~{} items{}",
                        name,
                        SizeFormatter::new(disk_space, BINARY),
                        approx_len,
                        kv_sep
                    );
                }
                Err(_) => {
                    println!("{}/", name);
                }
            }
        }
    } else {
        for name in &keyspace_names {
            println!("{}/", name);
        }
    }

    println!(
        "OK ({} {})",
        keyspace_names.len(),
        pluralize!("keyspace", keyspace_names.len())
    );
}

fn handle_scan_keyspace(keyspace: &Keyspace, prefix: Option<&str>) {
    let mut count = 0;
    let prefix_len = prefix.map(|p| p.len()).unwrap_or(0);

    // Use prefix iterator if we have a prefix, otherwise iterate all
    let iter: Box<dyn Iterator<Item = _>> = if let Some(prefix) = prefix {
        Box::new(keyspace.prefix(prefix))
    } else {
        Box::new(keyspace.iter())
    };

    for guard in iter {
        match guard.into_inner() {
            Ok((key, value)) => {
                // Strip the prefix to show relative path
                let key_str = String::from_utf8_lossy(&key[prefix_len..]);
                let value_str = String::from_utf8_lossy(&value);
                println!("{} = {}", key_str, value_str);
                count += 1;
            }
            Err(e) => {
                eprintln!("Error reading entry: {}", e);
            }
        }
    }

    println!("OK ({} {})", count, pluralize!("item", count));
}

fn handle_scan_keyspace_long(keyspace: &Keyspace, prefix: Option<&str>) {
    let mut count = 0;
    let mut total_key_bytes: u64 = 0;
    let mut total_value_bytes: u64 = 0;
    let prefix_len = prefix.map(|p| p.len()).unwrap_or(0);

    // Use prefix iterator if we have a prefix, otherwise iterate all
    let iter: Box<dyn Iterator<Item = _>> = if let Some(prefix) = prefix {
        Box::new(keyspace.prefix(prefix))
    } else {
        Box::new(keyspace.iter())
    };

    for guard in iter {
        match guard.into_inner() {
            Ok((key, value)) => {
                let value_len = value.len();
                total_key_bytes += key.len() as u64;
                total_value_bytes += value_len as u64;

                // Strip the prefix to show relative path
                let rel_key = &key[prefix_len..];
                let rel_key_len = rel_key.len();
                let key_str = String::from_utf8_lossy(rel_key);

                // Format value: show as string if valid UTF-8, otherwise hex preview
                let value_preview = format_value_preview(&value, 64);

                println!(
                    "{} ({}B) = {} ({}B)",
                    key_str, rel_key_len, value_preview, value_len
                );
                count += 1;
            }
            Err(e) => {
                eprintln!("Error reading entry: {}", e);
            }
        }
    }

    println!(
        "OK ({} {}, keys={}, values={})",
        count,
        pluralize!("item", count),
        SizeFormatter::new(total_key_bytes, BINARY),
        SizeFormatter::new(total_value_bytes, BINARY)
    );
}

/// Format a value for preview, truncating if necessary and showing hex for binary data
fn format_value_preview(value: &[u8], max_len: usize) -> String {
    if value.is_empty() {
        return "<empty>".to_string();
    }

    // Check if it's valid UTF-8
    match std::str::from_utf8(value) {
        Ok(s) => {
            if s.len() <= max_len {
                format!("\"{}\"", s.escape_default())
            } else {
                format!("\"{}\"... (+{}B)", &s[..max_len].escape_default(), s.len() - max_len)
            }
        }
        Err(_) => {
            // Show hex preview for binary data
            let preview_len = max_len.min(value.len());
            let hex: String = value[..preview_len]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            if value.len() > preview_len {
                format!("<{}>... (+{}B)", hex, value.len() - preview_len)
            } else {
                format!("<{}>", hex)
            }
        }
    }
}

fn handle_range(session: &ShellSession, start: &str, end: &str) {
    let mut count = 0;
    println!("({} items (not implemented))", count);
}

fn handle_count(session: &ShellSession) {
    let mut count = 0;
    println!("{} (not implemented)", count);
    // match session.tree.len(SeqNo::MAX, None) {
    //     Ok(count) => println!("{}", count),
    //     Err(e) => eprintln!("Error: {}", e),
    // }
}

fn handle_flush(session: &ShellSession) {
    match session.db.persist(PersistMode::SyncAll) {
        Ok(()) => println!("OK (flushed)"),
        Err(e) => eprintln!("Error: failed to flush: {}", e),
    }
}

fn handle_compact(session: &mut ShellSession, paths: &[String], all: bool) {
    // Step 1: Collect the list of keyspaces to compact
    let keyspace_names: Vec<String> = if all {
        // Collect all keyspaces
        session
            .db
            .list_keyspace_names()
            .iter()
            .filter_map(|name| {
                let name_str = std::str::from_utf8(name.as_bytes()).ok()?;
                Some(name_str.to_string())
            })
            .collect()
    } else if paths.is_empty() {
        // No paths provided, use current directory
        let Some(keyspace_name) = session.cwd.keyspace().map(|s| s.to_string()) else {
            eprintln!(
                "Error: no keyspace selected.\n\
                 Hint: Use 'cd <keyspace>', provide a path, or use -a to compact all keyspaces."
            );
            return;
        };
        vec![keyspace_name]
    } else {
        // Resolve keyspaces from provided paths
        let mut names = Vec::new();
        for p in paths {
            let target_path = session.cwd.join_str(p);
            if let Some(keyspace_name) = target_path.keyspace() {
                names.push(keyspace_name.to_string());
            } else {
                eprintln!("Error: invalid path '{}' (no keyspace component)", p);
            }
        }
        names
    };

    // Remove duplicates while preserving order
    let mut seen = std::collections::HashSet::new();
    let keyspace_names: Vec<String> = keyspace_names
        .into_iter()
        .filter(|name| seen.insert(name.clone()))
        .collect();

    if keyspace_names.is_empty() {
        println!("No keyspaces to compact");
        return;
    }

    // Step 2: Compact each keyspace
    let mut success_count = 0;
    let mut error_count = 0;

    for keyspace_name in &keyspace_names {
        match session.get_existing_keyspace(keyspace_name) {
            Ok(keyspace) => match keyspace.major_compact() {
                Ok(()) => {
                    println!("INFO (compacted '{}')", keyspace_name);
                    success_count += 1;
                }
                Err(e) => {
                    eprintln!("Error: compaction failed for '{}': {}", keyspace_name, e);
                    error_count += 1;
                }
            },
            Err(e) => {
                eprintln!("Error: cannot open keyspace '{}': {}", keyspace_name, e);
                error_count += 1;
            }
        }
    }

    println!(
        "{} ({} {} compacted, {} {} failed)",
        if error_count == 0 { "OK" } else { "FAILED" },
        success_count,
        pluralize!("keyspace", success_count),
        error_count,
        pluralize!("keyspace", error_count),
    );
}

fn handle_pwd(session: &ShellSession) {
    println!("{}", session.cwd.path().to_string_lossy());
}

fn handle_cd(session: &mut ShellSession, path: Option<&str>) {
    let old_path = session.cwd.clone();
    let old_path_str = old_path.path().to_string_lossy();
    if let Some(path) = path {
        let new_path = session.cwd.join_str(path);

        if let Some(keyspace_name) = new_path.keyspace() {
            // Try to open the existing keyspace - fail if it doesn't exist or can't be opened
            match session.get_existing_keyspace(&keyspace_name) {
                Ok(_) => {
                    debug!("Keyspace {keyspace_name} opened successfully, proceeding with cd"); // Keyspace opened successfully, proceed with cd
                    session.cwd = new_path;
                }
                Err(e) => {
                    eprintln!("Error: cannot open keyspace '{}': {}", keyspace_name, e);
                    return;
                }
            }
        } else {
            // No keyspace component (just "/"), proceed with cd
            session.cwd = new_path;
        }
    } else {
        // No path provided, change to root
        session.cwd = DbPathBuf::new_root(session.mode);
    }
    let new_path = session.cwd.path().to_string_lossy();
    debug!("changed cwd from {old_path_str:?} to {new_path:?}");
}

fn handle_mkdir(session: &mut ShellSession, path: &str) {
    let new_path = session.cwd.join_str(path);

    if let Some(keyspace_name) = new_path.keyspace() {
        // Check if keyspace already exists
        if session.db.keyspace_exists(&keyspace_name) {
            println!("OK (keyspace '{}' already exists)", keyspace_name);
            return;
        }
        // TODO: This has a race condition (TOCTOU - Time-of-Check to Time-of-Use)
        //       if the keyspace is created elsewhere between the check and the creation
        // Create the keyspace if it doesn't exist
        match session.get_or_create_keyspace(&keyspace_name) {
            Ok(_) => {
                println!("OK (created keyspace '{keyspace_name}')");
            }
            Err(e) => {
                eprintln!("Error: cannot create keyspace '{}': {}", keyspace_name, e);
            }
        }
    } else {
        eprintln!("Error: Root already exists");
    }
}

/// Result of executing a command
enum CommandResult {
    Continue,
    Exit,
}

/// Execute a parsed command
fn execute_command(
    session: &mut ShellSession,
    cmd: ToolCommand,
    auto_flush: bool,
) -> CommandResult {
    match cmd {
        ToolCommand::Get { key, hex } => handle_get(session, &key, hex),
        ToolCommand::Set { key, value } => handle_set(session, &key, &value, auto_flush),
        ToolCommand::Del {
            key,
            recursive,
            print_keys,
            force,
        } => handle_del(session, &key, recursive, print_keys, force, auto_flush),
        ToolCommand::Scan { prefix, long, _all } => handle_scan(session, prefix.as_deref(), long),
        ToolCommand::ScanLong { prefix } => handle_scan(session, prefix.as_deref(), true),
        ToolCommand::Range { start, end } => handle_range(session, &start, &end),
        ToolCommand::Count => handle_count(session),
        ToolCommand::Flush => handle_flush(session),
        ToolCommand::Compact { paths, all } => handle_compact(session, &paths, all),
        ToolCommand::Info => print_info(session),
    }
    CommandResult::Continue
}

/// Execute a shell-only command
fn execute_shell_command(
    session: &mut ShellSession,
    cmd: ShellCommand,
    auto_flush: bool,
) -> CommandResult {
    match cmd {
        ShellCommand::ToolCmd(tool_cmd) => execute_command(session, tool_cmd, auto_flush),
        ShellCommand::Exit => {
            // if session.has_batch() {
            //     eprintln!("Warning: discarding uncommitted batch");
            //     session.rollback_batch();
            // }
            handle_flush(session);
            CommandResult::Exit
        }
        ShellCommand::Abort => {
            // if session.has_batch() {
            //     eprintln!("Warning: discarding uncommitted batch");
            // }
            CommandResult::Exit
        }
        ShellCommand::Begin => {
            // if session.begin_batch() {
            //     println!("OK (batch started)");
            // } else {
            //    eprintln!("Error: batch already active");
            // }
            CommandResult::Continue
        }
        ShellCommand::Commit => {
            // if session.commit_batch() {
            //    println!("OK (batch committed, ready to flush)");
            //} else {
            //    eprintln!("Error: no active batch");
            //}
            CommandResult::Continue
        }
        ShellCommand::Rollback => {
            //if session.rollback_batch() {
            //    println!("OK (batch rolled back)");
            //} else {
            //    eprintln!("Error: no active batch");
            //}
            CommandResult::Continue
        }
        ShellCommand::Pwd => {
            handle_pwd(session);
            CommandResult::Continue
        }
        ShellCommand::Cd { path } => {
            handle_cd(session, path.as_deref());
            CommandResult::Continue
        }
        ShellCommand::Mkdir { path } => {
            handle_mkdir(session, &path);
            CommandResult::Continue
        }
    }
}

/// Parse and run a shell command line
fn run_shell_command(session: &mut ShellSession, line: &str) -> CommandResult {
    let line = line.trim();
    if line.is_empty() {
        return CommandResult::Continue;
    }

    let tokens = match session.mode {
        ShellMode::Windows => {
            // Use winsplit to parse Windows-style command line (VC++ 2008 rules)
            winsplit::split(line)
        }
        ShellMode::Unix => match shlex::split(line) {
            Some(t) => t,
            Some(_) => return CommandResult::Continue,
            None => {
                eprintln!("error: unclosed quote");
                return CommandResult::Continue;
            }
        },
    };

    if tokens.is_empty() {
        return CommandResult::Continue;
    }

    // Parse remaining commands
    match ShellArgs::try_parse_from(&tokens) {
        Ok(args) => execute_shell_command(session, args.command, false),
        Err(e) => {
            // Print clap's error message
            eprintln!("{}", e);
            CommandResult::Continue
        }
    }
}

fn run_shell(session: &mut ShellSession) {
    if io::stdin().is_terminal() {
        run_shell_interactive(session);
    } else {
        run_shell_non_interactive(session);
    }
}

fn run_shell_interactive(session: &mut ShellSession) {
    let filename: String = match session.path.file_name() {
        Some(filename) => filename.to_string_lossy().into_owned(),
        None => die!(
            "can't extract filename from path: {}",
            session.cwd.path().to_string_lossy()
        ),
    };

    println!("Welcome to the fjall shell");
    println!("Type 'help' for available commands, 'exit' to quit.\n");

    let mut rl = match DefaultEditor::new() {
        Ok(editor) => editor,
        Err(e) => {
            eprintln!("Error initializing line editor: {}", e);
            return;
        }
    };

    loop {
        let prompt = format!(
            "fjall({filename}):{}> ",
            session.cwd.path().to_string_lossy()
        );
        match rl.readline(&prompt) {
            Ok(line) => {
                rl.add_history_entry(&line);
                if let CommandResult::Exit = run_shell_command(session, &line) {
                    break;
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                // Ignore Ctrl+C, just show a new prompt
                continue;
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        }
    }
}

fn run_shell_non_interactive(session: &mut ShellSession) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        if stdout.flush().is_err() {
            die!("can't flush stdout");
        }

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => {
                // EOF
                break;
            }
            Ok(_) => {
                if let CommandResult::Exit = run_shell_command(session, &line) {
                    break;
                }
            }
            Err(e) => {
                die!("Error reading input: {}", e);
            }
        }
    }
}

fn main() {
    let args = ToolArgs::parse();
    let (verbose, level_filter) = init_tracing(args.quiet, args.verbose);

    let cmd = ToolArgs::command();

    info!(
        "starting {} ({} {}), log level: {level_filter}",
        cmd.get_name(),
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    let mode = if args.windows {
        ShellMode::Windows
    } else {
        args.mode
    };

    let mut session = match ShellSession::open(args.fjall_path, mode) {
        Ok(s) => s,
        Err(e) => {
            let note = if verbose {
                ""
            } else {
                ". Note: Use -v (one or multiple times) for more information"
            };
            die!("Error opening tree: {}{}", e, note);
        }
    };

    match args.command {
        Some(cmd) => {
            execute_command(&mut session, cmd, true);
        }
        None => run_shell(&mut session),
    }
}
