// TODO: remove these and fix the warnings instead
#![allow(unused_imports)]
#![allow(unused)]

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use humansize::{SizeFormatter, BINARY};
use path_clean::PathClean;
use pretty_hex::{HexConfig, PrettyHex};
use rustyline::DefaultEditor;
use std::collections::HashMap;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, trace, warn};
use typed_path::{TypedPath, TypedPathBuf};

use crate::tool_cli::{init_tracing, ShellMode};
use crate::pluralize;
use enquote;

/// Encapsulates a database path buffer and associated keyspace information.
#[derive(Debug, Clone)]
pub struct DbPathBuf {
    /// The underlying path (like cwd)
    pub path: TypedPathBuf,
    /// The corresponding keyspace
    pub keyspace: Option<String>,
    /// The corresponding prefix within the keyspace
    pub prefix: Option<String>,
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

pub struct ShellSession {
    pub path: PathBuf,
    db: Database,
    pub cwd: DbPathBuf,
    pub mode: ShellMode,
    keyspace_cache: HashMap<String, Keyspace>,
}

impl ShellSession {
    pub fn open(path: PathBuf, mode: ShellMode) -> Result<Self, fjall::Error> {
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

    pub fn print_info(&mut self) {
        let db = &self.db;

        println!("=== Database Information ===");
        println!("Path: {}", self.path.display());

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
                match self.get_or_create_keyspace(&name_str) {
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

    pub fn handle_get(&mut self, key: &str, hex: bool) {
        // Resolve target path using the same logic as handle_cd
        let target_path = self.cwd.join_str(key);

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

        let keyspace = match self.get_existing_keyspace(&keyspace_name) {
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
                        Ok(s) => println!("{}", enquote::enquote('"', s)),
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

    pub fn handle_set(&mut self, key: &str, value: &str, flush: bool) {
        // Resolve target path using the same logic as handle_get
        let target_path = self.cwd.join_str(key);

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

        let keyspace = match self.get_existing_keyspace(&keyspace_name) {
            Ok(ks) => ks,
            Err(e) => {
                eprintln!("Error: cannot open keyspace '{}': {}", keyspace_name, e);
                return;
            }
        };

        match keyspace.insert(&full_key, value) {
            Ok(()) => {
                if flush {
                    match self.db.persist(PersistMode::SyncAll) {
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

    pub fn handle_del(
        &mut self,
        key: &str,
        recursive: bool,
        print_keys: bool,
        force: bool,
        flush: bool,
    ) {
        // Resolve target path using the same logic as handle_get
        let target_path = self.cwd.join_str(key);

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
                if self
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
                let keyspace = match self.keyspace_cache.remove(&keyspace_name) {
                    Some(ks) => ks,
                    None => {
                        // Not in cache, try to open it first
                        match self.get_existing_keyspace(&keyspace_name) {
                            Ok(_) => {
                                // Now remove from cache
                                self.keyspace_cache.remove(&keyspace_name).unwrap()
                            }
                            Err(e) => {
                                eprintln!("Error: cannot open keyspace '{}': {}", keyspace_name, e);
                                return;
                            }
                        }
                    }
                };

                match self.db.delete_keyspace(keyspace) {
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

        let keyspace = match self.get_existing_keyspace(&keyspace_name) {
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
            if let Err(e) = self.db.persist(PersistMode::SyncAll) {
                eprintln!("Error: delete succeeded but flush failed: {}", e);
            }
        }
    }

    pub fn handle_scan(&mut self, path: Option<&str>, long: bool) {
        // Resolve target path - use provided path or current directory
        let target_path = if let Some(p) = path {
            self.cwd.join_str(p)
        } else {
            self.cwd.clone()
        };

        let Some(keyspace_name) = target_path.keyspace().map(|s| s.to_string()) else {
            // At root level - list keyspaces
            self.scan_root(long);
            return;
        };

        // The prefix is the path portion after the keyspace (may be None for full scan)
        let key_prefix = target_path.prefix.clone();

        let keyspace = match self.get_existing_keyspace(&keyspace_name) {
            Ok(ks) => ks,
            Err(e) => {
                eprintln!("Error: cannot open keyspace '{}': {}", keyspace_name, e);
                return;
            }
        };

        if long {
            scan_keyspace_long(keyspace, key_prefix.as_deref());
        } else {
            scan_keyspace(keyspace, key_prefix.as_deref());
        }
    }

    fn scan_root(&self, long: bool) {
        let db = &self.db;
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

    pub fn handle_range(&self, start: &str, end: &str) {
        let count = 0;
        println!("({} items (not implemented))", count);
    }

    pub fn handle_count(&self) {
        let count = 0;
        println!("{} (not implemented)", count);
    }

    pub fn handle_flush(&self) {
        match self.db.persist(PersistMode::SyncAll) {
            Ok(()) => println!("OK (flushed)"),
            Err(e) => eprintln!("Error: failed to flush: {}", e),
        }
    }

    pub fn handle_compact(&mut self, paths: &[String], all: bool) {
        // Step 1: Collect the list of keyspaces to compact
        let keyspace_names: Vec<String> = if all {
            // Collect all keyspaces
            self.db
                .list_keyspace_names()
                .iter()
                .filter_map(|name| {
                    let name_str = std::str::from_utf8(name.as_bytes()).ok()?;
                    Some(name_str.to_string())
                })
                .collect()
        } else if paths.is_empty() {
            // No paths provided, use current directory
            let Some(keyspace_name) = self.cwd.keyspace().map(|s| s.to_string()) else {
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
                let target_path = self.cwd.join_str(p);
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
            match self.get_existing_keyspace(keyspace_name) {
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

    pub fn handle_pwd(&self) {
        println!("{}", self.cwd.path().to_string_lossy());
    }

    pub fn handle_cd(&mut self, path: Option<&str>) {
        let old_path = self.cwd.clone();
        let old_path_str = old_path.path().to_string_lossy();
        if let Some(path) = path {
            let new_path = self.cwd.join_str(path);

            if let Some(keyspace_name) = new_path.keyspace() {
                // Try to open the existing keyspace - fail if it doesn't exist or can't be opened
                match self.get_existing_keyspace(&keyspace_name) {
                    Ok(_) => {
                        debug!("Keyspace {keyspace_name} opened successfully, proceeding with cd");
                        self.cwd = new_path;
                    }
                    Err(e) => {
                        eprintln!("Error: cannot open keyspace '{}': {}", keyspace_name, e);
                        return;
                    }
                }
            } else {
                // No keyspace component (just "/"), proceed with cd
                self.cwd = new_path;
            }
        } else {
            // No path provided, change to root
            self.cwd = DbPathBuf::new_root(self.mode);
        }
        let new_path = self.cwd.path().to_string_lossy();
        debug!("changed cwd from {old_path_str:?} to {new_path:?}");
    }

    pub fn handle_mkdir(&mut self, path: &str) {
        let new_path = self.cwd.join_str(path);

        if let Some(keyspace_name) = new_path.keyspace() {
            // Check if keyspace already exists
            if self.db.keyspace_exists(&keyspace_name) {
                println!("OK (keyspace '{}' already exists)", keyspace_name);
                return;
            }
            // TODO: This has a race condition (TOCTOU - Time-of-Check to Time-of-Use)
            //       if the keyspace is created elsewhere between the check and the creation
            // Create the keyspace if it doesn't exist
            match self.get_or_create_keyspace(&keyspace_name) {
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
}

// Helper functions for scan operations

fn scan_keyspace(keyspace: &Keyspace, prefix: Option<&str>) {
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
                println!("{} = {}", key_str, enquote::enquote('"', &value_str));
                count += 1;
            }
            Err(e) => {
                eprintln!("Error reading entry: {}", e);
            }
        }
    }

    println!("OK ({} {})", count, pluralize!("item", count));
}

fn scan_keyspace_long(keyspace: &Keyspace, prefix: Option<&str>) {
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
                enquote::enquote('"', s)
            } else {
                format!(
                    "{}... (+{}B)",
                    enquote::enquote('"', &s[..max_len]),
                    s.len() - max_len
                )
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
