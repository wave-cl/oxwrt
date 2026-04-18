//! Kernel module loading — walks /etc/modules-boot.d then
//! /etc/modules.d, resolves deps via modules.dep OR .modinfo byte-scan,
//! calls finit_module(2).
//! Split out of init.rs in step 6.

use super::*;

pub(super) fn load_modules() {
    // Resolve the running kernel release once — matches `uname -r`.
    let kernel_release = match rustix::system::uname().release().to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::warn!("load_modules: cannot read kernel release; skipping");
            return;
        }
    };
    let modules_root = PathBuf::from(format!("/lib/modules/{kernel_release}"));
    if !modules_root.exists() {
        tracing::warn!(
            root = %modules_root.display(),
            "load_modules: kernel modules root missing; skipping"
        );
        return;
    }

    // Parse modules.dep once up front. Maps module name → list of
    // dep module names (in bottom-up load order per depmod's
    // convention). Best-effort: if the file is missing or unparseable
    // we continue with an empty map; load_one_module then runs without
    // dep resolution and the /sys/module pre-check keeps it safe.
    let depmap = parse_modules_dep(&modules_root);

    for dir in ["/etc/modules-boot.d", "/etc/modules.d"] {
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                tracing::warn!(dir, error = %e, "load_modules: read_dir failed");
                continue;
            }
        };
        let mut files: Vec<_> = rd
            .filter_map(|r| r.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        for f in files {
            load_modules_file(&f, &modules_root, &depmap);
        }
    }
}

/// Parse /lib/modules/<ver>/modules.dep into a map of
/// `module_name → [dep_names]`. Format:
///
///     kernel/fs/f2fs/f2fs.ko: kernel/crypto/crc32c-generic.ko
///     kernel/net/ipv4/ip_tables.ko:
///     kernel/net/ipv4/nf_reject_ipv4.ko: kernel/net/nf_tables.ko
///
/// Each line: module-path ':' then zero or more dep-paths. We key
/// by the basename-without-.ko.
///
/// Returned deps are in the order they appear, which depmod emits
/// such that loading them left-to-right produces a valid sequence.
/// For our use we do a DFS before loading each top-level module, so
/// order within a single line's deps doesn't matter much — but we
/// preserve it for predictability.
fn parse_modules_dep(modules_root: &Path) -> std::collections::HashMap<String, Vec<String>> {
    // Preferred: read modules.dep if present (built by depmod, e.g. on
    // Debian/Ubuntu). OpenWrt's imagebuilder does NOT generate this
    // file — it relies on each .ko's embedded `depends=` modinfo field
    // read by ubox/kmodloader. Fall through to modinfo scanning when
    // modules.dep is missing.
    let path = modules_root.join("modules.dep");
    if let Ok(content) = std::fs::read_to_string(&path) {
        let mut map = std::collections::HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((lhs, rhs)) = line.split_once(':') else {
                continue;
            };
            let name = module_name_from_ko_path(lhs);
            let deps: Vec<String> = rhs
                .split_whitespace()
                .map(module_name_from_ko_path)
                .collect();
            map.insert(name, deps);
        }
        tracing::debug!(modules = map.len(), "parsed modules.dep");
        return map;
    }
    tracing::debug!(
        path = %path.display(),
        "modules.dep not present; falling back to .modinfo scanning"
    );
    parse_modinfo_deps(modules_root)
}

/// Fallback for OpenWrt-style trees that ship only `.ko` files (no
/// modules.dep). Walks every `*.ko` under `modules_root` and extracts the
/// `depends=` value from the ELF `.modinfo` section. Returns a map of
/// module-name → dep-names, keyed and valued with `-` → `_` canonicalization
/// so it slots straight into the existing `load_with_deps` DFS.
///
/// Why byte-scan instead of proper ELF parsing: `.modinfo` contents are
/// always a sequence of NUL-terminated `key=value` strings, and "depends="
/// is a sufficiently distinctive prefix that a raw memmem search is
/// correct for every real kernel .ko. This keeps oxwrtd dependency-free
/// (no `object` / `goblin` / `elf` crate).
fn parse_modinfo_deps(modules_root: &Path) -> std::collections::HashMap<String, Vec<String>> {
    let mut map = std::collections::HashMap::new();
    let rd = match std::fs::read_dir(modules_root) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::warn!(error = %e, "parse_modinfo_deps: read_dir failed");
            return map;
        }
    };
    for ent in rd.flatten() {
        let path = ent.path();
        if path.extension().and_then(|s| s.to_str()) != Some("ko") {
            continue;
        }
        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.replace('-', "_"),
            None => continue,
        };
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let deps = extract_modinfo_depends(&bytes);
        map.insert(name, deps);
    }
    tracing::debug!(modules = map.len(), "parsed .modinfo dep info");
    map
}

/// Scan ELF bytes for the NUL-terminated `depends=foo,bar,baz` entry in
/// the `.modinfo` section. Returns dep names with `-` → `_`
/// canonicalization; empty list when the module has no deps (a very
/// common case — look at `cfg80211`, `nfnetlink`, etc.).
fn extract_modinfo_depends(bytes: &[u8]) -> Vec<String> {
    const KEY: &[u8] = b"depends=";
    // Find every occurrence of "depends=" — .modinfo typically contains
    // only one, but scanning all of them is safe.
    let mut i = 0usize;
    while i + KEY.len() <= bytes.len() {
        if &bytes[i..i + KEY.len()] == KEY {
            let start = i + KEY.len();
            let end = start
                + bytes[start..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(bytes.len() - start);
            let value = &bytes[start..end];
            if value.is_empty() {
                return Vec::new();
            }
            // Comma-separated, skip empty entries.
            return std::str::from_utf8(value)
                .unwrap_or("")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.replace('-', "_"))
                .collect();
        }
        i += 1;
    }
    Vec::new()
}

/// "kernel/drivers/net/foo.ko" → "foo"
/// "kernel/drivers/net/foo.ko.xz" → "foo"
fn module_name_from_ko_path(p: &str) -> String {
    let base = p.rsplit('/').next().unwrap_or(p);
    let base = base
        .trim_end_matches(".xz")
        .trim_end_matches(".gz")
        .trim_end_matches(".zst");
    let base = base.trim_end_matches(".ko");
    base.to_string()
}

/// Parse one file under /etc/modules{,-boot}.d/ and load each module
/// listed. Format matches stock ubox/kmodloader:
///   # comment
///   <module-name> [param1=val1 param2=val2 ...]
pub(super) fn load_modules_file(
    file: &Path,
    modules_root: &Path,
    depmap: &std::collections::HashMap<String, Vec<String>>,
) {
    let content = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(file = %file.display(), error = %e, "load_modules: read failed");
            return;
        }
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        let Some(name) = it.next() else { continue };
        let params = it.next().unwrap_or("").trim();
        // Depth-first: load all transitive deps before the requested
        // module. Normalize - → _ for lookup; modules.dep uses the
        // underscore form canonical to the kernel.
        let canon = name.replace('-', "_");
        let mut visited = std::collections::HashSet::new();
        load_with_deps(&canon, depmap, modules_root, &mut visited);
        // Now load the requested module (with its params).
        load_one_module(name, params, modules_root);
    }
}

/// Walk the dep tree of `name` depth-first, loading each dep exactly
/// once (params defaulted to empty for dependency loads — they get
/// the kernel's default settings). `visited` short-circuits cycles
/// and repeat visits.
fn load_with_deps(
    name: &str,
    depmap: &std::collections::HashMap<String, Vec<String>>,
    modules_root: &Path,
    visited: &mut std::collections::HashSet<String>,
) {
    if !visited.insert(name.to_string()) {
        return;
    }
    if let Some(deps) = depmap.get(name) {
        for d in deps {
            load_with_deps(d, depmap, modules_root, visited);
        }
        // Finally load this module (no params — deps don't get the
        // config line's params). Skip if this is the top-level caller,
        // which load_modules_file will load with its own params.
        // Detect "top level" by checking: if the module has no deps
        // at all, is_empty is true — but that doesn't uniquely mark
        // us. Use visited.len() instead: exactly 1 means we're the
        // first node to land in the set and load_modules_file will
        // do the final load with params.
        if visited.len() > 1 {
            load_one_module(name, "", modules_root);
        }
    }
}

/// Locate `<name>.ko`(.xz/.gz/.zst) under `modules_root` and
/// finit_module it. Idempotent — EEXIST is success.
fn load_one_module(name: &str, params: &str, modules_root: &Path) {
    // Quick bail: if /sys/module/<name>/ already exists, the module
    // is loaded (or built into the kernel). This catches both the
    // coexist case (procd-init loaded everything upstream) and the
    // case where an earlier file in the sorted iteration pulled the
    // module in as a dependency. Either way: no work needed. Skipping
    // here is faster than calling finit_module and also avoids the
    // Linux "Unknown symbol" noise when we try to load a module that
    // depends on something not yet loaded — procd-init uses
    // modprobe's dep resolution for this; we don't.
    let sys_name = name.replace('-', "_");
    if Path::new(&format!("/sys/module/{sys_name}")).exists() {
        tracing::debug!(module = name, "already present; skipping");
        return;
    }

    // Normalize module name: kmodloader accepts both "-" and "_" forms.
    // The .ko filename is almost always the underscore form, but some
    // packages install with dashes — try both.
    let candidates = [
        format!("{name}.ko"),
        format!("{}.ko", name.replace('-', "_")),
        format!("{}.ko", name.replace('_', "-")),
    ];
    let ko_path = find_ko_under(modules_root, &candidates);
    let Some(ko_path) = ko_path else {
        // Missing .ko + absent from /sys/module: either the package
        // isn't installed in this image or we have a typo. Log at
        // debug — warning here would be noisy in coexist, where the
        // module might have been compiled out but procd-init also
        // skipped it.
        tracing::debug!(
            module = name,
            "not found under /lib/modules and not in /sys/module; skipping"
        );
        return;
    };

    let ko_file = match std::fs::File::open(&ko_path) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(
                module = name,
                path = %ko_path.display(),
                error = %e,
                "load_modules: open .ko failed"
            );
            return;
        }
    };

    // finit_module wants params as a NUL-terminated C string.
    let params_c = match std::ffi::CString::new(params) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(module = name, error = %e, "load_modules: params contain NUL");
            return;
        }
    };

    use std::os::fd::AsFd;
    match rustix::system::finit_module(ko_file.as_fd(), params_c.as_c_str(), 0) {
        Ok(()) => tracing::info!(module = name, "loaded"),
        Err(rustix::io::Errno::EXIST) => {
            tracing::debug!(module = name, "already loaded");
        }
        Err(e) => {
            // ENOENT from finit_module means the module needs a
            // symbol from an unloaded dependency. In coexist mode
            // procd-init resolved this via modprobe ordering; we
            // don't. Treat as debug so the boot log stays clean —
            // when the hot path (Stage 4) runs this function, we'll
            // add modules.dep parsing to drive correct ordering.
            let is_dep_issue = matches!(e, rustix::io::Errno::NOENT | rustix::io::Errno::NOEXEC);
            if is_dep_issue {
                tracing::debug!(module = name, error = %e, "finit_module failed (probable dep issue)");
            } else {
                tracing::warn!(module = name, error = %e, "finit_module failed");
            }
        }
    }
}

/// Recursively walk `root` looking for any of `candidates` as a
/// filename. Returns the first match. O(n) in module tree size but
/// fine on a firmware-sized /lib/modules (a few hundred .ko files).
///
/// Small optimization: cache the tree per-boot? Not worth it for
/// /etc/modules{,-boot}.d/ which has ~5-10 entries total on our
/// image. Defer until profiling shows it matters.
fn find_ko_under(root: &Path, candidates: &[String]) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if candidates.iter().any(|c| c == fname) {
                return Some(path);
            }
        }
    }
    None
}
