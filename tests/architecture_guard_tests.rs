use std::fs;
use std::path::{Path, PathBuf};

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("directory should be readable") {
        let entry = entry.expect("directory entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, files);
            continue;
        }

        let extension = path.extension().and_then(std::ffi::OsStr::to_str);
        if matches!(extension, Some("rs" | "md" | "mdx")) {
            files.push(path);
        }
    }
}

#[test]
fn legacy_persistence_symbols_are_gone_from_tracked_sources() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let guard_file = root.join("tests/architecture_guard_tests.rs");
    let banned = [
        "DatabaseAdapter",
        "AuthDatabase",
        "SeaOrmStore",
        "UserOps",
        "SessionOps",
        "AccountOps",
        "VerificationOps",
        "OrganizationOps",
        "MemberOps",
        "InvitationOps",
        "TwoFactorOps",
        "ApiKeyOps",
        "PasskeyOps",
    ];
    let mut files = Vec::new();

    for relative in ["crates", "src", "tests", "docs", "examples"] {
        collect_files(&root.join(relative), &mut files);
    }

    let mut violations = Vec::new();
    for path in files {
        if path == guard_file {
            continue;
        }
        let content = fs::read_to_string(&path).expect("source file should be readable");
        for symbol in &banned {
            if content.contains(symbol) {
                violations.push(format!("{} -> {}", path.display(), symbol));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "legacy persistence symbols remain:\n{}",
        violations.join("\n")
    );
}
