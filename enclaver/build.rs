use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const GIT_REV_ENV: &str = "ENCLAVER_GIT_REVISION";
const VERSION_ENV: &str = "ENCLAVER_VERSION_WITH_GIT";

fn main() {
    println!("cargo:rerun-if-env-changed={GIT_REV_ENV}");

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()));
    let repo_root = manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir);

    if let Some(git_dir) = resolve_git_dir(&repo_root) {
        emit_git_rerun_hints(&git_dir);
    }

    let git_revision = env::var(GIT_REV_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| read_git_revision(&repo_root))
        .unwrap_or_else(|| "unknown".to_string());

    let version_with_git = format!("{} (git {git_revision})", env!("CARGO_PKG_VERSION"));

    println!("cargo:rustc-env={GIT_REV_ENV}={git_revision}");
    println!("cargo:rustc-env={VERSION_ENV}={version_with_git}");
}

fn resolve_git_dir(repo_root: &Path) -> Option<PathBuf> {
    let dot_git = repo_root.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    if !dot_git.is_file() {
        return None;
    }

    let contents = fs::read_to_string(&dot_git).ok()?;
    let git_dir = contents.trim().strip_prefix("gitdir:")?.trim();
    let git_path = PathBuf::from(git_dir);
    if git_path.is_absolute() {
        Some(git_path)
    } else {
        Some(repo_root.join(git_path))
    }
}

fn emit_git_rerun_hints(git_dir: &Path) {
    let head_path = git_dir.join("HEAD");
    if head_path.exists() {
        println!("cargo:rerun-if-changed={}", head_path.display());
    }

    let packed_refs = git_dir.join("packed-refs");
    if packed_refs.exists() {
        println!("cargo:rerun-if-changed={}", packed_refs.display());
    }

    if let Ok(head_contents) = fs::read_to_string(&head_path)
        && let Some(reference) = head_contents.trim().strip_prefix("ref: ")
    {
        let reference_path = git_dir.join(reference.trim());
        if reference_path.exists() {
            println!("cargo:rerun-if-changed={}", reference_path.display());
        }
    }
}

fn read_git_revision(repo_root: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let revision = String::from_utf8(output.stdout).ok()?;
    let revision = revision.trim();
    if revision.is_empty() {
        None
    } else {
        Some(revision.to_string())
    }
}
