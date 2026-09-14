//! Vérifie qu'aucun interpréteur de commandes n'est joignable depuis le code.
//!
//! La matrice de sécurité du projet interdit formellement l'exécution de
//! processus : toute commande distante est une variante d'énumération, jamais
//! une chaîne. Ce test balaie les sources de l'espace de travail et échoue si un
//! moyen d'exécuter un processus y apparaît — y compris ajouté par
//! inadvertance, ce qui est précisément le scénario contre lequel il protège.
//!
//! Ce n'est pas une preuve formelle : un appel FFI direct à `CreateProcessW`
//! passerait au travers. C'est un garde-fou contre la dérive ordinaire, qui est
//! la façon dont ces choses arrivent en pratique.

use std::path::{Path, PathBuf};

/// Motifs interdits, avec l'explication qui accompagnera l'échec.
const FORBIDDEN: &[(&str, &str)] = &[
    ("std::process::Command", "exécution de processus"),
    ("process::Command", "exécution de processus"),
    ("Command::new", "exécution de processus"),
    ("CreateProcessW", "création de processus Win32"),
    ("CreateProcessA", "création de processus Win32"),
    ("ShellExecuteW", "lancement par le shell"),
    ("ShellExecuteA", "lancement par le shell"),
    ("WinExec", "lancement de programme"),
    ("libc::system", "appel système d'interpréteur"),
];

#[test]
fn no_source_file_can_reach_a_command_interpreter() {
    let root = workspace_root();
    let mut findings = Vec::new();

    for file in rust_sources(&root.join("crates")) {
        // Ce fichier cite les motifs par nature.
        if file.ends_with("no_shell.rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (line_number, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or(line);
            for (pattern, reason) in FORBIDDEN {
                if code.contains(pattern) {
                    findings.push(format!(
                        "{}:{} — {pattern} ({reason})",
                        file.display(),
                        line_number + 1
                    ));
                }
            }
        }
    }

    assert!(
        findings.is_empty(),
        "des moyens d'exécuter un processus ont été introduits :\n{}\n\n\
         La surface de commande doit rester une énumération fermée ; voir la \
         matrice de sécurité du projet.",
        findings.join("\n")
    );
}

#[test]
fn the_scan_actually_reads_the_sources() {
    // Un test qui ne lit rien passerait toujours. Celui-ci vérifie que le
    // balayage voit bien le code de l'agent.
    let files = rust_sources(&workspace_root().join("crates"));
    assert!(
        files.len() > 10,
        "seulement {} fichiers balayés : le chemin de recherche est faux",
        files.len()
    );
    assert!(
        files.iter().any(|f| f.ends_with("control.rs")),
        "le dispatcher de commandes doit faire partie du balayage"
    );
}

/// Remonte à la racine de l'espace de travail depuis le crate courant.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<nom>/ sous la racine")
        .to_path_buf()
}

/// Liste récursivement les fichiers `.rs`, en ignorant les artefacts de build.
fn rust_sources(directory: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            files.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files
}
