//! Vérifie qu'aucun interpréteur de commandes n'est joignable depuis le code.
//!
//! La matrice de sécurité du projet interdit formellement l'exécution de
//! processus : toute commande distante est une variante d'énumération, jamais
//! une chaîne. Ce test balaie les sources de l'espace de travail et échoue si un
//! moyen d'exécuter un processus y apparaît — y compris ajouté par
//! inadvertance, ce qui est précisément le scénario contre lequel il protège.
//!
//! Une exception unique existe : le superviseur de service doit faire naître un
//! processus dans la session interactive. Elle est nommée, justifiée, et le test
//! échoue si elle devient inutile — une exception que plus rien ne justifie est
//! une exception qu'on oublie de retirer.

use std::path::{Path, PathBuf};

/// Le seul endroit du projet autorisé à créer un processus, et le seul motif
/// qui le justifie.
///
/// La ligne de commande y est un `&'static str` : le compilateur refuse toute
/// chaîne construite à l'exécution, donc rien venu du réseau ne peut
/// l'atteindre. C'est cette garantie, et non la relecture, qui rend l'exception
/// acceptable.
const ALLOWED: &[(&str, &str)] = &[(
    "service/launcher.rs",
    "CreateProcessAsUserW",
)];

/// Motifs interdits, avec l'explication qui accompagnera l'échec.
const FORBIDDEN: &[(&str, &str)] = &[
    ("std::process::Command", "exécution de processus"),
    ("process::Command", "exécution de processus"),
    ("Command::new", "exécution de processus"),
    ("CreateProcessW", "création de processus Win32"),
    ("CreateProcessA", "création de processus Win32"),
    // Les variantes qui prennent un jeton : c'est par elles que passe le
    // superviseur, et il faut donc les surveiller, pas les ignorer.
    ("CreateProcessAsUserW", "création de processus sous un autre jeton"),
    ("CreateProcessWithTokenW", "création de processus sous un autre jeton"),
    ("CreateProcessWithLogonW", "création de processus sous d'autres identifiants"),
    ("ShellExecuteW", "lancement par le shell"),
    ("ShellExecuteA", "lancement par le shell"),
    ("WinExec", "lancement de programme"),
    ("libc::system", "appel système d'interpréteur"),
];

#[test]
fn no_source_file_can_reach_a_command_interpreter() {
    let root = workspace_root();
    let mut findings = Vec::new();
    let mut used: std::collections::HashSet<(&str, String)> = std::collections::HashSet::new();

    for file in rust_sources(&root.join("crates")) {
        // Ce fichier cite les motifs par nature.
        if file.ends_with("no_shell.rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let normalized = file.to_string_lossy().replace('\\', "/");
        for (line_number, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or(line);
            for (pattern, reason) in FORBIDDEN {
                if !contains_identifier(code, pattern) {
                    continue;
                }
                let excused = ALLOWED
                    .iter()
                    .any(|(path, allowed)| normalized.ends_with(path) && allowed == pattern);
                if excused {
                    used.insert((*pattern, normalized.clone()));
                    continue;
                }
                findings.push(format!(
                    "{}:{} — {pattern} ({reason})",
                    file.display(),
                    line_number + 1
                ));
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

    // Une exception qui ne sert plus doit disparaître, sans quoi elle finit par
    // couvrir du code qu'on n'a jamais examiné.
    for (path, pattern) in ALLOWED {
        assert!(
            used.iter().any(|(p, f)| p == pattern && f.ends_with(path)),
            "l'exception {pattern} dans {path} n'est plus utilisée : retirez-la"
        );
    }
}

#[test]
fn the_only_process_creation_takes_a_compile_time_command_line() {
    // L'exception ne tient que par cette signature. Si elle s'assouplissait,
    // une chaîne construite à l'exécution pourrait atteindre la ligne de
    // commande, et l'exception ne serait plus justifiable.
    let source = std::fs::read_to_string(
        workspace_root().join("crates/sidgate-agent/src/service/launcher.rs"),
    )
    .expect("le lanceur doit exister tant que l'exception existe");

    assert!(
        source.contains("arguments: &'static str"),
        "la ligne de commande du travailleur doit rester une constante de compilation"
    );
    assert!(
        !source.contains("arguments: &str"),
        "une signature acceptant une chaîne quelconque annulerait la garantie"
    );
}

#[test]
fn identifier_matching_does_not_fire_on_substrings() {
    assert!(contains_identifier("unsafe { CreateProcessW(...) }", "CreateProcessW"));
    assert!(!contains_identifier(
        "CreateProcessAsUserW(token, ...)",
        "CreateProcessA"
    ));
    assert!(!contains_identifier("MyCreateProcessW()", "CreateProcessW"));
    assert!(contains_identifier("CreateProcessW", "CreateProcessW"));
    assert!(!contains_identifier("", "CreateProcessW"));
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

/// Cherche `pattern` en tant qu'identifiant entier, et non en sous-chaîne.
///
/// Sans cette précision, `CreateProcessA` se déclencherait à l'intérieur de
/// `CreateProcessAsUserW` : le test dénoncerait un appel qui n'existe pas, et
/// l'on prendrait l'habitude de l'ignorer.
fn contains_identifier(haystack: &str, pattern: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(offset) = haystack[from..].find(pattern) {
        let start = from + offset;
        let end = start + pattern.len();
        let before_ok = start == 0 || !is_identifier_byte(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_identifier_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
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
