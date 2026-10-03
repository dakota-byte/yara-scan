use std::fs;
use std::process::Command;

/// Path to the compiled binary, provided by Cargo for integration tests.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_triage-scanner")
}

#[test]
fn matches_marker_in_fixture_file() {
    let dir = std::env::temp_dir().join("triage-scanner-test-match");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let rule = dir.join("test.yar");
    fs::write(
        &rule,
        r#"
rule TestMarker {
    meta:
        description = "integration test rule"
        author = "test"
        severity = "high"
    strings:
        $m = "INTEGRATION_TEST_MARKER_abc123"
    condition:
        $m
}
"#,
    )
    .unwrap();

    let target = dir.join("sample.txt");
    fs::write(&target, "harmless\nINTEGRATION_TEST_MARKER_abc123\n").unwrap();

    let out = Command::new(bin())
        .args(["--rules", rule.to_str().unwrap(), "--quiet", "--format", "json"])
        .arg(&target)
        .output()
        .unwrap();

    assert!(out.status.success() || out.status.code() == Some(2));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("TestMarker"), "stdout was: {stdout}");
    assert!(stdout.contains("integration test rule"), "stdout was: {stdout}");
    assert!(stdout.contains("high"), "stdout was: {stdout}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn clean_scan_exits_zero() {
    let dir = std::env::temp_dir().join("triage-scanner-test-clean");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let rule = dir.join("test.yar");
    fs::write(
        &rule,
        r#"
rule NeverMatches {
    strings:
        $m = "THIS_STRING_DOES_NOT_APPEAR_ANYWHERE_zzz999"
    condition:
        $m
}
"#,
    )
    .unwrap();

    let target = dir.join("sample.txt");
    fs::write(&target, "nothing to see here\n").unwrap();

    let out = Command::new(bin())
        .args(["--rules", rule.to_str().unwrap(), "--quiet"])
        .arg(&target)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn max_size_skips_large_files() {
    let dir = std::env::temp_dir().join("triage-scanner-test-maxsize");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let rule = dir.join("test.yar");
    fs::write(
        &rule,
        r#"
rule BigFileMarker {
    strings:
        $m = "BIG_FILE_MARKER_xyz789"
    condition:
        $m
}
"#,
    )
    .unwrap();

    let target = dir.join("big.txt");
    fs::write(&target, "BIG_FILE_MARKER_xyz789\n").unwrap();

    // Cap at 1 byte: the file is larger, so it must be skipped.
    let out = Command::new(bin())
        .args([
            "--rules",
            rule.to_str().unwrap(),
            "--quiet",
            "--max-size",
            "1",
        ])
        .arg(&target)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "large file should be skipped");

    let _ = fs::remove_dir_all(&dir);
}
