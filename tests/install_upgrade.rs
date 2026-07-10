use std::fs;

#[test]
fn reinstall_restarts_an_already_active_service() {
    let script = fs::read_to_string("install.sh").expect("read install.sh");
    assert!(
        script.contains("systemctl restart \"$SERVICE_NAME\""),
        "reinstall must restart the active process so it loads the new binary/config"
    );

    let active_commands: Vec<_> = script
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert!(
        !active_commands
            .iter()
            .any(|line| line.starts_with("systemctl enable --now")),
        "enable --now does not restart an already active service"
    );
}

#[test]
fn readiness_only_reads_logs_from_the_current_start() {
    let script = fs::read_to_string("install.sh").expect("read install.sh");
    assert!(script.contains("JOURNAL_SINCE_EPOCH=\"$(date +%s)\""));
    assert!(script.contains("--since \"@${JOURNAL_SINCE_EPOCH}\""));
}

#[test]
fn reinstall_backs_up_existing_configuration() {
    let script = fs::read_to_string("install.sh").expect("read install.sh");
    assert!(script.contains("CONF_BACKUP=\"${CONF_FILE}.bak.$(date +%Y%m%d%H%M%S)\""));
    assert!(script.contains("cp -p \"$CONF_FILE\" \"$CONF_BACKUP\""));
}
