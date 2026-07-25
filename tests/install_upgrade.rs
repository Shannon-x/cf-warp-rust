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

#[test]
fn update_detects_legacy_mtu_without_rewriting_configuration() {
    let script = fs::read_to_string("install.sh").expect("read install.sh");
    assert!(script.contains("read_configured_warp_mtu"));
    assert!(script.contains("v0.4.5+ 推荐 1280"));
    assert!(script.contains("--update 会保留配置且不会自动改写"));
}

#[test]
fn every_shipped_config_generator_uses_mtu_1280() {
    for path in [
        "install.sh",
        "scripts/run-binary.sh",
        "scripts/run-docker.sh",
        "scripts/quickstart.sh",
        "config.toml.example",
        "config.toml.docker.example",
    ] {
        let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        assert!(
            text.contains("mtu = 1280"),
            "{path} must generate or document mtu = 1280"
        );
        assert!(
            !text.contains("mtu = 1420"),
            "{path} still ships mtu = 1420"
        );
    }

    let config_source = fs::read_to_string("src/config.rs").expect("read main config defaults");
    assert!(
        config_source.contains("fn default_mtu() -> u16 {\n    1280\n}"),
        "main configuration fallback must stay at MTU 1280"
    );
    let netstack_source =
        fs::read_to_string("vendor/wireguard-netstack/src/netstack.rs").expect("read netstack");
    assert!(
        netstack_source.contains("pub const DEFAULT_MTU: usize = 1280;"),
        "vendored netstack fallback must stay at MTU 1280"
    );
}
