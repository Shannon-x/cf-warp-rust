//! 发布门禁的守门测试。
//!
//! 光断言「文件里出现过 `needs: verify`」是挡不住真实绕过路径的——只要新增一个
//! 忘记加 `needs` 的 publish job，子串仍然存在，测试照样绿。这里改成按缩进切出
//! 每个 job、解析它们的 `needs`、再算传递闭包，要求**每一个** job 都能到达那个
//! 调用 verify.yml 的门禁 job。
//!
//! workflow YAML 的缩进由 CI 里的 actionlint 把关，因此这里不需要完整的 YAML
//! 解析器，按层级切块即可。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

const PUBLISH_WORKFLOWS: [&str; 3] = [
    ".github/workflows/docker.yml",
    ".github/workflows/release.yml",
    ".github/workflows/release-macos.yml",
];

const VERIFY_CALL: &str = "uses: ./.github/workflows/verify.yml";

fn workflow(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// 切出 `jobs:` 下的每个顶层 job 及其属性块。
fn jobs(yaml: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut lines = yaml.lines();
    for line in lines.by_ref() {
        if line.trim_end() == "jobs:" {
            break;
        }
    }

    let mut current: Option<(String, Vec<&str>)> = None;
    for line in lines {
        // 回到顶层 key（无缩进的非空行）说明 jobs 段结束了。
        if !line.is_empty() && !line.starts_with(' ') {
            break;
        }
        let is_job_header = line
            .strip_prefix("  ")
            .is_some_and(|rest| !rest.starts_with(' ') && rest.trim_end().ends_with(':'));
        if is_job_header {
            if let Some((name, body)) = current.take() {
                out.insert(name, body.join("\n"));
            }
            let name = line.trim().trim_end_matches(':').to_string();
            current = Some((name, Vec::new()));
            continue;
        }
        if let Some((_, body)) = current.as_mut() {
            body.push(line);
        }
    }
    if let Some((name, body)) = current {
        out.insert(name, body.join("\n"));
    }
    out
}

/// 解析一个 job 块里的 `needs`，支持 `needs: a`、`needs: [a, b]` 和块序列。
fn needs_of(body: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let lines: Vec<&str> = body.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let Some(rest) = line.trim().strip_prefix("needs:") else {
            continue;
        };
        let rest = rest.trim();
        if rest.starts_with('[') {
            for part in rest
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
            {
                let part = part.trim().trim_matches(['"', '\'']);
                if !part.is_empty() {
                    out.insert(part.to_string());
                }
            }
        } else if !rest.is_empty() {
            out.insert(rest.trim_matches(['"', '\'']).to_string());
        } else {
            for next in &lines[index + 1..] {
                let next = next.trim();
                if let Some(item) = next.strip_prefix("- ") {
                    out.insert(item.trim().trim_matches(['"', '\'']).to_string());
                } else if !next.is_empty() {
                    break;
                }
            }
        }
    }
    out
}

/// 从 `job` 出发沿 needs 是否能到达 `target`。
fn reaches(jobs: &BTreeMap<String, String>, job: &str, target: &str) -> bool {
    let mut seen = BTreeSet::new();
    let mut stack = vec![job.to_string()];
    while let Some(current) = stack.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        let Some(body) = jobs.get(&current) else {
            continue;
        };
        for dep in needs_of(body) {
            if dep == target {
                return true;
            }
            stack.push(dep);
        }
    }
    false
}

#[test]
fn every_publish_job_transitively_depends_on_the_verification_gate() {
    for path in PUBLISH_WORKFLOWS {
        let yaml = workflow(path);
        let jobs = jobs(&yaml);
        assert!(!jobs.is_empty(), "{path}: 没有解析出任何 job");

        let gates: Vec<&String> = jobs
            .iter()
            .filter(|(_, body)| body.contains(VERIFY_CALL))
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            gates.len(),
            1,
            "{path} 应当恰好有一个调用 verify.yml 的门禁 job，实际: {gates:?}"
        );
        let gate = gates[0].clone();

        for name in jobs.keys() {
            if *name == gate {
                continue;
            }
            assert!(
                reaches(&jobs, name, &gate),
                "{path} 的 job `{name}` 没有（哪怕传递地）依赖门禁 job `{gate}`，\
                 可以在验证失败时照样构建或发布"
            );
        }
    }
}

/// `continue-on-error` / `if: always()` 会让 needs 形同虚设：上游红了下游照跑。
#[test]
fn publish_workflows_do_not_neutralize_the_gate() {
    for path in PUBLISH_WORKFLOWS {
        let yaml = workflow(path);
        for (index, line) in yaml.lines().enumerate() {
            let trimmed = line.trim();
            assert!(
                !trimmed.starts_with("continue-on-error:") || trimmed.ends_with("false"),
                "{path}:{} 用 continue-on-error 绕过了失败传播: {trimmed}",
                index + 1
            );
            assert!(
                !trimmed.replace(' ', "").starts_with("if:always()"),
                "{path}:{} 用 `if: always()` 让 job 在门禁失败后仍然运行: {trimmed}",
                index + 1
            );
        }
    }
}

#[test]
fn shared_verification_covers_main_vendored_and_shell_surfaces() {
    let yaml = workflow(".github/workflows/verify.yml");
    for required in [
        "cargo fmt --all -- --check",
        "cargo fmt --manifest-path vendor/wireguard-netstack/Cargo.toml --all -- --check",
        "cargo fmt --manifest-path vendor/warp-wireguard-gen/Cargo.toml --all -- --check",
        "cargo clippy --all-targets --release --locked -- -D warnings",
        // vendored 必须走 --manifest-path + --all-features，否则主项目的
        // default-features = false 会让 config.rs / dns.rs 完全不参与编译。
        "--manifest-path vendor/wireguard-netstack/Cargo.toml \\",
        "--manifest-path vendor/warp-wireguard-gen/Cargo.toml \\",
        "--all-targets --all-features --locked -- -D warnings",
        // 测试必须跑 debug profile：release 会关掉 debug_assertions 与
        // overflow-checks，而本项目大量处理分片偏移与长度算术。
        "cargo test --all-targets --locked",
        "--all-features --locked",
        "shellcheck install.sh scripts/*.sh tests/shell/*.sh",
        "for test_script in tests/shell/*.sh; do bash \"$test_script\"; done",
    ] {
        assert!(
            yaml.contains(required),
            "shared verification is missing `{required}`"
        );
    }
}

/// MSRV 只声明在 Cargo.toml 而 CI 全跑 stable 的话，用了新 API 也不会被发现。
#[test]
fn shared_verification_pins_and_checks_the_declared_msrv() {
    let yaml = workflow(".github/workflows/verify.yml");
    let declared = fs::read_to_string("Cargo.toml")
        .expect("read Cargo.toml")
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("rust-version")?
                .trim()
                .strip_prefix('=')
                .map(|v| v.trim().trim_matches('"').to_string())
        })
        .expect("Cargo.toml 必须声明 rust-version");

    assert!(
        yaml.contains(&format!("dtolnay/rust-toolchain@{declared}")),
        "verify.yml 没有钉住 Cargo.toml 声明的 MSRV {declared}"
    );
    assert!(
        jobs(&yaml).contains_key("msrv"),
        "verify.yml 缺少独立的 msrv job"
    );
}
