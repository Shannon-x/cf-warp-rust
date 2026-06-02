// CI 兜底测试：防止 Dockerfile / config.toml.docker.example / README 三方默认值再次漂移。
//
// 三个断言任一断裂都会让 `cargo test` 红：
//   · Dockerfile 必须复制 config.toml.docker.example（不是 config.toml.example）；
//   · config.toml.docker.example 必须 bind = 0.0.0.0:<port>（容器命名空间内的默认）；
//   · config.toml.example       必须 bind = 127.0.0.1:<port>（宿主直跑的安全默认）；
//   · README 必须如实陈述「镜像内默认 bind = 0.0.0.0:1080」并附「容器命名空间」澄清。
//
// 路径一律走 CARGO_MANIFEST_DIR，避免被 cargo-nextest 之类把 CWD 改到 workspace 根的运行器翻车。

use std::fs;
use std::path::Path;

fn manifest_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read(rel: &str) -> String {
    let p = manifest_path(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("读取 {} 失败: {}", p.display(), e))
}

fn parse_toml(rel: &str) -> toml::Value {
    let raw = read(rel);
    toml::from_str::<toml::Value>(&raw).unwrap_or_else(|e| panic!("{} 不是合法 TOML: {}", rel, e))
}

fn bind_str<'a>(v: &'a toml::Value, table: &str) -> &'a str {
    v.get(table)
        .and_then(|t| t.get("bind"))
        .and_then(|b| b.as_str())
        .unwrap_or_else(|| panic!("缺少 [{table}].bind 字段（或不是字符串）"))
}

#[test]
fn dockerfile_copies_docker_specific_example() {
    let dockerfile = read("Dockerfile");
    assert!(
        dockerfile.contains("COPY config.toml.docker.example /app/config.toml"),
        "Dockerfile 必须复制 config.toml.docker.example 而不是 config.toml.example"
    );
    // 防回滚：旧的 COPY 路径不应再以可执行指令形式出现（注释里出现可接受，但本仓库注释里没有该精确串）
    assert!(
        !dockerfile.contains("\nCOPY config.toml.example /app/config.toml"),
        "Dockerfile 不应再以 COPY 指令形式引用宿主版 config.toml.example"
    );
}

#[test]
fn docker_example_binds_unspecified_v4() {
    let v = parse_toml("config.toml.docker.example");
    let server_bind = bind_str(&v, "server");
    assert!(
        server_bind.starts_with("0.0.0.0:"),
        "docker example 的 [server].bind 必须默认 0.0.0.0:<port>，实际: {server_bind}"
    );
    let metrics_bind = bind_str(&v, "metrics");
    assert!(
        metrics_bind.starts_with("0.0.0.0:"),
        "docker example 的 [metrics].bind 必须默认 0.0.0.0:<port>，实际: {metrics_bind}"
    );
    let data_dir = v
        .get("warp")
        .and_then(|t| t.get("data_dir"))
        .and_then(|d| d.as_str())
        .expect("缺少 [warp].data_dir");
    assert_eq!(
        data_dir, "/app/data",
        "docker example 的 data_dir 必须指向容器 VOLUME /app/data"
    );
}

#[test]
fn host_example_binds_loopback() {
    // 防止以后有人改宿主默认时把容器/宿主两套又搞反
    let v = parse_toml("config.toml.example");
    let server_bind = bind_str(&v, "server");
    assert!(
        server_bind.starts_with("127.0.0.1:"),
        "宿主 example 的 [server].bind 必须默认 127.0.0.1:<port>（loopback 安全默认），实际: {server_bind}"
    );
}

#[test]
fn readme_documents_image_default_correctly() {
    let readme = read("README.md");
    assert!(
        readme.contains("镜像内默认 `bind = 0.0.0.0:1080`"),
        "README 必须如实陈述镜像默认 bind = 0.0.0.0:1080；若改文案，请同步更新本测试"
    );
    assert!(
        readme.contains("容器命名空间"),
        "README 必须附『容器命名空间』澄清，避免读者误以为 0.0.0.0 等于公网暴露"
    );
    assert!(
        readme.contains("config.toml.docker.example"),
        "README 必须明示 docker 专用 example 文件名，避免用户挂载宿主版 config.toml.example"
    );
}
