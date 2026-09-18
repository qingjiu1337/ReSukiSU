//! ksud WebUI 面板（浏览器直连 127.0.0.1）
//!
//! 独立的轻量 HTTP 面板守护进程（webuid），仅监听 127.0.0.1，
//! 用于在浏览器中查看 KernelSU 工作状态并切换内核功能开关
//! （传统 SU / 内核级卸载模块 / SU 日志 / ADB Root / SELinux 隐藏 / 隐身 Stealth）。
//!
//! - 鉴权：访问需要 token，首次启动自动生成并保存在
//!   `/data/adb/ksu/webui_token`（权限 0600，仅 root 可读）。
//!   token 可通过 URL 参数 `?token=` 或请求头 `X-KSU-Token` 提供。
//! - 端口：默认 8389，可用环境变量 `KSU_WEBUI_PORT` 覆盖。
//! - 启动：`ksud services` 阶段自动拉起；也可手动
//!   `ksud debug webuid`（同 sulogd 的管理方式）。
//!
//! 实现完全基于 std（无新增第三方依赖），不改变 CI 构建链。

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result};

use crate::{
    android::{
        feature::{self, FeatureId},
        ksucalls, utils,
    },
    defs,
};

pub const WEBUI_PORT_DEFAULT: u16 = 8389;
const TOKEN_FILE_NAME: &str = "webui_token";
const MAX_REQUEST: usize = 16 * 1024;

const ALL_FEATURES: [FeatureId; 6] = [
    FeatureId::SuCompat,
    FeatureId::KernelUmount,
    FeatureId::Sulog,
    FeatureId::AdbRoot,
    FeatureId::SelinuxHide,
    FeatureId::Stealth,
];

pub fn webui_port() -> u16 {
    std::env::var("KSU_WEBUI_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(WEBUI_PORT_DEFAULT)
}

fn token_path() -> PathBuf {
    PathBuf::from(defs::WORKING_DIR).join(TOKEN_FILE_NAME)
}

fn load_or_create_token() -> Result<String> {
    let path = token_path();

    if let Ok(tok) = std::fs::read_to_string(&path) {
        let tok = tok.trim().to_string();
        if !tok.is_empty() {
            return Ok(tok);
        }
    }

    // 首次生成：/dev/urandom 取 16 字节转 hex
    let mut raw = [0u8; 16];
    std::fs::read("/dev/urandom")
        .context("failed to read /dev/urandom")?
        .iter()
        .take(16)
        .enumerate()
        .for_each(|(i, b)| raw[i] = *b);
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();

    utils::ensure_dir_exists(std::path::Path::new(defs::WORKING_DIR))?;
    std::fs::write(&path, &token).with_context(|| format!("failed to write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(token)
}

/// 以 sulogd 相同的方式拉起 webuid 守护进程（double fork，脱离调用方生命周期）
pub fn spawn_webuid() -> Result<()> {
    use std::process::{Command, Stdio};

    if utils::create_daemon(true)? {
        let mut command = Command::new("/proc/self/exe");
        command
            .arg("webuid")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.spawn().context("failed to spawn webuid")?;
    }
    Ok(())
}

pub fn ensure_webuid_running() -> Result<()> {
    spawn_webuid()
}

pub fn run_webuid() -> Result<()> {
    let port = webui_port();
    // 预生成 token，启动失败尽早暴露
    let _ = load_or_create_token()?;

    let listener = TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("failed to bind 127.0.0.1:{port}"))?;
    log::info!("webuid listening on 127.0.0.1:{port}");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                std::thread::spawn(move || handle_conn(s));
            }
            Err(e) => {
                log::warn!("webuid accept error: {e}");
            }
        }
    }
    Ok(())
}

fn get_query_param<'a>(query: &'a str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            Some(v.to_string())
        } else {
            None
        }
    })
}

fn handle_conn(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut buf = [0u8; MAX_REQUEST];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);

    let mut lines = req.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    // 解析请求头中的 token
    let mut header_token: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.to_ascii_lowercase().starts_with("x-ksu-token:") {
            if let Some(pos) = line.find(':') {
                header_token = Some(line[pos + 1..].trim().to_string());
            }
        }
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };

    // 鉴权：header 优先，URL 参数兜底
    let token_expected = match load_or_create_token() {
        Ok(t) => t,
        Err(e) => {
            log::warn!("webuid: failed to load token: {e:#}");
            respond(
                &mut stream,
                500,
                "text/plain; charset=utf-8",
                "internal error: token unavailable\n",
            );
            return;
        }
    };
    let provided_token = header_token.or_else(|| get_query_param(query, "token"));
    let token_ok = matches!(provided_token.as_deref(), Some(t) if constant_time_eq(t.as_bytes(), token_expected.as_bytes()));
    if !token_ok {
        respond(
            &mut stream,
            403,
            "text/plain; charset=utf-8",
            "forbidden: token required\nhint: adb shell su -c 'cat /data/adb/ksu/webui_token'\n",
        );
        return;
    }

    match (method, path) {
        ("GET", "/") => {
            respond(&mut stream, 200, "text/html; charset=utf-8", PANEL_HTML);
        }
        ("GET", "/api/status") => {
            respond(&mut stream, 200, "application/json", &status_json());
        }
        ("GET" | "POST", "/api/feature/set") => {
            let id = get_query_param(query, "id").and_then(|v| v.parse::<u32>().ok());
            let value = get_query_param(query, "value").and_then(|v| v.parse::<u64>().ok());
            match (id, value) {
                (Some(id), Some(value)) => match set_feature_persist(id, value) {
                    Ok(()) => respond(
                        &mut stream,
                        200,
                        "application/json",
                        &format!("{{\"ok\":true,\"id\":{id},\"value\":{value}}}"),
                    ),
                    Err(e) => respond(
                        &mut stream,
                        500,
                        "application/json",
                        &format!("{{\"ok\":false,\"error\":\"{}\"}}", escape_json(&format!("{e:#}"))),
                    ),
                },
                _ => respond(
                    &mut stream,
                    400,
                    "application/json",
                    "{\"ok\":false,\"error\":\"missing id or value\"}",
                ),
            }
        }
        _ => respond(&mut stream, 404, "text/plain; charset=utf-8", "not found\n"),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 设置 feature（内核 + 持久化配置同步），复用 feature::apply_feature
/// 以获得 Sulog 拉起、Stealth 加固等副作用处理。
fn set_feature_persist(id: u32, value: u64) -> Result<()> {
    let feature_id = FeatureId::from_u32(id)
        .with_context(|| format!("unknown feature id {id}"))?;
    feature::apply_feature(feature_id, value)?;

    // 同步持久化配置，重启后由 init_features 恢复
    let mut cfg = feature::load_binary_config().unwrap_or_default();
    cfg.insert(id, value);
    let _ = feature::save_binary_config(&cfg);
    Ok(())
}

fn status_json() -> String {
    let info = ksucalls::get_info();

    let mut s = String::from("{");
    s.push_str(&format!("\"version\":\"{}\",", escape_json(defs::VERSION_NAME.trim())));
    s.push_str(&format!(
        "\"full_version\":\"{}\",",
        escape_json(defs::FULL_VERSION.trim())
    ));
    s.push_str(&format!("\"kernel_version_code\":{},", ksucalls::get_version()));
    s.push_str(&format!("\"kernel_features\":{},", info.features));
    s.push_str(&format!("\"uapi_version\":{},", info.uapi_version));
    s.push_str(&format!("\"port\":{},", webui_port()));

    s.push_str("\"features\":[");
    for (i, f) in ALL_FEATURES.iter().enumerate() {
        let (value, supported) = ksucalls::get_feature(*f as u32).unwrap_or((0, false));
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"id\":{},\"name\":\"{}\",\"value\":{},\"supported\":{}}}",
            *f as u32,
            f.name(),
            value,
            supported
        ));
    }
    s.push_str("]}");
    s
}

fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &str) {
    let status = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let resp = format!(
        "HTTP/1.1 {code} {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

const PANEL_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KernelSU WebUI 面板</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: system-ui, -apple-system, "PingFang SC", "Noto Sans SC", sans-serif;
    background: #0b0f14; color: #e6edf3; padding: 16px; max-width: 640px; margin: 0 auto;
  }
  h1 { font-size: 18px; padding: 8px 0 16px; display: flex; align-items: center; gap: 8px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: #3fb950; box-shadow: 0 0 8px #3fb95088; }
  .dot.bad { background: #f85149; box-shadow: 0 0 8px #f8514988; }
  .card {
    background: #11161d; border: 1px solid #1f2730; border-radius: 12px;
    padding: 14px 16px; margin-bottom: 12px;
  }
  .card h2 { font-size: 13px; color: #8b949e; font-weight: 500; margin-bottom: 8px; }
  .kv { display: flex; justify-content: space-between; padding: 4px 0; font-size: 14px; }
  .kv .k { color: #8b949e; }
  .kv .v { font-family: ui-monospace, monospace; }
  .row { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-top: 1px solid #1f2730; }
  .row:first-of-type { border-top: none; }
  .row .label { font-size: 15px; }
  .row .desc { font-size: 12px; color: #8b949e; margin-top: 2px; }
  .switch { position: relative; width: 44px; height: 26px; flex: none; }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider {
    position: absolute; inset: 0; background: #30363d; border-radius: 26px;
    transition: background .2s; cursor: pointer;
  }
  .slider::before {
    content: ""; position: absolute; width: 20px; height: 20px; border-radius: 50%;
    background: #e6edf3; top: 3px; left: 3px; transition: transform .2s;
  }
  .switch input:checked + .slider { background: #238636; }
  .switch input:checked + .slider::before { transform: translateX(18px); }
  .switch input:disabled + .slider { opacity: .4; cursor: not-allowed; }
  .unsup { font-size: 12px; color: #f85149; }
  footer { text-align: center; color: #484f58; font-size: 12px; padding: 12px 0; }
</style>
</head>
<body>
<h1><span class="dot" id="dot"></span>KernelSU WebUI 面板</h1>

<div class="card">
  <h2>工作状态</h2>
  <div class="kv"><span class="k">版本</span><span class="v" id="v-version">-</span></div>
  <div class="kv"><span class="k">内核版本号</span><span class="v" id="v-kernel">-</span></div>
  <div class="kv"><span class="k">UAPI 版本</span><span class="v" id="v-uapi">-</span></div>
  <div class="kv"><span class="k">监听端口</span><span class="v" id="v-port">-</span></div>
</div>

<div class="card">
  <h2>功能开关</h2>
  <div id="features"></div>
</div>

<div class="card">
  <h2>说明</h2>
  <div style="font-size:13px;color:#8b949e;line-height:1.7">
    开关即改即生效并持久化，重启后自动恢复。<br>
    「隐身模式」开启后：dmesg 对普通应用关闭、内核指针隐藏、
    KernelSU 内核日志静默（需 CONFIG_KSU_STEALTH）。
  </div>
</div>

<footer>ReSukiSU webuid &middot; 仅监听 127.0.0.1 &middot; token 鉴权</footer>

<script>
const token = new URLSearchParams(location.search).get('token') || '';

const FEAT_LABELS = {
  su_compat:    ['传统 SU 命令支持', '允许已授权应用通过传统 su 命令获取 root'],
  kernel_umount:['卸载模块（内核级）', '内核自动为普通应用卸载模块挂载'],
  sulog:        ['SU 日志', '内核 sulog 事件流与持久化'],
  adb_root:     ['ADB Root', '以 root 权限运行 adbd 守护进程'],
  selinux_hide: ['隐藏 SELinux 修改', '阻止应用检测 SELinux 修改'],
  stealth:      ['隐身模式（Stealth）', 'dmesg_restrict + kptr_restrict + 日志静默'],
};

async function api(path) {
  const sep = path.includes('?') ? '&' : '?';
  const r = await fetch(path + sep + 'token=' + encodeURIComponent(token));
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.text();
}

function render(status) {
  document.getElementById('v-version').textContent = status.full_version || status.version || '-';
  document.getElementById('v-kernel').textContent = status.kernel_version_code ?? '-';
  document.getElementById('v-uapi').textContent = status.uapi_version ?? '-';
  document.getElementById('v-port').textContent = status.port ?? '-';
  const ok = (status.kernel_features || 0) > 0;
  document.getElementById('dot').classList.toggle('bad', !ok);

  const box = document.getElementById('features');
  box.innerHTML = '';
  (status.features || []).forEach(f => {
    const [label, desc] = FEAT_LABELS[f.name] || [f.name, ''];
    const row = document.createElement('div');
    row.className = 'row';
    const left = document.createElement('div');
    left.innerHTML = '<div class="label">' + label + '</div><div class="desc">' + desc + '</div>';
    const right = document.createElement('div');
    if (!f.supported) {
      right.innerHTML = '<span class="unsup">内核未支持</span>';
    } else {
      const sw = document.createElement('label');
      sw.className = 'switch';
      sw.innerHTML = '<input type="checkbox" ' + (f.value ? 'checked' : '') + '><span class="slider"></span>';
      sw.querySelector('input').addEventListener('change', async (ev) => {
        ev.target.disabled = true;
        try {
          await api('/api/feature/set?id=' + f.id + '&value=' + (ev.target.checked ? 1 : 0));
          await load();
        } catch (e) {
          alert('设置失败: ' + e.message);
          ev.target.disabled = false;
        }
      });
      right.appendChild(sw);
    }
    row.appendChild(left);
    row.appendChild(right);
    box.appendChild(row);
  });
}

async function load() {
  try {
    render(JSON.parse(await api('/api/status')));
  } catch (e) {
    document.getElementById('dot').classList.add('bad');
  }
}

load();
setInterval(load, 15000);
</script>
</body>
</html>"#;
