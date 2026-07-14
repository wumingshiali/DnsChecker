//! DnsChecker GUI 应用程序入口。
//!
//! 显示 DNS 服务器列表，支持浮动窗口添加条目、一键全部测试并按分数排序。
//! 测试在后台线程执行，避免阻塞 GUI。解析支持 DoH（DNS over HTTPS）。

use eframe::egui;
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dns_checker_core::{check_resolve_quality, compute_score, ping_dns_multi, Encryption};

/// 窗口标题
const TITLE: &str = "Dns检测";
/// 窗口图标（编译时嵌入，运行时无需外部文件）
const ICON_BYTES: &[u8] = include_bytes!("icons/WindowIco.png");
/// 主字体（编译时嵌入，含中文字形，解决默认字体不支持中文导致的乱码）
const MAIN_FONT_BYTES: &[u8] = include_bytes!("fonts/MainFont.ttf");

/// 测试用的连接超时
const TIMEOUT: Duration = Duration::from_secs(3);
/// 每个 DNS 的 ping 采样次数
const PING_COUNT: usize = 5;
/// 延迟/解析质量超过此阈值（毫秒）视为「超时」，该项不记分
const LATENCY_TIMEOUT_MS: f64 = 1000.0;

/// 判断某项延迟是否超时（有值且超过阈值）。
fn is_timeout(v: Option<f64>) -> bool {
    matches!(v, Some(x) if x > LATENCY_TIMEOUT_MS)
}

/// DoH 端点
const DOH_ALIDNS: &str = "https://dns.alidns.com/dns-query";
const DOH_DNSPOD: &str = "https://doh.pub/dns-query";
const DOH_CLOUDFLARE: &str = "https://cloudflare-dns.com/dns-query";
const DOH_GOOGLE: &str = "https://dns.google/dns-query";
const DOH_QUAD9: &str = "https://dns.quad9.net/dns-query";

fn main() -> eframe::Result {
    let icon = load_icon();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(TITLE)
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        TITLE,
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(DnsCheckerApp::default()))
        }),
    )
}

/// 加载窗口图标。
///
/// 从编译时嵌入的 `ICON_BYTES` 解码 PNG 为 `egui::IconData`；
/// 失败时返回空 `IconData`（窗口仍可创建，仅无自定义图标），不中断启动。
fn load_icon() -> egui::IconData {
    match image::load_from_memory(ICON_BYTES) {
        Ok(image) => {
            let rgba = image.to_rgba8();
            egui::IconData {
                width: rgba.width(),
                height: rgba.height(),
                rgba: rgba.into_raw(),
            }
        }
        Err(err) => {
            eprintln!("load embedded icon failed: {}", err);
            egui::IconData::default()
        }
    }
}

/// 注册中文字体，设为 Proportional 与 Monospace 字体族的首选。
///
/// egui 默认字体不含中文字形，需加载含中文的 TTF 并插入字体族最前，
/// 否则中文会显示为方块（乱码）。
fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "MainFont".to_owned(),
        egui::FontData::from_static(MAIN_FONT_BYTES).into(),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        if let Some(list) = fonts.families.get_mut(&family) {
            list.insert(0, "MainFont".to_owned());
        }
    }
    ctx.set_fonts(fonts);
}

/// 列表中的一条 DNS 服务器记录。
struct DnsEntry {
    address: String,
    encryption: Encryption,
    recommendation: f64,
    /// 可选的 DoH 端点；`None` 时测试走明文 DNS over TCP
    doh: Option<String>,
    /// 测试结果（None = 未测试）
    dns_latency: Option<f64>,
    resolve_quality: Option<f64>,
    score: Option<f64>,
}

impl DnsEntry {
    /// 用 address 匹配（后台线程结果按地址回填，避免测试期间列表变动导致索引错位）
    fn matches(&self, address: &str) -> bool {
        self.address == address
    }
}

/// 添加窗口的表单状态。
#[derive(Default)]
struct AddForm {
    address: String,
    /// 支持的加密协议数量：0 / 1 / 2
    encryption_count: u8,
    /// DoH 端点 URL；留空表示不用 DoH
    doh: String,
}

/// 后台线程回传的单条测试结果。
struct TestResult {
    address: String,
    dns_latency: Option<f64>,
    resolve_quality: Option<f64>,
    score: Option<f64>,
}

/// 子任务结果（ping 或 resolve），用于按 address 配对后算分。
enum SubResult {
    Ping { address: String, latency: Option<f64> },
    Resolve { address: String, quality: Option<f64> },
}

impl SubResult {
    fn address(&self) -> &str {
        match self {
            SubResult::Ping { address, .. } => address,
            SubResult::Resolve { address, .. } => address,
        }
    }
}

/// 简易计数信号量，基于 `sync_channel` 实现，用于限制并发任务数。
struct Semaphore {
    sender: mpsc::SyncSender<()>,
    receiver: Mutex<mpsc::Receiver<()>>,
}

impl Semaphore {
    fn new(permits: usize) -> Self {
        let (sender, receiver) = mpsc::sync_channel(permits);
        // 预填 permits 个许可
        for _ in 0..permits {
            let _ = sender.send(());
        }
        Self {
            sender,
            receiver: Mutex::new(receiver),
        }
    }

    /// 获取一个许可，无可用时阻塞。
    fn acquire(&self) {
        let _ = self.receiver.lock().unwrap().recv();
    }

    /// 归还一个许可。
    fn release(&self) {
        let _ = self.sender.send(());
    }
}

/// 默认 DNS 列表（按服务商关联对应 DoH 端点；114DNS 无公开 DoH）
fn default_entries() -> Vec<DnsEntry> {
    vec![
        DnsEntry {
            address: "223.5.5.5".into(),
            encryption: Encryption::Full,
            recommendation: 0.8,
            doh: Some(DOH_ALIDNS.into()),
            dns_latency: None,
            resolve_quality: None,
            score: None,
        },
        DnsEntry {
            address: "119.29.29.29".into(),
            encryption: Encryption::Full,
            recommendation: 0.95,
            doh: Some(DOH_DNSPOD.into()),
            dns_latency: None,
            resolve_quality: None,
            score: None,
        },
        DnsEntry {
            address: "114.114.114.114".into(),
            encryption: Encryption::None,
            recommendation: 1.0,
            doh: None,
            dns_latency: None,
            resolve_quality: None,
            score: None,
        },
        DnsEntry {
            address: "1.1.1.1".into(),
            encryption: Encryption::Full,
            recommendation: 1.0,
            doh: Some(DOH_CLOUDFLARE.into()),
            dns_latency: None,
            resolve_quality: None,
            score: None,
        },
        DnsEntry {
            address: "8.8.8.8".into(),
            encryption: Encryption::Full,
            recommendation: 1.0,
            doh: Some(DOH_GOOGLE.into()),
            dns_latency: None,
            resolve_quality: None,
            score: None,
        },
        DnsEntry {
            address: "9.9.9.9".into(),
            encryption: Encryption::Full,
            recommendation: 1.0,
            doh: Some(DOH_QUAD9.into()),
            dns_latency: None,
            resolve_quality: None,
            score: None,
        },
    ]
}

/// 应用主状态。
struct DnsCheckerApp {
    entries: Vec<DnsEntry>,
    add_window_open: bool,
    add_form: AddForm,
    /// 后台测试的结果接收端；`Some` 表示测试进行中
    test_receiver: Option<mpsc::Receiver<TestResult>>,
    testing: bool,
    /// 是否经 SOCKS5 代理测试；DoH 解析忽略此项
    use_proxy: bool,
    /// SOCKS5 代理端口（配合 `use_proxy`）
    proxy_port: u16,
}

impl Default for DnsCheckerApp {
    fn default() -> Self {
        Self {
            entries: default_entries(),
            add_window_open: false,
            add_form: AddForm::default(),
            test_receiver: None,
            testing: false,
            use_proxy: false,
            proxy_port: 1080,
        }
    }
}

impl DnsCheckerApp {
    /// 每帧拉取后台测试结果，回填到对应条目并按分数排序。
    fn poll_test_results(&mut self) {
        // 用 block 限定 receiver 的借用范围，结束后才能 &mut 其他字段
        let (results, done) = {
            let rx = match &self.test_receiver {
                Some(rx) => rx,
                None => return,
            };
            let mut results = Vec::new();
            let mut done = false;
            loop {
                match rx.try_recv() {
                    Ok(r) => results.push(r),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        done = true;
                        break;
                    }
                }
            }
            (results, done)
        };

        for r in results {
            if let Some(entry) = self.entries.iter_mut().find(|e| e.matches(&r.address)) {
                entry.dns_latency = r.dns_latency;
                entry.resolve_quality = r.resolve_quality;
                entry.score = r.score;
            }
        }

        if done {
            self.test_receiver = None;
            self.testing = false;
        }
        // 实时按分数排序，让排名随结果到达动态更新
        self.sort_entries_by_score();
    }

    /// 按总分数降序排序；有分数的在前，无分数的在后。
    fn sort_entries_by_score(&mut self) {
        self.entries.sort_by(|a, b| match (a.score, b.score) {
            (Some(sa), Some(sb)) => sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
    }
}

/// 格式化延迟类数值（毫秒）；超时显示「超时」，无值时根据 `testing` 显示「测试中...」或「-」。
fn fmt_ms(v: Option<f64>, testing: bool) -> String {
    match v {
        Some(x) if x > LATENCY_TIMEOUT_MS => "超时".to_string(),
        Some(x) => format!("{:.1} ms", x),
        None => {
            if testing {
                "测试中...".to_string()
            } else {
                "-".to_string()
            }
        }
    }
}

/// 格式化分数列；有分显示值，任一项超时显示「超时」，否则根据 `testing` 显示「测试中...」或「-」。
fn fmt_score_cell(
    score: Option<f64>,
    latency: Option<f64>,
    quality: Option<f64>,
    testing: bool,
) -> String {
    if let Some(s) = score {
        return format!("{:.2}", s);
    }
    if is_timeout(latency) || is_timeout(quality) {
        return "超时".to_string();
    }
    if testing {
        "测试中...".to_string()
    } else {
        "-".to_string()
    }
}

impl eframe::App for DnsCheckerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // 1. 拉取后台测试结果
        self.poll_test_results();

        // 2. 渲染主面板
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading(TITLE);
            ui.separator();

            // 按钮行
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.testing, egui::Button::new("全部测试"))
                    .clicked()
                {
                    let (sender, receiver) = mpsc::channel();
                    self.test_receiver = Some(receiver);
                    self.testing = true;

                    // 克隆测试所需的不可变数据给后台线程（含 DoH 端点）
                    let tasks: Vec<(String, Encryption, f64, Option<String>)> = self
                        .entries
                        .iter()
                        .map(|e| {
                            (
                                e.address.clone(),
                                e.encryption,
                                e.recommendation,
                                e.doh.clone(),
                            )
                        })
                        .collect();
                    let ctx = ui.ctx().clone();
                    let use_proxy = self.use_proxy;
                    let proxy_port = self.proxy_port;

                    std::thread::spawn(move || {
                        // 构造代理地址（勾选走代理时按端口，否则 None 直连）
                        let proxy_str: Option<String> = if use_proxy {
                            Some(format!("127.0.0.1:{}", proxy_port))
                        } else {
                            None
                        };

                        // 并发限制：总最多 5，ping 类型最多 2，resolve 类型最多 2
                        let total_sem = Arc::new(Semaphore::new(5));
                        let ping_sem = Arc::new(Semaphore::new(2));
                        let resolve_sem = Arc::new(Semaphore::new(2));

                        let (sub_tx, sub_rx) = mpsc::channel::<SubResult>();

                        // 每个 DNS 的部分结果缓存：
                        // (encryption, recommendation, ping, resolve, sent)
                        let mut partials: HashMap<
                            String,
                            (Encryption, f64, Option<f64>, Option<f64>, bool),
                        > = HashMap::new();
                        for (address, encryption, recommendation, _doh) in &tasks {
                            partials.insert(
                                address.clone(),
                                (*encryption, *recommendation, None, None, false),
                            );
                        }

                        // 为每个 DNS 拆分 ping / resolve 两个子任务并行执行
                        for (address, _encryption, _recommendation, doh) in tasks {
                            // ping 子任务
                            {
                                let total = total_sem.clone();
                                let ping = ping_sem.clone();
                                let tx = sub_tx.clone();
                                let addr = address.clone();
                                let proxy = proxy_str.clone();
                                std::thread::spawn(move || {
                                    ping.acquire();
                                    total.acquire();
                                    let latency =
                                        ping_dns_multi(&addr, proxy.as_deref(), TIMEOUT, PING_COUNT)
                                            .ok()
                                            .and_then(|s| s.avg_latency())
                                            .map(|d| d.as_millis() as f64);
                                    total.release();
                                    ping.release();
                                    let _ = tx.send(SubResult::Ping { address: addr, latency });
                                });
                            }
                            // resolve 子任务
                            {
                                let total = total_sem.clone();
                                let resolve = resolve_sem.clone();
                                let tx = sub_tx.clone();
                                let addr = address.clone();
                                let proxy = proxy_str.clone();
                                std::thread::spawn(move || {
                                    resolve.acquire();
                                    total.acquire();
                                    let quality =
                                        check_resolve_quality(&addr, proxy.as_deref(), TIMEOUT, doh.as_deref())
                                            .ok()
                                            .and_then(|r| r.avg_latency())
                                            .map(|d| d.as_millis() as f64);
                                    total.release();
                                    resolve.release();
                                    let _ = tx
                                        .send(SubResult::Resolve { address: addr, quality });
                                });
                            }
                        }
                        drop(sub_tx); // 所有子任务派发完毕，关闭子结果通道

                        // 收集子结果，ping + resolve 都到后算分并回传
                        for result in sub_rx {
                            if let Some(p) = partials.get_mut(result.address()) {
                                match &result {
                                    SubResult::Ping { latency, .. } => p.2 = *latency,
                                    SubResult::Resolve { quality, .. } => p.3 = *quality,
                                }
                                if !p.4 && p.2.is_some() && p.3.is_some() {
                                    let dl = p.2.unwrap();
                                    let rq = p.3.unwrap();
                                    // 任一项超时（>1s）则不记分
                                    let score = if dl <= LATENCY_TIMEOUT_MS
                                        && rq <= LATENCY_TIMEOUT_MS
                                    {
                                        Some(compute_score(dl, rq, p.0, p.1))
                                    } else {
                                        None
                                    };
                                    let _ = sender.send(TestResult {
                                        address: result.address().to_owned(),
                                        dns_latency: p.2,
                                        resolve_quality: p.3,
                                        score,
                                    });
                                    p.4 = true;
                                    ctx.request_repaint();
                                }
                            }
                        }
                        // sub_rx 结束表示所有子任务完成；sender 随线程结束 drop，
                        // GUI 的 test_receiver 收到 Disconnected 标记测试结束
                    });
                }
                if ui.button("+ 添加").clicked() {
                    self.add_window_open = true;
                }
                if self.testing {
                    ui.label("测试中...");
                }
                ui.checkbox(&mut self.use_proxy, "走代理")
                    .on_hover_text("勾选后 ping 与明文 TCP 解析走 SOCKS5 代理；DoH 解析始终直连");
                if self.use_proxy {
                    ui.label("端口:");
                    ui.add(egui::DragValue::new(&mut self.proxy_port).range(1..=65535));
                }
            });

            ui.separator();

            // 列表（4 列）
            egui::Grid::new("dns_list")
                .striped(true)
                .min_col_width(110.0)
                .show(ui, |ui| {
                    ui.strong("地址");
                    ui.strong("延迟");
                    ui.strong("解析质量");
                    ui.strong("总分数");
                    ui.end_row();

                    for entry in &self.entries {
                        ui.label(&entry.address);
                        ui.label(fmt_ms(entry.dns_latency, self.testing));
                        ui.label(fmt_ms(entry.resolve_quality, self.testing));
                        ui.label(fmt_score_cell(
                            entry.score,
                            entry.dns_latency,
                            entry.resolve_quality,
                            self.testing,
                        ));
                        ui.end_row();
                    }
                });
        });

        // 3. 添加窗口
        if self.add_window_open {
            let mut keep_open = true;
            egui::Window::new("添加 DNS")
                .open(&mut keep_open)
                .resizable(false)
                .collapsible(false)
                .show(ui.ctx(), |ui| {
                    ui.horizontal(|ui| {
                        ui.label("地址:");
                        ui.text_edit_singleline(&mut self.add_form.address);
                    });

                    ui.horizontal(|ui| {
                        ui.label("DoH:");
                        ui.text_edit_singleline(&mut self.add_form.doh)
                            .on_hover_text("留空则走明文 DNS over TCP");
                    });

                    ui.label("支持的加密协议数量:");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.add_form.encryption_count, 0u8, "0 个 (0.5)");
                        ui.radio_value(&mut self.add_form.encryption_count, 1u8, "1 个 (0.75)");
                        ui.radio_value(&mut self.add_form.encryption_count, 2u8, "2 个 (1.0)");
                    });

                    ui.label("推荐系数: 1.00（固定，不可填）");

                    ui.horizontal(|ui| {
                        if ui.button("添加").clicked() {
                            let encryption = match self.add_form.encryption_count {
                                0 => Encryption::None,
                                1 => Encryption::Partial,
                                _ => Encryption::Full,
                            };
                            let doh = {
                                let trimmed = self.add_form.doh.trim();
                                if trimmed.is_empty() {
                                    None
                                } else {
                                    Some(trimmed.to_owned())
                                }
                            };
                            self.entries.push(DnsEntry {
                                address: self.add_form.address.trim().to_owned(),
                                encryption,
                                recommendation: 1.0,
                                doh,
                                dns_latency: None,
                                resolve_quality: None,
                                score: None,
                            });
                            self.add_form = AddForm::default();
                            self.add_window_open = false;
                        }
                        if ui.button("取消").clicked() {
                            self.add_window_open = false;
                        }
                    });
                });
            if !keep_open {
                self.add_window_open = false;
            }
        }
    }
}
