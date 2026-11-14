"use strict";

const API = {
  me: "/api/v1/auth/me",
  logout: "/api/v1/auth/logout",
  overview: "/api/v1/admin/overview",
  users: "/api/v1/admin/users",
  audit: "/api/v1/admin/audit",
  accessAudit: "/api/v1/admin/audit/access",
  rosterPreview: "/api/v1/admin/roster-import/preview",
  rosterCommit: "/api/v1/admin/roster-import/commit",
  settings: "/api/v1/admin/settings",
  attackDesktop: "/api/v1/admin/attack-desktop",
  vehicleRangeTemplates: "/api/v1/admin/vehicle-range/templates",
  vehicleRangeDBCAssets: "/api/v1/admin/vehicle-range/dbc-assets",
  vehicleCatalog: "/api/v1/admin/vehicles/catalog",
  bootstrap: "/api/v1/bootstrap",
};

const RESOURCE_LIBRARY_ID = "competition-library";
const CHALLENGE_LIBRARY_PAGE_SIZE = 5;
const OPERATIONS_PAGE_SIZE = 12;
const OPERATIONS_VIEWS = ["ranking", "submissions", "containers", "cheating"];
const state = { me: null, overview: {}, users: [], participants: [], audit: [], accessAudit: [], auditView: "operations", teams: [], teamLibrary: [], libraryTeams: [], vehicles: [], vehicleLibrary: [], libraryVehicles: [], challenges: [], challengeLibrary: [], libraryChallenges: [], challengeLibraryPage: 1, operations: null, containers: null, cheatingEvents: null, attackDesktop: null, vehicleRangeTemplates: [], vehicleRangeDBCAssets: [], vehicleRangeSettings: null, vehicleRangeInstances: [], editingVehicleRangeTemplateId: null, viewingVehicleRangeTemplate: null, vehicleRangeEditor: null, operationsView: "ranking", operationsPages: { ranking: 1, submissions: 1, containers: 1, cheating: 1 }, systemSettings: null, vehicleCatalog: [], localImages: [], kvmArtifacts: [], imageCatalogError: "", vehicleCapacity: {}, competition: null, competitionId: null, busyUsers: new Set(), editingUserId: null, editingChallengeId: null, editingChallengeScope: RESOURCE_LIBRARY_ID, busyContainers: new Set(), busyCheatingEvents: new Set(), busyTeams: new Set(), exportingOperations: new Set(), loadingOperations: false, teamLibraryImporting: false, rosterImport: { file: null, preview: null, busy: false } };
const $ = (selector, root = document) => root.querySelector(selector);

const VISUAL_ACTION_OPTIONS = [
  { id: "door-front-left-open", label: "开左前门" },
  { id: "door-front-right-open", label: "开右前门" },
  { id: "door-rear-left-open", label: "开左后门" },
  { id: "door-rear-right-open", label: "开右后门" },
  { id: "attack-tbox", label: "攻击 T-BOX" },
  { id: "attack-gateway", label: "攻击中央网关" },
  { id: "attack-central-compute", label: "攻击中央计算" },
  { id: "attack-front-zone", label: "攻击前区控制器" },
  { id: "attack-rear-zone", label: "攻击后区控制器" },
  { id: "attack-bms", label: "攻击 BMS" },
];
const RANGE_VISUAL_ACTION_OPTIONS = [
  { id: "solve-scan", label: "完成扫描" },
  ...VISUAL_ACTION_OPTIONS,
];
const RANGE_NODE_VISUAL_TYPE_OPTIONS = [
  { id: "", label: "自动识别（按节点标识/名称）" },
  { id: "cloud", label: "云服务 / TSP" },
  { id: "tbox", label: "T-BOX 通信盒" },
  { id: "ota", label: "OTA 更新服务" },
  { id: "gateway", label: "中央网关 / DoIP" },
  { id: "bcm", label: "BCM 车身控制器" },
  { id: "bms", label: "BMS 电池管理" },
  { id: "ivi", label: "IVI 车机中控" },
  { id: "adas", label: "ADAS 域控" },
  { id: "radar", label: "毫米波雷达" },
  { id: "camera", label: "摄像头模组" },
  { id: "obd", label: "OBD/诊断接口" },
  { id: "collector", label: "总线采集器" },
  { id: "sensor", label: "传感器" },
  { id: "actuator", label: "执行器" },
  { id: "ecu", label: "通用 ECU" },
];

const ADMIN_VIEWS = {
  competition: { kicker: "赛事治理 / 生命周期控制", title: "赛事管理" },
  overview: { kicker: "平台治理 / 实时快照", title: "运行总览" },
  users: { kicker: "身份中心 / 访问边界", title: "账号管理" },
  teams: { kicker: "参赛组织 / 隔离作用域", title: "参赛队伍" },
  "challenge-library": { kicker: "题目库 / 隔离运行时", title: "题目库" },
  "vehicle-library": { kicker: "车辆库 / 数字孪生实例", title: "车辆库" },
  "vehicle-range-library": { kicker: "车联网靶场 / 私有多节点拓扑", title: "车联网靶场" },
  "vehicle-range-topology": { kicker: "车联网靶场 / 可视化模板编排", title: "车联网靶场拓扑" },
  audit: { kicker: "审计中心 / 不可抵赖", title: "审计记录" },
  settings: { kicker: "系统治理 / 运行时策略", title: "系统设置" },
  "attack-desktop": { kicker: "攻击机 / 会话与节点治理", title: "攻击机管理" },
};

function adminViewFromLocation() {
  const requested = location.hash.slice(1).trim();
  const aliases = { challenges: "challenge-library", assets: "vehicle-library" };
  const view = aliases[requested] || requested;
  return ADMIN_VIEWS[view] ? view : "overview";
}

function activateAdminView(view = adminViewFromLocation()) {
  const activeView = ADMIN_VIEWS[view] ? view : "overview";
  document.body.dataset.adminView = activeView;
  document.querySelectorAll(".admin-section").forEach((section) => {
    section.classList.toggle("is-page-visible", section.id === activeView);
  });
  document.querySelectorAll(".nav-item").forEach((link) => {
    const linkView = link.getAttribute("href")?.slice(1);
    const isActive = linkView === activeView;
    link.classList.toggle("is-active", isActive);
    if (isActive) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  setText("#page-kicker", ADMIN_VIEWS[activeView].kicker);
  setText("#page-title", ADMIN_VIEWS[activeView].title);
  window.scrollTo(0, 0);
}

function bindAdminNavigation() {
  document.querySelectorAll(".nav-item").forEach((link) => link.addEventListener("click", (event) => {
    event.preventDefault();
    const view = link.getAttribute("href")?.slice(1) || "overview";
    if (location.hash !== "#" + view) history.pushState(null, "", "#" + view);
    activateAdminView(view);
    document.body.classList.remove("is-menu-open");
    $("#menu-button")?.setAttribute("aria-expanded", "false");
  }));
  window.addEventListener("hashchange", () => activateAdminView());
  window.addEventListener("popstate", () => activateAdminView());
}

function unwrap(payload) { return payload?.data && typeof payload.data === "object" ? payload.data : payload; }
function firstArray(...values) { return values.find(Array.isArray) || []; }
function userFrom(payload) { const body = unwrap(payload); return body?.user || body?.account || (body?.id || body?.username ? body : null); }
function itemsFrom(payload, key) { const body = unwrap(payload) || {}; return firstArray(body.items, body[key], body.overview?.[key]); }
function errorText(payload, status) {
  return payload?.error?.message || payload?.message || (status === 401 ? "登录会话已失效。" : status === 403 ? "当前账号没有管理权限。" : `请求失败（${status}）`);
}

async function request(path, options = {}) {
  const { raw, timeoutMs: configuredTimeout, ...fetchOptions } = options;
  const method = String(fetchOptions.method || "GET").toUpperCase();
  const timeoutMs = Number.isFinite(configuredTimeout) ? configuredTimeout : method === "GET" ? 20000 : 0;
  const controller = !fetchOptions.signal && timeoutMs > 0 ? new AbortController() : null;
  const timeout = controller ? window.setTimeout(() => controller.abort(), timeoutMs) : null;
  try {
    const response = await fetch(path, {
      credentials: "same-origin",
      ...fetchOptions,
      ...(controller ? { signal: controller.signal } : {}),
      headers: { Accept: "application/json", ...(fetchOptions.body && !raw ? { "Content-Type": "application/json" } : {}), ...(fetchOptions.headers || {}) },
    });
    const text = await response.text();
    let payload = null;
    if (text) { try { payload = JSON.parse(text); } catch { payload = null; } }
    if (!response.ok) { const error = new Error(errorText(payload, response.status)); error.status = response.status; error.code = payload?.error?.code || payload?.code; throw error; }
    return payload || {};
  } catch (error) {
    if (error?.name === "AbortError") throw Object.assign(new Error("请求超时，请检查管理服务或运行节点状态。"), { code: "request_timeout" });
    throw error;
  } finally {
    if (timeout) window.clearTimeout(timeout);
  }
}

function setText(selector, value) { const node = $(selector); if (node) node.textContent = value ?? "—"; }
function number(value, fallback = 0) { const result = Number(value); return Number.isFinite(result) ? result : fallback; }
function challengeVisualActions(challenge) {
  return (Array.isArray(challenge.visualActions) ? challenge.visualActions : Array.isArray(challenge.visual_actions) ? challenge.visual_actions : [])
    .map((action) => String(action || "").trim())
    .filter((action) => action && action !== "solve-scan");
}
function challengeAccessProtocol(challenge) {
  const value = String(challenge?.accessProtocol || challenge?.access_protocol || "tcp").toLowerCase();
  return ["http", "none"].includes(value) ? value : "tcp";
}
function challengeFlagMode(challenge) {
  return String(challenge?.flagMode || challenge?.flag_mode || "dynamic").toLowerCase() === "static" ? "static" : "dynamic";
}
function challengeAttachments(challenge) {
  return Array.isArray(challenge?.attachments) ? challenge.attachments : [];
}
function challengeContainerName(challenge) { return String(challenge?.containerName || challenge?.container_name || challenge?.slug || challenge?.id || "").trim(); }
function vehicleLabel(vehicle) {
  return `${vehicle.label || vehicle.id} · 展示载体 · GEN ${vehicle.generation ?? "—"}`;
}
function valueOf(source, ...keys) { for (const key of keys) if (source?.[key] !== undefined && source[key] !== null) return source[key]; return undefined; }
function formatDate(value) { if (!value) return "从未"; const date = new Date(value); return Number.isNaN(date.valueOf()) ? String(value) : new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(date); }
function isAdmin(user) { return ["admin", "administrator", "super_admin"].includes(String(user?.role || "").toLowerCase()); }
function isEnabled(user) { if (typeof user?.active === "boolean") return user.active; if (typeof user?.enabled === "boolean") return user.enabled; return !["disabled", "inactive", "blocked", "suspended"].includes(String(user?.status || "active").toLowerCase()); }
function isIndividualCompetition() { return state.competition?.mode === "individual" || (isVehicleRangeMode(state.competition?.mode) && String(valueOf(state.vehicleRangeSettings, "scopeMode", "scope_mode") || "") === "individual"); }
function userName(user) { return user?.display_name || user?.displayName || user?.name || user?.username || "未命名账号"; }
function roleLabel(role) { return isAdmin({ role }) ? "平台管理员" : String(role || "competitor").toLowerCase() === "operator" ? "赛事操作员" : "参赛选手"; }

function normalizeCompetition(raw) {
  const source = unwrap(raw)?.item || unwrap(raw)?.competition || unwrap(raw) || {};
  const mode = String(source.mode || "team").toLowerCase();
  return { ...source, id: source.id || "", title: source.title || "未命名赛事", mode: ["team", "individual", "attack", "vehicle_range"].includes(mode) ? mode : "team", status: source.status || "draft", phase: source.phase || "registration", startsAt: valueOf(source, "startsAt", "starts_at"), endsAt: valueOf(source, "endsAt", "ends_at"), cheatingDetectionEnabled: Boolean(valueOf(source, "cheatingDetectionEnabled", "cheating_detection_enabled")), maxActiveContainersPerTeam: Math.max(1, Number(valueOf(source, "maxActiveContainersPerTeam", "max_active_containers_per_team") || 1)) };
}
function normalizeOperations(raw) {
  const body = unwrap(raw) || {};
  const source = body.item || body.operations || body;
  return { ...source, ranking: firstArray(source.ranking), submissions: firstArray(source.submissions), totalTeams: number(valueOf(source, "totalTeams", "total_teams")), totalSubmissions: number(valueOf(source, "totalSubmissions", "total_submissions")) };
}
function normalizeContainers(raw) {
  const body = unwrap(raw) || {};
  const source = body.item || body.containers || body;
  return { ...source, containers: firstArray(source.containers), total: number(valueOf(source, "total")) };
}
function competitionStatusLabel(status) { return ({ draft: "草稿", ready: "报名中", live: "进行中", paused: "已暂停", finished: "已结束" })[status] || status || "未知"; }
function competitionPhaseLabel(phase) { return ({ registration: "报名阶段", running: "比赛进行中", paused: "暂停阶段", finished: "比赛已结束" })[phase] || phase || "未定义阶段"; }
function dateTimeLocal(value) {
  if (!value) return "";
  const date = new Date(value); if (Number.isNaN(date.valueOf())) return "";
  const pad = (item) => String(item).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
function dateTimeISO(value) { return value ? new Date(value).toISOString() : null; }

function showToast(text, error = false) { const toast = $("#toast"); toast.textContent = text; toast.classList.toggle("is-error", error); toast.classList.add("is-visible"); clearTimeout(showToast.timer); showToast.timer = setTimeout(() => toast.classList.remove("is-visible"), 3200); }
function showSectionError(selector, text) { const node = $(selector); node.textContent = text; node.hidden = false; }
function clearSectionError(selector) { const node = $(selector); node.textContent = ""; node.hidden = true; }
function empty(text, loading = false) { const node = document.createElement("div"); node.className = `empty-state${loading ? " is-loading" : ""}`; node.textContent = text; return node; }

function renderMetrics() {
  const authStats = state.overview.auth || {};
  const platformStats = state.overview.platform || {};
  setText("#metric-users", valueOf(authStats, "totalUsers") ?? "—");
  setText("#metric-active-users", valueOf(authStats, "activeUsers") ?? "—");
  setText("#metric-teams", valueOf(platformStats, "teams") ?? "—");
  setText("#metric-vehicles", valueOf(platformStats, "instances") ?? "—");
  setText("#metric-challenges", valueOf(platformStats, "challenges") ?? "—");
  setText("#metric-audit", valueOf(authStats, "auditEvents") ?? "—");
}

function renderServices() {
  const container = $("#service-list"); container.replaceChildren();
  const raw = state.overview.services || state.overview.health || state.overview.dependencies;
  let services = Array.isArray(raw) ? raw : raw && typeof raw === "object" ? Object.entries(raw).map(([name, value]) => typeof value === "object" ? { name, ...value } : { name, status: value }) : [];
  if (!services.length) services = [{ name: "管理接口", status: "online", detail: "当前管理请求正常" }, { name: "赛事数据库", status: state.overview.database || "unknown", detail: "赛事身份与资源事实源" }, { name: "实时状态服务", status: state.overview.redis || state.overview.realtime || "unknown", detail: "车辆状态与会话协调" }];
  services.forEach((service) => {
    const status = String(service.status || service.state || "unknown").toLowerCase();
    const online = ["ok", "online", "ready", "healthy", "up", "true"].includes(status);
    const warning = ["unknown", "degraded", "warning"].includes(status);
    const row = document.createElement("div"); row.className = `service-item ${online ? "" : warning ? "is-warning" : "is-offline"}`;
    row.append(document.createElement("i"));
    const copy = document.createElement("div"); const strong = document.createElement("strong"); strong.textContent = service.label || service.name || "未命名服务"; const small = document.createElement("small"); small.textContent = service.detail || service.message || "由管理控制面报告"; copy.append(strong, small);
    const label = document.createElement("span"); label.textContent = online ? "正常" : warning ? "待确认" : "异常"; row.append(copy, label); container.append(row);
  });
}

function auditAction(item) {
  const action = item.action_label || item.actionLabel || item.action || item.event || item.kind || "";
  const labels = { "auth.login": "账号登录", "auth.logout": "退出登录", "admin.user.create": "创建账号", "admin.user.update": "更新账号", "admin.user.delete": "物理删除账号", "admin.user.delete.batch": "批量物理删除账号", "roster.import": "批量导入队伍与选手", "admin.access": "管理权限拒绝", "team_scope.access": "队伍越权拒绝", "competition.create": "创建赛事", "competition.update": "更新赛事设置", "competition.start": "开始比赛", "competition.pause": "暂停比赛", "competition.resume": "恢复比赛", "competition.finish": "结束比赛", "competition.runtime.cleanup": "清理运行容器", "competition.delete": "删除赛事（归档）", "team.create": "创建队伍", "team.remove": "移除参赛队伍", "team.delete": "物理删除队伍", "team.delete.batch": "批量物理删除队伍", "vehicle.create": "创建展示车辆", "vehicle.delete": "删除展示车辆", "instance.lifecycle.start": "历史车辆兼容记录", "instance.lifecycle.stop": "历史车辆兼容记录", "instance.lifecycle.reset": "历史车辆兼容记录", "challenge.import": "导入题目", "challenge.library.attach": "从题目库导入赛事", "challenge.publish": "发布题目", "challenge.delete": "删除题目草稿", "challenge.metadata.update": "编辑题目设置", "challenge.access_protocol.update": "更新访问协议", "challenge.visual_actions.update": "配置通关动作", "challenge.run.start": "启动题目容器", "challenge.run.admin.restart": "管理员重启题目容器", "challenge.run.admin.stop": "管理员停止题目容器", "challenge.flag.accepted": "题目解出" };
  return labels[action] || action || "管理操作";
}
function auditDescription(item) { return item.description || item.message || item.summary || item.target_name || item.target || item.resource || `${item.outcome === "denied" ? "操作被拒绝" : "操作已记录"}`; }
function auditActor(item) { return item.actor_display_name || item.actor_username || item.actorUsername || item.actor || item.username || item.actorUsername || "系统"; }
function auditTime(item) { return item.created_at || item.createdAt || ""; }
function auditRemote(item) { return item.ip_address || item.ip || item.remote_addr || item.remoteIp || "内部节点"; }
function auditOutcome(item) {
  const raw = String(item.outcome ?? item.status ?? "").trim();
  const labels = { success: "成功", denied: "拒绝", failure: "失败" };
  return labels[raw] || raw || "—";
}
function auditDetails(details) {
  if (details && typeof details === "object" && !Array.isArray(details)) return details;
  if (typeof details === "string" && details.trim()) {
    try {
      const parsed = JSON.parse(details);
      return parsed && typeof parsed === "object" ? parsed : { value: parsed };
    } catch {
      return { value: details };
    }
  }
  return {};
}
function auditDetailValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}
function appendAuditDetailField(container, label, value) {
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  const text = auditDetailValue(value);
  if (text.includes("\n")) {
    const pre = document.createElement("pre");
    pre.textContent = text;
    dd.append(pre);
  } else {
    dd.textContent = text;
  }
  container.append(dt, dd);
}
function auditRawRecord(view, item) {
  if (view === "access") {
    return {
      sequence: item.sequence,
      username: item.username || item.actorUsername || null,
      userId: item.userId || null,
      role: item.role || null,
      teamId: item.teamId || null,
      teamName: item.teamName || null,
      competitionId: item.competitionId || null,
      method: item.method || null,
      path: item.path || null,
      status: item.status ?? null,
      durationMs: item.durationMs ?? null,
      remoteIp: item.remoteIp || null,
      userAgent: item.userAgent || null,
      requestId: item.requestId || null,
      createdAt: auditTime(item) || null,
    };
  }
  return {
    sequence: item.sequence,
    actorUserId: item.actorUserId || null,
    actorUsername: item.actorUsername || item.actor_username || null,
    action: item.action || null,
    actionLabel: auditAction(item),
    outcome: item.outcome || null,
    resource: item.resource || null,
    remoteIp: auditRemote(item),
    requestId: item.requestId || item.request_id || null,
    details: auditDetails(item.details),
    createdAt: auditTime(item) || null,
  };
}
function openAuditDetail(view, sequence) {
  const normalizedView = view === "access" ? "access" : "operations";
  const list = normalizedView === "access" ? state.accessAudit : state.audit;
  const item = list.find((entry) => String(entry.sequence ?? "") === String(sequence ?? ""));
  const dialog = $("#audit-detail-dialog");
  if (!item || !dialog) return;
  const raw = auditRawRecord(normalizedView, item);
  setText("#audit-detail-kicker", normalizedView === "access" ? "API 访问日志 / 详情" : "操作日志 / 详情");
  setText("#audit-detail-title", normalizedView === "access" ? `${item.method || "GET"} ${item.path || "—"}` : auditAction(item));
  const summary = $("#audit-detail-summary");
  summary.replaceChildren();
  [
    { label: "序号", value: raw.sequence },
    { label: normalizedView === "access" ? "账号" : "操作者", value: normalizedView === "access" ? raw.username : auditActor(item) },
    { label: "结果", value: normalizedView === "access" ? `HTTP ${raw.status ?? "—"}` : auditOutcome(item) },
    { label: "时间", value: formatDate(raw.createdAt) },
  ].forEach((entry) => {
    const card = document.createElement("div");
    const label = document.createElement("span");
    label.textContent = entry.label;
    const value = document.createElement("strong");
    value.textContent = auditDetailValue(entry.value);
    card.append(label, value);
    summary.append(card);
  });
  const fields = $("#audit-detail-fields");
  fields.replaceChildren();
  if (normalizedView === "access") {
    appendAuditDetailField(fields, "请求方法", raw.method);
    appendAuditDetailField(fields, "请求路径", raw.path);
    appendAuditDetailField(fields, "HTTP 状态", raw.status);
    appendAuditDetailField(fields, "耗时", raw.durationMs === null ? null : `${raw.durationMs}ms`);
    appendAuditDetailField(fields, "来源 IP", raw.remoteIp);
    appendAuditDetailField(fields, "User-Agent", raw.userAgent);
    appendAuditDetailField(fields, "请求 ID", raw.requestId);
    appendAuditDetailField(fields, "用户 ID", raw.userId);
    appendAuditDetailField(fields, "角色", raw.role);
    appendAuditDetailField(fields, "队伍", [raw.teamName, raw.teamId].filter(Boolean).join(" · "));
    appendAuditDetailField(fields, "赛事 ID", raw.competitionId);
    appendAuditDetailField(fields, "创建时间", raw.createdAt);
  } else {
    appendAuditDetailField(fields, "动作", raw.action);
    appendAuditDetailField(fields, "动作名称", raw.actionLabel);
    appendAuditDetailField(fields, "结果", auditOutcome(item));
    appendAuditDetailField(fields, "资源", raw.resource);
    appendAuditDetailField(fields, "来源 IP", raw.remoteIp);
    appendAuditDetailField(fields, "请求 ID", raw.requestId);
    appendAuditDetailField(fields, "操作者账号", raw.actorUsername);
    appendAuditDetailField(fields, "操作者 ID", raw.actorUserId);
    appendAuditDetailField(fields, "创建时间", raw.createdAt);
    appendAuditDetailField(fields, "details", raw.details);
  }
  $("#audit-detail-json").textContent = JSON.stringify(raw, null, 2);
  dialog.showModal();
}
function closeAuditDetail() {
  const dialog = $("#audit-detail-dialog");
  if (dialog?.open) dialog.close();
}
function auditFilterParams(view = state.auditView) {
  const params = new URLSearchParams({ limit: view === "access" ? "300" : "200" });
  const username = $("#audit-filter-username")?.value.trim();
  const team = $("#audit-filter-team")?.value.trim();
  const competition = $("#audit-filter-competition")?.value.trim();
  const action = $("#audit-filter-action")?.value.trim();
  const ip = $("#audit-filter-ip")?.value.trim();
  const status = $("#audit-filter-status")?.value.trim();
  const from = $("#audit-filter-from")?.value;
  const to = $("#audit-filter-to")?.value;
  if (username) params.set("username", username);
  if (team && view === "access") params.set("teamId", team);
  if (competition && view === "access") params.set("competitionId", competition);
  if (action) params.set(view === "access" ? "path" : "action", action);
  if (ip) params.set("ip", ip);
  if (status) params.set(view === "access" ? "status" : "outcome", status);
  if (from) params.set("from", new Date(from).toISOString());
  if (to) params.set("to", new Date(to).toISOString());
  return params.toString();
}
async function loadAuditRecords() {
  clearSectionError("#audit-message");
  const view = state.auditView;
  const endpoint = view === "access" ? API.accessAudit : API.audit;
  try {
    const payload = await request(`${endpoint}?${auditFilterParams(view)}`);
    if (view === "access") state.accessAudit = itemsFrom(payload, "accessAudit");
    else state.audit = itemsFrom(payload, "audit");
    renderAudit();
    if (view === "operations") renderActivities();
  } catch (error) {
    showSectionError("#audit-message", `审计记录载入失败：${error.message}`);
  }
}
function renderActivities() {
  const container = $("#activity-list"); container.replaceChildren();
  if (!state.audit.length) { container.append(empty("暂无管理活动")); return; }
  state.audit.slice(0, 4).forEach((item) => { const row = document.createElement("article"); row.className = "activity-item"; const copy = document.createElement("div"); const strong = document.createElement("strong"); strong.textContent = auditAction(item); const small = document.createElement("small"); small.textContent = item.actor_display_name || item.actor_username || item.actorUsername || item.actor || "系统"; copy.append(strong, small); const time = document.createElement("time"); time.dateTime = item.created_at || item.createdAt || ""; time.textContent = formatDate(time.dateTime); row.append(copy, time); container.append(row); });
}

function userTeamID(user) { return user.teamId || user.team_id || ""; }
function userTeamLabel(user) { const teamID = userTeamID(user); if (!teamID) return "未绑定"; const team = [...state.teams, ...state.libraryTeams].find((item) => String(item.id) === String(teamID)); return team?.name || user.team_name || teamID; }
function matchingUsers() { const query = $("#user-search").value.trim().toLowerCase(); if (!query) return state.users; return state.users.filter((user) => [user.username, userName(user), userTeamLabel(user), userTeamID(user)].some((value) => String(value || "").toLowerCase().includes(query))); }
function renderUsers() {
  const body = $("#users-table"); body.replaceChildren(); const users = matchingUsers(); setText("#user-count", `${users.length} 个账号`);
  if (!users.length) { const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 8; cell.append(empty(state.users.length ? "没有符合筛选条件的账号" : "尚未创建平台账号")); row.append(cell); body.append(row); syncBulkDeleteControls(); return; }
  users.forEach((user) => {
    const row = document.createElement("tr"); const enabled = isEnabled(user); const id = String(user.id || user.username); const values = [];
    const selectCell = document.createElement("td"); const select = document.createElement("input"); select.type = "checkbox"; select.dataset.userSelect = id; select.checked = false; selectCell.append(select); values.push(selectCell);
    const identity = document.createElement("td"); const wrap = document.createElement("div"); wrap.className = "identity-cell"; const mark = document.createElement("span"); mark.className = "identity-mark"; mark.textContent = String(user.username || "?").slice(0, 2).toUpperCase(); const copy = document.createElement("div"); const account = document.createElement("strong"); account.textContent = user.username || "—"; const ident = document.createElement("small"); ident.textContent = id; copy.append(account, ident); wrap.append(mark, copy); identity.append(wrap); values.push(identity);
    [userName(user), roleLabel(user.role), userTeamLabel(user), null, formatDate(user.last_login_at || user.lastLoginAt)].forEach((value, index) => { const cell = document.createElement("td"); if (index === 1) cell.className = "role-label"; if (index === 3) { const chip = document.createElement("span"); chip.className = `status-chip${enabled ? "" : " is-disabled"}`; chip.textContent = enabled ? "已启用" : "已停用"; cell.append(chip); } else cell.textContent = value; values.push(cell); });
    const currentUserID = String(state.me?.id || state.me?.userId || ""); const actionCell = document.createElement("td"); const actions = document.createElement("div"); actions.className = "user-actions";
    const edit = document.createElement("button"); edit.type = "button"; edit.className = "user-action"; edit.dataset.userAction = "edit"; edit.dataset.userId = id; edit.textContent = "编辑"; edit.disabled = state.busyUsers.has(id);
    const toggle = document.createElement("button"); toggle.type = "button"; toggle.className = `user-action${enabled ? "" : " is-enable"}`; toggle.dataset.userAction = "toggle"; toggle.dataset.userId = id; toggle.dataset.nextStatus = enabled ? "disabled" : "active"; toggle.textContent = enabled ? "停用" : "启用"; toggle.disabled = state.busyUsers.has(id) || id === currentUserID; if (id === currentUserID) toggle.title = "不能停用当前登录账号";
    const remove = document.createElement("button"); remove.type = "button"; remove.className = "user-action asset-delete-action"; remove.dataset.userAction = "delete"; remove.dataset.userId = id; remove.textContent = "物理删除"; remove.disabled = state.busyUsers.has(id) || id === currentUserID; remove.title = id === currentUserID ? "不能删除当前登录账号" : "永久删除账号及其会话，无法恢复";
    actions.append(edit, toggle, remove); actionCell.append(actions); values.push(actionCell); row.append(...values); body.append(row);
  });
  syncBulkDeleteControls();
}

function selectedIDs(selector) { return [...document.querySelectorAll(selector)].filter((input) => input.checked).map((input) => input.dataset.userSelect || input.dataset.teamSelect || input.dataset.competitionTeamSelect).filter(Boolean); }
function syncBulkDeleteControls() {
  const users = selectedIDs("[data-user-select]"); const teams = selectedIDs("[data-team-select]");
  const userButton = $("#delete-selected-users"); if (userButton) { userButton.disabled = !users.length; userButton.textContent = users.length ? `物理删除选中账号（${users.length}）` : "物理删除选中账号"; }
  const teamButton = $("#delete-selected-teams"); if (teamButton) { teamButton.disabled = !teams.length; teamButton.textContent = teams.length ? `物理删除选中队伍（${teams.length}）` : "物理删除选中队伍"; }
  const competitionTeams = selectedIDs("[data-competition-team-select]"); const competitionButton = $("#delete-selected-competition-teams"); if (competitionButton) { competitionButton.disabled = !competitionTeams.length; competitionButton.textContent = competitionTeams.length ? `物理删除选中队伍（${competitionTeams.length}）` : "物理删除选中队伍"; }
  const all = $("#select-all-users"); if (all) { const visible = document.querySelectorAll("[data-user-select]"); all.checked = visible.length > 0 && users.length === visible.length; all.indeterminate = users.length > 0 && users.length < visible.length; }
  const allTeams = $("#select-all-teams"); if (allTeams) { const visible = document.querySelectorAll("[data-team-select]"); allTeams.checked = visible.length > 0 && teams.length === visible.length; allTeams.indeterminate = teams.length > 0 && teams.length < visible.length; }
  const allCompetition = $("#select-all-competition-teams"); if (allCompetition) { const visible = document.querySelectorAll("[data-competition-team-select]"); allCompetition.checked = visible.length > 0 && competitionTeams.length === visible.length; allCompetition.indeterminate = competitionTeams.length > 0 && competitionTeams.length < visible.length; }
}

function renderCompetitionTeamAssets() {
  const list = $("#competition-team-list");
  if (!list) return;
  if (isIndividualCompetition()) {
    const items = state.participants || [];
    setText("#competition-team-current-total", items.length);
    list.replaceChildren();
    const toolbar = list.previousElementSibling;
    if (toolbar?.classList.contains("competition-team-toolbar")) toolbar.hidden = true;
    if (!items.length) { list.append(empty("当前赛事尚未导入个人选手")); return; }
    items.forEach((participant) => {
      const row = document.createElement("article"); row.className = "asset-item competition-current-asset"; row.style.setProperty("--item-color", "var(--signal-dim)"); row.append(document.createElement("i"));
      const copy = document.createElement("div"); const title = document.createElement("strong"); title.textContent = `${valueOf(participant, "displayName", "display_name") || participant.username} · ${participant.username}`;
      const detail = document.createElement("small"); detail.textContent = `个人独立作用域 · ${valueOf(participant, "scopeTeamId", "scope_team_id")}`;
      copy.append(title, detail);
      const status = document.createElement("span"); status.className = "asset-status is-active"; status.textContent = "已参赛";
      const remove = document.createElement("button"); remove.type = "button"; remove.className = "user-action asset-delete-action"; remove.dataset.removeParticipant = participant.userId; remove.textContent = "移除"; remove.disabled = ["live", "paused", "finished"].includes(state.competition?.status); remove.title = remove.disabled ? "比赛运行或结束期间不能移除个人选手" : "从本赛事移除，平台账号和原队伍不受影响";
      row.append(copy, status, remove); list.append(row);
    });
    return;
  }
  const items = state.teams || [];
  const toolbar = list.previousElementSibling;
  if (toolbar?.classList.contains("competition-team-toolbar")) toolbar.hidden = false;
  setText("#competition-team-current-total", items.length);
  list.replaceChildren();
  if (!items.length) { list.append(empty("当前赛事尚未导入队伍")); return; }
  items.forEach((team) => {
    const row = document.createElement("article"); row.className = "asset-item competition-current-asset has-selection"; row.style.setProperty("--item-color", team.color || "var(--signal-dim)"); row.append(document.createElement("i"));
    const selection = document.createElement("input"); selection.type = "checkbox"; selection.dataset.competitionTeamSelect = team.id; selection.setAttribute("aria-label", `选择当前赛事队伍 ${team.name || team.code || team.id}`); row.append(selection);
    const copy = document.createElement("div"); const title = document.createElement("strong"); title.textContent = team.name || team.code || team.id || "未命名队伍";
    const members = state.users.filter((user) => String(userTeamID(user) || "") === String(team.id || "")).length;
    const detail = document.createElement("small"); detail.textContent = `${team.code || team.id || "—"} · ${members} 名选手 · ${number(team.score)} 分`;
    copy.append(title, detail);
    const status = document.createElement("span"); status.className = `asset-status ${team.status === "active" ? "is-active" : ""}`; status.textContent = team.status === "active" ? "已导入" : (team.status || "状态未知");
    row.append(copy, status); list.append(row);
  });
  syncBulkDeleteControls();
}

function renderCompetitionVehicleAssets() {
  const list = $("#competition-vehicle-list");
  if (!list) return;
  const items = state.vehicles || [];
  setText("#competition-vehicle-current-total", items.length);
  list.replaceChildren();
  if (!items.length) { list.append(empty("当前赛事尚无展示车辆")); return; }
  items.forEach((vehicle) => {
    const row = document.createElement("article"); row.className = "asset-item competition-current-asset"; row.style.setProperty("--item-color", "var(--signal-dim)"); row.append(document.createElement("i"));
    const copy = document.createElement("div"); const title = document.createElement("strong"); title.textContent = vehicle.label || vehicle.name || vehicle.id || "未命名车辆";
    const bound = state.challenges.filter((challenge) => (challenge.boundVehicleInstanceIds || []).includes(vehicle.id)).map((challenge) => challenge.title || challenge.slug || challenge.id);
    const detail = document.createElement("small"); detail.textContent = `GEN ${vehicle.generation ?? "—"} · ${bound.length ? `绑定题目：${bound.join("、")}` : "尚未绑定题目"}`;
    copy.append(title, detail);
    const status = document.createElement("span"); status.className = "asset-status is-active"; status.textContent = "只读映射";
    row.append(copy, status); list.append(row);
  });
}

function renderCompetition() {
  const competition = state.competition;
  const emptyState = $("#competition-empty"); const content = $("#competition-content");
  if (!competition?.id) {
    emptyState.hidden = false; content.hidden = true; $("#competition-operations").hidden = true; setText("#competition-id-label", "未创建赛事"); $("#competition-create-toggle").hidden = true; $("#open-competition-bigscreen").disabled = true; setText("#competition-empty-kicker", "赛事尚未创建"); setText("#competition-empty-title", "创建第一场比赛"); setText("#competition-empty-description", "设置赛事名称、参赛模式和时间后，再按需加入参赛范围与题目。"); return;
  }
  const finished = competition.status === "finished";
  emptyState.hidden = true; content.hidden = false; $("#competition-operations").hidden = false; const createToggle = $("#competition-create-toggle"); createToggle.hidden = !finished; createToggle.textContent = "新建赛事";
  $("#open-competition-bigscreen").disabled = false;
  setText("#competition-id-label", competition.id);
  setText("#competition-control-title", competition.title);
  setText("#competition-control-id", competition.id);
  const attackMode = isAttackDesktopMode(competition.mode);
  const vehicleRangeMode = isVehicleRangeMode(competition.mode);
  const individual = isIndividualCompetition();
  setText("#competition-mode-label", competition.mode === "individual" ? "CTF · 个人赛" : vehicleRangeMode ? `车联网安全靶场赛 · ${individual ? "个人赛" : "团队赛"}` : "CTF · 团队赛");
  const accessMode = String(valueOf(competition, "accessMode", "access_mode") || (attackMode ? "attack" : "direct"));
  setText("#competition-access-mode-label", ({ attack: "攻击机", openvpn: "OpenVPN 私网", direct: "直连" })[accessMode] || "直连");
  setText("#competition-roster-title", competition.mode === "individual" ? "比赛内容 · 个人赛" : vehicleRangeMode ? "比赛内容 · 车联网靶场" : attackMode ? "比赛内容 · 攻击机赛" : "比赛内容 · 团队赛");
  setText("#teams-title", individual ? "选手与个人作用域" : "队伍与人员");
  setText("#teams-description", individual ? "平台个人参赛项独立于赛事维护；创建赛事后，再按需导入参赛账号。" : "平台队伍独立于赛事维护；创建赛事后，再按需导入队伍、选手和成绩空间。");
  setText("#team-name-label", individual ? "选手名称" : "队伍名称");
  setText("#team-list-kicker", "平台资源库");
  setText("#team-list-title", individual ? "平台个人参赛项" : "平台队伍库");
  const libraryBulkSummary = document.querySelector(".competition-resource-picker > .team-library-bulk-summary:not(#participant-library-bulk-summary)");
  const participantBulkSummary = $("#participant-library-bulk-summary");
  const libraryPickerNote = document.querySelector(".competition-resource-picker > small");
  if (libraryBulkSummary) libraryBulkSummary.hidden = individual;
  if (participantBulkSummary) participantBulkSummary.hidden = !individual;
  if (libraryPickerNote) {
    libraryPickerNote.textContent = individual
      ? "个人赛不导入队伍；请在下方“参赛人员”选择器中直接加入选手账号，系统为每名选手维护独立参赛作用域。"
      : "可一次选择多支队伍导入；系统会自动继承平台队伍中已关联的选手。";
  }
  setText("#competition-team-count", individual ? state.participants.length : state.teams.length);
  setText("#competition-team-current-title", individual ? "已导入个人选手" : "已导入队伍");
  setText("#competition-team-current-total", individual ? state.participants.length : state.teams.length);
  renderCompetitionTeamAssets();
  renderCompetitionVehicleAssets();
  const competitionTeamIDs = new Set(state.teams.map((team) => String(team.id || "")));
  setText("#competition-user-count", individual ? state.participants.length : state.users.filter((user) => String(userTeamID(user) || "") && competitionTeamIDs.has(String(userTeamID(user)))).length);
  setText("#competition-challenge-count", state.challenges.length);
  renderVehicleRangeSettings();
  const librarySelect = $("#competition-library-challenge");
  const libraryAdd = $("#competition-add-challenge");
  if (librarySelect) {
    const importableChallenges = importableLibraryChallenges();
    const selected = librarySelect.value;
    librarySelect.replaceChildren(new Option(importableChallenges.length ? "选择题目库题目" : "暂无可导入题目", ""));
    importableChallenges.forEach((challenge) => librarySelect.add(new Option(`${challenge.title || challenge.slug || challenge.id} · ${number(challenge.baseScore)} 分`, challenge.id)));
    librarySelect.value = importableChallenges.some((challenge) => challenge.id === selected) ? selected : "";
    if (libraryAdd) libraryAdd.disabled = !librarySelect.value;
  }
  const teamLibraryOptions = $("#team-library-options");
  const teamLibraryImport = $("#team-library-import");
  if (teamLibraryOptions) {
    const importableTeams = importableLibraryTeams();
    const selected = new Set([...teamLibraryOptions.querySelectorAll("input[type=checkbox]:checked")].map((input) => input.value));
    teamLibraryOptions.replaceChildren();
    if (!importableTeams.length) teamLibraryOptions.append(Object.assign(document.createElement("span"), { className: "library-empty-note", textContent: "暂无可导入队伍" }));
    importableTeams.forEach((team) => {
      const label = document.createElement("label"); label.className = "team-library-option";
      label.dataset.search = String((team.name || team.id || "") + " " + (team.organization || team.organization_name || "")).toLocaleLowerCase();
      const input = document.createElement("input"); input.type = "checkbox"; input.value = team.id; input.checked = selected.has(String(team.id)); input.disabled = competition.status === "finished";
      const copy = document.createElement("span"); copy.innerHTML = `<strong></strong><small></small>`; copy.querySelector("strong").textContent = team.name || team.id; copy.querySelector("small").textContent = `组织：${team.organization || team.organization_name || "未填写单位"} · ${number(team.memberCount ?? team.member_count)} 名账号`;
      label.append(input, copy); teamLibraryOptions.append(label);
    });
    const count = teamLibraryOptions.querySelectorAll("input[type=checkbox]:checked").length;
    setText("#team-library-selection-count", `已选 ${count} 支`);
    setText("#team-library-dialog-count", `已选 ${count} 支`);
    if (teamLibraryImport) teamLibraryImport.disabled = count === 0 || competition.status === "finished";
  }
  renderParticipantLibraryOptions(individual);
  const teamParticipantPicker = $("#team-participant-picker");
  if (teamParticipantPicker) teamParticipantPicker.hidden = individual;
  const participantUserSelect = $("#competition-participant-user");
  const participantTeamSelect = $("#competition-participant-team");
  const participantAdd = $("#competition-add-participant");
  if (participantUserSelect && participantTeamSelect) {
    const selectedUser = participantUserSelect.value;
    const selectedTeam = participantTeamSelect.value;
    participantUserSelect.replaceChildren(new Option("选择平台选手账号", ""));
    state.users.filter((user) => String(user.role || "").toLowerCase() === "team" && !competitionTeamIDs.has(String(userTeamID(user) || ""))).forEach((user) => {
      const label = `${userName(user)} · ${user.username || user.id || "—"}${userTeamID(user) ? ` · 当前 ${user.team_name || userTeamID(user)}` : " · 未绑定"}`;
      participantUserSelect.add(new Option(label, user.id || user.username));
    });
    participantUserSelect.value = [...participantUserSelect.options].some((option) => option.value === selectedUser) ? selectedUser : "";
    participantTeamSelect.replaceChildren(new Option("选择当前赛事队伍", ""));
    state.teams.filter((team) => team.status === "active").forEach((team) => participantTeamSelect.add(new Option(`${team.name || team.id} · ${team.code || team.id}`, team.id)));
    participantTeamSelect.value = [...participantTeamSelect.options].some((option) => option.value === selectedTeam) ? selectedTeam : "";
    if (participantAdd) participantAdd.disabled = !participantUserSelect.value || !participantTeamSelect.value || competition.status === "finished";
  }
  const statusChip = $("#competition-status-chip"); statusChip.textContent = competitionStatusLabel(competition.status); statusChip.className = `status-chip status-${competition.status}`;
  setText("#competition-phase-label", competitionPhaseLabel(competition.phase));
  const title = $("#competition-title"); if (document.activeElement !== title) title.value = competition.title || "";
  const start = $("#competition-start"); if (document.activeElement !== start) start.value = dateTimeLocal(competition.startsAt);
  const end = $("#competition-end"); if (document.activeElement !== end) end.value = dateTimeLocal(competition.endsAt);
  const maxContainers = $("#competition-max-containers"); if (maxContainers && document.activeElement !== maxContainers) maxContainers.value = competition.maxActiveContainersPerTeam;
  const cheatingDetection = $("#competition-cheating-detection");
  if (document.activeElement !== cheatingDetection) cheatingDetection.checked = competition.cheatingDetectionEnabled;
  setText("#competition-cheating-detection-note", competition.cheatingDetectionEnabled
    ? "已开启：五类规则持续留证，高危事件将即时禁止本作用域继续参加本赛事。"
    : "仅记录：五类规则持续留证，高危事件由管理员复核后手动禁赛。");
  const locked = finished;
  $("#competition-settings-form").querySelectorAll("input,button").forEach((node) => { node.disabled = locked; });
  const scheduleNote = competition.startsAt || competition.endsAt
    ? `计划时间：${competition.startsAt ? formatDate(competition.startsAt) : "手动开始"} — ${competition.endsAt ? formatDate(competition.endsAt) : "手动结束"}；系统会自动切换赛事状态。`
    : "未设置计划时间，管理员可在比赛控制台手动开始或补充时间。";
  setText("#competition-schedule-note", locked ? "比赛已结束，赛事设置已锁定。" : scheduleNote);
  const allowed = { start: ["ready", "paused"], pause: ["live"], resume: ["paused"], finish: ["ready", "live", "paused"], cleanup: ["paused", "finished"], delete: ["paused", "finished"] };
  $("#competition-actions").querySelectorAll("[data-competition-action]").forEach((button) => { const action = button.dataset.competitionAction; button.disabled = !allowed[action]?.includes(competition.status); });
  const challengeList = $("#competition-challenge-list"); challengeList.replaceChildren();
  setText("#competition-challenge-total", `${state.challenges.length}`);
  setText("#competition-challenge-dialog-count", `${state.challenges.length} 道题目`);
  if (!state.challenges.length) challengeList.append(empty("尚未导入题目，请从题目库导入；也可以在题目库新建草稿。"));
  state.challenges.forEach((challenge) => {
    const row = document.createElement("article");
    row.className = "asset-item";
    row.style.setProperty("--item-color", challenge.status === "published" ? "var(--signal)" : "var(--amber)");
    row.append(document.createElement("i"));
    const copy = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = challenge.title || challenge.slug || challenge.id;
    const boundVehicles = (challenge.boundVehicleInstanceIds || []).map((id) => state.vehicles.find((vehicle) => vehicle.id === id)?.label || id);
    const small = document.createElement("small");
    small.textContent = `${challenge.status === "published" ? "已发布" : "草稿"} · ${number(challenge.baseScore)} 分 · ${boundVehicles.length ? `车辆：${boundVehicles.join("、")}` : "未继承车辆映射"}`;
    copy.append(strong, small);
    row.append(copy);
    const actions = document.createElement("div");
    actions.className = "asset-item-actions";
    const status = document.createElement("span");
    status.textContent = challenge.status === "published" ? "选手端可见" : boundVehicles.length ? "已导入，待发布" : "待绑定车辆";
    actions.append(status);
    if (challenge.status !== "published") {
      const publish = document.createElement("button");
      publish.type = "button";
      publish.className = "user-action";
      publish.dataset.publishCompetitionChallenge = challenge.id;
      publish.textContent = "发布题目";
      publish.disabled = competition.status === "finished" || !boundVehicles.length;
      publish.title = boundVehicles.length ? "发布后选手端即可看到该题目" : "请先绑定车辆";
      actions.append(publish);
    }
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "user-action asset-delete-action";
    remove.dataset.removeCompetitionChallenge = challenge.id;
    remove.textContent = "移除题目";
    remove.disabled = competition.status === "finished";
    remove.title = challenge.status === "published"
      ? "从本赛事物理移除该已发布题目；已有运行、提交或得分记录会一并删除，请谨慎操作"
      : "从本赛事移除该草稿题目及其附件";
    actions.append(remove);
    row.append(actions);
    challengeList.append(row);
  });
  state.challenges.forEach((challenge, index) => {
    const row = challengeList.children[index];
    const copy = row?.querySelector("strong")?.parentElement;
    if (!copy || copy.querySelector("[data-batch-challenge]")) return;
    copy.classList.add("competition-challenge-copy");
    const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.dataset.batchChallenge = challenge.id; checkbox.setAttribute("aria-label", `选择题目 ${challenge.title || challenge.slug || challenge.id}`);
    checkbox.addEventListener("change", syncCompetitionBatchSelection);
    copy.prepend(checkbox);
  });
  syncCompetitionBatchSelection();
  enhanceCompetitionScoreControls();
}

function renderParticipantLibraryOptions(individual = isIndividualCompetition()) {
  const root = $("#participant-library-options");
  if (!root) return;
  const imported = new Set(state.participants.map((item) => String(valueOf(item, "userId", "user_id") || "")));
  const selected = new Set([...root.querySelectorAll("input[type=checkbox]:checked")].map((input) => input.value));
  const teamNames = new Map([...state.libraryTeams, ...state.teams].map((team) => [String(team.id), team.name || team.id]));
  const candidates = state.users.filter((user) => String(user.role || "").toLowerCase() === "team" && isEnabled(user) && !imported.has(String(user.id)));
  root.replaceChildren();
  if (!individual || !candidates.length) {
    root.append(Object.assign(document.createElement("span"), { className: "library-empty-note", textContent: individual ? "暂无可导入选手" : "当前赛事不是个人赛" }));
  }
  candidates.forEach((user) => {
    const label = document.createElement("label"); label.className = "team-library-option";
    const teamName = teamNames.get(String(userTeamID(user) || "")) || "未归属平台队伍";
    label.dataset.search = `${user.username || ""} ${userName(user)} ${teamName}`.toLocaleLowerCase();
    const input = document.createElement("input"); input.type = "checkbox"; input.value = user.id; input.checked = selected.has(String(user.id)); input.disabled = state.competition?.status === "finished";
    const copy = document.createElement("span"); copy.innerHTML = "<strong></strong><small></small>";
    copy.querySelector("strong").textContent = `${userName(user)} · ${user.username}`;
    copy.querySelector("small").textContent = `平台队伍：${teamName}`;
    label.append(input, copy); root.append(label);
  });
  const count = root.querySelectorAll("input[type=checkbox]:checked").length;
  setText("#participant-library-selection-count", `已选 ${count} 名`);
  setText("#participant-library-dialog-count", `已选 ${count} 名`);
  const importButton = $("#participant-library-import");
  if (importButton) importButton.disabled = count === 0 || state.competition?.status === "finished";
}

function enhanceCompetitionScoreControls() {
  const list = $("#competition-challenge-list");
  if (!list || !state.challenges.length) return;
  state.challenges.forEach((challenge, index) => {
    const row = list.children[index];
    if (!row || row.querySelector("[data-save-score-challenge]")) return;
    row.classList.add("competition-challenge-row");
    const control = document.createElement("div");
    control.className = "competition-score-control";
    const modeLabel = document.createElement("label");
    const modeText = document.createElement("span"); modeText.textContent = "赛事分值策略";
    const mode = document.createElement("select"); mode.dataset.scoreMode = ""; mode.innerHTML = "<option value='fixed'>固定分值</option><option value='dynamic'>动态分值（反比例幂函数）</option><option value='podium'>固定分值 + 血量奖励</option>"; mode.value = challenge.scoreMode || "fixed";
    modeLabel.append(modeText, mode);
    const fields = document.createElement("div"); fields.className = "score-fields";
    const save = document.createElement("button"); save.type = "button"; save.className = "user-action"; save.dataset.saveScoreChallenge = challenge.id; save.textContent = "保存分值";
    control.append(modeLabel, fields, save);
    mode.addEventListener("change", () => renderCompetitionScoreFields(control, challenge));
    renderCompetitionScoreFields(control, challenge);
    if (state.competition?.status === "finished") control.querySelectorAll("input,select,button").forEach((node) => { node.disabled = true; });
    const actions = row.querySelector(".asset-item-actions");
    if (actions) row.insertBefore(control, actions);
  });
}

function renderCompetitionScoreFields(control, challenge) {
  const mode = control.querySelector("[data-score-mode]").value;
  const fields = control.querySelector(".score-fields"); fields.replaceChildren();
  const addField = (label, key, value) => {
    const wrapper = document.createElement("label"); const text = document.createElement("span"); text.textContent = label;
    const input = document.createElement("input"); input.type = "number"; input.min = "1"; input.max = "1000000"; input.value = number(value, 1); input.dataset.scoreField = key;
    wrapper.append(text, input); fields.append(wrapper);
  };
  if (mode === "fixed") addField("本题得分", "baseScore", challenge.baseScore);
  if (mode === "dynamic") { addField("初始分", "baseScore", challenge.baseScore); addField("最低分", "dynamicMinScore", challenge.dynamicMinScore || challenge.baseScore); addField("衰减系数 k", "dynamicDecay", challenge.dynamicDecay || 80); }
  if (mode === "podium") { addField("一血奖励", "firstBloodScore", challenge.firstBloodScore || 20); addField("二血奖励", "secondBloodScore", challenge.secondBloodScore || 10); addField("三血及以后奖励", "thirdBloodScore", challenge.thirdBloodScore || 5); }
}

function renderCompetitionBatchScoreFields() {
  const fields = $("#competition-batch-score-fields");
  if (!fields) return;
  const mode = $("#competition-batch-score-mode").value;
  fields.replaceChildren();
  const selected = state.challenges.find((challenge) => [...document.querySelectorAll("[data-batch-challenge]:checked")].some((input) => input.dataset.batchChallenge === challenge.id)) || state.challenges[0] || {};
  const addField = (label, key, value) => {
    const wrapper = document.createElement("label"); wrapper.className = "field";
    const text = document.createElement("span"); text.textContent = label;
    const input = document.createElement("input"); input.type = "number"; input.min = "1"; input.max = "1000000"; input.value = number(value, 1); input.dataset.batchScoreField = key;
    wrapper.append(text, input); fields.append(wrapper);
  };
  if (mode === "fixed") addField("本题得分", "baseScore", selected.baseScore);
  if (mode === "dynamic") { addField("初始分", "baseScore", selected.baseScore); addField("最低分", "dynamicMinScore", selected.dynamicMinScore || selected.baseScore); addField("衰减系数 k", "dynamicDecay", selected.dynamicDecay || 80); }
  if (mode === "podium") { addField("一血奖励", "firstBloodScore", selected.firstBloodScore || 20); addField("二血奖励", "secondBloodScore", selected.secondBloodScore || 10); addField("三血及以后奖励", "thirdBloodScore", selected.thirdBloodScore || 5); }
}

function syncCompetitionBatchSelection() {
  const count = document.querySelectorAll("[data-batch-challenge]:checked").length;
  setText("#competition-score-selection-count", `已选 ${count} 道题目`);
  const save = $("#competition-batch-score-save"); if (save) save.disabled = !count || state.competition?.status === "finished";
  renderCompetitionBatchScoreFields();
}

function operationValue(item, ...keys) { return valueOf(item, ...keys); }
function isVehicleRangeOperationsMode() { return isVehicleRangeMode(state.competition?.mode); }
function operationsSubmissionLabels() {
  const vehicleRange = isVehicleRangeOperationsMode();
  return {
    tabKicker: vehicleRange ? "02 / PASSES" : "02 / FLAGS",
    tabTitle: vehicleRange ? "通关记录" : "提交记录",
    panelKicker: vehicleRange ? "RANGE PASS RECORDS" : "FLAG SUBMISSIONS",
    panelTitle: vehicleRange ? "选手通关记录" : "提交记录",
    loading: vehicleRange ? "正在载入选手通关记录…" : "正在载入提交记录…",
    empty: vehicleRange ? "暂无选手通关记录" : "暂无选手提交记录",
    total: vehicleRange ? "次通关" : "次",
    exportName: vehicleRange ? "选手通关记录" : "提交记录",
  };
}
function setOperationsTableHeaders(tableSelector, headers, variant) {
  const row = document.querySelector(`${tableSelector} thead tr`);
  if (!row || row.dataset.variant === variant) return;
  row.dataset.variant = variant;
  row.replaceChildren(...headers.map((label) => {
    const cell = document.createElement("th");
    cell.textContent = label;
    return cell;
  }));
}
function syncOperationsSubmissionLabels() {
  const labels = operationsSubmissionLabels();
  const vehicleRange = isVehicleRangeOperationsMode();
  const tab = $("#operations-tab-submissions");
  if (tab) {
    const kicker = tab.querySelector("span"); if (kicker) kicker.textContent = labels.tabKicker;
    const title = tab.querySelector("strong"); if (title) title.textContent = labels.tabTitle;
  }
  const panel = $("#operations-view-submissions");
  if (panel) {
    const kicker = panel.querySelector(".panel-heading div span"); if (kicker) kicker.textContent = ` ${labels.panelKicker} `;
    setText("#competition-submissions-title", labels.panelTitle);
  }
  setOperationsTableHeaders(".ranking-table", vehicleRange
    ? ["排名", "选手 / 队伍", "分数", "通关", "记录", "最后通关"]
    : ["排名", "选手 / 队伍", "分数", "解题", "提交", "最后解题"], vehicleRange ? "vehicle-range" : "ctf");
  setOperationsTableHeaders(".submissions-table", vehicleRange
    ? ["时间", "选手 / 队伍", "小题", "通关证据", "状态", "得分", "代次"]
    : ["时间", "选手 / 队伍", "题目", "提交内容", "结果", "得分", "代次"], vehicleRange ? "vehicle-range" : "ctf");
}
function operationsViewItems(view) {
  if (view === "ranking") return state.operations?.ranking || [];
  if (view === "submissions") return state.operations?.submissions || [];
  if (view === "containers") return state.containers?.containers || [];
  if (view === "cheating") return state.cheatingEvents || [];
  return [];
}
function operationsReportedTotal(view) {
  if (view === "submissions") return number(operationValue(state.operations || {}, "totalSubmissions", "total_submissions"));
  if (view === "containers") return number(valueOf(state.containers || {}, "total"));
  return operationsViewItems(view).length;
}
function pagedOperationsItems(view, items) {
  const pageCount = Math.max(1, Math.ceil(items.length / OPERATIONS_PAGE_SIZE));
  state.operationsPages[view] = Math.min(Math.max(1, number(state.operationsPages[view]) || 1), pageCount);
  const start = (state.operationsPages[view] - 1) * OPERATIONS_PAGE_SIZE;
  return items.slice(start, start + OPERATIONS_PAGE_SIZE);
}
function renderOperationsPagination(view, items, reportedTotal = items.length) {
  const footer = $(`[data-operations-pagination="${view}"]`);
  if (!footer) return;
  const pageCount = Math.max(1, Math.ceil(items.length / OPERATIONS_PAGE_SIZE));
  const page = Math.min(Math.max(1, number(state.operationsPages[view]) || 1), pageCount);
  state.operationsPages[view] = page;
  footer.hidden = items.length === 0;
  const start = items.length ? (page - 1) * OPERATIONS_PAGE_SIZE + 1 : 0;
  const end = Math.min(page * OPERATIONS_PAGE_SIZE, items.length);
  const total = Math.max(items.length, number(reportedTotal));
  const summary = total > items.length
    ? `第 ${start}–${end} 条 · 已载入 ${items.length} / 总计 ${total}`
    : `第 ${start}–${end} 条 · 共 ${items.length} 条`;
  setText(`[data-operations-page-summary="${view}"]`, summary);
  setText(`[data-operations-page-label="${view}"]`, `${page} / ${pageCount}`);
  footer.querySelector('[data-page-direction="-1"]').disabled = page <= 1;
  footer.querySelector('[data-page-direction="1"]').disabled = page >= pageCount;
}
function syncOperationsWorkbench() {
  syncOperationsSubmissionLabels();
  if (!OPERATIONS_VIEWS.includes(state.operationsView)) state.operationsView = "ranking";
  document.querySelectorAll("[data-operations-view]").forEach((button) => {
    const selected = button.dataset.operationsView === state.operationsView;
    button.classList.toggle("is-active", selected);
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  document.querySelectorAll("[data-operations-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.operationsPanel !== state.operationsView;
  });
  setText("#operations-tab-ranking-count", operationsViewItems("ranking").length);
  setText("#operations-tab-submissions-count", operationsReportedTotal("submissions"));
  setText("#operations-tab-containers-count", operationsReportedTotal("containers"));
  setText("#operations-tab-cheating-count", operationsReportedTotal("cheating"));
}
function activateOperationsView(view, { focus = false } = {}) {
  if (!OPERATIONS_VIEWS.includes(view)) return;
  state.operationsView = view;
  syncOperationsWorkbench();
  if (focus) $(`[data-operations-view="${view}"]`)?.focus();
}
function changeOperationsPage(view, direction) {
  if (!OPERATIONS_VIEWS.includes(view)) return;
  const items = operationsViewItems(view);
  const pageCount = Math.max(1, Math.ceil(items.length / OPERATIONS_PAGE_SIZE));
  const nextPage = Math.min(pageCount, Math.max(1, (number(state.operationsPages[view]) || 1) + direction));
  if (nextPage === state.operationsPages[view]) return;
  state.operationsPages[view] = nextPage;
  if (view === "containers") renderCompetitionContainers();
  else if (view === "cheating") renderCompetitionCheating();
  else renderCompetitionOperations();
  $(`[data-operations-panel="${view}"]`)?.scrollIntoView({ block: "start" });
}
function appendOperationsIdentity(cell, name, code) {
  const strong = document.createElement("strong"); strong.className = "operations-primary"; strong.textContent = name || "未命名选手";
  const small = document.createElement("small"); small.className = "operations-secondary"; small.textContent = code || "—";
  cell.append(strong, small);
}
function appendSubmissionContent(cell, item) {
  const submitted = operationValue(item, "submittedContent", "submitted_content");
  cell.className = "submission-content-cell";
  if (typeof submitted !== "string") {
    cell.classList.add("is-historical");
    const marker = document.createElement("small"); marker.textContent = "历史记录未保存内容";
    cell.append(marker);
    return;
  }
  const value = document.createElement("code"); value.className = "submission-content-value"; value.textContent = submitted; value.title = submitted;
  const copy = document.createElement("button"); copy.type = "button"; copy.className = "submission-copy-action"; copy.textContent = "复制"; copy.setAttribute("aria-label", "复制本次提交内容");
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(submitted);
      showToast("提交内容已复制");
    } catch {
      showToast("复制失败，请选中提交内容后手动复制");
    }
  });
  cell.append(value, copy);
}
function appendVehicleRangePassEvidence(cell, item) {
  const digest = String(operationValue(item, "evidenceDigest", "evidence_digest") || "").trim();
  const instance = operationValue(item, "instanceId", "instance_id", "runId", "run_id") || "—";
  const stage = operationValue(item, "stageKey", "stage_key", "challengeId", "challenge_id") || "—";
  cell.className = "submission-content-cell";
  const value = document.createElement("code"); value.className = "submission-content-value"; value.textContent = digest || "平台校验通过"; value.title = digest || "平台校验通过";
  const detail = document.createElement("small"); detail.className = "operations-secondary"; detail.textContent = `${stage} · ${instance}`;
  cell.append(value, detail);
}
function operationsDatasetItems(dataset) {
  if (!state.operations) return [];
  return dataset === "ranking" ? state.operations.ranking || [] : state.operations.submissions || [];
}
function syncOperationsExportButtons() {
  document.querySelectorAll("[data-export-operations]").forEach((button) => {
    const dataset = button.dataset.exportOperations;
    const items = operationsDatasetItems(dataset);
    const exporting = state.exportingOperations.has(dataset);
    button.disabled = !state.competitionId || state.loadingOperations || !state.operations || !items.length || exporting;
    button.textContent = exporting ? "导出中…" : "批量导出";
    button.setAttribute("aria-busy", exporting ? "true" : "false");
    button.title = !state.competitionId ? "尚未创建赛事" : state.loadingOperations || !state.operations ? "赛事运维数据载入后可导出" : !items.length ? "当前没有可导出的数据" : "";
  });
}
function renderCompetitionOperations() {
  enhanceCompetitionScoreControls();
  const rankingBody = $("#competition-ranking-table"); const submissionsBody = $("#competition-submissions-table");
  if (!rankingBody || !submissionsBody) return;
  const passRecordMode = isVehicleRangeOperationsMode();
  const submissionLabels = operationsSubmissionLabels();
  syncOperationsWorkbench();
  rankingBody.replaceChildren(); submissionsBody.replaceChildren();
  const operations = state.operations;
  if (!state.competitionId) {
    const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 6; cell.className = "operations-empty"; cell.textContent = "尚未创建赛事"; row.append(cell); rankingBody.append(row);
    const submissionRow = document.createElement("tr"); const submissionCell = document.createElement("td"); submissionCell.colSpan = 7; submissionCell.className = "operations-empty"; submissionCell.textContent = "尚未创建赛事"; submissionRow.append(submissionCell); submissionsBody.append(submissionRow);
    setText("#competition-ranking-total", "0"); setText("#competition-submission-total", "0"); setText("#competition-operations-summary", "等待赛事数据"); renderOperationsPagination("ranking", []); renderOperationsPagination("submissions", []); syncOperationsExportButtons(); return;
  }
  if (!operations) {
    const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 6; cell.className = "operations-empty"; cell.textContent = "正在载入赛事运维数据…"; row.append(cell); rankingBody.append(row);
    const submissionRow = document.createElement("tr"); const submissionCell = document.createElement("td"); submissionCell.colSpan = 7; submissionCell.className = "operations-empty"; submissionCell.textContent = submissionLabels.loading; submissionRow.append(submissionCell); submissionsBody.append(submissionRow); renderOperationsPagination("ranking", []); renderOperationsPagination("submissions", []); syncOperationsExportButtons(); return;
  }
  const allRanking = operations.ranking || []; const allSubmissions = operations.submissions || [];
  const ranking = pagedOperationsItems("ranking", allRanking); const submissions = pagedOperationsItems("submissions", allSubmissions);
  const totalSubmissions = operationValue(operations, "totalSubmissions", "total_submissions") || 0;
  setText("#competition-ranking-total", `${allRanking.length} 队`); setText("#competition-submission-total", `${totalSubmissions} ${submissionLabels.total}`); setText("#competition-operations-summary", `同步 ${formatDate(new Date())} · ${allRanking.length} 个排名作用域`);
  if (!allRanking.length) {
    const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 6; cell.className = "operations-empty"; cell.textContent = "暂无参赛队伍排名"; row.append(cell); rankingBody.append(row);
  } else ranking.forEach((item) => {
    const row = document.createElement("tr"); const rank = document.createElement("td"); rank.className = "rank-number"; rank.textContent = `#${operationValue(item, "rank") || "—"}`;
    const team = document.createElement("td"); appendOperationsIdentity(team, operationValue(item, "teamName", "team_name") || operationValue(item, "teamId", "team_id"), operationValue(item, "teamCode", "team_code"));
    const score = document.createElement("td"); score.textContent = `${number(operationValue(item, "score"))} 分`;
    const solves = document.createElement("td"); solves.textContent = `${number(operationValue(item, "solves"))}`;
    const submissionsCell = document.createElement("td"); submissionsCell.textContent = `${number(operationValue(item, "submissions"))}`;
    const lastSolved = document.createElement("td"); lastSolved.textContent = formatDate(operationValue(item, "lastSolvedAt", "last_solved_at"));
    row.append(rank, team, score, solves, submissionsCell, lastSolved); rankingBody.append(row);
  });
  if (!allSubmissions.length) {
    const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 7; cell.className = "operations-empty"; cell.textContent = submissionLabels.empty; row.append(cell); submissionsBody.append(row);
  } else submissions.forEach((item) => {
    const row = document.createElement("tr"); const created = document.createElement("td"); created.textContent = formatDate(operationValue(item, "createdAt", "created_at"));
    const team = document.createElement("td"); appendOperationsIdentity(team, operationValue(item, "teamName", "team_name") || operationValue(item, "teamId", "team_id"), operationValue(item, "teamCode", "team_code"));
    const challenge = document.createElement("td");
    if (passRecordMode) {
      const stageKey = operationValue(item, "stageKey", "stage_key", "challengeId", "challenge_id");
      const stageOrder = number(operationValue(item, "stageOrder", "stage_order"));
      appendOperationsIdentity(challenge, operationValue(item, "challengeTitle", "challenge_title") || stageKey, stageOrder ? `第 ${stageOrder} 小题 · ${stageKey}` : stageKey);
    } else appendOperationsIdentity(challenge, operationValue(item, "challengeTitle", "challenge_title") || operationValue(item, "challengeId", "challenge_id"), operationValue(item, "challengeId", "challenge_id"));
    const submittedContent = document.createElement("td");
    if (passRecordMode) appendVehicleRangePassEvidence(submittedContent, item);
    else appendSubmissionContent(submittedContent, item);
    const result = String(operationValue(item, "result") || "unknown").toLowerCase(); const resultCell = document.createElement("td"); const resultTag = document.createElement("span"); resultTag.className = `submission-result is-${result}`; resultTag.textContent = passRecordMode && result === "accepted" ? "已通关" : ({ accepted: "已通过", rejected: "未通过", duplicate: "重复", stale: "已过期" })[result] || result; resultCell.append(resultTag);
    const score = document.createElement("td"); score.textContent = number(operationValue(item, "scoreDelta", "score_delta")) ? `+${number(operationValue(item, "scoreDelta", "score_delta"))}` : "—";
    const generation = document.createElement("td"); generation.textContent = `G${operationValue(item, "generation") || "—"}`;
    row.append(created, team, challenge, submittedContent, resultCell, score, generation); submissionsBody.append(row);
  });
  renderOperationsPagination("ranking", allRanking);
  renderOperationsPagination("submissions", allSubmissions, totalSubmissions);
  syncOperationsWorkbench();
  syncOperationsExportButtons();
}

function exportFileNameFrom(response, dataset) {
  const disposition = response.headers.get("Content-Disposition") || response.headers.get("content-disposition") || "";
  const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  if (encoded) {
    try { return decodeURIComponent(encoded); } catch { return encoded; }
  }
  const quoted = disposition.match(/filename="?([^"]+)"?/i)?.[1];
  if (quoted) return quoted;
  const stamp = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, "");
  return `competition-${state.competitionId || "operations"}-${dataset}-${stamp}.csv`;
}

async function exportCompetitionOperations(dataset) {
  const labels = { ranking: "选手排名", submissions: operationsSubmissionLabels().exportName };
  if (!["ranking", "submissions"].includes(dataset) || !state.competitionId || state.exportingOperations.has(dataset)) return;
  if (state.loadingOperations || !state.operations) { showSectionError("#competition-operations-message", "赛事运维数据仍在载入，请稍后再导出。"); return; }
  if (!operationsDatasetItems(dataset).length) { showSectionError("#competition-operations-message", `${labels[dataset]}暂无可导出的数据。`); return; }
  state.exportingOperations.add(dataset); syncOperationsExportButtons(); clearSectionError("#competition-operations-message");
  try {
    const response = await fetch(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/operations/export?dataset=${encodeURIComponent(dataset)}`, { credentials: "same-origin", headers: { Accept: "text/csv" } });
    if (!response.ok) {
      let payload = null;
      const text = await response.text();
      if (text) { try { payload = JSON.parse(text); } catch { payload = { message: text }; } }
      throw new Error(errorText(payload, response.status));
    }
    const blob = await response.blob();
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.href = url;
    link.download = exportFileNameFrom(response, dataset);
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast(`${labels[dataset]} CSV 已开始下载`);
  } catch (error) {
    showSectionError("#competition-operations-message", `${labels[dataset]}导出失败：${error.message}`);
  } finally {
    state.exportingOperations.delete(dataset); syncOperationsExportButtons();
  }
}

function containerStatusLabel(status) { return ({ provisioning: "准备中", ready: "已就绪", running: "运行中", solved: "已通关", failed: "运行失败", resetting: "清理中", closed: "已关闭" })[status] || status || "未知"; }
function renderCompetitionContainers() {
  const body = $("#competition-containers-table");
  if (!body) return;
  syncOperationsWorkbench();
  body.replaceChildren();
  const inventory = state.containers;
  if (!state.competitionId) {
    const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 7; cell.className = "operations-empty"; cell.textContent = "尚未创建赛事"; row.append(cell); body.append(row); setText("#competition-container-total", "0"); renderOperationsPagination("containers", []); return;
  }
  if (!inventory) {
    const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 7; cell.className = "operations-empty"; cell.textContent = "正在载入选手运行容器…"; row.append(cell); body.append(row); renderOperationsPagination("containers", []); return;
  }
  const allContainers = inventory.containers || [];
  const containers = pagedOperationsItems("containers", allContainers);
  const totalContainers = number(valueOf(inventory, "total"));
  setText("#competition-container-total", `${totalContainers} 个`);
  if (!allContainers.length) {
    const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 7; cell.className = "operations-empty"; cell.textContent = "当前赛事没有选手开启的运行容器"; row.append(cell); body.append(row); renderOperationsPagination("containers", []); return;
  }
  containers.forEach((item) => {
    const runID = String(operationValue(item, "runId", "run_id") || "");
    const status = String(operationValue(item, "status") || "unknown").toLowerCase();
    const row = document.createElement("tr");
    const runtime = document.createElement("td"); runtime.className = "container-runtime-id";
    const handle = String(operationValue(item, "runtimeHandle", "runtime_handle") || "");
    runtime.textContent = handle ? `${handle.slice(0, 14)}${handle.length > 14 ? "…" : ""}` : runID || "—";
    const runtimeMeta = document.createElement("small"); runtimeMeta.textContent = `${runID || "—"} · G${operationValue(item, "generation") || "—"}`; runtime.append(runtimeMeta);
    const team = document.createElement("td"); appendOperationsIdentity(team, operationValue(item, "teamName", "team_name") || operationValue(item, "teamId", "team_id"), operationValue(item, "teamCode", "team_code"));
    const challenge = document.createElement("td"); appendOperationsIdentity(challenge, operationValue(item, "challengeTitle", "challenge_title") || operationValue(item, "challengeId", "challenge_id"), operationValue(item, "challengeId", "challenge_id"));
    const statusCell = document.createElement("td"); const statusTag = document.createElement("span"); statusTag.className = `container-status is-${status}`; statusTag.textContent = containerStatusLabel(status); statusCell.append(statusTag);
    const access = document.createElement("td"); access.className = "container-access"; const host = operationValue(item, "accessHost", "access_host"); const port = number(operationValue(item, "accessPort", "access_port")); access.textContent = host && port ? `${host}:${port}` : "未分配访问端口";
    const updated = document.createElement("td"); updated.textContent = formatDate(operationValue(item, "updatedAt", "updated_at"));
    const actions = document.createElement("td"); actions.className = "container-actions";
    const busy = state.busyContainers.has(runID);
    if (["provisioning", "ready", "running", "solved", "failed"].includes(status)) {
      const restart = document.createElement("button"); restart.type = "button"; restart.className = "container-action"; restart.dataset.containerAction = "restart"; restart.dataset.containerRun = runID; restart.textContent = "重启"; restart.disabled = busy; actions.append(restart);
      const stop = document.createElement("button"); stop.type = "button"; stop.className = "container-action is-danger"; stop.dataset.containerAction = "stop"; stop.dataset.containerRun = runID; stop.textContent = "停止"; stop.disabled = busy; actions.append(stop);
    } else { const label = document.createElement("span"); label.className = "operations-secondary"; label.textContent = "等待运行时收敛"; actions.append(label); }
    row.append(runtime, team, challenge, statusCell, access, updated, actions); body.append(row);
  });
  renderOperationsPagination("containers", allContainers, totalContainers);
  syncOperationsWorkbench();
}

const CHEATING_RULE_LABELS = {
  foreign_dynamic_flag: "使用对方动态 Flag",
  attachment_without_download: "未下载附件即正确提交",
  submission_burst: "短时高频提交",
  ip_rotation: "提交 IP 频繁变换",
  wrong_submission_burst: "短时高频错误 Flag",
};

function cheatingEvidence(item) {
  const evidence = operationValue(item, "evidence");
  if (evidence && typeof evidence === "object") return evidence;
  if (typeof evidence === "string") {
    try { return JSON.parse(evidence); } catch { return { raw: evidence }; }
  }
  return {};
}

function foreignFlagOwner(match = {}) {
  const ownerTeam = match.ownerTeam && typeof match.ownerTeam === "object" ? match.ownerTeam : {};
  const ownerRun = match.ownerRun && typeof match.ownerRun === "object" ? match.ownerRun : {};
  const proof = match.proof && typeof match.proof === "object" ? match.proof : {};
  return {
    teamId: ownerTeam.id || match.teamId || "",
    teamName: ownerTeam.name || "",
    teamCode: ownerTeam.code || "",
    runId: ownerRun.id || match.runId || "",
    generation: ownerRun.generation ?? match.generation ?? "",
    runStatus: ownerRun.status || "",
    proofSource: proof.source || match.source || "",
    proof,
  };
}

function foreignFlagTeamLabel(owner) {
  const name = owner.teamName || owner.teamId || "未知归属队伍";
  return owner.teamCode && owner.teamCode !== name ? `${name}（${owner.teamCode}）` : name;
}

function cheatingEvidenceSummary(item) {
  const rule = operationValue(item, "ruleCode", "rule_code");
  const evidence = cheatingEvidence(item);
  if (rule === "foreign_dynamic_flag") {
    if (evidence.demo) return "管理员演示记录：不包含真实提交，不能作为正式作弊证据";
    const matches = Array.isArray(evidence.matches) ? evidence.matches : [];
    const actor = evidence.actor && typeof evidence.actor === "object" ? evidence.actor : {};
    const actorName = actor.displayName || actor.username || operationValue(item, "userDisplayName", "user_display_name") || operationValue(item, "username") || "未知选手";
    const actorTeam = actor.teamName || operationValue(item, "teamName", "team_name") || operationValue(item, "teamId", "team_id") || "未知队伍";
    const owners = [...new Set(matches.map((match) => foreignFlagTeamLabel(foreignFlagOwner(match))).filter(Boolean))];
    return owners.length
      ? `${actorName}（${actorTeam}）提交的动态 Flag 归属于 ${owners.join("、")}；${matches.length} 条归属证据已闭合`
      : `${actorName}（${actorTeam}）提交的动态 Flag 命中对方运行记录，但归属身份不完整`;
  }
  if (rule === "attachment_without_download") {
    return evidence.downloadScope === "user" ? "该选手在正确提交前没有本题附件下载记录" : "全队成员在正确提交前均没有本题附件下载记录";
  }
  if (rule === "submission_burst") return `5 分钟内共提交 ${number(evidence.submissionCount)} 次 Flag`;
  if (rule === "ip_rotation") {
    const ips = Array.isArray(evidence.ips) ? evidence.ips.map((entry) => entry.ip).filter(Boolean) : [];
    return `5 分钟内使用 ${number(evidence.distinctIpCount)} 个 IP${ips.length ? `：${ips.join("、")}` : ""}`;
  }
  if (rule === "wrong_submission_burst") return `5 分钟内错误提交 ${number(evidence.wrongSubmissionCount)} 次`;
  return evidence.rule || "已记录结构化检测证据";
}

function cheatingEvidenceStep(index, label, title, detail) {
  const step = document.createElement("div"); step.className = "cheating-evidence-step";
  const marker = document.createElement("i"); marker.textContent = String(index).padStart(2, "0");
  const copy = document.createElement("div");
  const eyebrow = document.createElement("span"); eyebrow.textContent = label;
  const heading = document.createElement("strong"); heading.textContent = title;
  copy.append(eyebrow, heading);
  if (detail) {
    const small = document.createElement("small"); small.textContent = detail; copy.append(small);
  }
  step.append(marker, copy);
  return step;
}

function renderForeignFlagEvidence(item, evidence) {
  const chain = document.createElement("div"); chain.className = "cheating-evidence-chain";
  if (evidence.demo) {
    chain.classList.add("is-demo");
    chain.append(cheatingEvidenceStep("!", "演示记录", "这不是一次真实 Flag 提交", evidence.note || "仅用于管理员处置流程演示，不能作为正式作弊判定证据。"));
    return chain;
  }
  const actor = evidence.actor && typeof evidence.actor === "object" ? evidence.actor : {};
  const submission = evidence.submission && typeof evidence.submission === "object" ? evidence.submission : {};
  const challenge = evidence.challenge && typeof evidence.challenge === "object" ? evidence.challenge : {};
  const matches = Array.isArray(evidence.matches) ? evidence.matches : [];
  const actorName = actor.displayName || actor.username || operationValue(item, "userDisplayName", "user_display_name") || operationValue(item, "username") || "未知选手";
  const actorTeam = actor.teamName || operationValue(item, "teamName", "team_name") || actor.teamId || operationValue(item, "teamId", "team_id") || "未知队伍";
  const actorCode = actor.teamCode ? ` · ${actor.teamCode}` : "";
  chain.append(cheatingEvidenceStep(1, "提交主体", actorName, `账号 ${actor.username || actor.userId || "未知"} · 队伍 ${actorTeam}${actorCode}`));

  const submissionID = submission.id || operationValue(item, "submissionId", "submission_id") || "未知";
  const submittedAt = submission.submittedAt || operationValue(item, "createdAt", "created_at");
  const runID = submission.runId || operationValue(item, "runId", "run_id") || "未知运行";
  const generation = submission.generation ?? "—";
  const remoteIP = submission.remoteIp || "未记录 IP";
  chain.append(cheatingEvidenceStep(2, "触发提交", `提交 #${submissionID} · ${formatDate(submittedAt)}`, `${challenge.title || challenge.id || "未知题目"} · ${runID} · G${generation} · ${remoteIP}`));

  matches.forEach((match, matchIndex) => {
    const owner = foreignFlagOwner(match);
    const proofLabel = owner.proofSource === "accepted_submission"
      ? `归属队伍正确提交 #${owner.proof.submissionId || "—"}`
      : owner.proofSource === "active_dynamic_flag"
        ? "平台当前动态 Flag 派生校验"
        : owner.proofSource || "归属来源未标记";
    const proofTime = owner.proof.acceptedAt ? ` · ${formatDate(owner.proof.acceptedAt)}` : "";
    const ownerRun = `${owner.runId || "未知运行"} · G${owner.generation || "—"}${owner.runStatus ? ` · ${owner.runStatus}` : ""}`;
    chain.append(cheatingEvidenceStep(3 + matchIndex, "Flag 归属", foreignFlagTeamLabel(owner), `${ownerRun} · ${proofLabel}${proofTime}`));
  });

  const digest = submission.submittedDigestSha256 || evidence.submittedDigestSha256 || "";
  const digestLabel = digest ? `${digest.slice(0, 16)}…${digest.slice(-12)}` : "未记录摘要";
  chain.append(cheatingEvidenceStep(3 + matches.length, "闭环判定", "提交摘要与归属运行的动态 Flag 摘要一致", `SHA-256 ${digestLabel} · 为保护比赛 Flag，不展示明文`));
  return chain;
}

function cheatingEnforcementLabel(item) {
  const teamDisqualified = Boolean(operationValue(item, "teamDisqualified", "team_disqualified"));
  const userDisqualified = Boolean(operationValue(item, "userDisqualified", "user_disqualified"));
  if (teamDisqualified && userDisqualified) return ["选手及队伍均已禁赛", "两个独立作用域均在拦截"];
  if (teamDisqualified) return ["整队已禁赛", "该队伍全部选手均被拦截"];
  if (userDisqualified) return ["该选手已禁赛", "同队其他选手不受影响"];
  const action = operationValue(item, "enforcementAction", "enforcement_action");
  if (action === "reinstated") return ["已解除禁赛", "保留原始事件与管理审计"];
  if (action === "auto_disqualified") return ["曾自动禁赛", "当前禁赛状态已解除"];
  if (action === "manually_disqualified") return ["曾人工禁赛", "当前禁赛状态已解除"];
  return ["仅记录", "未执行自动处置"];
}

function renderCompetitionCheating() {
  const body = $("#competition-cheating-table");
  if (!body) return;
  syncOperationsWorkbench();
  body.replaceChildren();
  const policy = $("#competition-cheating-policy");
  const enabled = Boolean(state.competition?.cheatingDetectionEnabled);
  if (policy) {
    policy.textContent = enabled ? "高危自动禁赛已开启" : "仅记录 · 人工复核";
    policy.classList.toggle("is-enforcing", enabled);
  }
  if (!state.competitionId) {
    const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 6; cell.className = "operations-empty"; cell.textContent = "尚未创建赛事"; row.append(cell); body.append(row);
    setText("#competition-cheating-total", "0"); renderOperationsPagination("cheating", []); return;
  }
  if (!Array.isArray(state.cheatingEvents)) {
    const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 6; cell.className = "operations-empty"; cell.textContent = "正在载入作弊检测证据…"; row.append(cell); body.append(row);
    renderOperationsPagination("cheating", []); return;
  }
  const allEvents = state.cheatingEvents;
  const events = pagedOperationsItems("cheating", allEvents);
  setText("#competition-cheating-total", `${allEvents.length} 条`);
  if (!allEvents.length) {
    const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 6; cell.className = "operations-empty"; cell.textContent = "当前赛事没有触发作弊风险规则"; row.append(cell); body.append(row);
    renderOperationsPagination("cheating", []); return;
  }
  events.forEach((item) => {
    const id = String(operationValue(item, "id") || "");
    const risk = String(operationValue(item, "riskLevel", "risk_level") || "low").toLowerCase();
    const rule = String(operationValue(item, "ruleCode", "rule_code") || "");
    const disqualified = Boolean(operationValue(item, "disqualified"));
    const teamDisqualified = Boolean(operationValue(item, "teamDisqualified", "team_disqualified"));
    const userDisqualified = Boolean(operationValue(item, "userDisqualified", "user_disqualified"));
    const userID = String(operationValue(item, "userId", "user_id") || "");
    const row = document.createElement("tr");

    const riskCell = document.createElement("td"); riskCell.className = "cheating-risk-cell";
    const riskTag = document.createElement("span"); riskTag.className = `cheating-risk is-${risk}`; riskTag.textContent = ({ high: "高危", medium: "中危", low: "低危" })[risk] || risk;
    const created = document.createElement("time"); created.textContent = formatDate(operationValue(item, "createdAt", "created_at")); riskCell.append(riskTag, created);

    const participant = document.createElement("td");
    const userName = operationValue(item, "userDisplayName", "user_display_name");
    const username = operationValue(item, "username");
    const teamName = operationValue(item, "teamName", "team_name") || operationValue(item, "teamId", "team_id");
    const teamCode = operationValue(item, "teamCode", "team_code");
    appendOperationsIdentity(participant, userName || teamName, userName ? `${username || "未知账号"} · ${teamName}` : teamCode);

    const ruleCell = document.createElement("td"); ruleCell.className = "cheating-rule";
    const ruleTitle = document.createElement("strong"); ruleTitle.textContent = CHEATING_RULE_LABELS[rule] || rule || "未知规则";
    const challenge = document.createElement("small"); challenge.textContent = operationValue(item, "challengeTitle", "challenge_title") || operationValue(item, "challengeId", "challenge_id") || "跨题目行为"; ruleCell.append(ruleTitle, challenge);

    const evidenceCell = document.createElement("td"); evidenceCell.className = "cheating-evidence";
    const summary = document.createElement("span"); summary.textContent = cheatingEvidenceSummary(item);
    const details = document.createElement("details"); const detailsLabel = document.createElement("summary"); detailsLabel.textContent = "查看完整证据";
    const evidence = cheatingEvidence(item);
    details.append(detailsLabel);
    if (rule === "foreign_dynamic_flag") details.append(renderForeignFlagEvidence(item, evidence));
    const rawDetails = document.createElement("details"); rawDetails.className = "cheating-evidence-raw";
    const rawLabel = document.createElement("summary"); rawLabel.textContent = "查看原始 JSON";
    const evidenceJSON = document.createElement("pre"); evidenceJSON.textContent = JSON.stringify(evidence, null, 2);
    rawDetails.append(rawLabel, evidenceJSON); details.append(rawDetails); evidenceCell.append(summary, details);

    const enforcementCell = document.createElement("td"); enforcementCell.className = `cheating-enforcement ${disqualified ? "is-blocked" : "is-clear"}`;
    const [enforcementTitle, enforcementDetail] = cheatingEnforcementLabel(item);
    const enforcementStrong = document.createElement("strong"); enforcementStrong.textContent = enforcementTitle;
    const enforcementSmall = document.createElement("small"); enforcementSmall.textContent = enforcementDetail; enforcementCell.append(enforcementStrong, enforcementSmall);

    const actionCell = document.createElement("td");
    if (risk === "high") {
      const actions = document.createElement("div"); actions.className = "cheating-action-stack";
      const appendAction = (scope, blocked, label) => {
        const busyKey = `${id}:${scope}`;
        const button = document.createElement("button"); button.type = "button";
        button.className = `cheating-action ${blocked ? "is-reinstate" : "is-disqualify"}`;
        button.dataset.cheatingEvent = id;
        button.dataset.cheatingScope = scope;
        button.dataset.cheatingAction = blocked ? "reinstate" : "disqualify";
        button.textContent = state.busyCheatingEvents.has(busyKey)
          ? "处理中…"
          : `${blocked ? "解禁" : "禁赛"}${label}`;
        button.disabled = state.busyCheatingEvents.has(busyKey);
        actions.append(button);
      };
      if (userID) appendAction("user", userDisqualified, "该选手");
      appendAction("team", teamDisqualified, "整队");
      actionCell.append(actions);
    } else {
      const marker = document.createElement("span"); marker.className = "operations-secondary"; marker.textContent = "证据观察"; actionCell.append(marker);
    }
    row.append(riskCell, participant, ruleCell, evidenceCell, enforcementCell, actionCell); body.append(row);
  });
  renderOperationsPagination("cheating", allEvents);
  syncOperationsWorkbench();
}

async function controlCheatingEvent(eventID, scope, action) {
  if (!eventID || !state.competitionId || !["user", "team"].includes(scope)) return;
  const busyKey = `${eventID}:${scope}`;
  if (state.busyCheatingEvents.has(busyKey)) return;
  const disqualify = action === "disqualify";
  const scopeLabel = scope === "user" ? "该选手" : "该队伍及其全部选手";
  const prompt = disqualify
    ? `确认禁止${scopeLabel}继续参加本次比赛？现有登录会话后续访问本赛事也会被拦截。`
    : `确认解除${scopeLabel}的本赛事禁赛状态？其他选手和队伍的处置不会改变，原始证据仍会保留。`;
  if (!window.confirm(prompt)) return;
  state.busyCheatingEvents.add(busyKey); renderCompetitionCheating();
  try {
    await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/cheating-events/${encodeURIComponent(eventID)}/actions`, {
      method: "POST", body: JSON.stringify({ action, scope }),
    });
    await loadCompetitionOperations();
    showToast(disqualify ? `已禁赛${scopeLabel}` : `已解禁${scopeLabel}`);
  } catch (error) {
    showSectionError("#competition-operations-message", `作弊处置失败：${error.message}`);
  } finally {
    state.busyCheatingEvents.delete(busyKey); renderCompetitionCheating();
  }
}

function libraryCompetitionID(item) { return String(item?.competitionId || item?.competition_id || ""); }
function libraryCompetitionTitle(item) { return item?.competitionTitle || item?.competition_title || libraryCompetitionID(item) || "历史赛事"; }
function importableLibraryChallenges() {
  const currentChallengeSlugs = new Set((state.challenges || []).map((challenge) => String(challenge.slug || "").trim()).filter(Boolean));
  return (state.libraryChallenges || []).filter((challenge) => {
    const slug = String(challenge.slug || "").trim();
    return slug && !currentChallengeSlugs.has(slug);
  });
}
function importableLibraryTeams() {
  const currentTeamNames = new Set((state.teams || []).filter((team) => team.status !== "offline").map((team) => String(team.name || "").trim()));
  return (state.libraryTeams || []).filter((team) => !currentTeamNames.has(String(team.name || "").trim()));
}

function buildLibraryRow({ title, detail, color = "var(--signal-dim)", actionLabel, actionDataset, disabled = false }) {
  const row = document.createElement("article"); row.className = "asset-item"; row.style.setProperty("--item-color", color); row.append(document.createElement("i"));
  const copy = document.createElement("div"); const heading = document.createElement("strong"); heading.textContent = title; const meta = document.createElement("small"); meta.textContent = detail; copy.append(heading, meta);
  const actions = document.createElement("div"); actions.className = "asset-item-actions";
  if (actionLabel) {
    const button = document.createElement("button"); button.type = "button"; button.className = "user-action"; button.textContent = actionLabel; button.disabled = disabled;
    Object.entries(actionDataset || {}).forEach(([key, value]) => { button.dataset[key] = value; });
    actions.append(button);
  }
  row.append(copy, actions); return row;
}

function renderTeamLibrary() {
  const list = $("#team-library-list"); if (!list) return;
  const items = state.libraryTeams;
  setText("#team-library-total", items.length); list.replaceChildren();
  if (!items.length) { list.append(empty("队伍库为空，请先创建队伍")); return; }
  items.forEach((team) => {
    const detail = `${team.code || team.id || "—"} · ${number(team.memberCount ?? team.member_count)} 名账号 · ${number(team.score)} 分`;
    list.append(buildLibraryRow({ title: team.name || team.code || team.id, detail, color: team.color }));
  });
}

function renderVehicleLibrary() {
  const list = $("#vehicle-library-list"); if (!list) return;
  const items = state.libraryVehicles;
  setText("#vehicle-library-total", items.length); list.replaceChildren();
  items.forEach((vehicle) => {
    const definition = vehicle.vehicleDefinitionId || vehicle.vehicle_definition_id || "—";
    const detail = `${definition} · GEN ${vehicle.generation || "—"}`;
    list.append(buildLibraryRow({ title: vehicle.label || vehicle.id, detail, actionLabel: "删除", actionDataset: { vehicleAction: "remove", vehicleId: vehicle.id } }));
  });
}

function renderAssets() {
  $("#team-form").querySelectorAll("input,button,select").forEach((node) => { node.disabled = false; });
  setText("#team-total", state.libraryTeams.length); setText("#vehicle-total", state.libraryVehicles.length); const teamSelect = $("#new-team"); const selected = teamSelect.value; teamSelect.replaceChildren(new Option("不绑定队伍", ""));
  // Accounts are platform resources too, so their default team picker must
  // use the reusable platform team library even when no event exists yet.
  // Preserve an already-bound event team while editing an imported account.
  const selectableTeams = [...state.libraryTeams];
  state.teams.filter((team) => String(team.id || team.code) === String(selected)).forEach((team) => {
    if (!selectableTeams.some((item) => String(item.id || item.code) === String(team.id || team.code))) selectableTeams.push(team);
  });
  selectableTeams.forEach((team) => teamSelect.add(new Option(team.name || team.code || team.id, team.id || team.code)));
  if ([...teamSelect.options].some((option) => option.value === selected)) teamSelect.value = selected;
  const vehicleDefinition = $("#vehicle-definition");
  if (vehicleDefinition) {
    const selectedDefinition = vehicleDefinition.value;
    vehicleDefinition.replaceChildren(new Option(state.vehicleCatalog.length ? "选择车辆定义" : "未发现车辆定义", ""));
    state.vehicleCatalog.forEach((vehicle) => vehicleDefinition.add(new Option(vehicle.name || vehicle.label || vehicle.id, vehicle.id)));
    if ([...vehicleDefinition.options].some((option) => option.value === selectedDefinition)) vehicleDefinition.value = selectedDefinition;
    else if (state.vehicleCatalog.length === 1) vehicleDefinition.value = state.vehicleCatalog[0].id;
  }
  const vehicleForm = $("#vehicle-form");
  const canCreateVehicle = true;
  $("#vehicle-definition").disabled = !state.vehicleCatalog.length;
  $("#vehicle-label").disabled = false;
  const createVehicleButton = vehicleForm.querySelector("button[type='submit']");
  createVehicleButton.disabled = !state.vehicleCatalog.length;
  createVehicleButton.title = !state.vehicleCatalog.length ? "暂无本地展示车辆定义" : "创建 3D 展示车辆";
  const capacity = state.vehicleCapacity || {}; const providerDefinition = state.vehicleCatalog.find((vehicle) => String(vehicle.id) === String(vehicleDefinition?.value)) || state.vehicleCatalog[0]; const capacityText = state.vehicleCatalog.length ? `展示模式 · 不依赖 Provider · 当前定义 ${providerDefinition?.name || providerDefinition?.id || "—"}` : "暂无本地展示车辆定义";
  setText("#vehicle-provider-status", capacityText);
  const vehicleSummary = (vehicle) => {
    const scopeID = libraryCompetitionID(vehicle);
    const challengeItems = scopeID === RESOURCE_LIBRARY_ID ? state.libraryChallenges : state.challenges;
    const boundChallenges = challengeItems.filter((challenge) => (challenge.boundVehicleInstanceIds || []).includes(vehicle.id));
    const challengeText = boundChallenges.length ? `已绑定 ${boundChallenges.length} 道题` : "尚未绑定题目";
    return { id: vehicle.id, title: vehicle.label || vehicle.name || vehicle.id, detail: `动作展示载体 · 代次 ${vehicle.generation ?? "—"} · ${challengeText}`, state: "展示车辆", color: "var(--signal-dim)" };
  };
  const renderAssetList = (selector, items, message, map, teamList = false, allowRemove = true) => {
    const container = $(selector); container.replaceChildren(); if (!items.length) { container.append(empty(message)); return; }
    items.forEach((item) => {
      const data = map(item); const row = document.createElement("article"); row.className = `asset-item${teamList ? " has-selection" : ""}`; row.style.setProperty("--item-color", data.color || "var(--signal-dim)"); row.append(document.createElement("i"));
      const copy = document.createElement("div"); const title = document.createElement("strong"); title.textContent = data.title; const detail = document.createElement("small"); detail.textContent = data.detail; copy.append(title, detail);
      const selection = document.createElement("input"); if (teamList) { selection.type = "checkbox"; selection.dataset.teamSelect = item.id; selection.setAttribute("aria-label", `选择队伍 ${data.title}`); row.append(selection); }
      const status = document.createElement("span"); status.textContent = teamList ? (item.status === "offline" ? "已移除" : data.state) : "展示车辆";
      if (!teamList) {
        const actions = document.createElement("div"); actions.className = "asset-item-actions"; actions.append(status);
        if (allowRemove) {
          const remove = document.createElement("button"); remove.type = "button"; remove.className = "user-action asset-delete-action"; remove.dataset.vehicleAction = "remove"; remove.dataset.vehicleId = item.id; remove.textContent = "删除"; remove.title = "删除展示车辆（已绑定题目或已有历史记录时会被拒绝）";
          actions.append(remove);
        }
        row.append(copy, actions); container.append(row); return;
      }
      const actions = document.createElement("div"); actions.className = "asset-item-actions"; actions.append(status);
      if (!allowRemove) { row.append(copy, actions); container.append(row); return; }
      const remove = document.createElement("button"); const teamCompetitionID = item.competitionId || item.competition_id || RESOURCE_LIBRARY_ID; const removalBlocked = teamCompetitionID !== RESOURCE_LIBRARY_ID && state.competition?.status === "live"; remove.type = "button"; remove.className = "user-action asset-delete-action"; remove.dataset.teamAction = "remove"; remove.dataset.teamId = item.id; remove.dataset.teamCompetitionId = teamCompetitionID; remove.textContent = item.status === "offline" ? "已删除" : removalBlocked ? "比赛中" : "物理删除"; remove.disabled = item.status === "offline" || removalBlocked || state.busyTeams.has(item.id); remove.title = removalBlocked ? "比赛进行中不能删除队伍，请先暂停比赛" : "永久删除队伍、成员及其运行记录，无法恢复"; actions.append(remove);
      row.append(copy, actions); container.append(row);
    });
  };
  renderAssetList("#team-list", state.libraryTeams, "平台队伍库为空，请先创建队伍", (team) => ({ title: team.name || team.code || team.id, detail: `组织：${team.organization || team.organization_name || "未填写单位"} · ${team.code || team.id || "—"} · ${number(team.memberCount ?? team.member_count)} 名账号 · ${number(team.score)} 分`, state: "平台资源", color: team.color }), true, true);
  renderAssetList("#vehicle-list", state.libraryVehicles, "平台展示车辆库为空，请先创建车辆", vehicleSummary, false, true);
  renderTeamLibrary();
  renderVehicleLibrary();
  syncBulkDeleteControls();
}

function renderChallengeRows(list, items, vehicles, scopeID, emptyMessage) {
  list.replaceChildren();
  if (!items.length) { list.append(empty(emptyMessage)); return; }
  items.forEach((challenge) => {
    const row = document.createElement("article"); row.className = "asset-item challenge-admin-row"; row.dataset.challengeScope = scopeID; row.append(document.createElement("i"));
    const copy = document.createElement("div"); copy.className = "challenge-admin-copy"; const title = document.createElement("strong"); title.textContent = challenge.title || challenge.slug || challenge.id; const attachmentCount = challengeAttachments(challenge).length; const detail = document.createElement("small"); detail.textContent = `${challenge.slug || challenge.id} · ${String(challenge.runtimeKind || "runtime").toUpperCase()} · ${number(challenge.baseScore)} 分 · ${challengeAccessProtocol(challenge).toUpperCase()} · ${challengeFlagMode(challenge) === "static" ? "静态 Flag" : "动态 Flag"} · ${attachmentCount ? `附件 ${attachmentCount} 个` : "无附件"} · 容器 ${challengeContainerName(challenge) || "—"}`; copy.append(title, detail);
    const actions = document.createElement("div"); actions.className = "challenge-admin-actions"; const status = document.createElement("span"); const published = challenge.status === "published"; status.className = `challenge-status ${published ? "is-published" : "is-draft"}`; status.textContent = published ? "已发布" : "草稿"; actions.append(status);
    const edit = document.createElement("button"); edit.type = "button"; edit.className = "user-action challenge-edit-button"; edit.dataset.editChallenge = challenge.id; edit.textContent = "编辑"; actions.append(edit);
    if (challenge.status === "draft") {
      const publish = document.createElement("button"); publish.type = "button"; publish.className = "user-action"; publish.dataset.publishChallenge = challenge.id; publish.textContent = "发布"; actions.append(publish);
    }
    const remove = document.createElement("button"); remove.type = "button"; remove.className = "user-action asset-delete-action"; remove.dataset.deleteChallenge = challenge.id; remove.textContent = "删除"; remove.title = challenge.status === "draft" ? "删除题目及其附件" : "物理删除题目及其历史记录"; actions.append(remove);
    const binding = document.createElement("div"); binding.className = "challenge-binding-control";
    const select = document.createElement("select"); select.dataset.bindChallengeSelect = challenge.id; select.disabled = !vehicles.length;
    select.append(new Option(vehicles.length ? `选择车辆库车辆（共 ${vehicles.length} 辆）` : "车辆库为空", ""));
    vehicles.forEach((vehicle) => { const option = new Option(vehicleLabel(vehicle), vehicle.id); option.selected = (challenge.boundVehicleInstanceIds || []).includes(vehicle.id); select.add(option); });
    const bind = document.createElement("button"); bind.type = "button"; bind.className = "user-action"; bind.dataset.bindChallenge = challenge.id; bind.textContent = (challenge.boundVehicleInstanceIds || []).length ? "切换车辆" : "绑定车辆"; bind.disabled = !vehicles.length;
    const summary = document.createElement("small"); const bound = (challenge.boundVehicleInstanceIds || []).map((id) => vehicles.find((vehicle) => vehicle.id === id)?.label || id); summary.textContent = bound.length ? `当前绑定：${bound.join("、")}；可从车辆库切换其他车辆。` : "尚未绑定车辆，请从车辆库选择。"; binding.append(select, bind, summary);
    const visual = document.createElement("div"); visual.className = "challenge-visual-control";
    const visualTitle = document.createElement("span"); visualTitle.textContent = "通关动作";
    const selectedActions = new Set(challengeVisualActions(challenge));
    const options = document.createElement("div"); options.className = "challenge-visual-options";
    VISUAL_ACTION_OPTIONS.forEach((action) => { const label = document.createElement("label"); label.className = "challenge-visual-option"; const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.dataset.visualAction = action.id; checkbox.dataset.visualChallenge = challenge.id; checkbox.checked = selectedActions.has(action.id) || (action.id === "door-front-left-open" && selectedActions.has("door-open")); label.append(checkbox, document.createTextNode(action.label)); options.append(label); });
    const saveVisual = document.createElement("button"); saveVisual.type = "button"; saveVisual.className = "user-action"; saveVisual.dataset.saveVisualActions = challenge.id; saveVisual.textContent = "保存动作";
    const visualSummary = document.createElement("small"); visualSummary.textContent = selectedActions.size ? `已配置：${[...selectedActions].join("、")}` : "默认只播放通关扫描；勾选后提交成功会触发车辆动作。";
    visual.append(visualTitle, options, saveVisual, visualSummary);
    row.style.setProperty("--item-color", published ? "var(--signal)" : "var(--amber)"); row.append(copy, binding, visual, actions); list.append(row);
  });
}

function challengePageNumbers(currentPage, totalPages) {
  if (totalPages <= 7) return Array.from({ length: totalPages }, (_, index) => index + 1);
  const pages = new Set([1, totalPages, currentPage - 1, currentPage, currentPage + 1]);
  const sorted = [...pages].filter((page) => page >= 1 && page <= totalPages).sort((a, b) => a - b);
  const result = [];
  sorted.forEach((page, index) => {
    if (index && page - sorted[index - 1] > 1) result.push("ellipsis");
    result.push(page);
  });
  return result;
}

function renderChallengePagination(totalItems) {
  const pagination = $("#challenge-pagination");
  if (!pagination) return;
  const totalPages = Math.max(1, Math.ceil(totalItems / CHALLENGE_LIBRARY_PAGE_SIZE));
  state.challengeLibraryPage = Math.min(Math.max(Number(state.challengeLibraryPage) || 1, 1), totalPages);
  const start = totalItems ? (state.challengeLibraryPage - 1) * CHALLENGE_LIBRARY_PAGE_SIZE + 1 : 0;
  const end = Math.min(state.challengeLibraryPage * CHALLENGE_LIBRARY_PAGE_SIZE, totalItems);
  const summary = document.createElement("span"); summary.className = "challenge-page-summary";
  summary.textContent = totalItems
    ? `第 ${start}–${end} 题 / 共 ${totalItems} 题 · 每页 ${CHALLENGE_LIBRARY_PAGE_SIZE} 题`
    : `共 0 题 · 每页 ${CHALLENGE_LIBRARY_PAGE_SIZE} 题`;
  const controls = document.createElement("div"); controls.className = "challenge-page-controls";
  const addButton = (label, page, { current = false, disabled = false, ariaLabel = "" } = {}) => {
    const button = document.createElement("button"); button.type = "button"; button.dataset.challengePage = String(page); button.textContent = label; button.disabled = disabled;
    if (current) { button.classList.add("is-current"); button.setAttribute("aria-current", "page"); }
    if (ariaLabel) button.setAttribute("aria-label", ariaLabel);
    controls.append(button);
  };
  addButton("上一页", state.challengeLibraryPage - 1, { disabled: state.challengeLibraryPage === 1, ariaLabel: "上一页" });
  challengePageNumbers(state.challengeLibraryPage, totalPages).forEach((page) => {
    if (page === "ellipsis") {
      const ellipsis = document.createElement("span"); ellipsis.className = "challenge-page-ellipsis"; ellipsis.textContent = "…"; ellipsis.setAttribute("aria-hidden", "true"); controls.append(ellipsis); return;
    }
    addButton(String(page), page, { current: page === state.challengeLibraryPage, ariaLabel: `第 ${page} 页` });
  });
  addButton("下一页", state.challengeLibraryPage + 1, { disabled: state.challengeLibraryPage === totalPages, ariaLabel: "下一页" });
  pagination.replaceChildren(summary, controls);
}

function renderChallenges() {
  const libraryItems = state.libraryChallenges;
  const totalPages = Math.max(1, Math.ceil(libraryItems.length / CHALLENGE_LIBRARY_PAGE_SIZE));
  state.challengeLibraryPage = Math.min(Math.max(Number(state.challengeLibraryPage) || 1, 1), totalPages);
  const pageStart = (state.challengeLibraryPage - 1) * CHALLENGE_LIBRARY_PAGE_SIZE;
  const pageItems = libraryItems.slice(pageStart, pageStart + CHALLENGE_LIBRARY_PAGE_SIZE);
  setText("#challenge-total", libraryItems.length);
  const libraryList = $("#challenge-library-list");
  setText("#challenge-library-total", libraryItems.length);
  if (libraryList) renderChallengeRows(libraryList, libraryItems, state.libraryVehicles, RESOURCE_LIBRARY_ID, "题目库为空，请先新建题目或导入 CARPACK");
  renderChallengeRows($("#challenge-admin-list"), pageItems, state.libraryVehicles, RESOURCE_LIBRARY_ID, "平台题目库为空，请先新建题目或导入 CARPACK");
  renderChallengePagination(libraryItems.length);
  const importButton = $("#import-carpack"); importButton.disabled = !$("#carpack-file").files?.length;
  const newButton = $("#new-challenge-button"); if (newButton) newButton.disabled = false;
}

function renderAudit() {
  document.querySelectorAll("[data-audit-view]").forEach((button) => button.classList.toggle("is-active", button.dataset.auditView === state.auditView));
  const actionField = $("#audit-filter-action");
  const statusField = $("#audit-filter-status");
  if (actionField) actionField.placeholder = state.auditView === "access" ? "/api/v1/..." : "challenge.run.start";
  if (statusField) statusField.placeholder = state.auditView === "access" ? "200 / 403 / 500" : "success / denied / failure";
  const container = $("#audit-list");
  container.replaceChildren();
  if (state.auditView === "access") {
    if (!state.accessAudit.length) { container.append(empty("尚无 API 访问记录")); return; }
    state.accessAudit.forEach((item) => {
      const row = document.createElement("article");
      row.className = "audit-item";
      const actor = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = item.username || item.actorUsername || "未知账号";
      const small = document.createElement("small");
      small.textContent = [item.teamName || item.teamId, item.role].filter(Boolean).join(" · ") || "未关联队伍";
      actor.append(strong, small);
      const description = document.createElement("p");
      description.textContent = `${item.method || "GET"} ${item.path || "—"} · HTTP ${item.status ?? "—"} · ${item.durationMs ?? 0}ms`;
      const address = document.createElement("span");
      address.textContent = item.remoteIp || "内部节点";
      const time = document.createElement("time");
      time.dateTime = item.createdAt || "";
      time.textContent = formatDate(time.dateTime);
      const detail = document.createElement("button");
      detail.type = "button";
      detail.className = "user-action audit-detail-action";
      detail.dataset.auditDetail = "true";
      detail.dataset.auditView = "access";
      detail.dataset.auditSequence = item.sequence ?? "";
      detail.textContent = "详细信息";
      row.append(actor, description, address, time, detail);
      container.append(row);
    });
    return;
  }
  if (!state.audit.length) { container.append(empty("尚无审计记录")); return; }
  state.audit.forEach((item) => {
    const row = document.createElement("article");
    row.className = "audit-item";
    const actor = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = auditActor(item);
    const small = document.createElement("small");
    small.textContent = auditAction(item);
    actor.append(strong, small);
    const description = document.createElement("p");
    description.textContent = auditDescription(item);
    const address = document.createElement("span");
    address.textContent = auditRemote(item);
    const time = document.createElement("time");
    time.dateTime = auditTime(item);
    time.textContent = formatDate(time.dateTime);
    const detail = document.createElement("button");
    detail.type = "button";
    detail.className = "user-action audit-detail-action";
    detail.dataset.auditDetail = "true";
    detail.dataset.auditView = "operations";
    detail.dataset.auditSequence = item.sequence ?? "";
    detail.textContent = "详细信息";
    row.append(actor, description, address, time, detail);
    container.append(row);
  });
}

function syncDockerSettingsFields({ clearLocal = false } = {}) {
  const mode = $("#docker-mode")?.value || "local";
  const remote = mode === "remote";
  const selectors = ["#docker-host", "#docker-bind-address", "#docker-access-host", "#docker-tls-verify", "#docker-cert-path"];
  if (!remote && clearLocal) {
    selectors.forEach((selector) => {
      const node = $(selector);
      if (!node) return;
      if (node.type === "checkbox") node.checked = false;
      else node.value = "";
    });
  }
  selectors.forEach((selector) => {
    const node = $(selector);
    if (!node) return;
    node.disabled = !remote;
    node.closest(".field")?.classList.toggle("is-disabled", !remote);
  });
}

function renderSystemSettings() {
  const settings = state.systemSettings || {};
  const first = valueOf(settings, "challengePortFirst", "challenge_port_first");
  const last = valueOf(settings, "challengePortLast", "challenge_port_last");
  if (first !== undefined) $("#challenge-port-first").value = first;
  if (last !== undefined) $("#challenge-port-last").value = last;
  const dockerMode = valueOf(settings, "dockerMode", "docker_mode") || "local";
  $("#docker-mode").value = dockerMode;
  $("#docker-host").value = valueOf(settings, "dockerHost", "docker_host") || "";
  $("#docker-bind-address").value = valueOf(settings, "dockerBindAddress", "docker_bind_address") || "";
  $("#docker-access-host").value = valueOf(settings, "dockerAccessHost", "docker_access_host") || "";
  $("#docker-tls-verify").checked = Boolean(valueOf(settings, "dockerTLSVerify", "docker_tls_verify"));
  $("#docker-cert-path").value = valueOf(settings, "dockerCertPath", "docker_cert_path") || "";
  syncDockerSettingsFields();
  if (first !== undefined && last !== undefined) setText("#system-settings-note", `当前范围 ${first}–${last}，共 ${number(last) - number(first) + 1} 个端口；${dockerMode === "remote" ? "新题目将在远程 Docker 节点启动。" : "新实例将在本机 Docker 中启动。"}`);
}

function renderAttackDesktop() {
  const panel = $("#attack-desktop-empty");
  const content = $("#attack-desktop-content");
  const data = state.attackDesktop?.desktop || state.attackDesktop;
  if (!data) {
    if (panel) { panel.hidden = false; panel.textContent = "自建攻击机 Provider 未启用；选手端不会受到影响。"; }
    if (content) content.hidden = true;
    return;
  }
  if (panel) panel.hidden = true;
  if (content) content.hidden = false;
  setText("#kasmvnc-provider", data.provider || "—");
  setText("#kasmvnc-image", data.image || "—");
  setText("#kasmvnc-network", data.network || "—");
  setText("#kasmvnc-active", `${number(data.active)} 个`);
  setText("#kasmvnc-port-range", `${data.portFirst || "—"}–${data.portLast || "—"}`);
  setText("#kasmvnc-concurrency", `${number(data.startConcurrency)} 个并发槽位`);
  setText("#kasmvnc-quotas", `单用户 ${number(data.maxPerUser)} · 单队伍 ${number(data.maxPerTeam)} · 单赛事 ${number(data.maxPerCompetition)}`);
  const list = $("#kasmvnc-session-list");
  if (!list) return;
  list.replaceChildren();
  const sessions = Array.isArray(data.sessions) ? data.sessions : [];
  if (!sessions.length) { const empty = document.createElement("div"); empty.className = "empty-state"; empty.textContent = "当前没有活动攻击机桌面。"; list.append(empty); return; }
  sessions.sort((a, b) => String(a.expiresAt || "").localeCompare(String(b.expiresAt || "")));
  sessions.forEach((session) => {
    const row = document.createElement("article"); row.className = "asset-item attack-session-row";
    row.style.display = "grid";
    row.style.gridTemplateColumns = "280px minmax(300px, 1fr) 250px max-content";
    row.style.columnGap = "28px";
    row.style.minWidth = "920px";
    const copy = document.createElement("div"); copy.className = "attack-session-id";
    const title = document.createElement("strong"); title.textContent = session.sessionId || "未命名会话";
    const user = state.users.find((item) => String(item.id || item.username) === String(session.userId));
    const member = user ? `${userName(user)} · ${user.username || session.userId}` : (session.userId || "未知成员");
    const teamID = userTeamID(user || {});
    const teamName = user ? userTeamLabel(user) : (session.teamName || session.team_name || teamID || "未知队伍");
    const scope = document.createElement("small"); scope.className = "attack-session-scope"; scope.textContent = `成员：${member} · 队伍：${teamName}`;
    scope.style.cssText = "display:block;min-width:0;color:var(--text);font:560 11px/1.4 var(--mono);white-space:nowrap;";
    copy.append(title);
    const meta = document.createElement("small"); meta.className = "attack-session-meta"; meta.textContent = `${session.status || "—"} · 端口 ${session.port || "—"} · 到期 ${formatDateTime(session.expiresAt)}`;
    meta.style.cssText = "display:block;min-width:0;color:var(--text);font:560 11px/1.4 var(--mono);text-align:right;white-space:nowrap;";
    const access = document.createElement("button"); access.type = "button"; access.className = "secondary-button attack-session-access"; access.textContent = "管理员进入";
    access.addEventListener("click", async () => {
      access.disabled = true;
      try { const result = await request(`/api/v1/admin/attack-desktop/sessions/${encodeURIComponent(session.sessionId)}/access`, { method: "POST" }); window.open(result.url, "_blank", "noopener"); }
      catch (error) { showToast(`管理员桌面链接签发失败：${error.message}`, true); }
      finally { access.disabled = false; }
    });
    row.append(copy, scope, meta, access); list.append(row);
  });
}

function isVehicleRangeMode(mode = state.competition?.mode) { return String(mode || "").toLowerCase() === "vehicle_range"; }
function isAttackDesktopMode(mode = state.competition?.mode) { return String(mode || "").toLowerCase() === "attack" || isVehicleRangeMode(mode); }

function vehicleRangeScopeLabel(instance) {
  const team = [...state.teams, ...state.libraryTeams].find((item) => String(item.id) === String(instance.team_id || instance.teamId));
  const teamLabel = team?.name || instance.team_name || instance.teamName || instance.team_id || instance.teamId || "未关联队伍";
  if (String(instance.scope_mode || instance.scopeMode) !== "individual") return `团队靶场 · ${teamLabel}`;
  const user = state.users.find((item) => String(item.id) === String(instance.scope_id || instance.scopeId));
  const userLabel = user ? userName(user) : instance.scope_id || instance.scopeId || "未关联选手";
  return `个人靶场 · ${userLabel} · ${teamLabel}`;
}

function vehicleRangeInstanceStatusLabel(value) {
  const status = String(value || "unknown").toLowerCase();
  return ({
    provisioning: "编排中",
    active: "运行中",
    pausing: "暂停中",
    paused: "已暂停",
    resuming: "恢复中",
    resetting: "重置中",
    stopping: "停止中",
    stopped: "已停止",
    failed: "异常",
  })[status] || status;
}

function renderVehicleRangeInstances(instances, locked) {
  const list = $("#vehicle-range-instance-list");
  if (!list) return;
  list.replaceChildren();
  if (!instances.length) {
    const empty = document.createElement("p"); empty.className = "vehicle-range-instance-empty"; empty.textContent = "尚无靶场实例。选手启动攻击机后，在比赛端启动整车靶场即可在此查看运行状态。"; list.append(empty); return;
  }
  instances.forEach((instance) => {
    const row = document.createElement("article"); row.className = "vehicle-range-instance-row";
    const identity = document.createElement("div"); const id = document.createElement("strong"); id.textContent = instance.id || "未知实例"; const scope = document.createElement("small"); scope.textContent = vehicleRangeScopeLabel(instance); identity.append(id, scope);
    const runtime = document.createElement("div"); const status = document.createElement("strong"); status.className = "vehicle-range-instance-state"; status.textContent = `${vehicleRangeInstanceStatusLabel(instance.status)} · G${instance.generation || "—"}`; const template = document.createElement("small"); template.textContent = instance.template?.title || instance.template?.slug || instance.template_id || instance.templateId || "未读取到模板"; runtime.append(status, template);
    const activity = document.createElement("div"); const nodes = Array.isArray(instance.nodes) ? instance.nodes : []; const activeNodes = nodes.filter((node) => String(node.status || "").toLowerCase() === "running").length; const activityTitle = document.createElement("strong"); activityTitle.textContent = `${activeNodes} / ${nodes.length} 个节点运行`; const activityTime = document.createElement("small"); activityTime.textContent = `最近活动 ${formatDateTime(instance.last_activity_at || instance.lastActivityAt || instance.updated_at || instance.updatedAt)}`; activity.append(activityTitle, activityTime);
    const actions = document.createElement("div"); actions.className = "vehicle-range-instance-actions";
    const instanceID = instance.id || "";
    const currentStatus = String(instance.status || "").toLowerCase();
    const addAction = (action, label, className = "secondary-button", disabled = false) => {
      const button = document.createElement("button"); button.type = "button"; button.className = className; button.dataset.vehicleRangeInstanceAction = action; button.dataset.vehicleRangeInstance = instanceID; button.textContent = label; button.disabled = locked || disabled; actions.append(button); return button;
    };
    if (currentStatus === "active") addAction("pause", "暂停靶场");
    if (currentStatus === "paused") {
      addAction("resume", "恢复运行");
      addAction("snapshot", "保存阶段快照");
      const snapshots = Array.isArray(instance.snapshots) ? instance.snapshots : [];
      const select = document.createElement("select"); select.className = "vehicle-range-snapshot-select"; select.dataset.vehicleRangeSnapshotSelect = instanceID;
      select.append(new Option(snapshots.length ? "选择可恢复快照" : "暂无可恢复快照", ""));
      snapshots.forEach((snapshot) => {
        const label = snapshot.label || `G${snapshot.source_generation || snapshot.sourceGeneration || "—"} 阶段快照`;
        select.append(new Option(`${label} · ${snapshot.checkpoint_count || snapshot.checkpointCount || 0} 阶段`, snapshot.id));
      });
      select.disabled = locked || !snapshots.length;
      actions.append(select);
      addAction("restore", "恢复所选快照", "danger-button", !snapshots.length);
    }
    const resettable = ["active", "paused", "failed", "stopped"].includes(currentStatus);
    const reset = addAction("reset", "重置靶场", "secondary-button", !resettable);
    if (!resettable) reset.title = "实例处于编排中，完成当前启动、停止或重置后才能再次重置。";
    row.append(identity, runtime, activity, actions); list.append(row);
  });
}

function renderVehicleRangeSettings() {
  const panel = $("#vehicle-range-settings");
  if (!panel) return;
  const enabled = isVehicleRangeMode();
  panel.hidden = !enabled;
  if (!enabled) return;
  const settings = state.vehicleRangeSettings || {};
  const templateSelect = $("#competition-range-template");
  const selected = String(settings.template_id || settings.templateId || "");
  const published = (state.vehicleRangeTemplates || []).filter((item) => item.status === "published");
  if (templateSelect) {
    templateSelect.replaceChildren(new Option(published.length ? "选择已发布靶场模板" : "暂无已发布靶场模板", ""));
    published.forEach((template) => templateSelect.add(new Option(`${template.title || template.slug} / V${template.version} · ${template.nodes?.length || 0} 节点`, template.id)));
    templateSelect.value = published.some((template) => String(template.id) === selected) ? selected : "";
  }
  const scope = $("#competition-range-scope"); if (scope) scope.value = settings.scope_mode || settings.scopeMode || "team";
  const capacity = $("#competition-range-capacity"); if (capacity) capacity.value = Number(settings.max_active_instances || settings.maxActiveInstances || 100);
  const reset = $("#competition-range-reset"); if (reset) reset.checked = settings.allow_self_reset !== false && settings.allowSelfReset !== false;
  const instances = Array.isArray(state.vehicleRangeInstances) ? state.vehicleRangeInstances : [];
  const active = instances.filter((item) => ["provisioning", "active", "resetting", "stopping"].includes(String(item.status || "").toLowerCase())).length;
  setText("#vehicle-range-instance-summary", `${active} 运行中 / ${instances.length} 个实例记录`);
  const locked = state.competition?.status === "finished";
  renderVehicleRangeInstances(instances, locked);
  panel.querySelectorAll("input,select,button").forEach((node) => { node.disabled = locked; });
}

function renderVehicleRangeTemplates() {
  const items = Array.isArray(state.vehicleRangeTemplates) ? state.vehicleRangeTemplates : [];
  setText("#vehicle-range-template-total", items.length);
  const list = $("#vehicle-range-template-list");
  if (list) {
    list.replaceChildren();
    if (!items.length) {
      const empty = document.createElement("div"); empty.className = "empty-state"; empty.textContent = "尚未创建靶场模板。先保存草稿，确认节点镜像与阶段后再发布。"; list.append(empty);
    }
    items.forEach((template) => {
      const templateStatus = String(template.status || "").toLowerCase();
      const statusInfo = templateStatus === "published"
        ? { label: "已发布", className: "is-published", color: "var(--signal)" }
        : templateStatus === "draft"
          ? { label: "草稿", className: "is-draft", color: "var(--amber)" }
          : templateStatus === "retired"
            ? { label: "已归档", className: "is-retired", color: "var(--faint)" }
            : { label: "状态异常", className: "is-retired", color: "var(--danger)" };
      const row = document.createElement("article"); row.className = "asset-item vehicle-range-template-row"; row.style.setProperty("--item-color", statusInfo.color);
      const marker = document.createElement("i");
      const copy = document.createElement("div"); copy.className = "challenge-admin-copy";
      const title = document.createElement("strong"); title.textContent = `${template.title || template.slug || "未命名模板"} / V${template.version || 1}`;
      const nodes = Array.isArray(template.nodes) ? template.nodes : [];
      const buses = Array.isArray(template.buses) ? template.buses : [];
      const stages = Array.isArray(template.stages) ? template.stages : [];
      const detail = document.createElement("small"); detail.textContent = `${template.slug || "—"} · ${nodes.length} 节点 · ${buses.length} 条总线 · ${stages.length} 个阶段`;
      copy.append(title, detail);
      const status = document.createElement("span"); status.className = `challenge-status ${statusInfo.className}`; status.textContent = statusInfo.label;
      const actions = document.createElement("div"); actions.className = "challenge-admin-actions";
      const view = document.createElement("button"); view.type = "button"; view.className = "user-action"; view.dataset.viewVehicleRangeTemplate = template.id; view.textContent = "查看拓扑";
      const edit = document.createElement("button"); edit.type = "button"; edit.className = "user-action"; edit.dataset.editVehicleRangeTemplate = template.id; edit.textContent = "编辑";
      actions.append(view, edit);
      if (templateStatus === "draft") {
        const publish = document.createElement("button"); publish.type = "button"; publish.className = "user-action"; publish.dataset.publishVehicleRangeTemplate = template.id; publish.textContent = "发布";
        const remove = document.createElement("button"); remove.type = "button"; remove.className = "user-action asset-delete-action"; remove.dataset.deleteVehicleRangeTemplate = template.id; remove.textContent = "删除草稿";
        actions.append(publish, remove);
      } else if (templateStatus === "retired") {
        const remove = document.createElement("button"); remove.type = "button"; remove.className = "user-action asset-delete-action"; remove.dataset.deleteVehicleRangeTemplate = template.id; remove.title = "永久删除模板及其赛事引用、历史实例和阶段得分"; remove.textContent = "物理删除";
        actions.append(remove);
      } else if (templateStatus === "published") {
        const remove = document.createElement("button"); remove.type = "button"; remove.className = "user-action asset-delete-action"; remove.dataset.deleteVehicleRangeTemplate = template.id; remove.title = "永久删除模板及其赛事引用、历史实例和阶段得分"; remove.textContent = "物理删除";
        actions.append(remove);
      } else {
        const immutable = document.createElement("small"); immutable.textContent = "模板状态异常，已禁止操作"; actions.append(immutable);
      }
      row.append(marker, copy, status, actions); list.append(row);
    });
  }
  const select = $("#competition-create-range-template");
  if (select) {
    const selected = select.value;
    const published = items.filter((item) => item.status === "published");
    select.replaceChildren(new Option(published.length ? "选择已发布靶场模板" : "尚无已发布靶场模板", ""));
    published.forEach((template) => select.add(new Option(`${template.title || template.slug} / V${template.version} · ${template.nodes?.length || 0} 节点`, template.id)));
    select.value = published.some((item) => item.id === selected) ? selected : "";
  }
}

function formatAssetBytes(value) {
  const bytes = Math.max(0, number(value));
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function renderVehicleRangeDBCAssets() {
  const items = Array.isArray(state.vehicleRangeDBCAssets) ? state.vehicleRangeDBCAssets : [];
  setText("#vehicle-range-dbc-total", items.length);
  const list = $("#vehicle-range-dbc-list");
  if (!list) return;
  list.replaceChildren();
  if (!items.length) {
    const empty = document.createElement("div"); empty.className = "empty-state"; empty.textContent = "尚未上传 DBC 信号包。模板中的 dbc_digest 只能引用已校验的文件指纹。"; list.append(empty); return;
  }
  items.forEach((item) => {
    const row = document.createElement("article"); row.className = "asset-item vehicle-range-dbc-row";
    const marker = document.createElement("i"); marker.style.background = "var(--signal)";
    const copy = document.createElement("div"); copy.className = "challenge-admin-copy";
    const title = document.createElement("strong"); title.textContent = item.filename || "未命名 DBC";
    const digest = document.createElement("small"); digest.textContent = item.digest || "—";
    copy.append(title, digest);
    const meta = document.createElement("small"); meta.className = "vehicle-range-dbc-meta"; meta.textContent = `${number(item.frame_count || item.frameCount)} 帧 · ${formatAssetBytes(item.size_bytes || item.sizeBytes)} · ${formatDateTime(item.created_at || item.createdAt)}`;
    const copyDigest = document.createElement("button"); copyDigest.type = "button"; copyDigest.className = "user-action"; copyDigest.dataset.copyVehicleRangeDbc = item.digest || ""; copyDigest.textContent = "复制指纹";
    row.append(marker, copy, meta, copyDigest); list.append(row);
  });
}

function rangeEditorState() {
  if (!state.vehicleRangeEditor) state.vehicleRangeEditor = { nodes: [], buses: [], stages: [], selected: null, drag: null };
  return state.vehicleRangeEditor;
}

function rangeIdentifier(value, fallback = "node") {
  const normalized = String(value || "").toLowerCase().trim().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").replace(/-+/g, "-");
  return normalized || fallback;
}

function rangeUniqueKey(items, prefix) {
  const existing = new Set(items.map((item) => String(item.key || "").toLowerCase()));
  let index = 1;
  while (existing.has(`${prefix}-${index}`)) index += 1;
  return `${prefix}-${index}`;
}

function rangeClampedPosition(position, fallbackIndex = 0) {
  const column = fallbackIndex % 3; const row = Math.floor(fallbackIndex / 3);
  const fallback = { x: 6 + column * 29, y: 8 + (row % 3) * 22 };
  const source = position && typeof position === "object" ? position : fallback;
  return { x: Math.max(1, Math.min(75, number(source.x, fallback.x))), y: Math.max(3, Math.min(69, number(source.y, fallback.y))) };
}

function rangeCanvasMinHeight(editor) {
  const highestNode = editor.nodes.reduce((highest, node, index) => Math.max(highest, rangeClampedPosition(node.__position, index).y), 0);
  const busRows = Math.max(1, Math.ceil(editor.buses.length / 4));
  const busArea = 78 + busRows * 38;
  const nodeArea = Math.ceil(104 / Math.max(0.24, 1 - highestNode / 100));
  return Math.min(620, Math.max(480, nodeArea + busArea + 12));
}

function rangeTopologyFrom(value) {
  const raw = value && typeof value === "object" ? value : {};
  const nodes = (Array.isArray(raw.nodes) ? raw.nodes : []).map((source, index) => {
    const node = { ...source };
    node.runtime_kind = String(valueOf(source, "runtime_kind", "runtimeKind") || "container");
    node.visual_type = String(valueOf(source, "visual_type", "visualType") || "");
    node.image_ref = String(valueOf(source, "image_ref", "imageRef") || "");
    node.artifact_digest = String(valueOf(source, "artifact_digest", "artifactDigest") || "");
    node.artifact_storage_path = String(valueOf(source, "artifact_storage_path", "artifactStoragePath") || "");
    node.entry_port = number(valueOf(source, "entry_port", "entryPort"), 8080);
    node.ports = (Array.isArray(source.ports) ? source.ports : []).map((port) => number(port, 0)).filter(Boolean);
    node.vcpus = number(source.vcpus, 1);
    node.memory_mb = number(valueOf(source, "memory_mb", "memoryMB"), node.runtime_kind === "qemu-microvm" ? 1024 : 256);
    node.start_order = number(valueOf(source, "start_order", "startOrder"), (index + 1) * 10);
    node.network_alias = String(valueOf(source, "network_alias", "networkAlias") || node.key || "");
    node.bus_keys = (Array.isArray(valueOf(source, "bus_keys", "busKeys")) ? valueOf(source, "bus_keys", "busKeys") : []).map((key) => String(key || "").trim()).filter(Boolean);
    node.chain_authority = Boolean(valueOf(source, "chain_authority", "chainAuthority"));
    node.reporter = Boolean(source.reporter);
    node.environment = source.environment && typeof source.environment === "object" && !Array.isArray(source.environment) ? { ...source.environment } : {};
    node.__position = rangeClampedPosition(source.__position, index);
    return node;
  });
  const buses = (Array.isArray(raw.buses) ? raw.buses : []).map((source) => ({
    ...source, key: String(source.key || ""), label: String(source.label || ""), kind: String(source.kind || "can"), bitrate: number(source.bitrate, 500000), fd_enabled: Boolean(valueOf(source, "fd_enabled", "fdEnabled")), dbc_digest: String(valueOf(source, "dbc_digest", "dbcDigest") || ""),
  }));
  const stages = (Array.isArray(raw.stages) ? raw.stages : []).map((source, index) => ({
    ...source, key: String(source.key || ""), title: String(source.title || ""), description: String(source.description || ""), order: number(source.order, index + 1), score: number(source.score, 100),
    visual_node_key: String(valueOf(source, "visual_node_key", "visualNodeKey") || ""),
    visual_actions: (Array.isArray(valueOf(source, "visual_actions", "visualActions")) ? valueOf(source, "visual_actions", "visualActions") : []).map((action) => String(action || "").trim()).filter(Boolean),
  }));
  return { nodes, buses, stages, selected: null, drag: null };
}

function rangeTopologyForSave() {
  const editor = rangeEditorState();
  return {
    nodes: editor.nodes.map(({ __position, runtimeKind, visualType, imageRef, artifactDigest, artifactStoragePath, entryPort, memoryMB, startOrder, networkAlias, busKeys, chainAuthority, ...node }) => ({
      ...node,
      runtime_kind: String(node.runtime_kind || runtimeKind || "container"),
      visual_type: String(node.visual_type || visualType || ""),
      image_ref: String(node.image_ref || imageRef || ""),
      artifact_digest: String(node.artifact_digest || artifactDigest || ""),
      artifact_storage_path: String(node.artifact_storage_path || artifactStoragePath || ""),
      entry_port: number(node.entry_port ?? entryPort, 0),
      ports: Array.from(new Set((Array.isArray(node.ports) ? node.ports : []).map((port) => number(port, 0)).filter(Boolean))).sort((a, b) => a - b),
      vcpus: number(node.vcpus, 1), memory_mb: number(node.memory_mb ?? memoryMB, 256), start_order: number(node.start_order ?? startOrder, 1),
      network_alias: String(node.network_alias || networkAlias || node.key || ""),
      bus_keys: Array.from(new Set((Array.isArray(node.bus_keys) ? node.bus_keys : busKeys || []).map((key) => String(key || "").trim()).filter(Boolean))).sort(),
      chain_authority: Boolean(node.chain_authority ?? chainAuthority), reporter: Boolean(node.reporter),
      environment: node.environment && typeof node.environment === "object" && !Array.isArray(node.environment) ? node.environment : {},
    })),
    buses: editor.buses.map(({ fdEnabled, dbcDigest, ...bus }) => ({ ...bus, key: String(bus.key || ""), label: String(bus.label || ""), kind: String(bus.kind || "can"), bitrate: number(bus.bitrate, 0), fd_enabled: Boolean(bus.fd_enabled ?? fdEnabled), dbc_digest: String(bus.dbc_digest || dbcDigest || "") })),
    stages: editor.stages.map(({ visualNodeKey, visualActions, ...stage }, index) => ({
      ...stage, key: String(stage.key || ""), title: String(stage.title || ""), description: String(stage.description || ""), order: number(stage.order, index + 1), score: number(stage.score, 0),
      visual_node_key: String(stage.visual_node_key || visualNodeKey || ""),
      visual_actions: Array.from(new Set((Array.isArray(stage.visual_actions) ? stage.visual_actions : visualActions || []).map((action) => String(action || "").trim()).filter(Boolean))),
    })),
  };
}

function rangeSyncTopologyJSON() {
  const input = $("#vehicle-range-template-topology");
  if (input) input.value = JSON.stringify(rangeTopologyForSave(), null, 2);
}

function rangeSelectedItem() {
  const selected = rangeEditorState().selected;
  if (!selected) return null;
  const items = selected.type === "bus" ? rangeEditorState().buses : rangeEditorState().nodes;
  const item = items.find((entry) => entry.key === selected.key);
  return item ? { ...selected, item } : null;
}

function rangeSetSelected(type, key) {
  const editor = rangeEditorState();
  editor.selected = type && key ? { type, key } : null;
  renderRangeTopologyEditor();
}

function vehicleRangeTemplateIsReadOnly() { return Boolean(state.viewingVehicleRangeTemplate); }

function syncVehicleRangeTemplateEditorMode() {
  const form = $("#vehicle-range-template-form");
  const template = state.viewingVehicleRangeTemplate;
  const readOnly = Boolean(template);
  if (form) {
    form.classList.toggle("is-template-readonly", readOnly);
    form.querySelectorAll("input, textarea, select, button").forEach((control) => { control.disabled = readOnly; });
  }
  const banner = $("#vehicle-range-template-view-banner");
  if (banner) banner.hidden = !readOnly;
  if (!readOnly) return;
  const nodes = Array.isArray(template.nodes) ? template.nodes.length : 0;
  const buses = Array.isArray(template.buses) ? template.buses.length : 0;
  const stages = Array.isArray(template.stages) ? template.stages.length : 0;
  setText("#vehicle-range-template-view-title", `${template.title || template.slug || "未命名模板"} / V${template.version || 1}`);
  setText("#vehicle-range-template-view-meta", `${template.status === "published" ? "已发布" : template.status === "retired" ? "已归档" : "草稿"} · ${nodes} 节点 · ${buses} 条总线 · ${stages} 个阶段 · 此处仅查看；点击“编辑”可修改。`);
}

function rangeImageLabel(image) {
  const reference = image?.reference || (image?.repository && image.repository !== "<none>" ? `${image.repository}${image.tag && image.tag !== "<none>" ? `:${image.tag}` : ""}` : image?.id);
  return `${reference || "未命名镜像"} · ${String(image?.id || "").slice(0, 19)}`;
}

function rangeDefaultNode(runtimeKind, position) {
  const editor = rangeEditorState();
  const isKVM = runtimeKind === "qemu-microvm";
  const key = rangeUniqueKey(editor.nodes, isKVM ? "ecu" : "service");
  const image = state.localImages[0] || null;
  const artifact = state.kvmArtifacts[0] || null;
  const imagePorts = imageExposedPorts(image).filter((item) => item.protocol === "tcp");
  const entryPort = isKVM ? number(artifact?.entryPort, 8080) : number(imagePorts[0]?.port, 8080);
  const artifactDigest = String(artifact?.digest || "");
  return {
    key, label: isKVM ? `ECU 微虚拟机 ${editor.nodes.length + 1}` : `Docker 服务 ${editor.nodes.length + 1}`,
    visual_type: isKVM ? "ecu" : "", runtime_kind: runtimeKind, image_ref: isKVM ? "" : String(image?.id || ""), artifact_digest: isKVM ? artifactDigest : "",
    artifact_storage_path: isKVM && artifactDigest.startsWith("sha256:") ? artifactDigest.slice(7) : "",
    entry_port: entryPort, ports: [entryPort], vcpus: isKVM ? number(artifact?.vcpus, 1) : 1,
    memory_mb: isKVM ? number(artifact?.memoryMiB, 1024) : 256, start_order: (editor.nodes.length + 1) * 10,
    network_alias: key, bus_keys: [], chain_authority: false, reporter: false, environment: {},
    __position: rangeClampedPosition(position, editor.nodes.length),
  };
}

function rangeBusDefaults(kind) {
  const editor = rangeEditorState();
  const spec = {
    ethernet: { key: "ethernet", label: "车载以太网", bitrate: 100000000 }, doip: { key: "doip", label: "DoIP 诊断域", bitrate: 100000000 },
    can: { key: "can", label: "CAN 总线", bitrate: 500000 }, canfd: { key: "canfd", label: "CAN-FD 总线", bitrate: 2000000 },
  }[kind] || { key: "can", label: "CAN 总线", bitrate: 500000 };
  const key = editor.buses.some((bus) => bus.key === spec.key) ? rangeUniqueKey(editor.buses, spec.key) : spec.key;
  return { key, label: spec.label, kind, bitrate: spec.bitrate, fd_enabled: kind === "canfd", dbc_digest: "" };
}

function rangeAddNode(runtimeKind, position) {
  if (vehicleRangeTemplateIsReadOnly()) return;
  const editor = rangeEditorState(); const node = rangeDefaultNode(runtimeKind, position); editor.nodes.push(node);
  editor.selected = { type: "node", key: node.key }; renderRangeTopologyEditor();
}

function rangeAddBus(kind) {
  if (vehicleRangeTemplateIsReadOnly()) return;
  const editor = rangeEditorState();
  if (editor.buses.length >= 16) { showSectionError("#vehicle-range-message", "一个靶场模板最多可配置 16 条逻辑总线。"); return; }
  const bus = rangeBusDefaults(kind); editor.buses.push(bus); editor.selected = { type: "bus", key: bus.key }; renderRangeTopologyEditor();
}

function rangeAddStage() {
  if (vehicleRangeTemplateIsReadOnly()) return;
  const editor = rangeEditorState();
  if (editor.stages.length >= 64) { showSectionError("#vehicle-range-message", "一个靶场模板最多可配置 64 个阶段。"); return; }
  const order = editor.stages.length + 1; editor.stages.push({ key: rangeUniqueKey(editor.stages, "stage"), title: `阶段 ${order}`, description: "", order, score: 100, visual_node_key: "", visual_actions: [] }); renderRangeTopologyEditor();
}

function rangeRemoveNode(key) {
  if (vehicleRangeTemplateIsReadOnly()) return;
  const editor = rangeEditorState(); editor.nodes = editor.nodes.filter((node) => node.key !== key);
  editor.stages.forEach((stage) => { if (stage.visual_node_key === key) stage.visual_node_key = ""; });
  if (editor.selected?.type === "node" && editor.selected.key === key) editor.selected = null;
  renderRangeTopologyEditor();
}

function rangeRemoveBus(key) {
  if (vehicleRangeTemplateIsReadOnly()) return;
  const editor = rangeEditorState(); editor.buses = editor.buses.filter((bus) => bus.key !== key);
  editor.nodes.forEach((node) => { node.bus_keys = (node.bus_keys || []).filter((busKey) => busKey !== key); });
  if (editor.selected?.type === "bus" && editor.selected.key === key) editor.selected = null;
  renderRangeTopologyEditor();
}

function rangeNodeType(node) { return node.runtime_kind === "qemu-microvm" ? "KVM" : "DOCKER"; }
function rangeBusType(bus) { return { ethernet: "ETH", doip: "DOIP", can: "CAN", canfd: "CAN-FD" }[bus.kind] || "BUS"; }
function rangeNodeVisualTypeLabel(node) {
  const visualType = String(node?.visual_type || node?.visualType || "");
  return RANGE_NODE_VISUAL_TYPE_OPTIONS.find((item) => item.id === visualType)?.label || "自动识别";
}

function rangeNodeMeta(node) {
  const port = number(node.entry_port, 0); const resources = `${number(node.vcpus, 1)} vCPU · ${number(node.memory_mb, 0)} MiB`;
  return `${node.runtime_kind === "qemu-microvm" ? "KVM" : "Docker"} · ${rangeNodeVisualTypeLabel(node)} · TCP ${port || "—"} · ${resources}`;
}

function rangePositionFromEvent(event) {
  const canvas = $("#range-topology-canvas"); if (!canvas) return { x: 6, y: 8 };
  const rect = canvas.getBoundingClientRect();
  return rangeClampedPosition({ x: ((event.clientX - rect.left) / Math.max(rect.width, 1)) * 100 - 8, y: ((event.clientY - rect.top) / Math.max(rect.height, 1)) * 100 - 7 });
}

function rangeDrawLinks() {
  const canvas = $("#range-topology-canvas"); const svg = $("#range-topology-links"); if (!canvas || !svg) return;
  const editor = rangeEditorState(); const rect = canvas.getBoundingClientRect(); svg.replaceChildren();
  if (!rect.width || !rect.height) return;
  const selected = editor.selected;
  editor.nodes.forEach((node) => {
    const nodeElement = canvas.querySelector(`[data-range-node-key="${CSS.escape(node.key)}"]`); if (!nodeElement) return;
    const nodeRect = nodeElement.getBoundingClientRect();
    (node.bus_keys || []).forEach((busKey) => {
      const busElement = canvas.querySelector(`[data-range-bus-key="${CSS.escape(busKey)}"]`); if (!busElement) return;
      const busRect = busElement.getBoundingClientRect(); const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", String(nodeRect.left - rect.left + nodeRect.width / 2)); line.setAttribute("y1", String(nodeRect.bottom - rect.top));
      line.setAttribute("x2", String(busRect.left - rect.left + busRect.width / 2)); line.setAttribute("y2", String(busRect.top - rect.top));
      if ((selected?.type === "node" && selected.key === node.key) || (selected?.type === "bus" && selected.key === busKey)) line.classList.add("is-selected");
      svg.append(line);
    });
  });
}

function rangeMakeInspectorField(label, control) {
  const field = document.createElement("label"); field.className = "field"; const caption = document.createElement("span"); caption.textContent = label; field.append(caption, control); return field;
}

function rangeMakeInput(value, onChange, attributes = {}) {
  const input = document.createElement("input"); input.type = attributes.type || "text"; input.value = value ?? "";
  Object.entries(attributes).forEach(([key, attributeValue]) => { if (key !== "type") input[key] = attributeValue; });
  input.addEventListener("change", () => onChange(input.value, input)); return input;
}

function rangeMakeSelect(options, value, onChange) {
  const select = document.createElement("select"); options.forEach((option) => select.add(new Option(option.label, option.value)));
  select.value = value || ""; select.addEventListener("change", () => onChange(select.value, select)); return select;
}

function rangeParsePorts(value) {
  return Array.from(new Set(String(value || "").split(/[，,\s]+/).map((entry) => number(entry, 0)).filter((port) => port >= 1 && port <= 65535))).sort((a, b) => a - b);
}

function rangeEnvironmentText(environment) { return Object.entries(environment || {}).map(([key, value]) => `${key}=${value}`).join("\n"); }

function rangeParseEnvironment(value) {
  return String(value || "").split("\n").reduce((result, line) => {
    const separator = line.indexOf("="); if (separator <= 0) return result;
    const key = line.slice(0, separator).trim(); const entry = line.slice(separator + 1);
    if (key) result[key] = entry; return result;
  }, {});
}

function renderRangeNodeInspector(node) {
  const content = $("#range-topology-inspector-content"); if (!content) return;
  content.replaceChildren(); const fields = document.createElement("div"); fields.className = "range-inspector-fields";
  const keyInput = rangeMakeInput(node.key, (value) => { const next = rangeIdentifier(value, node.key); if (next !== node.key && rangeEditorState().nodes.some((item) => item !== node && item.key === next)) { showSectionError("#vehicle-range-message", "节点标识不能重复。"); renderRangeTopologyEditor(); return; } const old = node.key; node.key = next; if (!node.network_alias || node.network_alias === old) node.network_alias = next; if (rangeEditorState().selected?.key === old) rangeEditorState().selected.key = next; renderRangeTopologyEditor(); }, { maxLength: 63 });
  fields.append(rangeMakeInspectorField("节点标识", keyInput));
  fields.append(rangeMakeInspectorField("显示名称", rangeMakeInput(node.label, (value) => { node.label = value; renderRangeTopologyEditor(); }, { maxLength: 80 })));
  fields.append(rangeMakeInspectorField("3D 部件类型", rangeMakeSelect(RANGE_NODE_VISUAL_TYPE_OPTIONS.map((item) => ({ value: item.id, label: item.label })), node.visual_type || "", (value) => { node.visual_type = String(value || ""); renderRangeTopologyEditor(); })));
  const runtime = document.createElement("input"); runtime.value = node.runtime_kind === "qemu-microvm" ? "KVM 微虚拟机" : "Docker 容器"; runtime.readOnly = true; fields.append(rangeMakeInspectorField("运行类型", runtime));
  if (node.runtime_kind === "qemu-microvm") {
    const choices = [{ value: "", label: state.kvmArtifacts.length ? "选择已上传 KVM 镜像" : "尚无已上传 KVM 镜像" }, ...state.kvmArtifacts.map((item) => ({ value: item.digest, label: `${item.title || item.slug || "未命名镜像"} · ${item.memoryMiB || "—"} MiB · TCP ${item.entryPort || "—"}` }))];
    fields.append(rangeMakeInspectorField("KVM 镜像", rangeMakeSelect(choices, node.artifact_digest, (value) => { const artifact = state.kvmArtifacts.find((item) => item.digest === value); node.artifact_digest = value; node.artifact_storage_path = value.startsWith("sha256:") ? value.slice(7) : ""; if (artifact) { node.entry_port = number(artifact.entryPort, node.entry_port); node.ports = Array.from(new Set([node.entry_port, ...(node.ports || [])])); node.vcpus = number(artifact.vcpus, node.vcpus); node.memory_mb = number(artifact.memoryMiB, node.memory_mb); } renderRangeTopologyEditor(); })));
  } else {
    const choices = [{ value: "", label: state.localImages.length ? "选择当前 Docker 节点镜像" : "未发现当前 Docker 节点镜像" }, ...state.localImages.map((item) => ({ value: item.id, label: rangeImageLabel(item) }))];
    fields.append(rangeMakeInspectorField("Docker 镜像", rangeMakeSelect(choices, node.image_ref, (value) => { node.image_ref = value; const image = state.localImages.find((item) => item.id === value); const ports = imageExposedPorts(image).filter((item) => item.protocol === "tcp"); if (ports[0]) { node.entry_port = ports[0].port; node.ports = Array.from(new Set([node.entry_port, ...(node.ports || [])])); } renderRangeTopologyEditor(); })));
  }
  const resourceGrid = document.createElement("div"); resourceGrid.className = "range-inspector-grid";
  resourceGrid.append(rangeMakeInspectorField("入口 TCP 端口", rangeMakeInput(node.entry_port, (value) => { node.entry_port = number(value, 0); node.ports = Array.from(new Set([node.entry_port, ...(node.ports || [])].filter(Boolean))).sort((a, b) => a - b); renderRangeTopologyEditor(); }, { type: "number", min: 1, max: 65535 })), rangeMakeInspectorField("额外 TCP 端口", rangeMakeInput((node.ports || []).filter((port) => port !== node.entry_port).join(", "), (value) => { node.ports = Array.from(new Set([node.entry_port, ...rangeParsePorts(value)])).sort((a, b) => a - b); renderRangeTopologyEditor(); }, { placeholder: "例如 22, 8080" })));
  fields.append(resourceGrid);
  const capacityGrid = document.createElement("div"); capacityGrid.className = "range-inspector-grid";
  capacityGrid.append(rangeMakeInspectorField("vCPU", rangeMakeInput(node.vcpus, (value) => { node.vcpus = number(value, 1); rangeSyncTopologyJSON(); }, { type: "number", min: 1, max: 32 })), rangeMakeInspectorField("内存 MiB", rangeMakeInput(node.memory_mb, (value) => { node.memory_mb = number(value, 64); rangeSyncTopologyJSON(); }, { type: "number", min: 64, max: 65536 })));
  fields.append(capacityGrid);
  const topologyGrid = document.createElement("div"); topologyGrid.className = "range-inspector-grid";
  topologyGrid.append(rangeMakeInspectorField("启动顺序", rangeMakeInput(node.start_order, (value) => { node.start_order = number(value, 1); rangeSyncTopologyJSON(); }, { type: "number", min: 1, max: 10000 })), rangeMakeInspectorField("私网别名", rangeMakeInput(node.network_alias, (value) => { node.network_alias = rangeIdentifier(value, node.key); rangeSyncTopologyJSON(); }, { maxLength: 63 })));
  fields.append(topologyGrid);
  const busField = document.createElement("div"); busField.className = "field"; const busLabel = document.createElement("span"); busLabel.textContent = "接入逻辑总线"; const checks = document.createElement("div"); checks.className = "range-inspector-bus-checks";
  if (!rangeEditorState().buses.length) checks.append(Object.assign(document.createElement("small"), { textContent: "请先添加 CAN、CAN-FD、DoIP 或以太网总线。" }));
  rangeEditorState().buses.forEach((bus) => { const label = document.createElement("label"); const check = document.createElement("input"); check.type = "checkbox"; check.checked = (node.bus_keys || []).includes(bus.key); check.addEventListener("change", () => { node.bus_keys = check.checked ? Array.from(new Set([...(node.bus_keys || []), bus.key])) : (node.bus_keys || []).filter((key) => key !== bus.key); renderRangeTopologyEditor(); }); label.append(check, document.createTextNode(`${bus.label || bus.key} · ${rangeBusType(bus)}`)); checks.append(label); });
  busField.append(busLabel, checks); fields.append(busField);
  const switches = document.createElement("div"); switches.className = "range-inspector-switches";
  [["chain_authority", "链路权威节点", node.runtime_kind !== "container"], ["reporter", "只读总线采集器", node.runtime_kind !== "container"]].forEach(([property, labelText, disabled]) => { const label = document.createElement("label"); const check = document.createElement("input"); check.type = "checkbox"; check.checked = Boolean(node[property]); check.disabled = Boolean(disabled); check.addEventListener("change", () => { if (property === "chain_authority" && check.checked) rangeEditorState().nodes.forEach((item) => { if (item !== node) item.chain_authority = false; }); node[property] = check.checked; renderRangeTopologyEditor(); }); label.append(check, document.createTextNode(labelText)); switches.append(label); });
  fields.append(switches);
  const env = document.createElement("textarea"); env.value = rangeEnvironmentText(node.environment); env.placeholder = "KEY=value（每行一个）"; env.addEventListener("change", () => { node.environment = rangeParseEnvironment(env.value); rangeSyncTopologyJSON(); }); fields.append(rangeMakeInspectorField("环境变量（可选）", env));
  const remove = document.createElement("button"); remove.type = "button"; remove.className = "user-action range-inspector-danger"; remove.textContent = "删除节点"; remove.addEventListener("click", () => rangeRemoveNode(node.key)); fields.append(remove); content.append(fields);
}

function renderRangeBusInspector(bus) {
  const content = $("#range-topology-inspector-content"); if (!content) return;
  content.replaceChildren(); const fields = document.createElement("div"); fields.className = "range-inspector-fields";
  fields.append(rangeMakeInspectorField("总线标识", rangeMakeInput(bus.key, (value) => { const next = rangeIdentifier(value, bus.key); if (next !== bus.key && rangeEditorState().buses.some((item) => item !== bus && item.key === next)) { showSectionError("#vehicle-range-message", "总线标识不能重复。"); renderRangeTopologyEditor(); return; } const old = bus.key; bus.key = next; rangeEditorState().nodes.forEach((node) => { node.bus_keys = (node.bus_keys || []).map((key) => key === old ? next : key); }); if (rangeEditorState().selected?.key === old) rangeEditorState().selected.key = next; renderRangeTopologyEditor(); }, { maxLength: 63 })));
  fields.append(rangeMakeInspectorField("显示名称", rangeMakeInput(bus.label, (value) => { bus.label = value; renderRangeTopologyEditor(); }, { maxLength: 80 })));
  fields.append(rangeMakeInspectorField("总线类型", rangeMakeSelect([{ value: "ethernet", label: "车载以太网" }, { value: "doip", label: "DoIP 诊断域" }, { value: "can", label: "CAN" }, { value: "canfd", label: "CAN-FD" }], bus.kind, (value) => { bus.kind = value; bus.fd_enabled = value === "canfd"; if (value === "ethernet" || value === "doip") bus.bitrate = Math.max(number(bus.bitrate, 0), 10000000); renderRangeTopologyEditor(); })));
  fields.append(rangeMakeInspectorField("链路速率（bit/s）", rangeMakeInput(bus.bitrate, (value) => { bus.bitrate = number(value, 0); rangeSyncTopologyJSON(); }, { type: "number", min: 10000, max: bus.kind === "ethernet" || bus.kind === "doip" ? 10000000000 : 10000000 })));
  const fdLabel = document.createElement("label"); fdLabel.className = "range-inspector-switches"; const fdCheck = document.createElement("input"); fdCheck.type = "checkbox"; fdCheck.checked = Boolean(bus.fd_enabled); fdCheck.disabled = bus.kind !== "canfd"; fdCheck.addEventListener("change", () => { bus.fd_enabled = fdCheck.checked; rangeSyncTopologyJSON(); }); fdLabel.append(fdCheck, document.createTextNode("启用 CAN-FD 帧定义")); fields.append(fdLabel);
  const dbcOptions = [{ value: "", label: "不绑定 DBC 信号包" }, ...state.vehicleRangeDBCAssets.map((item) => ({ value: item.digest, label: `${item.filename || "DBC"} · ${number(item.frame_count || item.frameCount)} 帧` }))];
  fields.append(rangeMakeInspectorField("DBC 信号包", rangeMakeSelect(dbcOptions, bus.dbc_digest, (value) => { bus.dbc_digest = value; rangeSyncTopologyJSON(); })));
  const memberCount = rangeEditorState().nodes.filter((node) => (node.bus_keys || []).includes(bus.key)).length; const members = document.createElement("small"); members.textContent = `当前有 ${memberCount} 个节点接入该总线。`; fields.append(members);
  const remove = document.createElement("button"); remove.type = "button"; remove.className = "user-action range-inspector-danger"; remove.textContent = "删除总线"; remove.addEventListener("click", () => rangeRemoveBus(bus.key)); fields.append(remove); content.append(fields);
}

function renderRangeTopologyInspector() {
  const selected = rangeSelectedItem(); const type = $("#range-topology-selection-type"); const content = $("#range-topology-inspector-content"); if (!type || !content) return;
  if (!selected) { type.textContent = "未选择对象"; content.replaceChildren(Object.assign(document.createElement("div"), { className: "range-topology-inspector-empty", textContent: "选中画布内的节点或总线后，在这里配置。" })); return; }
  type.textContent = selected.type === "node" ? "节点配置" : "总线配置";
  if (selected.type === "node") renderRangeNodeInspector(selected.item); else renderRangeBusInspector(selected.item);
}

function renderRangeTopologyStages() {
  const list = $("#range-topology-stage-list"); if (!list) return; const editor = rangeEditorState(); list.replaceChildren();
  if (!editor.stages.length) { list.append(Object.assign(document.createElement("div"), { className: "range-topology-stage-empty", textContent: "至少配置一个阶段目标后才可保存靶场模板。" })); return; }
  editor.stages.sort((a, b) => number(a.order, 0) - number(b.order, 0)).forEach((stage, index) => {
    const row = document.createElement("article"); row.className = "range-topology-stage"; const order = document.createElement("b"); order.className = "range-stage-order"; order.textContent = String(index + 1).padStart(2, "0"); row.append(order);
    const key = rangeMakeInput(stage.key, (value) => { stage.key = rangeIdentifier(value, `stage-${index + 1}`); rangeSyncTopologyJSON(); }, { maxLength: 63 }); row.append(rangeMakeInspectorField("阶段标识", key));
    const description = document.createElement("textarea"); description.value = stage.description; description.placeholder = "阶段说明（可选）"; description.addEventListener("change", () => { stage.description = description.value; rangeSyncTopologyJSON(); }); const titleField = rangeMakeInspectorField("目标名称", rangeMakeInput(stage.title, (value) => { stage.title = value; rangeSyncTopologyJSON(); }, { maxLength: 120 })); titleField.append(description); row.append(titleField);
    row.append(rangeMakeInspectorField("积分", rangeMakeInput(stage.score, (value) => { stage.score = number(value, 0); rangeSyncTopologyJSON(); }, { type: "number", min: 0, max: 100000 })));
    const nodeOptions = [{ value: "", label: "不绑定拓扑节点" }, ...editor.nodes.map((node) => ({ value: node.key, label: node.label || node.key }))];
    row.append(rangeMakeInspectorField("3D 目标节点", rangeMakeSelect(nodeOptions, stage.visual_node_key, (value) => { stage.visual_node_key = value; rangeSyncTopologyJSON(); })));
    const actionField = document.createElement("fieldset"); actionField.className = "range-stage-visual-actions"; const actionLegend = document.createElement("legend"); actionLegend.textContent = "车辆联动动作"; actionField.append(actionLegend);
    const selectedActions = new Set(Array.isArray(stage.visual_actions) ? stage.visual_actions : []);
    RANGE_VISUAL_ACTION_OPTIONS.forEach((action) => { const label = document.createElement("label"); const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.checked = selectedActions.has(action.id); checkbox.addEventListener("change", () => { if (checkbox.checked) selectedActions.add(action.id); else selectedActions.delete(action.id); stage.visual_actions = [...selectedActions]; rangeSyncTopologyJSON(); }); label.append(checkbox, document.createTextNode(action.label)); actionField.append(label); });
    row.append(actionField);
    const remove = document.createElement("button"); remove.type = "button"; remove.className = "range-topology-stage-remove"; remove.title = "删除阶段"; remove.textContent = "×"; remove.addEventListener("click", () => { editor.stages = editor.stages.filter((item) => item !== stage); editor.stages.forEach((item, position) => { item.order = position + 1; }); renderRangeTopologyEditor(); }); row.append(remove); list.append(row);
  });
}

function renderRangeTopologyCanvas() {
  const editor = rangeEditorState(); const canvas = $("#range-topology-canvas"); const layer = $("#range-topology-node-layer"); const buses = $("#range-topology-bus-layer"); const emptyState = $("#range-topology-empty"); if (!canvas || !layer || !buses) return;
  canvas.style.setProperty("--range-topology-canvas-height", `${rangeCanvasMinHeight(editor)}px`);
  layer.replaceChildren(); buses.replaceChildren(); if (emptyState) emptyState.hidden = Boolean(editor.nodes.length || editor.buses.length);
  editor.nodes.forEach((node, index) => {
    node.__position = rangeClampedPosition(node.__position, index); const card = document.createElement("article"); card.className = `range-topology-node${node.runtime_kind === "qemu-microvm" ? " is-kvm" : ""}${editor.selected?.type === "node" && editor.selected.key === node.key ? " is-selected" : ""}`; card.dataset.rangeNodeKey = node.key; card.style.left = `${node.__position.x}%`; card.style.top = `${node.__position.y}%`;
    const head = document.createElement("header"); head.className = "range-topology-node-head"; const type = document.createElement("b"); type.className = "range-topology-node-type"; type.textContent = rangeNodeType(node); const title = document.createElement("span"); title.className = "range-topology-node-title"; title.textContent = node.label || node.key || "未命名节点"; const remove = document.createElement("button"); remove.type = "button"; remove.className = "range-topology-node-remove"; remove.title = "删除节点"; remove.textContent = "×"; remove.addEventListener("click", (event) => { event.stopPropagation(); rangeRemoveNode(node.key); }); head.append(type, title, remove);
    const body = document.createElement("div"); body.className = "range-topology-node-body"; body.append(Object.assign(document.createElement("small"), { className: "range-topology-node-meta", textContent: rangeNodeMeta(node) })); const nodeBuses = document.createElement("div"); nodeBuses.className = "range-topology-node-buses"; const attached = (node.bus_keys || []).map((key) => editor.buses.find((bus) => bus.key === key)).filter(Boolean); if (attached.length) attached.forEach((bus) => nodeBuses.append(Object.assign(document.createElement("span"), { textContent: bus.label || bus.key }))); else nodeBuses.append(Object.assign(document.createElement("span"), { className: "is-empty", textContent: "未接入总线" })); body.append(nodeBuses); card.append(head, body);
    card.addEventListener("click", () => rangeSetSelected("node", node.key)); head.addEventListener("pointerdown", (event) => { if (vehicleRangeTemplateIsReadOnly() || event.button !== 0 || event.target.closest("button")) return; event.preventDefault(); const drag = rangeEditorState().drag = { key: node.key, pointerId: event.pointerId }; head.setPointerCapture?.(event.pointerId); card.classList.add("is-dragging"); }); head.addEventListener("pointermove", (event) => { if (vehicleRangeTemplateIsReadOnly()) return; const drag = rangeEditorState().drag; if (!drag || drag.key !== node.key || drag.pointerId !== event.pointerId) return; node.__position = rangePositionFromEvent(event); card.style.left = `${node.__position.x}%`; card.style.top = `${node.__position.y}%`; window.requestAnimationFrame(rangeDrawLinks); }); const finishDrag = (event) => { if (vehicleRangeTemplateIsReadOnly()) return; const drag = rangeEditorState().drag; if (!drag || drag.key !== node.key || drag.pointerId !== event.pointerId) return; rangeEditorState().drag = null; card.classList.remove("is-dragging"); rangeSyncTopologyJSON(); window.requestAnimationFrame(rangeDrawLinks); }; head.addEventListener("pointerup", finishDrag); head.addEventListener("pointercancel", finishDrag); layer.append(card);
  });
  editor.buses.forEach((bus) => { const button = document.createElement("button"); button.type = "button"; button.className = `range-topology-bus is-${bus.kind}${editor.selected?.type === "bus" && editor.selected.key === bus.key ? " is-selected" : ""}`; button.dataset.rangeBusKey = bus.key; const type = document.createElement("b"); type.textContent = rangeBusType(bus); const label = document.createElement("span"); label.textContent = bus.label || bus.key || "未命名总线"; const speed = document.createElement("small"); speed.textContent = `${number(bus.bitrate, 0) >= 1000000 ? `${(number(bus.bitrate, 0) / 1000000).toFixed(number(bus.bitrate, 0) % 1000000 ? 1 : 0)}M` : `${Math.round(number(bus.bitrate, 0) / 1000)}K`}`; button.append(type, label, speed); button.addEventListener("click", () => rangeSetSelected("bus", bus.key)); buses.append(button); });
  window.requestAnimationFrame(rangeDrawLinks);
}

function renderRangeTopologyEditor() {
  if (!$("#range-topology-canvas")) return; const editor = rangeEditorState();
  setText("#range-topology-node-count", editor.nodes.length); setText("#range-topology-bus-count", editor.buses.length); setText("#range-topology-stage-count", editor.stages.length);
  setText("#range-topology-selection-hint", editor.selected ? "已选择对象；拖动节点仅调整画布排版，不改变启动顺序。" : "添加组件后，可拖动节点布局；节点接入总线由右侧配置。");
  renderRangeTopologyCanvas(); renderRangeTopologyInspector(); renderRangeTopologyStages(); rangeSyncTopologyJSON(); syncVehicleRangeTemplateEditorMode();
}

function resetVehicleRangeTopologyEditor() { state.vehicleRangeEditor = rangeTopologyFrom({ nodes: [], buses: [], stages: [] }); renderRangeTopologyEditor(); }

function populateVehicleRangeTopologyEditor(topology) { state.vehicleRangeEditor = rangeTopologyFrom(topology); renderRangeTopologyEditor(); }

function resetVehicleRangeTemplateForm() {
  const form = $("#vehicle-range-template-form"); if (!form) return;
  form.reset(); state.editingVehicleRangeTemplateId = null; state.viewingVehicleRangeTemplate = null;
  $("#vehicle-range-template-version").value = 1;
  resetVehicleRangeTopologyEditor();
  const button = form.querySelector("button[type=submit]"); if (button) button.textContent = "保存草稿模板";
  syncVehicleRangeTemplateEditorMode();
}

function populateVehicleRangeTemplate(template, { readOnly = false } = {}) {
  if (!template) return;
  state.editingVehicleRangeTemplateId = readOnly ? null : template.id;
  state.viewingVehicleRangeTemplate = readOnly ? template : null;
  $("#vehicle-range-template-slug").value = template.slug || "";
  $("#vehicle-range-template-version").value = template.version || 1;
  $("#vehicle-range-template-title").value = template.title || "";
  $("#vehicle-range-template-description").value = template.description || "";
  populateVehicleRangeTopologyEditor({ nodes: template.nodes || [], buses: template.buses || [], stages: template.stages || [] });
  const button = $("#vehicle-range-template-form button[type=submit]"); if (button) button.textContent = readOnly ? "只读查看" : "保存模板修改";
  syncVehicleRangeTemplateEditorMode();
  $("#vehicle-range-template-form")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function formatDateTime(value) {
  if (!value) return "—";
  const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(date);
}

function renderAll() { renderMetrics(); renderServices(); renderActivities(); renderUsers(); renderCompetition(); renderCompetitionOperations(); renderCompetitionContainers(); renderCompetitionCheating(); renderChallenges(); renderAssets(); renderAudit(); renderSystemSettings(); renderAttackDesktop(); renderVehicleRangeTemplates(); renderVehicleRangeDBCAssets(); renderNewChallengeOptions(); renderRangeTopologyEditor(); setText("#refreshed-at", `同步于 ${new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date())}`); }

async function loadData({ quiet = false } = {}) {
  if (!quiet) $("#refresh-button").disabled = true; clearSectionError("#users-message"); clearSectionError("#audit-message"); clearSectionError("#settings-message"); clearSectionError("#competition-operations-message"); clearSectionError("#competition-containers-message"); clearSectionError("#vehicle-message");
  state.loadingOperations = true; syncOperationsExportButtons();
  const results = await Promise.allSettled([request(API.overview), request(`${API.users}?limit=2000`), request(API.audit), request(API.bootstrap), request(API.settings), request(API.attackDesktop), request(API.vehicleRangeTemplates), request(API.vehicleRangeDBCAssets)]);
  const [overview, users, audit, bootstrap, settings, attackDesktop, vehicleRangeTemplates, vehicleRangeDBCAssets] = results;
  if (overview.status === "fulfilled") { const body = unwrap(overview.value) || {}; state.overview = body.overview || body; } else showToast(`总览载入失败：${overview.reason.message}`, true);
  if (users.status === "fulfilled") state.users = itemsFrom(users.value, "users"); else showSectionError("#users-message", `账号列表载入失败：${users.reason.message}`);
  if (audit.status === "fulfilled") state.audit = itemsFrom(audit.value, "audit"); else showSectionError("#audit-message", `审计记录载入失败：${audit.reason.message}`);
  if (settings.status === "fulfilled") { const body = unwrap(settings.value) || {}; state.systemSettings = body.settings || body; } else showSectionError("#settings-message", `系统设置载入失败：${settings.reason.message}`);
  state.attackDesktop = attackDesktop.status === "fulfilled" ? unwrap(attackDesktop.value) : null;
  if (vehicleRangeTemplates.status === "fulfilled") state.vehicleRangeTemplates = itemsFrom(vehicleRangeTemplates.value, "items");
  else { state.vehicleRangeTemplates = []; showSectionError("#vehicle-range-message", `靶场模板载入失败：${vehicleRangeTemplates.reason.message}`); }
  if (vehicleRangeDBCAssets.status === "fulfilled") state.vehicleRangeDBCAssets = itemsFrom(vehicleRangeDBCAssets.value, "items");
  else { state.vehicleRangeDBCAssets = []; showSectionError("#vehicle-range-message", `DBC 信号包载入失败：${vehicleRangeDBCAssets.reason.message}`); }
  const overviewTeams = firstArray(state.overview.teams, state.overview.resources?.teams); const overviewVehicles = firstArray(state.overview.instances, state.overview.vehicles, state.overview.resources?.vehicles);
  const bootstrapBody = bootstrap.status === "fulfilled" ? unwrap(bootstrap.value) || {} : {};
  state.teams = overviewTeams.length ? overviewTeams : firstArray(bootstrapBody.teams); state.vehicles = overviewVehicles.length ? overviewVehicles : firstArray(bootstrapBody.instances, bootstrapBody.vehicles);
  state.competition = bootstrapBody.competition ? normalizeCompetition(bootstrapBody.competition) : null; state.competitionId = state.competition?.id || state.teams[0]?.competitionId || state.teams[0]?.competition_id || null;
  const extra = await Promise.allSettled([
    state.competitionId ? request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}`) : Promise.resolve(null),
    state.competitionId ? request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/challenges`) : Promise.resolve({ items: [] }),
    request(API.vehicleCatalog),
    request(`/api/v1/admin/runtime/images`),
    state.competitionId ? request(`/api/v1/competitions/${encodeURIComponent(state.competitionId)}/teams`) : Promise.resolve({ items: [] }),
    state.competitionId ? request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/vehicles`) : Promise.resolve({ items: [] }),
    state.competitionId ? request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/operations?limit=1000`) : Promise.resolve({ item: null }),
    state.competitionId ? request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/containers?limit=1000`) : Promise.resolve({ item: null }),
    state.competitionId ? request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/cheating-events?limit=1000`) : Promise.resolve({ items: [] }),
    state.competitionId ? request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/participants`) : Promise.resolve({ items: [] }),
  ]);
  if (extra[0].status === "fulfilled" && extra[0].value) state.competition = normalizeCompetition(extra[0].value);
  state.challenges = extra[1].status === "fulfilled" ? itemsFrom(extra[1].value, "challenges") : [];
  const vehicleCatalog = extra[2].status === "fulfilled" ? unwrap(extra[2].value) || {} : {};
  state.vehicleCatalog = firstArray(vehicleCatalog.items, vehicleCatalog.vehicles);
  state.vehicleCapacity = vehicleCatalog.capacity || {};
  if (extra[3].status === "fulfilled") {
    state.localImages = itemsFrom(extra[3].value, "images");
    state.imageCatalogError = "";
  } else {
    state.localImages = [];
    state.imageCatalogError = extra[3].reason?.message || "镜像目录请求失败";
  }
  if (extra[4].status === "fulfilled") state.teams = itemsFrom(extra[4].value, "teams");
  if (extra[5].status === "fulfilled") state.vehicles = itemsFrom(extra[5].value, "vehicles");
  state.operations = extra[6].status === "fulfilled" && extra[6].value ? normalizeOperations(extra[6].value) : null;
  if (extra[6].status === "rejected" && state.competitionId) showSectionError("#competition-operations-message", `赛事运维数据载入失败：${extra[6].reason.message}`);
  state.containers = extra[7].status === "fulfilled" && extra[7].value ? normalizeContainers(extra[7].value) : null;
  if (extra[7].status === "rejected" && state.competitionId) showSectionError("#competition-containers-message", `运行容器数据载入失败：${extra[7].reason.message}`);
  state.cheatingEvents = extra[8].status === "fulfilled" ? itemsFrom(extra[8].value, "items") : null;
  if (extra[8].status === "rejected" && state.competitionId) showSectionError("#competition-operations-message", `作弊检测证据载入失败：${extra[8].reason.message}`);
  state.participants = extra[9].status === "fulfilled" ? itemsFrom(extra[9].value, "items") : [];
  state.vehicleRangeSettings = null;
  state.vehicleRangeInstances = [];
  if (state.competitionId && isVehicleRangeMode(state.competition?.mode)) {
    const [rangeSettings, rangeInstances] = await Promise.allSettled([
      request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/vehicle-range-settings`),
      request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/vehicle-range-instances?limit=1000`),
    ]);
    if (rangeSettings.status === "fulfilled") state.vehicleRangeSettings = unwrap(rangeSettings.value)?.item || unwrap(rangeSettings.value);
    else showSectionError("#competition-message", `靶场策略载入失败：${rangeSettings.reason.message}`);
    if (rangeInstances.status === "fulfilled") state.vehicleRangeInstances = itemsFrom(rangeInstances.value, "items");
    else showSectionError("#competition-message", `靶场实例载入失败：${rangeInstances.reason.message}`);
  }
  const libraryScope = await Promise.allSettled([
    request(`/api/v1/admin/competitions/${RESOURCE_LIBRARY_ID}/challenges`),
    request(`/api/v1/admin/competitions/${RESOURCE_LIBRARY_ID}/vehicles`),
  ]);
  state.libraryChallenges = libraryScope[0].status === "fulfilled" ? itemsFrom(libraryScope[0].value, "challenges") : [];
  state.libraryVehicles = libraryScope[1].status === "fulfilled" ? itemsFrom(libraryScope[1].value, "vehicles") : [];
  const excludedCompetition = state.competitionId || "";
  try { state.challengeLibrary = itemsFrom(await request(`/api/v1/admin/challenge-library?excludeCompetitionId=${encodeURIComponent(excludedCompetition)}`), "challenges"); }
  catch { state.challengeLibrary = []; }
  try { state.teamLibrary = itemsFrom(await request(`/api/v1/admin/team-library?excludeCompetitionId=${encodeURIComponent(excludedCompetition)}`), "teams"); }
  catch { state.teamLibrary = []; }
  try { state.vehicleLibrary = itemsFrom(await request(`/api/v1/admin/vehicle-library?excludeCompetitionId=${encodeURIComponent(excludedCompetition)}`), "vehicles"); }
  catch { state.vehicleLibrary = []; }
  state.libraryTeams = state.teamLibrary.filter((team) => libraryCompetitionID(team) === RESOURCE_LIBRARY_ID);
  state.loadingOperations = false;
  renderAll(); $("#refresh-button").disabled = false;
}

async function loadKVMArtifacts({ quiet = false } = {}) {
  try {
    const payload = await request(`/api/v1/admin/runtime/kvm-artifacts`);
    state.kvmArtifacts = itemsFrom(payload, "items");
    renderNewChallengeOptions();
    renderRangeTopologyEditor();
  } catch (error) {
    state.kvmArtifacts = [];
    renderNewChallengeOptions();
    renderRangeTopologyEditor();
    if (!quiet) showSectionError("#settings-message", `KVM 镜像目录载入失败：${error.message}`);
  }
}

async function loadCompetitionOperations() {
  if (!state.competitionId) { state.operations = null; state.containers = null; state.cheatingEvents = null; renderCompetitionOperations(); renderCompetitionContainers(); renderCompetitionCheating(); return; }
  const button = $("#competition-operations-refresh"); if (button) button.disabled = true;
  state.loadingOperations = true; syncOperationsExportButtons();
  clearSectionError("#competition-operations-message"); clearSectionError("#competition-containers-message");
  try {
    const [operationsPayload, containersPayload, cheatingPayload] = await Promise.all([
      request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/operations?limit=1000`),
      request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/containers?limit=1000`),
      request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/cheating-events?limit=1000`),
    ]);
    state.operations = normalizeOperations(operationsPayload); state.containers = normalizeContainers(containersPayload); state.cheatingEvents = itemsFrom(cheatingPayload, "items"); renderCompetitionOperations(); renderCompetitionContainers(); renderCompetitionCheating(); showToast("赛事运维、容器与作弊证据已刷新");
  } catch (error) {
    showSectionError("#competition-operations-message", `赛事运维数据刷新失败：${error.message}`);
  } finally { state.loadingOperations = false; syncOperationsExportButtons(); if (button) button.disabled = false; }
}

async function controlCompetitionContainer(runID, action) {
  if (!runID || !state.competitionId || state.busyContainers.has(runID)) return;
  const label = action === "restart" ? "重启" : "停止";
  if (!window.confirm(`确认${label}该选手运行容器？`)) return;
  state.busyContainers.add(runID); renderCompetitionContainers();
  try {
    await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/containers/${encodeURIComponent(runID)}/actions`, { method: "POST", body: JSON.stringify({ action }) });
    await loadCompetitionOperations();
    showToast(`容器${label}操作已完成`);
  } catch (error) {
    showSectionError("#competition-containers-message", `容器${label}失败：${error.message}`);
  } finally {
    state.busyContainers.delete(runID); renderCompetitionContainers();
  }
}

async function removeTeam(teamID) {
  if (!teamID || state.busyTeams.has(teamID)) return;
  const team = [...state.teams, ...state.libraryTeams].find((item) => String(item.id) === String(teamID));
  if (!team || team.status === "offline") return;
  if (!window.confirm(`确认永久删除队伍“${team.name || teamID}”吗？该操作会物理删除成员账号、车辆、成绩、提交和运行记录，无法恢复。`)) return;
  state.busyTeams.add(teamID); renderAssets();
  try {
    const competitionID = team.competitionId || team.competition_id || state.competitionId || RESOURCE_LIBRARY_ID;
    await request(`/api/v1/admin/competitions/${encodeURIComponent(competitionID)}/teams/${encodeURIComponent(teamID)}`, { method: "DELETE" });
    showToast(`队伍“${team.name || teamID}”及其关联数据已物理删除`);
    await loadData({ quiet: true });
  } catch (error) {
    showToast(`物理删除队伍失败：${error.message}`, true);
  } finally {
    state.busyTeams.delete(teamID); renderAssets();
  }
}

async function importLibraryTeam(sourceCompetitionID, teamID, button) {
  if (!state.competitionId || !sourceCompetitionID || !teamID || state.competition?.status === "finished") return;
  button.disabled = true;
  try {
    const result = await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/teams/library`, { method: "POST", body: JSON.stringify({ sourceCompetitionId: sourceCompetitionID, teamId: teamID }) });
    const membersImported = Number(result?.membersImported ?? result?.data?.membersImported ?? 0);
    showToast(`队伍已导入当前赛事，自动继承 ${membersImported} 名已关联选手，无需再次绑定`); await loadData({ quiet: true });
  } catch (error) { showSectionError("#teams-message", `导入队伍失败：${error.message}`); button.disabled = false; }
}

async function importLibraryChallenge(sourceCompetitionID, challengeID, button) {
  if (!state.competitionId || !sourceCompetitionID || !challengeID || state.competition?.status === "finished") return;
  button.disabled = true;
  try {
    await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/challenges/library`, { method: "POST", body: JSON.stringify({ sourceCompetitionId: sourceCompetitionID, challengeId: challengeID }) });
    showToast("题目已导入当前赛事草稿，已继承题目库车辆映射，请检查后发布"); await loadData({ quiet: true });
  } catch (error) { showSectionError("#challenges-message", `导入题目失败：${error.message}`); button.disabled = false; }
}

async function importLibraryVehicle(sourceCompetitionID, vehicleInstanceID, button) {
  if (!state.competitionId || !sourceCompetitionID || !vehicleInstanceID || state.competition?.status === "finished") return;
  button.disabled = true;
  try {
    await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/vehicles/library`, { method: "POST", body: JSON.stringify({ sourceCompetitionId: sourceCompetitionID, vehicleInstanceId: vehicleInstanceID }) });
    showToast("展示车辆已导入当前赛事，可在题目库绑定"); await loadData({ quiet: true });
  } catch (error) { showSectionError("#vehicle-message", `导入车辆失败：${error.message}`); button.disabled = false; }
}

const rosterImportDialog = $("#roster-import-dialog");
const rosterImportFile = $("#roster-import-file");

function setRosterImportBusy(busy, action = "") {
  state.rosterImport.busy = busy;
  $("#preview-roster-import").disabled = busy || !state.rosterImport.file;
  $("#commit-roster-import").disabled = busy || !state.rosterImport.preview?.valid;
  $("#cancel-roster-import").disabled = busy;
  $("#close-roster-import").disabled = busy;
  $("#preview-roster-import").textContent = busy && action === "preview" ? "正在预检…" : "上传并预检";
  $("#commit-roster-import").textContent = busy && action === "commit" ? "正在创建账号…" : "确认导入并下载结果";
}

function resetRosterImport() {
  rosterImportFile.value = "";
  state.rosterImport.file = null;
  state.rosterImport.preview = null;
  state.rosterImport.busy = false;
  $("#roster-import-file-name").textContent = "尚未选择文件";
  $("#roster-import-message").hidden = true;
  $("#roster-import-preview").hidden = true;
  $("#roster-import-preview").classList.remove("is-valid", "is-invalid");
  $("#roster-import-errors").replaceChildren();
  setRosterImportBusy(false);
}

function openRosterImport() {
  resetRosterImport();
  rosterImportDialog.showModal();
}

function closeRosterImport() {
  if (state.rosterImport.busy) return;
  rosterImportDialog.close();
  resetRosterImport();
}

function renderRosterIssues(issues = []) {
  const list = $("#roster-import-errors");
  list.replaceChildren();
  if (!issues.length) {
    const emptyRow = document.createElement("div");
    emptyRow.className = "roster-error-empty";
    emptyRow.textContent = "格式、容量、账号与队伍冲突检查全部通过";
    list.append(emptyRow);
    return;
  }
  issues.slice(0, 250).forEach((issue) => {
    const row = document.createElement("div");
    row.className = "roster-error-item";
    const location = document.createElement("strong");
    location.textContent = `${issue.sheet || "工作簿"}${issue.row ? ` · 第 ${issue.row} 行` : ""}${issue.column ? ` · ${issue.column} 列` : ""}`;
    const message = document.createElement("span");
    message.textContent = issue.message || issue.code || "数据不符合导入要求";
    row.append(location, message);
    list.append(row);
  });
  if (issues.length > 250) {
    const row = document.createElement("div");
    row.className = "roster-error-item";
    const location = document.createElement("strong");
    location.textContent = "其余问题";
    const message = document.createElement("span");
    message.textContent = `还有 ${issues.length - 250} 个问题未展开，请先按前述规则批量修正后重新预检。`;
    row.append(location, message);
    list.append(row);
  }
}

function renderRosterPreview(preview, overrideIssues = null) {
  const issues = overrideIssues || preview.errors || [];
  const valid = overrideIssues ? false : Boolean(preview.valid);
  state.rosterImport.preview = { ...preview, valid, errors: issues };
  const panel = $("#roster-import-preview");
  panel.hidden = false;
  panel.classList.toggle("is-valid", valid);
  panel.classList.toggle("is-invalid", !valid);
  $("#roster-preview-teams").textContent = `${number(preview.teamCount)} / 400`;
  $("#roster-preview-players").textContent = `${number(preview.playerCount)} / 1000`;
  $("#roster-preview-passwords").textContent = `${number(preview.generatedPasswordCount)}`;
  $("#roster-preview-status").textContent = valid ? "可以导入" : "需要修正";
  $("#roster-preview-heading").textContent = valid ? "预检通过，确认后将一次性创建全部记录" : "预检未通过，数据库尚未发生变化";
  $("#roster-preview-digest").textContent = preview.digest ? `文件指纹 ${preview.digest}` : "";
  $("#roster-preview-error-count").textContent = `${issues.length} 个问题`;
  renderRosterIssues(issues);
  setRosterImportBusy(false);
}

async function rosterFetch(path, formData, responseType = "json") {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { Accept: responseType === "blob" ? "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet, application/json" : "application/json" },
    body: formData,
  });
  if (!response.ok) {
    let payload = null;
    try { payload = await response.json(); } catch { payload = null; }
    const error = new Error(errorText(payload, response.status));
    error.status = response.status;
    error.code = payload?.error?.code;
    error.issues = payload?.error?.details?.errors || [];
    throw error;
  }
  return responseType === "blob" ? response : response.json();
}

function rosterResultFilename(response) {
  const disposition = response.headers.get("Content-Disposition") || "";
  const utf8Name = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Name) {
    try { return decodeURIComponent(utf8Name[1]); } catch { /* use fallback below */ }
  }
  const plainName = disposition.match(/filename="?([^";]+)"?/i);
  return plainName?.[1] || `cybercar-roster-result-${new Date().toISOString().slice(0, 10)}.xlsx`;
}

$("#open-roster-import").addEventListener("click", openRosterImport);
$("#close-roster-import").addEventListener("click", closeRosterImport);
$("#cancel-roster-import").addEventListener("click", closeRosterImport);
rosterImportDialog.addEventListener("click", (event) => { if (event.target === rosterImportDialog) closeRosterImport(); });
rosterImportFile.addEventListener("change", () => {
  const file = rosterImportFile.files?.[0] || null;
  state.rosterImport.file = file;
  state.rosterImport.preview = null;
  $("#roster-import-message").hidden = true;
  $("#roster-import-preview").hidden = true;
  if (!file) {
    $("#roster-import-file-name").textContent = "尚未选择文件";
  } else if (!file.name.toLowerCase().endsWith(".xlsx")) {
    $("#roster-import-file-name").textContent = file.name;
    $("#roster-import-message").textContent = "仅支持平台模板格式的 .xlsx 文件。";
    $("#roster-import-message").hidden = false;
    state.rosterImport.file = null;
  } else if (file.size > 10 * 1024 * 1024) {
    $("#roster-import-file-name").textContent = `${file.name} · 文件超过 10 MiB`;
    $("#roster-import-message").textContent = "文件超过 10 MiB 上限，请拆分或移除无关内容。";
    $("#roster-import-message").hidden = false;
    state.rosterImport.file = null;
  } else {
    $("#roster-import-file-name").textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KiB`;
  }
  setRosterImportBusy(false);
});
const competitionChallengeDialog = $("#competition-challenge-dialog");
function closeCompetitionChallengeDialog() {
  if (competitionChallengeDialog?.open) competitionChallengeDialog.close();
}
$("#open-competition-challenge-dialog")?.addEventListener("click", () => {
  competitionChallengeDialog.showModal();
});
$("#close-competition-challenge-dialog")?.addEventListener("click", closeCompetitionChallengeDialog);
$("#cancel-competition-challenge-dialog")?.addEventListener("click", closeCompetitionChallengeDialog);
$("#competition-challenge-library-link")?.addEventListener("click", closeCompetitionChallengeDialog);
competitionChallengeDialog?.addEventListener("click", (event) => { if (event.target === competitionChallengeDialog) closeCompetitionChallengeDialog(); });
$("#competition-batch-score-mode")?.addEventListener("change", renderCompetitionBatchScoreFields);
$("#competition-score-select-all")?.addEventListener("click", () => {
  const inputs = [...document.querySelectorAll("[data-batch-challenge]")];
  const shouldSelect = inputs.some((input) => !input.checked);
  inputs.forEach((input) => { input.checked = shouldSelect; });
  syncCompetitionBatchSelection();
});
$("#competition-batch-score-save")?.addEventListener("click", async (event) => {
  const challengeIds = [...document.querySelectorAll("[data-batch-challenge]:checked")].map((input) => input.dataset.batchChallenge);
  if (!state.competitionId || !challengeIds.length) return;
  const payload = { challengeIds, scoreMode: $("#competition-batch-score-mode").value };
  document.querySelectorAll("[data-batch-score-field]").forEach((input) => { payload[input.dataset.batchScoreField] = Number(input.value); });
  if (payload.scoreMode === "dynamic" && payload.dynamicMinScore > payload.baseScore) {
    $("#competition-challenge-dialog-message").textContent = "动态分值配置无效：最低分不能高于初始分。衰减系数 k 越大，前期下降越慢；最低分是长期运行的下限。";
    $("#competition-challenge-dialog-message").hidden = false;
    return;
  }
  const button = event.currentTarget; button.disabled = true; $("#competition-challenge-dialog-message").hidden = true;
  try {
    await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/challenges/batch-score/update`, { method: "PATCH", body: JSON.stringify(payload) });
    showToast(`已批量保存 ${challengeIds.length} 道题目的分值`); await loadData({ quiet: true });
  } catch (error) {
    $("#competition-challenge-dialog-message").textContent = `批量保存失败：${error.message}`; $("#competition-challenge-dialog-message").hidden = false;
  } finally { syncCompetitionBatchSelection(); }
});
$("#preview-roster-import").addEventListener("click", async () => {
  if (!state.rosterImport.file || state.rosterImport.busy) return;
  $("#roster-import-message").hidden = true;
  setRosterImportBusy(true, "preview");
  const formData = new FormData();
  formData.append("file", state.rosterImport.file);
  try {
    const payload = await rosterFetch(API.rosterPreview, formData);
    renderRosterPreview(unwrap(payload)?.item || unwrap(payload) || {});
  } catch (error) {
    $("#roster-import-message").textContent = `预检失败：${error.message}`;
    $("#roster-import-message").hidden = false;
    setRosterImportBusy(false);
  }
});
$("#commit-roster-import").addEventListener("click", async () => {
  const { file, preview, busy } = state.rosterImport;
  if (!file || !preview?.valid || busy) return;
  $("#roster-import-message").hidden = true;
  setRosterImportBusy(true, "commit");
  const formData = new FormData();
  formData.append("file", file);
  formData.append("expectedDigest", preview.digest);
  try {
    const response = await rosterFetch(API.rosterCommit, formData, "blob");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = rosterResultFilename(response);
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    const teams = response.headers.get("X-Roster-Team-Count") || preview.teamCount;
    const players = response.headers.get("X-Roster-Player-Count") || preview.playerCount;
    setRosterImportBusy(false);
    closeRosterImport();
    showToast(`批量导入完成：${teams} 支队伍、${players} 名选手；账号结果已下载`);
    await loadData({ quiet: true });
  } catch (error) {
    if (error.issues?.length) renderRosterPreview(preview, error.issues);
    $("#roster-import-message").textContent = `导入失败：${error.message}`;
    $("#roster-import-message").hidden = false;
    setRosterImportBusy(false);
  }
});

function mountVehicleRangeTopologyWorkspace() {
  const host = $("#vehicle-range-topology-form-host"); const form = $("#vehicle-range-template-form"); const message = $("#vehicle-range-message");
  if (!host || !form) return;
  if (message) host.append(message);
  host.append(form);
}

async function initialize() {
  mountVehicleRangeTopologyWorkspace();
  bindAdminNavigation();
  activateAdminView();
  try {
    const payload = await request(API.me); const user = userFrom(payload); if (!user) throw Object.assign(new Error("未获取到登录账号。"), { status: 401 });
    if (!isAdmin(user)) { window.location.replace("/"); return; }
    state.me = user; setText("#operator-name", userName(user)); setText("#operator-role", roleLabel(user.role));
    $("#boot-screen strong").textContent = "正在载入管理数据";
    $("#boot-screen small").textContent = "管理权限已通过，正在同步当前赛事…";
    await loadData(); $("#control-state").textContent = "连接正常"; $(".control-state").classList.add("is-online"); $("#admin-shell").setAttribute("aria-busy", "false"); $("#boot-screen").classList.add("is-complete");
    void loadKVMArtifacts({ quiet: true });
  } catch (error) { if (error.status === 401 || error.status === 403) { window.location.replace("/login.html"); return; } $("#boot-screen strong").textContent = "无法进入管理控制台"; $("#boot-screen small").textContent = error.message; setTimeout(() => window.location.replace("/login.html"), 2500); }
}

$("#refresh-button").addEventListener("click", async () => {
  await loadData();
  void loadKVMArtifacts({ quiet: true });
});

async function refreshAttackDesktopAdmin() {
  const button = $("#kasmvnc-admin-refresh"); if (button) button.disabled = true;
  try { state.attackDesktop = await request(API.attackDesktop); renderAttackDesktop(); }
  catch (error) { state.attackDesktop = null; renderAttackDesktop(); if (error.status !== 503) showSectionError("#attack-desktop-message", `攻击机状态刷新失败：${error.message}`); }
  finally { if (button) button.disabled = false; }
}

async function attackDesktopAdminAction(action, label) {
  const button = $("#kasmvnc-admin-" + action); if (button) button.disabled = true;
  clearSectionError("#attack-desktop-message");
  try {
    state.attackDesktop = await request(`/api/v1/admin/attack-desktop/${action}`, { method: "POST" });
    renderAttackDesktop(); showToast(label);
  } catch (error) { showSectionError("#attack-desktop-message", `${label}失败：${error.message}`); }
  finally { if (button) button.disabled = false; }
}

$("#kasmvnc-admin-refresh")?.addEventListener("click", refreshAttackDesktopAdmin);
$("#kasmvnc-admin-preflight")?.addEventListener("click", () => attackDesktopAdminAction("preflight", "攻击机节点预检完成"));
$("#kasmvnc-admin-reconcile")?.addEventListener("click", () => attackDesktopAdminAction("reconcile", "Docker 会话已同步"));
$("#kasmvnc-admin-cleanup")?.addEventListener("click", () => {
  if (window.confirm("确认回收所有已过期的攻击机桌面吗？运行中的桌面不会被停止。")) attackDesktopAdminAction("cleanup", "过期攻击机桌面已回收");
});
$("#docker-mode").addEventListener("change", () => syncDockerSettingsFields({ clearLocal: $("#docker-mode").value === "local" }));
$("#competition-operations-refresh").addEventListener("click", loadCompetitionOperations);
document.querySelectorAll("[data-audit-view]").forEach((button) => button.addEventListener("click", () => {
  state.auditView = button.dataset.auditView === "access" ? "access" : "operations";
  loadAuditRecords();
}));
$("#audit-filter-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  loadAuditRecords();
});
$("#audit-filter-reset")?.addEventListener("click", () => {
  $("#audit-filter-form")?.reset();
  loadAuditRecords();
});
$("#audit-list")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-audit-detail]");
  if (!button) return;
  openAuditDetail(button.dataset.auditView, button.dataset.auditSequence);
});
$("#close-audit-detail-dialog")?.addEventListener("click", closeAuditDetail);
$("#cancel-audit-detail-dialog")?.addEventListener("click", closeAuditDetail);
$("#audit-detail-dialog")?.addEventListener("click", (event) => { if (event.target === $("#audit-detail-dialog")) closeAuditDetail(); });
$("#copy-audit-detail-json")?.addEventListener("click", async () => {
  const text = $("#audit-detail-json")?.textContent || "";
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    showToast("审计详情 JSON 已复制");
  } catch {
    showToast("复制失败，请选中详情 JSON 后手动复制", true);
  }
});
$("#competition-operations").addEventListener("click", (event) => {
  const viewButton = event.target.closest("[data-operations-view]");
  if (viewButton) { activateOperationsView(viewButton.dataset.operationsView); return; }
  const pageButton = event.target.closest("[data-operations-page]");
  if (pageButton) { changeOperationsPage(pageButton.dataset.operationsPage, number(pageButton.dataset.pageDirection)); return; }
  const cheatingButton = event.target.closest("[data-cheating-event]");
  if (cheatingButton) {
    controlCheatingEvent(
      cheatingButton.dataset.cheatingEvent,
      cheatingButton.dataset.cheatingScope,
      cheatingButton.dataset.cheatingAction,
    );
    return;
  }
  const exportButton = event.target.closest("[data-export-operations]");
  if (exportButton) exportCompetitionOperations(exportButton.dataset.exportOperations);
});
$("#competition-operations-tabs").addEventListener("keydown", (event) => {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const current = event.target.closest("[data-operations-view]");
  if (!current) return;
  event.preventDefault();
  const currentIndex = OPERATIONS_VIEWS.indexOf(current.dataset.operationsView);
  const nextIndex = event.key === "Home" ? 0
    : event.key === "End" ? OPERATIONS_VIEWS.length - 1
      : (currentIndex + (event.key === "ArrowRight" ? 1 : -1) + OPERATIONS_VIEWS.length) % OPERATIONS_VIEWS.length;
  activateOperationsView(OPERATIONS_VIEWS[nextIndex], { focus: true });
});
$("#open-competition-bigscreen").addEventListener("click", () => {
  if (!state.competitionId) return;
  window.open(`/event-screen.html?competitionId=${encodeURIComponent(state.competitionId)}`, "_blank", "noopener,noreferrer");
});
$("#competition-containers-table").addEventListener("click", (event) => {
  const button = event.target.closest("[data-container-action]");
  if (!button) return;
  controlCompetitionContainer(button.dataset.containerRun, button.dataset.containerAction);
});
$("#team-list").addEventListener("click", (event) => {
  const button = event.target.closest("[data-team-action]");
  if (button?.dataset.teamAction === "remove") removeTeam(button.dataset.teamId);
});
$("#team-library-list").addEventListener("click", (event) => {
  const button = event.target.closest("[data-import-team-id]");
  if (button) importLibraryTeam(button.dataset.importTeamCompetition, button.dataset.importTeamId, button);
});
$("#vehicle-list").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-vehicle-action='remove']");
  if (!button) return;
  const vehicle = state.libraryVehicles.find((item) => String(item.id) === String(button.dataset.vehicleId));
  const label = vehicle?.label || vehicle?.name || button.dataset.vehicleId;
  if (!window.confirm(`确认删除展示车辆“${label}”吗？已绑定题目或已有运行历史的车辆不能删除。`)) return;
  button.disabled = true;
  try {
    await request(`/api/v1/admin/competitions/${RESOURCE_LIBRARY_ID}/vehicles/${encodeURIComponent(button.dataset.vehicleId)}`, { method: "DELETE" });
    showToast("平台展示车辆已删除");
    await loadData({ quiet: true });
  } catch (error) {
    showToast(`删除展示车辆失败：${error.message}`, true);
    button.disabled = false;
  }
});
$("#vehicle-library-list").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-vehicle-action='remove']");
  if (!button) return;
  const vehicle = state.libraryVehicles.find((item) => String(item.id) === String(button.dataset.vehicleId));
  const label = vehicle?.label || vehicle?.name || button.dataset.vehicleId;
  if (!window.confirm(`确认删除全局展示车辆“${label}”吗？已绑定题目或已有历史记录的车辆不能删除。`)) return;
  button.disabled = true;
  try {
    await request(`/api/v1/admin/competitions/${RESOURCE_LIBRARY_ID}/vehicles/${encodeURIComponent(button.dataset.vehicleId)}`, { method: "DELETE" });
    showToast("全局展示车辆已删除"); await loadData({ quiet: true });
  } catch (error) { showToast(`删除全局展示车辆失败：${error.message}`, true); button.disabled = false; }
});
$("#challenge-library-list").addEventListener("click", (event) => {
  const button = event.target.closest("[data-import-challenge-id]");
  if (button) importLibraryChallenge(button.dataset.importChallengeCompetition, button.dataset.importChallengeId, button);
});
$("#user-search").addEventListener("input", renderUsers);
$("#carpack-file").addEventListener("change", () => {
  const file = $("#carpack-file").files?.[0]; $("label[for='carpack-file']").textContent = file ? file.name : "选择 CARPACK（兼容导入）"; renderChallenges();
});
$("#competition-create-toggle").addEventListener("click", () => {
  const panel = $("#competition-empty"); panel.hidden = !panel.hidden;
  if (!panel.hidden) { setText("#competition-empty-kicker", "下一场赛事"); setText("#competition-empty-title", "新建赛事"); setText("#competition-empty-description", "当前赛事已结束。创建后将获得独立的题目、队伍、车辆孪生与成绩空间。"); $("#competition-create-title").focus(); }
});
$("#competition-create-form").addEventListener("submit", async (event) => {
  event.preventDefault(); if (state.competitionId && state.competition?.status !== "finished") return;
  const form = event.currentTarget;
  const title = $("#competition-create-title").value.trim(); const start = $("#competition-create-start").value; const end = $("#competition-create-end").value;
  const button = form.querySelector("button"); button.disabled = true;
  const selectedMode = $("#competition-create-mode").value || "ctf";
  const mode = selectedMode === "ctf" ? ($("#competition-create-ctf-format").value || "team") : "vehicle_range";
  const accessMode = $("#competition-create-access-mode").value || (mode === "vehicle_range" ? "attack" : "direct");
  const maxActiveContainersPerTeam = Number($("#competition-create-max-containers").value || 1);
  const attackPayload = accessMode === "attack" ? { attackWorkspaceId: $("#competition-create-attack-workspace").value.trim(), attackDesktopCpuMilli: Number($("#competition-create-attack-cpu").value || 2000), attackDesktopMemoryMb: Number($("#competition-create-attack-memory").value || 4096), attackDesktopMaxMinutes: Number($("#competition-create-attack-minutes").value || 240) } : {};
  const vehicleRangePayload = mode === "vehicle_range" ? { vehicleRangeTemplateId: $("#competition-create-range-template").value, vehicleRangeScopeMode: $("#competition-create-range-scope").value, vehicleRangeMaxActiveInstances: Number($("#competition-create-range-capacity").value || 100), vehicleRangeAllowSelfReset: $("#competition-create-range-reset").checked } : {};
  if (mode === "vehicle_range" && !vehicleRangePayload.vehicleRangeTemplateId) { showToast("请先选择一个已发布的车联网靶场模板", true); button.disabled = false; return; }
  try { await request("/api/v1/admin/competitions", { method: "POST", body: JSON.stringify({ title, mode, accessMode, startsAt: dateTimeISO(start), endsAt: dateTimeISO(end), cheatingDetectionEnabled: $("#competition-create-cheating-detection").checked, maxActiveContainersPerTeam, ...attackPayload, ...vehicleRangePayload }) }); form.reset(); $("#competition-create-max-containers").value = 1; $("#competition-create-attack-cpu").value = 2000; $("#competition-create-attack-memory").value = 4096; $("#competition-create-attack-minutes").value = 240; $("#competition-create-range-capacity").value = 100; $("#competition-create-range-reset").checked = true; showToast(mode === "individual" ? "个人赛已创建，请按需加入参赛账号与题目" : mode === "vehicle_range" ? "车联网靶场赛事已创建，请导入队伍并开始比赛" : mode === "attack" ? "攻击机赛事已创建，请继续配置队伍、题目和 Kasm 网络" : "团队赛已创建，请按需加入参赛队伍与题目"); await loadData({ quiet: true }); }
  catch (error) { if (error.code === "competition_exists") { await loadData({ quiet: true }); showToast("已载入现有赛事，请继续配置赛事"); } else { showToast(`创建赛事失败：${error.message}`, true); } }
  finally { button.disabled = false; }
});
function syncCompetitionCreateAccessOptions(mode = $("#competition-create-mode")?.value || "ctf") {
  const access = $("#competition-create-access-mode");
  const openVPN = $("#competition-create-openvpn-option");
  const vehicleRange = mode === "vehicle_range";
  if (openVPN) {
    openVPN.disabled = !vehicleRange;
    openVPN.hidden = !vehicleRange;
  }
  if (!vehicleRange && access?.value === "openvpn") access.value = "direct";
  setText("#competition-create-access-mode-help", vehicleRange
    ? "攻击机模式在云桌面内访问；OpenVPN 模式为每名选手签发独立配置，只放行本队或本人的靶场网段。"
    : "CTF 保持现有直连映射或攻击机访问，不使用车联网靶场 OpenVPN。"
  );
}

$("#competition-create-mode").addEventListener("change", (event) => {
  const fields = $("#competition-attack-create-fields");
  const range = $("#competition-range-create-fields");
  const ctfFormat = $("#competition-create-ctf-format");
  if (ctfFormat) ctfFormat.closest(".field").hidden = event.target.value !== "ctf";
  $("#competition-create-access-mode").value = event.target.value === "vehicle_range" ? "attack" : "direct";
  syncCompetitionCreateAccessOptions(event.target.value);
  if (fields) fields.hidden = $("#competition-create-access-mode").value !== "attack";
  if (range) range.hidden = event.target.value !== "vehicle_range";
});
$("#competition-create-access-mode").addEventListener("change", (event) => {
  const fields = $("#competition-attack-create-fields");
  if (fields) fields.hidden = event.target.value !== "attack";
});
syncCompetitionCreateAccessOptions();
$("#vehicle-range-template-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (vehicleRangeTemplateIsReadOnly()) { showToast("当前为只读查看，模板不会被修改"); return; }
  const form = event.currentTarget;
  const button = form.querySelector("button[type=submit]");
  const topology = rangeTopologyForSave();
  if (!topology.nodes.length) { showSectionError("#vehicle-range-message", "请在画布中至少添加一个 Docker 节点或 KVM 靶机。"); return; }
  if (!topology.stages.length) { showSectionError("#vehicle-range-message", "请至少添加一个解题阶段与积分目标。"); return; }
  const missingRuntime = topology.nodes.find((node) => node.runtime_kind === "qemu-microvm" ? !node.artifact_digest : !node.image_ref);
  if (missingRuntime) { showSectionError("#vehicle-range-message", `节点“${missingRuntime.label || missingRuntime.key}”尚未选择${missingRuntime.runtime_kind === "qemu-microvm" ? " KVM 镜像" : " Docker 镜像"}。`); return; }
  const payload = {
    slug: $("#vehicle-range-template-slug").value.trim(), version: Number($("#vehicle-range-template-version").value), title: $("#vehicle-range-template-title").value.trim(), description: $("#vehicle-range-template-description").value.trim(),
    nodes: Array.isArray(topology.nodes) ? topology.nodes : [], buses: Array.isArray(topology.buses) ? topology.buses : [], stages: Array.isArray(topology.stages) ? topology.stages : [],
  };
  button.disabled = true; clearSectionError("#vehicle-range-message");
  try {
    const editingID = state.editingVehicleRangeTemplateId;
    await request(editingID ? `${API.vehicleRangeTemplates}/${encodeURIComponent(editingID)}` : API.vehicleRangeTemplates, { method: editingID ? "PUT" : "POST", body: JSON.stringify(payload) });
    resetVehicleRangeTemplateForm(); showToast(editingID ? "靶场模板已更新；选手刷新后可看到分数/阶段变化，拓扑变更需重启靶场" : "靶场模板草稿已保存"); await loadData({ quiet: true });
  } catch (error) { showSectionError("#vehicle-range-message", `保存靶场模板失败：${error.message}`); }
  finally { button.disabled = false; }
});
$("#range-topology-auto-layout")?.addEventListener("click", () => {
  if (vehicleRangeTemplateIsReadOnly()) return;
  rangeEditorState().nodes.forEach((node, index) => { node.__position = rangeClampedPosition(null, index); }); renderRangeTopologyEditor();
});
document.querySelectorAll("[data-range-add-node]").forEach((button) => button.addEventListener("click", () => rangeAddNode(button.dataset.rangeAddNode)));
document.querySelectorAll("[data-range-add-bus]").forEach((button) => button.addEventListener("click", () => rangeAddBus(button.dataset.rangeAddBus)));
document.querySelectorAll("[data-range-palette-node]").forEach((button) => button.addEventListener("click", () => rangeAddNode(button.dataset.rangePaletteNode)));
document.querySelectorAll("[data-range-palette-bus]").forEach((button) => button.addEventListener("click", () => rangeAddBus(button.dataset.rangePaletteBus)));
document.querySelectorAll("[data-range-palette-node],[data-range-palette-bus]").forEach((item) => item.addEventListener("dragstart", (event) => {
  event.dataTransfer?.setData("application/x-cybercar-range", JSON.stringify({ type: item.dataset.rangePaletteNode ? "node" : "bus", kind: item.dataset.rangePaletteNode || item.dataset.rangePaletteBus }));
  if (event.dataTransfer) event.dataTransfer.effectAllowed = "copy";
}));
$("#range-topology-canvas")?.addEventListener("dragover", (event) => { if (Array.from(event.dataTransfer?.types || []).includes("application/x-cybercar-range")) { event.preventDefault(); event.dataTransfer.dropEffect = "copy"; } });
$("#range-topology-canvas")?.addEventListener("drop", (event) => {
  if (vehicleRangeTemplateIsReadOnly()) return;
  event.preventDefault(); let payload = null; try { payload = JSON.parse(event.dataTransfer?.getData("application/x-cybercar-range") || "null"); } catch { return; }
  if (!payload?.kind) return; if (payload.type === "node") rangeAddNode(payload.kind, rangePositionFromEvent(event)); else if (payload.type === "bus") rangeAddBus(payload.kind);
});
$("#range-topology-add-stage")?.addEventListener("click", rangeAddStage);
$("#range-topology-apply-json")?.addEventListener("click", () => {
  if (vehicleRangeTemplateIsReadOnly()) return;
  let topology; try { topology = JSON.parse($("#vehicle-range-template-topology").value); } catch { showSectionError("#vehicle-range-message", "高级模式中的 JSON 无法解析，请修正后再应用。"); return; }
  if (!topology || typeof topology !== "object" || Array.isArray(topology)) { showSectionError("#vehicle-range-message", "高级模式必须提供包含 nodes、buses、stages 的 JSON 对象。"); return; }
  clearSectionError("#vehicle-range-message"); populateVehicleRangeTopologyEditor(topology); showToast("已将 JSON 应用到可视化画布");
});
$("#range-topology-refresh-json")?.addEventListener("click", () => { rangeSyncTopologyJSON(); showToast("已从画布刷新 JSON"); });
$("#vehicle-range-dbc-file")?.addEventListener("change", (event) => {
  const file = event.currentTarget.files?.[0] || null;
  setText("#vehicle-range-dbc-file-name", file ? `${file.name} · ${formatAssetBytes(file.size)}` : "未选择文件");
  const upload = $("#vehicle-range-dbc-upload"); if (upload) upload.disabled = !file;
});
$("#vehicle-range-dbc-upload")?.addEventListener("click", async (event) => {
  const input = $("#vehicle-range-dbc-file"); const file = input?.files?.[0] || null;
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) { showSectionError("#vehicle-range-message", "DBC 信号包不能超过 2 MiB。"); return; }
  const button = event.currentTarget; const body = new FormData(); body.append("file", file, file.name);
  button.disabled = true; clearSectionError("#vehicle-range-message");
  try {
    await request(API.vehicleRangeDBCAssets, { method: "POST", body, raw: true });
    input.value = ""; setText("#vehicle-range-dbc-file-name", "未选择文件"); showToast("DBC 信号包已校验并入库"); await loadData({ quiet: true });
  } catch (error) { showSectionError("#vehicle-range-message", `上传 DBC 信号包失败：${error.message}`); }
  finally { button.disabled = false; }
});
$("#vehicle-range-dbc-list")?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy-vehicle-range-dbc]"); const digest = button?.dataset.copyVehicleRangeDbc;
  if (!button || !digest) return;
  try { await navigator.clipboard.writeText(digest); showToast("DBC 指纹已复制，可填入模板总线的 dbc_digest"); }
  catch { showSectionError("#vehicle-range-message", "浏览器未允许复制，请手动复制 DBC 指纹。"); }
});
$("#vehicle-range-template-list")?.addEventListener("click", async (event) => {
  const view = event.target.closest("[data-view-vehicle-range-template]");
  if (view) {
    const templateID = view.dataset.viewVehicleRangeTemplate;
    if (!templateID) return;
    view.disabled = true;
    try {
      const payload = await request(`${API.vehicleRangeTemplates}/${encodeURIComponent(templateID)}`);
      const template = unwrap(payload)?.item || payload?.item;
      if (!template) throw new Error("未找到靶场模板");
      populateVehicleRangeTemplate(template, { readOnly: true });
      if (location.hash !== "#vehicle-range-topology") history.pushState(null, "", "#vehicle-range-topology");
      activateAdminView("vehicle-range-topology");
      showToast("已打开只读拓扑视图");
    } catch (error) {
      showSectionError("#vehicle-range-message", `加载靶场拓扑失败：${error.message}`);
    } finally {
      view.disabled = false;
    }
    return;
  }
  const edit = event.target.closest("[data-edit-vehicle-range-template]");
  if (edit) {
    populateVehicleRangeTemplate(state.vehicleRangeTemplates.find((item) => String(item.id) === String(edit.dataset.editVehicleRangeTemplate)));
    if (location.hash !== "#vehicle-range-topology") history.pushState(null, "", "#vehicle-range-topology");
    activateAdminView("vehicle-range-topology");
    return;
  }
  const remove = event.target.closest("[data-delete-vehicle-range-template]");
  if (remove) {
    const template = state.vehicleRangeTemplates.find((item) => String(item.id) === String(remove.dataset.deleteVehicleRangeTemplate));
    if (!template || !window.confirm(`确认永久删除“${template.title || template.slug} / V${template.version}”？此操作无法恢复；关联赛事设置、历史靶场实例、阶段事件和对应得分会一并清理。`)) return;
    remove.disabled = true;
    try {
      await request(`${API.vehicleRangeTemplates}/${encodeURIComponent(template.id)}`, { method: "DELETE" });
      if (String(state.editingVehicleRangeTemplateId) === String(template.id)) resetVehicleRangeTemplateForm();
      showToast("靶场模板已物理删除"); await loadData({ quiet: true });
    } catch (error) {
      showSectionError("#vehicle-range-message", `删除靶场模板失败：${error.message}`); remove.disabled = false;
    }
    return;
  }
  const publish = event.target.closest("[data-publish-vehicle-range-template]");
  if (!publish) return;
  const template = state.vehicleRangeTemplates.find((item) => String(item.id) === String(publish.dataset.publishVehicleRangeTemplate));
  if (!template || !window.confirm(`确认发布“${template.title || template.slug} / V${template.version}”？发布后该版本不可修改。`)) return;
  publish.disabled = true;
  try { await request(`${API.vehicleRangeTemplates}/${encodeURIComponent(template.id)}/publish`, { method: "POST" }); showToast("靶场模板已发布，可用于创建赛事"); await loadData({ quiet: true }); }
  catch (error) { showSectionError("#vehicle-range-message", `发布靶场模板失败：${error.message}`); publish.disabled = false; }
});
$("#vehicle-range-template-view-exit")?.addEventListener("click", () => {
  resetVehicleRangeTemplateForm();
  showToast("已退出只读拓扑视图");
});
$("#competition-library-challenge").addEventListener("change", (event) => { $("#competition-add-challenge").disabled = !event.target.value; });
$("#competition-add-challenge").addEventListener("click", async (event) => {
  const challengeID = $("#competition-library-challenge").value;
  if (!state.competitionId || !challengeID) return;
  const source = importableLibraryChallenges().find((challenge) => challenge.id === challengeID);
  const sourceCompetitionID = libraryCompetitionID(source);
  if (!sourceCompetitionID) return;
  const button = event.currentTarget; button.disabled = true;
  try {
    await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/challenges/library`, { method: "POST", body: JSON.stringify({ sourceCompetitionId: sourceCompetitionID, challengeId: challengeID }) });
    showToast("题目已导入当前赛事，已继承题目库车辆映射，请检查后发布"); await loadData({ quiet: true });
  } catch (error) { showSectionError("#competition-message", `导入题目失败：${error.message}`); button.disabled = false; }
});
$("#competition-challenge-list").addEventListener("click", async (event) => {
  const removeButton = event.target.closest("[data-remove-competition-challenge]");
  if (removeButton && state.competitionId) {
    const challengeID = removeButton.dataset.removeCompetitionChallenge;
    const challenge = state.challenges.find((item) => String(item.id) === String(challengeID));
    if (!challenge) return;
    const removeWarning = challenge.status === "published"
      ? "该已发布题目、附件、车辆绑定、运行记录、提交记录与得分记录会被物理删除。"
      : "该草稿及其附件、车辆绑定和运行记录会被删除。";
    if (!window.confirm(`确认从本赛事移除题目“${challenge.title || challenge.slug || challengeID}”吗？${removeWarning}`)) return;
    removeButton.disabled = true;
    try {
      await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/challenges/${encodeURIComponent(challengeID)}`, { method: "DELETE" });
      showToast("题目已从本赛事移除"); await loadData({ quiet: true });
    } catch (error) { showSectionError("#competition-message", `移除赛事题目失败：${error.message}`); removeButton.disabled = false; }
    return;
  }
  const scoreButton = event.target.closest("[data-save-score-challenge]");
  if (scoreButton && state.competitionId) {
    const control = scoreButton.closest(".competition-score-control");
    const mode = control.querySelector("[data-score-mode]").value;
    const payload = { scoreMode: mode };
    control.querySelectorAll("[data-score-field]").forEach((input) => { payload[input.dataset.scoreField] = Number(input.value); });
    scoreButton.disabled = true;
    try {
      await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/challenges/${encodeURIComponent(scoreButton.dataset.saveScoreChallenge)}`, { method: "PATCH", body: JSON.stringify(payload) });
      showToast("赛事题目分值已保存"); await loadData({ quiet: true });
    } catch (error) { showSectionError("#competition-message", `保存题目分值失败：${error.message}`); scoreButton.disabled = false; }
    return;
  }
  const button = event.target.closest("[data-publish-competition-challenge]");
  if (!button || !state.competitionId) return;
  button.disabled = true;
  try {
    await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/challenges/${encodeURIComponent(button.dataset.publishCompetitionChallenge)}/publish`, { method: "POST" });
    showToast("题目已发布，选手端现在可以看到");
    await loadData({ quiet: true });
  } catch (error) {
    showSectionError("#competition-message", `发布赛事题目失败：${error.message}`);
    button.disabled = false;
  }
});
$("#competition-settings-form").addEventListener("submit", async (event) => {
  event.preventDefault(); if (!state.competitionId || state.competition?.status === "finished") return;
  const button = event.currentTarget.querySelector("button[type='submit']"); button.disabled = true;
  try { await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}`, { method: "PATCH", body: JSON.stringify({ title: $("#competition-title").value.trim(), startsAt: dateTimeISO($("#competition-start").value), endsAt: dateTimeISO($("#competition-end").value), cheatingDetectionEnabled: $("#competition-cheating-detection").checked, maxActiveContainersPerTeam: Number($("#competition-max-containers").value || 1) }) }); showToast("赛事设置已保存"); await loadData({ quiet: true }); }
  catch (error) { showSectionError("#competition-message", `保存赛事失败：${error.message}`); }
  finally { button.disabled = false; }
});
$("#competition-range-save")?.addEventListener("click", async (event) => {
  if (!state.competitionId || !isVehicleRangeMode() || state.competition?.status === "finished") return;
  const templateId = $("#competition-range-template").value;
  if (!templateId) { showSectionError("#competition-message", "请选择一个已发布的车联网靶场模板。"); return; }
  const capacity = Number($("#competition-range-capacity").value);
  if (!Number.isInteger(capacity) || capacity < 1 || capacity > 2000) {
    showSectionError("#competition-message", "靶场上限必须为 1–2000。"); return;
  }
  event.currentTarget.disabled = true;
  try {
    const payload = await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/vehicle-range-settings`, {
      method: "PATCH",
      body: JSON.stringify({ templateId, scopeMode: $("#competition-range-scope").value, maxActiveInstances: capacity, allowSelfReset: $("#competition-range-reset").checked }),
    });
    state.vehicleRangeSettings = unwrap(payload)?.item || unwrap(payload);
    renderVehicleRangeSettings();
    showToast("车联网靶场策略已保存；变更会在下一次启动实例时生效");
  } catch (error) { showSectionError("#competition-message", `保存靶场策略失败：${error.message}`); }
  finally { event.currentTarget.disabled = false; }
});
$("#vehicle-range-instance-list")?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-vehicle-range-instance-action]");
  const instanceID = button?.dataset.vehicleRangeInstance;
  const action = button?.dataset.vehicleRangeInstanceAction;
  if (!button || !instanceID || !state.competitionId || state.competition?.status === "finished") return;
  let path = `/api/v1/admin/vehicle-range-instances/${encodeURIComponent(instanceID)}`;
  let body;
  let pending = "";
  let success = "";
  if (action === "pause") {
    path += "/pause"; pending = "正在暂停靶场"; success = "靶场已暂停；节点、私网地址与当前代次均已保留";
  } else if (action === "resume") {
    path += "/resume"; pending = "正在恢复靶场"; success = "靶场已恢复原代次运行";
  } else if (action === "snapshot") {
    const label = window.prompt("快照名称（可选）", `G${(state.vehicleRangeInstances || []).find((item) => String(item.id) === String(instanceID))?.generation || ""} 阶段恢复点`);
    if (label === null) return;
    path += "/snapshots"; body = JSON.stringify({ label }); pending = "正在保存阶段快照"; success = "阶段快照已保存，可在暂停状态下恢复";
  } else if (action === "restore") {
    const actions = button.closest(".vehicle-range-instance-actions");
    const snapshotID = actions?.querySelector("[data-vehicle-range-snapshot-select]")?.value;
    if (!snapshotID) { showSectionError("#competition-message", "请先选择一个可恢复快照。"); return; }
    if (!window.confirm("恢复会停止当前靶场，并以相同模板创建新的运行代次；只恢复服务器已验证的阶段进度，不会保留 Flag、密钥或桌面数据。确认继续？")) return;
    path += `/snapshots/${encodeURIComponent(snapshotID)}/restore`; pending = "正在从快照重建靶场"; success = "靶场已按快照重建为新代次，已恢复验证阶段";
  } else if (action === "reset") {
    if (!window.confirm("重置会停止并重新创建该作用域的全部靶场节点；当前阶段进度将从新代次开始。确认继续？")) return;
    path += "/reset"; pending = "正在重置靶场"; success = "靶场重置请求已受理，正在重新编排节点";
  } else return;
  button.disabled = true;
  try { await request(path, { method: "POST", body }); showToast(success || pending); await loadData({ quiet: true }); }
  catch (error) { showSectionError("#competition-message", `${pending || "靶场操作"}失败：${error.message}`); button.disabled = false; }
});
$("#system-settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const first = Number($("#challenge-port-first").value);
  const last = Number($("#challenge-port-last").value);
  const dockerMode = $("#docker-mode").value;
  const dockerHost = $("#docker-host").value.trim();
  const dockerBindAddress = $("#docker-bind-address").value.trim();
  const dockerAccessHost = $("#docker-access-host").value.trim();
  const dockerCertPath = $("#docker-cert-path").value.trim();
  const hasRemoteValues = Boolean(dockerHost || dockerBindAddress || dockerAccessHost || dockerCertPath || $("#docker-tls-verify").checked);
  if (!Number.isInteger(first) || !Number.isInteger(last) || first < 1024 || last > 65535 || first > last || last - first > 20000 || [9989, 9990, 9991].some((reserved) => first <= reserved && reserved <= last)) {
    showSectionError("#settings-message", "端口范围无效：需在 1024–65535 内、最多包含 20001 个端口，且不能包含平台监听端口 9989–9991。");
    return;
  }
  if (dockerMode === "remote" && (!/^(tcp|ssh):\/\/[^\s]+$/i.test(dockerHost) || !dockerAccessHost)) {
    showSectionError("#settings-message", "远程 Docker 模式需要填写 tcp:// 或 ssh:// 地址，以及选手可达的访问地址。");
    return;
  }
  if (dockerMode === "local" && hasRemoteValues) {
    showSectionError("#settings-message", "已填写远程节点参数，请先将 Docker 节点模式切换为“远程 Docker API”，或清空远程参数后保存本机模式。");
    return;
  }
  if (dockerBindAddress && !/^[0-9a-f:.]+$/i.test(dockerBindAddress)) {
    showSectionError("#settings-message", "节点绑定地址必须是 IP 地址，例如 192.168.20.138 或 0.0.0.0。");
    return;
  }
  clearSectionError("#settings-message");
  const button = event.currentTarget.querySelector("button[type='submit']"); button.disabled = true;
  try {
    const response = await request(API.settings, { method: "PATCH", body: JSON.stringify({
      challengePortFirst: first, challengePortLast: last, dockerMode, dockerHost,
      dockerBindAddress, dockerAccessHost, dockerTLSVerify: $("#docker-tls-verify").checked, dockerCertPath,
    }) });
    const body = unwrap(response) || {}; state.systemSettings = body.settings || body; renderSystemSettings();
    await loadData({ quiet: true });
    showToast(dockerMode === "remote" ? "远程 Docker 节点已保存，新题目将从远程节点启动" : "本机 Docker 节点已保存，新题目将在本机启动");
  } catch (error) {
    showSectionError("#settings-message", `保存系统设置失败：${error.message}`);
  } finally { button.disabled = false; }
});
$("#kvm-artifact-file").addEventListener("change", (event) => {
  const file = event.target.files?.[0] || null;
  $("#kvm-artifact-file-name").textContent = file ? `${file.name} · ${(file.size / (1024 * 1024)).toFixed(1)} MiB` : "选择 KVM 镜像";
  $("#upload-kvm-artifact").disabled = !file;
});
$("#upload-kvm-artifact").addEventListener("click", async (event) => {
  const file = $("#kvm-artifact-file").files?.[0]; if (!file) return;
  const button = event.currentTarget; button.disabled = true; clearSectionError("#settings-message");
  try {
    await request("/api/v1/admin/runtime/kvm-artifacts/import", { method: "POST", body: file, raw: true, headers: { "Content-Type": "application/octet-stream" } });
    $("#kvm-artifact-file").value = ""; $("#kvm-artifact-file-name").textContent = "选择 KVM 镜像";
    showToast("KVM 镜像已校验并上传，可在创建题目时选择"); await loadKVMArtifacts();
  } catch (error) { showSectionError("#settings-message", `KVM 镜像上传失败：${error.message}`); }
  finally { button.disabled = !$("#kvm-artifact-file").files?.length; }
});
$("#competition-actions").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-competition-action]"); if (!button || !state.competitionId) return;
  const action = button.dataset.competitionAction;
  if (action === "finish" && !window.confirm("确认结束本场比赛吗？结束后会暂停题目运行容器，但会保留成绩、题目、队伍和审计记录。")) return;
  if (action === "cleanup" && !window.confirm("确认删除本场赛事的运行容器吗？账号、赛题、车辆、队伍关系、成绩与审计记录都会保留。")) return;
  if (action === "delete" && !window.confirm("确认删除本场比赛吗？系统会先删除运行容器，再将赛事归档并从赛事列表隐藏；账号、赛题、车辆、队伍关系、成绩与审计记录都会保留。")) return;
  button.disabled = true;
  try {
    if (action === "cleanup") await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/runtime-cleanup`, { method: "POST" });
    else if (action === "delete") await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}`, { method: "DELETE" });
    else await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/actions`, { method: "POST", body: JSON.stringify({ action }) });
    showToast(({ start: "比赛已开始", pause: "比赛已暂停，运行容器已冻结", resume: "比赛已恢复，运行容器已解除冻结", finish: "比赛已结束，运行容器已冻结", cleanup: "运行容器已删除，赛事数据全部保留", delete: "比赛已删除，历史数据已归档保留" })[action] || "赛事状态已更新"); await loadData({ quiet: true });
  }
  catch (error) { showSectionError("#competition-message", `${action === "cleanup" ? "清理运行容器" : action === "delete" ? "删除比赛" : "赛事状态操作"}失败：${error.message}`); renderCompetition(); }
});
$("#team-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = { name: $("#team-name").value.trim(), organization: $("#team-organization").value.trim(), color: $("#team-color").value };
  const button = form.querySelector("button"); button.disabled = true;
  try { const created = await request(`/api/v1/admin/competitions/${RESOURCE_LIBRARY_ID}/teams`, { method: "POST", body: JSON.stringify(payload) }); form.reset(); $("#team-color").value = "#65E6D4"; showToast(`队伍库已创建，系统标识 ${created?.code || "已生成"}`); await loadData({ quiet: true }); }
  catch (error) { showToast(`创建队伍失败：${error.message}`, true); }
  finally { button.disabled = false; }
});
function selectedLibraryTeamIDs() {
  return [...document.querySelectorAll("#team-library-options input[type=checkbox]:checked")].map((input) => input.value);
}
function syncTeamLibraryPicker() {
  const count = selectedLibraryTeamIDs().length;
  setText("#team-library-selection-count", `已选 ${count} 支`);
  setText("#team-library-dialog-count", `已选 ${count} 支`);
  const button = $("#team-library-import");
  if (button) {
    button.textContent = state.teamLibraryImporting ? "正在导入…" : count ? `导入选中队伍（${count}）` : "导入选中队伍";
    button.disabled = !count || state.competition?.status === "finished" || state.teamLibraryImporting;
  }
}
$("#team-library-options").addEventListener("change", syncTeamLibraryPicker);
$("#team-library-search").addEventListener("input", (event) => {
  const query = event.target.value.trim().toLocaleLowerCase();
  document.querySelectorAll("#team-library-options .team-library-option").forEach((label) => {
    label.hidden = Boolean(query) && !label.dataset.search.includes(query);
  });
});
$("#team-library-select-all").addEventListener("click", () => {
  const options = [...document.querySelectorAll("#team-library-options input[type=checkbox]:not(:disabled)")];
  const shouldCheck = options.some((input) => !input.checked);
  options.forEach((input) => { input.checked = shouldCheck; });
  syncTeamLibraryPicker();
});
$("#team-library-import").addEventListener("click", async (event) => {
  event.preventDefault();
  clearSectionError("#team-library-dialog-message");
  if (!state.competitionId) {
    showSectionError("#team-library-dialog-message", "请先选择要维护的赛事。");
    return;
  }
  if (state.competition?.status === "finished") {
    showSectionError("#team-library-dialog-message", "已结束赛事不能继续导入队伍。");
    return;
  }
  const selectedIDs = new Set(selectedLibraryTeamIDs());
  const sources = importableLibraryTeams().filter((team) => selectedIDs.has(String(team.id)) && (team.competitionId || team.competition_id));
  if (!sources.length) {
    showSectionError("#team-library-dialog-message", "未找到可导入的已选队伍，请刷新后重新选择。");
    return;
  }
  state.teamLibraryImporting = true;
  syncTeamLibraryPicker();
  try {
    const result = await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/teams/library/batch`, {
      method: "POST",
      body: JSON.stringify({ items: sources.map((source) => ({ sourceCompetitionId: source.competitionId || source.competition_id, teamId: source.id })) }),
    });
    const success = Number(result?.count ?? result?.data?.count ?? sources.length);
    clearSectionError("#teams-message");
    showToast(`已批量导入 ${success} 支队伍，请在账号管理中绑定当前赛事账号`);
    closeTeamLibraryDialog();
    await loadData({ quiet: true });
  } catch (error) {
    const message = `批量导入未完成：${error.message}。本次采用整批事务，失败时不会写入任何队伍。`;
    showSectionError("#team-library-dialog-message", message);
    showSectionError("#teams-message", message);
  } finally {
    state.teamLibraryImporting = false;
    syncTeamLibraryPicker();
  }
});
const teamLibraryDialog = $("#team-library-dialog");
$("#open-team-library-dialog").addEventListener("click", () => {
  clearSectionError("#team-library-dialog-message");
  syncTeamLibraryPicker();
  teamLibraryDialog.showModal();
  requestAnimationFrame(() => $("#team-library-search").focus());
});
function closeTeamLibraryDialog() {
  teamLibraryDialog.close();
  clearSectionError("#team-library-dialog-message");
  $("#team-library-search").value = "";
  document.querySelectorAll("#team-library-options .team-library-option").forEach((label) => { label.hidden = false; });
}
$("#close-team-library-dialog").addEventListener("click", closeTeamLibraryDialog);
$("#cancel-team-library-dialog").addEventListener("click", closeTeamLibraryDialog);
teamLibraryDialog.addEventListener("click", (event) => { if (event.target === teamLibraryDialog) closeTeamLibraryDialog(); });
function selectedParticipantUserIDs() { return [...document.querySelectorAll("#participant-library-options input[type=checkbox]:checked")].map((input) => input.value); }
function syncParticipantLibraryPicker() {
  const count = selectedParticipantUserIDs().length;
  setText("#participant-library-selection-count", `已选 ${count} 名`);
  setText("#participant-library-dialog-count", `已选 ${count} 名`);
  $("#participant-library-import").disabled = !count || state.competition?.status === "finished";
}
const participantLibraryDialog = $("#participant-library-dialog");
$("#participant-library-options").addEventListener("change", syncParticipantLibraryPicker);
$("#participant-library-search").addEventListener("input", (event) => {
  const query = event.target.value.trim().toLocaleLowerCase();
  document.querySelectorAll("#participant-library-options .team-library-option").forEach((label) => { label.hidden = Boolean(query) && !label.dataset.search.includes(query); });
});
$("#participant-library-select-all").addEventListener("click", () => {
  const options = [...document.querySelectorAll("#participant-library-options input[type=checkbox]:not(:disabled)")];
  const shouldCheck = options.some((input) => !input.checked);
  options.forEach((input) => { input.checked = shouldCheck; });
  syncParticipantLibraryPicker();
});
$("#open-participant-library-dialog").addEventListener("click", () => { renderParticipantLibraryOptions(true); participantLibraryDialog.showModal(); requestAnimationFrame(() => $("#participant-library-search").focus()); });
function closeParticipantLibraryDialog() { participantLibraryDialog.close(); $("#participant-library-search").value = ""; }
$("#close-participant-library-dialog").addEventListener("click", closeParticipantLibraryDialog);
$("#cancel-participant-library-dialog").addEventListener("click", closeParticipantLibraryDialog);
participantLibraryDialog.addEventListener("click", (event) => { if (event.target === participantLibraryDialog) closeParticipantLibraryDialog(); });
$("#participant-library-import").addEventListener("click", async (event) => {
  const userIds = selectedParticipantUserIDs();
  if (!state.competitionId || !userIds.length) return;
  const button = event.currentTarget; button.disabled = true; button.textContent = "正在导入…";
  try {
    const result = await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/participants/batch`, { method: "POST", body: JSON.stringify({ userIds }) });
    showToast(`已导入 ${Number(result?.count ?? userIds.length)} 名个人参赛选手`);
    closeParticipantLibraryDialog();
    await loadData({ quiet: true });
  } catch (error) { showSectionError("#teams-message", `批量导入选手失败：${error.message}`); }
  finally { button.textContent = "导入选中选手"; button.disabled = false; }
});
$("#competition-team-list").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-remove-participant]");
  if (!button || !state.competitionId) return;
  const participant = state.participants.find((item) => String(item.userId) === String(button.dataset.removeParticipant));
  if (!participant || !window.confirm(`确认将选手“${participant.displayName || participant.username}”移出本赛事吗？平台账号和原队伍不会改变。`)) return;
  button.disabled = true;
  try {
    await request(`/api/v1/admin/competitions/${encodeURIComponent(state.competitionId)}/participants/${encodeURIComponent(participant.userId)}`, { method: "DELETE" });
    showToast("个人选手已移出本赛事"); await loadData({ quiet: true });
  } catch (error) { showSectionError("#teams-message", `移除个人选手失败：${error.message}`); button.disabled = false; }
});
function syncParticipantPicker() {
  const user = $("#competition-participant-user")?.value;
  const team = $("#competition-participant-team")?.value;
  const button = $("#competition-add-participant");
  if (button) button.disabled = !user || !team || state.competition?.status === "finished";
}
$("#competition-participant-user").addEventListener("change", syncParticipantPicker);
$("#competition-participant-team").addEventListener("change", syncParticipantPicker);
$("#competition-add-participant").addEventListener("click", async (event) => {
  const userID = $("#competition-participant-user").value;
  const teamID = $("#competition-participant-team").value;
  if (!userID || !teamID) return;
  const user = state.users.find((item) => String(item.id || item.username) === String(userID));
  const team = state.teams.find((item) => String(item.id) === String(teamID));
  if (!user || !team) return;
  if (!window.confirm(`确认将选手“${userName(user)}”加入当前赛事队伍“${team.name || team.id}”吗？该账号的当前所属队伍会更新。`)) return;
  const button = event.currentTarget; button.disabled = true;
  try {
    await request(`/api/v1/admin/users/${encodeURIComponent(user.id || user.username)}`, { method: "PATCH", body: JSON.stringify({ teamId: teamID }) });
    showToast("选手已加入当前赛事"); await loadData({ quiet: true });
  } catch (error) { showSectionError("#teams-message", `加入选手失败：${error.message}`); button.disabled = false; }
});
$("#vehicle-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const providerDefinition = $("#vehicle-definition").value; const payload = { vehicleDefinitionId: providerDefinition, label: $("#vehicle-label").value.trim() };
  if (!payload.vehicleDefinitionId) { showToast(state.vehicleCatalog.length ? "请选择车辆定义" : "暂无本地展示车辆定义", true); return; }
  if (!payload.label) { showToast("请填写实例名称", true); return; }
  const button = form.querySelector("button"); button.disabled = true;
  try {
    await request(`/api/v1/admin/competitions/${RESOURCE_LIBRARY_ID}/vehicles`, { method: "POST", body: JSON.stringify(payload) });
    form.reset(); showToast("赛事公共车辆已创建，请到题目库绑定");
    await loadData({ quiet: true });
  } catch (error) { showToast(`创建车辆失败：${error.message}`, true); }
  finally { button.disabled = false; renderAssets(); }
});
$("#import-carpack").addEventListener("click", async () => {
  const file = $("#carpack-file").files?.[0]; if (!file) return;
  const button = $("#import-carpack"); button.disabled = true; clearSectionError("#challenges-message");
  try {
    await request(`/api/v1/admin/competitions/${RESOURCE_LIBRARY_ID}/challenges/import`, { method: "POST", body: file, raw: true, headers: { "Content-Type": "application/octet-stream" } });
    $("#carpack-file").value = ""; $("label[for='carpack-file']").textContent = "选择 CARPACK（兼容导入）"; showToast("CARPACK 已校验并导入为草稿"); await loadData({ quiet: true });
  } catch (error) { showSectionError("#challenges-message", `导入失败：${error.message}`); }
  finally { renderChallenges(); }
});
const newChallengeDialog = $("#new-challenge-dialog"); const newChallengeForm = $("#new-challenge-form");
function renderNewChallengeActions() {
  const container = $("#new-challenge-visual-actions");
  if (!container) return;
  container.replaceChildren();
  VISUAL_ACTION_OPTIONS.forEach((action) => {
    const label = document.createElement("label"); label.className = "challenge-visual-option";
    const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.dataset.newChallengeAction = action.id; checkbox.checked = action.id === "solve-scan";
    label.append(checkbox, document.createTextNode(action.label)); container.append(label);
  });
}
function imageExposedPorts(image) {
  const ports = Array.isArray(image?.exposedPorts) ? image.exposedPorts : Array.isArray(image?.exposed_ports) ? image.exposed_ports : [];
  return ports.map((item) => ({ port: number(item?.port, 0), protocol: String(item?.protocol || "").toLowerCase() }))
    .filter((item) => item.port >= 1 && item.port <= 65535 && ["tcp", "udp", "sctp"].includes(item.protocol));
}
function syncNewChallengeEntryPort() {
  const imageSelect = $("#new-challenge-image"); const entryPort = $("#new-challenge-entry-port"); const note = $("#new-challenge-entry-port-note");
  if (!imageSelect || !entryPort || !note) return;
  const remote = String(valueOf(state.systemSettings || {}, "dockerMode", "docker_mode") || "local") === "remote";
  const target = remote ? "远程节点镜像" : "本机镜像";
  const image = state.localImages.find((item) => String(item.id) === String(imageSelect.value));
  const tcpPorts = imageExposedPorts(image).filter((item) => item.protocol === "tcp");
  if (tcpPorts.length) {
    entryPort.value = String(tcpPorts[0].port);
    entryPort.dataset.autoDetected = "true";
    note.textContent = tcpPorts.length === 1
      ? `已从镜像 EXPOSE 自动识别：${tcpPorts[0].port}/tcp。`
      : `已自动选择 ${tcpPorts[0].port}/tcp；镜像还声明了 ${tcpPorts.slice(1).map((item) => `${item.port}/tcp`).join("、")}，如题目入口不同可手动修改。`;
    return;
  }
  if (entryPort.dataset.autoDetected === "true") entryPort.value = "";
  delete entryPort.dataset.autoDetected;
  note.textContent = image ? "该镜像没有声明 TCP EXPOSE，请手动填写容器实际监听端口。" : `先选择${target}，平台会读取 Docker EXPOSE 的 TCP 端口。`;
}
function renderNewChallengeOptions() {
  const imageSelect = $("#new-challenge-image");
  const kvmSelect = $("#new-challenge-kvm-artifact");
  const remote = String(valueOf(state.systemSettings || {}, "dockerMode", "docker_mode") || "local") === "remote";
  const target = remote ? "远程节点" : "本机节点";
  const imageTarget = remote ? "远程节点镜像" : "本机镜像";
  const imageError = String(state.imageCatalogError || "").trim();
  setText("#new-challenge-source-title", `选择${imageTarget}创建真实题目`);
  setText("#new-challenge-image-label", imageTarget);
  setText("#new-challenge-image-note", imageError ? `${target} Docker 镜像目录不可用：${imageError}` : `显示当前${target}已有的 Docker 镜像，启动时不会拉取镜像。`);
  if (imageSelect) {
    const selected = imageSelect.value;
    const emptyLabel = imageError ? `${imageTarget}目录不可用` : state.localImages.length ? `选择${imageTarget}` : `未发现${imageTarget}`;
    imageSelect.replaceChildren(new Option(emptyLabel, ""));
    state.localImages.forEach((image) => { const exposed = imageExposedPorts(image); const portLabel = exposed.length ? ` · EXPOSE ${exposed.map((item) => `${item.port}/${item.protocol}`).join(",")}` : ""; const reference = image.reference || (image.repository && image.repository !== "<none>" ? `${image.repository}${image.tag && image.tag !== "<none>" ? `:${image.tag}` : ""}` : image.id); const label = `${reference || "未命名镜像"} · ${String(image.id || "").slice(0, 19)}${image.size ? ` · ${image.size}` : ""}${portLabel}`; imageSelect.add(new Option(label, image.id)); });
    if ([...imageSelect.options].some((option) => option.value === selected)) imageSelect.value = selected;
  }
  if (kvmSelect) {
    const selected = kvmSelect.value;
  kvmSelect.replaceChildren(new Option(state.kvmArtifacts.length ? "选择本地 KVM 镜像" : "未发现已上传的 KVM 镜像", ""));
  state.kvmArtifacts.forEach((artifact) => kvmSelect.add(new Option(`${artifact.title || artifact.slug || "未命名镜像"} · ${artifact.slug || "—"} · ${artifact.memoryMiB || "—"} MiB · ${artifact.vcpus || "—"} vCPU · TCP ${artifact.entryPort || "—"}`, artifact.digest)));
    if ([...kvmSelect.options].some((option) => option.value === selected)) kvmSelect.value = selected;
  }
  syncNewChallengeEntryPort();
  updateNewChallengeRuntime();
}
function updateNewChallengeRuntime() {
  const kind = $("#new-challenge-runtime-kind")?.value || "container";
  const attachment = kind === "attachment";
  const kvm = kind === "qemu-microvm";
  document.querySelectorAll("[data-runtime-container-settings]").forEach((node) => {
    node.hidden = attachment || kvm;
    node.querySelectorAll("input, select").forEach((input) => { input.disabled = attachment || kvm; });
  });
  document.querySelectorAll("[data-runtime-kvm-settings]").forEach((node) => {
    node.hidden = !kvm;
    node.querySelectorAll("input, select").forEach((input) => { input.disabled = !kvm; });
  });
  const image = $("#new-challenge-image");
  const artifact = $("#new-challenge-kvm-artifact");
  const entryPort = $("#new-challenge-entry-port");
  const kvmPorts = $("#new-challenge-kvm-ports");
  if (image) image.required = !attachment && !kvm;
  if (artifact) artifact.required = kvm;
  if (entryPort) { entryPort.required = !attachment; entryPort.disabled = attachment; entryPort.closest(".field")?.classList.toggle("is-disabled", attachment); }
  if (kvmPorts) { kvmPorts.disabled = !kvm; kvmPorts.closest(".field")?.classList.toggle("is-disabled", !kvm); }
  setText("#new-challenge-entry-port-label", kvm ? "KVM 入口端口" : "容器入口端口");
  setText("#new-challenge-entry-port-note", kvm ? "填写虚拟机内服务监听的端口，平台会映射到选手访问端口。" : "选择镜像后平台会读取 Docker EXPOSE 的 TCP 端口，也可手动调整。");
  const protocol = $("#new-challenge-protocol");
  if (protocol) { protocol.disabled = attachment; if (attachment) protocol.value = "none"; else if (protocol.value === "none") protocol.value = "tcp"; }
  const flagMode = $("#new-challenge-flag-mode");
  if (flagMode) {
    const staticOption = flagMode.querySelector('option[value="static"]');
    if (staticOption) staticOption.disabled = attachment;
    if (attachment) flagMode.value = "static";
  }
  setText("#new-challenge-source-title", attachment ? "创建纯附件题，不启动运行环境" : kvm ? "选择本地 KVM 镜像创建虚拟机靶场" : "选择 Docker 节点镜像创建容器靶场");
  setText("#new-challenge-runtime-note", attachment ? "发布前必须上传至少一个附件；选手下载附件后直接提交固定 Flag。" : kvm ? "KVM 题目由 187 的 KVM Worker 启动，每支队伍独立运行。" : "Docker 题启动时由 Docker 节点创建独立靶场。");
  setText("#new-challenge-runtime-help", attachment ? "纯附件题不分配容器端口。创建草稿后，在题目编辑窗口上传附件，再绑定展示车辆并发布。" : kvm ? "KVM 镜像包含 kernel、rootfs、入口端口和资源参数，不会从 Docker 节点拉取镜像。" : "车辆不在此处绑定。创建题目后，到题目列表右侧的“绑定车辆”中选择车辆库实例；这样题目库和车辆库可以按任意顺序维护。");
}
function closeNewChallengeDialog() {
  newChallengeDialog.close(); newChallengeForm.reset(); $("#new-challenge-container-name").dataset.touched = ""; $("#new-challenge-dialog-message").hidden = true; renderNewChallengeActions(); updateNewChallengeRuntime();
}
$("#new-challenge-button").addEventListener("click", () => { newChallengeForm.reset(); $("#new-challenge-container-name").dataset.touched = ""; $("#new-challenge-dialog-message").hidden = true; renderNewChallengeOptions(); renderNewChallengeActions(); updateNewChallengeRuntime(); newChallengeDialog.showModal(); requestAnimationFrame(() => $("#new-challenge-slug").focus()); });
$("#close-new-challenge-dialog").addEventListener("click", closeNewChallengeDialog);
$("#cancel-new-challenge-dialog").addEventListener("click", closeNewChallengeDialog);
newChallengeDialog.addEventListener("click", (event) => { if (event.target === newChallengeDialog) closeNewChallengeDialog(); });
$("#new-challenge-slug").addEventListener("input", (event) => { const container = $("#new-challenge-container-name"); if (container && !container.dataset.touched) container.value = event.target.value.trim(); });
$("#new-challenge-container-name").addEventListener("input", (event) => { event.target.dataset.touched = "true"; });
$("#new-challenge-image").addEventListener("change", syncNewChallengeEntryPort);
$("#new-challenge-runtime-kind").addEventListener("change", updateNewChallengeRuntime);
newChallengeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const runtimeKind = $("#new-challenge-runtime-kind").value;
  const attachmentOnly = runtimeKind === "attachment";
  const kvmTarget = runtimeKind === "qemu-microvm";
  const required = [$("#new-challenge-slug"), $("#new-challenge-title"), $("#new-challenge-score"), $("#new-challenge-vcpus"), $("#new-challenge-memory"), $("#new-challenge-disk"), $("#new-challenge-runtime")];
  if (!attachmentOnly && !kvmTarget) required.push($("#new-challenge-image"), $("#new-challenge-entry-port"));
  if (kvmTarget) required.push($("#new-challenge-kvm-artifact"));
  const missing = required.find((field) => !String(field?.value || "").trim());
  if (missing) { $("#new-challenge-dialog-message").textContent = kvmTarget ? "请填写题目标识、名称并选择本地 KVM 镜像。" : "请填写题目标识、名称、当前节点镜像和运行参数。车辆可创建后再绑定。"; $("#new-challenge-dialog-message").hidden = false; missing.focus(); return; }
  const flagMode = attachmentOnly ? "static" : $("#new-challenge-flag-mode").value; const staticFlag = $("#new-challenge-static-flag").value;
  if (flagMode === "static" && !staticFlag) { $("#new-challenge-dialog-message").textContent = "静态 Flag 题目必须填写固定 Flag。"; $("#new-challenge-dialog-message").hidden = false; $("#new-challenge-static-flag").focus(); return; }
  const button = $("#create-challenge-button"); button.disabled = true; button.textContent = "校验中"; $("#new-challenge-dialog-message").hidden = true;
  const guestPorts = kvmTarget ? [Number($("#new-challenge-entry-port").value), ...String($("#new-challenge-kvm-ports")?.value || "").split(",").map((value) => Number(value.trim())).filter((value) => Number.isInteger(value) && value > 0 && value <= 65535)] : [];
  const uniqueGuestPorts = [...new Set(guestPorts)];
  if (kvmTarget && (uniqueGuestPorts.length < 1 || uniqueGuestPorts.length > 16)) { $("#new-challenge-dialog-message").textContent = "KVM 至少需要 1 个端口，最多 16 个；请检查端口列表。"; $("#new-challenge-dialog-message").hidden = false; button.disabled = false; button.textContent = "校验并创建题目"; return; }
  const payload = {
    slug: $("#new-challenge-slug").value.trim(), title: $("#new-challenge-title").value.trim(), description: $("#new-challenge-description").value.trim(),
    runtimeKind, containerName: $("#new-challenge-container-name").value.trim(), imageReference: runtimeKind === "container" ? $("#new-challenge-image").value : "", artifactDigest: kvmTarget ? $("#new-challenge-kvm-artifact").value : "",
    accessProtocol: attachmentOnly ? "none" : $("#new-challenge-protocol").value, flagMode, entryPort: attachmentOnly ? 0 : Number($("#new-challenge-entry-port").value), baseScore: Number($("#new-challenge-score").value),
    portMappings: kvmTarget ? uniqueGuestPorts.map((guestPort) => ({ protocol: "tcp", guestPort })) : [],
    vcpus: Number($("#new-challenge-vcpus").value), memoryMb: Number($("#new-challenge-memory").value), diskMb: Number($("#new-challenge-disk").value), maxRuntimeSeconds: Number($("#new-challenge-runtime").value),
    visualActions: [...document.querySelectorAll("[data-new-challenge-action]:checked")].map((input) => input.dataset.newChallengeAction),
  };
  if (staticFlag) payload.staticFlag = staticFlag;
  try {
    await request(`/api/v1/admin/competitions/${RESOURCE_LIBRARY_ID}/challenges`, { method: "POST", body: JSON.stringify(payload) });
    closeNewChallengeDialog(); showToast(attachmentOnly ? "纯附件题草稿已创建，请在编辑窗口上传附件" : kvmTarget ? "KVM 靶机题目已创建为草稿" : "Docker 镜像题目已创建为草稿"); await loadData({ quiet: true });
  } catch (error) { $("#new-challenge-dialog-message").textContent = error.message; $("#new-challenge-dialog-message").hidden = false; }
  finally { button.disabled = false; button.textContent = "校验并创建题目"; }
});
$("#challenge-library").addEventListener("click", async (event) => {
  const pageButton = event.target.closest("[data-challenge-page]");
  if (pageButton) {
    const page = Number(pageButton.dataset.challengePage);
    if (Number.isInteger(page) && page >= 1) {
      state.challengeLibraryPage = page;
      renderChallenges();
      $("#challenge-list-title")?.scrollIntoView({ block: "start", behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
    }
    return;
  }
  const rowScope = event.target.closest("[data-challenge-scope]")?.dataset.challengeScope || RESOURCE_LIBRARY_ID;
  const scopedChallenges = rowScope === RESOURCE_LIBRARY_ID ? state.libraryChallenges : state.challenges;
  const deleteButton = event.target.closest("[data-delete-challenge]");
  if (deleteButton) {
    const challengeID = deleteButton.dataset.deleteChallenge;
    const challenge = scopedChallenges.find((item) => String(item.id) === String(challengeID));
    if (!challenge) return;
    if (!window.confirm("确认物理删除题目“" + (challenge.title || challenge.slug || challengeID) + "”吗？题目附件、车辆绑定、运行记录、提交记录和成绩都会删除，且不可恢复。")) return;
    deleteButton.disabled = true;
    try {
      await request("/api/v1/admin/competitions/" + encodeURIComponent(rowScope) + "/challenges/" + encodeURIComponent(challengeID), { method: "DELETE" });
      showToast("题目及相关历史记录已删除"); await loadData({ quiet: true });
    } catch (error) { showToast("删除题目失败：" + error.message, true); deleteButton.disabled = false; }
    return;
  }
  const editButton = event.target.closest("[data-edit-challenge]");
  if (editButton) {
    openChallengeDialog(scopedChallenges.find((item) => String(item.id) === String(editButton.dataset.editChallenge)), rowScope);
    return;
  }
  const visualButton = event.target.closest("[data-save-visual-actions]");
  if (visualButton) {
    const challengeID = visualButton.dataset.saveVisualActions;
    const visualActions = [...document.querySelectorAll(`[data-visual-challenge="${CSS.escape(challengeID)}"]:checked`)].map((input) => input.dataset.visualAction).filter(Boolean);
    visualButton.disabled = true;
    try {
      await request(`/api/v1/admin/competitions/${encodeURIComponent(rowScope)}/challenges/${encodeURIComponent(challengeID)}`, { method: "PATCH", body: JSON.stringify({ visualActions }) });
      showToast("题目通关动作已保存");
      await loadData({ quiet: true });
    } catch (error) { showToast(`保存动作失败：${error.message}`, true); visualButton.disabled = false; }
    return;
  }
  const bindButton = event.target.closest("[data-bind-challenge]");
  if (bindButton) {
    const challengeID = bindButton.dataset.bindChallenge; const select = bindButton.closest(".challenge-admin-row")?.querySelector("[data-bind-challenge-select]"); const vehicleInstanceID = select?.value;
    if (!vehicleInstanceID) { showToast("请选择车辆库中的车辆", true); return; }
    bindButton.disabled = true;
    try {
      const challenge = scopedChallenges.find((item) => item.id === challengeID);
      const existing = (challenge?.boundVehicleInstanceIds || []).filter((id) => id !== vehicleInstanceID);
      const vehicles = rowScope === RESOURCE_LIBRARY_ID ? state.libraryVehicles : state.vehicles;
      for (const oldVehicleID of existing) {
        await request(`/api/v1/admin/competitions/${encodeURIComponent(rowScope)}/challenges/${encodeURIComponent(challengeID)}/vehicles/${encodeURIComponent(oldVehicleID)}`, { method: "DELETE" });
      }
      if (!vehicles.some((vehicle) => String(vehicle.id) === String(vehicleInstanceID))) throw new Error("车辆不在当前题目作用域中");
      await request(`/api/v1/admin/competitions/${encodeURIComponent(rowScope)}/challenges/${encodeURIComponent(challengeID)}/vehicles`, { method: "POST", body: JSON.stringify({ vehicleInstanceId: vehicleInstanceID }) });
      showToast(existing.length ? "题目车辆绑定已切换" : "题目已绑定车辆库车辆"); await loadData({ quiet: true });
    }
    catch (error) { showToast(`绑定车辆失败：${error.message}`, true); bindButton.disabled = false; }
    return;
  }
  const button = event.target.closest("[data-publish-challenge]"); if (!button) return;
  button.disabled = true; clearSectionError("#challenges-message");
  try { await request(`/api/v1/admin/competitions/${encodeURIComponent(rowScope)}/challenges/${encodeURIComponent(button.dataset.publishChallenge)}/publish`, { method: "POST" }); showToast("题目已发布"); await loadData({ quiet: true }); }
  catch (error) { showSectionError("#challenges-message", `发布失败：${error.message}`); button.disabled = false; }
});
$("#logout-button").addEventListener("click", async () => { const button = $("#logout-button"); button.disabled = true; button.textContent = "正在退出"; try { await request(API.logout, { method: "POST" }); window.location.replace("/login.html"); } catch (error) { showToast(`退出失败：${error.message}`, true); button.disabled = false; button.textContent = "退出登录"; } });

$("#users-table").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-user-action]"); if (!button) return; const { userAction, userId, nextStatus } = button.dataset;
  if (userAction === "edit") { const user = state.users.find((item) => String(item.id || item.username) === userId); if (user) openUserDialog(user); return; }
  if (userAction === "delete") { await deleteUsers([userId]); return; }
  const verb = nextStatus === "active" ? "启用" : "停用";
  if (!window.confirm(`确认${verb}账号“${userId}”吗？该操作将写入审计记录。`)) return;
  state.busyUsers.add(userId); renderUsers();
  try { await request(`${API.users}/${encodeURIComponent(userId)}`, { method: "PATCH", body: JSON.stringify({ active: nextStatus === "active" }) }); showToast(`账号已${verb}`); await loadData({ quiet: true }); } catch (error) { showToast(`${verb}失败：${error.message}`, true); } finally { state.busyUsers.delete(userId); renderUsers(); }
});
$("#users-table").addEventListener("change", (event) => { if (event.target.matches("[data-user-select]")) syncBulkDeleteControls(); });
$("#select-all-users").addEventListener("change", (event) => { document.querySelectorAll("[data-user-select]").forEach((input) => { input.checked = event.target.checked; }); syncBulkDeleteControls(); });
$("#team-list").addEventListener("change", (event) => { if (event.target.matches("[data-team-select]")) syncBulkDeleteControls(); });
$("#select-all-teams").addEventListener("change", (event) => { document.querySelectorAll("[data-team-select]").forEach((input) => { input.checked = event.target.checked; }); syncBulkDeleteControls(); });
$("#competition-team-list").addEventListener("change", (event) => { if (event.target.matches("[data-competition-team-select]")) syncBulkDeleteControls(); });
$("#select-all-competition-teams").addEventListener("change", (event) => { document.querySelectorAll("[data-competition-team-select]").forEach((input) => { input.checked = event.target.checked; }); syncBulkDeleteControls(); });
$("#delete-selected-users").addEventListener("click", () => deleteUsers(selectedIDs("[data-user-select]")));
$("#delete-selected-teams").addEventListener("click", () => deleteTeams(selectedIDs("[data-team-select]")));
$("#delete-selected-competition-teams").addEventListener("click", () => deleteTeams(selectedIDs("[data-competition-team-select]"), state.competition?.id));

async function deleteUsers(ids) {
  ids = [...new Set(ids)].filter(Boolean); if (!ids.length) return;
  const names = ids.map((id) => state.users.find((user) => String(user.id || user.username) === id)?.username || id).join("、");
  if (!window.confirm(`确认物理删除 ${ids.length} 个账号（${names}）吗？会话、账号数据将永久删除，无法恢复。`)) return;
  ids.forEach((id) => state.busyUsers.add(id)); renderUsers();
  try {
    await request(ids.length === 1 ? `${API.users}/${encodeURIComponent(ids[0])}` : `${API.users}/batch-delete`, { method: ids.length === 1 ? "DELETE" : "POST", body: ids.length === 1 ? undefined : JSON.stringify({ userIds: ids }) });
    showToast(`已物理删除 ${ids.length} 个账号`); await loadData({ quiet: true });
  } catch (error) { showToast(`物理删除账号失败：${error.message}`, true); }
  finally { ids.forEach((id) => state.busyUsers.delete(id)); renderUsers(); }
}

async function deleteTeams(ids, competitionIDOverride = "") {
  ids = [...new Set(ids)].filter(Boolean); if (!ids.length) return;
  const names = ids.map((id) => state.libraryTeams.find((team) => String(team.id) === id)?.name || state.teams.find((team) => String(team.id) === id)?.name || id).join("、");
  const matched = state.libraryTeams.find((team) => ids.includes(String(team.id)));
  const competitionID = competitionIDOverride || matched?.competitionId || matched?.competition_id || RESOURCE_LIBRARY_ID;
  if (!window.confirm(`确认物理删除 ${ids.length} 支队伍（${names}）吗？成员账号、车辆、成绩、提交及运行记录将永久删除，无法恢复。`)) return;
  ids.forEach((id) => state.busyTeams.add(id)); renderAssets();
  try {
    await request(`/api/v1/admin/competitions/${encodeURIComponent(competitionID)}/teams/${ids.length === 1 ? encodeURIComponent(ids[0]) : "batch-delete"}`, { method: ids.length === 1 ? "DELETE" : "POST", body: ids.length === 1 ? undefined : JSON.stringify({ teamIds: ids }) });
    showToast(`已物理删除 ${ids.length} 支队伍`); await loadData({ quiet: true });
  } catch (error) { showToast(`物理删除队伍失败：${error.message}`, true); }
  finally { ids.forEach((id) => state.busyTeams.delete(id)); renderAssets(); }
}

const dialog = $("#user-dialog"); const userForm = $("#user-form");
function closeDialog() { dialog.close(); userForm.reset(); state.editingUserId = null; $("#dialog-message").hidden = true; userForm.querySelectorAll("[aria-invalid]").forEach((input) => input.removeAttribute("aria-invalid")); }
function openUserDialog(user = null) {
  state.editingUserId = user ? String(user.id || user.username) : null;
  userForm.reset(); $("#dialog-message").hidden = true;
  const editing = Boolean(user); $("#dialog-kicker").textContent = editing ? "账号维护 / 权限与凭据" : "账号登记 / 新建身份"; $("#dialog-title").textContent = editing ? "编辑平台用户" : "新增平台用户"; $("#save-user-button").textContent = editing ? "保存修改" : "创建用户";
  const password = $("#new-password"); password.required = !editing; password.value = ""; password.placeholder = editing ? "留空则保持原密码" : ""; $("#password-label").textContent = editing ? "重置密码（可选）" : "初始密码"; $("#password-help").textContent = editing ? "留空则不修改；填写后会撤销该账号的现有会话" : "至少 12 个字符、最多 72 个 UTF-8 字节，请通过安全渠道交付";
  if (editing) { $("#new-username").value = user.username || ""; $("#new-display-name").value = userName(user); $("#new-role").value = String(user.role || "team").toLowerCase(); $("#new-team").value = userTeamID(user); }
  dialog.showModal(); requestAnimationFrame(() => $("#new-username").focus());
}
$("#open-user-dialog").addEventListener("click", () => openUserDialog());
$("#close-user-dialog").addEventListener("click", closeDialog); $("#cancel-user-dialog").addEventListener("click", closeDialog);
dialog.addEventListener("click", (event) => { if (event.target === dialog) closeDialog(); });
userForm.addEventListener("submit", async (event) => {
  event.preventDefault(); const fields = { username: $("#new-username"), displayName: $("#new-display-name"), password: $("#new-password") }; const editing = Boolean(state.editingUserId); let invalid = false;
  [fields.username, fields.displayName, ...(!editing ? [fields.password] : [])].forEach((input) => { const emptyValue = !input.value.trim(); input.toggleAttribute("aria-invalid", emptyValue); invalid ||= emptyValue; });
  if (invalid) { $("#dialog-message").textContent = "请填写全部必填字段。"; $("#dialog-message").hidden = false; return; }
  const button = $("#save-user-button"); button.disabled = true; button.textContent = editing ? "正在保存" : "正在创建"; $("#dialog-message").hidden = true;
  const role = $("#new-role").value; const payload = { username: fields.username.value.trim(), displayName: fields.displayName.value.trim(), role, teamId: role === "team" ? ($("#new-team").value || null) : null }; if (fields.password.value) payload.password = fields.password.value;
  try {
    const path = editing ? `${API.users}/${encodeURIComponent(state.editingUserId)}` : API.users; await request(path, { method: editing ? "PATCH" : "POST", body: JSON.stringify(payload) }); const changedSelf = editing && state.editingUserId === String(state.me?.id || state.me?.userId || ""); closeDialog(); showToast(editing ? "用户资料已更新，现有会话已撤销" : "用户创建成功"); if (changedSelf) { window.location.replace("/login.html"); return; } await loadData({ quiet: true });
  } catch (error) { $("#dialog-message").textContent = error.message; $("#dialog-message").hidden = false; } finally { button.disabled = false; button.textContent = editing ? "保存修改" : "创建用户"; }
});

const challengeDialog = $("#challenge-dialog"); const challengeForm = $("#challenge-form");
function formatAttachmentSize(bytes) {
  const value = Number(bytes || 0);
  if (!Number.isFinite(value) || value < 1024) return `${value || 0} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}
function renderChallengeAttachments(challenge) {
  const list = $("#challenge-edit-attachments");
  if (!list) return;
  list.replaceChildren();
  const attachments = challengeAttachments(challenge);
  if (!attachments.length) { const empty = document.createElement("span"); empty.className = "attachment-empty"; empty.textContent = "暂无附件"; list.append(empty); return; }
  attachments.forEach((attachment) => {
    const row = document.createElement("div"); row.className = "challenge-attachment-item";
    const name = document.createElement("strong"); name.textContent = attachment.filename || attachment.id || "未命名附件";
    const meta = document.createElement("small"); meta.textContent = `${formatAttachmentSize(attachment.sizeBytes)} · ${formatDate(attachment.createdAt)}`;
    const open = document.createElement("a"); open.href = attachment.downloadPath || "#"; open.target = "_blank"; open.rel = "noopener noreferrer"; open.textContent = "下载";
    const remove = document.createElement("button"); remove.type = "button"; remove.dataset.deleteChallengeAttachment = attachment.id; remove.textContent = "删除";
    row.append(name, meta, open, remove); list.append(row);
  });
}
function updateChallengeFlagEditor() {
  const mode = $("#challenge-edit-flag-mode")?.value || "dynamic";
  const input = $("#challenge-edit-static-flag"); const help = $("#challenge-edit-flag-help");
  if (!input || !help) return;
  const isStatic = mode === "static";
  input.disabled = !isStatic;
  $("#challenge-edit-flag-mode").disabled = false;
	help.textContent = isStatic ? "静态 Flag 仅加密保存用于提交校验；固定答案应预置在题目镜像或附件中，平台不会注入容器。已有值不会回显。" : "动态 Flag 按赛事、队伍和运行代次生成，启动动态题目时通过 FLAG 环境变量注入容器。切换为动态会清除已配置的静态 Flag。";
}
function closeChallengeDialog() {
  challengeDialog.close(); challengeForm.reset(); state.editingChallengeId = null; state.editingChallengeScope = RESOURCE_LIBRARY_ID;
  $("#challenge-dialog-message").hidden = true;
  $("#challenge-edit-attachments")?.replaceChildren();
  challengeForm.querySelectorAll("[aria-invalid]").forEach((input) => input.removeAttribute("aria-invalid"));
}
function openChallengeDialog(challenge, scopeID = RESOURCE_LIBRARY_ID) {
  if (!challenge) return;
  state.editingChallengeId = String(challenge.id);
  state.editingChallengeScope = scopeID || RESOURCE_LIBRARY_ID;
  challengeForm.reset(); $("#challenge-dialog-message").hidden = true;
  $("#challenge-edit-title").value = challenge.title || "";
  $("#challenge-edit-container-name").value = challengeContainerName(challenge);
  $("#challenge-edit-access-protocol").value = challengeAccessProtocol(challenge);
  $("#challenge-edit-slug").value = challenge.slug || challenge.id || "";
  $("#challenge-edit-description").value = challenge.description || "";
  $("#challenge-edit-flag-mode").value = challengeFlagMode(challenge);
  $("#challenge-edit-static-flag").value = "";
  $("#challenge-edit-has-attachments").checked = Boolean(challenge.hasAttachments || challengeAttachments(challenge).length);
  $("#challenge-edit-attachment-name").textContent = "未选择文件，单个附件最大 64 MiB";
  renderChallengeAttachments(challenge); updateChallengeFlagEditor();
  challengeDialog.showModal(); requestAnimationFrame(() => $("#challenge-edit-title").focus());
}
$("#close-challenge-dialog").addEventListener("click", closeChallengeDialog);
$("#cancel-challenge-dialog").addEventListener("click", closeChallengeDialog);
challengeDialog.addEventListener("click", (event) => { if (event.target === challengeDialog) closeChallengeDialog(); });
$("#challenge-edit-flag-mode").addEventListener("change", updateChallengeFlagEditor);
$("#challenge-edit-attachment").addEventListener("change", (event) => { const file = event.target.files?.[0]; $("#challenge-edit-attachment-name").textContent = file ? `${file.name} · ${formatAttachmentSize(file.size)}` : "未选择文件，单个附件最大 64 MiB"; });
$("#upload-challenge-attachment").addEventListener("click", async () => {
  const file = $("#challenge-edit-attachment").files?.[0];
  if (!file || !state.editingChallengeId) { $("#challenge-dialog-message").textContent = "请先选择附件文件。"; $("#challenge-dialog-message").hidden = false; return; }
  const button = $("#upload-challenge-attachment"); button.disabled = true; button.textContent = "上传中"; $("#challenge-dialog-message").hidden = true;
  try {
    const form = new FormData(); form.append("file", file);
    await request(`/api/v1/admin/competitions/${encodeURIComponent(state.editingChallengeScope)}/challenges/${encodeURIComponent(state.editingChallengeId)}/attachments`, { method: "POST", body: form, raw: true });
    $("#challenge-edit-attachment").value = ""; $("#challenge-edit-attachment-name").textContent = "未选择文件，单个附件最大 64 MiB";
    await loadData({ quiet: true });
    const source = state.editingChallengeScope === RESOURCE_LIBRARY_ID ? state.libraryChallenges : state.challenges;
    const challenge = source.find((item) => String(item.id) === String(state.editingChallengeId)); if (challenge) { $("#challenge-edit-has-attachments").checked = true; renderChallengeAttachments(challenge); }
    showToast("附件上传成功");
  } catch (error) { $("#challenge-dialog-message").textContent = error.message; $("#challenge-dialog-message").hidden = false; }
  finally { button.disabled = false; button.textContent = "上传附件"; }
});
$("#challenge-edit-attachments").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-delete-challenge-attachment]");
  if (!button || !state.editingChallengeId) return;
  if (!window.confirm("确认删除这个题目附件吗？选手将无法继续下载它。")) return;
  button.disabled = true;
  try {
    await request(`/api/v1/admin/competitions/${encodeURIComponent(state.editingChallengeScope)}/challenges/${encodeURIComponent(state.editingChallengeId)}/attachments/${encodeURIComponent(button.dataset.deleteChallengeAttachment)}`, { method: "DELETE" });
    showToast("题目附件已删除"); await loadData({ quiet: true });
    const source = state.editingChallengeScope === RESOURCE_LIBRARY_ID ? state.libraryChallenges : state.challenges;
    const challenge = source.find((item) => String(item.id) === String(state.editingChallengeId)); if (challenge) { $("#challenge-edit-has-attachments").checked = challengeAttachments(challenge).length > 0; renderChallengeAttachments(challenge); }
  } catch (error) { showToast(`删除附件失败：${error.message}`, true); button.disabled = false; }
});
challengeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = [$("#challenge-edit-title"), $("#challenge-edit-container-name")];
  let invalid = false;
  fields.forEach((input) => { const emptyValue = !input.value.trim(); input.toggleAttribute("aria-invalid", emptyValue); invalid ||= emptyValue; });
  if (invalid) { $("#challenge-dialog-message").textContent = "题目名称和容器名称不能为空。"; $("#challenge-dialog-message").hidden = false; return; }
  if (!state.editingChallengeId) return;
  const currentChallenges = state.editingChallengeScope === RESOURCE_LIBRARY_ID ? state.libraryChallenges : state.challenges;
  const currentChallenge = currentChallenges.find((item) => String(item.id) === String(state.editingChallengeId));
  const flagMode = $("#challenge-edit-flag-mode").value;
  const staticFlag = $("#challenge-edit-static-flag").value;
  if (flagMode === "static" && challengeFlagMode(currentChallenge) !== "static" && !staticFlag) { $("#challenge-dialog-message").textContent = "切换为静态 Flag 时必须填写固定 Flag。"; $("#challenge-dialog-message").hidden = false; $("#challenge-edit-static-flag").focus(); return; }
  const selectedFile = $("#challenge-edit-attachment").files?.[0];
  const existingAttachments = challengeAttachments(currentChallenge);
  if (!$("#challenge-edit-has-attachments").checked && existingAttachments.length) { $("#challenge-dialog-message").textContent = "已有附件不会因取消勾选而自动删除，请在附件列表中逐个删除。"; $("#challenge-dialog-message").hidden = false; return; }
  if ($("#challenge-edit-has-attachments").checked && !existingAttachments.length && !selectedFile) { $("#challenge-dialog-message").textContent = "已勾选‘题目包含附件’，请先选择文件并上传附件。"; $("#challenge-dialog-message").hidden = false; $("#challenge-edit-attachment").focus(); return; }
  const button = $("#save-challenge-button"); button.disabled = true; button.textContent = "正在保存"; $("#challenge-dialog-message").hidden = true;
  const payload = {
    title: $("#challenge-edit-title").value.trim(),
    containerName: $("#challenge-edit-container-name").value.trim(),
    accessProtocol: $("#challenge-edit-access-protocol").value,
    description: $("#challenge-edit-description").value.trim(),
    flagMode,
  };
  if (staticFlag) payload.staticFlag = staticFlag;
  try {
    await request(`/api/v1/admin/competitions/${encodeURIComponent(state.editingChallengeScope)}/challenges/${encodeURIComponent(state.editingChallengeId)}`, { method: "PATCH", body: JSON.stringify(payload) });
    if (selectedFile) {
      const form = new FormData(); form.append("file", selectedFile);
      await request(`/api/v1/admin/competitions/${encodeURIComponent(state.editingChallengeScope)}/challenges/${encodeURIComponent(state.editingChallengeId)}/attachments`, { method: "POST", body: form, raw: true });
    }
    closeChallengeDialog(); showToast(selectedFile ? "题目设置和附件已保存" : "题目设置已保存"); await loadData({ quiet: true });
  } catch (error) {
    $("#challenge-dialog-message").textContent = error.message; $("#challenge-dialog-message").hidden = false;
  } finally { button.disabled = false; button.textContent = "保存修改"; }
});

$("#menu-button").addEventListener("click", (event) => { const open = document.body.classList.toggle("is-menu-open"); event.currentTarget.setAttribute("aria-expanded", String(open)); });

initialize();
