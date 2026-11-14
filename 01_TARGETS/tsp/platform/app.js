"use strict";

const ASSET_VERSION = "20260814-polling-timeout-v1";
const POLL_INTERVALS = Object.freeze({
  bootstrap: 30000,
  ranking: 5000,
  attackDesktop: 15000,
  vehicleRange: 5000,
  attackTargets: 15000,
  challengeFallback: 15000,
  twinFallback: 20000,
  visualSync: 3000,
  participationRecheck: 15000,
});
const WS_RECONNECT_MAX_MS = 60000;

const state = {
  bootstrap: null,
  twin: null,
  currentUser: null,
  selectedInstanceId: null,
  participation: { eligible: true, disqualification: null },
  participationRecheck: { timer: null, inFlight: false },
  intervals: [],
  solvedBindings: new Map(),
  mechanicalBindings: new Map(),
  busy: false,
  realtime: {
    socket: null,
    instanceId: null,
    reconnectTimer: null,
    reconnectDelayMs: 1000,
  },
  challenges: {
    items: [],
    selectedId: null,
    detail: null,
    run: null,
    solve: null,
    bindingInstanceId: null,
    bindingChallengeId: null,
    events: [],
    appliedVisualKeys: new Set(),
    loading: false,
    busy: false,
    lastSequence: 0,
    stream: {
      socket: null,
      challengeId: null,
      runId: null,
      reconnectTimer: null,
      reconnectDelayMs: 1000,
      catchupPromise: null,
    },
  },
  rankingLoading: false,
  attackTargetsPayload: null,
  attackDesktopSession: null,
  vehicleRange: null,
  vehicleRangeVisual: { contextId: "", completed: new Set(), generation: 0, actionsKey: "" },
};

const ARENA_VISUAL_ACTIONS = new Set([
  "solve-scan",
  "door-open",
  "door-front-left-open",
  "door-front-right-open",
  "door-rear-left-open",
  "door-rear-right-open",
  "attack-tbox",
  "attack-gateway",
  "attack-central-compute",
  "attack-front-zone",
  "attack-rear-zone",
  "attack-bms",
]);
const MECHANICAL_VISUAL_ACTIONS = new Set([
  "door-open",
  "door-front-left-open",
  "door-front-right-open",
  "door-rear-left-open",
  "door-rear-right-open",
  "attack-tbox",
  "attack-gateway",
  "attack-central-compute",
  "attack-front-zone",
  "attack-rear-zone",
  "attack-bms",
]);
const RANGE_VISUAL_ACTION_LABELS = Object.freeze({
  "solve-scan": "验证扫描",
  "door-open": "打开车门",
  "door-front-left-open": "打开左前门",
  "door-front-right-open": "打开右前门",
  "door-rear-left-open": "打开左后门",
  "door-rear-right-open": "打开右后门",
  "attack-tbox": "攻击 T-BOX",
  "attack-gateway": "攻击中央网关",
  "attack-central-compute": "攻击中央计算",
  "attack-front-zone": "攻击前区控制器",
  "attack-rear-zone": "攻击后区控制器",
  "attack-bms": "攻击 BMS",
});
const VEHICLE_RANGE_STAGE_DETAIL_FALLBACKS = Object.freeze({
  "cloud-bola-exposed": "通过虚构 TSP 的 BOLA/IDOR 缺陷读取不属于访客账号的维护包。",
  "tbox-maintenance-session": "利用旧版 JWT 算法混淆取得受控的维护诊断票据。",
  "diagnostic-session-unlocked": "在 DoIP 上经扩展会话和 SecurityAccess 解锁受控诊断权限。",
  "legacy-route-exploited": "验证功能寻址被错误转发至物理 BCM 的缺陷。",
  "body-control-confirmed": "CGW 写入带 CRC/计数器的 CAN 车身动作，BCM ACK 由可信采集器确认。",
  "final-objective-retrieved": "在控制闭环成立后从 TSP 读取该作用域专属动态 Flag。",
  "q1-ota-package": "利用云端 IDOR 读取测试车 OTA 包和历史 PCAP 附件。",
  "q2-service-token": "从 OTA 包中提取开发态 JWT，并利用 alg=none 分支伪造服务账号凭据。",
  "q3-protocol-map": "结合 MQTT 任务报文和历史 PCAP，还原自定义二进制协议字段布局。",
  "q4-task-forged": "利用 ECDSA-P256 nonce 复用恢复任务签名私钥，并伪造越权诊断任务。",
  "q5-diag-session": "根据可推导时间种子破解 UDS SecurityAccess，建立安全诊断会话。",
  "q6-route-open": "发现并利用网关 ACL 通配测试路由，建立到动力域的 ISO-TP 诊断路径。",
  "q7-body-applied": "读取运输密钥并派生 BCM SecOC Key，构造四门解锁帧序列。",
  "q8-power-applied": "迁移 SecOC 逆向方法到动力域，构造 VCU 驻车使能帧。",
  "q9-interlock": "在 BCM 解锁与 VCU 驻车的 10 秒窗口内完成 BMS 涓流放电互锁。",
  "q10-complete": "读取最终 DID，提交由当前 generation 状态生成的动态令牌。",
});

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function report3DModuleFailure(message) {
  const stage = $("#twin-stage");
  stage?.classList.remove("is-3d-ready");
  stage?.classList.add("is-3d-failed");
  if (stage) stage.dataset.threeReady = "false";
  setText("#vehicle-3d-loading-title", "3D 模块加载失败");
  setText("#vehicle-3d-loading-detail", `${message} / 已启用二维降级`);
}

window.addEventListener("error", (event) => {
  if (String(event.filename || "").includes("vehicle-3d") || String(event.message || "").includes("GLTFLoader")) {
    report3DModuleFailure(event.message || "3D 模块运行错误");
  }
});
window.addEventListener("unhandledrejection", (event) => {
  const message = event.reason instanceof Error ? event.reason.message : String(event.reason || "3D 模块异步错误");
  if (message.includes("GLTF") || message.includes("WebGL") || message.includes("module")) report3DModuleFailure(message);
});

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function setText(selector, value) {
  // Callers may already hold a node (for example the snapshot summary).
  // Passing that node to querySelector coerces it to "[object HTML...]",
  // which is not a selector and breaks the entire competition refresh loop.
  const node = typeof selector === "string" ? $(selector) : selector;
  if (node) node.textContent = value ?? "—";
}

function vehicleRangeStageOrderLabel(stage) {
  const order = finiteNumber(stage?.order, NaN);
  return Number.isFinite(order) && order > 0 ? String(order).padStart(2, "0") : "—";
}

function vehicleRangeStageTitle(stage) {
  return stage?.title || stage?.name || stage?.key || "未命名小题";
}

function vehicleRangeStageDescription(stage) {
  return stage?.detail || stage?.description || stage?.objective || VEHICLE_RANGE_STAGE_DETAIL_FALLBACKS[stage?.key] || "该小题暂未配置赛题说明。";
}

function closeVehicleRangeStageDetail() {
  const dialog = $("#vehicle-range-stage-dialog");
  if (dialog) dialog.hidden = true;
}

function openVehicleRangeStageDetail(stage) {
  const dialog = $("#vehicle-range-stage-dialog");
  if (!dialog) return;
  const order = vehicleRangeStageOrderLabel(stage);
  setText("#vehicle-range-stage-detail-title", `${order} ${vehicleRangeStageTitle(stage)}`);
  setText("#vehicle-range-stage-detail-description", vehicleRangeStageDescription(stage));
  dialog.hidden = false;
  $(".stage-detail-close", dialog)?.focus();
}

function selectedCompetitionId() {
  const query = new URLSearchParams(location.search).get("competitionId");
  return query || sessionStorage.getItem("cybercar.selectedCompetition") || "";
}

function redirectToCompetitionSelection() {
  const next = encodeURIComponent(`${location.pathname}${location.hash}`);
  location.replace(`/competitions.html?next=${next}`);
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return String(value);
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function formatNumber(value, digits = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toFixed(digits) : "—";
}

function finiteNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function formatDecisionTime(value) {
  if (!value) return "时间未记录";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return String(value);
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function disqualificationRuleLabel(code) {
  return ({
    foreign_dynamic_flag: "提交了其他队伍的动态 Flag",
    attachment_without_download: "未下载附件即正确提交",
  })[code] || "高危作弊事件";
}

function normalizeParticipation(raw = {}) {
  const disqualification = raw?.disqualification || null;
  return {
    eligible: raw?.eligible !== false && !disqualification,
    teamId: String(raw?.teamId || raw?.team_id || disqualification?.team_id || disqualification?.teamId || ""),
    disqualification,
  };
}

function participantIsDisqualified() {
  return Boolean(state.participation?.disqualification);
}

async function api(path, options = {}) {
  const { redirectOnUnauthorized = true, ...fetchOptions } = options;
  const response = await fetch(path, {
    ...fetchOptions,
    headers: { "Content-Type": "application/json", ...(fetchOptions.headers || {}) },
  });
  let body = null;
  if (response.status !== 204) {
    const text = await response.text();
    if (text.trim()) {
      try {
        body = JSON.parse(text);
      } catch {
        if (response.ok) throw new Error(`服务器返回了无法解析的响应（HTTP ${response.status}）`);
      }
    }
  }
  if (!response.ok) {
    if (response.status === 401 && redirectOnUnauthorized) {
      const next = encodeURIComponent(`${location.pathname}${location.hash}`);
      location.replace(`/login.html?next=${next}`);
    }
    const error = new Error(body?.error?.message || `请求失败（HTTP ${response.status}）`);
    error.status = response.status;
    error.code = body?.error?.code || "request_failed";
    throw error;
  }
  return body;
}

async function requireSession() {
  try {
    const payload = await api("/api/v1/auth/me");
    const user = payload.user || payload;
    state.currentUser = user;
    setText("#current-user", user.displayName || user.display_name || user.username || "已登录");
    const adminLink = $("#admin-link");
    if (adminLink) adminLink.hidden = user.role !== "admin";
    if (String(user.role || "").toLowerCase() === "team" && !selectedCompetitionId()) {
      redirectToCompetitionSelection();
      return false;
    }
    return true;
  } catch (error) {
    if (!location.pathname.endsWith("/login.html")) showToast(error.message, true);
    return false;
  }
}

async function logout() {
  try {
    await api("/api/v1/auth/logout", { method: "POST", body: "{}" });
  } catch (error) {
    if (!String(error.message).includes("401")) showToast(error.message, true);
  } finally {
    disconnectTwinStream();
    disconnectChallengeStream();
    location.replace("/login.html");
  }
}

function closePasswordDialog() {
  const dialog = $("#password-dialog");
  if (!dialog) return;
  dialog.hidden = true;
  $("#password-form")?.reset();
  const feedback = $("#password-feedback");
  if (feedback) {
    feedback.textContent = "";
    feedback.classList.remove("is-error");
  }
}

function openPasswordDialog() {
  const dialog = $("#password-dialog");
  if (!dialog) return;
  dialog.hidden = false;
  const feedback = $("#password-feedback");
  if (feedback) {
    feedback.textContent = "新密码不少于 12 个字符，且不超过 bcrypt 72 字节限制。";
    feedback.classList.remove("is-error");
  }
  $("#password-current")?.focus();
}

function passwordPolicyError(password) {
  const characters = [...password].length;
  const bytes = new TextEncoder().encode(password).length;
  if (characters < 12) return "新密码至少需要 12 个字符。";
  if (bytes > 72) return "新密码 UTF-8 编码后不能超过 72 字节。";
  return "";
}

async function submitPasswordChange(form) {
  const feedback = $("#password-feedback");
  const submit = $("#password-submit");
  const currentPassword = String($("#password-current", form)?.value || "");
  const newPassword = String($("#password-new", form)?.value || "");
  const confirmPassword = String($("#password-confirm", form)?.value || "");
  const fail = (message) => {
    if (feedback) {
      feedback.textContent = message;
      feedback.classList.add("is-error");
    }
    showToast(message, true);
  };
  if (!currentPassword) {
    fail("请输入当前密码。");
    return;
  }
  const policyError = passwordPolicyError(newPassword);
  if (policyError) {
    fail(policyError);
    return;
  }
  if (newPassword !== confirmPassword) {
    fail("两次输入的新密码不一致。");
    return;
  }
  if (newPassword === currentPassword) {
    fail("新密码不能与当前密码相同。");
    return;
  }
  if (submit) submit.disabled = true;
  try {
    await api("/api/v1/auth/password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword }),
      redirectOnUnauthorized: false,
    });
    closePasswordDialog();
    showToast("密码已修改，请重新登录。");
    setTimeout(() => location.replace("/login.html"), 800);
  } catch (error) {
    fail(error.message || "修改密码失败。");
  } finally {
    if (submit) submit.disabled = false;
  }
}

function showToast(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("is-error", error);
  toast.classList.add("is-visible");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("is-visible"), 3200);
}

function stopParticipantActivity() {
  state.intervals.forEach((timer) => clearInterval(timer));
  state.intervals = [];
  clearTimeout(applyChallengeEvent.refreshTimer);
  disconnectTwinStream();
  disconnectChallengeStream();
}

function stopParticipationRecheck() {
  if (state.participationRecheck.timer) clearInterval(state.participationRecheck.timer);
  state.participationRecheck.timer = null;
  state.participationRecheck.inFlight = false;
}

function startParticipationRecheck() {
  if (state.participationRecheck.timer) return;
  const recheck = async () => {
    if (state.participationRecheck.inFlight) return;
    const competitionId = selectedCompetitionId();
    if (!competitionId) return;
    state.participationRecheck.inFlight = true;
    try {
      const payload = await api(`/api/v1/bootstrap?competitionId=${encodeURIComponent(competitionId)}`);
      const participation = normalizeParticipation(payload.participation);
      if (!participation.disqualification) {
        stopParticipationRecheck();
        location.reload();
        return;
      }
      state.bootstrap = payload;
      renderParticipationLock(payload);
    } catch (error) {
      console.warn("参赛权限状态复查失败", error);
    } finally {
      state.participationRecheck.inFlight = false;
    }
  };
  state.participationRecheck.timer = setInterval(recheck, POLL_INTERVALS.participationRecheck);
}

function renderParticipationLock(payload = {}) {
  state.participation = normalizeParticipation(payload.participation);
  const lock = $("#participation-lock");
  const disqualification = state.participation.disqualification;
  if (!disqualification) {
    stopParticipationRecheck();
    document.body.classList.remove("is-disqualified");
    if (lock) lock.hidden = true;
    $$(".rail-nav .nav-item").forEach((button) => { button.disabled = false; });
    return false;
  }

  stopParticipantActivity();
  startParticipationRecheck();
  document.body.classList.add("is-disqualified");
  if (lock) lock.hidden = false;
  $$(".rail-nav .nav-item").forEach((button) => { button.disabled = true; });
  const competition = payload.competition || {};
  const team = (Array.isArray(payload.teams) ? payload.teams : []).find((item) =>
    String(item.id || "") === state.participation.teamId
  );
  const ruleCode = disqualification.rule_code || disqualification.ruleCode;
  const scopeType = disqualification.scope_type || disqualification.scopeType || "team";
  const participantName = state.currentUser?.displayName || state.currentUser?.display_name ||
    state.currentUser?.username || disqualification.user_id || disqualification.userId || "当前选手";
  setText("#competition-title", competition.title || "赛事参赛权限已撤销");
  setText("#competition-phase", "已禁赛");
  setText("#competition-status", "DISQUALIFIED");
  setText("#provider-status", "权限已撤销");
  setText("#participation-lock-rule", disqualificationRuleLabel(ruleCode));
  setText("#participation-lock-team", scopeType === "user"
    ? `选手：${participantName}`
    : `队伍：${team?.name || state.participation.teamId || "当前队伍"}`);
  setText("#participation-lock-time", formatDecisionTime(disqualification.created_at || disqualification.createdAt));
  setText("#participation-lock-reason", disqualification.reason || "高危作弊事件触发本赛事禁赛");
  return true;
}

function selectedInstance() {
  return state.bootstrap?.instances?.find((item) => item.id === state.selectedInstanceId) || null;
}

function instanceById(instanceId) {
  return state.bootstrap?.instances?.find((item) => item.id === instanceId) || null;
}

function currentTeamId() {
  // Individual competitions allocate a competition-local scope team without
  // changing the account's reusable platform-team membership. Bootstrap is
  // authoritative once a competition is selected; fall back to /auth/me only
  // before that response is available (and for ordinary team competitions).
  return String(
    state.participation?.teamId ||
    state.currentUser?.teamId ||
    state.currentUser?.team_id ||
    "",
  ).trim();
}

function isTeamUser() {
  return String(state.currentUser?.role || "").toLowerCase() === "team";
}

function participantVisibleInstances(instances = []) {
  if (!isTeamUser()) return instances;
  const teamId = currentTeamId();
  return instances.filter((instance) => String(instance.team_id || instance.teamId || "") === teamId);
}

function applyParticipantBootstrapScope(payload) {
  if (!isTeamUser()) return payload;
  payload.instances = participantVisibleInstances(Array.isArray(payload.instances) ? payload.instances : []);
  if (payload.stats && typeof payload.stats === "object") {
    payload.stats.instances = payload.instances.length;
    payload.stats.runningInstances = payload.instances.length;
  }
  return payload;
}

function compatibleChallenges(instance) {
  if (!instance) return [];
  const challenges = state.challenges.items.filter((challenge) => challenge?.status === "published" || !challenge?.status);
  // The administrator assigns challenge workloads to concrete vehicle
  // instances. Only those assignments are selectable for this vehicle; the
  // challenge's vehicleDefinitionId describes the package, not the target
  // instance's provider profile.
  return challenges.filter((challenge) => Array.isArray(challenge.boundVehicleInstanceIds)
    && challenge.boundVehicleInstanceIds.includes(instance.id));
}

function assignChallengeVehicle(challenge) {
  if (!challenge) return null;
  const run = state.challenges.run && state.challenges.run.challengeId === challenge.id
    ? state.challenges.run
    : normalizeRun(challenge.run);
  const solve = state.challenges.solve && state.challenges.solve.challengeId === challenge.id
    ? state.challenges.solve
    : normalizeSolve(challenge.solve);
  const configuredIds = Array.isArray(challenge.boundVehicleInstanceIds) ? challenge.boundVehicleInstanceIds : [];
  const assignedId = String(run?.vehicleInstanceId || solve?.vehicleInstanceId || configuredIds[0] || "");
  const instance = instanceById(assignedId);
  state.challenges.bindingChallengeId = challenge.id;
  state.challenges.bindingInstanceId = instance?.id || null;
  if (instance) {
    state.selectedInstanceId = instance.id;
    // Keep the selector scoped to the administrator-assigned vehicle set and
    // refresh it whenever the selected challenge points at another vehicle.
    renderInstanceSelect(state.bootstrap?.instances || []);
  }
  return instance;
}

function assignedChallengeVehicleId(challenge) {
  if (!challenge) return "";
  const run = currentChallengeRun();
  if (run?.challengeId === challenge.id && run.vehicleInstanceId) return String(run.vehicleInstanceId);
  const solve = currentChallengeSolve();
  if (solve?.challengeId === challenge.id && solve.vehicleInstanceId) return String(solve.vehicleInstanceId);
  if (state.challenges.bindingChallengeId === challenge.id && state.challenges.bindingInstanceId) {
    return String(state.challenges.bindingInstanceId);
  }
  return String(challenge.boundVehicleInstanceIds?.[0] || "");
}

function solvedBindingKey(instanceId, challengeId, runId = "") {
  return `${instanceId}:${challengeId || "unknown"}:${runId || "current"}`;
}

function updateSolvedStage(instanceId = state.selectedInstanceId) {
  const stage = $("#twin-stage");
  if (!stage) return;
  const solved = Boolean(instanceId && state.solvedBindings.has(instanceId) && state.solvedBindings.get(instanceId).size);
  const mechanicalActions = state.mechanicalBindings.get(String(instanceId || ""));
  stage.classList.toggle("arena-solved", solved);
  stage.classList.toggle("arena-door-front-left-open", Boolean(mechanicalActions?.has("door-open") || mechanicalActions?.has("door-front-left-open")));
  stage.classList.toggle("arena-door-front-right-open", Boolean(mechanicalActions?.has("door-front-right-open")));
  stage.classList.toggle("arena-door-rear-left-open", Boolean(mechanicalActions?.has("door-rear-left-open")));
  stage.classList.toggle("arena-door-rear-right-open", Boolean(mechanicalActions?.has("door-rear-right-open")));
  if (solved && mechanicalActions?.size && window.vehicleTwin3D?.applyVisualActions) {
    window.vehicleTwin3D.applyVisualActions(instanceId, [...mechanicalActions], true);
  }
}

function syncSelectedVehicleVisuals() {
  if (isVehicleRangeCompetition()) {
    syncVehicleRangeVisuals(state.vehicleRange);
    return;
  }
  const instanceId = String(state.selectedInstanceId || "");
  if (!instanceId || !state.solvedBindings.has(instanceId)) return;
  const actions = state.mechanicalBindings.get(instanceId);
  if (!actions?.size || !window.vehicleTwin3D?.applyVisualActions) return;
  window.vehicleTwin3D.applyVisualActions(instanceId, [...actions], true);
}

function markArenaSolved(instanceId, solved, challengeId = "", runId = "") {
  const id = String(instanceId || "").trim();
  if (!id) return;
  const key = solvedBindingKey(id, challengeId, runId);
  let bindings = state.solvedBindings.get(id);
  if (solved) {
    if (!bindings) {
      bindings = new Set();
      state.solvedBindings.set(id, bindings);
    }
    bindings.add(key);
  } else if (bindings) {
    bindings.delete(key);
    if (!bindings.size) {
      state.solvedBindings.delete(id);
      state.mechanicalBindings.delete(id);
      if (window.vehicleTwin3D?.applyVisualActions) {
        window.vehicleTwin3D.applyVisualActions(id, [...MECHANICAL_VISUAL_ACTIONS], false);
      }
    }
  }
  window.__cybercarSolvedInstances = new Set([...state.solvedBindings.keys()]);
  updateSolvedStage(id);
  window.dispatchEvent(new CustomEvent("cybercar:arena-solved", { detail: { instanceId: id, solved: Boolean(solved) } }));
  renderArena(state.bootstrap?.instances || []);
}

function markMechanicalVisuals(instanceId, actions = []) {
  const id = String(instanceId || "").trim();
  if (!id) return;
  const mechanicalActions = actions.filter((action) => MECHANICAL_VISUAL_ACTIONS.has(action));
  const next = new Set(mechanicalActions);
  const current = state.mechanicalBindings.get(id) || new Set();
  const changed = current.size !== next.size || [...current].some((action) => !next.has(action));
  if (next.size) state.mechanicalBindings.set(id, next);
  else state.mechanicalBindings.delete(id);
  if (!changed) {
    updateSolvedStage(id);
    return;
  }
  window.__cybercarPending3DVisuals = Array.isArray(window.__cybercarPending3DVisuals) ? window.__cybercarPending3DVisuals : [];
  window.__cybercarPending3DVisuals = window.__cybercarPending3DVisuals.filter((item) => item.instanceId !== id);
  window.__cybercarPending3DVisuals.push({ instanceId: id, actions: [...MECHANICAL_VISUAL_ACTIONS], open: false });
  if (mechanicalActions.length) window.__cybercarPending3DVisuals.push({ instanceId: id, actions: mechanicalActions, open: true });
  if (window.__cybercarPending3DVisuals.length > 32) window.__cybercarPending3DVisuals.shift();
  if (window.vehicleTwin3D?.applyVisualActions) {
    window.vehicleTwin3D.applyVisualActions(id, [...MECHANICAL_VISUAL_ACTIONS], false);
    if (mechanicalActions.length) window.vehicleTwin3D.applyVisualActions(id, mechanicalActions, true);
    window.__cybercarPending3DVisuals = window.__cybercarPending3DVisuals.filter((item) => item.instanceId !== id);
  }
  updateSolvedStage(id);
}

function scopedPath(instance, suffix = "") {
  const competitionId = encodeURIComponent(instance.competition_id);
  const teamId = encodeURIComponent(instance.team_id);
  const instanceId = encodeURIComponent(instance.id);
  return `/api/v1/competitions/${competitionId}/teams/${teamId}/instances/${instanceId}${suffix}`;
}

function twinSocketUrl(instance) {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const competitionId = encodeURIComponent(instance.competition_id);
  const teamId = encodeURIComponent(instance.team_id);
  const instanceId = encodeURIComponent(instance.id);
  return `${protocol}//${location.host}/ws/v1/competitions/${competitionId}/teams/${teamId}/instances/${instanceId}/twin`;
}

function twinSocketIsOpen(instanceId = state.selectedInstanceId) {
  return state.realtime.instanceId === instanceId && state.realtime.socket?.readyState === WebSocket.OPEN;
}

function challengeScope() {
  const competitionId = state.bootstrap?.competition?.id;
  const teamId = currentTeamId();
  return competitionId && teamId ? { competitionId, teamId } : null;
}

function attackSessionPath() {
  const scope = challengeScope();
  return scope ? `/api/v1/competitions/${encodeURIComponent(scope.competitionId)}/teams/${encodeURIComponent(scope.teamId)}/attack/session` : "";
}

function attackTargetsPath() {
  const scope = challengeScope();
  return scope ? `/api/v1/competitions/${encodeURIComponent(scope.competitionId)}/teams/${encodeURIComponent(scope.teamId)}/attack-targets` : "";
}

function competitionMode() { return String(state.bootstrap?.competition?.mode || "").toLowerCase(); }
function competitionAccessMode() {
  const competition = state.bootstrap?.competition || {};
  const explicit = String(competition.access_mode || competition.accessMode || "").toLowerCase();
  if (explicit) return explicit;
  return competitionMode() === "attack" || competitionMode() === "vehicle_range" ? "attack" : "direct";
}
function isAttackDesktopCompetition() { return competitionAccessMode() === "attack"; }
function isVehicleRangeVPNCompetition() { return isVehicleRangeCompetition() && competitionAccessMode() === "openvpn"; }
function isVehicleRangeCompetition() { return competitionMode() === "vehicle_range"; }
function competitionModeLabel() { return isVehicleRangeCompetition() ? "车联网安全靶场模式" : "CTF"; }

function setMetricCaption(index, label, suffix) {
  const article = $$(".metric-band article")[index];
  if (!article) return;
  const labelNode = article.querySelector("span");
  const suffixNode = article.querySelector("small");
  if (labelNode) labelNode.textContent = label;
  if (suffixNode) suffixNode.textContent = suffix;
}

function activeNodeCount(nodes = []) {
  return nodes.filter((node) => ["active", "running", "ready", "online"].includes(String(node.status || "").toLowerCase())).length;
}

function renderOverviewMetrics(payload = state.bootstrap, rangePayload = state.vehicleRange) {
  if (!payload) return;
  const stats = payload.stats || {};
  const teams = Array.isArray(payload.teams) ? payload.teams : [];
  const teamTotal = teams.length || Number(stats.teams) || 0;
  const activeTeams = teams.length ? teams.filter((team) => team.status === "active").length : Number(stats.activeTeams) || 0;
  setMetricCaption(0, "活跃战队", `/ ${String(teamTotal).padStart(2, "0")} TEAMS`);
  setText("#metric-active-teams", String(activeTeams).padStart(2, "0"));

  if (isVehicleRangeCompetition()) {
    const settings = rangePayload?.settings || {};
    const instance = rangePayload?.item || null;
    const template = instance?.template || settings.template || {};
    const nodes = Array.isArray(instance?.nodes) ? instance.nodes : [];
    const templateNodes = Array.isArray(template.nodes) ? template.nodes : [];
    const events = Array.isArray(instance?.events) ? instance.events : [];
    const stages = Array.isArray(template.stages) ? template.stages : [];
    const totalNodes = templateNodes.length || nodes.length || 0;
    const visibleNodes = nodes.length || totalNodes;
    const runningNodes = activeNodeCount(nodes);
    const nodeValue = runningNodes || visibleNodes;
    const stageValue = stages.length || (template.id ? 1 : 0);

    setMetricCaption(1, "靶场节点", `/ ${String(totalNodes).padStart(2, "0")} NODES`);
    setText("#metric-running", String(nodeValue).padStart(2, "0"));
    setText("#metric-instance-total", `/ ${String(totalNodes).padStart(2, "0")} NODES`);
    setMetricCaption(2, "证据事件", "APPEND-ONLY");
    setText("#metric-events", String(events.length).padStart(3, "0"));
    setMetricCaption(3, "攻击阶段", template.status === "published" ? `V${template.version || 1} / PUBLISHED` : "RANGE TEMPLATE");
    setText("#metric-paths", String(stageValue).padStart(2, "0"));
    return;
  }

  setMetricCaption(1, "展示车辆", `/ ${String(stats.instances || 0).padStart(2, "0")} INSTANCES`);
  setText("#metric-running", String(stats.instances || 0).padStart(2, "0"));
  setText("#metric-instance-total", `/ ${String(stats.instances || 0).padStart(2, "0")} INSTANCES`);
  setMetricCaption(2, "证据事件", "APPEND-ONLY");
  setText("#metric-events", String(stats.evidenceEvents || 0).padStart(3, "0"));
  setMetricCaption(3, "已发布题目", "CHALLENGE CONTENT");
  setText("#metric-paths", String(state.challenges.items.length).padStart(2, "0"));
}

function syncCompetitionModeNavigation() {
  const vehicleRange = isVehicleRangeCompetition();
  const navigation = $(".rail-nav");
  if (!navigation) return;
  const rangeOrder = ["overview", "teams", "vehicle-range", "evidence"];
  const ctfOrder = ["overview", "twin", "challenges", "arena", "teams", "evidence"];
  const order = vehicleRange ? rangeOrder : ctfOrder;
  const visibleViews = new Set(order);
  const items = new Map($$(".nav-item", navigation).map((item) => [item.dataset.view, item]));

  items.forEach((item, view) => {
    item.hidden = !visibleViews.has(view);
    item.setAttribute("aria-hidden", item.hidden ? "true" : "false");
  });
  order.forEach((view, index) => {
    const item = items.get(view);
    if (!item) return;
    const indexLabel = item.querySelector("span");
    if (indexLabel) indexLabel.textContent = String(index + 1).padStart(2, "0");
    navigation.append(item);
  });

  ["twin", "challenges", "arena"].forEach((view) => {
    const panel = $(`#view-${view}`);
    if (panel) {
      panel.hidden = vehicleRange;
      panel.setAttribute("aria-hidden", vehicleRange ? "true" : "false");
    }
  });
}

function competitionView(name) {
  const requested = String(name || "overview");
  if (isVehicleRangeCompetition() && ["twin", "challenges", "arena"].includes(requested)) return "vehicle-range";
  if (!isVehicleRangeCompetition() && requested === "vehicle-range") return "overview";
  return requested;
}

function vehicleRangePath(suffix = "") {
  const scope = challengeScope();
  return scope ? `/api/v1/competitions/${encodeURIComponent(scope.competitionId)}/teams/${encodeURIComponent(scope.teamId)}/vehicle-range${suffix}` : "";
}

function renderAttackTargets(payload = null) {
  state.attackTargetsPayload = payload;
  const panel = $("#attack-targets"), list = $("#attack-target-list");
  if (!panel || !list) return;
  const items = Array.isArray(payload?.items) ? payload.items : [];
  list.replaceChildren();
  items.forEach((item) => {
    const row = element("div", "attack-target-row");
    const label = element("strong", "", `${item.target_kind === "kvm" ? "KVM" : "Docker"} · ${item.target_id}`);
    const privateHost = String(item.targetHost || item.target_host || "").trim();
    const privatePort = Number(item.targetPort || item.target_port || 0);
    const address = privateHost && privatePort ? `${privateHost}:${privatePort}` : (payload.gatewayUrl ? `${payload.gatewayUrl}/v1/connect/${item.id}` : "授权网关未配置地址");
    const value = element("code", "", address);
    const copy = element("button", "secondary-button", privateHost ? "复制内网地址" : "复制代理地址");
    copy.type = "button";
    copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(address); showToast(privateHost ? "内网地址已复制" : "代理地址已复制"); } catch { showToast("复制失败，请手动复制", true); } });
    row.append(label, value, copy); list.append(row);
  });
  panel.hidden = !items.length;
  if (state.challenges?.detail && state.challenges?.run) {
    renderChallengeAccess(state.challenges.detail, state.challenges.run);
  }
}

async function loadAttackTargets({ quiet = true } = {}) {
  if (competitionMode() !== "attack") { renderAttackTargets(null); return; }
  const path = attackTargetsPath(); if (!path) return;
  try { renderAttackTargets(await api(path)); } catch (error) { renderAttackTargets(null); if (!quiet) showToast(`靶机授权读取失败：${error.message}`, true); }
}

function renderAttackDesktop(session = null) {
  const panel = $("#attack-desktop-panel");
  if (!panel) return;
  state.attackDesktopSession = session;
  const attack = isAttackDesktopCompetition();
  panel.hidden = !attack;
  if (!attack) return;
  const status = String(session?.status || "stopped").toLowerCase();
  const statusLabel = ({ provisioning: "启动中", running: "运行中", stopping: "停止中", stopped: "已停止", failed: "异常" })[status] || "未启动";
  setText("#attack-desktop-status", statusLabel);
  const statusNode = $("#attack-desktop-status");
  if (statusNode) statusNode.dataset.status = status;
  const start = $("#attack-desktop-start"), stop = $("#attack-desktop-stop"), open = $("#attack-desktop-open");
  if (start) start.disabled = ["provisioning", "running", "stopping"].includes(status);
  if (stop) stop.disabled = !["provisioning", "running", "stopping"].includes(status);
  if (open) { open.hidden = !session?.kasm_url || status !== "running"; open.href = session?.kasm_url || "#"; }
}

async function loadAttackDesktop({ quiet = true } = {}) {
  if (!isAttackDesktopCompetition()) { renderAttackDesktop(null); return; }
  const path = attackSessionPath();
  if (!path) return;
  try {
    const payload = await api(path);
    renderAttackDesktop(payload?.item || payload);
  } catch (error) {
    if (error.status === 404) renderAttackDesktop(null);
    else if (!quiet) showToast(`攻击机状态读取失败：${error.message}`, true);
  }
}

function rangeStatusLabel(status) {
  return ({ provisioning: "建立中", running: "运行中", active: "运行中", pausing: "暂停中", paused: "已暂停", resuming: "恢复中", resetting: "重置中", stopping: "停止中", stopped: "已停止", failed: "异常" })[String(status || "").toLowerCase()] || "未启动";
}

function formatVehicleRangeEventTime(value) {
  const date = new Date(value || 0);
  return Number.isNaN(date.getTime()) || !value ? "—" : new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(date);
}

function vehicleRangeEventTone(event = {}) {
  switch (String(event.type || "").toLowerCase()) {
    case "range.active": return "is-ready";
    case "range.paused": return "is-paused";
    case "range.resumed": return "is-ready";
    case "range.snapshot.created": return "is-snapshot";
    case "range.snapshot.restored": return "is-snapshot";
    case "range.failed": return "is-failed";
    case "range.provisioning": return "is-pending";
    default: return "";
  }
}

function renderVehicleRangeVPN(access = null, instance = null) {
  const panel = $("#vehicle-range-vpn");
  if (!panel) return;
  const enabled = isVehicleRangeVPNCompetition();
  panel.hidden = !enabled;
  if (!enabled) return;
  const profile = access?.profile || null;
  const routes = Array.isArray(access?.routes) ? access.routes : [];
  const connected = profile?.connected === true;
  const running = String(instance?.status || "").toLowerCase() === "active";
  const status = $("#vehicle-range-vpn-status");
  if (status) {
    status.textContent = connected ? "已连接" : profile ? "已签发" : running ? "可下载" : "等待靶场";
    status.dataset.status = connected ? "active" : profile ? "provisioning" : "stopped";
  }
  setText("#vehicle-range-vpn-summary", connected ? "VPN 隧道已建立，可直接访问下列靶场网段" : profile ? "配置已签发，等待客户端建立隧道" : running ? "私网路由已就绪，可下载个人配置" : "启动靶场后下载配置");
  setText("#vehicle-range-vpn-address", profile?.tunnelAddress || "—");
  setText("#vehicle-range-vpn-connection", connected ? `在线${profile.remoteAddress ? ` · ${profile.remoteAddress}` : ""}` : "未连接");
  setText("#vehicle-range-vpn-expiry", profile?.expiresAt ? formatDecisionTime(profile.expiresAt) : "—");
  const routeList = $("#vehicle-range-vpn-route-list");
  if (routeList) {
    routeList.replaceChildren();
    if (!routes.length) routeList.append(element("code", "", running ? "正在同步靶场路由" : "靶场启动后同步"));
    routes.forEach((route) => routeList.append(element("code", "", route)));
  }
  const download = $("#vehicle-range-vpn-download"), revoke = $("#vehicle-range-vpn-revoke");
  if (download) download.disabled = !running || access?.available === false;
  if (revoke) revoke.disabled = !profile;
}

function normalizeRangeVisualActions(actions) {
  return (Array.isArray(actions) ? actions : [])
    .map((action) => String(action || "").trim())
    .filter((action, index, all) => action && ARENA_VISUAL_ACTIONS.has(action) && all.indexOf(action) === index);
}

function rangeVisualContextId(instance) {
  if (!instance?.id) return "";
  return `vehicle-range:${instance.id}:gen-${Number(instance.generation) || 1}`;
}

function renderVehicleRangeActionSummary(stages, completed) {
  const list = $("#vehicle-range-action-list");
  if (!list) return;
  const triggered = [];
  (Array.isArray(stages) ? stages : []).forEach((stage) => {
    if (!completed.has(stage.key)) return;
    normalizeRangeVisualActions(stage.visual_actions || stage.visualActions).forEach((action) => {
      if (!triggered.some((item) => item.action === action)) {
        triggered.push({ action, stage: stage.title || stage.name || stage.key });
      }
    });
  });

  list.replaceChildren();
  if (!triggered.length) {
    setText("#vehicle-range-action-summary", "尚无已触发车辆动作");
    list.append(element("em", "", "等待服务端验证阶段"));
    return;
  }

  const vehicleActionCount = triggered.filter((item) => item.action !== "solve-scan").length;
  setText(
    "#vehicle-range-action-summary",
    vehicleActionCount ? `${vehicleActionCount} 个整车动作已生效` : `${triggered.length} 个阶段效果已生效`,
  );
  triggered.forEach(({ action, stage }) => {
    const chip = element("span", action === "solve-scan" ? "is-scan" : "is-vehicle-action", RANGE_VISUAL_ACTION_LABELS[action] || action);
    chip.title = `触发阶段：${stage}`;
    list.append(chip);
  });
}

function syncVehicleRangeVisuals(payload = state.vehicleRange, completedSet = null) {
  const instance = payload?.item || null;
  const template = instance?.template || payload?.settings?.template || null;
  const contextId = rangeVisualContextId(instance);
  const generation = Number(instance?.generation) || 0;
  const checkpoints = Array.isArray(instance?.checkpoints) ? instance.checkpoints : [];
  const completed = completedSet || new Set(checkpoints.map((checkpoint) => checkpoint.stage_key || checkpoint.stageKey).filter(Boolean));
  const stages = Array.isArray(template?.stages) ? template.stages : [];
  const previous = state.vehicleRangeVisual;
  const sameGeneration = Boolean(contextId && previous.contextId === contextId && previous.generation === generation);
  const newlyCompleted = sameGeneration ? [...completed].filter((stageKey) => !previous.completed.has(stageKey)) : [];

  const topologyState = { template, instance, completedStages: [...completed] };
  window.__cybercarPendingRangeState = topologyState;
  if (window.vehicleRange3D?.setState) {
    window.vehicleRange3D.setState(topologyState);
    newlyCompleted.forEach((stageKey) => window.vehicleRange3D.playStage?.(stageKey));
  }

  const priorContextId = previous.contextId;
  if (priorContextId && priorContextId !== contextId && window.vehicleTwin3D?.applyVisualActions) {
    window.vehicleTwin3D.applyVisualActions(priorContextId, [...MECHANICAL_VISUAL_ACTIONS], false);
  }
  const persistentActions = stages
    .filter((stage) => completed.has(stage.key))
    .flatMap((stage) => normalizeRangeVisualActions(stage.visual_actions || stage.visualActions))
    .filter((action, index, all) => all.indexOf(action) === index);
  renderVehicleRangeActionSummary(stages, completed);
  const actionsKey = persistentActions.join("|");
  if (contextId) {
    if (window.vehicleTwin3D?.setPresentationContext) window.vehicleTwin3D.setPresentationContext(contextId);
    if (priorContextId !== contextId || previous.actionsKey !== actionsKey) {
      window.__cybercarPending3DVisuals = Array.isArray(window.__cybercarPending3DVisuals) ? window.__cybercarPending3DVisuals : [];
      window.__cybercarPending3DVisuals = window.__cybercarPending3DVisuals.filter((item) => item.instanceId !== contextId);
      window.__cybercarPending3DVisuals.push({ instanceId: contextId, actions: [...MECHANICAL_VISUAL_ACTIONS], open: false });
      if (persistentActions.length) window.__cybercarPending3DVisuals.push({ instanceId: contextId, actions: persistentActions, open: true });
      if (window.vehicleTwin3D?.applyVisualActions) {
        window.vehicleTwin3D.applyVisualActions(contextId, [...MECHANICAL_VISUAL_ACTIONS], false);
        if (persistentActions.length) window.vehicleTwin3D.applyVisualActions(contextId, persistentActions, true);
        window.__cybercarPending3DVisuals = window.__cybercarPending3DVisuals.filter((item) => item.instanceId !== contextId);
      }
    }
  }
  state.vehicleRangeVisual = { contextId, completed: new Set(completed), generation, actionsKey };
  setText("#vehicle-range-visual-status", contextId ? `${completed.size} / ${stages.length} 已验证` : "等待靶场");
}

function renderVehicleRange(payload = state.vehicleRange) {
  const view = $("#view-vehicle-range");
  const enabled = isVehicleRangeCompetition();
  syncCompetitionModeNavigation();
  if (!view) return;
  if (!enabled) { view.classList.remove("is-active"); return; }
  const settings = payload?.settings || {};
  const instance = payload?.item || null;
  const template = instance?.template || settings.template || {};
  const status = String(instance?.status || "stopped").toLowerCase();
  const accessMode = competitionAccessMode();
  const requiresDesktop = accessMode === "attack";
  const usesOpenVPN = accessMode === "openvpn";
  renderOverviewMetrics(state.bootstrap, payload);
  setText("#vehicle-range-template-title", template.title ? `${template.title} / V${template.version || 1}` : "未分配靶场模板");
  setText("#vehicle-range-description", template.description || (requiresDesktop ? "启动后将在攻击机所在私有网络中创建全部节点。" : usesOpenVPN ? "启动后将创建独立靶场网络，并为当前选手提供专属 OpenVPN 接入。" : "启动后将创建当前参赛作用域的独立靶场网络。"));
  setText("#vehicle-range-access-description", requiresDesktop ? "攻击机与本队靶机位于同一私有网络；请在云桌面内使用节点 IP 与端口访问。" : usesOpenVPN ? "通过个人 OpenVPN 证书接入本队或本人靶场私网；其他队伍网段不被路由和防火墙放行。" : "靶场节点位于赛事私有网络，平台只向当前参赛作用域提供授权访问。");
  setText("#vehicle-range-status", rangeStatusLabel(status));
  const statusNode = $("#vehicle-range-status"); if (statusNode) statusNode.dataset.status = status;
  const scopeLabel = settings.scope_mode === "individual" ? "个人独立靶场" : "队伍共享靶场";
  setText("#vehicle-range-scope", scopeLabel);
  setText("#vehicle-range-generation", instance ? `GEN ${instance.generation || 1}` : "—");
  const checkpoints = Array.isArray(instance?.checkpoints) ? instance.checkpoints : [];
  const stages = Array.isArray(template.stages) ? template.stages : [];
  setText("#vehicle-range-progress", stages.length ? `${checkpoints.length} / ${stages.length}` : "—");
  const completedStages = new Set(checkpoints.map((checkpoint) => checkpoint.stage_key || checkpoint.stageKey).filter(Boolean));
  syncVehicleRangeVisuals(payload, completedStages);
  const rangeScore = stages.reduce((total, stage) => completedStages.has(stage.key) ? total + finiteNumber(stage.score, 0) : total, 0);
  setText("#vehicle-range-score", formatNumber(rangeScore));
  const desktopRunning = ["provisioning", "running"].includes(String(state.attackDesktopSession?.status || "").toLowerCase());
  const changing = ["provisioning", "pausing", "resuming", "resetting", "stopping"].includes(status);
  const start = $("#vehicle-range-start"), pause = $("#vehicle-range-pause"), resume = $("#vehicle-range-resume"), reset = $("#vehicle-range-reset"), stop = $("#vehicle-range-stop"), openDesktop = $("#vehicle-range-open-desktop");
  const accessReady = !requiresDesktop || desktopRunning;
  const rebuildDisabled = settings.allow_self_reset === false && Boolean(instance?.started_at || instance?.startedAt) && ["stopped","failed"].includes(status);
  if (start) { start.disabled = changing || ["active", "paused"].includes(status) || !accessReady || rebuildDisabled; start.textContent = status === "failed" ? "重新启动整车靶场" : "启动整车靶场"; }
  if (pause) pause.disabled = !instance || status !== "active" || changing;
  if (resume) resume.disabled = !instance || status !== "paused" || changing;
  if (reset) reset.disabled = !instance || changing || !accessReady || settings.allow_self_reset === false;
  if (stop) stop.disabled = !instance || ["stopped", "failed"].includes(status) || changing;
  if (openDesktop) openDesktop.hidden = !requiresDesktop || desktopRunning;
  setText("#vehicle-range-help", requiresDesktop && !desktopRunning ? "请先启动攻击机；桌面运行后才能创建本队私有靶场网络。" : status === "paused" ? "靶场已冻结：节点、私有地址与当前代次保持不变；可保存快照、恢复运行或从已有快照重建。" : usesOpenVPN ? "启动完成后下载个人 .ovpn 配置；连接成功即可访问下列私有节点地址。" : requiresDesktop ? "靶场仅会加入本队攻击机私有网络；请在云桌面内访问下列内网地址。" : "请使用管理员提供的赛事直连网络访问下列私有节点地址。");
  renderVehicleRangeVPN(payload?.vpn || null, instance);
  const snapshotSelect = $("#vehicle-range-snapshot-select"), snapshotButton = $("#vehicle-range-snapshot"), restoreButton = $("#vehicle-range-restore"), snapshotSummary = $("#vehicle-range-snapshot-summary");
  const snapshots = Array.isArray(instance?.snapshots) ? instance.snapshots : [];
  if (snapshotSelect) {
    const selected = snapshotSelect.value;
    snapshotSelect.replaceChildren();
    if (!snapshots.length) snapshotSelect.append(new Option("暂无可恢复快照", ""));
    snapshots.forEach((snapshot, index) => {
      const label = snapshot.label || `GEN ${snapshot.source_generation || snapshot.sourceGeneration || "—"} · 阶段 ${snapshot.checkpoint_count ?? snapshot.checkpointCount ?? 0}`;
      snapshotSelect.append(new Option(label, snapshot.id));
      if (snapshot.id === selected) snapshotSelect.value = selected;
      else if (!selected && index === 0) snapshotSelect.value = snapshot.id;
    });
    snapshotSelect.disabled = !snapshots.length || changing;
  }
  if (snapshotButton) snapshotButton.disabled = !instance || status !== "paused" || changing;
  if (restoreButton) restoreButton.disabled = !instance || status !== "paused" || changing || !snapshotSelect?.value || !accessReady || settings.allow_self_reset === false;
  if (snapshotSummary) setText(snapshotSummary, snapshots.length ? `${snapshots.length} 个可恢复点` : status === "paused" ? "现在可保存" : "暂停后可保存");
  const nodeList = $("#vehicle-range-nodes");
  if (nodeList) {
    nodeList.replaceChildren();
    const nodes = Array.isArray(instance?.nodes) ? instance.nodes : [];
    if (!nodes.length) nodeList.append(element("p", "", "靶场启动后显示每个节点的内网地址。"));
    nodes.forEach((node) => {
      const templateNode = (template.nodes || []).find((item) => item.key === node.node_key || item.key === node.nodeKey) || {};
      const row = element("article", "vehicle-range-node");
      const name = element("strong", "", templateNode.label || node.node_key || node.nodeKey || "未命名节点");
      const stateLabel = element("span", `is-${String(node.status || "unknown").toLowerCase()}`, rangeStatusLabel(node.status));
      const ports = (Array.isArray(node.ports) ? node.ports : []).map((port) => port.port || port).filter(Boolean);
      const endpoint = node.private_host || node.privateHost ? `${node.private_host || node.privateHost}${ports.length ? `:${ports.join(" / ")}` : ""}` : "等待私有地址";
      const address = element("code", "", endpoint);
      const copy = element("button", "secondary-button", "复制地址"); copy.type = "button"; copy.disabled = !node.private_host && !node.privateHost;
      copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(endpoint); showToast(`靶场内网地址已复制，请在${usesOpenVPN ? "VPN 连接建立后" : requiresDesktop ? "云桌面内" : "授权网络内"}使用`); } catch { showToast("复制失败，请手动复制", true); } });
      row.append(name, stateLabel, address, copy); nodeList.append(row);
    });
  }
  const stageList = $("#vehicle-range-stages");
  if (stageList) {
    stageList.replaceChildren();
    if (!stages.length) stageList.append(element("li", "", "模板尚未定义攻击阶段。"));
    stages.forEach((stage) => {
      const done = completedStages.has(stage.key);
      const item = element("li", done ? "is-complete" : "");
      const titleRow = element("div", "vehicle-range-stage-title");
      const detailButton = element("button", "vehicle-range-stage-detail-button", "查看赛题详情");
      detailButton.type = "button";
      detailButton.addEventListener("click", () => openVehicleRangeStageDetail(stage));
      titleRow.append(element("strong", "", vehicleRangeStageTitle(stage)), detailButton);
      item.append(element("span", "", vehicleRangeStageOrderLabel(stage)), titleRow);
      stageList.append(item);
    });
  }
  const events = $("#vehicle-range-events");
  if (events) {
    events.replaceChildren();
    const items = Array.isArray(instance?.events) ? instance.events : [];
    if (!items.length) events.append(element("p", "", "尚无靶场事件。"));
    items.slice(0, 20).forEach((event) => { const row = element("article", `vehicle-range-event ${vehicleRangeEventTone(event)}`.trim()); row.append(element("time", "", formatVehicleRangeEventTime(event.occurred_at || event.occurredAt)), element("strong", "", event.type || "range.event"), element("span", "", event.message || "—")); events.append(row); });
  }
}

async function loadVehicleRange({ quiet = true } = {}) {
  if (!isVehicleRangeCompetition()) { state.vehicleRange = null; renderVehicleRange(null); return; }
  const path = vehicleRangePath(); if (!path) return;
  try { state.vehicleRange = await api(path); renderVehicleRange(state.vehicleRange); }
  catch (error) { state.vehicleRange = null; renderVehicleRange(null); if (!quiet) showToast(`整车靶场状态读取失败：${error.message}`, true); }
}

function challengePath(challengeId = "", suffix = "") {
  const scope = challengeScope();
  if (!scope) return null;
  const base = `/api/v1/competitions/${encodeURIComponent(scope.competitionId)}/teams/${encodeURIComponent(scope.teamId)}/challenges`;
  return challengeId ? `${base}/${encodeURIComponent(challengeId)}${suffix}` : base;
}

function challengeSocketUrl(challengeId) {
  const path = challengePath(challengeId, "/run");
  if (!path) return null;
  return `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}${path.replace("/api/", "/ws/")}`;
}

function disconnectTwinStream() {
  clearTimeout(state.realtime.reconnectTimer);
  state.realtime.reconnectTimer = null;
  const socket = state.realtime.socket;
  state.realtime.socket = null;
  state.realtime.instanceId = null;
  if (socket && socket.readyState < WebSocket.CLOSING) socket.close(1000, "instance changed");
}

function reconnectDelayWithJitter(delay) {
  return Math.round(delay * (0.8 + Math.random() * 0.4));
}

function nextReconnectDelay(currentDelay) {
  const base = Number.isFinite(currentDelay) && currentDelay > 0 ? currentDelay : 1000;
  return Math.min(base * 2, WS_RECONNECT_MAX_MS);
}

function connectTwinStream(instance = selectedInstance()) {
  if (participantIsDisqualified()) return;
  if (!instance || !("WebSocket" in window)) return;
  if (state.realtime.instanceId === instance.id && state.realtime.socket?.readyState <= WebSocket.OPEN) return;
  disconnectTwinStream();

  const socket = new WebSocket(twinSocketUrl(instance));
  state.realtime.socket = socket;
  state.realtime.instanceId = instance.id;

  socket.addEventListener("open", () => {
    state.realtime.reconnectDelayMs = 1000;
  });
  socket.addEventListener("message", (event) => {
    if (state.realtime.socket !== socket || state.selectedInstanceId !== instance.id) return;
    try {
      const raw = JSON.parse(event.data);
      state.twin = normalizeTwin(raw, instance);
      renderTwin(state.twin, instance);
    } catch (error) {
      console.warn("忽略无法解析的车辆实时消息", error);
    }
  });
  socket.addEventListener("close", () => {
    if (state.realtime.socket !== socket || state.selectedInstanceId !== instance.id) return;
    state.realtime.socket = null;
    const delay = state.realtime.reconnectDelayMs;
    state.realtime.reconnectDelayMs = nextReconnectDelay(delay);
    state.realtime.reconnectTimer = setTimeout(() => connectTwinStream(selectedInstance()), reconnectDelayWithJitter(delay));
  });
  socket.addEventListener("error", () => socket.close());
}

async function loadBootstrap({ quiet = false } = {}) {
  try {
    const competitionId = selectedCompetitionId();
    const payload = await api(competitionId ? `/api/v1/bootstrap?competitionId=${encodeURIComponent(competitionId)}` : "/api/v1/bootstrap");
    state.bootstrap = payload;
    if (renderParticipationLock(payload)) return;
    payload.teams = Array.isArray(payload.teams) ? payload.teams : [];
    payload.instances = Array.isArray(payload.instances) ? payload.instances : [];
    payload.events = Array.isArray(payload.events) ? payload.events : [];
    applyParticipantBootstrapScope(payload);
    if (!state.selectedInstanceId || !payload.instances.some((item) => item.id === state.selectedInstanceId)) {
      state.selectedInstanceId = payload.instances[0]?.id || null;
    }
    renderBootstrap(payload);
    renderVehicleRange(state.vehicleRange);
    if (state.selectedInstanceId) {
      if (!twinSocketIsOpen()) await loadTwin({ quiet: true });
      connectTwinStream();
    } else {
      disconnectTwinStream();
      renderNoInstance();
    }
  } catch (error) {
    if (!quiet) showToast(error.message, true);
    setText("#provider-status", "控制面离线");
  }
}

async function loadTeamRanking({ quiet = true } = {}) {
  const competitionId = state.bootstrap?.competition?.id || selectedCompetitionId();
  if (!competitionId || state.rankingLoading) return;
  state.rankingLoading = true;
  try {
    const payload = await api(`/api/v1/competitions/${encodeURIComponent(competitionId)}/teams`);
    const teams = unwrapList(payload, "items", "teams");
    if (!state.bootstrap || state.bootstrap.competition?.id !== competitionId) return;
    state.bootstrap.teams = teams;
    renderLeaderboard(teams);
    renderTeams(teams, state.bootstrap.instances || []);
    setText("#metric-active-teams", String(teams.filter((team) => team.status === "active").length).padStart(2, "0"));
    setText("#metric-team-total", `/ ${String(teams.length).padStart(2, "0")} TEAMS`);
  } catch (error) {
    if (!quiet) showToast(`战队排名刷新失败：${error.message}`, true);
  } finally {
    state.rankingLoading = false;
  }
}

function unwrapList(payload, ...keys) {
  if (Array.isArray(payload)) return payload;
  for (const key of keys) if (Array.isArray(payload?.[key])) return payload[key];
  return [];
}

function normalizeChallenge(raw = {}) {
  const source = raw.item || raw.challenge || raw;
  return {
    ...source,
    id: String(source.id || source.challengeId || source.challenge_id || ""),
    slug: String(source.slug || source.code || source.id || ""),
    title: String(source.title || "未命名题目"),
    description: String(source.description || ""),
    status: String(source.status || "published"),
    baseScore: Number(source.baseScore ?? source.base_score ?? 0),
    runtimeKind: String(source.runtimeKind || source.runtime_kind || "").trim().toLowerCase(),
    accessProtocol: ["http", "none"].includes(String(source.accessProtocol || source.access_protocol || "tcp").toLowerCase()) ? String(source.accessProtocol || source.access_protocol).toLowerCase() : "tcp",
    flagMode: String(source.flagMode || source.flag_mode || "dynamic").toLowerCase() === "static" ? "static" : "dynamic",
    staticFlagConfigured: Boolean(source.staticFlagConfigured ?? source.static_flag_configured),
    hasAttachments: Boolean(source.hasAttachments ?? source.has_attachments),
    attachments: Array.isArray(source.attachments) ? source.attachments.map((attachment) => ({
      ...attachment,
      id: String(attachment.id || ""),
      filename: String(attachment.filename || attachment.id || "附件"),
      sizeBytes: Number(attachment.sizeBytes ?? attachment.size_bytes ?? 0),
      downloadPath: String(attachment.downloadPath || attachment.download_path || ""),
    })) : [],
    vehicleDefinitionId: String(source.vehicleDefinitionId || source.vehicle_definition_id || ""),
    boundVehicleInstanceIds: Array.isArray(source.boundVehicleInstanceIds)
      ? source.boundVehicleInstanceIds.map((id) => String(id))
      : Array.isArray(source.bound_vehicle_instance_ids)
        ? source.bound_vehicle_instance_ids.map((id) => String(id))
        : [],
    entryPort: source.entryPort ?? source.entry_port ?? null,
    run: raw.run || source.run || source.currentRun || source.current_run || null,
    solve: raw.solve || source.solve || null,
  };
}

function normalizeRun(payload) {
  if (!payload) return null;
  const run = payload.item || payload.run || payload;
  if (!run?.id) return null;
  const accessPort = Number(run.accessPort ?? run.access_port ?? 0);
  const accessPorts = (Array.isArray(run.accessPorts) ? run.accessPorts : Array.isArray(run.access_ports) ? run.access_ports : [])
    .map((item) => ({ protocol: String(item?.protocol || "tcp").toLowerCase(), hostPort: Number(item?.hostPort ?? item?.host_port ?? 0), guestPort: Number(item?.guestPort ?? item?.guest_port ?? 0) }))
    .filter((item) => item.hostPort >= 1 && item.hostPort <= 65535 && item.guestPort >= 1 && item.guestPort <= 65535);
  return {
    ...run,
    id: String(run.id),
    challengeId: String(run.challengeId ?? run.challenge_id ?? ""),
    teamId: String(run.teamId ?? run.team_id ?? ""),
    competitionId: String(run.competitionId ?? run.competition_id ?? ""),
    status: String(run.status || "provisioning"),
    generation: Number(run.generation ?? 0),
    vehicleInstanceId: run.vehicleInstanceId ?? run.vehicle_instance_id ?? null,
    accessHost: String(run.accessHost ?? run.access_host ?? "").trim(),
    accessPort: Number.isInteger(accessPort) ? accessPort : 0,
    accessPorts,
    lastSequence: Number(run.lastSequence ?? run.last_sequence ?? 0),
  };
}

function normalizeSolve(payload) {
  if (!payload) return null;
  const solve = payload.item || payload.solve || payload;
  const runId = solve.runId || solve.run_id || solve.id;
  if (!runId) return null;
  return {
    ...solve,
    runId: String(runId),
    competitionId: String(solve.competitionId || solve.competition_id || ""),
    challengeId: String(solve.challengeId || solve.challenge_id || ""),
    teamId: String(solve.teamId || solve.team_id || ""),
    vehicleInstanceId: solve.vehicleInstanceId ?? solve.vehicle_instance_id ?? null,
    generation: Number(solve.generation ?? 0),
    solvedAt: solve.solvedAt || solve.solved_at || null,
    closedAt: solve.closedAt || solve.closed_at || null,
  };
}

function selectedChallenge() {
  return state.challenges.items.find((item) => item.id === state.challenges.selectedId) || state.challenges.detail;
}

function currentChallengeRun() {
  const selectedId = String(state.challenges.selectedId || "");
  if (!selectedId) return null;
  const candidates = [state.challenges.run, state.challenges.detail?.run, selectedChallenge()?.run];
  for (const candidate of candidates) {
    const run = normalizeRun(candidate);
    if (run && run.challengeId === selectedId) return run;
  }
  return null;
}

function currentChallengeSolve() {
  return state.challenges.solve || normalizeSolve(state.challenges.detail?.solve) || normalizeSolve(selectedChallenge()?.solve) || null;
}

async function loadChallenges({ quiet = false } = {}) {
  // A vehicle-range competition is a single private topology with its own
  // staged objectives. It must not query or render the conventional CTF
  // challenge catalog, otherwise participants are shown a misleading empty
  // "题目" page.
  if (isVehicleRangeCompetition()) {
    state.challenges.items = [];
    state.challenges.selectedId = null;
    state.challenges.detail = null;
    state.challenges.run = null;
    state.challenges.solve = null;
    disconnectChallengeStream();
    renderChallenges();
    return;
  }
  const scope = challengeScope();
  if (!scope) {
    state.challenges.items = [];
    state.challenges.selectedId = null;
    state.challenges.detail = null;
    state.challenges.run = null;
    disconnectChallengeStream();
    renderChallenges("当前账号未绑定参赛战队，无法建立题目运行作用域。");
    return;
  }
  if (state.challenges.loading) return;
  state.challenges.loading = true;
  try {
    const payload = await api(challengePath());
    const teamVehicleIDs = new Set((state.bootstrap?.instances || []).map((instance) => String(instance.id)));
    state.challenges.items = unwrapList(payload, "items", "challenges")
      .map(normalizeChallenge)
      .filter((item) => item.id && item.boundVehicleInstanceIds.some((id) => teamVehicleIDs.has(id)));
    if (!state.challenges.items.some((item) => item.id === state.challenges.selectedId)) {
      state.challenges.selectedId = state.challenges.items[0]?.id || null;
    }
    if (!state.challenges.selectedId) {
      state.challenges.detail = null;
      state.challenges.run = null;
      disconnectChallengeStream();
      renderChallenges();
      return;
    }
    const assignedInstance = assignChallengeVehicle(selectedChallenge());
    if (assignedInstance) {
      renderInstanceSelect(state.bootstrap?.instances || []);
      await loadTwin({ quiet: true });
      connectTwinStream();
    }
    await loadSelectedChallenge({ quiet: true });
  } catch (error) {
    state.challenges.items = [];
    state.challenges.detail = null;
    state.challenges.run = null;
    disconnectChallengeStream();
    renderChallenges(error.status === 404 ? "题目服务尚未发布任何可用内容。" : "题目服务暂时不可用，未使用本地数据替代。", error.status !== 404);
    if (!quiet && error.status !== 404) showToast(error.message, true);
  } finally {
    state.challenges.loading = false;
  }
}

async function loadSelectedChallenge({ quiet = false } = {}) {
  const challengeId = state.challenges.selectedId;
  if (!challengeId) return;
  try {
    const detailPayload = await api(challengePath(challengeId));
    if (state.challenges.selectedId !== challengeId) return;
    state.challenges.detail = normalizeChallenge(detailPayload);
    const index = state.challenges.items.findIndex((item) => item.id === challengeId);
    if (index >= 0) state.challenges.items[index] = { ...state.challenges.items[index], ...state.challenges.detail };
    state.challenges.run = normalizeRun(detailPayload.run || state.challenges.detail.run);
    state.challenges.solve = normalizeSolve(detailPayload.solve || state.challenges.detail.solve);
    // Reconcile the selected vehicle from this challenge's own detail. Never
    // carry a binding from a previously selected challenge.
    const previousInstanceId = state.selectedInstanceId;
    const assignedInstance = assignChallengeVehicle(state.challenges.detail);
    if (assignedInstance && assignedInstance.id !== previousInstanceId) {
      disconnectTwinStream();
      await loadTwin({ quiet: true });
      connectTwinStream(assignedInstance);
    }
    applySelectedChallengeVisuals(state.challenges.detail, assignedInstance);
    // Current challenge detail responses include run:null when the team is
    // idle. Only use the legacy fallback endpoint when that field is absent.
    // This prevents a normal "not started" state from generating a polling
    // 404 every few seconds.
    if (!state.challenges.run && !Object.prototype.hasOwnProperty.call(detailPayload, "run")) {
      try {
        state.challenges.run = normalizeRun(await api(challengePath(challengeId, "/run")));
      } catch (error) {
        if (error.status !== 404 || error.code !== "challenge_run_not_found") throw error;
      }
    }
    const catchupAfterSequence = state.challenges.lastSequence;
    if (!state.challenges.run) {
      state.challenges.lastSequence = 0;
      state.challenges.events = [];
    }
    renderChallenges();
    const run = currentChallengeRun();
    if (run) {
      await catchUpChallengeEvents(catchupAfterSequence);
      connectChallengeStream(challengeId, run);
    } else {
      disconnectChallengeStream();
    }
  } catch (error) {
    renderChallenges("无法读取这道题目的服务端状态。", true);
    if (!quiet) showToast(error.message, true);
  }
}

function normalizeArenaEvent(raw) {
  const event = raw?.event || raw;
  if (!event || event.schemaVersion !== "cybercar-arena-event-0.1") return null;
  const scope = event.scope || {};
  const sequence = Number(event.sequence);
  if (!Number.isSafeInteger(sequence) || sequence < 1 || typeof event.type !== "string") return null;
  return {
    ...event,
    sequence,
    scope: {
      competitionId: scope.competitionId || scope.competition_id,
      teamId: scope.teamId || scope.team_id,
      challengeId: scope.challengeId || scope.challenge_id,
      runId: scope.runId || scope.run_id,
      instanceId: scope.instanceId || scope.instance_id,
      generation: scope.generation,
    },
    data: event.data && typeof event.data === "object" ? event.data : {},
    createdAt: event.createdAt || event.created_at || null,
  };
}

function configuredChallengeVisualActions() {
  const challenge = state.challenges.detail || selectedChallenge();
  const rawActions = Array.isArray(challenge?.visualActions)
    ? challenge.visualActions
    : Array.isArray(challenge?.visual_actions)
      ? challenge.visual_actions
      : [];
  return rawActions
    .map((action) => String(action || "").trim())
    .filter((action, index, all) => action && ARENA_VISUAL_ACTIONS.has(action) && all.indexOf(action) === index);
}

function applySelectedChallengeVisuals(challenge = state.challenges.detail || selectedChallenge(), instance = null) {
  const vehicleInstance = instance || instanceById(assignedChallengeVehicleId(challenge));
  const instanceId = String(vehicleInstance?.id || assignedChallengeVehicleId(challenge) || state.selectedInstanceId || "");
  if (!instanceId || !window.vehicleTwin3D?.setChallengeVisualActions) return;
  // The server-provided challenge definition is the source of truth. This
  // changes only the local 3D presentation, never solve state or scoring.
  window.vehicleTwin3D.setChallengeVisualActions(instanceId, configuredChallengeVisualActions());
}

function eventMatchesCurrentRun(event) {
  const scope = challengeScope();
  const run = currentChallengeRun();
  if (!scope || !run) return false;
  const runId = run.id || run.runId || run.run_id;
  return event.scope.competitionId === scope.competitionId
    && event.scope.teamId === scope.teamId
    && event.scope.challengeId === state.challenges.selectedId
    && (!event.scope.runId || event.scope.runId === runId);
}

function dispatchArenaEvent(event) {
  window.__cybercarArenaEvents = Array.isArray(window.__cybercarArenaEvents) ? window.__cybercarArenaEvents : [];
  window.__cybercarArenaEvents.push(event);
  if (window.__cybercarArenaEvents.length > 64) window.__cybercarArenaEvents.shift();
  playArenaOverlay(event);
  if (window.vehicleTwin3D?.playArenaEvent) window.vehicleTwin3D.playArenaEvent(event);
  window.dispatchEvent(new CustomEvent("cybercar:arena-event", { detail: event }));
}

function dispatchAcceptedVisualEvent(run = currentChallengeRun(), challenge = state.challenges.detail || selectedChallenge()) {
  if (!challenge) return false;
  const runMatchesChallenge = run && (!run.challengeId || run.challengeId === challenge.id);
  const scopedRun = runMatchesChallenge ? run : null;
  const currentSolve = currentChallengeSolve();
  const solve = currentSolve && (!currentSolve.challengeId || currentSolve.challengeId === challenge.id) ? currentSolve : null;
  const runId = String(scopedRun?.id || solve?.runId || "");
  const vehicleInstanceId = String(scopedRun?.vehicleInstanceId || scopedRun?.vehicle_instance_id || solve?.vehicleInstanceId || assignedChallengeVehicleId(challenge) || "");
  if (!runId || !vehicleInstanceId) return false;
  const actions = (Array.isArray(challenge?.visualActions) ? challenge.visualActions : [])
    .map((action) => String(action).trim())
    .filter((action, index, all) => action && ARENA_VISUAL_ACTIONS.has(action) && all.indexOf(action) === index);
  if (!actions.includes("solve-scan")) actions.unshift("solve-scan");
  markMechanicalVisuals(vehicleInstanceId, actions);
  const key = `${runId}:${vehicleInstanceId}:accepted`;
  if (state.challenges.appliedVisualKeys.has(key)) return false;
  const event = {
    schemaVersion: "cybercar-arena-event-0.1",
    sequence: Date.now(),
    type: "flag.accepted",
    audience: "team",
    scope: {
      competitionId: scopedRun?.competitionId || scopedRun?.competition_id || solve?.competitionId || challengeScope()?.competitionId || "",
      teamId: scopedRun?.teamId || scopedRun?.team_id || solve?.teamId || currentTeamId(),
      challengeId: scopedRun?.challengeId || scopedRun?.challenge_id || solve?.challengeId || challenge.id || "",
      runId,
      instanceId: vehicleInstanceId,
      generation: scopedRun?.generation ?? solve?.generation ?? 0,
    },
    revision: Number(scopedRun?.revision || 0),
    data: {
      result: "accepted",
      effect: "solve-scan",
      effectId: `${runId}:accepted-local:${scopedRun?.generation ?? solve?.generation ?? 0}`,
      visualAction: "solve-scan",
      visualActions: actions,
    },
    createdAt: solve?.solvedAt || new Date().toISOString(),
  };
  state.challenges.appliedVisualKeys.add(key);
  markArenaSolved(vehicleInstanceId, true, state.challenges.selectedId, runId);
  dispatchArenaEvent(event);
  return true;
}

function arenaVisual(event) {
  const data = event?.data || {};
  const rawActions = event?.visualActions || event?.visual_actions || data.visualActions || data.visual_actions;
  const rawAction = event?.visualAction || event?.visual_action || data.visualAction || data.visual_action || "solve-scan";
  const eventActions = (Array.isArray(rawActions) ? rawActions : [rawAction])
    .map((action) => (typeof action === "string" ? action : (action?.action || action?.effect || "")))
    .map((action) => String(action).trim())
    .filter((action) => action && ARENA_VISUAL_ACTIONS.has(action));
  // A historical event may have been emitted before an administrator added
  // more final-result actions to the challenge. The challenge definition is
  // the current source of truth for the presentation, so merge it into the
  // event without changing the server-side score or evidence record.
  const configuredActions = event?.type === "flag.accepted" ? configuredChallengeVisualActions() : [];
  const actions = [...eventActions, ...configuredActions]
    .filter((action, index, all) => all.indexOf(action) === index);
  return {
    actions,
    effectId: String(event?.effectId || event?.effect_id || data.effectId || data.effect_id || ""),
    durationMs: Math.min(8000, Math.max(400, Number(event?.durationMs || event?.duration_ms || data.durationMs || data.duration_ms || 2200))),
  };
}

function playArenaOverlay(event) {
  const visual = arenaVisual(event);
  if (event?.type !== "flag.accepted") return;
  if (!visual.actions.length || !visual.effectId) return;
  const instanceId = event?.scope?.instanceId || event?.scope?.instance_id || event?.data?.instanceId || event?.data?.instance_id || state.challenges.run?.vehicleInstanceId || state.selectedInstanceId;
  markMechanicalVisuals(instanceId, visual.actions);
  const stage = $("#twin-stage");
  if (!stage) return;
  const pulse = (node, className) => {
    if (!node) return;
    node.classList.remove(className);
    void node.getBoundingClientRect();
    node.classList.add(className);
    window.setTimeout(() => node.classList.remove(className), visual.durationMs);
  };
  const hasMechanicalAction = visual.actions.some((action) => MECHANICAL_VISUAL_ACTIONS.has(action));
  if (visual.actions.includes("solve-scan") && !hasMechanicalAction) pulse(stage, "arena-solve-scan");
}

function applyChallengeEvent(raw) {
  const event = normalizeArenaEvent(raw);
  if (!event || !eventMatchesCurrentRun(event)) return false;
  if (state.challenges.events.some((item) => item.sequence === event.sequence)) return false;
  state.challenges.lastSequence = Math.max(state.challenges.lastSequence, event.sequence);
  state.challenges.events = [...state.challenges.events, event].sort((a, b) => b.sequence - a.sequence).slice(0, 20);
  if (event.type === "flag.accepted" && state.challenges.run) state.challenges.run.status = "solved";
  if (event.type === "flag.accepted") {
    const instanceId = event.scope.instanceId || event.data.instanceId || event.data.instance_id || state.challenges.run?.vehicleInstanceId;
    markArenaSolved(instanceId, true, state.challenges.selectedId, state.challenges.run?.id || event.scope.runId);
    dispatchArenaEvent(event);
  }
  renderChallengeDetail();
  clearTimeout(applyChallengeEvent.refreshTimer);
  applyChallengeEvent.refreshTimer = setTimeout(() => {
    loadSelectedChallenge({ quiet: true });
    loadBootstrap({ quiet: true });
  }, 800);
  return true;
}

async function catchUpChallengeEvents(afterSequence = state.challenges.lastSequence) {
  const stream = state.challenges.stream;
  if (stream.catchupPromise || !state.challenges.selectedId || !currentChallengeRun()) return stream.catchupPromise;
  const challengeId = state.challenges.selectedId;
  stream.catchupPromise = (async () => {
    let cursor = Math.max(0, Number(afterSequence) || 0);
    for (let page = 0; page < 10; page += 1) {
      const payload = await api(`${challengePath(challengeId, "/run/events")}?afterSequence=${cursor}&limit=200`);
      if (state.challenges.selectedId !== challengeId) return;
      const events = unwrapList(payload, "items", "events").map(normalizeArenaEvent).filter(Boolean).sort((a, b) => a.sequence - b.sequence);
      for (const event of events) applyChallengeEvent(event);
      const next = events.reduce((max, event) => Math.max(max, event.sequence), cursor);
      if (events.length < 200 || next <= cursor) break;
      cursor = next;
    }
  })().catch((error) => {
    if (error.status !== 404) console.warn("题目事件补偿失败", error);
  }).finally(() => { stream.catchupPromise = null; });
  return stream.catchupPromise;
}

function disconnectChallengeStream() {
  const stream = state.challenges.stream;
  clearTimeout(stream.reconnectTimer);
  stream.reconnectTimer = null;
  const socket = stream.socket;
  stream.socket = null;
  stream.challengeId = null;
  stream.runId = null;
  if (socket && socket.readyState < WebSocket.CLOSING) socket.close(1000, "challenge changed");
}

function connectChallengeStream(challengeId = state.challenges.selectedId, run = currentChallengeRun()) {
  if (participantIsDisqualified()) return;
  if (!challengeId || !run || !("WebSocket" in window)) return;
  const runId = String(run.id || run.runId || run.run_id || "");
  const stream = state.challenges.stream;
  if (stream.challengeId === challengeId && stream.runId === runId && stream.socket?.readyState <= WebSocket.OPEN) return;
  disconnectChallengeStream();
  const url = challengeSocketUrl(challengeId);
  if (!url) return;
  const socket = new WebSocket(url);
  stream.socket = socket;
  stream.challengeId = challengeId;
  stream.runId = runId;
  renderChallengeStreamState("连接中");
  socket.addEventListener("open", () => {
    if (stream.socket !== socket) return;
    stream.reconnectDelayMs = 1000;
    renderChallengeStreamState("实时在线");
    catchUpChallengeEvents(state.challenges.lastSequence);
  });
  socket.addEventListener("message", (message) => {
    if (stream.socket !== socket) return;
    try { applyChallengeEvent(JSON.parse(message.data)); } catch (error) { console.warn("忽略无法解析的题目消息", error); }
  });
  socket.addEventListener("close", () => {
    if (stream.socket !== socket || state.challenges.selectedId !== challengeId) return;
    stream.socket = null;
    renderChallengeStreamState("补偿同步");
    catchUpChallengeEvents(state.challenges.lastSequence);
    const delay = stream.reconnectDelayMs;
    stream.reconnectDelayMs = nextReconnectDelay(delay);
    stream.reconnectTimer = setTimeout(() => connectChallengeStream(challengeId, currentChallengeRun()), reconnectDelayWithJitter(delay));
  });
  socket.addEventListener("error", () => socket.close());
}

async function startChallengeRun() {
  const challengeId = state.challenges.selectedId;
  if (!challengeId || state.challenges.busy) return;
  const binding = state.challenges.bindingChallengeId === challengeId ? state.challenges.bindingInstanceId : "";
  if (!binding) {
    showToast("该题目尚未分配赛事公共车辆，请联系赛事管理员在题目库中绑定车辆。", true);
    return;
  }
  state.challenges.busy = true;
  renderChallengeDetail();
  try {
    const payload = await api(challengePath(challengeId, "/run"), {
      method: "POST",
      body: JSON.stringify({}),
    });
    state.challenges.run = normalizeRun(payload);
    if (state.challenges.run?.vehicleInstanceId) {
      state.challenges.bindingInstanceId = state.challenges.run.vehicleInstanceId;
      state.challenges.bindingChallengeId = challengeId;
    }
		showToast(String(state.challenges.detail?.runtimeKind || "").toLowerCase() === "attachment" ? "附件题答题会话已建立" : "已分配车辆的题目运行已建立");
    state.challenges.events = [];
    state.challenges.lastSequence = 0;
    await loadSelectedChallenge({ quiet: true });
  } catch (error) {
    showToast(error.message, true);
  } finally {
    state.challenges.busy = false;
    renderChallengeDetail();
  }
}

async function stopChallengeRun() {
	const challengeId = state.challenges.selectedId;
	const run = currentChallengeRun();
	if (!challengeId || !run || state.challenges.busy) return;
	state.challenges.busy = true;
	renderChallengeDetail();
	try {
		await api(challengePath(challengeId, "/run/reset"), { method: "POST", body: "{}" });
		if (run.vehicleInstanceId) markArenaSolved(run.vehicleInstanceId, false, challengeId, run.id);
		disconnectChallengeStream();
		state.challenges.run = null;
		state.challenges.bindingInstanceId = null;
		state.challenges.bindingChallengeId = null;
		state.challenges.events = [];
		state.challenges.lastSequence = 0;
		showToast(String(state.challenges.detail?.runtimeKind || "").toLowerCase() === "attachment" ? "答题会话已结束，可以重新开始" : "容器已停止，可以重新启动题目");
		await loadSelectedChallenge({ quiet: true });
	} catch (error) {
		showToast(error.message, true);
	} finally {
		state.challenges.busy = false;
		renderChallengeDetail();
	}
}

function changeChallengeRun() {
	return currentChallengeRun() ? stopChallengeRun() : startChallengeRun();
}

async function submitFlag(form) {
  const challengeId = state.challenges.selectedId;
  const input = $("#flag-input");
  const flag = input.value.trim();
  input.value = "";
  if (!challengeId || !flag || state.challenges.busy) return;
  state.challenges.busy = true;
  renderChallengeDetail();
  setText("#flag-result", "正在由服务端校验…");
  try {
    const result = await api(challengePath(challengeId, "/submissions"), { method: "POST", body: JSON.stringify({ flag }) });
    const accepted = result.accepted === true || result.result === "accepted";
    const node = $("#flag-result");
    node.classList.toggle("is-success", accepted);
    node.classList.toggle("is-error", !accepted);
    node.textContent = accepted ? (result.duplicate ? "Flag 已在此前通过，未重复计分。" : "Flag 验证通过，解题结果已入账。") : "Flag 未通过验证。";
    if (accepted) {
      dispatchAcceptedVisualEvent();
      await catchUpChallengeEvents(state.challenges.lastSequence);
      await Promise.all([loadSelectedChallenge({ quiet: true }), loadBootstrap({ quiet: true })]);
    }
  } catch (error) {
    const node = $("#flag-result");
    node.classList.add("is-error");
    node.classList.remove("is-success");
    node.textContent = error.message;
  } finally {
    state.challenges.busy = false;
    renderChallengeDetail();
    form.reset();
  }
}

async function loadTwin({ quiet = false } = {}) {
  const instance = selectedInstance();
  if (!instance) return;
  const requestedInstanceId = instance.id;
  try {
    const raw = await api(scopedPath(instance, "/twin"));
    // A participant can switch challenges while the previous twin request is
    // in flight. Do not let a late response paint the old vehicle over the
    // newly selected challenge vehicle.
    if (state.selectedInstanceId !== requestedInstanceId) return;
    state.twin = normalizeTwin(raw, instance);
    renderTwin(state.twin, instance);
  } catch (error) {
    if (state.selectedInstanceId !== requestedInstanceId) return;
    state.twin = null;
    renderTwinOffline(instance, error.message);
    if (!quiet) showToast(error.message, true);
  }
}

function normalizeTwin(raw, instance) {
  if (raw.schemaVersion === "cybercar-twin-0.1") return { ...raw, instanceId: instance.id };

  const signalMap = raw.signals && typeof raw.signals === "object" ? raw.signals : {};
  const read = (...needles) => {
    for (const [key, candidate] of Object.entries(signalMap)) {
      if (!needles.some((needle) => key.toLowerCase().includes(needle))) continue;
      if (candidate && typeof candidate === "object") {
        if (candidate.available === false) continue;
        return candidate.value;
      }
      return candidate;
    }
    return null;
  };
  const participants = Array.isArray(raw.participants) ? raw.participants : [];
  const nodes = participants.slice(0, 10).map((participant, index) => ({
    id: String(participant.id || participant.role || `participant-${index}`),
    label: String(participant.name || participant.role || participant.id || "VEHICLE NODE"),
    zone: String(participant.provider || participant.kind || "vehicle"),
    status: ["running", "ready", "online"].includes(String(participant.status).toLowerCase()) ? "online" : "offline",
  }));
  return {
    schemaVersion: "cybercar-twin-0.1",
    instanceId: raw.instanceId || instance.id,
    generation: raw.runtimeGeneration ?? raw.generation ?? instance.generation,
    capturedAt: raw.projectedAt || new Date().toISOString(),
    source: "provider",
    sourceLabel: "LIVE / VEHICLE-SIM PROVIDER",
    operationalState: raw.runtimeStatus || instance.status,
    vehicle: {
      label: instance.label,
      definitionId: raw.vehicleDefinitionId || instance.vehicle_definition_id,
      team: { id: instance.team_id, name: instance.team_name, code: instance.team_code },
    },
    signals: {
      speedKph: read("speed"),
      gear: read("gear"),
      steeringDeg: read("steer"),
      batterySocPercent: read("soc", "battery"),
      canFdLoadPercent: null,
      ignition: read("ignition"),
    },
    nodes,
    links: Array.isArray(raw.buses)
      ? raw.buses.slice(0, 8).map((bus) => ({ from: "gateway", to: String(bus.id || bus.name || "bus"), protocol: String(bus.kind || bus.protocol || "VEHICLE BUS") }))
      : [],
    contentStatus: { challengeRuntime: "external" },
    raw,
  };
}

function renderBootstrap(payload) {
  const { competition, stats, teams, instances, events } = payload;
  setText("#competition-title", competition.title);
  setText("#competition-phase", competition.phase);
  setText("#competition-status", competition.status.toUpperCase());
  renderOverviewMetrics(payload, state.vehicleRange);
  syncCompetitionModeNavigation();

  const providerIndicator = $("#provider-indicator");
  providerIndicator.classList.add("is-online");
  providerIndicator.classList.remove("is-offline");
  setText("#provider-status", competitionModeLabel());
  providerIndicator.title = `当前赛事模式：${competitionModeLabel()}`;

  renderInstanceSelect(instances);
  renderLeaderboard(teams);
  renderRecentEvents(events);
  renderArena(instances);
  renderTeams(teams, instances);
  renderEvidence(events);
  updateSolvedStage();
  tickCompetitionCountdown();
}

function renderInstanceSelect(instances) {
  const visibleInstances = participantVisibleInstances(instances);
  const challengeItems = state.challenges.items || [];
  const assignedByVehicle = new Map();
  for (const challenge of challengeItems) {
    for (const instanceId of challenge.boundVehicleInstanceIds || []) {
      const list = assignedByVehicle.get(String(instanceId)) || [];
      list.push(challenge.title || challenge.slug || challenge.id);
      assignedByVehicle.set(String(instanceId), list);
    }
  }
  const candidateInstances = visibleInstances.filter((item) => !assignedByVehicle.size || assignedByVehicle.has(String(item.id)));
  const instance = candidateInstances.find((item) => item.id === state.selectedInstanceId) || candidateInstances[0] || null;
  if (!state.selectedInstanceId && instance) state.selectedInstanceId = instance.id;
  const select = $("#instance-select");
  if (!select) return;
  select.replaceChildren(...candidateInstances.map((item) => {
    const assignments = assignedByVehicle.get(String(item.id)) || [];
    const suffix = assignments.length ? ` · ${assignments.join(" / ")}` : "";
    const option = element("option", "", `${item.label} / ${item.id}${suffix}`);
    option.value = item.id;
    return option;
  }));
  if (!candidateInstances.length) {
    select.append(element("option", "", "未分配"));
  }
  select.disabled = candidateInstances.length < 1;
  select.value = instance?.id || "";
}

function renderLeaderboard(teams) {
  const list = $("#leaderboard");
  list.replaceChildren();
  const maxScore = Math.max(...teams.map((team) => Number(team.score)), 1);
  teams.slice(0, 5).forEach((team) => {
    const item = element("li");
    item.style.setProperty("--team-color", team.color);
    const name = element("span", "team-name", team.name);
    const code = element("span", "team-code", `${team.code} / ${team.status.toUpperCase()}`);
    const organization = element("span", "team-organization", `组织：${team.organization || team.organization_name || "未填写单位"}`);
    const score = element("span", "score");
    score.append(document.createTextNode(String(team.score)), element("small", "", " PTS"));
    const bar = element("span", "rank-bar");
    const fill = element("i");
    fill.style.width = `${(Number(team.score) / maxScore) * 100}%`;
    bar.append(fill);
    item.append(name, code, organization, score, bar);
    list.append(item);
  });
  if (!teams.length) list.append(emptyState("暂无战队积分记录"));
}

function eventNode(event) {
  const item = element("article", `event-item ${event.severity || "info"}`);
  const meta = element("div", "event-meta");
  meta.append(
    element("span", "", `#${String(event.sequence).padStart(4, "0")} / G${event.generation ?? "—"}`),
    element("time", "", formatTime(event.created_at)),
  );
  item.append(meta, element("p", "", event.message));
  return item;
}

function renderRecentEvents(events) {
  const list = $("#recent-events");
  list.replaceChildren(...events.slice(0, 7).map(eventNode));
  if (!events.length) list.append(emptyState("暂无可信证据事件"));
}

function statusTag(status) {
  const normalized = String(status || "").toLowerCase();
  const labels = { display: "展示车辆", running: "运行中", degraded: "降级", stopped: "已停止", error: "异常" };
  const tag = element("span", `status-tag ${normalized}`);
  tag.append(element("i"), document.createTextNode(labels[normalized] || status || "未知"));
  return tag;
}

function renderArena(instances) {
  instances = participantVisibleInstances(instances);
  const body = $("#arena-table");
  body.replaceChildren();
  for (const instance of instances) {
    const row = document.createElement("tr");
    const identity = element("td", "cell-primary");
    identity.append(element("strong", "", instance.label), element("small", "", instance.id));
    const team = element("td", "cell-primary");
    team.append(element("strong", "", instance.team_name || "赛事公共车辆"), element("small", "", instance.team_code || "PUBLIC"));
    const definition = element("td", "", instance.vehicle_definition_id);
    const source = element("td", "", "3D DISPLAY");
    const status = document.createElement("td");
    status.append(statusTag(instance.status));
    const generation = element("td", "", `G${instance.generation} / V${instance.version}`);
    const binding = document.createElement("td");
    const assignment = element("div", "arena-assignment");
    const challenges = compatibleChallenges(instance);
    if (!challenges.length) {
      assignment.append(element("span", "arena-assignment-empty", "管理员尚未分配题目"));
    } else {
      challenges.forEach((challenge) => {
        const item = element("div", "arena-assignment-item");
        const copy = element("span", "", challenge.title + " / " + challenge.slug);
        const enter = element("button", "", "进入题目");
        enter.type = "button";
        enter.dataset.arenaOpen = instance.id;
        enter.dataset.arenaChallengeId = challenge.id;
        item.append(copy, enter);
        if (state.challenges.run?.vehicleInstanceId === instance.id && state.challenges.selectedId === challenge.id) {
          item.append(element("small", "", "运行中"));
        }
        assignment.append(item);
      });
    }
    const assignmentMeta = element("small", "arena-assignment-meta", challenges.length ? "管理员已分配" : "等待赛事管理员配置");
    assignment.append(assignmentMeta);
    if (state.solvedBindings.has(instance.id)) assignment.append(element("small", "arena-assignment-meta", "动画循环"));
    binding.append(assignment);
    row.append(identity, team, definition, source, status, generation, binding);
    body.append(row);
  }
  if (!instances.length) {
    const row = document.createElement("tr");
    const cell = element("td", "table-empty", "暂无 3D 展示车辆");
    cell.colSpan = 7;
    row.append(cell);
    body.append(row);
  }
}

function renderTeams(teams, instances) {
  const grid = $("#team-grid");
  grid.replaceChildren();
  teams.forEach((team, index) => {
    const card = element("article", "team-card");
    card.dataset.rank = String(index + 1).padStart(2, "0");
    card.style.setProperty("--team-color", team.color);
    const sigil = element("div", "team-sigil");
    const score = element("div", "team-score");
    score.append(element("strong", "", team.score), element("small", "", "LEDGER POINTS"));
    const footer = document.createElement("footer");
    const instanceCount = instances.filter((instance) => instance.team_id === team.id).length;
    const vehicleSummary = isTeamUser() && team.id !== currentTeamId() ? "车辆信息已隔离" : `${instanceCount} 竞技车`;
    footer.append(element("span", "", vehicleSummary), element("span", "", team.status.toUpperCase()));
    card.append(sigil, element("h3", "", team.name), element("div", "team-card-code", team.code), score, footer);
    grid.append(card);
  });
  if (!teams.length) grid.append(emptyState("暂无已登记战队"));
}

function renderEvidence(events) {
  const ledger = $("#evidence-ledger");
  ledger.replaceChildren();
  for (const event of events) {
    const row = element("article", "ledger-row");
    const sequence = element("div", "ledger-seq", `#${String(event.sequence).padStart(5, "0")}`);
    const kind = element("div", "ledger-kind");
    kind.append(element("strong", "", event.kind), element("small", "", `${event.severity.toUpperCase()} / G${event.generation ?? "—"}`));
    const message = element("div", "ledger-message", event.message);
    const scope = element("div", "ledger-scope");
    scope.append(element("strong", "", event.team_code || "PLATFORM"), element("small", "", `${event.instance_label || "GLOBAL"} / ${formatTime(event.created_at)}`));
    row.append(sequence, kind, message, scope);
    ledger.append(row);
  }
  if (!events.length) ledger.append(emptyState("暂无追加式证据事件"));
}

function emptyState(message) {
  const node = element("div", "data-empty");
  node.append(element("span", "", "NO DATA"), element("p", "", message));
  return node;
}

function renderNoInstance() {
  setText("#svg-vehicle-id", "NO INSTANCE");
  setText("#twin-source", "NO DISPLAY INSTANCE");
  setText("#twin-captured", "—");
  setText("#twin-generation", "—");
  setText("#instance-state", "NOT PROVISIONED");
  ["#signal-speed", "#signal-gear", "#signal-steering", "#signal-soc", "#signal-bus"].forEach((selector) => setText(selector, "—"));
  const stage = $("#twin-stage");
  stage?.classList.add("is-offline");
  $$(".ecu-node", stage).forEach((node) => node.classList.add("is-offline"));
  renderTopology({ nodes: [], links: [] });
  renderSignalContracts({});
  updateSolvedStage(null);
}

function renderChallenges(emptyMessage = "", isError = false) {
  const list = $("#challenge-list");
  if (!list) return;
  list.replaceChildren();
  if (state.bootstrap?.instances) renderInstanceSelect(state.bootstrap.instances);
  if (isVehicleRangeCompetition()) {
    setText("#challenge-count", "整车靶场模式");
    renderOverviewMetrics(state.bootstrap, state.vehicleRange);
    if (state.bootstrap?.instances) renderArena(state.bootstrap.instances);
    const empty = $("#challenge-empty");
    const detail = $("#challenge-detail");
    if (empty) {
      empty.hidden = false;
      empty.classList.remove("is-error");
    }
    if (detail) detail.hidden = true;
    setText("#challenge-empty-title", "本赛事使用整车攻击靶场");
    setText("#challenge-empty-detail", "节点、逻辑总线与阶段目标均在“整车靶场”中管理；请从左侧进入该工作区并启动本队私有靶场。");
    return;
  }
  state.challenges.items.forEach((challenge, index) => {
    const button = element("button", "challenge-list-item");
    button.type = "button";
    button.dataset.challengeId = challenge.id;
    button.classList.toggle("is-active", challenge.id === state.challenges.selectedId);
    const meta = element("span", "", `${String(index + 1).padStart(2, "0")} / ${challenge.slug}`);
    const title = element("strong", "", challenge.title);
    const runtime = challenge.runtimeKind === "attachment" ? "ATTACHMENT ONLY" : challenge.runtimeKind ? challenge.runtimeKind.toUpperCase() : "VEHICLE RUNTIME";
    const attachmentCount = Array.isArray(challenge.attachments) ? challenge.attachments.length : 0;
    const attachmentLabel = attachmentCount ? ` · 附件 ${attachmentCount}` : "";
    const footer = element("small", "", `${challenge.baseScore} PTS · ${runtime}${attachmentLabel}`);
    button.append(meta, title, footer);
    list.append(button);
  });
  setText("#challenge-count", `${state.challenges.items.length} 道已发布题目`);
  setText("#metric-paths", String(state.challenges.items.length).padStart(2, "0"));
  if (state.bootstrap?.instances) renderArena(state.bootstrap.instances);
  const empty = $("#challenge-empty");
  const detail = $("#challenge-detail");
  const hasSelection = Boolean(selectedChallenge());
  empty.hidden = hasSelection;
  detail.hidden = !hasSelection;
  empty.classList.toggle("is-error", isError);
  if (!hasSelection) {
    setText("#challenge-empty-title", isError ? "题目服务暂不可用" : "暂无可用车辆题目");
    setText("#challenge-empty-detail", emptyMessage || "平台不会生成假题目或模拟进度。题目发布并绑定车辆后将在这里出现。");
    return;
  }
  renderChallengeDetail();
}

function activateChallenge(challengeId, preferredInstanceId = "") {
  const challenge = state.challenges.items.find((item) => item.id === challengeId);
  if (!challenge) return;
  state.challenges.selectedId = challenge.id;
  state.challenges.detail = null;
  state.challenges.run = null;
  state.challenges.solve = null;
  state.challenges.bindingChallengeId = null;
  state.challenges.bindingInstanceId = null;
  state.challenges.events = [];
  state.challenges.lastSequence = 0;
  disconnectChallengeStream();
  const assigned = assignChallengeVehicle(challenge);
  if (preferredInstanceId && (challenge.boundVehicleInstanceIds || []).includes(preferredInstanceId)) {
    state.selectedInstanceId = preferredInstanceId;
    state.challenges.bindingChallengeId = challenge.id;
    state.challenges.bindingInstanceId = preferredInstanceId;
    renderInstanceSelect(state.bootstrap?.instances || []);
  } else if (!assigned) {
    state.selectedInstanceId = null;
  }
  // Clear the previous challenge's presentation immediately. The selected
  // challenge detail will apply its server-configured actions after loading.
  if (state.selectedInstanceId && window.vehicleTwin3D?.setChallengeVisualActions) {
    window.vehicleTwin3D.setChallengeVisualActions(state.selectedInstanceId, []);
  }
  loadTwin({ quiet: true });
  connectTwinStream();
  renderChallenges();
  loadSelectedChallenge();
}

function selectAssignedVehicle(instanceId) {
  const id = String(instanceId || "");
  const targetChallenge = state.challenges.items.find((item) => (item.boundVehicleInstanceIds || []).includes(id));
  if (!targetChallenge) return;
  if (targetChallenge.id !== state.challenges.selectedId) {
    activateChallenge(targetChallenge.id, id);
    return;
  }
  state.selectedInstanceId = id;
  state.challenges.bindingChallengeId = targetChallenge.id;
  state.challenges.bindingInstanceId = id;
  disconnectTwinStream();
  loadTwin({ quiet: true });
  connectTwinStream();
  renderInstanceSelect(state.bootstrap?.instances || []);
  renderChallengeDetail();
}

function renderChallengeStreamState(value) {
  setText("#challenge-stream-state", value);
}

function renderChallengeAccess(challenge, run) {
  const panel = $("#challenge-access");
  const endpoint = $("#challenge-access-endpoint");
  const route = $("#challenge-access-route");
  const link = $("#challenge-access-link");
  if (!panel || !endpoint || !route || !link) return;
  const runtimeKind = String(challenge?.runtimeKind || challenge?.runtime_kind || "").trim().toLowerCase();
  // Always clear the previous challenge's endpoint before deciding whether
  // the current challenge has a runtime. Attachment challenges must never
  // inherit a TCP address from the previously selected container challenge.
  panel.hidden = true;
  panel.style.display = "none";
  endpoint.textContent = "—";
  route.textContent = "";
  link.dataset.endpoint = "";
  link.removeAttribute("href");
  if (runtimeKind === "attachment") {
	return;
	}
	const attackMode = String(state.bootstrap?.competition?.mode || "").toLowerCase() === "attack";
	if (attackMode && run?.id) {
		const targets = (state.attackTargetsPayload?.items || []).filter((item) => {
			const targetID = String(item.target_id || item.targetId || "");
			return targetID === String(run.id) || targetID.startsWith(`${run.id}-port-`);
		}).sort((a, b) => String(a.target_id || a.targetId || "").localeCompare(String(b.target_id || b.targetId || ""), undefined, { numeric: true }));
    const gatewayURL = String(state.attackTargetsPayload?.gatewayUrl || "").replace(/\/$/, "");
		if (targets.length) {
			const proxies = targets.map((target) => {
				const host = String(target.targetHost || target.target_host || "").trim();
				const port = Number(target.targetPort || target.target_port || 0);
				return host && port ? `${host}:${port}` : `${gatewayURL}/v1/connect/${target.id}`;
			});
			panel.hidden = false;
			panel.style.removeProperty("display");
			endpoint.textContent = proxies.join("\n");
			route.textContent = proxies.some((value) => value.startsWith("http")) ? (proxies.length > 1 ? `攻击机代理 · ${proxies.length} 个端口 · 仅在个人云桌面内使用` : "攻击机代理 · 仅在个人云桌面内使用") : "攻击机私有内网 · 仅本队云桌面可访问";
			link.dataset.endpoint = proxies.join("\n");
			link.dataset.protocol = "tcp";
			link.removeAttribute("href");
			return;
		}
	}

  const host = String(run?.accessHost || "").trim();
  const port = Number(run?.accessPort || 0);
  const entryPort = Number(challenge?.entryPort || 0);
  const protocol = String(challenge?.accessProtocol || challenge?.access_protocol || "tcp").toLowerCase() === "http" ? "http" : "tcp";
  if (!run || !host || !Number.isInteger(port) || port < 1 || port > 65535) {
    panel.hidden = true;
    return;
  }

  const displayHost = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  const ports = Array.isArray(run.accessPorts) && run.accessPorts.length ? run.accessPorts : [{ hostPort: port, guestPort: entryPort, protocol }];
  const endpointText = ports.map((item) => `${displayHost}:${item.hostPort}`).join("、");
  panel.hidden = false;
  panel.style.removeProperty("display");
  endpoint.textContent = endpointText;
  route.textContent = ports.length > 1 ? `KVM 多端口：${ports.map((item) => `${item.guestPort}→${item.hostPort}/${String(item.protocol || "tcp").toUpperCase()}`).join("、")} · 实例 ${run.generation ? `GEN ${run.generation}` : "已建立"}` : entryPort ? `容器端口 ${entryPort} / ${protocol.toUpperCase()} · 实例 ${run.generation ? `GEN ${run.generation}` : "已建立"}` : `容器端口 / ${protocol.toUpperCase()}`;
  link.dataset.endpoint = endpointText;
  link.dataset.protocol = protocol;
  if (protocol === "http") {
    link.href = `http://${displayHost}:${port}/`;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = "打开 HTTP 靶场";
    link.title = link.href;
  } else {
    link.href = "#";
    link.removeAttribute("target");
    link.removeAttribute("rel");
    link.textContent = "复制 TCP 地址";
    link.title = "这是原始 TCP/DoIP 端口，浏览器不能直接打开";
  }
}

function formatAttachmentSizeForDisplay(bytes) {
  const value = Number(bytes || 0);
  if (!Number.isFinite(value) || value < 1024) return `${value || 0} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function renderChallengeDetail() {
  const challenge = state.challenges.detail || selectedChallenge();
  if (!challenge || $("#challenge-detail")?.hidden) return;
  const candidateRun = currentChallengeRun();
  const run = candidateRun && candidateRun.challengeId === challenge.id ? candidateRun : null;
  const candidateSolve = currentChallengeSolve();
  const solve = candidateSolve && (!candidateSolve.challengeId || candidateSolve.challengeId === challenge.id) ? candidateSolve : null;
  const attachmentOnly = String(challenge.runtimeKind || challenge.runtime_kind || "").trim().toLowerCase() === "attachment";
  const staticFlag = String(challenge.flagMode || "").toLowerCase() === "static";
  if (!run && state.challenges.bindingChallengeId !== challenge.id) assignChallengeVehicle(challenge);
  const runStatus = String(run?.status || "not-started").toLowerCase();
  const solved = runStatus === "solved" || Boolean(solve?.runId);
  const detail = $("#challenge-detail");
  detail?.classList.toggle("is-solved", solved);
  const solvedBanner = $("#challenge-solved-banner");
  if (solvedBanner) solvedBanner.hidden = !solved;
  const boundInstanceId = assignedChallengeVehicleId(challenge);
  const boundInstance = instanceById(boundInstanceId);
  setText("#challenge-bound-vehicle", boundInstance ? `${boundInstance.label} / ${boundInstance.id}` : "未分配");
  if (run?.vehicleInstanceId) {
    state.challenges.bindingInstanceId = run.vehicleInstanceId;
    state.challenges.bindingChallengeId = challenge.id;
    if (state.bootstrap?.instances) renderArena(state.bootstrap.instances);
  }
  if (solved && boundInstanceId) {
    markArenaSolved(boundInstanceId, true, challenge.id, run?.id || solve?.runId || "");
    dispatchAcceptedVisualEvent(run, challenge);
  }
  setText("#challenge-slug", `${challenge.slug} / V${challenge.version ?? "—"}`);
  setText("#challenge-title", challenge.title);
  setText("#challenge-score", String(challenge.baseScore));
  setText("#challenge-description", challenge.description || "题目未提供公开说明。");
  const attachmentPanel = $("#challenge-attachments");
  if (attachmentPanel) {
    attachmentPanel.replaceChildren();
    const attachments = Array.isArray(challenge.attachments) ? challenge.attachments : [];
    attachmentPanel.hidden = !attachments.length;
    if (attachments.length) {
      const heading = element("strong", "", `题目附件 · ${attachments.length} 个（点击下载）`); attachmentPanel.append(heading);
      const list = element("div", "challenge-attachment-links");
      attachments.forEach((attachment) => {
        const link = document.createElement("a");
        link.href = attachment.downloadPath || "#";
        link.textContent = `下载 ${attachment.filename} · ${formatAttachmentSizeForDisplay(attachment.sizeBytes)}`;
        link.setAttribute("download", attachment.filename);
        link.setAttribute("aria-label", `下载题目附件 ${attachment.filename}`);
        link.rel = "noopener";
        if (!attachment.downloadPath) {
          link.setAttribute("aria-disabled", "true");
          link.addEventListener("click", (event) => event.preventDefault());
        }
        list.append(link);
      });
      attachmentPanel.append(list);
    }
  }
  setText("#challenge-run-state", run ? (solved ? "已解出" : attachmentOnly ? "可直接提交" : runStatus.toUpperCase()) : solved ? "已解出" : attachmentOnly ? "无需启动，可直接提交" : "尚未启动");
  setText("#flag-form label strong", staticFlag ? "提交固定 Flag" : "提交动态 Flag");
  $("#challenge-run-state")?.classList.toggle("is-solved", solved);
  setText("#challenge-generation", run ? `GEN ${run.generation ?? "—"}` : solve?.generation ? `GEN ${solve.generation}` : "—");
  setText("#challenge-cursor", state.challenges.lastSequence ? `SEQ ${state.challenges.lastSequence}` : "SEQ —");
  renderChallengeAccess(challenge, run);
  const start = $("#challenge-start");
  start.hidden = attachmentOnly;
  start.textContent = state.challenges.busy
    ? (run ? "正在停止容器…" : "正在排队启动…")
    : run
      ? (attachmentOnly ? "结束答题" : "停止容器")
      : boundInstanceId
        ? (solved ? "重新启动题目运行" : attachmentOnly ? "开始答题" : "启动已分配题目")
        : "等待管理员分配";
  start.classList.toggle("is-reset", Boolean(run));
  start.disabled = state.challenges.busy || runStatus === "resetting" || (!run && !boundInstanceId);
  const canSubmit = attachmentOnly
    ? !solved && !state.challenges.busy && (!run || !["solved", "failed", "closed", "resetting", "provisioning"].includes(runStatus))
    : Boolean(run) && !["solved", "failed", "closed", "resetting", "provisioning"].includes(runStatus);
  $("#flag-input").disabled = !canSubmit || state.challenges.busy;
  $("#flag-form button").disabled = !canSubmit || state.challenges.busy;
  if (!run) renderChallengeStreamState(solved ? "已解出 / 答题会话已结束" : attachmentOnly ? "附件题可直接提交" : "未建立运行");
  else if (!state.challenges.stream.socket) renderChallengeStreamState("补偿同步");

  const events = $("#challenge-events");
  events.replaceChildren();
  state.challenges.events.forEach((event) => {
    const row = element("article", "challenge-event-row");
    row.append(
      element("span", "", `#${event.sequence}`),
      element("strong", "", event.type === "flag.accepted" ? "Flag 验证通过" : event.type),
      element("time", "", formatTime(event.createdAt)),
    );
    events.append(row);
  });
  if (!state.challenges.events.length) events.append(emptyState(run ? "暂无判定事件" : attachmentOnly ? "提交后接收判定事件" : "启动题目后接收判定事件"));
}

function renderTwin(twin, instance) {
  window.__cybercarTwin = twin;
  window.dispatchEvent(new CustomEvent("cybercar:twin", { detail: twin }));
  const signals = twin.signals || {};
  setText("#svg-vehicle-id", `${twin.vehicle?.label || instance.label} / ${twin.vehicle?.definitionId || instance.vehicle_definition_id}`);
  setText("#twin-source", twin.sourceLabel || twin.source?.toUpperCase() || "UNKNOWN SOURCE");
  setText("#twin-captured", `CAPTURED ${formatTime(twin.capturedAt)}`);
  setText("#twin-generation", String(twin.generation ?? instance.generation).padStart(2, "0"));
  setText("#signal-speed", formatNumber(signals.speedKph, 1));
  setText("#signal-gear", signals.gear ?? "—");
  setText("#signal-steering", formatNumber(signals.steeringDeg, 1));
  setText("#signal-soc", formatNumber(signals.batterySocPercent, 1));
  setText("#signal-bus", formatNumber(signals.canFdLoadPercent, 1));
  setText("#instance-state", String(twin.operationalState || instance.status).toUpperCase());
  updateSolvedStage(instance.id);

  const stage = $("#twin-stage");
  const running = ["running", "degraded", "display", "stopped"].includes(String(twin.operationalState).toLowerCase());
  stage.classList.toggle("is-offline", !running);
  const statusById = new Map((twin.nodes || []).map((node) => [node.id, node.status]));
  $$(".ecu-node", stage).forEach((node) => node.classList.toggle("is-offline", statusById.get(node.dataset.node) !== "online"));
  renderTopology(twin);
  renderSignalContracts(signals);
}

function renderTwinOffline(instance, message) {
  const offlineTwin = {
    operationalState: "offline",
    nodes: [],
    signals: {},
    instanceId: instance.id,
  };
  window.__cybercarTwin = offlineTwin;
  window.dispatchEvent(new CustomEvent("cybercar:twin", { detail: offlineTwin }));
  setText("#svg-vehicle-id", `${instance.label} / NO TWIN DATA`);
  setText("#twin-source", "OFFLINE / NO FALLBACK");
  setText("#twin-captured", message);
  ["#signal-speed", "#signal-gear", "#signal-steering", "#signal-soc", "#signal-bus"].forEach((selector) => setText(selector, "—"));
  $("#twin-stage").classList.add("is-offline");
  updateSolvedStage(instance.id);
  $$(".ecu-node", $("#twin-stage")).forEach((node) => node.classList.add("is-offline"));
}

function renderTopology(twin) {
  const container = $("#topology-list");
  container.replaceChildren();
  const links = twin.links || [];
  for (const node of twin.nodes || []) {
    const item = element("article", `topology-item ${node.status === "online" ? "" : "offline"}`);
    const text = element("div");
    text.append(element("strong", "", node.label), element("small", "", `${node.id} / ${node.zone || "vehicle"}`));
    const protocols = links.filter((link) => link.from === node.id || link.to === node.id).map((link) => link.protocol);
    item.append(element("i"), text, element("span", "", protocols[0] || "STATE NODE"));
    container.append(item);
  }
  if (!container.children.length) container.append(element("p", "", "暂无车辆拓扑节点。"));
}

function renderSignalContracts(signals) {
  const container = $("#signal-contracts");
  container.replaceChildren();
  const items = [
    ["车辆速度", `${formatNumber(signals.speedKph, 1)} km/h`],
    ["变速器挡位", signals.gear ?? "—"],
    ["转向角度", `${formatNumber(signals.steeringDeg, 1)}°`],
    ["动力电池电量", `${formatNumber(signals.batterySocPercent, 1)} %`],
    ["CAN FD 总线负载", `${formatNumber(signals.canFdLoadPercent, 1)} %`],
    ["点火状态", signals.ignition ?? "—"],
  ];
  for (const [label, value] of items) {
    const item = element("article", "signal-contract");
    item.append(element("span", "", label), element("strong", "", value));
    container.append(item);
  }
}

function switchView(name) {
  const viewName = competitionView(name);
  $$(".nav-item").forEach((item) => item.classList.toggle("is-active", item.dataset.view === viewName));
  $$(".view").forEach((view) => view.classList.toggle("is-active", view.id === `view-${viewName}`));
  history.replaceState(null, "", `#${viewName}`);
  if (viewName === "overview") requestAnimationFrame(syncSelectedVehicleVisuals);
}

function bindEvents() {
	  document.addEventListener("click", (event) => {
	    const navigation = event.target.closest("[data-view]");
	    if (navigation) switchView(navigation.dataset.view);
	    const jump = event.target.closest("[data-jump]");
	    if (jump) switchView(jump.dataset.jump);
	    if (event.target.closest("[data-stage-detail-close]")) closeVehicleRangeStageDetail();
	    if (event.target.closest("[data-password-close]")) closePasswordDialog();
	    const challenge = event.target.closest("[data-challenge-id]");
    if (challenge && challenge.dataset.challengeId !== state.challenges.selectedId) {
      activateChallenge(challenge.dataset.challengeId);
    }
    const arenaOpen = event.target.closest("[data-arena-open]");
    if (arenaOpen && !arenaOpen.disabled) {
      const instanceId = arenaOpen.dataset.arenaOpen;
      const challengeId = arenaOpen.dataset.arenaChallengeId;
      if (!instanceId || !challengeId) return;
      activateChallenge(challengeId, instanceId);
      switchView("challenges");
    }
  });

  $("#challenge-start")?.addEventListener("click", changeChallengeRun);
  $("#challenge-access-link")?.addEventListener("click", async (event) => {
    if (event.currentTarget.dataset.protocol === "http") return;
    event.preventDefault();
    const endpoint = event.currentTarget.dataset.endpoint;
    if (!endpoint) return;
    try {
      await navigator.clipboard.writeText(endpoint);
      showToast(`已复制 TCP/DoIP 地址：${endpoint}`);
    } catch {
      showToast(`请使用 TCP 客户端连接：${endpoint}`);
    }
  });
  $("#flag-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    submitFlag(event.currentTarget);
  });
  $("#instance-select")?.addEventListener("change", (event) => {
    selectAssignedVehicle(event.currentTarget.value);
  });
  $("#attack-desktop-start")?.addEventListener("click", async (event) => {
    const path = attackSessionPath();
    if (!path) return;
    event.currentTarget.disabled = true;
    try {
      const payload = await api(path, { method: "POST", body: "{}" });
      renderAttackDesktop(payload?.item || payload);
      renderVehicleRange(state.vehicleRange);
      showToast("攻击机正在启动，状态变为运行中后即可进入云桌面");
    } catch (error) {
      showToast(`启动攻击机失败：${error.message}`, true);
      await loadAttackDesktop({ quiet: true });
    }
  });
  $("#attack-desktop-stop")?.addEventListener("click", async (event) => {
    const path = attackSessionPath();
    if (!path || !window.confirm("确认停止当前个人攻击机吗？")) return;
    event.currentTarget.disabled = true;
    try {
      await api(path, { method: "DELETE" });
      renderAttackDesktop(null);
      renderVehicleRange(state.vehicleRange);
      showToast("攻击机已停止");
    } catch (error) {
      showToast(`停止攻击机失败：${error.message}`, true);
      await loadAttackDesktop({ quiet: true });
    }
  });
  const runVehicleRangeAction = async (action, confirmation) => {
    const path = vehicleRangePath(`/${action}`); if (!path) return;
    if (confirmation && !window.confirm(confirmation)) return;
    const button = $(`#vehicle-range-${action}`); if (button) button.disabled = true;
    try {
      const payload = await api(path, { method: "POST", body: "{}" });
      state.vehicleRange = payload; renderVehicleRange(payload);
      showToast(({ start: "整车靶场正在建立，请稍候刷新节点状态", pause: "整车靶场已冻结", resume: "整车靶场已恢复", reset: "整车靶场正在重置", stop: "整车靶场已停止" })[action] || "操作已完成");
      await loadVehicleRange({ quiet: true });
    } catch (error) { showToast(`${({ start: "启动", pause: "暂停", resume: "恢复", reset: "重置", stop: "停止" })[action] || "操作"}整车靶场失败：${error.message}`, true); await loadVehicleRange({ quiet: true }); }
  };
  $("#vehicle-range-start")?.addEventListener("click", () => runVehicleRangeAction("start"));
  $("#vehicle-range-pause")?.addEventListener("click", () => runVehicleRangeAction("pause", "确认暂停整车靶场？节点与私有地址会保留，但所有 Docker/KVM 节点将冻结。"));
  $("#vehicle-range-resume")?.addEventListener("click", () => runVehicleRangeAction("resume"));
  $("#vehicle-range-reset")?.addEventListener("click", () => runVehicleRangeAction("reset", "确认重置整车靶场？本队当前节点会被销毁并按模板重新建立。"));
  $("#vehicle-range-stop")?.addEventListener("click", () => runVehicleRangeAction("stop", state.vehicleRange?.settings?.allow_self_reset === false ? "确认停止整车靶场？本赛事禁止自行重建，停止后需联系管理员重新启动。" : "确认停止整车靶场？停止后可再次启动新的代次。"));
  $("#vehicle-range-vpn-download")?.addEventListener("click", async (event) => {
    const path = vehicleRangePath("/vpn/config");
    if (!path) return;
    event.currentTarget.disabled = true;
    try {
      const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}", cache: "no-store" });
      if (!response.ok) {
        let message = `请求失败（HTTP ${response.status}）`;
        try { message = (await response.json())?.error?.message || message; } catch { /* keep status message */ }
        throw new Error(message);
      }
      const blob = await response.blob();
      const disposition = response.headers.get("Content-Disposition") || "";
      const encodedName = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
      const plainName = disposition.match(/filename="?([^";]+)"?/i)?.[1];
      const filename = encodedName ? decodeURIComponent(encodedName) : plainName || "cybercar-vehicle-range.ovpn";
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showToast("个人 OpenVPN 配置已签发；旧配置已自动吊销");
      await loadVehicleRange({ quiet: true });
    } catch (error) {
      showToast(`下载 OpenVPN 配置失败：${error.message}`, true);
      await loadVehicleRange({ quiet: true });
    }
  });
  $("#vehicle-range-vpn-refresh")?.addEventListener("click", () => loadVehicleRange({ quiet: false }));
  $("#vehicle-range-vpn-revoke")?.addEventListener("click", async (event) => {
    const path = vehicleRangePath("/vpn");
    if (!path || !window.confirm("确认吊销当前 OpenVPN 配置吗？已导入客户端的旧配置将立即失效。")) return;
    event.currentTarget.disabled = true;
    try {
      await api(path, { method: "DELETE" });
      showToast("当前 OpenVPN 配置已吊销");
      await loadVehicleRange({ quiet: true });
    } catch (error) {
      showToast(`吊销 OpenVPN 配置失败：${error.message}`, true);
      await loadVehicleRange({ quiet: true });
    }
	  });
	  $("#vehicle-range-snapshot")?.addEventListener("click", async (event) => {
    const path = vehicleRangePath("/snapshots"); if (!path) return;
    const label = window.prompt("快照名称（可选）", "") || "";
    event.currentTarget.disabled = true;
    try { await api(path, { method: "POST", body: JSON.stringify({ label }) }); showToast("阶段快照已保存"); await loadVehicleRange({ quiet: true }); }
    catch (error) { showToast(`保存阶段快照失败：${error.message}`, true); await loadVehicleRange({ quiet: true }); }
  });
  $("#vehicle-range-restore")?.addEventListener("click", async (event) => {
    const snapshotID = $("#vehicle-range-snapshot-select")?.value;
    const path = vehicleRangePath(`/snapshots/${encodeURIComponent(snapshotID || "")}/restore`); if (!snapshotID || !path) return;
    if (!window.confirm("确认恢复所选快照？当前节点会被销毁，并以同一模板创建新的靶场代次。已验证阶段会恢复，进程内存与临时数据不会保留。")) return;
    event.currentTarget.disabled = true;
    try { await api(path, { method: "POST", body: "{}" }); showToast("快照正在恢复到新一代靶场"); await loadVehicleRange({ quiet: true }); }
    catch (error) { showToast(`恢复快照失败：${error.message}`, true); await loadVehicleRange({ quiet: true }); }
	  });
	  $("#change-password-button")?.addEventListener("click", openPasswordDialog);
	  $("#password-form")?.addEventListener("submit", (event) => {
	    event.preventDefault();
	    submitPasswordChange(event.currentTarget);
	  });
	  $("#logout-button")?.addEventListener("click", logout);
  window.addEventListener("hashchange", () => {
    const name = location.hash.slice(1);
    if (["overview", "twin", "challenges", "arena", "teams", "evidence", "vehicle-range"].includes(name) && (name !== "vehicle-range" || isVehicleRangeCompetition())) switchView(name);
  });
	  window.addEventListener("keydown", (event) => {
	    if (event.key === "Escape" && !$("#vehicle-range-stage-dialog")?.hidden) closeVehicleRangeStageDetail();
	    if (event.key === "Escape" && !$("#password-dialog")?.hidden) closePasswordDialog();
	  });
	}

function formatCountdown(milliseconds) {
  const totalSeconds = Math.max(0, Math.ceil(Number(milliseconds) / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return [hours, minutes, seconds].map((value) => String(value).padStart(2, "0")).join(":");
}

function tickCompetitionCountdown() {
  const clock = $("#system-clock");
  if (!clock) return;
  const competition = state.bootstrap?.competition;
  if (!competition) {
    clock.textContent = "—";
    clock.title = "等待赛事信息";
    return;
  }
  const now = Date.now();
  const status = String(competition.status || "").toLowerCase();
  const start = Date.parse(competition.starts_at || competition.startsAt || "");
  const end = Date.parse(competition.ends_at || competition.endsAt || "");
  let value = "未设置";
  let title = "赛事未设置计划时间";
  if (status === "finished") {
    value = "已结束";
    title = "赛事已结束";
  } else if (status === "ready" && Number.isFinite(start) && start > now) {
    value = formatCountdown(start - now);
    title = "距离比赛开始";
  } else if (Number.isFinite(end) && end > now && (status === "live" || status === "paused" || (status === "ready" && Number.isFinite(start) && start <= now))) {
    value = formatCountdown(end - now);
    title = status === "paused" ? "距离计划结束（赛事已暂停）" : "距离比赛结束";
  } else if (status === "live") {
    value = "进行中";
    title = "赛事进行中，未设置结束时间";
  } else if (status === "paused") {
    value = "已暂停";
    title = "赛事已暂停，未设置结束时间";
  } else if (status === "ready") {
    value = "等待开始";
    title = "等待管理员开始赛事";
  }
  clock.textContent = value;
  clock.title = title;
}

async function initialize() {
  bindEvents();
  tickCompetitionCountdown();
  state.intervals.push(setInterval(tickCompetitionCountdown, 1000));
  if (!(await requireSession())) return;
  document.body.classList.remove("auth-pending");
  const initialView = location.hash.slice(1);
  if (["twin", "challenges", "arena", "teams", "evidence", "vehicle-range"].includes(initialView) && (initialView !== "vehicle-range" || isVehicleRangeCompetition())) switchView(initialView);
  await loadBootstrap();
  if (participantIsDisqualified()) return;
  await loadAttackDesktop({ quiet: true });
  await loadVehicleRange({ quiet: true });
  // Bootstrap is the first point at which the mode is authoritative.  A
  // direct link to the range must therefore be resolved after it loads, not
  // before the competition metadata is available.
  if (isVehicleRangeCompetition()) {
    // The range is the participant's primary workspace. Explicit links to
    // allowed range views are preserved; retired CTF-only views resolve back
    // to the range through competitionView().
    const requested = location.hash.slice(1);
    switchView(requested || "vehicle-range");
  }
  await loadAttackTargets({ quiet: true });
  import(`/vehicle-3d.js?v=${ASSET_VERSION}`).catch((error) => {
    report3DModuleFailure(error instanceof Error ? error.message : String(error));
  });
  import(`/vehicle-range-3d.js?v=${ASSET_VERSION}`).catch((error) => {
    const empty = $("#vehicle-range-3d-empty");
    if (empty) {
      empty.hidden = false;
      empty.querySelector("strong").textContent = "3D 拓扑加载失败";
      empty.querySelector("small").textContent = error instanceof Error ? error.message : String(error);
    }
  });
  await loadChallenges({ quiet: true });
  state.intervals.push(setInterval(() => loadBootstrap({ quiet: true }), POLL_INTERVALS.bootstrap));
  state.intervals.push(setInterval(() => loadTeamRanking({ quiet: true }), POLL_INTERVALS.ranking));
  if (competitionAccessMode() === "attack") {
    state.intervals.push(setInterval(() => loadAttackDesktop({ quiet: true }), POLL_INTERVALS.attackDesktop));
  }
  if (isVehicleRangeCompetition()) {
    state.intervals.push(setInterval(() => loadVehicleRange({ quiet: true }), POLL_INTERVALS.vehicleRange));
  }
  if (competitionMode() === "attack") {
    state.intervals.push(setInterval(() => loadAttackTargets({ quiet: true }), POLL_INTERVALS.attackTargets));
  }
  state.intervals.push(setInterval(() => {
    if (currentChallengeRun()) catchUpChallengeEvents(state.challenges.lastSequence);
    else loadChallenges({ quiet: true });
  }, POLL_INTERVALS.challengeFallback));
  state.intervals.push(setInterval(() => {
    if (!twinSocketIsOpen()) loadTwin({ quiet: true });
  }, POLL_INTERVALS.twinFallback));
  state.intervals.push(setInterval(syncSelectedVehicleVisuals, POLL_INTERVALS.visualSync));
}

initialize();
window.addEventListener("cybercar:3d-ready", () => applySelectedChallengeVisuals());
window.addEventListener("pagehide", () => {
  stopParticipationRecheck();
  disconnectTwinStream();
  disconnectChallengeStream();
});
