"use strict";

const state = { user: null, items: [], next: "/" };
const $ = (selector, root = document) => root.querySelector(selector);

function unwrap(payload) { return payload?.data && typeof payload.data === "object" ? payload.data : payload; }
function errorText(payload, status) { return payload?.error?.message || payload?.message || `请求失败（${status}）`; }
async function request(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options, headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) } });
  const text = await response.text(); let payload = null; if (text) { try { payload = JSON.parse(text); } catch { payload = null; } }
  if (!response.ok) { const error = new Error(errorText(payload, response.status)); error.status = response.status; throw error; }
  return payload || {};
}
function formatDate(value) { if (!value) return "时间未设置"; const date = new Date(value); return Number.isNaN(date.valueOf()) ? String(value) : new Intl.DateTimeFormat("zh-CN", { month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit", hour12:false }).format(date); }
function statusLabel(status) { return ({ draft:"草稿", ready:"报名中", live:"进行中", paused:"已暂停", finished:"已结束" })[status] || status || "未知"; }
function modeLabel(competition = {}) {
  const mode = String(competition.mode || "team").toLowerCase();
  if (mode === "vehicle_range") return "车联网安全靶场赛";
  if (mode === "individual") return "CTF · 个人赛";
  if (mode === "attack") return "攻击机赛";
  return "CTF · 团队赛";
}
function accessModeLabel(competition = {}) {
  const accessMode = String(competition.access_mode || competition.accessMode || "").toLowerCase();
  return ({ direct: "直连", attack: "攻击机", openvpn: "OpenVPN 私网" })[accessMode] || "";
}
function normalizeItem(raw) {
  const source = raw?.competition || raw?.item || raw || {};
  return {
    competition: source,
    eligible: raw?.eligible !== false,
    team: raw?.team || null,
    disqualification: raw?.disqualification || null,
  };
}
function ruleLabel(code) {
  return ({
    foreign_dynamic_flag: "提交了其他队伍的动态 Flag",
    attachment_without_download: "未下载附件即正确提交",
  })[code] || "高危作弊事件";
}
function setMessage(text, error = false) { const message = $("#competition-message"); message.textContent = text; message.classList.toggle("is-error", error); }
function destination() { return state.next || "/"; }
function safeNext(raw) {
  try {
    const url = new URL(raw || "/", location.origin);
    if (url.origin !== location.origin) return "/";
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return "/";
  }
}
function enterCompetition(competition) {
  if (!competition?.id) return;
  sessionStorage.setItem("cybercar.selectedCompetition", competition.id);
  const next = destination(); const url = new URL(next, location.origin); url.searchParams.set("competitionId", competition.id); location.replace(`${url.pathname}${url.search}${url.hash}`);
}
function render() {
  const list = $("#competition-list"); list.replaceChildren(); $("#competition-count").textContent = `${state.items.length} 场赛事`;
  if (!state.items.length) { setMessage("当前没有可选择的赛事，请联系赛事管理员。", true); return; }
  setMessage("请选择一场赛事进入竞赛页面。");
  state.items.forEach(({ competition, eligible, team, disqualification }) => {
    const status = String(competition.status || "").toLowerCase();
    const disqualified = Boolean(disqualification);
    const row = document.createElement("article");
    row.className = `event-row ${status === "live" ? "is-live" : ""}${eligible ? "" : " is-disabled"}${disqualified ? " is-disqualified" : ""}`;
    row.append(document.createElement("i"));
    const copy = document.createElement("div");
    copy.className = "event-copy";
    const title = document.createElement("strong");
    title.textContent = competition.title || competition.id;
    const detail = document.createElement("small");
    const accessLabel = accessModeLabel(competition);
    detail.textContent = `${modeLabel(competition)}${accessLabel ? ` · ${accessLabel}` : ""} · ${competition.id} · ${competition.starts_at || competition.startsAt ? `${formatDate(competition.starts_at || competition.startsAt)} 开始` : "开始时间未设置"}${team?.name ? ` · ${team.name}` : ""}`;
    copy.append(title, detail);
    if (disqualified) {
      const notice = document.createElement("div");
      notice.className = "event-ban-detail";
      const noticeTitle = document.createElement("strong");
      noticeTitle.textContent = ruleLabel(disqualification.rule_code || disqualification.ruleCode);
      const noticeMeta = document.createElement("small");
      noticeMeta.textContent = `处置时间 ${formatDate(disqualification.created_at || disqualification.createdAt)} · ${disqualification.reason || "本赛事参赛权限已撤销"}`;
      notice.append(noticeTitle, noticeMeta);
      copy.append(notice);
    }
    const meta = document.createElement("div");
    meta.className = "event-meta";
    const stateLabel = document.createElement("span");
    stateLabel.className = `event-status is-${disqualified ? "disqualified" : status}`;
    stateLabel.textContent = disqualified ? "已被禁赛" : eligible ? statusLabel(status) : "未分配参赛范围";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "enter-event";
    button.textContent = disqualified ? "已禁赛" : !eligible ? "不可参加" : status === "finished" ? "查看赛事" : "进入赛事";
    button.disabled = !eligible;
    button.addEventListener("click", () => enterCompetition(competition));
    meta.append(stateLabel, button);
    row.append(copy, meta);
    list.append(row);
  });
}
async function initialize() {
  const params = new URLSearchParams(location.search); state.next = safeNext(params.get("next"));
  try {
    const me = unwrap(await request("/api/v1/auth/me")); state.user = me?.user || me;
    $("#current-user").textContent = state.user?.displayName || state.user?.display_name || state.user?.username || "已登录";
    if (["admin", "administrator", "super_admin"].includes(String(state.user?.role || "").toLowerCase())) { location.replace("/admin.html"); return; }
    const payload = unwrap(await request("/api/v1/competitions")); state.items = (Array.isArray(payload?.items) ? payload.items : []).map(normalizeItem); render();
  } catch (error) {
    if (error.status === 401 || error.status === 403) { const next = encodeURIComponent(`${location.pathname}${location.search}`); location.replace(`/login.html?next=${next}`); return; }
    setMessage(`赛事列表载入失败：${error.message}`, true); $("#competition-count").textContent = "连接失败";
  }
}
$("#logout-button").addEventListener("click", async () => { const button = $("#logout-button"); button.disabled = true; try { await request("/api/v1/auth/logout", { method:"POST", body:"{}" }); } finally { location.replace("/login.html"); } });
initialize();
