"use strict";

const API = {
	check: "/api/v1/auth/check",
	me: "/api/v1/auth/me",
  login: "/api/v1/auth/login",
};

const form = document.querySelector("#login-form");
const sessionCheck = document.querySelector("#session-check");
const message = document.querySelector("#form-message");
const submitButton = document.querySelector("#submit-button");
const connectionStatus = document.querySelector("#connection-status");
const authStatus = document.querySelector(".auth-status");
const usernameInput = document.querySelector("#username");
const passwordInput = document.querySelector("#password");

const accessHost = document.querySelector("#access-host");
if (accessHost) accessHost.textContent = window.location.host || "本地节点";

function unwrap(payload) {
  return payload?.data && typeof payload.data === "object" ? payload.data : payload;
}

function userFrom(payload) {
  const body = unwrap(payload);
  return body?.user || body?.account || (body?.id || body?.username ? body : null);
}

function errorMessage(payload, status) {
  return payload?.error?.message || payload?.message || (status === 401 ? "账号或密码不正确。" : `请求失败（${status}）`);
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) },
  });
  const text = await response.text();
  let payload = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = null; }
  }
  if (!response.ok) {
    const error = new Error(errorMessage(payload, response.status));
    error.status = response.status;
    throw error;
  }
  return payload || {};
}

function destinationFor(user) {
  const role = String(user?.role || "").toLowerCase();
  if (["admin", "administrator", "super_admin"].includes(role)) return "/admin.html";
  const next = new URLSearchParams(location.search).get("next");
  const selection = new URL("/competitions.html", location.origin);
  if (next) selection.searchParams.set("next", next);
  return `${selection.pathname}${selection.search}`;
}

function enterFor(user) {
  window.location.replace(destinationFor(user));
}

function showForm() {
  sessionCheck.hidden = true;
  form.hidden = false;
  authStatus?.classList.add("is-ready");
  if (connectionStatus) connectionStatus.textContent = "身份服务可用";
  requestAnimationFrame(() => usernameInput.focus());
}

function showError(text) {
  message.textContent = text;
  message.hidden = false;
}

function clearError() {
  message.hidden = true;
  message.textContent = "";
  usernameInput.removeAttribute("aria-invalid");
  passwordInput.removeAttribute("aria-invalid");
}

function setBusy(busy) {
  submitButton.disabled = busy;
  submitButton.classList.toggle("is-busy", busy);
  usernameInput.disabled = busy;
  passwordInput.disabled = busy;
  document.querySelector(".button-label").textContent = busy ? "正在验证身份" : "验证并进入平台";
}

async function checkSession() {
  try {
    const payload = await request(API.check);
    if (!unwrap(payload)?.authenticated) {
      showForm();
      return;
    }
    const user = userFrom(payload);
    if (user) {
      if (connectionStatus) connectionStatus.textContent = "已识别登录身份";
      enterFor(user);
      return;
    }
    showForm();
  } catch (error) {
    if (error.status === 401 || error.status === 403) {
      showForm();
      return;
    }
    showForm();
    if (connectionStatus) connectionStatus.textContent = "身份服务暂不可用";
    showError(`无法检查登录状态：${error.message}`);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();

  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password) {
    if (!username) usernameInput.setAttribute("aria-invalid", "true");
    if (!password) passwordInput.setAttribute("aria-invalid", "true");
    showError("请输入账号和密码后继续。");
    return;
  }

  setBusy(true);
  try {
    await request(API.login, { method: "POST", body: JSON.stringify({ username, password }) });
    const me = await request(API.me);
    const user = userFrom(me);
    if (!user) throw new Error("登录成功，但未获取到账号信息。");
    if (connectionStatus) connectionStatus.textContent = "身份验证通过";
    enterFor(user);
  } catch (error) {
    passwordInput.value = "";
    passwordInput.setAttribute("aria-invalid", "true");
    showError(error.message || "登录失败，请稍后重试。");
    passwordInput.focus();
  } finally {
    setBusy(false);
  }
});

document.querySelector("#password-toggle").addEventListener("click", (event) => {
  const showing = passwordInput.type === "text";
  passwordInput.type = showing ? "password" : "text";
  event.currentTarget.textContent = showing ? "显示" : "隐藏";
  event.currentTarget.setAttribute("aria-pressed", String(!showing));
  passwordInput.focus();
});

[usernameInput, passwordInput].forEach((input) => input.addEventListener("input", clearError));
checkSession();
