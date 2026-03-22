// 在TopIAM页面运行：自动发现应用并监控点击
(function() {
  'use strict';

  const seenAppKeys = new Set();
  const appLaunchCache = new Map();
  const API_EVENT = '__TOPIAM_APP_LIST_RESPONSE__';
  const FORM_POST_EVENT = '__TOPIAM_FORM_POST_CAPTURED__';
  const FORM_POST_DECISION_EVENT = '__TOPIAM_FORM_POST_DECISION__';
  const DEBUG_EVENT = '__TOPIAM_DEBUG_EVENT__';
  const DEBUG_PANEL_STORAGE_KEY = 'debugPanelEnabled';

  const debugState = {
    enabled: false,
    panel: null,
    list: null,
    maxLogs: 80
  };
  const launchState = {
    inFlight: false,
    startedAt: 0,
    timer: null
  };
  let isDetectedTopIamPlatform = false;
  let topiamDetectInFlight = false;
  let topiamDetectAttempts = 0;
  let userDebugPanelEnabled = true;
  let topiamLogoutReportedAt = 0;
  let topiamLogoutClickPendingAt = 0;
  let topiamAuthProbeInFlight = false;
  let topiamAuthLastReport = { authenticated: null, at: 0 };

  monitorLog('content script 已加载', {
    href: location.href,
    readyState: document.readyState
  });

  function monitorLog(message, payload) {
    console.log('[TopIAM Monitor]', message, payload || '');
    pushDebugLog(message, payload);
  }

  function normalizeUserName(value) {
    const text = String(value || '').trim();
    if (!text) return '';
    if (text.length < 2 || text.length > 80) return '';
    if (/^(welcome|logout|登录|退出|菜单|设置)$/i.test(text)) return '';
    return text;
  }

  function deepFindUserName(obj, depth = 0) {
    if (!obj || typeof obj !== 'object' || depth > 4) return '';
    const keys = ['username', 'userName', 'realName', 'displayName', 'nickname', 'name', 'account', 'loginName'];

    for (const key of keys) {
      if (typeof obj[key] === 'string') {
        const hit = normalizeUserName(obj[key]);
        if (hit) return hit;
      }
    }

    if (Array.isArray(obj)) {
      for (const item of obj) {
        const hit = deepFindUserName(item, depth + 1);
        if (hit) return hit;
      }
      return '';
    }

    for (const value of Object.values(obj)) {
      if (value && typeof value === 'object') {
        const hit = deepFindUserName(value, depth + 1);
        if (hit) return hit;
      }
    }
    return '';
  }

  function detectTopIamUserNameFromPage() {
    const selectors = [
      '[data-user-name]',
      '[data-username]',
      '[class*="user-name" i]',
      '[class*="username" i]',
      '[class*="account" i]',
      '.ant-pro-global-header [class*="name" i]',
      '.ant-pro-global-header-right [class*="name" i]',
      '.topiam-header [class*="name" i]'
    ];

    for (const selector of selectors) {
      const node = document.querySelector(selector);
      if (!node) continue;
      const fromAttr = normalizeUserName(node.getAttribute('data-user-name') || node.getAttribute('data-username'));
      if (fromAttr) return fromAttr;
      const fromText = normalizeUserName(node.textContent || '');
      if (fromText) return fromText;
    }

    const objects = [
      window.__INITIAL_STATE__,
      window.__APP_DATA__,
      window.__NUXT__,
      window.__STORE__,
      window.gon
    ];

    for (const obj of objects) {
      const hit = deepFindUserName(obj, 0);
      if (hit) return hit;
    }

    return '';
  }

  function isCurrentUserApiSuccess(payload) {
    if (!payload || typeof payload !== 'object') return false;
    return payload.success === true || String(payload.status || '').toLowerCase() === 'success';
  }

  function hasTopIamCurrentUserShape(payload) {
    if (!payload || typeof payload !== 'object') return false;
    if (!Object.prototype.hasOwnProperty.call(payload, 'result')) return false;
    const result = payload.result;
    return !!result && typeof result === 'object';
  }

  function getCurrentUserEndpoint() {
    return `${location.protocol}//${location.host}/api/v1/session/current_user?_topiam_probe=1`;
  }

  async function fetchTopIamCurrentUser() {
    let timeoutId = null;
    try {
      const endpoint = getCurrentUserEndpoint();
      const controller = new AbortController();
      timeoutId = setTimeout(() => controller.abort(), 3500);

      const resp = await fetch(endpoint, {
        method: 'GET',
        credentials: 'include',
        cache: 'no-store',
        redirect: 'follow',
        signal: controller.signal
      });

      const redirectedToLogin = (() => {
        if (!resp.redirected) return false;
        try {
          const final = new URL(String(resp.url || ''), location.href);
          const finalPath = String(final.pathname || '').toLowerCase();
          if (/\/authorize\/form\//.test(finalPath) || /\/initiator\//.test(finalPath)) return false;
          return /^\/login(?:\/|$)/.test(finalPath)
            || /^\/signin(?:\/|$)/.test(finalPath)
            || /^\/oauth(?:\/|$)/.test(finalPath)
            || /^\/cas(?:\/|$)/.test(finalPath)
            || /^\/auth\/login(?:\/|$)/.test(finalPath);
        } catch {
          return false;
        }
      })();
      if (resp.status === 401 || resp.status === 403 || redirectedToLogin) {
        return { platformDetected: false, authenticated: false, username: '', fullName: '', source: `http_${resp.status}` };
      }

      const payload = await resp.clone().json().catch(() => null);
      if (isUnauthorizedPayload(payload)) {
        return { platformDetected: true, authenticated: false, username: '', fullName: '', source: 'api_unauthorized_payload' };
      }
      if (!isCurrentUserApiSuccess(payload)) {
        return { platformDetected: false, authenticated: false, username: '', fullName: '', source: 'api_unsuccessful' };
      }

      if (!hasTopIamCurrentUserShape(payload)) {
        return { platformDetected: false, authenticated: false, username: '', fullName: '', source: 'api_shape_mismatch' };
      }

      const result = payload?.result || {};
      const username = normalizeUserName(result.username);
      const fullName = normalizeUserName(result.fullName || result.displayName || result.name);
      if (!username) {
        return { platformDetected: true, authenticated: false, username: '', fullName: '', source: 'api_no_username' };
      }

      return { platformDetected: true, authenticated: true, username, fullName, source: 'api_current_user' };
    } catch (error) {
      return { platformDetected: false, authenticated: false, username: '', fullName: '', source: `api_error_${error?.message || 'unknown'}` };
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
    }
  }

  async function syncTopIamIdentity(reason = 'unknown') {
    const apiUser = await fetchTopIamCurrentUser();
    const username = apiUser.authenticated
      ? apiUser.username
      : detectTopIamUserNameFromPage();
    const fullName = apiUser.authenticated ? apiUser.fullName : '';
    if (!username) return;

    chrome.runtime.sendMessage({
      action: 'syncTopIamIdentity',
      username,
      fullName,
      source: `topiam_page_${reason}_${apiUser.source || 'dom_fallback'}`
    }, (response) => {
      if (chrome.runtime.lastError) return;
      if (response?.success) {
        monitorLog('已同步TopIAM平台用户', { username, fullName });
      }
    });
  }

  function reportTopIamLogout(reason = 'unknown') {
    const now = Date.now();
    if (now - topiamLogoutReportedAt < 5000) return;
    topiamLogoutReportedAt = now;

    chrome.runtime.sendMessage({
      action: 'topiamUserLoggedOut',
      source: `topiam_page_${reason}`
    }, (response) => {
      if (chrome.runtime.lastError) {
        monitorLog('上报TopIAM退出失败', {
          reason,
          error: chrome.runtime.lastError.message
        });
        return;
      }
      monitorLog('已上报TopIAM退出登录', { reason, ok: Boolean(response?.success) });
    });
  }

  function isLikelyTopIamLogoutControl(node) {
    if (!(node instanceof HTMLElement)) return false;

    const text = String(node.textContent || '').replace(/\s+/g, ' ').trim().toLowerCase();
    const id = String(node.id || '').toLowerCase();
    const cls = String(node.className || '').toLowerCase();
    const hrefRaw = String(node.getAttribute?.('href') || '').trim();
    const href = hrefRaw.toLowerCase();
    const onclick = String(node.getAttribute?.('onclick') || '').toLowerCase();
    const dataAction = String(node.getAttribute?.('data-action') || '').toLowerCase();

    const exactTextHit = /^(退出登录|退出|注销|logout|log out|sign out)$/.test(text);
    const attrHit = /logout|signout|sign-out/.test(id)
      || /logout|signout|sign-out/.test(cls)
      || /logout|signout|sign-out/.test(onclick)
      || /logout|signout|sign-out/.test(dataAction);

    let hrefHit = false;
    if (hrefRaw) {
      try {
        const resolved = new URL(hrefRaw, location.href);
        const sameOrigin = resolved.origin === location.origin;
        const path = String(resolved.pathname || '').toLowerCase();
        hrefHit = sameOrigin && /\/logout(?:\/|$)|\/signout(?:\/|$)|\/sign-out(?:\/|$)/.test(path);
      } catch {
        hrefHit = /\/logout(?:\/|$)|\/signout(?:\/|$)|\/sign-out(?:\/|$)/.test(href);
      }
    }

    return exactTextHit || hrefHit || (attrHit && /退出|注销|logout|sign\s*out/.test(text));
  }

  function confirmTopIamLogoutAfterClick() {
    const pendingAt = Date.now();
    topiamLogoutClickPendingAt = pendingAt;

    setTimeout(() => {
      if (topiamLogoutClickPendingAt !== pendingAt) return;

      const username = detectTopIamUserNameFromPage();
      const onLoginPage = isTopIamLoginPage();
      if (!username && onLoginPage) {
        reportTopIamLogout('logout_click_confirmed');
        return;
      }

      monitorLog('忽略退出点击信号（未满足登录页二次确认）', {
        path: location.pathname,
        onLoginPage,
        hasUsername: Boolean(username)
      });
    }, 1200);
  }

  function isTopIamLoginPage() {
    const url = location.href.toLowerCase();
    const path = String(location.pathname || '').toLowerCase();
    const hostHit = isDetectedTopIamPlatform;
    if (!hostHit) return false;

    const isAuthorizeFlow = /\/api\/v1\/authorize\/form\/[^/]+\/initiator/.test(path)
      || /\/api\/v1\/user\/app\/initiator\//.test(path)
      || /\/authorize\/form\//.test(path);
    if (isAuthorizeFlow) return false;

    if (/^\/login(?:\/|$)/.test(path)
      || /^\/signin(?:\/|$)/.test(path)
      || /^\/oauth(?:\/|$)/.test(path)
      || /^\/cas(?:\/|$)/.test(path)
      || /^\/auth\/login(?:\/|$)/.test(path)) {
      return true;
    }

    const hasPassword = Boolean(document.querySelector('input[type="password"]'));
    const hasSubmit = Boolean(document.querySelector('button[type="submit"],input[type="submit"]'));
    const hasLoginHint = /login|signin|sign-in|验证码|短信登录|账户登录|password/i.test(url)
      || Boolean(document.querySelector('[name*="user" i],[name*="login" i],[id*="login" i]'));
    return hasPassword && hasSubmit && hasLoginHint;
  }

  function isPortalAppPage() {
    return /^\/portal\/app(?:\/|$)/.test(String(location.pathname || '').toLowerCase());
  }

  function isTopIamAppListPage() {
    const path = String(location.pathname || '').toLowerCase();
    if (/^\/portal\/app(?:\/|$)/.test(path)) return true;
    if (/\/my-apps(?:\/|$)|\/application(?:\/|$)|\/portal\/application(?:\/|$)/.test(path)) return true;

    const hasAppListDom = Boolean(document.querySelector(
      '.topiam-app-list-item-card, .topiam-app-list-item-content-wrapper, [class*="app-list-item" i], [data-app-id], [data-id]'
    ));
    return hasAppListDom;
  }

  function removeDebugPanel() {
    if (debugState.panel) {
      try {
        debugState.panel.remove();
      } catch (e) {}
    }
    debugState.panel = null;
    debugState.list = null;
  }

  function applyDebugPanelPreference(source = 'unknown') {
    if (!isDetectedTopIamPlatform) return;

    const shouldEnable = Boolean(userDebugPanelEnabled && isTopIamAppListPage());
    debugState.enabled = shouldEnable;

    if (shouldEnable) {
      ensureDebugPanel();
      monitorLog('调试面板已启用', { source, path: location.pathname });
      return;
    }

    removeDebugPanel();
    console.log('[TopIAM Monitor] 调试面板已禁用', { source, path: location.pathname });
  }

  function loadDebugPanelPreference() {
    chrome.storage.local.get([DEBUG_PANEL_STORAGE_KEY], (result) => {
      const value = result?.[DEBUG_PANEL_STORAGE_KEY];
      userDebugPanelEnabled = value !== false;
      if (isDetectedTopIamPlatform) {
        applyDebugPanelPreference('storage_load');
      }
    });
  }

  function watchDebugPanelPreferenceChange() {
    if (window.__topiamDebugPreferenceWatchBound) return;
    window.__topiamDebugPreferenceWatchBound = true;

    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== 'local') return;
      if (!Object.prototype.hasOwnProperty.call(changes, DEBUG_PANEL_STORAGE_KEY)) return;
      userDebugPanelEnabled = changes[DEBUG_PANEL_STORAGE_KEY]?.newValue !== false;
      applyDebugPanelPreference('storage_change');
    });
  }

  function onTopIamPortalPathReady(source = 'unknown') {
    if (!isDetectedTopIamPlatform) return;

    if (!isTopIamAppListPage()) {
      applyDebugPanelPreference(`non_app_list_${source}`);
      return;
    }

    applyDebugPanelPreference(source);
    monitorTopIamLogout();
    monitorAppClicks();
    monitorAppDiscovery();
  }

  function watchPortalPathChanges() {
    if (window.__topiamPortalPathWatcherBound) return;
    window.__topiamPortalPathWatcherBound = true;

    const emit = (source) => {
      if (isDetectedTopIamPlatform) {
        onTopIamPortalPathReady(source);
      }
    };

    const rawPushState = history.pushState;
    history.pushState = function(...args) {
      const ret = rawPushState.apply(this, args);
      setTimeout(() => emit('pushState'), 0);
      return ret;
    };

    const rawReplaceState = history.replaceState;
    history.replaceState = function(...args) {
      const ret = rawReplaceState.apply(this, args);
      setTimeout(() => emit('replaceState'), 0);
      return ret;
    };

    window.addEventListener('popstate', () => emit('popstate'));
    window.addEventListener('hashchange', () => emit('hashchange'));
    window.addEventListener('pageshow', () => emit('pageshow'));
  }

  function monitorTopIamLogout() {
    if (isTopIamAppListPage() && !window.__topiamLogoutClickBound) {
      window.__topiamLogoutClickBound = true;
      document.addEventListener('click', (event) => {
        const path = typeof event.composedPath === 'function' ? event.composedPath() : [];
        const nodes = path.filter((n) => n instanceof HTMLElement);

        const hit = nodes.find((node) => {
          return isLikelyTopIamLogoutControl(node);
        });

        if (hit) {
          monitorLog('检测到TopIAM退出点击', {
            text: String(hit.textContent || '').trim().slice(0, 40)
          });
          confirmTopIamLogoutAfterClick();
        }
      }, true);
      monitorLog('已启用退出点击监听（应用列表页）', { path: location.pathname });
    } else {
      monitorLog('当前非应用列表页，跳过退出点击监听', { path: location.pathname });
    }

    if (window.__topiamLogoutPollBound) return;
    window.__topiamLogoutPollBound = true;

    const checkByPage = () => {
      const username = detectTopIamUserNameFromPage();
      if (!username && isTopIamLoginPage()) {
        reportTopIamLogout('login_page_detected');
      }
    };

    setInterval(checkByPage, 3000);
    checkByPage();
  }

  function shouldReportAuthState(authenticated) {
    const now = Date.now();
    if (topiamAuthLastReport.authenticated === null) return true;
    if (topiamAuthLastReport.authenticated !== authenticated) return true;
    return now - topiamAuthLastReport.at > 60000;
  }

  function reportTopIamAuthState(authenticated, username, source) {
    if (!shouldReportAuthState(authenticated)) return;

    topiamAuthLastReport = {
      authenticated,
      at: Date.now()
    };

    chrome.runtime.sendMessage({
      action: 'reportTopIamAuthState',
      authenticated,
      username: username || '',
      source: `topiam_probe_${source}`
    }, (response) => {
      if (chrome.runtime.lastError) {
        monitorLog('上报TopIAM认证状态失败', {
          authenticated,
          source,
          error: chrome.runtime.lastError.message
        });
        return;
      }
      monitorLog('已上报TopIAM认证状态', {
        authenticated,
        source,
        ok: Boolean(response?.success)
      });
    });
  }

  function isUnauthorizedPayload(payload) {
    if (!payload || typeof payload !== 'object') return false;
    const code = String(payload.code || payload.status || payload.errorCode || '').toLowerCase();
    const message = String(payload.message || payload.msg || payload.error || '').toLowerCase();
    return /401|403|unauth|login|expired|token/.test(code) || /未登录|登录过期|请登录|unauth|expired|token/.test(message);
  }

  async function probeTopIamSession(reason = 'interval') {
    if (topiamAuthProbeInFlight) return;
    if (document.visibilityState === 'hidden' && reason === 'interval') return;

    topiamAuthProbeInFlight = true;
    try {
      const apiUser = await fetchTopIamCurrentUser();
      const username = apiUser.authenticated ? apiUser.username : detectTopIamUserNameFromPage();
      const fullName = apiUser.authenticated ? apiUser.fullName : '';
      if (isTopIamLoginPage()) {
        reportTopIamAuthState(false, '', `${reason}_login_page`);
        return;
      }

      if (!apiUser.authenticated) {
        reportTopIamAuthState(false, '', `${reason}_${apiUser.source}`);
        return;
      }

      const currentUser = username || detectTopIamUserNameFromPage();
      if (currentUser) {
        chrome.runtime.sendMessage({
          action: 'syncTopIamIdentity',
          username: currentUser,
          fullName,
          source: `topiam_probe_${reason}`
        }, () => {
          if (chrome.runtime.lastError) {
            monitorLog('探针同步TopIAM用户失败', {
              reason,
              error: chrome.runtime.lastError.message
            });
          }
        });
      }
      reportTopIamAuthState(true, currentUser, `${reason}_ok`);
    } catch (error) {
      monitorLog('TopIAM会话探针异常', { reason, error: error?.message || 'unknown' });
    } finally {
      topiamAuthProbeInFlight = false;
    }
  }

  function startTopIamSessionProbe() {
    probeTopIamSession('bootstrap');
    setInterval(() => probeTopIamSession('interval'), 15000);

    window.addEventListener('focus', () => probeTopIamSession('focus'));
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        probeTopIamSession('visible');
      }
    });
  }

  function pushDebugLog(message, payload) {
    if (!debugState.enabled) return;
    if (!debugState.panel) {
      ensureDebugPanel();
    }
    if (!debugState.list) return;

    const line = document.createElement('div');
    line.style.cssText = 'padding:4px 6px;border-bottom:1px solid #f0f0f0;font-size:11px;line-height:1.4;word-break:break-all;';
    const time = new Date().toLocaleTimeString();
    let text = `[${time}] ${message}`;
    if (payload) {
      try {
        text += ` | ${JSON.stringify(payload)}`;
      } catch (e) {
        text += ' | [payload]';
      }
    }
    line.textContent = text;
    debugState.list.prepend(line);

    while (debugState.list.children.length > debugState.maxLogs) {
      debugState.list.removeChild(debugState.list.lastChild);
    }
  }

  function ensureDebugPanel() {
    if (!debugState.enabled) return;
    if (debugState.panel || !document.documentElement) return;

    const wrap = document.createElement('div');
    wrap.id = 'topiam-debug-panel';
    wrap.style.cssText = [
      'position:fixed',
      'right:12px',
      'bottom:12px',
      'z-index:2147483647',
      'width:420px',
      'max-height:320px',
      'background:#fff',
      'border:1px solid #d9d9d9',
      'border-radius:8px',
      'box-shadow:0 8px 24px rgba(0,0,0,0.2)',
      'font-family:system-ui'
    ].join(';');

    const head = document.createElement('div');
    head.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:#1890ff;color:#fff;border-radius:8px 8px 0 0;font-size:12px;font-weight:600;';
    head.textContent = 'TopIAM 调试面板';

    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex;gap:8px;';

    const clearBtn = document.createElement('button');
    clearBtn.textContent = '清空';
    clearBtn.style.cssText = 'border:none;background:rgba(255,255,255,0.2);color:#fff;border-radius:4px;padding:2px 8px;cursor:pointer;font-size:11px;';
    clearBtn.onclick = () => {
      if (debugState.list) debugState.list.innerHTML = '';
    };

    const hideBtn = document.createElement('button');
    hideBtn.textContent = '收起';
    hideBtn.style.cssText = 'border:none;background:rgba(255,255,255,0.2);color:#fff;border-radius:4px;padding:2px 8px;cursor:pointer;font-size:11px;';

    const body = document.createElement('div');
    body.style.cssText = 'max-height:280px;overflow:auto;background:#fff;';

    hideBtn.onclick = () => {
      const hidden = body.style.display === 'none';
      body.style.display = hidden ? 'block' : 'none';
      hideBtn.textContent = hidden ? '收起' : '展开';
    };

    actions.appendChild(clearBtn);
    actions.appendChild(hideBtn);
    head.appendChild(actions);

    wrap.appendChild(head);
    wrap.appendChild(body);

    debugState.panel = wrap;
    debugState.list = body;

    document.documentElement.appendChild(wrap);
  }

  async function detectTopIAM() {
    if (isDetectedTopIamPlatform || topiamDetectInFlight) return;
    topiamDetectInFlight = true;
    topiamDetectAttempts += 1;
    try {
      const apiProbe = await fetchTopIamCurrentUser();
      if (!apiProbe.platformDetected) {
        monitorLog('TopIAM平台探测未命中，等待重试', {
          attempt: topiamDetectAttempts,
          source: apiProbe.source,
          href: location.href
        });
        return;
      }
      isDetectedTopIamPlatform = true;

      const domain = window.location.hostname;

      monitorLog('检测到TopIAM平台（host探测）', { domain, href: location.href, source: apiProbe.source });

      chrome.runtime.sendMessage({
        action: 'registerTopiamDomain',
        domain
      }, () => {
        if (chrome.runtime.lastError) {
          monitorLog('自动注册TopIAM域名失败', {
            domain,
            error: chrome.runtime.lastError.message
          });
          return;
        }
        monitorLog('已自动注册TopIAM域名', { domain });
      });

      if (!isPortalAppPage()) {
        monitorLog('当前非门户应用页，仅保持平台识别（点击拦截仍等待/portal/app）', {
          domain,
          path: location.pathname
        });
      }

      syncTopIamIdentity('detect');
      setTimeout(() => syncTopIamIdentity('delayed_1s'), 1000);
      setTimeout(() => syncTopIamIdentity('delayed_3s'), 3000);
      monitorTopIamLogout();
      startTopIamSessionProbe();

      installApiBridge();
      bindApiEvent();
      fetchTopIamAppList('detect').catch(() => {});
      setTimeout(() => fetchTopIamAppList('detect_delayed_1s').catch(() => {}), 1000);
      setTimeout(() => fetchTopIamAppList('detect_delayed_3s').catch(() => {}), 3000);
      bindFormPostEvent();
      onTopIamPortalPathReady('detect');
      setTimeout(() => onTopIamPortalPathReady('detect_delayed_1s'), 1000);
      setTimeout(() => onTopIamPortalPathReady('detect_delayed_3s'), 3000);
      monitorFormSubmission();
    } finally {
      topiamDetectInFlight = false;
    }
  }

  function scheduleTopIamDetectionRetries() {
    const delays = [0, 600, 1500, 3000, 6000, 12000];
    delays.forEach((delay) => {
      setTimeout(() => {
        if (!isDetectedTopIamPlatform) {
          detectTopIAM().catch(() => {});
        }
      }, delay);
    });

    window.addEventListener('focus', () => {
      if (!isDetectedTopIamPlatform) {
        detectTopIAM().catch(() => {});
      }
    });

    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && !isDetectedTopIamPlatform) {
        detectTopIAM().catch(() => {});
      }
    });
  }

  function installApiBridge() {
    if (window.__topiamApiBridgeInstalled) return;
    window.__topiamApiBridgeInstalled = true;

    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('page-bridge.js');
    script.dataset.topiamEvent = API_EVENT;
    script.dataset.topiamFormEvent = FORM_POST_EVENT;
    script.dataset.topiamDecisionEvent = FORM_POST_DECISION_EVENT;
    script.dataset.topiamDebugEvent = DEBUG_EVENT;
    const container = document.documentElement || document.head || document.body;
    if (container) {
      container.appendChild(script);
      monitorLog('已注入 page-bridge', { src: script.src });
      script.remove();
      return;
    }

    let retries = 0;
    const timer = setInterval(() => {
      const c = document.documentElement || document.head || document.body;
      retries += 1;
      if (c) {
        c.appendChild(script);
        monitorLog('重试后注入 page-bridge 成功');
        script.remove();
        clearInterval(timer);
      }
      if (retries > 20) {
        clearInterval(timer);
      }
    }, 20);
  }

  function bindApiEvent() {
    if (window.__topiamApiEventBound) return;
    window.__topiamApiEventBound = true;

    window.addEventListener(API_EVENT, (event) => {
      const detail = event?.detail || {};
      const apps = normalizeAppList(detail.body);
      monitorLog('收到 app/list 响应', { url: detail.url, count: apps.length });
      processAppList(apps, 'bridge_event');
    });
  }

  async function fetchTopIamAppList(reason = 'unknown') {
    if (!isDetectedTopIamPlatform) return;
    const pageSize = 20;
    const seen = new Set();
    const mergedApps = [];

    const appendUniqueApps = (apps) => {
      if (!Array.isArray(apps)) return;
      apps.forEach((item) => {
        if (!item || typeof item !== 'object') return;
        const key = String(item.id || item.appId || item.code || item.clientId || item.name || item.appName || '').trim();
        if (!key || seen.has(key)) return;
        seen.add(key);
        mergedApps.push(item);
      });
    };

    const fetchPage = async (current) => {
      const endpoint = `${location.protocol}//${location.host}/api/v1/user/app/list?current=${encodeURIComponent(String(current))}&pageSize=${encodeURIComponent(String(pageSize))}&_topiam_probe=1`;
      const resp = await fetch(endpoint, {
        method: 'GET',
        credentials: 'include',
        cache: 'no-store',
        redirect: 'follow'
      });
      const payload = await resp.clone().json().catch(() => null);
      const apps = normalizeAppList(payload);
      const pagination = extractAppListPagination(payload);
      return { status: resp.status, apps, pagination };
    };

    try {
      const first = await fetchPage(0);
      appendUniqueApps(first.apps);

      const totalPages = Math.max(1, Number(first.pagination.totalPages || 1));
      const pageBase = Number(first.pagination.current) === 0 ? 0 : 1;
      const lastPage = pageBase + totalPages - 1;

      for (let page = pageBase + 1; page <= lastPage; page += 1) {
        const next = await fetchPage(page);
        appendUniqueApps(next.apps);
      }

      monitorLog('主动拉取 app/list 完成', {
        reason,
        status: first.status,
        pageSize,
        pageBase,
        totalPages,
        count: mergedApps.length
      });
      processAppList(mergedApps, `active_fetch_${reason}`);
    } catch (error) {
      monitorLog('主动拉取 app/list 失败', {
        reason,
        error: error?.message || String(error)
      });
    }
  }

  function processAppList(apps, source = 'unknown') {
    if (!Array.isArray(apps) || apps.length === 0) return;

    cacheAppLaunchItems(apps);

    const formApps = [];
    apps.forEach((item) => {
      const app = mapApiApp(item);
      if (app) {
        formApps.push(app);
      }
    });

    if (formApps.length > 0) {
      chrome.runtime.sendMessage({
        action: 'registerDiscoveredApps',
        apps: formApps
      }, (response) => {
        if (chrome.runtime.lastError || !response?.ok) {
          formApps.forEach((app) => registerDiscoveredApp(app));
        }
      });
    }

    monitorLog('处理应用列表完成', {
      source,
      total: apps.length,
      registeredFormApps: formApps.length
    });
  }

  function bindFormPostEvent() {
    if (window.__topiamFormEventBound) return;
    window.__topiamFormEventBound = true;

    window.addEventListener(FORM_POST_EVENT, (event) => {
      const detail = event?.detail || {};
      const token = detail.token;
      const payload = detail.payload;
      if (!token || !payload) return;

      monitorLog('捕获程序化 form.submit', {
        token,
        targetUrl: payload.targetUrl,
        submitMethod: payload.submitMethod,
        username: payload.username
      });

      chrome.runtime.sendMessage({
        action: 'interceptFormPost',
        payload
      }, (response) => {
        if (chrome.runtime.lastError || !response?.ok) {
          monitorLog('后台未接管，放行原生提交', {
            token,
            error: chrome.runtime.lastError?.message || response?.error || 'unknown'
          });
          dispatchFormDecision(token, { allowNative: true });
          return;
        }

        monitorLog('后台接管成功，取消原生提交', { token });
        dispatchFormDecision(token, { cancelNative: true });
      });
    });
  }

  function bindBridgeDebugEvent() {
    if (window.__topiamBridgeDebugBound) return;
    window.__topiamBridgeDebugBound = true;

    window.addEventListener(DEBUG_EVENT, (event) => {
      const detail = event?.detail || {};
      monitorLog(`Bridge: ${detail.message || 'debug'}`, detail.payload || {});
    });
  }

  function bindBackgroundDebugEvent() {
    if (window.__topiamBgDebugBound) return;
    window.__topiamBgDebugBound = true;

    chrome.runtime.onMessage.addListener((request) => {
      if (request?.action !== 'topiamDebug') return;
      monitorLog(`BG: ${request.message || 'debug'}`, request.payload || {});
    });
  }

  function cacheAppLaunchItems(apps) {
    apps.forEach((item) => {
      if (!item || typeof item !== 'object') return;
      const appId = String(item.appId || item.id || '').trim();
      const appName = normalizeAppName(String(item.appName || item.name || ''));
      const initLoginUrl = item.initLoginUrl || item.init_login_url || item.idpInitUrl || '';
      const protocol = getAppProtocol(item);

      if (protocol !== 'form') return;
      if (!initLoginUrl) return;

      const model = { appId, appName, initLoginUrl, protocol };
      if (appId) appLaunchCache.set(`id:${appId}`, model);
      if (appName) appLaunchCache.set(`name:${appName}`, model);
    });

    monitorLog('已缓存应用启动信息', { size: appLaunchCache.size });
  }

  function dispatchFormDecision(token, decision) {
    window.dispatchEvent(new CustomEvent(FORM_POST_DECISION_EVENT, {
      detail: {
        token,
        ...decision
      }
    }));
  }

  function normalizeAppList(body) {
    if (!body || typeof body !== 'object') return [];

    const candidates = [
      body.data,
      body.data?.records,
      body.data?.list,
      body.records,
      body.list,
      body.result,
      body.result?.records,
      body.result?.list
    ];

    for (const item of candidates) {
      if (Array.isArray(item)) return item;
    }
    return [];
  }

  function extractAppListPagination(body) {
    if (!body || typeof body !== 'object') {
      return { totalPages: 1, current: 0 };
    }

    const pagination = body.pagination || body.data?.pagination || body.result?.pagination || {};
    const totalPagesRaw = pagination.totalPages ?? pagination.total_pages ?? 1;
    const currentRaw = pagination.current ?? pagination.page ?? pagination.currentPage ?? 0;
    const totalPages = Number(totalPagesRaw);
    const current = Number(currentRaw);

    return {
      totalPages: Number.isFinite(totalPages) && totalPages > 0 ? totalPages : 1,
      current: Number.isFinite(current) ? current : 1
    };
  }

  function mapApiApp(item) {
    if (!item || typeof item !== 'object') return null;

    const protocol = getAppProtocol(item);
    if (protocol !== 'form') return null;

    const initLoginUrl = String(item.initLoginUrl || item.init_login_url || item.idpInitUrl || '').trim();

    const targetUrl = '';
    const targetOrigin = '';

    const appId = String(item.appId || item.id || item.clientId || '').trim();
    const appCode = String(item.code || item.appCode || '').trim();
    const name = String(item.appName || item.name || item.displayName || appId || '未知应用').trim();

    if (!initLoginUrl && !appId && !appCode) return null;

    return {
      appId,
      appCode,
      name,
      sourceDomain: location.hostname,
      initLoginUrl,
      protocol,
      targetUrl,
      targetOrigin,
      realTargetUrl: '',
      isFormFillLike: true
    };
  }

  function getAppProtocol(item) {
    if (!item || typeof item !== 'object') return '';
    return String(item.protocol || item.protocal || '').trim().toLowerCase();
  }

  function monitorAppDiscovery() {
    if (window.__topiamAppDiscoveryBound) return;
    window.__topiamAppDiscoveryBound = true;

    scanForAppCards(document);

    const observer = new MutationObserver(() => {
      scanForAppCards(document);
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['href', 'onclick', 'data-app-id', 'data-id', 'data-type', 'data-url', 'data-target']
    });
  }

  function scanForAppCards(root) {
    const selectors = [
      'a[href]',
      'button[data-app-id]',
      '[data-id]',
      '[data-app-id]',
      '[onclick*="appId"]',
      '[onclick*="form-fill"]',
      '[onclick*="auto-login"]'
    ].join(',');

    const nodes = root.querySelectorAll(selectors);
    nodes.forEach((node) => {
      const app = buildAppInfo(node);
      if (app && app.isFormFillLike) {
        registerDiscoveredApp(app);
      }
    });
  }

  function monitorAppClicks() {
    if (window.__topiamAppClicksBound) return;
    window.__topiamAppClicksBound = true;

    if (!isTopIamAppListPage()) {
      monitorLog('当前非应用列表页，跳过应用点击监听', { path: location.pathname });
      return;
    }

    document.addEventListener('click', (e) => {
      const candidate = resolveClickCandidate(e);
      monitorLog('捕获到点击事件', {
        hasCandidate: Boolean(candidate),
        targetTag: e.target?.tagName || 'unknown'
      });

      if (!candidate) return;

      const launch = resolveLaunchFromClickedElement(candidate);
      if (launch?.initLoginUrl && launch?.protocol === 'form') {
        e.preventDefault();
        e.stopImmediatePropagation();
        monitorLog('已硬拦截应用点击，改为后台预取并接管', launch);
        prefetchInitAndLaunch(launch);
        showInterceptNotice(candidate);
        return;
      }

      const fallbackInitLoginUrl = resolveInitLoginUrlFromElement(candidate);
      if (fallbackInitLoginUrl) {
        e.preventDefault();
        e.stopImmediatePropagation();
        monitorLog('命中兜底 initLoginUrl，改为后台预取并接管', {
          initLoginUrl: fallbackInitLoginUrl
        });
        prefetchInitAndLaunch({
          initLoginUrl: fallbackInitLoginUrl,
          protocol: 'form',
          appId: candidate.getAttribute('data-app-id') || candidate.getAttribute('data-id') || '',
          appName: (candidate.textContent || '').trim()
        });
        showInterceptNotice(candidate);
        return;
      }

      const app = buildAppInfo(candidate);
      if (!app || !app.isFormFillLike) return;

      registerDiscoveredApp(app);
      showInterceptNotice(candidate);
    }, true);
  }

  function resolveClickCandidate(event) {
    const path = typeof event.composedPath === 'function' ? event.composedPath() : [];
    for (const node of path) {
      if (node instanceof HTMLElement && looksLikeAppEntry(node)) return node;
    }

    let cursor = event.target;
    for (let i = 0; i < 20 && cursor; i++) {
      if (cursor instanceof HTMLElement && looksLikeAppEntry(cursor)) return cursor;
      cursor = cursor.parentElement;
    }
    return null;
  }

  function looksLikeAppEntry(node) {
    const signal = [
      node.getAttribute('data-app-id'),
      node.getAttribute('data-id'),
      node.getAttribute('data-url'),
      node.getAttribute('data-target'),
      node.getAttribute('onclick'),
      node.getAttribute('href'),
      node.className
    ].filter(Boolean).join(' ');

    if (node.tagName === 'A' || node.tagName === 'BUTTON') return true;
    if (node.getAttribute('role') === 'button') return true;
    if (node.hasAttribute('data-app-id') || node.hasAttribute('data-id')) return true;
    if (/topiam-app|app-list-item|form-fill|auto-login|initsso/i.test(signal)) return true;

    return false;
  }

  function resolveLaunchFromClickedElement(element) {
    const card = element.closest('.topiam-app-list-item-card, .topiam-app-list-item-content-wrapper, [class*="topiam-app-list-item-card"]');
    if (!card) return null;

    const appId = card.getAttribute('data-app-id') || card.getAttribute('data-id') || '';
    const titleNode = card.querySelector('.topiam-app-list-item-content-title') || card.querySelector('[class*="content-title"]');
    const appName = normalizeAppName((titleNode?.textContent || '').trim());

    if (appId && appLaunchCache.has(`id:${appId}`)) return appLaunchCache.get(`id:${appId}`);
    if (appName && appLaunchCache.has(`name:${appName}`)) return appLaunchCache.get(`name:${appName}`);

    const fallback = findLaunchByClosestName(card.textContent || '');
    if (fallback) return fallback;

    return null;
  }

  function normalizeAppName(name) {
    return String(name || '').replace(/\s+/g, '').trim();
  }

  function findLaunchByClosestName(rawText) {
    const normalizedText = normalizeAppName(rawText);
    if (!normalizedText) return null;

    for (const [key, value] of appLaunchCache.entries()) {
      if (!key.startsWith('name:')) continue;
      const appName = key.slice(5);
      if (appName && normalizedText.includes(appName)) {
        return value;
      }
    }
    return null;
  }

  function prefetchInitAndLaunch(launch) {
    if (launchState.inFlight && Date.now() - launchState.startedAt < 8000) {
      monitorLog('已有预取任务进行中，忽略重复点击');
      return;
    }

    launchState.inFlight = true;
    launchState.startedAt = Date.now();
    if (launchState.timer) {
      clearTimeout(launchState.timer);
    }
    launchState.timer = setTimeout(() => {
      launchState.inFlight = false;
      launchState.timer = null;
      monitorLog('预取超时看门狗触发，自动释放点击锁');
    }, 15000);

    chrome.runtime.sendMessage({
      action: 'prefetchInitLogin',
      initLoginUrl: launch.initLoginUrl,
      openInNewTab: true,
      app: {
        appId: launch.appId || '',
        appName: launch.appName || launch.name || ''
      }
    }, (response) => {
      launchState.inFlight = false;
      if (launchState.timer) {
        clearTimeout(launchState.timer);
        launchState.timer = null;
      }

      if (chrome.runtime.lastError || !response?.ok) {
        const code = String(response?.code || '').toUpperCase();
        if (code === 'NO_DEFAULT_ACCOUNT') {
          showTransientNotice('至少需要配置一个默认账户', 'warning');
          monitorLog('后台预取失败：缺少默认账户，已阻断跳转', {
            error: response?.error || 'NO_DEFAULT_ACCOUNT'
          });
          return;
        }

        monitorLog('后台预取失败，本次不自动回退开页', {
          error: chrome.runtime.lastError?.message || response?.error || 'unknown'
        });
        showTransientNotice('预访问未获取到账密，未跳转应用', 'warning');
        return;
      }

      monitorLog('后台预取成功，已派发真实应用任务');
    });
  }

  function showTransientNotice(message, level = 'info') {
    const notice = document.createElement('div');
    const colorMap = {
      info: { bg: '#e6f7ff', border: '#91d5ff', text: '#096dd9' },
      warning: { bg: '#fff7e6', border: '#ffd591', text: '#d46b08' },
      error: { bg: '#fff1f0', border: '#ffccc7', text: '#cf1322' }
    };
    const style = colorMap[level] || colorMap.info;

    notice.style.cssText = `
      position: fixed;
      right: 20px;
      top: 20px;
      z-index: 2147483647;
      background: ${style.bg};
      border: 1px solid ${style.border};
      color: ${style.text};
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.12);
      padding: 10px 14px;
      font-size: 12px;
      font-family: system-ui;
      max-width: 360px;
      line-height: 1.5;
    `;
    notice.textContent = message;

    (document.body || document.documentElement).appendChild(notice);
    setTimeout(() => {
      try {
        notice.remove();
      } catch (e) {}
    }, 3500);
  }

  window.addEventListener('pageshow', (event) => {
    const wasInBFCache = event.persisted;
    launchState.inFlight = false;
    if (launchState.timer) {
      clearTimeout(launchState.timer);
      launchState.timer = null;
    }
    monitorLog('页面恢复显示', { 
      isFromBFCache: wasInBFCache,
      timestamp: Date.now() 
    });
  });

  document.addEventListener('visibilitychange', () => {
    const isVisible = document.visibilityState === 'visible';
    const timeSinceStart = Date.now() - launchState.startedAt;
    
    if (isVisible && launchState.inFlight && timeSinceStart > 6000) {
      launchState.inFlight = false;
      if (launchState.timer) {
        clearTimeout(launchState.timer);
        launchState.timer = null;
      }
      monitorLog('页面重新可见且接管状态过期，已释放点击锁', {
        timeSinceStart,
        timestamp: Date.now()
      });
    } else if (isVisible) {
      monitorLog('页面重新可见', { 
        inFlight: launchState.inFlight,
        timeSinceStart 
      });
    }
  });

  function resolveInitLoginUrlFromElement(element) {
    const card = element.closest('.topiam-app-list-item-card, .topiam-app-list-item-content-wrapper, [class*="topiam-app-list-item-card"], [class*="app-list-item"]') || element;

    const rawParts = [
      element.getAttribute('href') || '',
      element.getAttribute('data-url') || '',
      element.getAttribute('data-target') || '',
      element.getAttribute('onclick') || '',
      card.getAttribute('onclick') || '',
      card.getAttribute('data-url') || ''
    ].filter(Boolean).join(' ');

    const absUrlMatch = rawParts.match(/https?:\/\/[^'"\s)]+/i);
    if (absUrlMatch) {
      const value = absUrlMatch[0];
      if (/\/authorize\/form\/|\/api\/v1\/authorize\/form\/|\/initiator(?:[/?#]|$)/i.test(value)) {
        return value;
      }
    }

    const relUrlMatch = rawParts.match(/\/(?:api\/v1\/authorize\/form\/[^'"\s)]*|api\/v1\/user\/app\/initiator\/[^'"\s)]*|authorize\/form\/[^'"\s)]*|initiator\/[^'"\s)]*)/i);
    if (relUrlMatch) {
      try {
        return new URL(relUrlMatch[0], location.origin).href;
      } catch (e) {
        return '';
      }
    }

    return '';
  }

  function launchInitSso(initLoginUrl) {
    try {
      const parsed = new URL(initLoginUrl, location.origin);
      monitorLog('按原始 initLoginUrl 新标签发起 SSO 中转', { href: parsed.href });
      const popup = window.open(parsed.href, '_blank', 'noopener,noreferrer');
      if (!popup) {
        window.location.assign(parsed.href);
      }
    } catch (error) {
      monitorLog('主动发起失败，回退原生跳转', { initLoginUrl, error: String(error) });
      const popup = window.open(initLoginUrl, '_blank', 'noopener,noreferrer');
      if (!popup) {
        window.location.href = initLoginUrl;
      }
    }
  }

  function monitorFormSubmission() {
    if (window.__topiamSubmitHooked) return;
    window.__topiamSubmitHooked = true;

    document.addEventListener('submit', (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (form.dataset.topiamIntercepting === '1') return;

      const payload = extractFromSubmittedForm(form);
      if (!payload) return;

      form.dataset.topiamIntercepting = '1';

      event.preventDefault();
      event.stopImmediatePropagation();

      chrome.runtime.sendMessage({
        action: 'interceptFormPost',
        payload
      }, (response) => {
        if (chrome.runtime.lastError || !response?.ok) {
          delete form.dataset.topiamIntercepting;
          form.submit();
          return;
        }

        delete form.dataset.topiamIntercepting;
      });
    }, true);
  }

  function extractFromSubmittedForm(form) {
    const action = form.getAttribute('action') || form.action || '';
    if (!action) return null;

    let targetUrl = '';
    try {
      targetUrl = new URL(action, location.href).href;
    } catch (e) {
      return null;
    }

    const targetOrigin = (() => {
      try {
        return new URL(targetUrl).origin;
      } catch (e) {
        return '';
      }
    })();

    if (!targetOrigin || targetOrigin === location.origin) return null;

    const formData = new FormData(form);
    let username = '';
    let password = '';
    const extra = {};

    for (const [key, value] of formData.entries()) {
      const stringValue = typeof value === 'string' ? value : '';
      const lower = String(key).toLowerCase();

      if (!username && ['username', 'user', 'login', 'account', 'email', 'principal', 'name'].includes(lower)) {
        username = stringValue;
      } else if (!password && ['password', 'pass', 'pwd', 'passwd', 'secret', 'credential'].includes(lower)) {
        password = stringValue;
      } else {
        extra[key] = stringValue;
      }
    }

    if (!username || !password) return null;

    return {
      sourceUrl: location.href,
      targetUrl,
      targetOrigin,
      submitMethod: (form.method || 'get').toLowerCase(),
      username,
      password,
      extra
    };
  }

  function buildAppInfo(element) {
    const rawHref = element.href || element.getAttribute('href') || '';
    const rawOnclick = element.getAttribute('onclick') || '';
    const rawDataUrl = element.getAttribute('data-url') || element.getAttribute('data-target') || '';
    const raw = [rawHref, rawOnclick, rawDataUrl].filter(Boolean).join(' ');

    const parsed = parseFromRaw(raw);
    const appId = element.getAttribute('data-app-id') || element.getAttribute('data-id') || parsed.appId || '';
    const name = (element.innerText || element.getAttribute('title') || appId || '').trim();

    const targetUrl = parsed.targetUrl || '';
    let targetOrigin = '';
    if (targetUrl) {
      try {
        targetOrigin = new URL(targetUrl).origin;
      } catch (e) {
        targetOrigin = '';
      }
    }

    const isFormFillLike = /form-fill|auto-login|\/app\/[^\/]+\/login/i.test(raw) ||
      element.getAttribute('data-type') === 'form' ||
      Boolean(appId && targetUrl);

    if (!appId && !targetUrl && !isFormFillLike) return null;

    return {
      appId,
      name: name || '未知应用',
      sourceDomain: location.hostname,
      targetUrl,
      targetOrigin,
      isFormFillLike
    };
  }

  function parseFromRaw(raw) {
    const result = { appId: '', targetUrl: '' };
    if (!raw) return result;

    const absMatch = raw.match(/https?:\/\/[^'"\s)]+/i);
    const relMatch = raw.match(/\/(?:portal|api|app)\/[^'"\s)]+/i);
    const entryRaw = absMatch ? absMatch[0] : (relMatch ? new URL(relMatch[0], location.origin).href : '');

    if (!entryRaw) return result;

    try {
      const entry = new URL(entryRaw, location.origin);
      result.appId = entry.searchParams.get('appId') || entry.pathname.match(/\/app\/([^\/]+)/)?.[1] || '';
      result.targetUrl = entry.searchParams.get('target') ||
        entry.searchParams.get('redirect') ||
        entry.searchParams.get('url') ||
        '';
    } catch (e) {
      return result;
    }

    return result;
  }

  function registerDiscoveredApp(app) {
    const key = [
      app.appId || '',
      app.appCode || '',
      app.initLoginUrl || '',
      app.targetOrigin || '',
      app.targetUrl || ''
    ].join('|');
    if (seenAppKeys.has(key)) return;
    seenAppKeys.add(key);

    chrome.runtime.sendMessage({
      action: 'registerDiscoveredApp',
      app
    }, () => {
      if (chrome.runtime.lastError) {
        seenAppKeys.delete(key);
      }
    });
  }

  function showInterceptNotice(element) {
    const rect = element.getBoundingClientRect();
    const notice = document.createElement('div');
    notice.style.cssText = `
      position: fixed;
      left: ${rect.left + rect.width / 2}px;
      top: ${rect.bottom + 10}px;
      transform: translateX(-50%);
      background: #1890ff;
      color: white;
      padding: 8px 16px;
      border-radius: 4px;
      font-size: 12px;
      z-index: 2147483647;
      box-shadow: 0 2px 8px rgba(0,0,0,0.2);
      pointer-events: none;
    `;
    notice.textContent = '插件将接管此应用登录';
    document.body.appendChild(notice);

    setTimeout(() => notice.remove(), 1500);
  }

  function bootstrapEarly() {
    bindBridgeDebugEvent();
    bindBackgroundDebugEvent();
    watchPortalPathChanges();
    watchDebugPanelPreferenceChange();
    loadDebugPanelPreference();
    scheduleTopIamDetectionRetries();
    detectTopIAM().then(() => {
      if (debugState.enabled) {
        ensureDebugPanel();
      }
    }).catch(() => {});
  }

  bootstrapEarly();

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      if (debugState.enabled) ensureDebugPanel();
    });
  } else if (debugState.enabled) {
    ensureDebugPanel();
  }
})();