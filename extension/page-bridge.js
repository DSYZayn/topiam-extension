(function() {
  'use strict';

  if (window.__topiamApiHooked) return;
  window.__topiamApiHooked = true;

  const currentScript = document.currentScript;
  const EVENT_NAME = (currentScript && currentScript.dataset && currentScript.dataset.topiamEvent) || '__TOPIAM_APP_LIST_RESPONSE__';
  const FORM_EVENT_NAME = (currentScript && currentScript.dataset && currentScript.dataset.topiamFormEvent) || '__TOPIAM_FORM_POST_CAPTURED__';
  const FORM_DECISION_EVENT = (currentScript && currentScript.dataset && currentScript.dataset.topiamDecisionEvent) || '__TOPIAM_FORM_POST_DECISION__';
  const BLOCK_CREDENTIAL_EVENT = (currentScript && currentScript.dataset && currentScript.dataset.topiamBlockCredentialEvent) || '__TOPIAM_BLOCK_CREDENTIAL_STORE__';
  const DEBUG_EVENT_NAME = (currentScript && currentScript.dataset && currentScript.dataset.topiamDebugEvent) || '__TOPIAM_DEBUG_EVENT__';
  const API_PATTERN = /\/api\/v1\/user\/app\/list/i;
  const FORM_DECISION_TIMEOUT_MS = 1200;
  const DEFAULT_BLOCK_DURATION_MS = 2 * 60 * 1000;
  const MAX_BLOCK_DURATION_MS = 10 * 60 * 1000;
  const pendingNativeSubmit = new Map();
  let credentialStoreBlockedUntil = 0;

  function debug(message, payload) {
    try {
      window.dispatchEvent(new CustomEvent(DEBUG_EVENT_NAME, {
        detail: { message, payload: payload || {} }
      }));
    } catch (e) {}
  }

  function emit(payload) {
    try {
      window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: payload }));
    } catch (e) {}
  }

  function normalizeBlockDuration(rawDuration) {
    const parsed = Number(rawDuration);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return DEFAULT_BLOCK_DURATION_MS;
    }
    return Math.max(1000, Math.min(MAX_BLOCK_DURATION_MS, Math.floor(parsed)));
  }

  function isCredentialStoreBlocked() {
    return Date.now() < credentialStoreBlockedUntil;
  }

  function installCredentialStoreBlocker() {
    try {
      const credentialsApi = navigator && navigator.credentials;
      if (!credentialsApi || typeof credentialsApi.store !== 'function') {
        debug('当前页面不支持 navigator.credentials.store，无需安装拦截');
        return;
      }

      const rawStore = credentialsApi.store.bind(credentialsApi);
      credentialsApi.store = function(...args) {
        if (isCredentialStoreBlocked()) {
          debug('已拦截 navigator.credentials.store 调用', {
            remainingMs: Math.max(0, credentialStoreBlockedUntil - Date.now())
          });
          return Promise.resolve(null);
        }
        return rawStore(...args);
      };

      debug('已安装 navigator.credentials.store 拦截器');
    } catch (error) {
      debug('安装 navigator.credentials.store 拦截器失败', {
        error: error?.message || String(error)
      });
    }

    window.addEventListener(BLOCK_CREDENTIAL_EVENT, (event) => {
      const detail = event?.detail || {};
      const durationMs = normalizeBlockDuration(detail.durationMs);
      credentialStoreBlockedUntil = Math.max(credentialStoreBlockedUntil, Date.now() + durationMs);
      debug('已更新凭据存储拦截窗口', {
        source: detail.source || 'unknown',
        durationMs,
        blockedUntil: credentialStoreBlockedUntil
      });
    });
  }

  function handleBody(url, body) {
    if (!API_PATTERN.test(url || '')) return;
    debug('命中 app/list 接口', { url });
    emit({ url, body });
  }

  function collectFormPayload(form) {
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

    const data = new FormData(form);
    const entries = Array.from(data.entries());
    let username = '';
    let password = '';
    const extra = {};

    for (const [key, value] of entries) {
      const str = typeof value === 'string' ? value : '';
      const lower = String(key).toLowerCase();

      if (!username && ['username', 'user', 'login', 'account', 'email', 'principal', 'name'].includes(lower)) {
        username = str;
      } else if (!password && ['password', 'pass', 'pwd', 'passwd', 'secret', 'credential'].includes(lower)) {
        password = str;
      } else {
        extra[key] = str;
      }
    }

    // TopIAM form_redirect.ftlh 兜底：前两个 hidden 字段依次为 username/password
    if (!username || !password) {
      const hiddenInputs = Array.from(form.querySelectorAll('input[type="hidden"]'));
      const looksLikeTopiamRedirect = form.name === 'auto_submit_form' || hiddenInputs.length >= 2;

      if (looksLikeTopiamRedirect && hiddenInputs.length >= 2) {
        username = username || hiddenInputs[0].value || '';
        password = password || hiddenInputs[1].value || '';

        if (Object.keys(extra).length === 0 && hiddenInputs.length > 2) {
          hiddenInputs.slice(2).forEach((input) => {
            if (input.name) {
              extra[input.name] = input.value || '';
            }
          });
        }
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

  function scheduleSubmitDecision(rawSubmit, form, payload) {
    const token = `native_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    debug('捕获 native form.submit', {
      token,
      targetUrl: payload.targetUrl,
      submitMethod: payload.submitMethod,
      username: payload.username
    });
    const timer = setTimeout(() => {
      pendingNativeSubmit.delete(token);
      debug('等待扩展决策超时，放行原生提交', { token });
      try {
        rawSubmit.call(form);
      } catch (e) {}
    }, FORM_DECISION_TIMEOUT_MS);

    pendingNativeSubmit.set(token, { form, rawSubmit, timer });
    window.dispatchEvent(new CustomEvent(FORM_EVENT_NAME, {
      detail: {
        token,
        payload
      }
    }));
  }

  const rawFetch = window.fetch;
  if (typeof rawFetch === 'function') {
    window.fetch = function(...args) {
      return rawFetch.apply(this, args).then((res) => {
        try {
          const reqUrl = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
          const absUrl = new URL(reqUrl, location.origin).href;
          if (API_PATTERN.test(absUrl)) {
            res.clone().json().then((json) => handleBody(absUrl, json)).catch(() => {});
          }
        } catch (e) {}
        return res;
      });
    };
  }

  installCredentialStoreBlocker();

  const rawOpen = XMLHttpRequest.prototype.open;
  const rawSend = XMLHttpRequest.prototype.send;
  const rawSubmit = HTMLFormElement.prototype.submit;

  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this.__topiamUrl = url;
    return rawOpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function(...args) {
    this.addEventListener('load', function() {
      try {
        const absUrl = new URL(this.__topiamUrl || '', location.origin).href;
        if (!API_PATTERN.test(absUrl)) return;
        const text = this.responseType === '' || this.responseType === 'text' ? this.responseText : '';
        if (!text) return;
        const data = JSON.parse(text);
        handleBody(absUrl, data);
      } catch (e) {}
    });
    return rawSend.apply(this, args);
  };

  HTMLFormElement.prototype.submit = function(...args) {
    try {
      const payload = collectFormPayload(this);
      if (payload) {
        scheduleSubmitDecision(rawSubmit, this, payload);
        return;
      }
    } catch (e) {}

    return rawSubmit.apply(this, args);
  };

  window.addEventListener(FORM_DECISION_EVENT, (event) => {
    const detail = event?.detail || {};
    const token = detail.token;
    if (!token || !pendingNativeSubmit.has(token)) return;

    const record = pendingNativeSubmit.get(token);
    pendingNativeSubmit.delete(token);
    clearTimeout(record.timer);

    if (detail.allowNative) {
      debug('收到 allowNative 决策，放行原生提交', { token });
      try {
        record.rawSubmit.call(record.form);
      } catch (e) {}
      return;
    }

    debug('收到 cancelNative 决策，已取消原生提交', { token });
  });
})();
