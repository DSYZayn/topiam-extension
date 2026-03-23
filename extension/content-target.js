(function() {
  'use strict';

  // 【诊断】立即输出，验证脚本是否加载
  console.log('[TopIAM Target] ✅ content-target.js 已加载，开始初始化...');

  const IS_TOP_WINDOW = window.top === window;

  const TARGET_LOG_PREFIX = '[TopIAM Target]';
  const TOPIAM_WATERMARK_CLASS = 'topiam-extension-watermark-layer';
  const TOPIAM_WATERMARK_LEGACY_CLASS = 'topiam-pro-layout-watermark';
  const TOPIAM_WATERMARK_SIZE = 332;
  const TOPIAM_RESET_RETRY_MARKER = '__topiam_reset_retry';
  const NON_STANDARD_LOGIN_ERROR = 'NON_STANDARD_LOGIN_SURFACE';
  const DISCOVERED_APPS_STORAGE_KEY = 'discoveredApps';
  const TOPIAM_BLOCK_CREDENTIAL_EVENT = '__TOPIAM_BLOCK_CREDENTIAL_STORE__';
  const SSO_STATE_SYNC_INTERVAL_MS = 30000;

  let isSessionExpiring = false;
  let ssoStateSyncTimer = null;
  let watermarkUsername = '';
  let watermarkRepairTimer = null;
  let bootHasResetRetryMarker = false;
  let forceRefreshPathRules = [];
  let watermarkWhitelistUrlMap = new Map();
  let watermarkWhitelistHostMap = new Map();

  function targetLog(message, payload) {
    if (typeof payload === 'undefined') {
      console.log(`${TARGET_LOG_PREFIX} ${message}`);
      return;
    }
    console.log(`${TARGET_LOG_PREFIX} ${message}`, payload);
  }

  function targetError(message, payload) {
    if (typeof payload === 'undefined') {
      console.error(`${TARGET_LOG_PREFIX} ${message}`);
      return;
    }
    console.error(`${TARGET_LOG_PREFIX} ${message}`, payload);
  }

  function isLikelyLoginContext() {
    const directPassword = safeQuerySelector('input[type="password"], input[name*="pass" i], input[id*="pass" i]');
    if (directPassword) return true;

    const userLike = safeQuerySelector('input[name*="user" i], input[name*="account" i], input[name*="login" i], input[autocomplete="username"], input[type="email"]');
    const loginButton = safeQuerySelector('button[type="submit"], input[type="submit"], button, a, [role="button"]');
    if (userLike && loginButton) return true;

    const loginForm = safeQuerySelector('form[action*="login" i], form[action*="signin" i], form[action*="auth" i], form[action*="sso" i]');
    if (loginForm) return true;

    const pathLike = `${String(window.location.pathname || '').toLowerCase()} ${String(window.location.search || '').toLowerCase()} ${String(window.location.hash || '').toLowerCase()}`;
    if (/login|signin|sign-in|auth|oauth|cas|passport|\/sso(?:\/|$)/.test(pathLike)) return true;

    return false;
  }

  function isLikelyLoginDocument(doc) {
    if (!doc) return false;
    try {
      const hasPassword = Boolean(doc.querySelector('input[type="password"], input[name*="pass" i], input[id*="pass" i]'));
      if (hasPassword) return true;

      const hasUserLike = Boolean(doc.querySelector('input[name*="user" i], input[name*="account" i], input[name*="login" i], input[autocomplete="username"], input[type="email"]'));
      const hasButtonLike = Boolean(doc.querySelector('button[type="submit"], input[type="submit"], button, [role="button"]'));
      if (hasUserLike && hasButtonLike) return true;

      const hasLoginForm = Boolean(doc.querySelector('form[action*="login" i], form[action*="signin" i], form[action*="auth" i], form[action*="sso" i]'));
      if (hasLoginForm) return true;

      const pathLike = `${String(doc.location?.pathname || '').toLowerCase()} ${String(doc.location?.search || '').toLowerCase()} ${String(doc.location?.hash || '').toLowerCase()}`;
      return /login|signin|sign-in|auth|oauth|cas|passport|\/sso(?:\/|$)/.test(pathLike);
    } catch (error) {
      return false;
    }
  }

  function isLikelyLoginFrameElement(frame) {
    if (!frame) return false;

    const srcHint = String(frame.getAttribute('src') || '').toLowerCase();
    const idHint = String(frame.id || '').toLowerCase();
    const nameHint = String(frame.name || '').toLowerCase();
    const classHint = String(frame.className || '').toLowerCase();
    const attrHint = `${srcHint} ${idHint} ${nameHint} ${classHint}`;
    if (/login|signin|sign-in|auth|sso|oauth|cas|passport|account/.test(attrHint)) {
      return true;
    }

    try {
      return isLikelyLoginDocument(frame.contentDocument);
    } catch (error) {
      return false;
    }
  }

  function collectLikelyLoginFrames(frames) {
    const allFrames = Array.isArray(frames) ? frames : [];
    const byHint = allFrames.filter((frame) => {
      try {
        return isLikelyLoginFrameElement(frame);
      } catch (error) {
        return false;
      }
    });

    return byHint;
  }

  function safeQuerySelector(selector, root = document) {
    try {
      return root.querySelector(selector);
    } catch (error) {
      return null;
    }
  }

  function cleanTaskMarkerFromUrl() {
    try {
      const url = new URL(window.location.href);
      const hashContent = (url.hash || '').replace(/^#/, '');
      if (!hashContent) return;
      const kept = hashContent
        .split('&')
        .filter((item) => item
          && !item.startsWith('__topiam_task=')
          && !item.startsWith(`${TOPIAM_RESET_RETRY_MARKER}=`));
      url.hash = kept.join('&');
      url.searchParams.delete('__topiam_task');
      url.searchParams.delete(TOPIAM_RESET_RETRY_MARKER);
      url.searchParams.delete('__topiam_hard_reload_ts');
      history.replaceState(null, null, url.href);
    } catch (error) {
      history.replaceState(
        null,
        null,
        window.location.href
          .replace(/__topiam_task=[a-zA-Z0-9_]+/g, '')
          .replace(new RegExp(`${TOPIAM_RESET_RETRY_MARKER}=[^&]+`, 'g'), '')
          .replace(/([?&])__topiam_hard_reload_ts=[^&#]*(&)?/g, '$1')
      );
    }
  }

  function setTaskAndResetMarkerAndReload(taskId) {
    const fallbackHardReload = () => {
      setTimeout(() => {
        try {
          window.location.reload();
        } catch (error) {}
      }, 1500);
    };

    try {
      const url = new URL(window.location.href);
      const hashParams = new URLSearchParams((url.hash || '').replace(/^#/, ''));
      hashParams.set('__topiam_task', String(taskId || ''));
      hashParams.set(TOPIAM_RESET_RETRY_MARKER, '1');
      url.searchParams.set('__topiam_hard_reload_ts', String(Date.now()));
      url.hash = hashParams.toString();
      window.location.replace(url.href);
      fallbackHardReload();
      return;
    } catch (error) {}

    const current = window.location.href.split('#')[0];
    const joiner = current.includes('?') ? '&' : '?';
    window.location.replace(`${current}${joiner}__topiam_hard_reload_ts=${Date.now()}#__topiam_task=${encodeURIComponent(String(taskId || ''))}&${TOPIAM_RESET_RETRY_MARKER}=1`);
    fallbackHardReload();
  }

  function resolveSessionExpiredLoginUrl() {
    const candidates = new Set();
    const addCandidate = (input) => {
      if (!input) return;
      try {
        const url = new URL(String(input), window.location.href);
        if (!/^https?:$/i.test(url.protocol)) return;
        if (url.origin !== window.location.origin) return;
        url.searchParams.set('__topiam_session_expired', '1');
        url.searchParams.set('_ts', String(Date.now()));
        candidates.add(url.href);
      } catch (error) {}
    };

    try {
      const formActions = Array.from(document.querySelectorAll('form[action]'));
      formActions.forEach((form) => {
        const action = String(form.getAttribute('action') || '').trim();
        if (/login|signin|sign-in|auth|sso|oauth|cas/i.test(action)) {
          addCandidate(action);
        }
      });
    } catch (error) {}

    const commonPaths = [
      '/login',
      '/signin',
      '/sign-in',
      '/auth/login',
      '/user/login',
      '/account/login',
      '/oauth/login',
      '/cas/login'
    ];
    commonPaths.forEach((path) => addCandidate(path));

    try {
      const pathname = String(window.location.pathname || '/');
      const inferred = pathname
        .replace(/(start|home|index|main)(\.[a-z0-9]+)?$/i, (_m, _w, ext) => `login${ext || ''}`)
        .replace(/(dashboard|portal)(\.[a-z0-9]+)?$/i, (_m, _w, ext) => `login${ext || ''}`);
      if (inferred && inferred !== pathname) {
        addCandidate(inferred);
      }
      if (/\.html?$/i.test(pathname)) {
        addCandidate(pathname.replace(/[^/]+\.html?$/i, 'login.html'));
      }
    } catch (error) {}

    const currentWithoutHash = String(window.location.href || '').split('#')[0];
    for (const candidate of candidates.values()) {
      if (candidate.split('#')[0] !== currentWithoutHash) {
        return candidate;
      }
    }
    return '';
  }

  function normalizePathForMatch(pathLike) {
    const raw = String(pathLike || '').trim();
    if (!raw) return '/';
    const withSlash = raw.startsWith('/') ? raw : `/${raw}`;
    return withSlash.replace(/\/+/g, '/').toLowerCase();
  }

  function splitForceRefreshRuleText(raw) {
    return String(raw || '')
      .split(/[\n,;|]/)
      .map((item) => item.trim())
      .filter(Boolean);
  }

  function parseForceRefreshPathRules(extra) {
    const candidates = [
      extra?.force_refresh_path,
      extra?.forceRefreshPath,
      extra?.FORCE_REFRESH_PATH
    ];

    const rules = [];
    candidates.forEach((entry) => {
      if (Array.isArray(entry)) {
        entry.forEach((item) => {
          rules.push(...splitForceRefreshRuleText(item));
        });
      } else {
        rules.push(...splitForceRefreshRuleText(entry));
      }
    });

    return [...new Set(rules.map((rule) => normalizePathForMatch(rule)).filter(Boolean))];
  }

  function matchesForceRefreshPathRule(pathname, rule) {
    const path = normalizePathForMatch(pathname);
    const normalizedRule = normalizePathForMatch(rule);
    if (!normalizedRule) return false;

    if (normalizedRule.startsWith('/**/')) {
      const suffix = normalizePathForMatch(normalizedRule.slice(4));
      if (!suffix || suffix === '/') return false;
      return path.endsWith(suffix) || path.includes(`${suffix}/`);
    }

    return path === normalizedRule || path.endsWith(normalizedRule);
  }

  function shouldForceRefreshCurrentPath() {
    if (!forceRefreshPathRules.length) return false;
    const currentPath = normalizePathForMatch(window.location.pathname || '/');
    const matchedRule = forceRefreshPathRules.find((rule) => matchesForceRefreshPathRule(currentPath, rule));
    if (!matchedRule) return false;

    targetLog('命中 force_refresh_path 规则，判定为非标登录页', {
      currentPath,
      matchedRule
    });
    return true;
  }

  function applyForceRefreshRules(extra) {
    forceRefreshPathRules = parseForceRefreshPathRules(extra || {});
    targetLog('已应用 force_refresh_path 规则', {
      count: forceRefreshPathRules.length,
      rules: forceRefreshPathRules
    });
  }

  function isLikelyNonStandardLoginSurface() {
    if (!IS_TOP_WINDOW) return false;
    if (isLikelyLoginContext()) return false;
    if (hasLikelyLoggedInSurface()) return false;
    if (isLikelyPostLoginPath()) return false;

    if (shouldForceRefreshCurrentPath()) {
      return true;
    }

    const passwordExists = Boolean(safeQuerySelector('input[type="password"], input[name*="pass" i], input[id*="pass" i]'));
    if (passwordExists) return false;

    const hintSelectors = [
      '[class*="chooser" i]',
      '[id*="chooser" i]',
      '[class*="history" i][class*="account" i]',
      '[class*="recent" i][class*="account" i]',
      '[class*="login" i][class*="history" i]',
      '[data-testid*="account" i]',
      '[id*="account-list" i]'
    ];

    const hasHintNode = hintSelectors.some((selector) => Boolean(safeQuerySelector(selector)));
    const bodyText = String(document.body?.innerText || '').slice(0, 4000).toLowerCase();
    const hasHintText = /历史登录|历史账号|账号列表|选择账号|切换账号|最近登录|记住账号|账号选择|登录方式|choose\s*account|select\s*account|recent\s*account|saved\s*account/.test(bodyText);
    const hasAccountItems = document.querySelectorAll('[data-account], [class*="account" i], [id*="account" i]').length >= 3;

    if ((hasHintNode || hasHintText || hasAccountItems) && !hasLikelyLoginSurface()) {
      return true;
    }

    return false;
  }

  async function shouldFastResetForNonStandardLogin(maxWaitMs = 650, intervalMs = 100) {
    if (!IS_TOP_WINDOW) return false;
    const start = Date.now();
    while (Date.now() - start < maxWaitMs) {
      if (isLikelyNonStandardLoginSurface()) {
        targetLog('快速探测命中非标准登录页', {
          waitedMs: Date.now() - start,
          href: window.location.href
        });
        return true;
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    return false;
  }

  function assertNotNonStandardLoginSurface(source = 'unknown') {
    if (!IS_TOP_WINDOW) return;
    if (isLikelyPostLoginPath()) {
      targetLog('当前URL更像登录后页面，跳过非标登录页中断', {
        source,
        href: window.location.href
      });
      return;
    }
    if (!isLikelyNonStandardLoginSurface()) return;
    targetLog('命中非标准登录页，立即中断常规代填流程', {
      source,
      href: window.location.href
    });
    throw new Error(NON_STANDARD_LOGIN_ERROR);
  }

  async function clearClientSideSiteData() {
    let localRemoved = 0;
    let sessionRemoved = 0;

    try {
      localRemoved = localStorage.length;
      localStorage.clear();
    } catch (error) {}

    try {
      sessionRemoved = sessionStorage.length;
      sessionStorage.clear();
    } catch (error) {}

    let idbRemoved = 0;
    try {
      if (window.indexedDB && typeof indexedDB.databases === 'function') {
        const databases = await indexedDB.databases();
        const names = (databases || []).map((db) => db?.name).filter(Boolean);
        await Promise.all(names.map((name) => new Promise((resolve) => {
          try {
            const request = indexedDB.deleteDatabase(name);
            request.onsuccess = () => resolve(true);
            request.onerror = () => resolve(false);
            request.onblocked = () => resolve(false);
          } catch (error) {
            resolve(false);
          }
        })));
        idbRemoved = names.length;
      }
    } catch (error) {}

    let cacheRemoved = 0;
    try {
      if (window.caches && typeof caches.keys === 'function') {
        const cacheKeys = await caches.keys();
        await Promise.all(cacheKeys.map((key) => caches.delete(key).catch(() => false)));
        cacheRemoved = cacheKeys.length;
      }
    } catch (error) {}

    return { localRemoved, sessionRemoved, idbRemoved, cacheRemoved };
  }

  async function forceResetAppStateAndRetry(taskId, reason = 'unknown') {
    if (!IS_TOP_WINDOW || !taskId) return false;
    if (bootHasResetRetryMarker) {
      targetLog('已存在重试标记，本轮不再执行强制重置', { reason, taskId });
      return false;
    }

    targetLog('检测到非标准登录形态，开始强制清理应用状态并重试', {
      reason,
      origin: location.origin,
      taskId
    });

    const withTimeout = (promise, ms, fallbackValue) => Promise.race([
      promise,
      new Promise((resolve) => setTimeout(() => resolve(fallbackValue), ms))
    ]);

    const cookiePromise = (async () => {
      try {
        const cookieResult = await chrome.runtime.sendMessage({
          action: 'clearSiteCookies',
          origin: location.origin,
          reason: `force_reset_${String(reason || 'unknown')}`
        });
        targetLog('后台cookie清理结果', cookieResult || {});
        return cookieResult || { success: false };
      } catch (error) {
        targetLog('后台cookie清理异常', { error: error?.message || String(error) });
        return { success: false, timeout: false };
      }
    })();

    const clientPromise = clearClientSideSiteData()
      .then((result) => {
        targetLog('前端站点数据清理结果', result);
        return result;
      })
      .catch(() => ({ localRemoved: 0, sessionRemoved: 0, idbRemoved: 0, cacheRemoved: 0 }));

    await Promise.allSettled([
      withTimeout(cookiePromise, 450, { success: false, timeout: true }),
      withTimeout(clientPromise, 450, { timeout: true })
    ]);

    showSubmitNotice('⚠ 检测到非标准登录页，已强制清理应用缓存并重试');
    setTaskAndResetMarkerAndReload(taskId);
    return true;
  }

  function getRetryStateKey() {
    return `topiam_retry_${location.origin}`;
  }

  function readRetryCount() {
    try {
      const raw = sessionStorage.getItem(getRetryStateKey());
      if (!raw) return 0;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return 0;
      if (Date.now() - Number(parsed.ts || 0) > 10 * 60 * 1000) return 0;
      return Number(parsed.count || 0);
    } catch (error) {
      return 0;
    }
  }

  function writeRetryCount(count) {
    try {
      sessionStorage.setItem(getRetryStateKey(), JSON.stringify({ count, ts: Date.now() }));
    } catch (error) {}
  }

  async function tryRecoverTaskIdFromBackground() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'getPendingTaskForTab' });
      if (response?.success && response.taskId) {
        targetLog('从background恢复到任务ID', { taskId: response.taskId });
        return response.taskId;
      }
      return '';
    } catch (error) {
      targetLog('从background恢复任务ID失败', { error: error?.message || String(error) });
      return '';
    }
  }

  async function waitForLoginSurface(maxWaitMs = 1000, intervalMs = 120) {
    const start = Date.now();
    let rounds = 0;

    while (Date.now() - start < maxWaitMs) {
      assertNotNonStandardLoginSurface('wait_for_login_surface');

      const hasPassword = Boolean(safeQuerySelector('input[type="password"], input[name*="pass" i], input[id*="pass" i]'));
      const hasUserLike = Boolean(safeQuerySelector('input[name*="user" i], input[name*="account" i], input[name*="login" i], input[autocomplete="username"], input[type="email"]'));
      const hasButtonLike = Boolean(safeQuerySelector('button[type="submit"], input[type="submit"], button, a, [role="button"]'));
      const likelyLoginFrames = collectLikelyLoginFrames(Array.from(document.querySelectorAll('iframe')));
      const hasLikelyLoginIframe = likelyLoginFrames.length > 0;
      const hasFrameworkHint = Boolean(window.React || window.__REACT_ROOTS__ || window.Vue || safeQuerySelector('[data-reactroot], [data-v-app], #__vue_app__'));

      if (hasPassword || (hasUserLike && hasButtonLike) || hasLikelyLoginIframe || hasFrameworkHint) {
        targetLog('登录界面已就绪，继续代填', {
          rounds,
          waitedMs: Date.now() - start,
          hasPassword,
          hasUserLike,
          hasButtonLike,
          hasLikelyLoginIframe,
          hasFrameworkHint
        });
        return;
      }

      rounds += 1;
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }

    targetLog('等待登录界面就绪超时（快速模式），按现状继续尝试代填', {
      waitedMs: Date.now() - start,
      rounds
    });
  }

  function detectStrategy() {
    // iframe内部不应该再选iframe策略，直接尝试标准策略
    // 这防止了嵌套iframe导致的递归问题
    if (!IS_TOP_WINDOW) {
      if (window.React || window.__REACT_ROOTS__ || safeQuerySelector('[data-reactroot]')) return 'react';
      if (window.Vue || safeQuerySelector('[data-v-app], #__vue_app__')) return 'vue';
      const hasShadowHost = Array.from(document.querySelectorAll('body *')).some((node) => Boolean(node.shadowRoot));
      if (hasShadowHost) return 'shadow';
      // iframe内部强制使用standard策略，不用iframe策略
      // 这样避免了iframe内部再去等待ACK导致的死锁
      targetLog('iframe内部策略选择: 强制使用standard(避免嵌套iframe问题)');
      return 'standard';
    }

    if (safeQuerySelector('input[type="password"]')) return 'standard';

    if (window.React || window.__REACT_ROOTS__ || safeQuerySelector('[data-reactroot]')) return 'react';
    if (window.Vue || safeQuerySelector('[data-v-app], #__vue_app__')) return 'vue';

    const hasShadowHost = Array.from(document.querySelectorAll('body *')).some((node) => Boolean(node.shadowRoot));
    if (hasShadowHost) return 'shadow';

    // 检测iframe中的输入框 - 包括跨域iframe
    const iframes = document.querySelectorAll('iframe');
    const hasAnyIframe = iframes.length > 0;
    for (const iframe of iframes) {
      try {
        const doc = iframe.contentDocument;
        if (doc?.querySelector('input[type="password"]')) {
          targetLog('主框架检测策略: 在iframe中找到password输入框');
          return 'iframe';
        }
      } catch (e) {
        // 跨域iframe无法直接访问，但仍然继续检查
      }
    }

    // 仅当iframe存在明确登录特征时，才使用iframe策略，避免在业务框架页消息风暴
    if (hasAnyIframe) {
      const likelyLoginFrames = collectLikelyLoginFrames(Array.from(iframes));
      if (likelyLoginFrames.length > 0) {
        targetLog('主框架检测策略: 检测到疑似登录iframe，使用iframe策略', { likelyCount: likelyLoginFrames.length });
        return 'iframe';
      }
      targetLog('主框架检测策略: 虽有iframe但无登录特征，回落standard策略', { frameCount: iframes.length });
      return 'standard';
    }

    return 'standard';
  }

  class SmartFiller {
    constructor(user, pass, extra, fullName = '') {
      this.user = user;
      this.pass = pass;
      this.extra = extra || {};
      this.fullName = String(fullName || user || '').trim();
      this.didFillPassword = false;
      this.didSubmit = false;
    }

    async execute(strategy) {
      targetLog('SmartFiller.execute 开始', { 
        strategy,
        isTopWindow: IS_TOP_WINDOW,
        href: window.location.href
      });
      this.hardenCredentialPersistence();

      try {
        switch(strategy) {
          case 'react':
            targetLog('执行 React 策略');
            await this.fillReact();
            break;
          case 'vue':
            targetLog('执行 Vue 策略');
            await this.fillVue();
            break;
          case 'shadow':
            targetLog('执行 Shadow DOM 策略');
            await this.fillShadowDOM();
            break;
          case 'iframe':
            targetLog('执行 iframe 策略');
            await this.fillIframe();
            break;
          default:
            targetLog('执行标准策略');
            await this.fillStandard();
        }
        targetLog('SmartFiller.execute 主策略成功完成', { strategy });
      } catch (error) {
        if (String(error?.message || '').includes(NON_STANDARD_LOGIN_ERROR)) {
          throw error;
        }
        targetError('SmartFiller 首轮策略失败，触发回退', {
          strategy,
          error: error?.message || String(error)
        });
        await this.sleep(500);
        try {
          targetLog('尝试回退 standard 策略');
          await this.fillStandard();
          targetLog('standard 回退策略成功');
        } catch (standardError) {
          targetError('standard 回退失败，评估是否允许最后尝试 iframe 策略', {
            error: standardError?.message || String(standardError)
          });
          const likelyLoginFrames = collectLikelyLoginFrames(Array.from(document.querySelectorAll('iframe')));
          if (likelyLoginFrames.length === 0) {
            throw standardError;
          }
          targetLog('检测到疑似登录iframe，执行最后回退 iframe 策略', { likelyCount: likelyLoginFrames.length });
          await this.fillIframe();
        }
      }
    }

    hardenCredentialPersistence() {
      this.activateCredentialStoreBlockWindow();
      document.querySelectorAll('form').forEach((form) => {
        form.setAttribute('autocomplete', 'off');
      });
      document.querySelectorAll('input').forEach((input) => {
        const type = (input.getAttribute('type') || '').toLowerCase();
        if (type === 'password') {
          input.setAttribute('autocomplete', 'new-password');
        } else {
          input.setAttribute('autocomplete', 'off');
        }
      });
    }

    activateCredentialStoreBlockWindow(durationMs = 2 * 60 * 1000) {
      const safeDurationMs = Number.isFinite(Number(durationMs)) && Number(durationMs) > 0
        ? Math.floor(Number(durationMs))
        : 2 * 60 * 1000;
      const payload = {
        durationMs: Math.max(1000, Math.min(10 * 60 * 1000, safeDurationMs)),
        source: 'content_target_autofill'
      };

      try {
        window.dispatchEvent(new CustomEvent(TOPIAM_BLOCK_CREDENTIAL_EVENT, { detail: payload }));
        targetLog('已请求 page-bridge 进入凭据存储拦截窗口', payload);
      } catch (error) {
        targetError('请求凭据存储拦截窗口失败', { error: error?.message || String(error) });
      }
    }

    setNativeValue(element, value) {
      if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement)) return;
      const prototype = element instanceof HTMLTextAreaElement
        ? window.HTMLTextAreaElement.prototype
        : window.HTMLInputElement.prototype;
      const descriptor = Object.getOwnPropertyDescriptor(prototype, 'value');
      if (descriptor?.set) {
        descriptor.set.call(element, value);
      } else {
        element.value = value;
      }
      // 触发React/Vue等框架的状态更新事件
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype,
        'value'
      ).set;
      if (nativeInputValueSetter) {
        nativeInputValueSetter.call(element, value);
      }
    }

    fillField(element, value) {
      if (!(element instanceof HTMLElement)) return;
      const stringValue = String(value || '');
      
      element.focus();
      this.setNativeValue(element, stringValue);
      
      // 验证填充是否成功
      const valueAfterFill = element.value || '';
      const successful = valueAfterFill === stringValue;
      const typeLike = String(element?.type || element?.getAttribute?.('type') || '').toLowerCase();
      if (successful && typeLike === 'password') {
        this.didFillPassword = true;
      }
      targetLog('fillField 验证', {
        expected: stringValue.substring(0, 20),
        actual: valueAfterFill.substring(0, 20),
        success: successful
      });
      
      // 按顺序触发各类事件以确保所有框架都能检测到变化
      const events = [
        new Event('keydown', { bubbles: true, cancelable: true }),
        new Event('keypress', { bubbles: true, cancelable: true }),
        new Event('beforeinput', { bubbles: true, cancelable: true }),
        new Event('input', { bubbles: true, cancelable: true }),
        new Event('keyup', { bubbles: true, cancelable: true }),
        new Event('change', { bubbles: true, cancelable: true }),
        new Event('blur', { bubbles: true, cancelable: true })
      ];
      
      events.forEach(event => {
        try {
          element.dispatchEvent(event);
        } catch (e) {}
      });
    }

    triggerRealClick(element) {
      if (!(element instanceof HTMLElement)) {
        targetLog('triggerRealClick: 元素不是HTMLElement', { type: typeof element });
        return false;
      }
      
      try {
        element.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
        targetLog('triggerRealClick: scrollIntoView成功');
      } catch (e) {
        targetLog('triggerRealClick: scrollIntoView失败', { error: e?.message });
      }
      
      // 最可靠的方式：直接调用 element.click()
      // 这会触发所有在DOM上注册的click监听器
      try {
        element.click();
        targetLog('triggerRealClick: element.click()调用成功', {
          tag: element.tagName,
          hasProperty_onclick: Boolean(element.onclick),
          hasAttribute_onclick: Boolean(element.getAttribute('onclick')),
          type: element.getAttribute('type')
        });
        return true;
      } catch (error) {
        targetError('triggerRealClick: element.click()异常', {
          error: String(error?.message || error),
          errorType: error?.constructor?.name
        });
      }

      // 备选方案：手动分发各种鼠标事件
      const mouseEvents = ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click'];
      let successfulEvents = 0;
      for (const eventName of mouseEvents) {
        try {
          const evt = new MouseEvent(eventName, {
            bubbles: true,
            cancelable: true,
            view: window
          });
          element.dispatchEvent(evt);
          successfulEvents++;
        } catch (e) {
          targetLog('triggerRealClick: ' + eventName + '事件分发失败', { error: e?.message });
        }
      }
      
      if (successfulEvents > 0) {
        targetLog('triggerRealClick: 备选-事件分发', { successCount: successfulEvents });
        return true;
      }

      // 再备选：form.submit()
      if (element instanceof HTMLButtonElement || (element instanceof HTMLInputElement && element.type === 'submit')) {
        try {
          const form = element.form || element.closest('form');
          if (form) {
            form.submit();
            targetLog('triggerRealClick: 备选-form.submit()');
            return true;
          }
        } catch (e) {
          targetError('triggerRealClick: form.submit()异常', { error: String(e?.message || e) });
        }
      }

      targetError('triggerRealClick: 所有点击方法都失败');
      return false;
    }

    isUsableClickable(node) {
      if (!(node instanceof HTMLElement)) return false;
      if (node.offsetParent === null) return false;
      if (node.hasAttribute('disabled')) return false;
      if (node.getAttribute('aria-disabled') === 'true') return false;
      
      // 检查元素是否被隐藏（display, visibility, opacity）
      const style = window.getComputedStyle(node);
      if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
        return false;
      }
      
      // 检查元素的宽度和高度（太小的元素可能不是可点击的）
      const rect = node.getBoundingClientRect();
      if (rect.width < 20 || rect.height < 20) {
        return false;
      }
      
      // 检查元素是否超出可视区域（已被scrollParent滚出）
      if (rect.bottom < 0 || rect.top > window.innerHeight || rect.right < 0 || rect.left > window.innerWidth) {
        return false;
      }
      
      return true;
    }

    async clickDetectedLoginButton(root = document, passwordEl = null, stage = 'submit') {
      const button = this.findSmartLoginButton(root, passwordEl);
      if (!button) {
        targetLog('未命中登录按钮', { 
          stage,
          rootTag: root?.tagName || 'unknown',
          passwordElFound: Boolean(passwordEl)
        });
        return false;
      }

      const rect = button.getBoundingClientRect();
      targetLog('命中登录按钮并执行点击', {
        stage,
        tag: button.tagName,
        id: button.id || '',
        name: button.getAttribute('name') || '',
        type: button.getAttribute('type') || '',
        class: (button.className || '').substring(0, 100),
        text: (button.textContent || button.getAttribute('value') || '').trim().slice(0, 100),
        visible: {
          width: Math.round(rect.width),
          height: Math.round(rect.height),
          top: Math.round(rect.top),
          left: Math.round(rect.left)
        },
        hasOnclick: Boolean(button.onclick || button.getAttribute('onclick'))
      });
      this.triggerRealClick(button);
      this.didSubmit = true;
      
      // 点击后等待，给页面和服务器足够的时间响应（AJAX请求、表单提交等）
      await this.sleep(800);
      
      return true;
    }

    async tryTwoStepLogin(root = document, detected = null) {
      const info = detected || this.findCredentialInputs(root);
      if (!info?.userEl || info?.passEl) {
        return false;
      }

      targetLog('检测到单输入框登录流程，先提交账号步骤');
      this.fillField(info.userEl, this.user);
      await this.sleep(300);
      const clicked = await this.clickDetectedLoginButton(root, null, 'step-1-user');
      if (!clicked) {
        return false;
      }

      for (let i = 0; i < 14; i++) {
        await this.sleep(350);
        const next = this.findCredentialInputs(root);
        if (next?.passEl) {
          targetLog('账号步骤后检测到密码框，进入第二步');
          this.fillField(next.passEl, this.pass);
          await this.sleep(300);
          await this.tryAutoSubmit(root, next.passEl);
          return true;
        }
      }

      targetLog('两步登录流程未等到密码框出现');
      return false;
    }

    findCredentialInputs(root = document) {
      const collectInputs = (container) => {
        const result = [];
        if (!container || !container.querySelectorAll) return result;

        const direct = Array.from(container.querySelectorAll('input'));
        direct.forEach((node) => result.push(node));

        const allNodes = Array.from(container.querySelectorAll('*'));
        allNodes.forEach((node) => {
          if (node.shadowRoot) {
            const shadowInputs = collectInputs(node.shadowRoot);
            shadowInputs.forEach((item) => result.push(item));
          }
        });

        return result;
      };

      const visibleInputs = collectInputs(root).filter((node) => {
        if (!(node instanceof HTMLInputElement)) return false;
        const type = (node.type || '').toLowerCase();
        if (['hidden', 'file', 'checkbox', 'radio', 'button', 'submit', 'reset'].includes(type)) return false;
        if (node.disabled) return false;
        if (node.readOnly && type !== 'password') return false;
        if (node.offsetParent === null && type !== 'password') return false;
        return true;
      });

      const readMeta = (node) => {
        const type = String(node.type || node.getAttribute('type') || '').toLowerCase();
        const name = (node.getAttribute('name') || '').toLowerCase();
        const id = (node.getAttribute('id') || '').toLowerCase();
        const placeholder = (node.getAttribute('placeholder') || '').toLowerCase();
        const autocomplete = (node.getAttribute('autocomplete') || '').toLowerCase();
        const ariaLabel = (node.getAttribute('aria-label') || '').toLowerCase();
        const className = (node.getAttribute('class') || '').toLowerCase();
        const dataField = (node.getAttribute('data-field') || '').toLowerCase();
        const labelText = (node.closest('label')?.textContent || '').toLowerCase();
        const bucket = `${name} ${id} ${placeholder} ${autocomplete} ${ariaLabel} ${labelText} ${className} ${dataField}`;
        return { type, bucket };
      };

      const scorePassword = (node) => {
        const { type, bucket } = readMeta(node);
        let score = 0;
        if (type === 'password') score += 120;
        if (/password|passwd|pass|pwd|secret|credential|密[码碼]/i.test(bucket)) score += 80;
        if (/current-password|new-password/i.test(bucket)) score += 40;
        return score;
      };

      const scoreUser = (node) => {
        const { type, bucket } = readMeta(node);
        let score = 0;
        if (type === 'email' || type === 'text' || type === 'tel') score += 30;
        if (/username|user|login|account|email|mobile|phone|principal|uid|工号|账号|用[户戶]名|邮[箱箱]/i.test(bucket)) score += 90;
        if (/username|email|tel/i.test(bucket)) score += 20;
        if (/password|passwd|pass|pwd|密[码碼]/i.test(bucket)) score -= 120;
        return score;
      };

      const passCandidates = visibleInputs
        .map((node) => ({ node, score: scorePassword(node) }))
        .filter((item) => item.score > 0)
        .sort((a, b) => b.score - a.score);

      const userCandidates = visibleInputs
        .map((node) => ({ node, score: scoreUser(node) }))
        .filter((item) => item.score > 0)
        .sort((a, b) => b.score - a.score);

      const getContainer = (node) => {
        return node.closest('form, [class*="login" i], [id*="login" i], .ant-form, .el-form, .layui-form') || document.body;
      };

      const getDistance = (a, b) => {
        if (!a || !b) return 99999;
        if (a === b) return 0;
        const aRect = a.getBoundingClientRect();
        const bRect = b.getBoundingClientRect();
        const dx = Math.abs((aRect.left + aRect.width / 2) - (bRect.left + bRect.width / 2));
        const dy = Math.abs((aRect.top + aRect.height / 2) - (bRect.top + bRect.height / 2));
        return dx + dy;
      };

      let bestPair = { userEl: null, passEl: null, score: -1 };

      passCandidates.forEach((passItem) => {
        const passNode = passItem.node;
        const passContainer = getContainer(passNode);

        const sameContainerUsers = userCandidates.filter((userItem) => {
          const userNode = userItem.node;
          return getContainer(userNode) === passContainer && userNode !== passNode;
        });

        const candidateUsers = sameContainerUsers.length ? sameContainerUsers : userCandidates;
        const bestUserForPass = candidateUsers[0] || null;
        const distancePenalty = bestUserForPass ? Math.min(getDistance(bestUserForPass.node, passNode), 1500) / 20 : 25;
        const pairScore = passItem.score + (bestUserForPass ? bestUserForPass.score : 15) - distancePenalty;

        if (pairScore > bestPair.score) {
          bestPair = {
            userEl: bestUserForPass?.node || null,
            passEl: passNode,
            score: pairScore
          };
        }
      });

      let userEl = bestPair.userEl;
      let passEl = bestPair.passEl;

      if (!passEl && visibleInputs.length) {
        passEl = visibleInputs[visibleInputs.length - 1] || null;
      }

      if (!userEl && passEl) {
        const siblings = visibleInputs.filter((node) => node !== passEl && getContainer(node) === getContainer(passEl));
        userEl = siblings.find((node) => {
          const type = (node.getAttribute('type') || '').toLowerCase();
          return ['text', 'email', 'tel', ''].includes(type);
        }) || null;
      }

      targetLog('识别登录输入框', {
        inputCount: visibleInputs.length,
        hasUser: Boolean(userEl),
        hasPass: Boolean(passEl),
        userName: userEl?.getAttribute('name') || userEl?.id || '',
        passName: passEl?.getAttribute('name') || passEl?.id || '',
        passType: passEl?.getAttribute('type') || '',
        pairScore: bestPair.score
      });

      return { userEl, passEl };
    }

    findSubmitButton(root = document, passwordEl = null) {
      const form = passwordEl?.form || null;
      const scope = form || root;

      // 方法1：查找type="submit"的按钮（最可靠）
      const submitSelectors = ['button[type="submit"]', 'input[type="submit"]'];
      for (const selector of submitSelectors) {
        const candidates = Array.from(scope.querySelectorAll(selector));
        const usable = candidates.find((button) => {
          if (!(button instanceof HTMLElement)) return false;
          if (button.hasAttribute('disabled')) return false;
          if (button.getAttribute('aria-disabled') === 'true') return false;
          if (button.offsetParent === null) return false;
          return true;
        });
        if (usable) return usable;
      }

      // 方法2：查找onclick属性的真正button元素（不包括div等容器）
      const oninclickButtons = Array.from(scope.querySelectorAll('button[onclick], input[type="button"][onclick]')).filter((btn) => {
        if (!this.isUsableClickable(btn)) return false;
        const text = (btn.textContent || btn.getAttribute('value') || '').trim().toLowerCase();
        return /登录|登錄|login|sign\s*in|submit|continue|next|go|进入|提交|确定/.test(text);
      });
      if (oninclickButtons.length > 0) return oninclickButtons[0];

      // 方法3：在form内査找真正的button元素（type=button或无type）
      if (form) {
        const formButtons = Array.from(form.querySelectorAll('button:not([type="submit"]), button[type="button"]')).filter((btn) => {
          if (!(btn instanceof HTMLButtonElement)) return false;
          if (!this.isUsableClickable(btn)) return false;
          const text = (btn.textContent || '').trim().toLowerCase();
          return /登录|登錄|login|sign\s*in|submit|continue|next|go|进入|提交|确定/.test(text);
        });
        if (formButtons.length > 0) return formButtons[0];
      }

      // 方法4：查找常见的CSS类名（仅限button和input类型）
      const fallbackSelectors = [
        'button.login-btn, button.login-form__submit',
        'button.ant-btn-primary', 
        'button.el-button--primary',
        'button.login',
        'button.submit',
        'button.call-to-action',
        'input[type="button"].login',
        'input[value*="登"]',
        'input[value*="Login"]',
        'input[value*="Sign"]'
      ];
      for (const selector of fallbackSelectors) {
        const node = scope.querySelector(selector);
        if (this.isUsableClickable(node) && (node instanceof HTMLButtonElement || node instanceof HTMLInputElement)) {
          return node;
        }
      }

      // 方法5：查找任何真正的button元素（不包括div等容器），按文本匹配排序
      const allButtons = Array.from(scope.querySelectorAll('button:not([type="submit"]), button[type="button"], input[type="button"]'));
      const textMatch = allButtons.filter((btn) => {
        const text = (btn.textContent || btn.getAttribute('value') || '').trim().toLowerCase();
        return /登|login|submit|sign|确|go/.test(text) && this.isUsableClickable(btn);
      });
      if (textMatch.length > 0) return textMatch[0];

      return null;
    }

    findSmartLoginButton(root = document, passwordEl = null) {
      const primary = this.findSubmitButton(root, passwordEl);
      if (primary) return primary;

      const getDistance = (a, b) => {
        if (!a || !b) return 99999;
        const aRect = a.getBoundingClientRect();
        const bRect = b.getBoundingClientRect();
        const dx = Math.abs((aRect.left + aRect.width / 2) - (bRect.left + bRect.width / 2));
        const dy = Math.abs((aRect.top + aRect.height / 2) - (bRect.top + bRect.height / 2));
        return dx + dy;
      };

      const anchor = passwordEl || this.findCredentialInputs(root).passEl || this.findCredentialInputs(root).userEl;

      if (anchor) {
        const container = anchor.closest('form, [class*="login" i], [id*="login" i], .ant-form, .el-form, .layui-form') || root;
        
        // 优先在容器内查找真正的button/input元素
        const buttonLikeCandidates = Array.from(container.querySelectorAll('button, input[type="button"], input[type="submit"]')).filter((node) => this.isUsableClickable(node));
        
        // 如果有button/input，只从中选择
        if (buttonLikeCandidates.length > 0) {
          const ranked = buttonLikeCandidates
            .map((node) => {
              const text = `${node.textContent || ''} ${node.getAttribute('value') || ''} ${node.getAttribute('aria-label') || ''}`.trim();
              const semantic = /登录|登錄|login|sign\s*in|submit|continue|next|进入系统|立即登录|go|提交|确定/i.test(text);
              const distance = getDistance(anchor, node);
              const score = (semantic ? 1000 : 0) - distance;
              return { node, score, distance, semantic };
            })
            .sort((a, b) => b.score - a.score);

          const best = ranked[0];
          if (best) {
            targetLog('按输入框附近命中登录按钮(button)', {
              distance: Math.round(best.distance),
              semantic: best.semantic,
              tag: best.node.tagName,
              text: (best.node.textContent || best.node.getAttribute('value') || '').trim().slice(0, 60)
            });
            return best.node;
          }
        }

        // 如果没找到button，才扩展到div等容器元素（有onclick或role=button）
        const extendedCandidates = Array.from(container.querySelectorAll('a, div[role="button"], span[role="button"], [onclick], [class*="btn" i], [class*="login" i], [class*="submit" i]')).filter((node) => {
          if (!this.isUsableClickable(node)) return false;
          // 排除文本过长的容器（可能是安全提示等）
          const text = (node.textContent || '').trim();
          if (text.length > 200) return false;
          return true;
        });

        if (extendedCandidates.length > 0) {
          const ranked = extendedCandidates
            .map((node) => {
              const text = `${node.textContent || ''} ${node.getAttribute('value') || ''} ${node.getAttribute('aria-label') || ''}`.trim();
              const semantic = /登录|登錄|login|sign\s*in|submit|continue|next|进入系统|立即登录|go|提交|确定/i.test(text);
              const distance = getDistance(anchor, node);
              const score = (semantic ? 1000 : 0) - distance;
              return { node, score, distance, semantic };
            })
            .sort((a, b) => b.score - a.score);

          const best = ranked[0];
          if (best && (best.semantic || best.distance < 420)) {
            targetLog('按输入框附近命中登录按钮(容器)', {
              distance: Math.round(best.distance),
              semantic: best.semantic,
              tag: best.node.tagName,
              text: (best.node.textContent || best.node.getAttribute('value') || '').trim().slice(0, 60)
            });
            return best.node;
          }
        }
      }

      // 全局搜索：优先查找真正的button元素
      const globalButtons = Array.from(root.querySelectorAll('button, input[type="button"], input[type="submit"]')).filter((btn) => {
        if (!this.isUsableClickable(btn)) return false;
        const text = (btn.textContent || btn.getAttribute('value') || '').trim().toLowerCase();
        return /登|login|submit|sign|确|go/.test(text);
      });
      
      if (globalButtons.length > 0) {
        targetLog('全局查找: 发现真正button元素');
        return globalButtons[0];
      }

      // 最后才扩展到div等容器元素
      const extendedSelectors = [
        'a, div[role="button"], span[role="button"], [onclick], [onclick*="submit"], [onclick*="login"]',
        '[class*="btn" i], [class*="login" i], [class*="submit" i]',
        '[id*="btn"], [id*="login"], [id*="submit"]'
      ];

      for (const selector of extendedSelectors) {
        try {
          const candidates = Array.from(root.querySelectorAll(selector)).filter((node) => {
            if (!this.isUsableClickable(node)) return false;
            const text = (node.textContent || '').trim();
            // 排除过长的文本（可能不是按钮）
            if (text.length > 200) return false;
            return true;
          });
          
          const textRegex = /登录|登錄|login|sign\s*in|submit|continue|next|进入系统|立即登录|go|提交|确定/i;

          const matched = candidates.find((node) => {
            const text = `${node.textContent || ''} ${node.getAttribute('value') || ''} ${node.getAttribute('aria-label') || ''}`.trim();
            return textRegex.test(text);
          });

          if (matched) {
            targetLog('扩展查找: 在容器元素中找到按钮', {
              tag: matched.tagName,
              class: matched.className?.slice(0, 60)
            });
            return matched;
          }
        } catch (e) {}
      }

      return null;
    }

    getLikelyUsernameCandidates(root = document, passwordEl = null) {
      const scope = passwordEl?.form || root;
      const nodes = Array.from(scope.querySelectorAll('input'));

      return nodes.filter((node) => {
        if (!(node instanceof HTMLInputElement)) return false;
        if (node === passwordEl) return false;

        const type = (node.getAttribute('type') || '').toLowerCase();
        if (['password', 'hidden', 'file', 'checkbox', 'radio', 'button', 'submit', 'reset'].includes(type)) {
          return false;
        }

        const name = (node.getAttribute('name') || '').toLowerCase();
        const id = (node.getAttribute('id') || '').toLowerCase();
        const placeholder = (node.getAttribute('placeholder') || '').toLowerCase();
        const autocomplete = (node.getAttribute('autocomplete') || '').toLowerCase();
        const ariaLabel = (node.getAttribute('aria-label') || '').toLowerCase();
        const labelText = (node.closest('label')?.textContent || '').toLowerCase();
        const bucket = `${name} ${id} ${placeholder} ${autocomplete} ${ariaLabel} ${labelText}`;

        const isUserLike = /username|user|login|account|email|mobile|phone|principal|uid|工号|账号|用[户戶]名|邮[箱箱]/i.test(bucket)
          || autocomplete === 'username';

        if (!isUserLike) return false;

        // 可见或已有值都算候选，避免误判“没有账号框”
        const hasValue = Boolean((node.value || '').trim());
        const visible = node.offsetParent !== null;
        if (!visible && !hasValue) return false;

        return true;
      });
    }

    evaluateSubmitReadiness(root = document, detected = null, passwordEl = null) {
      if (!passwordEl) {
        return { allowSubmit: true, reason: 'no_password_element' };
      }

      const explicitUser = detected?.userEl || null;
      if (explicitUser) {
        const hasUserValue = Boolean((explicitUser.value || '').trim());
        if (hasUserValue) {
          return { allowSubmit: true, reason: 'explicit_user_filled' };
        }
        return {
          allowSubmit: false,
          reason: 'explicit_user_empty',
          candidate: explicitUser,
          candidateCount: 1
        };
      }

      const candidates = this.getLikelyUsernameCandidates(root, passwordEl);
      if (candidates.length === 0) {
        // 密码单字段场景，允许提交
        return { allowSubmit: true, reason: 'no_username_candidate' };
      }

      const filled = candidates.find((node) => Boolean((node.value || '').trim()));
      if (filled) {
        return { allowSubmit: true, reason: 'username_candidate_filled', candidateCount: candidates.length };
      }

      const editable = candidates.find((node) => !node.disabled && !node.readOnly) || null;
      return {
        allowSubmit: false,
        reason: 'username_candidates_empty',
        candidate: editable,
        candidateCount: candidates.length
      };
    }

    async tryAutoSubmit(root = document, passwordEl = null) {
      if (this.hasCaptcha()) {
        targetLog('检测到验证码，跳过自动提交');
        return false;
      }

      for (let i = 0; i < 8; i++) {
        const detected = this.findCredentialInputs(root);
        const localPasswordEl = passwordEl || detected.passEl || root.querySelector('input[type="password"]');
        
        targetLog('tryAutoSubmit 尝试', {
          attempt: i + 1,
          foundPasswordEl: Boolean(localPasswordEl),
          rootTag: root?.tagName || 'unknown'
        });

        const readiness = this.evaluateSubmitReadiness(root, detected, localPasswordEl);
        if (!readiness.allowSubmit) {
          targetLog('阻止自动点击：账号未确认已填写', {
            attempt: i + 1,
            reason: readiness.reason,
            candidateCount: readiness.candidateCount || 0
          });

          if (readiness.candidate && this.user) {
            try {
              this.fillField(readiness.candidate, this.user);
              targetLog('已补填账号字段，等待下一轮提交检测');
            } catch (error) {
              targetLog('补填账号字段失败', { error: error?.message });
            }
          }

          if (i < 7) {
            await this.sleep(350);
          }
          continue;
        }
        
        const clicked = await this.clickDetectedLoginButton(root, localPasswordEl, `submit-${i + 1}`);

        if (clicked) {
          targetLog('已自动点击登录按钮成功', { attempt: i + 1 });
          return true;
        }

        const form = localPasswordEl?.form || null;
        if (form && typeof form.requestSubmit === 'function') {
          try {
            form.requestSubmit();
            this.didSubmit = true;
            targetLog('未命中登录按钮，已执行 form.requestSubmit 兜底', { attempt: i + 1 });
            return true;
          } catch (error) {
            targetLog('form.requestSubmit 兜底失败', { attempt: i + 1, error: error?.message });
          }
        }

        if (form) {
          try {
            form.submit();
            this.didSubmit = true;
            targetLog('未命中登录按钮，已执行 form.submit 兜底', { attempt: i + 1 });
            return true;
          } catch (error) {
            targetLog('form.submit 兜底失败', { attempt: i + 1, error: error?.message });
          }
        }

        if (i < 7) {
          await this.sleep(300);
        }
      }

      targetLog('未找到可提交的登录控件，所有8次尝试都失败');
      return false;
    }

    async fillReact() {
      const findInputs = () => {
        const detected = this.findCredentialInputs(document);
        return { user: detected.userEl, pass: detected.passEl };
      };

      let inputs = findInputs();
      let attempts = 0;
      while (!inputs.pass && attempts < 12) {
        await this.sleep(400);
        inputs = findInputs();
        attempts += 1;
      }

      if (!inputs.pass) {
        const twoStepDone = await this.tryTwoStepLogin(document, { userEl: inputs.user, passEl: inputs.pass });
        if (twoStepDone) return;
      }

      if (!inputs.pass) {
        throw new Error('未找到输入框');
      }

      if (inputs.user) {
        this.fillField(inputs.user, this.user);
        await this.sleep(250);
      }
      this.fillField(inputs.pass, this.pass);
      await this.sleep(600);
      const submitted = await this.tryAutoSubmit(document, inputs.pass);
      if (!submitted) {
        throw new Error('React/Vue页面未找到可点击登录按钮');
      }
    }

    fillVue() {
      return this.fillReact();
    }

    async fillShadowDOM() {
      const fillRecursive = (root) => {
        const user = root.querySelector('input:not([type="password"]):not([type="hidden"])');
        const pass = root.querySelector('input[type="password"]');

        if (user) {
          this.fillField(user, this.user);
        }
        if (pass) {
          this.fillField(pass, this.pass);
        }

        root.querySelectorAll('*').forEach((node) => {
          if (node.shadowRoot) fillRecursive(node.shadowRoot);
        });
      };

      fillRecursive(document.body);
      await this.sleep(900);
      const passEl = document.querySelector('input[type="password"]');
      const submitted = await this.tryAutoSubmit(document, passEl);
      if (!submitted) {
        throw new Error('Shadow DOM 页面未找到可点击登录按钮');
      }
    }

    async fillIframe() {
      const allFrames = Array.from(document.querySelectorAll('iframe'));
      const candidateFrames = collectLikelyLoginFrames(allFrames);
      let broadcastCount = 0;

      targetLog('fillIframe: 开始处理iframe', { frameCount: allFrames.length, candidateCount: candidateFrames.length });

      if (candidateFrames.length === 0) {
        throw new Error('未发现疑似登录iframe，跳过iframe策略');
      }

      // 设置监听器，用于检测这些iframe是否即将卸载（登录成功的标志）
      const iframeUnloadListeners = [];
      candidateFrames.forEach((iframe) => {
        try {
          const handleIframeUnload = () => {
            // iframe页面卸载 = 登录成功，立即标记成功
            targetLog('fillIframe: 检测到iframe本身即将卸载，判定为成功登录');
            window._iframeLoginResultTemp = true;
          };
          // 尝试在iframe的contentWindow上监听beforeunload
          // (这对跨域iframe无效，但对同域iframe有效)
          try {
            if (iframe.contentWindow) {
              iframe.contentWindow.addEventListener('beforeunload', handleIframeUnload);
              iframeUnloadListeners.push({ iframe, handler: handleIframeUnload });
            }
          } catch (e) {
            // 跨域iframe无法监听，continue
          }
        } catch (e) {}
      });

      // 第一步：尝试直接访问可读的iframe
      for (const iframe of candidateFrames) {
        try {
          const doc = iframe.contentDocument;
          if (!doc) continue;

          targetLog('fillIframe: 发现可读iframe，尝试填充');
          const detected = this.findCredentialInputs(doc);
          
          if (detected.passEl) {
            if (detected.userEl) {
              this.fillField(detected.userEl, this.user);
              await this.sleep(250);
            }
            this.fillField(detected.passEl, this.pass);
            await this.sleep(600);

            const submitted = await this.tryAutoSubmit(doc, detected.passEl);
            if (submitted) {
              targetLog('fillIframe: 已在可读iframe内完成登录');
              return;
            }
          }

          // 尝试查找嵌套iframe
          const nestedFrames = Array.from(doc.querySelectorAll('iframe'));
          if (nestedFrames.length > 0) {
            targetLog('fillIframe: 发现嵌套iframe，展开搜索', { nestedCount: nestedFrames.length });
            for (const nested of nestedFrames) {
              try {
                const nestedDoc = nested.contentDocument;
                if (!nestedDoc) continue;

                const nestedDetected = this.findCredentialInputs(nestedDoc);
                if (nestedDetected.passEl) {
                  if (nestedDetected.userEl) {
                    this.fillField(nestedDetected.userEl, this.user);
                    await this.sleep(250);
                  }
                  this.fillField(nestedDetected.passEl, this.pass);
                  await this.sleep(600);
                  const submitted = await this.tryAutoSubmit(nestedDoc, nestedDetected.passEl);
                  if (submitted) {
                    targetLog('fillIframe: 已在嵌套iframe内完成登录');
                    return;
                  }
                }
              } catch (e) {
                targetLog('fillIframe: 嵌套iframe跨域或不可读', { error: e?.message });
              }
            }
          }
        } catch (error) {
          targetLog('fillIframe: iframe跨域或加载失败，准备广播消息', { error: error?.message });
        }
      }

      // 第二步：向所有iframe广播postMessage
      targetLog('fillIframe: 向iframe广播postMessage指令');
      candidateFrames.forEach((iframe, index) => {
        try {
          iframe.contentWindow.postMessage({
            type: 'TOPIAM_AUTO_FILL',
            username: this.user,
            password: this.pass,
            extra: this.extra,
            fullName: this.fullName || this.user
          }, '*');
          broadcastCount += 1;
          targetLog('fillIframe: 广播消息已发送', { frameIndex: index });
        } catch (e) {
          targetLog('fillIframe: 广播失败', { frameIndex: index, error: e?.message });
        }
      });

      // 第三步：等待iframe处理结果（等待最多35秒，包含iframe内的runFill完整流程）
      if (broadcastCount > 0) {
        targetLog('fillIframe: 等待iframe自处理', { broadcastCount });
        
        // 重置iframe结果状态，准备接收新的消息
        window._iframeLoginResultTemp = null;
        
        // 等待iframe传回结果（最多35秒）
        // iframe 内部会执行 SmartFiller.execute ~5-10秒 + waitForPageChange ~15秒 = 20-25秒
        // 加上网络延迟和处理时间，设置为35秒确保不会过早超时
        const startTime = Date.now();
        const MAX_WAIT_TIME = 35000; // 35秒
        let lastRebroadcastAt = Date.now();
        let lastRescanAt = Date.now();
        let rebroadcastCount = 0;
        const MAX_REBROADCAST = 3;
        
        while (Date.now() - startTime < MAX_WAIT_TIME) {
          if (window._iframeLoginResultTemp !== null) {
            targetLog('fillIframe: 收到iframe处理结果', { success: window._iframeLoginResultTemp });
            return;
          }

          const now = Date.now();

          // 慢页面容错1：周期性重发广播，避免iframe脚本晚加载错过首轮消息
          if (rebroadcastCount < MAX_REBROADCAST && now - lastRebroadcastAt >= 2000) {
            const currentFrames = collectLikelyLoginFrames(Array.from(document.querySelectorAll('iframe')));
            currentFrames.forEach((iframe) => {
              try {
                iframe.contentWindow.postMessage({
                  type: 'TOPIAM_AUTO_FILL',
                  username: this.user,
                  password: this.pass,
                  extra: this.extra,
                  fullName: this.fullName || this.user
                }, '*');
              } catch (e) {}
            });
            rebroadcastCount += 1;
            targetLog('fillIframe: 周期性重发广播', { frameCount: currentFrames.length, rebroadcastCount });
            lastRebroadcastAt = now;
          }

          // 慢页面容错2：周期性仅扫描可读iframe，避免递归触发tryFillInIframes导致广播雪崩
          if (now - lastRescanAt >= 2500) {
            let fallbackFilled = false;
            const readableFrames = Array.from(document.querySelectorAll('iframe'));
            for (const frame of readableFrames) {
              try {
                const doc = frame.contentDocument;
                if (!doc) continue;
                const detected = this.findCredentialInputs(doc);
                if (!detected.passEl) continue;

                if (detected.userEl) {
                  this.fillField(detected.userEl, this.user);
                  await this.sleep(250);
                }
                this.fillField(detected.passEl, this.pass);
                await this.sleep(600);
                const submitted = await this.tryAutoSubmit(doc, detected.passEl);
                if (submitted) {
                  fallbackFilled = true;
                  break;
                }
              } catch (e) {}
            }
            if (fallbackFilled) {
              targetLog('fillIframe: 周期性重扫命中输入框并完成提交');
              return;
            }
            lastRescanAt = now;
          }

          await this.sleep(300);
        }
        
        targetLog('fillIframe: 等待iframe结果超时（35秒），默认继续处理');
        return;
      }

      throw new Error('无法访问任何iframe，且postMessage广播失败');
    }

    async fillStandard() {
      assertNotNonStandardLoginSurface('fill_standard_start');

      let detected = this.findCredentialInputs(document);
      let userEl = detected.userEl;
      let passEl = detected.passEl;

      if (!passEl && !userEl) {
        for (let i = 0; i < 12; i++) {
          assertNotNonStandardLoginSurface('fill_standard_retry_loop');
          await this.sleep(350);
          detected = this.findCredentialInputs(document);
          userEl = detected.userEl;
          passEl = detected.passEl;
          if (passEl || userEl) {
            targetLog('fillStandard: 延迟检测后发现输入框', { attempt: i + 1 });
            break;
          }
        }
      }

      // 如果主文档找不到，尝试在iframe中找
      if (!passEl && !userEl) {
        targetLog('主文档未找到输入框，尝试在iframe中搜索');
        const iframeResult = await this.tryFillInIframes();
        if (iframeResult) {
          return;
        }
      }

      if (!passEl) {
        const twoStepDone = await this.tryTwoStepLogin(document, detected);
        if (twoStepDone) {
          return;
        }
      }

      if (!passEl) {
        throw new Error('未找到标准输入框');
      }

      if (userEl) {
        this.fillField(userEl, this.user);
        await this.sleep(250);
      }
      this.fillField(passEl, this.pass);
      await this.sleep(600);
      const submitted = await this.tryAutoSubmit(document, passEl);
      if (!submitted) {
        throw new Error('标准页面未找到可点击登录按钮');
      }
    }

    async tryFillInIframes() {
      const iframes = Array.from(document.querySelectorAll('iframe'));
      const candidateFrames = collectLikelyLoginFrames(iframes);
      
      targetLog('tryFillInIframes: 开始搜索iframe', { 
        totalIframes: iframes.length,
        candidateIframes: candidateFrames.length,
        location: window.location.href 
      });

      if (candidateFrames.length === 0) {
        targetLog('tryFillInIframes: 无疑似登录iframe，跳过广播');
        return false;
      }
      
      for (const iframe of candidateFrames) {
        try {
          const doc = iframe.contentDocument;
          if (!doc) {
            targetLog('iframe无法访问（可能跨域）', { 
              iframeSrc: iframe.src,
              iframeId: iframe.id 
            });
            continue;
          }

          targetLog('iframe已可访问，搜索输入框', { 
            iframeSrc: iframe.src,
            iframeId: iframe.id 
          });
          
          const detected = this.findCredentialInputs(doc);
          
          targetLog('iframe输入框搜索结果', {
            hasUser: Boolean(detected.userEl),
            hasPass: Boolean(detected.passEl),
            userName: detected.userEl?.getAttribute('name'),
            passName: detected.passEl?.getAttribute('name')
          });
          
          if (detected.passEl) {
            if (detected.userEl) {
              this.fillField(detected.userEl, this.user);
              await this.sleep(250);
            }
            this.fillField(detected.passEl, this.pass);
            await this.sleep(600);
            
            targetLog('iframe输入框已填充，尝试提交');
            const submitted = await this.tryAutoSubmit(doc, detected.passEl);
            if (submitted) {
              targetLog('iframe代填成功', { 
                iframeSrc: iframe.src,
                iframeId: iframe.id 
              });
              return true;
            } else {
              targetLog('iframe未找到提交按钮');
            }
          }
        } catch (error) {
          targetLog('iframe处理失败', { 
            error: error?.message,
            stack: error?.stack?.split('\n')[0] 
          });
        }
      }

      // 尝试通过postMessage处理跨域iframe
      targetLog('尝试通过postMessage向所有iframe广播代填指令');
      candidateFrames.forEach((iframe, idx) => {
        try {
          iframe.contentWindow.postMessage({
            type: 'TOPIAM_AUTO_FILL',
            username: this.user,
            password: this.pass,
            extra: this.extra,
            fullName: this.fullName || this.user
          }, '*');
          targetLog('postMessage已发送', { iframeIndex: idx });
        } catch (e) {
          targetLog('postMessage发送失败', { iframeIndex: idx, error: e?.message });
        }
      });

      await this.sleep(1200);
      return false;
    }

    hasCaptcha() {
      return !!document.querySelector('img[src*="captcha"], .g-recaptcha, .h-captcha, input[name*="captcha"], #captcha, [class*="captcha"]');
    }

    sleep(ms) {
      return new Promise((resolve) => setTimeout(resolve, ms));
    }
  }

  function showSubmitNotice(message = '✓ TopIAM 已自动填写并提交登录') {
    // 防重复消息：同一条消息在2秒内只显示一次
    window._topiamLastNotice = window._topiamLastNotice || { message: '', time: 0 };
    const now = Date.now();
    
    if (window._topiamLastNotice.message === message && now - window._topiamLastNotice.time < 2000) {
      targetLog('忽略重复消息（2秒内同一消息）', { message });
      return;
    }
    
    window._topiamLastNotice = { message, time: now };
    targetLog('💬 【显示通知】', { message, timestamp: now });
    
    // 保存到sessionStorage用于长期跟踪
    try {
      sessionStorage.setItem('topiam_login_message', JSON.stringify({
        message,
        timestamp: Date.now(),
        type: message.includes('成功') ? 'success' : message.includes('失败') ? 'error' : 'warning'
      }));
    } catch (e) {
      targetLog('sessionStorage保存失败', { error: e?.message });
    }

    const div = document.createElement('div');
    const bgColor = message.includes('成功') ? '#e6f7ff' : message.includes('失败') ? '#fff1f0' : '#fff2f0';
    const borderColor = message.includes('成功') ? '#91d5ff' : message.includes('失败') ? '#ffccc7' : '#ffccc7';
    const textColor = message.includes('成功') ? '#096dd9' : message.includes('失败') ? '#cf1322' : '#cf1322';
    
    div.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${bgColor};
      border: 1px solid ${borderColor};
      color: ${textColor};
      padding: 12px 24px;
      border-radius: 4px;
      z-index: 2147483647;
      font-family: system-ui;
      font-size: 14px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      min-width: 300px;
    `;
    div.textContent = message;
    document.body.appendChild(div);
    
    // 3.5秒后自动移除
    setTimeout(() => {
      try {
        div.remove();
      } catch (e) {}
    }, 3500);
  }

  // 页面加载时清理过期消息（不再重复显示）
  // 消息已通过showSubmitNotice的防重复逻辑处理，不需要cross-page传递
  function displayPendingMessage() {
    try {
      const pending = sessionStorage.getItem('topiam_login_message');
      if (pending) {
        // 消息超过5秒则删除（防止旧消息积累）
        const { message, timestamp } = JSON.parse(pending);
        if (Date.now() - timestamp >= 5000) {
          sessionStorage.removeItem('topiam_login_message');
          targetLog('清理过期消息', { message });
        }
        // 【注】不再从sessionStorage重新显示消息
        // 消息展示完全由showSubmitNotice的当前页面逻辑处理
        // 这样可以避免每次页面加载都重复显示相同消息
      }
    } catch (e) {
      targetLog('displayPendingMessage失败', { error: e?.message });
    }
  }

  function buildWatermarkDataUrl(username) {
    const canvas = document.createElement('canvas');
    canvas.width = TOPIAM_WATERMARK_SIZE;
    canvas.height = TOPIAM_WATERMARK_SIZE;
    const ctx = canvas.getContext('2d');
    if (!ctx) return '';

    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.translate(canvas.width / 2, canvas.height / 2);
    ctx.rotate((-22 * Math.PI) / 180);
    ctx.translate(-canvas.width / 2, -canvas.height / 2);

    const safeName = String(username || '').trim() || 'TopIAM User';
    ctx.font = '16px system-ui, -apple-system, Segoe UI, Roboto, sans-serif';
    ctx.fillStyle = 'rgba(15, 23, 42, 0.14)';
    ctx.textBaseline = 'middle';

    const lines = [safeName, `${safeName} · ${new Date().toLocaleDateString()}`];
    const positions = [
      { x: 28, y: 96 },
      { x: 150, y: 208 }
    ];

    for (let i = 0; i < positions.length; i++) {
      const text = lines[i % lines.length];
      const p = positions[i];
      ctx.fillText(text, p.x, p.y);
    }

    try {
      return canvas.toDataURL('image/png');
    } catch (error) {
      targetLog('生成水印base64失败', { error: error?.message });
      return '';
    }
  }

  function removeUserWatermark() {
    const selectors = [
      `.${TOPIAM_WATERMARK_CLASS}[data-topiam-user]`,
      `.${TOPIAM_WATERMARK_LEGACY_CLASS}[data-topiam-user]`,
      `.${TOPIAM_WATERMARK_CLASS}`,
      `.${TOPIAM_WATERMARK_LEGACY_CLASS}`
    ];
    const layers = selectors.flatMap((selector) => Array.from(document.querySelectorAll(selector)));
    layers.forEach((layer) => {
      try {
        layer.remove();
      } catch (error) {}
    });
    if (layers.length > 0) {
      targetLog('已移除插件用户水印层', { count: layers.length });
    }
    watermarkUsername = '';
  }

  function ensureWatermarkRepairLoop() {
    if (!IS_TOP_WINDOW || watermarkRepairTimer) return;
    watermarkRepairTimer = setInterval(() => {
      try {
        if (!watermarkUsername) return;
        if (isTopIamPlatformPage()) return;
        const layer = document.querySelector(`.${TOPIAM_WATERMARK_CLASS}[data-topiam-user]`);
        if (!layer) {
          ensureUserWatermark(watermarkUsername);
          targetLog('检测到水印层缺失，已自动补挂载', { username: watermarkUsername });
        }
      } catch (error) {}
    }, 2000);
  }

  function isTopIamPlatformPage() {
    const host = String(window.location.hostname || '').toLowerCase();
    const path = String(window.location.pathname || '').toLowerCase();
    const href = String(window.location.href || '').toLowerCase();
    const title = String(document.title || '').toLowerCase();

    if (/topiam/.test(host) || /topiam/.test(path) || /topiam/.test(href) || /topiam/.test(title)) {
      return true;
    }

    if (/^\/portal\/app(?:\/|$)/.test(path)
      || /^\/login(?:\/|$)/.test(path)
      || /^\/signin(?:\/|$)/.test(path)
      || /^\/oauth(?:\/|$)/.test(path)
      || /^\/cas(?:\/|$)/.test(path)
      || /^\/auth\/login(?:\/|$)/.test(path)
      || /\/api\/v1\/authorize\/form\//.test(path)
      || /\/api\/v1\/user\/app\/initiator\//.test(path)) {
      return true;
    }

    return Boolean(document.querySelector('[class*="topiam" i], [id*="topiam" i], script[src*="topiam" i], link[href*="topiam" i], meta[name*="topiam" i]'));
  }

  function ensureUserWatermark(username) {
    if (!IS_TOP_WINDOW) return;
    if (!isCurrentUrlWhitelistedByRealUrl()) {
      targetLog('跳过水印注入：当前URL不在realTargetUrl白名单', {
        href: window.location.href
      });
      removeUserWatermark();
      return;
    }
    const safeName = String(username || '').trim();
    if (!safeName) {
      removeUserWatermark();
      return;
    }

    const dataUrl = buildWatermarkDataUrl(safeName);
    if (!dataUrl) return;

    let layer = document.querySelector(`.${TOPIAM_WATERMARK_CLASS}`);
    if (!layer) {
      layer = document.createElement('div');
      layer.className = TOPIAM_WATERMARK_CLASS;
      layer.style.cssText = [
        'z-index:2147483646',
        'position:fixed',
        'left:0',
        'top:0',
        'width:100vw',
        'height:100vh',
        'pointer-events:none',
        'background-repeat:repeat',
        `background-size:${TOPIAM_WATERMARK_SIZE}px ${TOPIAM_WATERMARK_SIZE}px`
      ].join(';');
      (document.documentElement || document.body).appendChild(layer);
    }

    layer.style.backgroundImage = `url("${dataUrl}")`;
    layer.setAttribute('data-topiam-user', safeName);
    watermarkUsername = safeName;
    targetLog('已注入/更新用户水印', { username: safeName });
  }

  async function querySsoSessionState() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'queryLoginSession' });
      return {
        isValid: Boolean(response?.isValid),
        hadSession: Boolean(response?.hadSession),
        username: String(response?.username || ''),
        topiamUsername: String(response?.topiamUsername || ''),
        topiamFullName: String(response?.topiamFullName || ''),
        topiamAuthenticated: Boolean(response?.topiamAuthenticated),
        expiresAt: Number(response?.expiresAt || 0),
        timeLeftMs: Number(response?.timeLeftMs || 0)
      };
    } catch (error) {
      return { isValid: false, hadSession: false, username: '', topiamUsername: '', topiamFullName: '', topiamAuthenticated: false, expiresAt: 0, timeLeftMs: 0 };
    }
  }

  async function queryTopIamIdentity() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'getTopIamIdentity' });
      return {
        username: String(response?.username || '').trim(),
        fullName: String(response?.fullName || '').trim(),
        authenticated: Boolean(response?.authenticated)
      };
    } catch (error) {
      return { username: '', fullName: '', authenticated: false };
    }
  }

  function waitForPageChange(timeoutMs = 15000) {
    const originalUrl = window.location.href;
    const originalPathname = window.location.pathname;
    const originalHash = window.location.hash;
    let changeDetected = false;

    return new Promise((resolve) => {
      // 监听页面卸载事件（form.submit() 会触发这个）
      const handleBeforeUnload = () => {
        changeDetected = true;
        cleanup();
        targetLog('检测到页面即将卸载：beforeunload事件', { currentUrl: window.location.href });
        resolve(true);
      };

      const handleUnload = () => {
        if (!changeDetected) {
          changeDetected = true;
          cleanup();
          targetLog('检测到页面卸载：unload事件');
        }
      };

      // 监听URL变化事件
      const handleHashChange = () => {
        if (window.location.href !== originalUrl) {
          changeDetected = true;
          cleanup();
          targetLog('检测到页面跳转：hashchange事件触发', { from: originalUrl, to: window.location.href });
          resolve(true);
        }
      };

      const handlePopState = () => {
        if (window.location.href !== originalUrl) {
          changeDetected = true;
          cleanup();
          targetLog('检测到页面跳转：popstate事件触发', { from: originalUrl, to: window.location.href });
          resolve(true);
        }
      };

      // 定期检查URL和加载状态
      const checkInterval = setInterval(() => {
        if (changeDetected) return;

        // 1. URL完整路径改变（最可靠）
        if (window.location.href !== originalUrl) {
          changeDetected = true;
          cleanup();
          targetLog('检测到页面跳转：URL改变', { from: originalUrl, to: window.location.href });
          resolve(true);
          return;
        }

        // 2. pathname改变（真实路由导航）
        if (window.location.pathname !== originalPathname) {
          changeDetected = true;
          cleanup();
          targetLog('检测到页面跳转：pathname改变', { from: originalPathname, to: window.location.pathname });
          resolve(true);
          return;
        }

        // 3. hash改变（SPA单页应用）
        if (window.location.hash !== originalHash) {
          changeDetected = true;
          cleanup();
          targetLog('检测到页面跳转：hash改变', { from: originalHash, to: window.location.hash });
          resolve(true);
          return;
        }

        // 4. 页面从加载状态到interactive或complete（新页面加载完成）
        if (document.readyState === 'loading') {
          changeDetected = true;
          cleanup();
          targetLog('检测到页面重新加载：readyState=loading');
          resolve(true);
          return;
        }
      }, 300);

      // 超时处理
      const timeout = setTimeout(() => {
        if (!changeDetected) {
          cleanup();
          targetLog('页面跳转检测超时：未检测到URL改变、路由改变、页面重新加载或卸载，判定为失败', { timeoutMs });
          resolve(false);
        }
      }, timeoutMs);

      const cleanup = () => {
        clearInterval(checkInterval);
        clearTimeout(timeout);
        window.removeEventListener('beforeunload', handleBeforeUnload);
        window.removeEventListener('unload', handleUnload);
        window.removeEventListener('hashchange', handleHashChange);
        window.removeEventListener('popstate', handlePopState);
      };

      // 最关键：监听 beforeunload，这样 form.submit() 导致的页面卸载也能被检测到
      window.addEventListener('beforeunload', handleBeforeUnload);
      window.addEventListener('unload', handleUnload);
      window.addEventListener('hashchange', handleHashChange);
      window.addEventListener('popstate', handlePopState);
    });
  }

  function showManualHelper() {
    const div = document.createElement('div');
    div.id = 'topiam-helper';
    div.style.cssText = `
      position: fixed;
      bottom: 30px;
      right: 30px;
      background: white;
      border: 2px solid #ff4d4f;
      border-radius: 8px;
      padding: 16px;
      z-index: 2147483647;
      font-family: system-ui;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      min-width: 280px;
    `;
    div.innerHTML = `
      <div style="font-weight: bold; color: #ff4d4f; margin-bottom: 12px;">⚠️ 自动登录失败</div>
      <div style="font-size: 12px; color: #666; margin-bottom: 8px;">请手动复制账密登录</div>
      <div style="background: #fff2f0; padding: 8px; border-radius: 4px; margin-bottom: 8px; font-family: monospace; font-size: 12px;">账号信息已过期，请重新点击TopIAM应用</div>
      <button id="topiam-helper-close" style="width: 100%; background: #ff4d4f; color: white; border: none; padding: 8px; border-radius: 4px; cursor: pointer;">关闭</button>
    `;
    document.body.appendChild(div);
    const close = div.querySelector('#topiam-helper-close');
    if (close) {
      close.addEventListener('click', () => div.remove());
    }
  }

  function showRetryButton() {
    const btn = document.createElement('button');
    btn.textContent = 'TopIAM登录失败，点击刷新重试';
    btn.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: #1890ff;
      color: white;
      border: none;
      padding: 10px 20px;
      border-radius: 4px;
      cursor: pointer;
      z-index: 2147483647;
    `;
    btn.onclick = () => location.reload();
    document.body.appendChild(btn);
  }

  function normalizeRealUrlForWhitelist(urlLike) {
    try {
      const parsed = new URL(String(urlLike || '').trim());
      const protocol = String(parsed.protocol || '').toLowerCase();
      if (protocol !== 'http:' && protocol !== 'https:') return '';
      const path = String(parsed.pathname || '/').replace(/\/+$/, '') || '/';
      return `${parsed.origin}${path}`;
    } catch (error) {
      return '';
    }
  }

  function normalizeHostForWhitelist(urlLike) {
    try {
      const parsed = new URL(String(urlLike || '').trim());
      const protocol = String(parsed.protocol || '').toLowerCase();
      if (protocol !== 'http:' && protocol !== 'https:') return '';
      return String(parsed.hostname || '').toLowerCase();
    } catch (error) {
      return '';
    }
  }

  function isCurrentUrlWhitelistedByRealUrl() {
    const currentNormalized = normalizeRealUrlForWhitelist(window.location.href);
    const currentHost = normalizeHostForWhitelist(window.location.href);
    if (!currentNormalized && !currentHost) return false;

    const matchedUrlEntries = currentNormalized
      ? (watermarkWhitelistUrlMap.get(currentNormalized) || [])
      : [];
    if (matchedUrlEntries.length > 0) {
      targetLog('水印白名单命中(realTargetUrl)', {
        matchType: 'url_exact',
        currentNormalized,
        currentHost,
        matchedCount: matchedUrlEntries.length,
        matchedEntries: matchedUrlEntries.slice(0, 3)
      });
      return true;
    }

    const matchedHostEntries = currentHost
      ? (watermarkWhitelistHostMap.get(currentHost) || [])
      : [];
    if (matchedHostEntries.length > 0) {
      targetLog('水印白名单命中(realTargetUrl)', {
        matchType: 'host_fallback',
        currentNormalized,
        currentHost,
        matchedCount: matchedHostEntries.length,
        matchedEntries: matchedHostEntries.slice(0, 3)
      });
      return true;
    }

    targetLog('水印白名单未命中(realTargetUrl)', {
      currentNormalized,
      currentHost,
      whitelistUrlSize: watermarkWhitelistUrlMap.size,
      whitelistHostSize: watermarkWhitelistHostMap.size
    });
    return false;
  }

  function rebuildWatermarkWhitelist(discoveredApps) {
    const list = Array.isArray(discoveredApps) ? discoveredApps : [];
    const nextUrlMap = new Map();
    const nextHostMap = new Map();

    list.forEach((app) => {
      const rawRealTargetUrl = String(app?.realTargetUrl || '').trim();
      const normalized = normalizeRealUrlForWhitelist(rawRealTargetUrl);
      const host = normalizeHostForWhitelist(rawRealTargetUrl);
      if (!normalized && !host) return;

      const entry = {
        appId: String(app?.appId || '').trim(),
        name: String(app?.name || '').trim(),
        realTargetUrl: rawRealTargetUrl || normalized || ''
      };

      if (normalized) {
        const urlEntries = nextUrlMap.get(normalized) || [];
        urlEntries.push(entry);
        nextUrlMap.set(normalized, urlEntries);
      }

      if (host) {
        const hostEntries = nextHostMap.get(host) || [];
        hostEntries.push(entry);
        nextHostMap.set(host, hostEntries);
      }
    });

    watermarkWhitelistUrlMap = nextUrlMap;
    watermarkWhitelistHostMap = nextHostMap;

    const samples = Array.from(watermarkWhitelistUrlMap.entries())
      .slice(0, 3)
      .map(([normalized, entries]) => ({
        normalized,
        appId: String(entries?.[0]?.appId || ''),
        name: String(entries?.[0]?.name || ''),
        realTargetUrl: String(entries?.[0]?.realTargetUrl || normalized)
      }));

    const hostSamples = Array.from(watermarkWhitelistHostMap.entries())
      .slice(0, 3)
      .map(([host, entries]) => ({
        host,
        appId: String(entries?.[0]?.appId || ''),
        name: String(entries?.[0]?.name || ''),
        realTargetUrl: String(entries?.[0]?.realTargetUrl || '')
      }));

    targetLog('已更新水印白名单(realTargetUrl)', {
      size: watermarkWhitelistUrlMap.size,
      hostSize: watermarkWhitelistHostMap.size,
      sample: samples,
      hostSample: hostSamples
    });
  }

  function loadWatermarkWhitelist() {
    chrome.storage.local.get([DISCOVERED_APPS_STORAGE_KEY], (result) => {
      const apps = Array.isArray(result?.[DISCOVERED_APPS_STORAGE_KEY])
        ? result[DISCOVERED_APPS_STORAGE_KEY]
        : [];
      rebuildWatermarkWhitelist(apps);
    });
  }

  function watchWatermarkWhitelist() {
    if (window.__topiamWatermarkWhitelistWatchBound) return;
    window.__topiamWatermarkWhitelistWatchBound = true;

    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== 'local') return;
      if (!Object.prototype.hasOwnProperty.call(changes, DISCOVERED_APPS_STORAGE_KEY)) return;
      const nextApps = Array.isArray(changes[DISCOVERED_APPS_STORAGE_KEY]?.newValue)
        ? changes[DISCOVERED_APPS_STORAGE_KEY].newValue
        : [];
      rebuildWatermarkWhitelist(nextApps);
    });
  }

  async function enforceAccessPolicy(hasTask) {
    try {
      const policy = await chrome.runtime.sendMessage({
        action: 'checkAccessPolicy',
        url: location.href,
        hasTask
      });

      if (!policy || policy.allowed) return true;
      
      // 根据拒绝原因显示不同的提示
      blockDirectLogin(policy.reason);
      return false;
    } catch (error) {
      return true;
    }
  }

  function blockDirectLogin(reason = 'sso_required') {
    const blocker = (event) => {
      const target = event.target;
      const isFormSubmit = target instanceof HTMLFormElement;
      const isLoginButton = target instanceof HTMLElement && target.matches('button[type="submit"], input[type="submit"], .login-btn, [class*="login"]');
      if (!isFormSubmit && !isLoginButton) return;

      event.preventDefault();
      event.stopImmediatePropagation();
      showAccessDeniedNotice(reason);
    };

    document.addEventListener('submit', blocker, true);
    document.addEventListener('click', blocker, true);
    showAccessDeniedNotice(reason);
  }

  function showAccessDeniedNotice(reason = 'sso_required') {
    // 根据原因显示不同的提示
    const messages = {
      'sso_required': '此应用受SSO保护，请返回TopIAM重新点击应用入口进行登录。',
      'session_expired': '您的SSO会话已过期，请返回TopIAM重新点击应用入口进行登录。'
    };
    
    const message = messages[reason] || messages['sso_required'];
    showSsoRequiredNotice(message);
  }

  function showSsoRequiredNotice(message = null) {
    if (document.getElementById('topiam-sso-required')) return;

    const defaultMessage = message || '此应用受SSO保护，请返回TopIAM重新点击应用入口进行登录。';
    
    const div = document.createElement('div');
    div.id = 'topiam-sso-required';
    div.style.cssText = `
      position: fixed;
      right: 20px;
      bottom: 20px;
      z-index: 2147483647;
      background: #fff2f0;
      color: #cf1322;
      border: 1px solid #ffccc7;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.12);
      padding: 12px 14px;
      font-size: 12px;
      font-family: system-ui;
      max-width: 320px;
      line-height: 1.5;
    `;
    div.textContent = defaultMessage;
    document.body.appendChild(div);
  }

  function hasLikelyLoginSurface() {
    if (isLikelyLoginContext()) return true;
    const likelyFrames = collectLikelyLoginFrames(Array.from(document.querySelectorAll('iframe')));
    if (likelyFrames.length > 0) return true;
    return false;
  }

  function hasLikelyLoggedInSurface() {
    if (hasLikelyLoginSurface()) return false;

    if (isLikelyPostLoginPath()) return true;

    const selectors = [
      '[class*="user" i]',
      '[class*="avatar" i]',
      '[class*="profile" i]',
      '[class*="logout" i]',
      '[id*="logout" i]',
      '[data-user-name]',
      '[data-username]'
    ];
    const hasUiMarker = selectors.some((selector) => {
      try {
        return Boolean(document.querySelector(selector));
      } catch {
        return false;
      }
    });

    const bodyText = String(document.body?.innerText || '').slice(0, 5000).toLowerCase();
    const hasTextMarker = /退出|注销|logout|sign\s*out|欢迎|welcome|个人中心|用户中心|我的账号/.test(bodyText);

    return hasUiMarker || hasTextMarker;
  }

  function isLikelyPostLoginPath() {
    const pathname = String(window.location.pathname || '').toLowerCase();
    const search = String(window.location.search || '').toLowerCase();
    const hash = String(window.location.hash || '').toLowerCase();
    const combined = `${pathname} ${search} ${hash}`;
    const normalizedPath = pathname.replace(/\/+$/, '') || '/';

    const loginKeywords = /login|signin|sign-in|auth|oauth|cas|passport|账户登录|扫码登录/;
    if (loginKeywords.test(combined)) return false;

    const exactPostLoginPaths = new Set([
      '/',
      '/dashboard',
      '/home',
      '/index',
      '/index.html',
      '/main',
      '/mainmenu',
      '/menu',
      '/app',
      '/portal',
      '/portal/main',
      '/console',
      '/workbench',
      '/desktop',
      '/overview'
    ]);

    if (exactPostLoginPaths.has(normalizedPath)) {
      return true;
    }

    const prefixPostLoginPatterns = [
      /^\/dashboard(?:\/|$)/,
      /^\/menu(?:\/|$)/,
      /^\/app(?:\/|$)/,
      /^\/home(?:\/|$)/,
      /^\/main(?:\/|$)/,
      /^\/portal(?:\/|$)/,
      /^\/console(?:\/|$)/,
      /^\/workbench(?:\/|$)/,
      /^\/desktop(?:\/|$)/,
      /^\/overview(?:\/|$)/
    ];
    if (prefixPostLoginPatterns.some((rule) => rule.test(normalizedPath))) {
      return true;
    }

    const postLoginKeywords = /mainmenu|dashboard|console|home|index|portal\/main|workbench|desktop|overview|welcome|url_name=mainmenu|url_name=menu|url_name=app/;
    if (postLoginKeywords.test(combined)) {
      return true;
    }

    const hasMenuLikeUi = Boolean(safeQuerySelector(
      '[class*="menu" i], [class*="sidebar" i], [class*="nav" i], [class*="header" i], [id*="menu" i], [id*="nav" i]'
    ));
    const hasPasswordField = Boolean(safeQuerySelector('input[type="password"], input[name*="pass" i], input[id*="pass" i]'));

    if (normalizedPath === '/' && !hasPasswordField) {
      const rootHints = /dashboard|mainmenu|menu|app|console|home|workbench|desktop|overview|welcome/;
      if (rootHints.test(`${search} ${hash}`) || hasMenuLikeUi) {
        return true;
      }
    }

    return hasMenuLikeUi && !hasPasswordField;
  }

  async function shouldSkipAutofillAsAlreadyLoggedIn(options = {}) {
    if (!IS_TOP_WINDOW) return false;
    if (options?.hasTask) {
      const start = Date.now();
      const maxWaitMs = 1200;
      while (Date.now() - start < maxWaitMs) {
        if (hasLikelyLoginSurface()) return false;
        if (isLikelyPostLoginPath()) {
          targetLog('当前存在有效taskId，命中登录后路径特征，跳过代填', {
            waitedMs: Date.now() - start,
            href: window.location.href
          });
          return true;
        }
        if (hasLikelyLoggedInSurface()) {
          targetLog('当前存在有效taskId，但已命中登录后界面特征，跳过代填', {
            waitedMs: Date.now() - start,
            href: window.location.href
          });
          return true;
        }
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
      return false;
    }

    const pathLike = `${String(window.location.pathname || '').toLowerCase()} ${String(window.location.search || '').toLowerCase()} ${String(window.location.hash || '').toLowerCase()}`;
    if (/login|signin|sign-in|auth|oauth|cas|passport|\/sso(?:\/|$)/.test(pathLike)) {
      return false;
    }

    if (hasLikelyLoginSurface()) {
      return false;
    }

    const probeStart = Date.now();
    const MAX_PROBE_MS = 1200;
    const INTERVAL_MS = 250;
    while (Date.now() - probeStart < MAX_PROBE_MS) {
      await new Promise((resolve) => setTimeout(resolve, INTERVAL_MS));
      if (hasLikelyLoginSurface()) {
        targetLog('已探测到登录界面特征，不跳过代填', {
          waitedMs: Date.now() - probeStart
        });
        return false;
      }
    }

    targetLog('短探测结束，未发现登录界面特征，判定为已登录态', {
      waitedMs: Date.now() - probeStart,
      href: window.location.href
    });
    return hasLikelyLoggedInSurface();
  }

  async function startSessionAfterLogin(taskId, username, source = 'autofill_success') {
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'startLoginSession',
        username,
        taskId
      });
      if (response?.success) {
        targetLog('✓✓✓ 【会话启动成功】SSO会话已创建，应用存活已绑定SSO状态', {
          username: response?.topiamUsername || username,
          source
        });
        synchronizeSsoState(`session_started_${source}`).catch(() => {});
      } else {
        targetLog('⚠️  会话启动返回失败响应', { error: response?.error, source });
      }
    } catch (e) {
      targetLog('⚠️  会话启动异常', { error: e?.message, source });
    }
  }

  async function executeSessionExpirationFlow(trigger = 'background_push') {
    if (isSessionExpiring) {
      targetLog('⚠️  已在会话过期过程中，忽略重复触发', { trigger });
      return false;
    }
    isSessionExpiring = true;

    targetLog('🔴 【会话过期】触发强制注销流程', { trigger });

    performIntelligentFillExecuting = false;
    targetLog('【会话过期】已重置执行标记，取消待执行的代填');

    targetLog('【会话过期】清除URL中的taskId标记');
    cleanTaskMarkerFromUrl();

    try {
      chrome.runtime.sendMessage({ action: 'clearPendingTask' }, (response) => {
        if (chrome.runtime.lastError) {
          targetLog('通知background清除taskId失败', { error: chrome.runtime.lastError.message });
          return;
        }
        if (response?.success) {
          targetLog('✓ 已通知background清除taskId');
        }
      });
    } catch (e) {
      targetLog('通知background清除taskId失败', { error: e?.message });
    }

    try {
      const sessionClearResponse = await chrome.runtime.sendMessage({
        action: 'clearCurrentTabSession',
        reason: 'session_expired'
      });
      targetLog('已通知background清除当前标签页会话', sessionClearResponse || {});
    } catch (error) {
      targetLog('通知background清除当前标签页会话失败', { error: error?.message || String(error) });
    }

    try {
      const cookieResult = await chrome.runtime.sendMessage({
        action: 'clearSiteCookies',
        origin: window.location.origin,
        reason: `session_expired_${String(trigger || 'unknown')}`
      });
      targetLog('会话过期后台cookie清理结果', cookieResult || {});
    } catch (error) {
      targetLog('会话过期后台cookie清理异常', { error: error?.message || String(error) });
    }

    const cookiesToClear = [];
    document.cookie.split(';').forEach((cookie) => {
      const name = cookie.split('=')[0].trim();
      if (/session|token|auth|sid|jsessionid|phpsessid|remember/i.test(name)) {
        document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/;`;
        cookiesToClear.push(name);
      }
    });
    if (cookiesToClear.length > 0) {
      targetLog('已清除cookies', { names: cookiesToClear });
    }

    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && /token|auth|session|user|login/i.test(key)) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach((key) => localStorage.removeItem(key));
    if (keysToRemove.length > 0) {
      targetLog('已清除localStorage');
    }

    const sessionKeysToRemove = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && (/token|auth|session|user|login/i.test(key) || key === 'topiam_login_message')) {
        sessionKeysToRemove.push(key);
      }
    }
    sessionKeysToRemove.forEach((key) => sessionStorage.removeItem(key));
    if (sessionKeysToRemove.length > 0) {
      targetLog('已清除sessionStorage');
    }

    removeUserWatermark();
    showSubmitNotice('⚠ SSO会话已过期，请重新登录');

    setTimeout(() => {
      const loginUrl = resolveSessionExpiredLoginUrl();
      if (loginUrl) {
        targetLog('🔄 【会话过期】即将跳转登录页...', { loginUrl });
        window.location.replace(loginUrl);
      } else {
        targetLog('🔄 【会话过期】未识别到登录页，回退为页面重载');
        window.location.reload();
      }
    }, 1500);

    targetLog('✓ 【会话过期】强制注销流程已完成，等待页面重新加载');
    return true;
  }

  async function isManagedWatermarkContext() {
    if (isTopIamPlatformPage()) return false;
    const whitelisted = isCurrentUrlWhitelistedByRealUrl();
    targetLog('水印上下文判定结果', {
      href: window.location.href,
      whitelisted
    });
    return whitelisted;
  }

  async function synchronizeSsoState(source = 'poll') {
    if (!IS_TOP_WINDOW) return;

    if (isTopIamPlatformPage()) {
      return;
    }

    const managedContext = await isManagedWatermarkContext();
    if (!managedContext) {
      removeUserWatermark();
      return;
    }

    const loginContext = isLikelyLoginContext();
    const state = await querySsoSessionState();
    const platformUser = String(state.topiamFullName || state.topiamUsername || state.username || '').trim();

    if (loginContext) {
      let loginPageUser = String(platformUser || watermarkUsername || '').trim();
      if (!loginPageUser) {
        const identity = await queryTopIamIdentity();
        loginPageUser = String(identity.fullName || identity.username || '').trim();
      }

      if (loginPageUser) {
        if (watermarkUsername !== loginPageUser) {
          ensureUserWatermark(loginPageUser);
        }
        return;
      }
    }

    if (state.isValid && platformUser) {
      if (watermarkUsername !== platformUser) {
        ensureUserWatermark(platformUser);
      }
      return;
    }

    removeUserWatermark();

    if (state.hadSession && !state.isValid && !isSessionExpiring) {
      await executeSessionExpirationFlow(`state_sync_${source}`);
      return;
    }

    if (!state.topiamAuthenticated && !isSessionExpiring) {
      try {
        const policy = await chrome.runtime.sendMessage({
          action: 'checkAccessPolicy',
          url: location.href,
          hasTask: false
        });
        if (policy && policy.allowed === false && policy.reason === 'session_expired') {
          targetLog('命中访问策略 session_expired，触发会话过期流程', {
            source,
            href: location.href
          });
          await executeSessionExpirationFlow(`policy_${source}`);
        }
      } catch (error) {
        targetLog('会话过期策略兜底检查失败', { error: error?.message || String(error) });
      }
    }
  }

  function startSsoStateSync() {
    if (!IS_TOP_WINDOW || ssoStateSyncTimer) return;

    ensureWatermarkRepairLoop();
    synchronizeSsoState('bootstrap').catch(() => {});
    ssoStateSyncTimer = setInterval(() => {
      synchronizeSsoState('interval').catch(() => {});
    }, SSO_STATE_SYNC_INTERVAL_MS);

    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        synchronizeSsoState('visibility').catch(() => {});
      }
    });
    window.addEventListener('focus', () => {
      synchronizeSsoState('focus').catch(() => {});
    });
  }

  // 临时变量用于iframe处理通信
  window._iframeLoginResultTemp = null;

  window.addEventListener('message', (event) => {
    const data = event?.data || {};
    if (data.type !== 'TOPIAM_AUTO_FILL_ACK') return;
    
    const success = Boolean(data.ok);
    targetLog('收到iframe代填回执', {
      ok: success,
      reason: data.reason || ''
    });
    
    // 记录iframe的代填结果，这样runFill可以读取
    window._iframeLoginResultTemp = success;
    targetLog('设置iframe代填结果到全局变量', { result: success });
  });

  function schedulePostSubmitRetry(auth, strategy) {
    const maxRetries = 1;
    const originalUrl = window.location.href;
    
    setTimeout(async () => {
      // 检查是否页面已经跳转了
      if (window.location.href !== originalUrl) {
        targetLog('页面已成功跳转，登录完成');
        showSubmitNotice('✓ TopIAM 已成功登录并跳转');
        return;
      }

      const passwordEl = document.querySelector('input[type="password"]');
      const hasPasswordField = Boolean(passwordEl);
      const passwordEmpty = hasPasswordField ? !String(passwordEl.value || '').trim() : false;
      const loginForm = document.querySelector('form[action*="login"], form[action*="signin"], form[action*="auth"]');
      const stillOnLoginPage = Boolean(loginForm) || hasPasswordField;

      targetLog('提交后状态检查', {
        urlChanged: window.location.href !== originalUrl,
        hasPasswordField,
        passwordEmpty,
        stillOnLoginPage,
        href: location.href
      });

      if (!stillOnLoginPage || !passwordEmpty) {
        targetLog('登录后页面状态正常（已离开登录页或密码字段已清空）');
        return;
      }

      const currentRetry = readRetryCount();
      if (currentRetry >= maxRetries) {
        targetLog('检测到登录页回退，但已达到自动重试上限');
        return;
      }

      writeRetryCount(currentRetry + 1);
      targetLog('检测到登录页回退且密码为空，触发自动重试', { retry: currentRetry + 1 });

      try {
        const filler = new SmartFiller(auth.username, auth.password, auth.extra, auth.fullName || '');
        await filler.execute(strategy);
      } catch (error) {
        targetError('自动重试代填失败', error);
      }
    }, 2500);
  }

  async function runFill(auth) {
    if (!auth?.username || !auth?.password) {
      targetError('缺少可用账密，无法执行代填');
      return false;
    }

    const startUrl = window.location.href;
    
    targetLog('【runFill 开始】', { 
      username: auth.username,
      hasExtra: Boolean(auth.extra && Object.keys(auth.extra).length > 0),
      isTopWindow: IS_TOP_WINDOW,
      href: window.location.href
    });

    await waitForLoginSurface(1000, 120);
    
    const strategy = detectStrategy();
    targetLog('检测到代填策略', { strategy });
    
    const filler = new SmartFiller(auth.username, auth.password, auth.extra || {}, auth.fullName || '');
    
    // 创建一个标志，用于检测页面是否被卸载
    let pageAboutToUnload = false;
    const handleBeforeUnload = () => {
      pageAboutToUnload = true;
      targetLog('检测到页面即将卸载，标记页面改变状态');
      
      // 如果当前执行的是iframe策略，页面卸载说明iframe内的登录成功了
      // 立即设置iframe结果为true，不必等待ACK消息
      if (strategy === 'iframe' && window._iframeLoginResultTemp === null) {
        targetLog('iframe策略下检测到页面卸载，推断为iframe登录成功，立即设置结果');
        window._iframeLoginResultTemp = true;
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload, { once: true });
    
    try {
      await filler.execute(strategy);
      targetLog('代填执行完成，开始等待页面跳转验证', { strategy });
    } catch (error) {
      targetError('代填执行失败', { 
        strategy,
        error: error?.message,
        stack: error?.stack?.split('\n')[0]
      });
      window.removeEventListener('beforeunload', handleBeforeUnload);
      throw error;
    }
    
    window.removeEventListener('beforeunload', handleBeforeUnload);

    if (!filler.didFillPassword) {
      targetLog('严格模式告警：未检测到密码字段被成功填充，尝试按可能成功继续', {
        strategy,
        href: window.location.href
      });
    }

    if (!filler.didSubmit) {
      try {
        const passEl = document.querySelector('input[type="password"], input[name*="pass" i], input[id*="pass" i]');
        const form = passEl?.form || null;
        if (form && typeof form.requestSubmit === 'function') {
          form.requestSubmit();
          filler.didSubmit = true;
        } else if (form) {
          form.submit();
          filler.didSubmit = true;
        }
      } catch (error) {}

      if (!filler.didSubmit) {
        targetLog('严格模式告警：未检测到有效提交动作，按可能自动登录继续', {
          strategy,
          href: window.location.href
        });
      }
    }

    const pageChanged = pageAboutToUnload
      || window.location.href !== startUrl
      || window._iframeLoginResultTemp === true
      || await waitForPageChange(4000);

    let postHasPasswordField = false;
    let postPasswordValueEmpty = true;
    let postHasSubmitControl = false;
    try {
      const passwordEl = document.querySelector('input[type="password"], input[name*="pass" i], input[id*="pass" i]');
      postHasPasswordField = Boolean(passwordEl);
      postPasswordValueEmpty = passwordEl ? !String(passwordEl.value || '').trim() : true;
      postHasSubmitControl = Boolean(document.querySelector('button[type="submit"], input[type="submit"], button, [role="button"]'));
    } catch (error) {}

    const stillStrongLoginSurface = postHasPasswordField && postHasSubmitControl;
    const acceptedByPostSignals = !postHasPasswordField || postPasswordValueEmpty;

    const strongFailureSignal = !pageChanged && stillStrongLoginSurface && !acceptedByPostSignals;
    if (strongFailureSignal) {
      targetLog('严格模式告警：提交后仍像登录页，但为避免误判先按成功处理', {
        strategy,
        didFillPassword: filler.didFillPassword,
        didSubmit: filler.didSubmit,
        postHasPasswordField,
        postPasswordValueEmpty,
        postHasSubmitControl,
        href: window.location.href
      });
    }

    let stabilizedLoggedInSurface = false;
    let stabilizedLoginSurface = hasLikelyLoginSurface();
    const probeStart = Date.now();
    const PROBE_WINDOW_MS = 2600;
    while (Date.now() - probeStart < PROBE_WINDOW_MS) {
      if (window.location.href !== startUrl || window._iframeLoginResultTemp === true) {
        stabilizedLoggedInSurface = true;
        break;
      }

      const nowLoggedIn = hasLikelyLoggedInSurface();
      const nowLoginSurface = hasLikelyLoginSurface();
      if (nowLoggedIn) {
        stabilizedLoggedInSurface = true;
        stabilizedLoginSurface = false;
        break;
      }

      stabilizedLoginSurface = nowLoginSurface;
      await new Promise((resolve) => setTimeout(resolve, 260));
    }

    const loginConfirmed = pageChanged
      || stabilizedLoggedInSurface
      || (filler.didSubmit && !stabilizedLoginSurface && acceptedByPostSignals);

    const postLoginPathConfirmed = isLikelyPostLoginPath();
    const finalLoginConfirmed = loginConfirmed || postLoginPathConfirmed;

    if (!finalLoginConfirmed) {
      targetLog('登录成功判定未通过：提交后仍缺少明确成功信号', {
        pageChanged,
        stabilizedLoggedInSurface,
        stabilizedLoginSurface,
        postLoginPathConfirmed,
        didFillPassword: filler.didFillPassword,
        didSubmit: filler.didSubmit,
        postHasPasswordField,
        postPasswordValueEmpty,
        postHasSubmitControl,
        href: window.location.href
      });
      return false;
    }

    targetLog('代填流程已通过严格校验', {
      pageChanged,
      loginConfirmed: finalLoginConfirmed,
      stabilizedLoggedInSurface,
      stabilizedLoginSurface,
      postLoginPathConfirmed,
      strategy,
      didFillPassword: filler.didFillPassword,
      didSubmit: filler.didSubmit,
      postHasPasswordField,
      postPasswordValueEmpty,
      postHasSubmitControl
    });
    showSubmitNotice('✓ TopIAM 已检测到登录成功');
    return true;
  }

  async function performIntelligentFill(taskId) {
    try {
      try {
        // 第一时间显示日志，确认函数被调用
        targetLog('【代填开始】performIntelligentFill 执行中...', { 
          taskId,
          isTopWindow: IS_TOP_WINDOW,
          href: window.location.href
        });
        
        const auth = await chrome.runtime.sendMessage({ action: 'getCredentials', taskId });
        if (!auth?.success) {
          targetError('获取凭据失败', { 
            error: auth?.error || 'unknown',
            taskId
          });
          showSubmitNotice('❌ 无法获取登录凭据，请重新点击应用');
          showManualHelper();
          return;
        }

        targetLog('已获取凭据，开始代填', { 
          username: auth.username,
          taskId
        });

        if (!isTopIamPlatformPage()) {
          ensureUserWatermark(auth.fullName || auth.username);
          targetLog('已在代填开始阶段注入用户水印', {
            username: auth.username,
            fullName: auth.fullName,
            taskId
          });
        }

        applyForceRefreshRules(auth.extra || {});

        const skipAutofill = await shouldSkipAutofillAsAlreadyLoggedIn({ hasTask: Boolean(taskId) });
        if (skipAutofill) {
          targetLog('检测到应用已处于登录态，跳过自动代填', {
            href: window.location.href,
            username: auth.username
          });
          if (taskId) {
            showSubmitNotice('✓ TopIAM 代填流程已完成登录');
            await startSessionAfterLogin(taskId, auth.username, 'task_flow_logged_in');
          } else {
            showSubmitNotice('✓ 检测到应用已登录，跳过自动代填');
            await startSessionAfterLogin(taskId, auth.username, 'already_logged_in_skip');
          }
          return;
        }

        if (shouldForceRefreshCurrentPath()) {
          const resetTriggeredByRule = await forceResetAppStateAndRetry(taskId, 'force_refresh_path_rule');
          if (resetTriggeredByRule) {
            return;
          }
        }

        const fastNonStandard = await shouldFastResetForNonStandardLogin();
        if (fastNonStandard) {
          const resetTriggered = await forceResetAppStateAndRetry(taskId, 'fast_non_standard_detect');
          if (resetTriggered) {
            return;
          }
        }

        const loginSuccess = await runFill(auth);
        
        if (loginSuccess) {
          targetLog('✓ 代填和登录验证全流程完成，用户已成功登录');
          await startSessionAfterLogin(taskId, auth.username, 'autofill_success');
          if (!isTopIamPlatformPage()) {
            ensureUserWatermark(auth.fullName || auth.username);
          }
        } else {
          targetLog('代填流程完成但登录验证未通过，可能需要额外操作');
        }
      } catch (error) {
        targetError('代填整体异常', { 
          error: error?.message,
          stack: error?.stack?.split('\n')[0]
        });

        const errorMessage = String(error?.message || '');
        const canTryForcedReset = /未找到标准输入框|标准页面未找到可点击登录按钮|NON_STANDARD_LOGIN_SURFACE/i.test(errorMessage);
        if (canTryForcedReset) {
          const resetTriggered = await forceResetAppStateAndRetry(taskId, 'non_standard_login_surface');
          if (resetTriggered) {
            return;
          }
        }

        if (hasLikelyLoggedInSurface()) {
          targetLog('捕获异常但页面呈现已登录特征，按成功处理', {
            error: errorMessage,
            href: window.location.href
          });
          if (taskId) {
            showSubmitNotice('✓ TopIAM 代填流程已完成登录');
            await startSessionAfterLogin(taskId, auth?.username || '', 'task_flow_error_but_logged_in');
          } else {
            showSubmitNotice('✓ 检测到应用已登录，跳过失败提示');
            await startSessionAfterLogin(taskId, auth?.username || '', 'error_but_logged_in');
          }
          return;
        }

        showSubmitNotice('❌ 自动登录失败，请手动操作');
        showRetryButton();
      }
    } finally {
      // 重置执行标记，允许后续继续执行（如果需要）
      performIntelligentFillExecuting = false;
      targetLog('performIntelligentFill执行标记已重置');
    }
  }

  // 用于标记iframe是否已经向parent发送过ACK
  window._iframeAckSent = false;
  let iframeMessageHandling = false;
  let iframeLastMessageDigest = '';
  let iframeLastMessageAt = 0;

  function sendIframeAckToParent(success, reason) {
    if (window._iframeAckSent) {
      targetLog('iframe ACK已发送过，避免重复发送', { success, reason });
      return;
    }
    
    window._iframeAckSent = true;
    
    // 如果当前已经在卸载过程中，给予一点时间让postMessage送出
    // beforeunload事件中的postMessage仍然可以被发送
    const sendNow = () => {
      try {
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ 
            type: 'TOPIAM_AUTO_FILL_ACK', 
            ok: success, 
            reason
          }, '*');
          targetLog('iframe成功发送ACK给parent', { success, reason });
        }
      } catch (e) {
        targetLog('iframe发送ACK失败', { error: e?.message });
      }
    };
    
    // 立即发送
    sendNow();
    
    // 再在unload时尝试发送一次，确保消息能到达
    window.addEventListener('unload', sendNow, { once: true });
  }

  window.addEventListener('message', async (event) => {
    const data = event?.data;
    if (!data || data.type !== 'TOPIAM_AUTO_FILL') return;

    if (IS_TOP_WINDOW) {
      return;
    }

    if (!isLikelyLoginContext()) {
      targetLog('忽略iframe代填消息：当前非登录上下文', { href: window.location.href });
      return;
    }

    const digest = `${String(data.username || '')}|${Boolean(data.password)}`;
    const now = Date.now();
    if (iframeMessageHandling) {
      targetLog('忽略重复iframe代填消息：当前仍在处理中', { href: window.location.href });
      return;
    }
    if (digest === iframeLastMessageDigest && now - iframeLastMessageAt < 2500) {
      targetLog('忽略短时间重复iframe代填消息', { href: window.location.href });
      return;
    }
    iframeLastMessageDigest = digest;
    iframeLastMessageAt = now;
    iframeMessageHandling = true;
    window._iframeAckSent = false;

    targetLog('收到父页面下发的iframe代填消息', {
      isTop: IS_TOP_WINDOW,
      hasUsername: Boolean(data.username),
      hasPassword: Boolean(data.password)
    });

    // 在iframe内，监听自己的beforeunload，确保登录成功导致的卸载能被及时通知
    let iframeUnloadDetected = false;
    const handleIframeUnload = () => {
      if (!iframeUnloadDetected) {
        iframeUnloadDetected = true;
        targetLog('【iframe内部】检测到本iframe即将卸载，推断登录成功');
        // 立即向parent发送成功信号
        sendIframeAckToParent(true, 'iframe_unload_detected');
      }
    };
    window.addEventListener('beforeunload', handleIframeUnload, { once: true });

    try {
      // 慢页面下登录控件可能晚于消息到达，不强依赖登录上下文判断，直接进入runFill
      // runFill内部已有 waitForLoginSurface 兜底等待

      const loginSuccess = await runFill({
        username: data.username || '',
        password: data.password || '',
        extra: data.extra || {},
        fullName: data.fullName || data.username || ''
      });
      
      window.removeEventListener('beforeunload', handleIframeUnload);
      
      targetLog('iframe代填完成，发送回执', { loginSuccess, fullName: String(data.fullName || '') });
      sendIframeAckToParent(loginSuccess, loginSuccess ? 'page_changed' : 'page_not_changed');
      
    } catch (error) {
      window.removeEventListener('beforeunload', handleIframeUnload);
      targetError('iframe消息代填失败', error);
      sendIframeAckToParent(false, error?.message || 'exception_occurred');
    } finally {
      iframeMessageHandling = false;
    }
  });

  // 防重复执行标记
  let performIntelligentFillExecuting = false;

  async function bootstrap() {
    // 页面加载时检查是否有待显示的登录消息
    displayPendingMessage();
    
    targetLog('=== TopIAM扩展已激活 ===', {
      isTopWindow: IS_TOP_WINDOW,
      href: window.location.href,
      isLoginContext: isLikelyLoginContext()
    });
    
    if (!IS_TOP_WINDOW && !isLikelyLoginContext()) {
      targetLog('【跳过】非顶层窗口且非登录页面');
      return;
    }

    let taskId = '';
    let isDirectFromSSO = false; // 标记是否直接从SSO来（hash中有__topiam_task）
    const hash = window.location.hash;
    const match = hash.match(/__topiam_task=([a-zA-Z0-9_]+)/);
    const search = window.location.search;
    const searchParams = new URLSearchParams(search);
    const queryTaskId = String(searchParams.get('__topiam_task') || '').trim();
    bootHasResetRetryMarker = /(?:^|[&#])__topiam_reset_retry=1(?:&|$)/.test(hash)
      || searchParams.get(TOPIAM_RESET_RETRY_MARKER) === '1';
    if (bootHasResetRetryMarker) {
      targetLog('检测到一次性重试标记（强制清理后回跳）');
    }

    if (match) {
      taskId = match[1];
      isDirectFromSSO = true;
      targetLog('从URL hash命中代填任务（直接来自SSO）', { taskId, isTop: IS_TOP_WINDOW });
      cleanTaskMarkerFromUrl();
    } else if (queryTaskId) {
      taskId = queryTaskId;
      isDirectFromSSO = true;
      targetLog('从URL query命中代填任务（直接来自SSO）', { taskId, isTop: IS_TOP_WINDOW });
      cleanTaskMarkerFromUrl();
    } else {
      // 仅顶层窗口允许从 background 消费待处理 taskId，避免 iframe 抢占导致主页面无法代填
      if (IS_TOP_WINDOW) {
        taskId = await tryRecoverTaskIdFromBackground();
      }
      if (taskId) {
        targetLog('通过标签页兜底恢复代填任务（后台恢复）', { taskId, isTop: IS_TOP_WINDOW });
      }
    }

    loadWatermarkWhitelist();
    watchWatermarkWhitelist();
    startSsoStateSync();

    // 【改进】使用isLikelyLoginContext()判断
    const isLoginPage = isLikelyLoginContext();
    
    targetLog('bootstrap检查结果', {
      isLoginPage,
      isDirectFromSSO,
      hasTaskId: Boolean(taskId),
      isTopWindow: IS_TOP_WINDOW,
      hasResetRetryMarker: bootHasResetRetryMarker
    });

    if (taskId && !bootHasResetRetryMarker && IS_TOP_WINDOW) {
      const fastNonStandardOnBootstrap = isLikelyNonStandardLoginSurface()
        || await shouldFastResetForNonStandardLogin(600, 100);
      if (fastNonStandardOnBootstrap) {
        targetLog('bootstrap阶段命中非标准登录页，优先触发强制重置');
        await forceResetAppStateAndRetry(taskId, 'bootstrap_fast_non_standard_detect');
        return;
      }
    }

    // 【简化逻辑】
    // 如果taskId存在（来自SSO）且是登录页 → 代填
    if (taskId && isLoginPage && !performIntelligentFillExecuting) {
      targetLog('🚀 【触发代填】来自SSO且是登录页');
      performIntelligentFillExecuting = true;
      setTimeout(() => {
        targetLog('⏰ 延迟 80ms 后，开始执行 performIntelligentFill...');
        performIntelligentFill(taskId);
      }, 80);
      return;
    }

    // 如果taskId存在但不是登录页（可能自动授权/SSE动态界面）
    if (taskId && !isLoginPage && !performIntelligentFillExecuting) {
      targetLog('🚀 【触发代填】来自SSO但非登录页（自动授权推断）');
      performIntelligentFillExecuting = true;
      setTimeout(() => {
        targetLog('⏰ 延迟 80ms 后，开始执行 performIntelligentFill...');
        performIntelligentFill(taskId);
      }, 80);
      return;
    }

    // 无taskId的情况
    await enforceAccessPolicy(false);
    targetLog('无taskId，访问策略检查完毕');
  }

  // SSO会话过期监控机制
  // 定期检查SSO会话是否过期，过期时强制清除应用session并重新加载
  // 【改进】不再使用 setInterval 进行定时监控（用户离开标签页会停止）
  // 改为由后台 Service Worker (background.js) 进行定期检查和被动通知
  // 当会话过期时，background 向此标签页的 content script 发送 'enforceSessionExpiration' 消息

  // 处理来自 background service worker 的会话过期通知
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'enforceSessionExpiration') {
      executeSessionExpirationFlow('background_push')
        .then((ok) => sendResponse({ success: Boolean(ok) }))
        .catch((error) => sendResponse({ success: false, error: error?.message || 'unknown_error' }));
      return true;
    }
    // 其他请求类型不需要处理，返回 false 或不返回
    return false;
  });

  bootstrap();
})();
