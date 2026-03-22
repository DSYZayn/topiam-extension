const CREDENTIAL_TTL_MS = 30 * 60 * 1000; // 30分钟，避免长流程中凭据过期
const LAUNCH_GRANT_TTL_MS = 30 * 60 * 1000; // 也同步增加到30分钟
const BG_LOG_PREFIX = '[TopIAM BG]';
const TAB_TASK_TTL_MS = 10 * 60 * 1000;
const PREFETCH_TIMEOUT_MS = 12000;
// 凭据现在支持在TTL内无限次读取，无需readCount限制
const CRED_CACHE_TTL_MS = 4 * 60 * 60 * 1000;
const CRED_CACHE_KEY = 'topiamEncryptedCredentialCache';
const CRED_CACHE_AES_KEY = 'topiamCredentialAesKey';
const TOPIAM_IDENTITY_KEY = 'topiamCurrentIdentity';

let TOPIAM_IDENTITY = {
  username: '',
  fullName: '',
  updatedAt: 0,
  source: ''
};

let TOPIAM_AUTH_STATE = {
  authenticated: false,
  updatedAt: 0,
  source: ''
};

let TOPIAM_AUTH_SOFT_FAIL = {
  count: 0,
  lastAt: 0
};
const TOPIAM_AUTH_SOFT_FAIL_ESCALATE_COUNT = 4;
const TOPIAM_HEARTBEAT_INTERVAL_MS = 15000;
const TOPIAM_HEARTBEAT_FAIL_THRESHOLD = 2;

let TOPIAM_HEARTBEAT_FAIL = {
  count: 0,
  lastAt: 0,
  reason: ''
};
let TOPIAM_HEARTBEAT_LAST_CHECK_AT = 0;

const TOPIAM_SESSION_COOKIE_NAME = /session|token|auth|sid|jsessionid|remember|ticket/i;
const TOPIAM_LOGOUT_PATH_RE = /\/api\/v1\/logout(?:$|\?)/i;
const TOPIAM_LOGOUT_SIGNAL_COOLDOWN_MS = 4000;
let TOPIAM_LAST_LOGOUT_SIGNAL_AT = 0;

// 【诊断】background service worker 启动时立即输出（无条件）
try {
  console.log('[TopIAM BG] 【第1步】background.js 代码开始执行');
  console.log('[TopIAM BG] 【第1步】BG_LOG_PREFIX =', '[TopIAM BG]');
} catch (e) {
  console.error('[TopIAM BG] 【第1步】异常:', e.message);
}

function bgLog(message, payload) {
  if (typeof payload === 'undefined') {
    console.log(`${BG_LOG_PREFIX} ${message}`);
    return;
  }
  console.log(`${BG_LOG_PREFIX} ${message}`, payload);
}

function setTopIamIdentity(username, source = 'unknown', fullName = '') {
  const safeName = String(username || '').trim();
  if (!safeName) return;
  const safeFullName = String(fullName || '').trim();

  TOPIAM_IDENTITY = {
    username: safeName,
    fullName: safeFullName,
    updatedAt: Date.now(),
    source: String(source || 'unknown')
  };

  chrome.storage.local.set({
    [TOPIAM_IDENTITY_KEY]: TOPIAM_IDENTITY
  }, () => {});

  TOPIAM_AUTH_STATE = {
    authenticated: true,
    updatedAt: Date.now(),
    source: TOPIAM_IDENTITY.source
  };

  bgLog('已更新TopIAM平台用户身份', {
    username: safeName,
    fullName: safeFullName,
    source: TOPIAM_IDENTITY.source
  });
}

function getTopIamIdentity() {
  return TOPIAM_IDENTITY;
}

function setTopIamAuthState(authenticated, source = 'unknown') {
  TOPIAM_AUTH_STATE = {
    authenticated: Boolean(authenticated),
    updatedAt: Date.now(),
    source: String(source || 'unknown')
  };

  if (TOPIAM_AUTH_STATE.authenticated) {
    TOPIAM_AUTH_SOFT_FAIL = { count: 0, lastAt: 0 };
    TOPIAM_HEARTBEAT_FAIL = { count: 0, lastAt: 0, reason: '' };
  }

  bgLog('TopIAM认证状态更新', TOPIAM_AUTH_STATE);
}

function isTopIamAuthenticated() {
  return Boolean(TOPIAM_AUTH_STATE.authenticated);
}

function getCookiesByDomain(domain) {
  return new Promise((resolve) => {
    try {
      chrome.cookies.getAll({ domain }, (cookies) => {
        if (chrome.runtime.lastError) {
          bgLog('读取TopIAM cookies失败', { error: chrome.runtime.lastError.message, domain });
          resolve([]);
          return;
        }
        resolve(Array.isArray(cookies) ? cookies : []);
      });
    } catch (error) {
      bgLog('读取TopIAM cookies异常', { error: error?.message, domain });
      resolve([]);
    }
  });
}

function hasValidTopIamSessionCookie(cookies) {
  const nowSec = Date.now() / 1000;
  return cookies.some((item) => {
    const name = String(item?.name || '');
    if (!TOPIAM_SESSION_COOKIE_NAME.test(name)) return false;
    if (!item?.value) return false;
    if (typeof item.expirationDate === 'number' && item.expirationDate <= nowSec) return false;
    return true;
  });
}

async function probeTopIamAuthByCookies(source = 'cookie_probe') {
  const candidateDomains = [...new Set(
    (TOPIAM_DOMAINS || [])
      .map((domain) => String(domain || '').trim().toLowerCase())
      .filter(Boolean)
  )];

  if (candidateDomains.length === 0) {
    return isTopIamAuthenticated();
  }

  const cookieBatches = await Promise.all(candidateDomains.map((domain) => getCookiesByDomain(domain)));
  const cookies = cookieBatches.flat();
  const authenticated = hasValidTopIamSessionCookie(cookies);
  const previous = isTopIamAuthenticated();
  const hasAnyCookies = cookies.length > 0;

  if (authenticated && authenticated !== previous) {
    setTopIamAuthState(authenticated, source);
    return authenticated;
  }

  // 仅在TopIAM域无任何cookie时，才将认证状态判定为失效，避免会话cookie命名差异导致误杀
  if (!authenticated && previous && !hasAnyCookies) {
    setTopIamAuthState(false, `${source}_cookie_empty`);
    bgLog('cookie探针命中空cookie，仅更新TopIAM认证状态，不执行全局会话销毁', {
      source,
      previous,
      hasAnyCookies
    });
    return false;
  }

  if (!authenticated && previous && hasAnyCookies) {
    bgLog('cookie探针未命中会话cookie，保持当前认证状态（避免误判）', {
      source,
      cookieCount: cookies.length
    });
  }

  return authenticated;
}

function normalizeTopIamDomain(domainLike) {
  const raw = String(domainLike || '').trim().toLowerCase();
  if (!raw) return '';
  try {
    if (/^https?:\/\//.test(raw)) {
      return String(new URL(raw).hostname || '').toLowerCase();
    }
    return String(new URL(`https://${raw}`).hostname || '').toLowerCase();
  } catch {
    return raw.replace(/^\.+/, '');
  }
}

function buildTopIamHeartbeatBases() {
  const domains = [...new Set((TOPIAM_DOMAINS || []).map(normalizeTopIamDomain).filter(Boolean))];
  const bases = [];
  for (const domain of domains) {
    bases.push(`https://${domain}`);
    bases.push(`http://${domain}`);
  }
  return [...new Set(bases)];
}

function parseTopIamCurrentUserPayload(payload) {
  if (!payload || typeof payload !== 'object') {
    return { decisive: false, authenticated: false, reason: 'payload_invalid' };
  }

  const code = String(payload.code || payload.status || payload.errorCode || '').toLowerCase();
  const message = String(payload.message || payload.msg || payload.error || '').toLowerCase();
  const unauthorizedHit = /401|403|unauth|login|expired|token/.test(code)
    || /未登录|登录过期|请登录|unauth|expired|token/.test(message);
  if (unauthorizedHit) {
    return { decisive: true, authenticated: false, reason: 'api_unauthorized_payload' };
  }

  const success = payload.success === true || String(payload.status || '').toLowerCase() === 'success';
  if (!success) {
    return { decisive: true, authenticated: false, reason: 'api_unsuccessful' };
  }

  const result = payload?.result;
  const username = String(result?.username || '').trim();
  const fullName = String(result?.fullName || result?.displayName || result?.name || '').trim();
  if (!username) {
    return { decisive: true, authenticated: false, reason: 'api_no_username' };
  }

  return {
    decisive: true,
    authenticated: true,
    reason: 'api_current_user',
    username,
    fullName
  };
}

async function probeTopIamAuthByCurrentUserApi(source = 'heartbeat') {
  const bases = buildTopIamHeartbeatBases();
  if (bases.length === 0) {
    return { decisive: false, authenticated: isTopIamAuthenticated(), reason: 'no_topiam_domains' };
  }

  let firstDecisiveFalse = null;

  for (const base of bases) {
    const endpoint = `${base}/api/v1/session/current_user?_topiam_bg_heartbeat=1&_ts=${Date.now()}`;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);
      const resp = await fetch(endpoint, {
        method: 'GET',
        credentials: 'include',
        cache: 'no-store',
        redirect: 'follow',
        signal: controller.signal
      });
      clearTimeout(timer);

      if (resp.status === 401 || resp.status === 403) {
        firstDecisiveFalse = firstDecisiveFalse || { decisive: true, authenticated: false, reason: `http_${resp.status}` };
        continue;
      }

      if (!resp.ok) {
        continue;
      }

      let redirectedToLogin = false;
      try {
        const final = new URL(String(resp.url || ''), endpoint);
        const finalPath = String(final.pathname || '').toLowerCase();
        redirectedToLogin = resp.redirected && (
          /^\/login(?:\/|$)/.test(finalPath)
          || /^\/signin(?:\/|$)/.test(finalPath)
          || /^\/oauth(?:\/|$)/.test(finalPath)
          || /^\/cas(?:\/|$)/.test(finalPath)
          || /^\/auth\/login(?:\/|$)/.test(finalPath)
        );
      } catch {}

      if (redirectedToLogin) {
        firstDecisiveFalse = firstDecisiveFalse || { decisive: true, authenticated: false, reason: 'redirect_login' };
        continue;
      }

      const payload = await resp.clone().json().catch(() => null);
      const parsed = parseTopIamCurrentUserPayload(payload);
      if (!parsed.decisive) {
        continue;
      }

      if (parsed.authenticated) {
        setTopIamIdentity(parsed.username, `${source}_${parsed.reason}`, parsed.fullName || '');
        setTopIamAuthState(true, `${source}_${parsed.reason}`);
        return { decisive: true, authenticated: true, reason: parsed.reason, username: parsed.username };
      }

      firstDecisiveFalse = firstDecisiveFalse || { decisive: true, authenticated: false, reason: parsed.reason };
    } catch {}
  }

  if (firstDecisiveFalse) {
    return firstDecisiveFalse;
  }

  return { decisive: false, authenticated: isTopIamAuthenticated(), reason: 'heartbeat_inconclusive' };
}

// 【诊断】bgLog 函数已定义，进行第一次日志测试
(function() {
  try {
    bgLog('【第2步】bgLog 函数已定义并可用');
  } catch (e) {
    console.error('[TopIAM BG] 【第2步】bgLog 执行异常:', e.message);
  }
})();

chrome.storage.local.get([TOPIAM_IDENTITY_KEY], (result) => {
  const identity = result?.[TOPIAM_IDENTITY_KEY];
  if (identity && typeof identity === 'object' && identity.username) {
    TOPIAM_IDENTITY = {
      username: String(identity.username || '').trim(),
      fullName: String(identity.fullName || '').trim(),
      updatedAt: Number(identity.updatedAt || 0),
      source: String(identity.source || 'storage')
    };
    bgLog('已恢复TopIAM平台用户身份', {
      username: TOPIAM_IDENTITY.username,
      source: TOPIAM_IDENTITY.source
    });
    TOPIAM_AUTH_STATE = {
      authenticated: true,
      updatedAt: Date.now(),
      source: 'identity_restore'
    };
  }
});

function maskSecret(value) {
  if (!value || typeof value !== 'string') return '';
  if (value.length <= 2) return '*'.repeat(value.length);
  return `${value[0]}***${value[value.length - 1]}`;
}

function getHostnameSafe(urlLike, fallback = '') {
  try {
    return new URL(urlLike).hostname;
  } catch (error) {
    return fallback;
  }
}

function attachTaskToHash(url, taskId) {
  const hashContent = (url.hash || '').replace(/^#/, '');
  const tokens = hashContent ? hashContent.split('&').filter(Boolean) : [];
  const filtered = tokens.filter((item) => !item.startsWith('__topiam_task='));
  filtered.push(`__topiam_task=${taskId}`);
  url.hash = filtered.join('&');
}

function tryGetLaunchUrlFromSource(sourceUrl) {
  if (!sourceUrl) return '';
  try {
    const parsed = new URL(sourceUrl);
    return parsed.searchParams.get('target') ||
      parsed.searchParams.get('redirect') ||
      parsed.searchParams.get('url') ||
      parsed.searchParams.get('target_uri') ||
      parsed.searchParams.get('target_link_url') ||
      '';
  } catch (error) {
    return '';
  }
}

function tryGetLaunchUrlFromExtra(extra) {
  if (!extra || typeof extra !== 'object') return '';
  const keys = [
    'target',
    'redirect',
    'url',
    'target_uri',
    'target_link_url',
    'loginUrl',
    'login_url'
  ];

  for (const key of keys) {
    const value = extra[key];
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }
  }
  return '';
}

function sanitizeLaunchUrl(rawUrl, payload) {
  const parsed = new URL(rawUrl);
  const sensitiveKeyPattern = /(user(name)?|account|login|email|principal|pass(word)?|pwd|secret|credential)/i;
  const userValue = String(payload.username || '').trim();
  const passValue = String(payload.password || '').trim();

  let hasSensitiveQuery = false;
  for (const [key, value] of parsed.searchParams.entries()) {
    if (sensitiveKeyPattern.test(key)) {
      hasSensitiveQuery = true;
      break;
    }
    if ((userValue && value === userValue) || (passValue && value === passValue)) {
      hasSensitiveQuery = true;
      break;
    }
  }

  const isGet = String(payload.submitMethod || '').toLowerCase() === 'get';
  if (isGet || hasSensitiveQuery) {
    parsed.search = '';
  }

  return parsed.href;
}

function inferLaunchUrl(payload) {
  const sourceCandidate = tryGetLaunchUrlFromSource(payload.sourceUrl);
  if (sourceCandidate) {
    return normalizeTargetUrl(sourceCandidate, payload.sourceUrl);
  }

  const extraCandidate = tryGetLaunchUrlFromExtra(payload.extra);
  if (extraCandidate) {
    return normalizeTargetUrl(extraCandidate, payload.sourceUrl);
  }

  const normalizedTargetUrl = normalizeTargetUrl(payload.targetUrl, payload.sourceUrl);
  const parsed = new URL(normalizedTargetUrl);
  const isPost = String(payload.submitMethod || '').toLowerCase() === 'post';

  if (isPost) {
    return parsed.origin;
  }
  return sanitizeLaunchUrl(normalizedTargetUrl, payload);
}

const SecureVault = {
  data: new Map(),

  set(key, value) {
    this.data.set(key, {
      ...value,
      created: Date.now()
    });
    setTimeout(() => this.delete(key), CREDENTIAL_TTL_MS);
  },

  get(key) {
    const item = this.data.get(key);
    if (!item) return null;
    
    // 检查是否超过TTL
    if (Date.now() - item.created > CREDENTIAL_TTL_MS) {
      this.delete(key);
      return null;
    }
    
    // TTL内，允许无限次读取
    return item;
  },

  delete(key) {
    this.data.delete(key);
  }
};

const LaunchGate = {
  grantsByTab: new Map(),

  grant(tabId, origin) {
    this.grantsByTab.set(String(tabId), {
      origin,
      expiresAt: Date.now() + LAUNCH_GRANT_TTL_MS
    });
  },

  check(tabId, origin) {
    const record = this.grantsByTab.get(String(tabId));
    if (!record) return false;
    if (Date.now() > record.expiresAt) {
      this.grantsByTab.delete(String(tabId));
      return false;
    }
    return record.origin === origin;
  },

  cleanup() {
    const now = Date.now();
    for (const [tabId, record] of this.grantsByTab.entries()) {
      if (record.expiresAt <= now) {
        this.grantsByTab.delete(tabId);
      }
    }
  }
};

const TabTaskIndex = {
  records: new Map(),

  set(tabId, taskId, origin) {
    this.records.set(String(tabId), {
      taskId,
      origin,
      expiresAt: Date.now() + TAB_TASK_TTL_MS
    });
  },

  consume(tabId, origin) {
    const key = String(tabId);
    const record = this.records.get(key);
    if (!record) return '';
    if (Date.now() > record.expiresAt) {
      this.records.delete(key);
      return '';
    }
    // 如果origin匹配则直接返回，否则记录日志但仍然返回（允许跨域回退）
    if (origin && record.origin && record.origin !== origin) {
      bgLog('任务恢复时origin不匹配，但仍然允许恢复', {
        tabId,
        expectedOrigin: record.origin,
        senderOrigin: origin
      });
    }
    return record.taskId;
  },

  cleanup() {
    const now = Date.now();
    for (const [tabId, record] of this.records.entries()) {
      if (record.expiresAt <= now) {
        this.records.delete(tabId);
      }
    }
  },

  remove(tabId) {
    this.records.delete(String(tabId));
  }
};

// SSO 会话管理：跟踪用户登录状态，支持10秒自动过期
const LoginSession = {
  sessions: new Map(), // tabId -> { login: boolean, startTime, username, expiresAt }
  SESSION_DURATION_MS: 30 * 60 * 1000, // 30分钟

  startSession(tabId, username, durationMs) {
    const now = Date.now();
    const safeDurationMs = Number.isFinite(Number(durationMs)) && Number(durationMs) > 0
      ? Math.min(Number(durationMs), 12 * 60 * 60 * 1000)
      : this.SESSION_DURATION_MS;
    this.sessions.set(String(tabId), {
      login: true,
      startTime: now,
      username,
      expiresAt: now + safeDurationMs
    });
    bgLog('SSO会话开始', { tabId, username, duration: safeDurationMs });
  },

  isSessionValid(tabId) {
    const session = this.sessions.get(String(tabId));
    if (!session || !session.login) return false;
    if (Date.now() > session.expiresAt) {
      bgLog('SSO会话已过期', { tabId, username: session.username });
      // 不要删除会话，让hadSessionEver能检查到已过期的会话
      // 清理工作由cleanup方法负责
      return false;
    }
    return true;
  },

  getSession(tabId) {
    if (this.isSessionValid(tabId)) {
      return this.sessions.get(String(tabId));
    }
    return null;
  },

  // 检查是否曾经有过会话（即使已过期也返回，用于判断是否需要强制注销）
  hadSessionEver(tabId) {
    const session = this.sessions.get(String(tabId));
    return session && session.login === true;
  },

  endSession(tabId) {
    if (this.sessions.has(String(tabId))) {
      this.sessions.delete(String(tabId));
      bgLog('SSO会话已结束', { tabId });
    }
  },

  cleanup() {
    const now = Date.now();
    for (const [tabId, session] of this.sessions.entries()) {
      if (session.expiresAt <= now) {
        this.sessions.delete(tabId);
        bgLog('会话过期清理', { tabId });
      }
    }
  }
};

async function revokeAllAppSessions(reason = 'topiam_logout') {
  const entries = Array.from(LoginSession.sessions.entries());
  if (!entries.length) {
    bgLog('全局会话销毁：当前无活动会话', { reason });
    return;
  }

  bgLog('全局会话销毁开始', { reason, count: entries.length });

  for (const [tabId] of entries) {
    const numTabId = parseInt(tabId, 10);
    if (!Number.isFinite(numTabId)) continue;

    try {
      chrome.tabs.sendMessage(
        numTabId,
        { action: 'enforceSessionExpiration', reason },
        { frameId: 0 },
        () => {
          if (chrome.runtime.lastError) {
            bgLog('全局会话销毁通知失败（标签可能关闭）', {
              tabId,
              reason,
              error: chrome.runtime.lastError.message
            });
            return;
          }
          bgLog('全局会话销毁通知已发送', { tabId, reason });
        }
      );
    } catch (error) {
      bgLog('全局会话销毁通知异常', { tabId, reason, error: error?.message });
    }
  }

  LoginSession.sessions.clear();
  LaunchGate.grantsByTab.clear();
  TabTaskIndex.records.clear();

  bgLog('全局会话销毁完成', { reason });
}

// 【诊断】LoginSession 对象创建完成
console.log('[TopIAM BG] ✅ LoginSession 对象已创建，会话监控即将启动，会话有效期：10000ms');

// 定期清理过期会话和监控会话状态
// 注：使用 setInterval 在 Service Worker 中是可靠的，因为 Service Worker 在浏览器运行期间持续存在
const sessionMonitorInterval = setInterval(async () => {
  await probeTopIamAuthByCookies('session_monitor');

  const nowHeartbeat = Date.now();
  if (isTopIamAuthenticated() && nowHeartbeat - TOPIAM_HEARTBEAT_LAST_CHECK_AT >= TOPIAM_HEARTBEAT_INTERVAL_MS) {
    TOPIAM_HEARTBEAT_LAST_CHECK_AT = nowHeartbeat;
    const heartbeat = await probeTopIamAuthByCurrentUserApi('session_monitor_heartbeat');

    if (heartbeat.decisive && !heartbeat.authenticated) {
      if (nowHeartbeat - TOPIAM_HEARTBEAT_FAIL.lastAt > 90000) {
        TOPIAM_HEARTBEAT_FAIL = { count: 0, lastAt: nowHeartbeat, reason: '' };
      }
      TOPIAM_HEARTBEAT_FAIL.count += 1;
      TOPIAM_HEARTBEAT_FAIL.lastAt = nowHeartbeat;
      TOPIAM_HEARTBEAT_FAIL.reason = heartbeat.reason || 'unknown';

      bgLog('TopIAM current_user 心跳失败', {
        reason: TOPIAM_HEARTBEAT_FAIL.reason,
        failCount: TOPIAM_HEARTBEAT_FAIL.count,
        threshold: TOPIAM_HEARTBEAT_FAIL_THRESHOLD
      });

      if (TOPIAM_HEARTBEAT_FAIL.count >= TOPIAM_HEARTBEAT_FAIL_THRESHOLD && isTopIamAuthenticated()) {
        setTopIamAuthState(false, `heartbeat_${TOPIAM_HEARTBEAT_FAIL.reason}`);
        await revokeAllAppSessions('topiam_session_expired_heartbeat');
      }
    }
  }

  // 【修复】先检测过期会话并发送通知，再清理
  // 步骤1：识别所有过期的会话（但先不删除）
  const now = Date.now();
  const expiredSessions = [];
  for (const [tabId, session] of LoginSession.sessions.entries()) {
    if (session.expiresAt <= now) {
      expiredSessions.push({ tabId, session });
    }
  }
  
  // 步骤2：向所有过期会话的标签页发送通知
  for (const { tabId, session } of expiredSessions) {
    try {
      bgLog('【后台监控】检测到会话过期，通知标签页', { tabId, username: session.username });
      
      // 【关键修复】tabId 存储为字符串，但 chrome.tabs.sendMessage 需要整数
      const numTabId = parseInt(tabId, 10);
      
      chrome.tabs.sendMessage(
        numTabId,
        { action: 'enforceSessionExpiration' },
        { frameId: 0 }, // 仅向主 frame 发送
        (response) => {
          if (chrome.runtime.lastError) {
            bgLog('通知会话过期失败（标签页可能已关闭）', { 
              tabId, 
              error: chrome.runtime.lastError.message 
            });
          } else if (response?.success) {
            bgLog('✓ 会话过期通知已发送并被处理', { tabId });
          }
        }
      );
    } catch (error) {
      bgLog('发送会话过期通知异常', { tabId, error: error?.message });
    }
  }
  
  // 步骤3：清理过期会话
  LoginSession.cleanup();
  
  // 步骤4：监控活跃标签页的会话过期状态
  try {
    const allTabs = await chrome.tabs.query({});
    
    // 【诊断】记录所有活跃会话状态（每次都打印，不管是否有会话）
    const sessionSummary = [];
    for (const [key, value] of LoginSession.sessions.entries()) {
      const timeLeft = Math.max(0, value.expiresAt - Date.now());
      sessionSummary.push({ 
        tabId: key, 
        username: value.username, 
        timeLeftMs: timeLeft,
        isExpired: timeLeft === 0 
      });
    }
    
    // 总是打印监控状态，便于诊断
    bgLog('【会话监控周期执行】', { 
      activeSessions: sessionSummary.length,
      openTabs: allTabs.length,
      sessions: sessionSummary 
    });
  } catch (error) {
    bgLog('会话监控循环异常', { error: error?.message });
  }
}, 5000);

// 【诊断】监控循环已启动
console.log('[TopIAM BG] ✅ 会话监控循环已启动，每 5000ms 执行一次');

let TOPIAM_DOMAINS = [];
let PROTECTED_APP_ORIGINS = new Set();
const ENABLE_NAVIGATION_INTERCEPT = true;
const PREFETCH_GHOST_TABS = new Map();
const PREFETCH_SESSIONS = new Map();
const PREFETCH_INTERCEPT_LOCK_MS = 15000;
const PREFETCH_INTERCEPT_LOCKS = new Map();

function setPrefetchInterceptLock(tabId) {
  if (typeof tabId !== 'number') return;
  PREFETCH_INTERCEPT_LOCKS.set(tabId, Date.now() + PREFETCH_INTERCEPT_LOCK_MS);
}

function clearPrefetchInterceptLock(tabId) {
  if (typeof tabId !== 'number') return;
  PREFETCH_INTERCEPT_LOCKS.delete(tabId);
}

function hasValidPrefetchInterceptLock(tabId) {
  if (typeof tabId !== 'number') return false;
  const expiresAt = Number(PREFETCH_INTERCEPT_LOCKS.get(tabId) || 0);
  if (!expiresAt) return false;
  if (Date.now() > expiresAt) {
    PREFETCH_INTERCEPT_LOCKS.delete(tabId);
    return false;
  }
  return true;
}

function isTopIamUrl(urlLike) {
  try {
    const host = new URL(urlLike).hostname;
    return TOPIAM_DOMAINS.some((domain) => {
      const normalizedDomain = String(domain || '').trim().toLowerCase();
      if (!normalizedDomain) return false;
      return host === normalizedDomain || host.endsWith(`.${normalizedDomain}`);
    });
  } catch (error) {
    return false;
  }
}

function isTopIamLogoutRequest(details) {
  if (!details || String(details.method || '').toUpperCase() !== 'POST') return false;
  try {
    const parsed = new URL(String(details.url || ''));
    const host = String(parsed.hostname || '').toLowerCase();
    const path = String(parsed.pathname || '').toLowerCase();
    if (!TOPIAM_LOGOUT_PATH_RE.test(path)) return false;

    if (isTopIamUrl(details.url)) return true;
    return false;
  } catch {
    return false;
  }
}

function triggerImmediateTopIamLogout(source = 'topiam_logout_api') {
  const now = Date.now();
  if (now - TOPIAM_LAST_LOGOUT_SIGNAL_AT < TOPIAM_LOGOUT_SIGNAL_COOLDOWN_MS) {
    return;
  }
  TOPIAM_LAST_LOGOUT_SIGNAL_AT = now;

  const previous = getTopIamIdentity().username;
  TOPIAM_IDENTITY = {
    username: '',
    fullName: '',
    updatedAt: now,
    source
  };
  chrome.storage.local.set({ [TOPIAM_IDENTITY_KEY]: TOPIAM_IDENTITY }, () => {});
  setTopIamAuthState(false, source);

  bgLog('检测到TopIAM主动退出API，立即执行全局会话销毁', {
    source,
    previousUser: previous || ''
  });

  revokeAllAppSessions('topiam_logout_api').catch((error) => {
    bgLog('主动退出API触发会话销毁失败', { error: error?.message || 'unknown' });
  });
}

function normalizeCookieDomain(domain) {
  return String(domain || '').replace(/^\./, '').toLowerCase();
}

function isCookieDomainMatch(cookieDomain, host) {
  const normalizedCookieDomain = normalizeCookieDomain(cookieDomain);
  const normalizedHost = normalizeCookieDomain(host);
  if (!normalizedCookieDomain || !normalizedHost) return false;
  return normalizedHost === normalizedCookieDomain || normalizedHost.endsWith(`.${normalizedCookieDomain}`);
}

async function clearCookiesForOrigin(originUrl) {
  const parsed = new URL(originUrl);
  const host = parsed.hostname;
  const allCookies = await chrome.cookies.getAll({});
  const matched = allCookies.filter((cookie) => isCookieDomainMatch(cookie.domain, host));

  let removed = 0;
  for (const cookie of matched) {
    try {
      const cookieHost = normalizeCookieDomain(cookie.domain);
      const protocol = cookie.secure ? 'https:' : 'http:';
      const cookieUrl = `${protocol}//${cookieHost}${cookie.path || '/'}`;
      await chrome.cookies.remove({
        url: cookieUrl,
        name: cookie.name,
        storeId: cookie.storeId
      });
      removed += 1;
    } catch (error) {}
  }

  return { matched: matched.length, removed };
}

function sendMonitorDebug(tabId, message, payload) {
  if (typeof tabId !== 'number') return;
  chrome.tabs.sendMessage(tabId, {
    action: 'topiamDebug',
    message,
    payload: payload || {}
  }, () => {});
}

function bytesToBase64(bytes) {
  let binary = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < arr.byteLength; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const arr = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    arr[i] = binary.charCodeAt(i);
  }
  return arr;
}

async function getOrCreateAesKey() {
  const fromLocal = await chrome.storage.local.get([CRED_CACHE_AES_KEY]);
  let rawBase64 = fromLocal?.[CRED_CACHE_AES_KEY] || '';

  if (!rawBase64) {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    rawBase64 = bytesToBase64(raw);
    await chrome.storage.local.set({ [CRED_CACHE_AES_KEY]: rawBase64 });
  }

  return crypto.subtle.importKey(
    'raw',
    base64ToBytes(rawBase64),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

async function readCredentialCache() {
  const stored = await chrome.storage.local.get([CRED_CACHE_KEY]);
  return stored?.[CRED_CACHE_KEY] || {};
}

async function writeCredentialCache(cache) {
  await chrome.storage.local.set({ [CRED_CACHE_KEY]: cache });
}

function normalizeCacheName(value) {
  return String(value || '').trim().toLowerCase().replace(/\s+/g, '');
}

function getCacheKeys(meta = {}) {
  const keys = [];
  if (meta.appId) keys.push(`id:${String(meta.appId).trim()}`);
  const appName = normalizeCacheName(meta.appName);
  if (appName) keys.push(`name:${appName}`);

  const sourceUrl = String(meta.sourceUrl || '').trim();
  if (sourceUrl) {
    try {
      const parsed = new URL(sourceUrl);
      const sourceFingerprint = `${parsed.hostname}${parsed.pathname}`.toLowerCase();
      keys.push(`src:${sourceFingerprint}`);
    } catch (error) {}
  }

  const targetUrl = String(meta.targetUrl || '').trim();
  if (targetUrl) {
    try {
      keys.push(`host:${new URL(targetUrl).hostname.toLowerCase()}`);
    } catch (error) {}
  }
  return [...new Set(keys)];
}

async function putEncryptedCredentialCache(meta, payload) {
  const cacheKeys = getCacheKeys({
    appId: meta?.appId,
    appName: meta?.appName,
    sourceUrl: payload?.sourceUrl,
    targetUrl: payload?.targetUrl
  });
  if (!cacheKeys.length || !payload?.username || !payload?.password) return;

  try {
    const key = await getOrCreateAesKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const body = JSON.stringify({
      username: payload.username,
      password: payload.password,
      extra: payload.extra || {},
      targetUrl: payload.targetUrl || '',
      sourceUrl: payload.sourceUrl || '',
      submitMethod: payload.submitMethod || 'post',
      appName: payload.appName || '',
      expiresAt: Date.now() + CRED_CACHE_TTL_MS
    });
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(body)
    );

    const cache = await readCredentialCache();
    cacheKeys.forEach((cacheKey) => {
      cache[cacheKey] = {
        cipher: bytesToBase64(new Uint8Array(encrypted)),
        iv: bytesToBase64(iv),
        updatedAt: Date.now()
      };
    });
    await writeCredentialCache(cache);
  } catch (error) {
    bgLog('写入加密账密缓存失败', {
      appId: meta?.appId || '',
      appName: meta?.appName || '',
      error: error?.message || String(error)
    });
  }
}

async function getEncryptedCredentialCache(meta) {
  const cacheKeys = getCacheKeys(meta);
  if (!cacheKeys.length) return null;

  try {
    const cache = await readCredentialCache();
    const item = cacheKeys
      .map((key) => cache[key])
      .find((entry) => entry?.cipher && entry?.iv);
    if (!item?.cipher || !item?.iv) return null;

    const key = await getOrCreateAesKey();
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(item.iv) },
      key,
      base64ToBytes(item.cipher)
    );

    const parsed = JSON.parse(new TextDecoder().decode(decrypted));
    if (!parsed?.username || !parsed?.password) return null;
    if (Date.now() > Number(parsed.expiresAt || 0)) return null;
    return parsed;
  } catch (error) {
    bgLog('读取加密账密缓存失败', {
      appId: meta?.appId || '',
      appName: meta?.appName || '',
      error: error?.message || String(error)
    });
    return null;
  }
}

function extractCredentialsFromFormData(formData) {
  if (!formData || typeof formData !== 'object') {
    return { username: '', password: '', extra: {} };
  }

  let username = '';
  let password = '';
  const extra = {};

  Object.entries(formData).forEach(([key, values]) => {
    const value = Array.isArray(values) ? String(values[0] || '') : String(values || '');
    const lower = String(key).toLowerCase();

    if (!username && ['username', 'user', 'login', 'account', 'email', 'principal', 'name'].includes(lower)) {
      username = value;
      return;
    }
    if (!password && ['password', 'pass', 'pwd', 'passwd', 'secret', 'credential'].includes(lower)) {
      password = value;
      return;
    }
    extra[key] = value;
  });

  return { username, password, extra };
}

async function prefetchInitLoginAndDispatch(originalTabId, initLoginUrl, appMeta, options = {}) {
  const ghostTab = await chrome.tabs.create({
    url: initLoginUrl,
    active: false
  });

  const ghostTabId = ghostTab.id;
  if (typeof ghostTabId !== 'number') {
    throw new Error('创建预取标签失败');
  }

  PREFETCH_GHOST_TABS.set(ghostTabId, {
    originalTabId,
    appId: appMeta?.appId || '',
    appName: appMeta?.appName || '',
    openInNewTab: Boolean(options.openInNewTab),
    startedAt: Date.now()
  });
  const keepGhostAsDestination = Boolean(options.openInNewTab);

  bgLog('开始预访问 initLoginUrl', { originalTabId, ghostTabId, initLoginUrl });
  sendMonitorDebug(originalTabId, '预取开始', {
    ghostTabId,
    initLoginUrl,
    appId: appMeta?.appId || '',
    appName: appMeta?.appName || ''
  });

  return new Promise((resolve, reject) => {
    let done = false;
    const state = {
      username: '',
      password: '',
      extra: {},
      extractedTargetUrl: ''
    };

    const cleanup = async () => {
      chrome.tabs.onUpdated.removeListener(onUpdated);
      clearTimeout(timeoutId);
      PREFETCH_GHOST_TABS.delete(ghostTabId);
      PREFETCH_SESSIONS.delete(ghostTabId);
      try {
        await chrome.tabs.remove(ghostTabId);
      } catch (error) {}
    };

    const finish = async (error) => {
      if (done) return;
      done = true;
      await cleanup();
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    };

    const tryDispatchFromFallback = async (targetUrl, reason) => {
      if (!state.username || !state.password || !targetUrl) return false;
      if (done) return true;

      const dispatchPayload = {
        sourceUrl: initLoginUrl,
        targetUrl,
        submitMethod: 'post',
        username: state.username,
        password: state.password,
        extra: state.extra,
        appId: appMeta?.appId || '',
        appName: appMeta?.appName || '',
        openInNewTab: Boolean(options.openInNewTab),
        destinationTabId: keepGhostAsDestination ? ghostTabId : undefined
      };

      try {
        sendMonitorDebug(originalTabId, '触发预取兜底派发', {
          reason,
          targetUrl,
          username: state.username,
          hasPassword: Boolean(state.password)
        });

        chrome.tabs.onUpdated.removeListener(onUpdated);
        clearTimeout(timeoutId);
        PREFETCH_SESSIONS.delete(ghostTabId);
        PREFETCH_GHOST_TABS.delete(ghostTabId);

        await dispatchTaskToTarget(originalTabId, dispatchPayload);

        if (!keepGhostAsDestination) {
          try {
            await chrome.tabs.remove(ghostTabId);
          } catch (error) {}
        }

        done = true;
        resolve();
        return true;
      } catch (error) {
        await finish(error);
        return true;
      }
    };

    PREFETCH_SESSIONS.set(ghostTabId, {
      resolve: async (payload) => {
        if (done) return;
        done = true;
        chrome.tabs.onUpdated.removeListener(onUpdated);
        clearTimeout(timeoutId);
        PREFETCH_SESSIONS.delete(ghostTabId);
        PREFETCH_GHOST_TABS.delete(ghostTabId);

        if (!keepGhostAsDestination) {
          try {
            await chrome.tabs.remove(ghostTabId);
          } catch (error) {}
        }

        sendMonitorDebug(originalTabId, '预取成功（POST提取）', {
          targetUrl: payload?.targetUrl || '',
          username: payload?.username || '',
          hasPassword: Boolean(payload?.password)
        });
        resolve();
      },
      reject: async (error) => {
        await finish(error);
      }
    });

    const onUpdated = async (tabId, changeInfo, tab) => {
      if (tabId !== ghostTabId) return;

      const observedUrl = changeInfo.url || tab?.url || '';
      if (!observedUrl) return;

      sendMonitorDebug(originalTabId, '预取观察到跳转URL', {
        ghostTabId,
        url: observedUrl,
        status: changeInfo.status || ''
      });

      if (!isTopIamUrl(observedUrl)) {
        sendMonitorDebug(originalTabId, '已离开TopIAM域，等待POST提交拦截', {
          ghostTabId,
          url: observedUrl
        });

        if (await tryDispatchFromFallback(observedUrl, 'leave_topiam_without_post_capture')) {
          return;
        }
        return;
      }

      if ((changeInfo.status === 'complete' || tab?.status === 'complete') && /\/initiator/i.test(observedUrl)) {
        try {
          const results = await chrome.scripting.executeScript({
            target: { tabId: ghostTabId },
            func: extractCredentialsFromPage
          });

          const extracted = results?.[0]?.result;
          if (extracted?.username && extracted?.password) {
            state.username = extracted.username;
            state.password = extracted.password;
            state.extra = extracted.extraParams || {};
            state.extractedTargetUrl = extracted.targetUrl || '';

            sendMonitorDebug(originalTabId, '在 initiator 页提取到账密', {
              ghostTabId,
              username: state.username,
              hasPassword: Boolean(state.password),
              hasTarget: Boolean(state.extractedTargetUrl)
            });

            if (state.extractedTargetUrl) {
              const normalized = normalizeTargetUrl(state.extractedTargetUrl, observedUrl);
              if (await tryDispatchFromFallback(normalized, 'initiator_dom_extract')) {
                return;
              }
            }
          }
        } catch (error) {
          sendMonitorDebug(originalTabId, 'initiator 页提取失败', {
            ghostTabId,
            error: error?.message || String(error)
          });
        }
      }
    };

    chrome.tabs.onUpdated.addListener(onUpdated);

    const timeoutId = setTimeout(async () => {
      if (done) return;
      sendMonitorDebug(originalTabId, '预取超时（未捕获到POST账密）', { ghostTabId });
      await finish(new Error('预取超时，未捕获POST账密'));
    }, PREFETCH_TIMEOUT_MS);
  });
}

async function refreshPolicyFromStorage() {
  const result = await chrome.storage.local.get(['topiamDomains', 'discoveredApps', 'protectedAppOrigins']);
  TOPIAM_DOMAINS = result.topiamDomains || [];

  const origins = new Set(result.protectedAppOrigins || []);
  const discovered = result.discoveredApps || [];
  discovered.forEach((app) => {
    if (app?.targetOrigin) origins.add(app.targetOrigin);
  });
  PROTECTED_APP_ORIGINS = origins;

  bgLog('监控域名已加载', TOPIAM_DOMAINS);
  bgLog('受保护应用源已加载', [...PROTECTED_APP_ORIGINS]);
}

refreshPolicyFromStorage();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (!ENABLE_NAVIGATION_INTERCEPT) return;
  if (details.frameId !== 0) return;

  if (PREFETCH_GHOST_TABS.has(details.tabId)) {
    return;
  }

  if (hasValidPrefetchInterceptLock(details.tabId)) {
    bgLog('导航兜底跳过：标签页已有预取任务进行中', { tabId: details.tabId, url: details.url });
    return;
  }

  const url = new URL(details.url);
  const isTopIAM = TOPIAM_DOMAINS.some((domain) => url.hostname.includes(domain));
  if (!isTopIAM) return;

  const fullPath = `${url.pathname}${url.search}`.toLowerCase();
  const isFormInitiator = /\/api\/v1\/authorize\/form\/[^/]+\/initiator/.test(fullPath)
    || /\/api\/v1\/user\/app\/initiator\//.test(fullPath)
    || (url.pathname.toLowerCase().includes('/initiator') && (url.searchParams.has('appId') || url.searchParams.has('target') || url.searchParams.has('redirect')));

  const isFormFill = url.pathname.includes('form-fill') ||
                     url.pathname.includes('auto-login') ||
                     (url.searchParams.has('appId') && url.searchParams.has('target')) ||
                     url.pathname.match(/\/app\/[^\/]+\/login/) ||
                     isFormInitiator;
  if (!isFormFill) return;

  bgLog('捕获导航型表单代填跳转', { tabId: details.tabId, url: details.url, isFormInitiator });

  chrome.tabs.update(details.tabId, {
    url: 'data:text/html,<html><head><style>body{background:#f0f2f5;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:system-ui;}</style></head><body><div style="text-align:center;color:#1890ff;"><div style="font-size:48px;margin-bottom:20px;">🔐</div><div>TopIAM插件接管中...</div></div></body></html>'
  });

  extractAndRedirect(details.url, details.tabId);
}, { url: [{ schemes: ['https', 'http'] }] });

async function extractAndRedirect(formFillUrl, originalTabId) {
  let ghostTabId;

  try {
    const ghostTab = await chrome.tabs.create({
      url: formFillUrl,
      active: false
    });
    ghostTabId = ghostTab.id;

    await waitForTabLoad(ghostTabId);

    const results = await chrome.scripting.executeScript({
      target: { tabId: ghostTabId },
      func: extractCredentialsFromPage
    });

    const extracted = results[0]?.result;
    if (!extracted || !extracted.username || !extracted.password) {
      throw new Error('未能提取账密');
    }
    bgLog('幽灵页提取到凭据', {
      tabId: originalTabId,
      username: extracted.username,
      passwordMasked: maskSecret(extracted.password),
      hasTargetInPage: Boolean(extracted.targetUrl)
    });

    let targetUrl = extracted.targetUrl;
    if (!targetUrl) {
      const urlObj = new URL(formFillUrl);
      targetUrl = urlObj.searchParams.get('target') ||
                  urlObj.searchParams.get('redirect') ||
                  urlObj.searchParams.get('url');
    }

    if (!targetUrl) {
      const appId = new URL(formFillUrl).searchParams.get('appId') ||
                    new URL(formFillUrl).pathname.match(/\/app\/([^\/]+)/)?.[1];
      const { complexApps = {} } = await chrome.storage.local.get(['complexApps']);
      if (appId && complexApps[appId]?.url) {
        targetUrl = complexApps[appId].url;
      }
    }

    if (!targetUrl) {
      throw new Error('无法确定目标URL');
    }

    const normalizedTargetUrl = normalizeTargetUrl(targetUrl);
    const target = new URL(normalizedTargetUrl);
    PROTECTED_APP_ORIGINS.add(target.origin);

    const appIdFromUrl = new URL(formFillUrl).searchParams.get('appId') ||
      new URL(formFillUrl).pathname.match(/\/app\/([^\/]+)/)?.[1] || '';
    await upsertDiscoveredApp({
      appId: appIdFromUrl,
      name: appIdFromUrl || target.hostname,
      sourceDomain: new URL(formFillUrl).hostname,
      targetUrl: target.href,
      targetOrigin: target.origin
    });

    const taskId = `task_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    SecureVault.set(taskId, {
      username: extracted.username,
      password: extracted.password,
      extra: extracted.extraParams || {},
      originalTab: originalTabId,
      targetOrigin: target.origin
    });

    LaunchGate.grant(originalTabId, target.origin);
    bgLog('任务已签发(导航链路)', {
      taskId,
      originalTabId,
      targetOrigin: target.origin
    });

    attachTaskToHash(target, taskId);
    bgLog('即将跳转目标站(导航链路)', { tabId: originalTabId, target: target.href });
    chrome.tabs.update(originalTabId, { url: target.href });
  } catch (error) {
    console.error(`${BG_LOG_PREFIX} 导航链路提取失败`, error);
    chrome.tabs.update(originalTabId, { url: formFillUrl });
  } finally {
    if (ghostTabId) {
      chrome.tabs.remove(ghostTabId).catch(() => {});
    }
  }
}

async function dispatchTaskToTarget(originalTabId, payload) {
  const openInNewTab = Boolean(payload.openInNewTab);
  const preferredDestinationTabId = Number.isInteger(payload.destinationTabId) ? payload.destinationTabId : null;
  bgLog('收到表单拦截派发请求', {
    tabId: originalTabId,
    sourceUrl: payload.sourceUrl,
    targetUrl: payload.targetUrl,
    username: payload.username,
    passwordMasked: maskSecret(payload.password),
    openInNewTab,
    preferredDestinationTabId
  });

  const launchUrl = inferLaunchUrl(payload);
  const target = new URL(launchUrl);
  let realTargetUrl = '';
  try {
    if (payload?.targetUrl) {
      realTargetUrl = normalizeTargetUrl(payload.targetUrl, payload.sourceUrl);
    }
  } catch (error) {}

  PROTECTED_APP_ORIGINS.add(target.origin);

  await upsertDiscoveredApp({
    appId: payload.appId || '',
    name: payload.appName || target.hostname,
    sourceDomain: getHostnameSafe(payload.sourceUrl, ''),
    targetUrl: target.href,
    targetOrigin: target.origin,
    realTargetUrl: realTargetUrl || payload.realTargetUrl || ''
  });

  await putEncryptedCredentialCache({
    appId: payload.appId || '',
    appName: payload.appName || '',
    sourceUrl: payload.sourceUrl || '',
    targetUrl: target.href
  }, payload);

  const taskId = `task_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  let destinationTabId = preferredDestinationTabId || originalTabId;

  if (openInNewTab && !preferredDestinationTabId) {
    const created = await chrome.tabs.create({
      url: 'about:blank',
      active: true
    });
    if (typeof created?.id !== 'number') {
      throw new Error('创建目标标签页失败');
    }
    destinationTabId = created.id;
  }

  SecureVault.set(taskId, {
    username: payload.username,
    password: payload.password,
    extra: payload.extra || {},
    originalTab: destinationTabId,
    targetOrigin: target.origin
  });

  LaunchGate.grant(destinationTabId, target.origin);
  TabTaskIndex.set(destinationTabId, taskId, target.origin);
  bgLog('任务已签发(表单拦截链路)', {
    taskId,
    originalTabId,
    destinationTabId,
    targetOrigin: target.origin
  });

  attachTaskToHash(target, taskId);
  bgLog('即将跳转目标站(表单拦截链路)', {
    tabId: destinationTabId,
    target: target.href,
    openInNewTab
  });
  await chrome.tabs.update(destinationTabId, {
    url: target.href,
    active: openInNewTab ? true : undefined
  });
}

function normalizeTargetUrl(rawUrl, baseUrl) {
  const parsed = baseUrl ? new URL(rawUrl, baseUrl) : new URL(rawUrl);
  if (parsed.protocol === 'https:' && isPrivateIpV4(parsed.hostname)) {
    bgLog('检测到私网IP HTTPS，自动降级到HTTP', { from: rawUrl });
    parsed.protocol = 'http:';
  }
  return parsed.href;
}

function isPrivateIpV4(hostname) {
  const match = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return false;

  const octets = match.slice(1).map(Number);
  if (octets.some((num) => Number.isNaN(num) || num < 0 || num > 255)) return false;

  if (octets[0] === 10) return true;
  if (octets[0] === 127) return true;
  if (octets[0] === 192 && octets[1] === 168) return true;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  if (octets[0] === 169 && octets[1] === 254) return true;

  return false;
}

function waitForTabLoad(tabId) {
  return new Promise((resolve) => {
    const listener = (updatedTabId, info) => {
      if (updatedTabId === tabId && info.status === 'complete') {
        chrome.tabs.onUpdated.removeListener(listener);
        setTimeout(resolve, 500);
      }
    };
    chrome.tabs.onUpdated.addListener(listener);
  });
}

function extractCredentialsFromPage() {
  const forms = document.querySelectorAll('form');
  for (let form of forms) {
    const action = form.action || form.getAttribute('action');
    let username = '';
    let password = '';
    const extra = {};

    form.querySelectorAll('input').forEach((input) => {
      const name = input.name || input.id;
      const value = input.value;
      if (!name) return;

      const lower = name.toLowerCase();
      if (['username', 'user', 'login', 'account', 'email', 'uin', 'principal', 'name'].includes(lower)) {
        username = value;
      } else if (['password', 'pass', 'pwd', 'passwd', 'secret', 'credential'].includes(lower)) {
        password = value;
      } else {
        extra[name] = value;
      }
    });

    if (username && password) {
      return {
        hasCredentials: true,
        username,
        password,
        targetUrl: action,
        extraParams: extra
      };
    }
  }

  const hiddenUser = document.querySelector('input[type="hidden"][name*="user"], input[type="hidden"][name*="account"]');
  const hiddenPass = document.querySelector('input[type="hidden"][name*="pass"], input[type="hidden"][name*="pwd"]');
  const targetInput = document.querySelector('input[type="hidden"][name="target"], input[type="hidden"][name="redirect"]');

  if (hiddenUser && hiddenPass) {
    return {
      hasCredentials: true,
      username: hiddenUser.value,
      password: hiddenPass.value,
      targetUrl: targetInput?.value,
      extraParams: {}
    };
  }

  if (window.appData?.credentials || window.loginData || window.formData) {
    const data = window.appData?.credentials || window.loginData || window.formData;
    return {
      hasCredentials: true,
      username: data.username || data.user || data.account,
      password: data.password || data.pass || data.credential,
      targetUrl: data.target || data.redirect || data.url,
      extraParams: data.extra || {}
    };
  }

  return { hasCredentials: false };
}

function buildAppIdentitySet(obj) {
  const values = [
    obj?.appId,
    obj?.appCode,
    obj?.initLoginUrl,
    obj?.realTargetUrl,
    obj?.targetOrigin,
    obj?.targetUrl
  ]
    .map((value) => String(value || '').trim())
    .filter(Boolean);
  return new Set(values);
}

function findDiscoveredAppIndex(apps, app) {
  const incomingIds = buildAppIdentitySet(app);
  if (incomingIds.size === 0) return -1;

  return apps.findIndex((item) => {
    const existingIds = buildAppIdentitySet(item);
    for (const value of incomingIds) {
      if (existingIds.has(value)) return true;
    }
    return false;
  });
}

function mergeDiscoveredApp(existing, incoming) {
  const merged = {
    ...(existing || {}),
    ...(incoming || {})
  };

  const keepExistingWhenIncomingEmpty = [
    'realTargetUrl',
    'targetUrl',
    'targetOrigin',
    'initLoginUrl',
    'appCode',
    'name',
    'sourceDomain'
  ];

  keepExistingWhenIncomingEmpty.forEach((key) => {
    const incomingValue = incoming?.[key];
    if (typeof incomingValue === 'string' && incomingValue.trim() === '' && typeof existing?.[key] === 'string' && existing[key].trim()) {
      merged[key] = existing[key];
    }
  });

  return merged;
}

async function upsertDiscoveredApps(appList) {
  const result = await chrome.storage.local.get(['discoveredApps', 'protectedAppOrigins']);
  const apps = result.discoveredApps || [];
  const protectedOrigins = new Set(result.protectedAppOrigins || []);

  const list = Array.isArray(appList) ? appList : [];
  list.forEach((app) => {
    if (!app || typeof app !== 'object') return;

    if (app.targetOrigin) {
      protectedOrigins.add(app.targetOrigin);
      PROTECTED_APP_ORIGINS.add(app.targetOrigin);
    }

    const index = findDiscoveredAppIndex(apps, app);
    if (index >= 0) {
      apps[index] = { ...mergeDiscoveredApp(apps[index], app), updatedAt: Date.now() };
    } else {
      apps.push({ ...app, createdAt: Date.now(), updatedAt: Date.now() });
    }
  });

  await chrome.storage.local.set({
    discoveredApps: apps,
    protectedAppOrigins: [...protectedOrigins]
  });
}

async function upsertDiscoveredApp(app) {
  return upsertDiscoveredApps([app]);
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getCredentials') {
    bgLog('收到凭据读取请求', {
      taskId: request.taskId,
      senderTabId: sender?.tab?.id,
      senderUrl: sender?.url
    });
    const data = SecureVault.get(request.taskId);
    if (!data) {
      sendResponse({ success: false, error: '凭据已过期或不存在' });
      return true;
    }

    const senderTabId = sender?.tab?.id;
    const senderOrigin = sender?.url ? new URL(sender.url).origin : '';
    if (!senderTabId || senderTabId !== data.originalTab) {
      bgLog('任务上下文校验失败', {
        taskId: request.taskId,
        senderTabId,
        expectedTabId: data.originalTab
      });
      sendResponse({ success: false, error: '任务上下文校验失败' });
      return true;
    }

    if (senderOrigin && data.targetOrigin && senderOrigin !== data.targetOrigin) {
      bgLog('检测到目标站重定向跨源，按同标签放行凭据读取', {
        taskId: request.taskId,
        senderOrigin,
        expectedOrigin: data.targetOrigin
      });
    }

    // 重要: 不在读取时删除凭据，让TTL自动过期
    // 这样可以支持同一个凭据被多次读取（比如重试、iframe等场景）
    bgLog('凭据读取成功，保留凭据以支持二次读取', { taskId: request.taskId });
    
    sendResponse({
      success: true,
      username: data.username,
      password: data.password,
      extra: data.extra
    });
    return true;
  }

  if (request.action === 'startLoginSession') {
    const tabId = sender?.tab?.id;
    const username = request.username;
    const sessionDurationMs = request.sessionDurationMs;
    const platformUser = getTopIamIdentity().username || username;
    
    bgLog('【会话启动】收到启动会话请求', { tabId, username, platformUser });
    
    if (tabId && username) {
      LoginSession.startSession(String(tabId), platformUser, sessionDurationMs);
      bgLog('✓ 【会话启动】SSO会话已成功创建', { 
        tabId, 
        username: platformUser,
        expiresInMs: LoginSession.sessions.get(String(tabId))?.expiresAt - Date.now()
      });
      sendResponse({ success: true, topiamUsername: platformUser });
    } else {
      bgLog('✗ 【会话启动】缺少必要参数', { tabId, username });
      sendResponse({ success: false, error: '缺少必要参数' });
    }
    return true;
  }

  if (request.action === 'syncTopIamIdentity') {
    const username = String(request.username || '').trim();
    const fullName = String(request.fullName || '').trim();
    const source = String(request.source || sender?.url || 'content-monitor');
    if (!username) {
      sendResponse({ success: false, error: 'empty_username' });
      return true;
    }

    setTopIamIdentity(username, source, fullName);
    setTopIamAuthState(true, source);
    sendResponse({ 
      success: true, 
      username: getTopIamIdentity().username,
      fullName: getTopIamIdentity().fullName || ''
    });
    return true;
  }

  if (request.action === 'topiamUserLoggedOut') {
    const source = String(request.source || sender?.url || 'topiam_logout_signal');
    const sourceLower = source.toLowerCase();
    const previous = getTopIamIdentity().username;

    if (/topiam_page_logout_click(?:$|[^a-z_])/.test(sourceLower) && !/confirmed/.test(sourceLower)) {
      bgLog('收到未确认的TopIAM退出点击信号，已降级忽略', {
        source,
        previousUser: previous || ''
      });
      sendResponse({ success: true, ignored: true, reason: 'unconfirmed_logout_click' });
      return true;
    }

    TOPIAM_IDENTITY = {
      username: '',
      fullName: '',
      updatedAt: Date.now(),
      source
    };
    setTopIamAuthState(false, source);
    chrome.storage.local.set({ [TOPIAM_IDENTITY_KEY]: TOPIAM_IDENTITY }, () => {});

    bgLog('收到TopIAM退出登录信号，开始全局销毁应用会话', {
      source,
      previousUser: previous || ''
    });

    revokeAllAppSessions('topiam_manual_logout')
      .then(() => sendResponse({ success: true }))
      .catch((error) => sendResponse({ success: false, error: error?.message || 'revoke_failed' }));
    return true;
  }

  if (request.action === 'reportTopIamAuthState') {
    const authenticated = Boolean(request.authenticated);
    const username = String(request.username || '').trim();
    const fullName = String(request.fullName || '').trim();
    const source = String(request.source || sender?.url || 'auth_probe');

    if (authenticated && username) {
      setTopIamIdentity(username, source, fullName);
      setTopIamAuthState(true, source);
      sendResponse({ success: true, authenticated: true });
      return true;
    }

    if (!authenticated) {
      const sourceLower = source.toLowerCase();
      const explicitLogoutSignal = /logout_click_confirmed|logout_confirmed|login_page|manual_logout|cookie_expired|http_401|http_403|api_unauthorized|unauth|expired|api_unsuccessful|api_no_username/.test(sourceLower);

      probeTopIamAuthByCookies(`report_auth_state_${sourceLower || 'unknown'}`)
        .then((cookieAuthenticated) => {
          if (cookieAuthenticated) {
            TOPIAM_AUTH_SOFT_FAIL = { count: 0, lastAt: 0 };
            sendResponse({ success: true, authenticated: true, ignored: true });
            return;
          }

          let shouldEscalate = explicitLogoutSignal;
          if (!explicitLogoutSignal) {
            const now = Date.now();
            if (now - TOPIAM_AUTH_SOFT_FAIL.lastAt > 60000) {
              TOPIAM_AUTH_SOFT_FAIL = { count: 0, lastAt: now };
            }
            TOPIAM_AUTH_SOFT_FAIL.count += 1;
            TOPIAM_AUTH_SOFT_FAIL.lastAt = now;

            shouldEscalate = TOPIAM_AUTH_SOFT_FAIL.count >= TOPIAM_AUTH_SOFT_FAIL_ESCALATE_COUNT;

            if (!shouldEscalate) {
              bgLog('TopIAM认证软失效（弱信号），忽略全局会话销毁', {
                source,
                softFailCount: TOPIAM_AUTH_SOFT_FAIL.count,
                escalateAt: TOPIAM_AUTH_SOFT_FAIL_ESCALATE_COUNT
              });
              sendResponse({ success: true, authenticated: true, pendingConfirm: true });
              return;
            }

            bgLog('TopIAM认证软失效达到阈值，升级为会话失效', {
              source,
              softFailCount: TOPIAM_AUTH_SOFT_FAIL.count,
              escalateAt: TOPIAM_AUTH_SOFT_FAIL_ESCALATE_COUNT
            });
          }

          TOPIAM_AUTH_SOFT_FAIL = { count: 0, lastAt: 0 };
          setTopIamAuthState(false, source);
          revokeAllAppSessions('topiam_session_expired_probe')
            .then(() => sendResponse({ success: true, authenticated: false }))
            .catch((error) => sendResponse({ success: false, error: error?.message || 'probe_revoke_failed' }));
        })
        .catch((error) => sendResponse({ success: false, error: error?.message || 'auth_probe_confirm_failed' }));
      return true;
    }

    sendResponse({ success: true, authenticated: isTopIamAuthenticated() });
    return true;
  }

  if (request.action === 'getTopIamIdentity') {
    const identity = getTopIamIdentity();
    sendResponse({ success: true, ...identity, authenticated: isTopIamAuthenticated() });
    return true;
  }

  if (request.action === 'checkAccessPolicy') {
    const pageUrl = request.url;
    const hasTask = Boolean(request.hasTask);
    const tabId = sender?.tab?.id;

    Promise.all([
      refreshPolicyFromStorage(),
      probeTopIamAuthByCookies('check_access_policy')
    ])
      .then(() => {
        const page = new URL(pageUrl);
        const isProtected = PROTECTED_APP_ORIGINS.has(page.origin);
        if (!isProtected || hasTask) {
          sendResponse({ allowed: true, reason: 'not_protected_or_has_task' });
          return;
        }

        // 检查 LaunchGate（最近通过SSO启动）
        const grantedViaLaunchGate = typeof tabId === 'number' ? LaunchGate.check(tabId, page.origin) : false;

        // 检查 LoginSession（用户在SSO有效期内）
        const sessionValid = typeof tabId === 'number' ? LoginSession.isSessionValid(tabId) : false;
        const topiamAuthenticated = isTopIamAuthenticated();

        // 检查是否曾经有过会话（现在可能已过期）
        const hadSessionEver = typeof tabId === 'number' ? LoginSession.hadSessionEver(tabId) : false;

        bgLog('访问策略检查结果', {
          pageOrigin: page.origin,
          tabId,
          hasTask,
          isProtected,
          grantedViaLaunchGate,
          sessionValid,
          hadSessionEver,
          topiamAuthenticated
        });

        if (!topiamAuthenticated) {
          sendResponse({ allowed: false, reason: 'session_expired' });
          return;
        }

        if (grantedViaLaunchGate || sessionValid) {
          const reason = grantedViaLaunchGate ? 'recent_sso_launch' : 'active_sso_session';
          sendResponse({ allowed: true, reason });
        } else if (hadSessionEver && !sessionValid) {
          // 曾经有会话但现在已过期
          bgLog('返回session_expired', { tabId });
          sendResponse({ allowed: false, reason: 'session_expired' });
        } else {
          // 从未有会话
          sendResponse({ allowed: false, reason: 'sso_required' });
        }
      })
      .catch(() => {
        sendResponse({ allowed: true, reason: 'invalid_url' });
      });
    return true;
  }

  if (request.action === 'clearPluginCache') {
    const keys = [
      'topiamDomains',
      'discoveredApps',
      'protectedAppOrigins',
      CRED_CACHE_KEY,
      CRED_CACHE_AES_KEY,
      TOPIAM_IDENTITY_KEY,
      'complexApps'
    ];

    chrome.storage.local.remove(keys, async () => {
      TOPIAM_DOMAINS = [];
      PROTECTED_APP_ORIGINS = new Set();
      TOPIAM_IDENTITY = {
        username: '',
        fullName: '',
        updatedAt: Date.now(),
        source: 'clear_plugin_cache'
      };
      TOPIAM_AUTH_STATE = {
        authenticated: false,
        updatedAt: Date.now(),
        source: 'clear_plugin_cache'
      };

      try {
        await revokeAllAppSessions('plugin_cache_cleared');
      } catch (error) {}

      LaunchGate.grantsByTab.clear();
      TabTaskIndex.records.clear();

      bgLog('插件缓存与运行态已清空');
      sendResponse({ success: true });
    });
    return true;
  }

  if (request.action === 'queryLoginSession') {
    // 查询当前tab的SSO会话状态
    // 不依赖应用是否受保护，直接返回会话信息
    const tabId = sender?.tab?.id;
    
    if (typeof tabId !== 'number') {
      sendResponse({ isValid: false, hadSession: false, username: '', expiresAt: 0, timeLeftMs: 0 });
      return true;
    }
    
    probeTopIamAuthByCookies('query_login_session')
      .then(() => {
        const isSessionValid = LoginSession.isSessionValid(tabId);
        const hadSessionEver = LoginSession.hadSessionEver(tabId);
        const session = LoginSession.sessions.get(String(tabId));

        bgLog('会话查询', {
          tabId,
          isValid: isSessionValid,
          hadSession: hadSessionEver,
          username: session?.username || ''
        });

        sendResponse({
          isValid: isSessionValid,
          hadSession: hadSessionEver,
          username: session?.username || '',
          topiamUsername: getTopIamIdentity().username || session?.username || '',
          topiamFullName: getTopIamIdentity().fullName || '',
          topiamAuthenticated: isTopIamAuthenticated(),
          expiresAt: Number(session?.expiresAt || 0),
          timeLeftMs: Math.max(0, Number(session?.expiresAt || 0) - Date.now())
        });
      })
      .catch(() => {
        sendResponse({ isValid: false, hadSession: false, username: '', topiamUsername: '', topiamAuthenticated: false, expiresAt: 0, timeLeftMs: 0 });
      });
    return true;
  }

  if (request.action === 'clearSiteCookies') {
    const origin = String(request.origin || sender?.url || '').trim();
    if (!origin) {
      sendResponse({ success: false, error: 'empty_origin' });
      return true;
    }

    clearCookiesForOrigin(origin)
      .then((result) => {
        bgLog('已执行应用cookie强制清理', {
          origin,
          matched: result.matched,
          removed: result.removed
        });
        sendResponse({ success: true, ...result });
      })
      .catch((error) => {
        sendResponse({ success: false, error: error?.message || 'clear_cookie_failed' });
      });
    return true;
  }

  if (request.action === 'clearPendingTask') {
    // 清除当前tab的待处理任务（在会话过期时调用）
    const tabId = sender?.tab?.id;
    if (typeof tabId === 'number') {
      TabTaskIndex.remove(tabId);
      bgLog('已清除tab的待处理任务', { tabId });
    }
    sendResponse({ success: true });
    return true;
  }

  if (request.action === 'getPendingTaskForTab') {
    const tabId = sender?.tab?.id;
    const frameId = sender?.frameId;
    const senderOrigin = sender?.url ? new URL(sender.url).origin : '';
    if (typeof tabId !== 'number') {
      sendResponse({ success: false, error: 'invalid_sender_tab' });
      return true;
    }

    // 只允许主 frame 消费待恢复任务，避免 all_frames 场景下被 iframe 提前消费
    if (typeof frameId === 'number' && frameId !== 0) {
      bgLog('忽略非主frame的任务恢复请求', { tabId, frameId, senderOrigin });
      sendResponse({ success: false, error: 'not_top_frame' });
      return true;
    }

    const taskId = TabTaskIndex.consume(tabId, senderOrigin);
    if (!taskId) {
      bgLog('未找到待恢复任务', { tabId, senderOrigin });
      sendResponse({ success: false, error: 'no_pending_task' });
      return true;
    }

    bgLog('按标签页兜底下发任务ID成功', { tabId, senderOrigin, taskId });
    sendResponse({ success: true, taskId });
    return true;
  }

  if (request.action === 'registerTopiamDomain') {
    const domain = request.domain;
    chrome.storage.local.get(['topiamDomains'], (result) => {
      const domains = result.topiamDomains || [];
      if (!domains.includes(domain)) {
        domains.push(domain);
        chrome.storage.local.set({ topiamDomains: domains });
        TOPIAM_DOMAINS = domains;
      }
    });
    sendResponse({ registered: true });
    bgLog('注册TopIAM域名', { domain });
    return true;
  }

  if (request.action === 'updateDomains') {
    TOPIAM_DOMAINS = Array.isArray(request.domains) ? request.domains : [];
    chrome.storage.local.set({ topiamDomains: TOPIAM_DOMAINS });
    sendResponse({ updated: true, domains: TOPIAM_DOMAINS.length });
    return true;
  }

  if (request.action === 'registerDiscoveredApp') {
    bgLog('收到应用发现上报', request.app || {});
    upsertDiscoveredApp(request.app || {})
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: error?.message || '保存失败' }));
    return true;
  }

  if (request.action === 'registerDiscoveredApps') {
    const apps = Array.isArray(request.apps) ? request.apps : [];
    bgLog('收到应用批量发现上报', { count: apps.length });
    upsertDiscoveredApps(apps)
      .then(() => sendResponse({ ok: true, count: apps.length }))
      .catch((error) => sendResponse({ ok: false, error: error?.message || '批量保存失败' }));
    return true;
  }

  if (request.action === 'interceptFormPost') {
    const senderTabId = sender?.tab?.id;
    const payload = request.payload || {};

    const mapped = typeof senderTabId === 'number' ? PREFETCH_GHOST_TABS.get(senderTabId) : null;
    const tabId = mapped?.originalTabId ?? senderTabId;

    if (typeof tabId !== 'number') {
      sendResponse({ ok: false, error: '无有效标签页' });
      return true;
    }

    if (!payload.targetUrl || !payload.username || !payload.password) {
      bgLog('表单拦截数据不完整，放行原生提交', payload);
      sendResponse({ ok: false, error: '表单数据不完整' });
      return true;
    }

    const enrichedPayload = {
      ...payload,
      appId: payload.appId || mapped?.appId || '',
      appName: payload.appName || mapped?.appName || ''
    };

    if (mapped && typeof senderTabId === 'number') {
      const session = PREFETCH_SESSIONS.get(senderTabId);
      const dispatchPayload = {
        ...enrichedPayload,
        sourceUrl: enrichedPayload.sourceUrl || sender?.url || '',
        submitMethod: 'post',
        openInNewTab: Boolean(mapped.openInNewTab),
        destinationTabId: mapped.openInNewTab ? senderTabId : undefined
      };

      dispatchTaskToTarget(tabId, dispatchPayload)
        .then(async () => {
          if (session?.resolve) {
            await session.resolve(dispatchPayload);
          } else {
            PREFETCH_GHOST_TABS.delete(senderTabId);
          }
          sendResponse({ ok: true });
        })
        .catch(async (error) => {
          if (session?.reject) {
            await session.reject(error);
          }
          sendResponse({ ok: false, error: error?.message || '预取派发失败' });
        });
      return true;
    }

    dispatchTaskToTarget(tabId, enrichedPayload)
      .then(async () => {
        if (typeof senderTabId === 'number' && mapped) {
          PREFETCH_GHOST_TABS.delete(senderTabId);
          try {
            await chrome.tabs.remove(senderTabId);
          } catch (error) {}
        }
        sendResponse({ ok: true });
      })
      .catch((error) => sendResponse({ ok: false, error: error?.message || '任务派发失败' }));
    return true;
  }

  if (request.action === 'prefetchInitLogin') {
    const tabId = sender?.tab?.id;
    const initLoginUrl = String(request.initLoginUrl || '').trim();
    const appMeta = request.app || {};
    const openInNewTab = Boolean(request.openInNewTab);

    if (typeof tabId === 'number') {
      sendMonitorDebug(tabId, '收到预取请求', {
        initLoginUrl,
        appId: appMeta?.appId || '',
        appName: appMeta?.appName || '',
        openInNewTab
      });
    }

    if (typeof tabId !== 'number') {
      sendResponse({ ok: false, error: '无有效标签页' });
      return true;
    }

    if (!initLoginUrl) {
      sendResponse({ ok: false, error: 'initLoginUrl 为空' });
      return true;
    }

    setPrefetchInterceptLock(tabId);

    prefetchInitLoginAndDispatch(tabId, initLoginUrl, appMeta, { openInNewTab })
      .then(() => {
        clearPrefetchInterceptLock(tabId);
        sendResponse({ ok: true });
      })
      .catch(async (error) => {
        clearPrefetchInterceptLock(tabId);
        const cached = await getEncryptedCredentialCache({
          appId: appMeta?.appId || '',
          appName: appMeta?.appName || '',
          sourceUrl: initLoginUrl,
          targetUrl: initLoginUrl
        });
        if (cached?.username && cached?.password) {
          try {
            const cachedPayload = {
              sourceUrl: initLoginUrl,
              targetUrl: cached.targetUrl || initLoginUrl,
              submitMethod: cached.submitMethod || 'post',
              username: cached.username,
              password: cached.password,
              extra: cached.extra || {},
              appId: appMeta?.appId || '',
              appName: appMeta?.appName || cached.appName || '',
              openInNewTab
            };
            await dispatchTaskToTarget(tabId, cachedPayload);
            sendMonitorDebug(tabId, '预取失败，已使用加密缓存账密', {
              appId: appMeta?.appId || '',
              username: cached.username,
              hasPassword: Boolean(cached.password),
              targetUrl: cached.targetUrl || initLoginUrl
            });
            sendResponse({ ok: true, fromCache: true });
            return;
          } catch (cacheDispatchError) {
            sendMonitorDebug(tabId, '缓存账密派发失败', {
              error: cacheDispatchError?.message || 'unknown'
            });
          }
        }

        const failureMessage = String(error?.message || 'unknown');
        const missingCredentialLike = /未捕获POST账密|未能提取账密|POST已捕获但未识别到账密字段|未识别到账密字段|账密|凭据/i.test(failureMessage);

        sendMonitorDebug(tabId, '预取失败', { error: failureMessage });
        sendResponse({
          ok: false,
          code: missingCredentialLike ? 'NO_DEFAULT_ACCOUNT' : 'PREFETCH_FAILED',
          error: missingCredentialLike ? '至少需要配置一个默认账户' : (failureMessage || '预取失败')
        });
      });
    return true;
  }
});

chrome.alarms.create('cleanup', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(async () => {
  await probeTopIamAuthByCookies('alarm_cleanup');
  LaunchGate.cleanup();
  TabTaskIndex.cleanup();
  bgLog('定时清理完成');
});

chrome.tabs.onRemoved.addListener((tabId) => {
  TabTaskIndex.remove(tabId);
  PREFETCH_GHOST_TABS.delete(tabId);
  PREFETCH_SESSIONS.delete(tabId);
  PREFETCH_INTERCEPT_LOCKS.delete(tabId);
});

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!isTopIamLogoutRequest(details)) return;
    triggerImmediateTopIamLogout('topiam_logout_api_request');
  },
  { urls: ['<all_urls>'] }
);

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const ghost = PREFETCH_GHOST_TABS.get(details.tabId);
    if (!ghost) return;

    const formData = details.requestBody?.formData;
    const extracted = extractCredentialsFromFormData(formData);
    if (!extracted.username || !extracted.password) {
      sendMonitorDebug(ghost.originalTabId, 'POST已捕获但未识别到账密字段', {
        ghostTabId: details.tabId,
        requestUrl: details.url,
        formKeys: formData ? Object.keys(formData) : []
      });
      return;
    }

    sendMonitorDebug(ghost.originalTabId, '已从POST请求体提取到账密', {
      ghostTabId: details.tabId,
      requestUrl: details.url,
      username: extracted.username,
      hasPassword: Boolean(extracted.password)
    });

    const session = PREFETCH_SESSIONS.get(details.tabId);
    if (!session) return;

    const payload = {
      sourceUrl: '',
      targetUrl: details.url,
      submitMethod: 'post',
      username: extracted.username,
      password: extracted.password,
      extra: extracted.extra,
      appId: ghost.appId || '',
      appName: ghost.appName || '',
      openInNewTab: Boolean(ghost.openInNewTab),
      destinationTabId: ghost.openInNewTab ? details.tabId : undefined
    };

    dispatchTaskToTarget(ghost.originalTabId, payload)
      .then(async () => {
        if (session.resolve) {
          await session.resolve(payload);
        }
      })
      .catch(async (error) => {
        sendMonitorDebug(ghost.originalTabId, 'POST提取后派发失败', {
          error: error?.message || 'unknown'
        });
        if (session.reject) {
          await session.reject(error);
        }
      });
  },
  { urls: ['<all_urls>'] },
  ['requestBody']
);