document.addEventListener('DOMContentLoaded', () => {
  const domainsInput = document.getElementById('domains');
  const saveBtn = document.getElementById('saveBtn');
  const clearCacheBtn = document.getElementById('clearCacheBtn');
  const debugPanelEnabledInput = document.getElementById('debugPanelEnabled');
  const statusDiv = document.getElementById('status');
  const appListDiv = document.getElementById('appList');
  
  // 加载配置
  chrome.storage.local.get(['topiamDomains', 'discoveredApps', 'debugPanelEnabled'], (result) => {
    if (Array.isArray(result.topiamDomains) && result.topiamDomains.length > 0) {
      domainsInput.value = result.topiamDomains.join(', ');
      statusDiv.textContent = '状态: 已配置 (' + result.topiamDomains.length + ' 个域名)';
      statusDiv.className = 'status active';
    } else {
      statusDiv.textContent = '状态: 等待自动发现或手动配置';
      statusDiv.className = 'status inactive';
    }

    debugPanelEnabledInput.checked = result.debugPanelEnabled !== false;
    
    if (result.discoveredApps && result.discoveredApps.length > 0) {
      renderApps(result.discoveredApps);
    }
  });
  
  saveBtn.addEventListener('click', () => {
    const domains = domainsInput.value.split(',').map(s => s.trim()).filter(s => s);
    chrome.storage.local.set({
      topiamDomains: domains,
      debugPanelEnabled: debugPanelEnabledInput.checked
    }, () => {
      statusDiv.textContent = '状态: 已配置 (' + domains.length + ' 个域名)';
      statusDiv.className = 'status active';
      
      // 通知background更新
      chrome.runtime.sendMessage({ action: 'updateDomains', domains });
    });
  });

  debugPanelEnabledInput.addEventListener('change', () => {
    chrome.storage.local.set({ debugPanelEnabled: debugPanelEnabledInput.checked });
  });

  clearCacheBtn.addEventListener('click', () => {
    const ok = window.confirm('确认清除插件缓存？这会清空已发现应用、域名和凭据缓存。');
    if (!ok) return;

    const keys = [
      'topiamDomains',
      'discoveredApps',
      'protectedAppOrigins',
      'topiamEncryptedCredentialCache',
      'topiamCredentialAesKey',
      'topiamCurrentIdentity',
      'complexApps',
      'debugPanelEnabled'
    ];

    chrome.storage.local.remove(keys, () => {
      chrome.runtime.sendMessage({ action: 'clearPluginCache' }, () => {
        domainsInput.value = '';
        debugPanelEnabledInput.checked = true;
        statusDiv.textContent = '状态: 缓存已清除，请重新配置';
        statusDiv.className = 'status inactive';
        appListDiv.innerHTML = '<div style="color: #999; font-size: 12px;">暂无，点击TopIAM应用后自动识别</div>';
        chrome.runtime.sendMessage({ action: 'updateDomains', domains: [] });
      });
    });
  });
  
  function renderApps(apps) {
    appListDiv.innerHTML = apps.map(app => `
      <div class="app-item">
        <span>${app.name || '未知应用'}</span>
        <span style="color: #666;">${app.realTargetUrl || app.targetUrl || '待预访问提取真实URL'}</span>
      </div>
    `).join('');
  }
});