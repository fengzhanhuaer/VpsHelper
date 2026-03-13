import { GetSettings, SaveSettings, CheckUpdate, DoUpdate, GetVersion } from '../../wailsjs/go/main/App.js';
import { EventsOn } from '../../wailsjs/runtime/runtime.js';

export default class SettingsView {
    constructor(container) {
        this.container = container;
        this.updateProgressUnsubscribe = null;
    }

    async mount() {
        this.container.innerHTML = `
            <div class="settings-container" style="padding: 20px; color: #e4e4e7;">
                <h2 style="margin-bottom: 20px;">系统设置</h2>
                
                <div class="card" style="background: rgba(40, 50, 70, 0.4); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 20px; margin-bottom: 20px;">
                    <h3 style="margin-bottom: 15px; font-size: 16px;">主控连接配置</h3>
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; color: #a1a1aa;">主控服务器地址 (Server URL)</label>
                        <input type="text" id="setting-server-url" placeholder="例如: https://your-master-node.com" style="width: 100%; max-width: 400px; padding: 10px; border-radius: 4px; border: 1px solid #3f3f46; background: #18181b; color: #fff;">
                    </div>
                    <div style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 5px; color: #a1a1aa;">节点密钥 (Secret Key)</label>
                        <input type="password" id="setting-secret-key" placeholder="输入主控端生成的 Secret Key" style="width: 100%; max-width: 400px; padding: 10px; border-radius: 4px; border: 1px solid #3f3f46; background: #18181b; color: #fff;">
                    </div>
                    <button id="btn-save-settings" style="padding: 10px 20px; background: #3b82f6; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; transition: background 0.2s;">
                        保存配置
                    </button>
                    <span id="save-msg" style="margin-left: 10px; color: #4ade80; display: none;">保存成功！</span>
                </div>

                <div class="card" style="background: rgba(40, 50, 70, 0.4); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 20px;">
                    <h3 style="margin-bottom: 15px; font-size: 16px;">检查更新<span id="current-version-display" style="font-size: 13px; font-weight: normal; color: #a1a1aa; margin-left: 10px;">当前版本: 获取中...</span></h3>
                    <div style="margin-bottom: 15px; color: #a1a1aa; font-size: 14px;">
                        <label style="margin-right: 15px;">
                            <input type="radio" name="update-mode" value="direct" checked> GitHub 直连下载
                        </label>
                        <label>
                            <input type="radio" name="update-mode" value="proxy"> 通过主控代理下载
                        </label>
                    </div>
                    <button id="btn-check-update" style="padding: 10px 20px; background: #10b981; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; transition: background 0.2s;">
                        检查新版本
                    </button>
                    
                    <div id="update-info-area" style="margin-top: 15px; display: none; padding: 15px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 4px;">
                        <div style="margin-bottom: 10px;">发现新版本: <span id="new-version-text" style="font-weight: bold; color: #10b981;"></span></div>
                        <button id="btn-do-update" style="padding: 8px 16px; background: #f59e0b; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            立即下载并更新
                        </button>
                        <div id="update-status" style="margin-top: 10px; font-size: 13px; color: #fbbf24; display: none;">正在下载更新包...</div>
                    </div>
                </div>
            </div>
        `;

        this.bindEvents();
        await this.loadSettings();
    }

    async loadSettings() {
        try {
            const cfg = await GetSettings();
            if (cfg) {
                document.getElementById('setting-server-url').value = cfg.server_url || '';
                document.getElementById('setting-secret-key').value = cfg.secret_key || '';
            }
            try {
                const ver = await GetVersion();
                document.getElementById('current-version-display').innerText = `当前版本: ${ver}`;
            } catch (verErr) {
                console.error("Failed to load version:", verErr);
                document.getElementById('current-version-display').innerText = "当前版本: 未知";
            }
        } catch (err) {
            console.error("Failed to load settings:", err);
        }
    }

    bindEvents() {
        const btnSave = document.getElementById('btn-save-settings');
        const msgSave = document.getElementById('save-msg');
        
        btnSave.addEventListener('click', async () => {
            const url = document.getElementById('setting-server-url').value.trim();
            const key = document.getElementById('setting-secret-key').value.trim();
            try {
                btnSave.disabled = true;
                btnSave.innerText = "保存中...";
                await SaveSettings(url, key);
                msgSave.style.display = 'inline-block';
                setTimeout(() => { msgSave.style.display = 'none'; }, 3000);
            } catch (err) {
                alert("保存失败: " + err);
            } finally {
                btnSave.disabled = false;
                btnSave.innerText = "保存配置";
            }
        });

        // 检查更新逻辑
        const btnCheck = document.getElementById('btn-check-update');
        const infoArea = document.getElementById('update-info-area');
        const verText = document.getElementById('new-version-text');
        const btnDo = document.getElementById('btn-do-update');
        const statusText = document.getElementById('update-status');

        if (this.updateProgressUnsubscribe) {
            this.updateProgressUnsubscribe();
            this.updateProgressUnsubscribe = null;
        }
        this.updateProgressUnsubscribe = EventsOn('nethelper:update:progress', (payload) => {
            const msg = Array.isArray(payload) ? payload[0] : payload;
            if (!msg) return;
            statusText.style.display = 'block';
            statusText.innerText = String(msg);
        });

        let currentUpdateInfo = null;
        let isUsingProxy = false;

        btnCheck.addEventListener('click', async () => {
            try {
                btnCheck.disabled = true;
                btnCheck.innerText = "检查中...";
                infoArea.style.display = 'none';
                statusText.style.display = 'none';

                isUsingProxy = document.querySelector('input[name="update-mode"]:checked').value === 'proxy';
                
                const res = await CheckUpdate(isUsingProxy);
                if (res && res.has_update) {
                    currentUpdateInfo = res;
                    verText.innerText = res.version;
                    infoArea.style.display = 'block';
                } else {
                    alert("当前已是最新版本");
                }
            } catch (err) {
                alert("检查更新出错: " + err);
            } finally {
                btnCheck.disabled = false;
                btnCheck.innerText = "检查新版本";
            }
        });

        btnDo.addEventListener('click', async () => {
            if (!currentUpdateInfo) return;
            try {
                btnDo.disabled = true;
                btnCheck.disabled = true;
                statusText.style.display = 'block';
                statusText.innerText = "准备开始升级...";
                
                await DoUpdate(isUsingProxy, currentUpdateInfo.version, currentUpdateInfo.urls);
                alert("更新成功！NetHelper 即将重启。");
            } catch (err) {
                statusText.innerText = "更新失败: " + err;
                btnDo.disabled = false;
                btnCheck.disabled = false;
            }
        });
    }

    unmount() {
        if (this.updateProgressUnsubscribe) {
            this.updateProgressUnsubscribe();
            this.updateProgressUnsubscribe = null;
        }
        this.container.innerHTML = '';
    }
}
