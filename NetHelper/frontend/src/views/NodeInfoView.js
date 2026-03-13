import { GetProbeNodeInfo } from '../../wailsjs/go/main/App.js';

export default class NodeInfoView {
    constructor(container) {
        this.container = container;
        this.refreshTimer = null;
        this.refreshIntervalMs = 15000;
        this.isLoading = false;
    }

    async mount() {
        this.container.innerHTML = `
            <header class="topbar">
                <div class="view-title">探针节点信息</div>
                <div class="toolbar">
                    <button id="btn-node-refresh" style="padding: 6px 10px; background: #10b981; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600;">
                        强制刷新
                    </button>
                </div>
            </header>
            <main class="view-body" style="padding: 20px;">
                <div class="card" style="background: rgba(40, 50, 70, 0.4); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 20px; max-width: 900px;">
                    <h3 style="margin-bottom: 12px; font-size: 16px; color: #e4e4e7;">探针节点列表</h3>
                    <div id="node-info-status" style="margin-bottom: 14px; color: #a1a1aa; font-size: 13px;">正在加载本地缓存...</div>

                    <div style="overflow:auto; border: 1px solid rgba(255,255,255,0.08); border-radius: 6px;">
                        <table style="width:100%; border-collapse: collapse; font-size: 12px;">
                            <thead>
                                <tr style="background: rgba(15,23,42,0.65); color:#94a3b8;">
                                    <th style="text-align:left; padding:8px; border-bottom:1px solid rgba(255,255,255,0.08);">ID</th>
                                    <th style="text-align:left; padding:8px; border-bottom:1px solid rgba(255,255,255,0.08);">名称</th>
                                    <th style="text-align:left; padding:8px; border-bottom:1px solid rgba(255,255,255,0.08);">IP地址</th>
                                    <th style="text-align:left; padding:8px; border-bottom:1px solid rgba(255,255,255,0.08);">DDNS地址</th>
                                    <th style="text-align:left; padding:8px; border-bottom:1px solid rgba(255,255,255,0.08);">在线</th>
                                    <th style="text-align:left; padding:8px; border-bottom:1px solid rgba(255,255,255,0.08);">版本</th>
                                    <th style="text-align:left; padding:8px; border-bottom:1px solid rgba(255,255,255,0.08);">上报间隔</th>
                                    <th style="text-align:left; padding:8px; border-bottom:1px solid rgba(255,255,255,0.08);">最近心跳</th>
                                </tr>
                            </thead>
                            <tbody id="node-info-tbody"></tbody>
                        </table>
                    </div>
                </div>
            </main>
        `;

        this.bindElements();
        await this.loadNodeInfo(false);

        this.refreshTimer = setInterval(async () => {
            await this.loadNodeInfo(true, true);
        }, this.refreshIntervalMs);
    }

    bindElements() {
        this.statusEl = document.getElementById('node-info-status');
        this.btnRefresh = document.getElementById('btn-node-refresh');
        this.tbody = document.getElementById('node-info-tbody');

        this.btnRefresh.addEventListener('click', async () => {
            await this.loadNodeInfo(true);
        });
    }

    async loadNodeInfo(forceRefresh, silent = false) {
        if (this.isLoading) {
            return;
        }
        this.isLoading = true;

        try {
            if (!silent) {
                this.btnRefresh.disabled = true;
                this.btnRefresh.innerText = forceRefresh ? '刷新中...' : '强制刷新';
                this.statusEl.style.color = '#a1a1aa';
                this.statusEl.innerText = forceRefresh ? '正在从主控拉取最新节点信息...' : '正在读取本地缓存...';
            }

            const data = await GetProbeNodeInfo(forceRefresh);
            this.renderData(data || {});

            this.statusEl.style.color = '#4ade80';
            this.statusEl.innerText = forceRefresh
                ? (silent ? '已自动刷新实时字段。' : '已强制刷新并更新本地缓存。')
                : '已从本地缓存加载。';
        } catch (err) {
            this.statusEl.style.color = '#f87171';
            this.statusEl.innerText = '加载失败: ' + err;
        } finally {
            if (!silent) {
                this.btnRefresh.disabled = false;
                this.btnRefresh.innerText = '强制刷新';
            }
            this.isLoading = false;
        }
    }

    renderData(data) {
        const nodes = Array.isArray(data.nodes) ? data.nodes : [];
        const getText = (v) => (v === undefined || v === null || v === '' ? '-' : String(v));

        if (nodes.length === 0) {
            this.tbody.innerHTML = `<tr><td colspan="8" style="padding: 12px; color:#94a3b8;">暂无探针节点数据</td></tr>`;
            return;
        }

        this.tbody.innerHTML = nodes.map((n) => `
            <tr style="border-bottom:1px solid rgba(255,255,255,0.06);">
                <td style="padding:8px; color:#e2e8f0;">${getText(n.node_id)}</td>
                <td style="padding:8px; color:#e2e8f0;">${getText(n.name)}</td>
                <td style="padding:8px; color:#e2e8f0;">${getText(n.address)}</td>
                <td style="padding:8px; color:#e2e8f0;">${getText(n.ddns_address)}</td>
                <td style="padding:8px; color:${n.online ? '#4ade80' : '#f87171'};">${n.online ? '在线' : '离线'}</td>
                <td style="padding:8px; color:#e2e8f0;">${getText(n.version)}</td>
                <td style="padding:8px; color:#e2e8f0;">${getText(n.report_interval)}</td>
                <td style="padding:8px; color:#e2e8f0;">${getText(n.last_ping_str)}</td>
            </tr>
        `).join('');
    }

    unmount() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
        this.container.innerHTML = '';
    }
}
