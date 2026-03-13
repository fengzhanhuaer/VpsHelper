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
                <div class="view-title">节点信息</div>
                <div class="toolbar">
                    <button id="btn-node-refresh" style="padding: 6px 10px; background: #10b981; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600;">
                        强制刷新
                    </button>
                </div>
            </header>
            <main class="view-body" style="padding: 20px;">
                <div class="card" style="background: rgba(40, 50, 70, 0.4); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 20px; max-width: 900px;">
                    <h3 style="margin-bottom: 12px; font-size: 16px; color: #e4e4e7;">探针节点详情</h3>
                    <div id="node-info-status" style="margin-bottom: 14px; color: #a1a1aa; font-size: 13px;">正在加载本地缓存...</div>

                    <div style="display: grid; grid-template-columns: 180px 1fr; row-gap: 10px; column-gap: 10px; font-size: 13px;">
                        <div style="color:#94a3b8;">节点ID</div><div id="node-field-id" style="color:#e2e8f0;">-</div>
                        <div style="color:#94a3b8;">节点名称</div><div id="node-field-name" style="color:#e2e8f0;">-</div>
                        <div style="color:#94a3b8;">IP地址</div><div id="node-field-address" style="color:#e2e8f0;">-</div>
                        <div style="color:#94a3b8;">DDNS地址</div><div id="node-field-ddns" style="color:#e2e8f0;">-</div>
                        <div style="color:#94a3b8;">主控地址</div><div id="node-field-server" style="color:#e2e8f0; word-break: break-all;">-</div>
                        <div style="color:#94a3b8;">上报间隔(秒)</div><div id="node-field-interval" style="color:#e2e8f0;">-</div>
                        <div style="color:#94a3b8;">最近更新时间</div><div id="node-field-updated" style="color:#e2e8f0;">-</div>
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

        this.fieldNodeID = document.getElementById('node-field-id');
        this.fieldName = document.getElementById('node-field-name');
        this.fieldAddress = document.getElementById('node-field-address');
        this.fieldDDNS = document.getElementById('node-field-ddns');
        this.fieldServer = document.getElementById('node-field-server');
        this.fieldInterval = document.getElementById('node-field-interval');
        this.fieldUpdated = document.getElementById('node-field-updated');

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
        const getText = (v) => (v === undefined || v === null || v === '' ? '-' : String(v));

        this.fieldNodeID.innerText = getText(data.node_id);
        this.fieldName.innerText = getText(data.name);
        this.fieldAddress.innerText = getText(data.address);
        this.fieldDDNS.innerText = getText(data.ddns_address);
        this.fieldServer.innerText = getText(data.server_url);
        this.fieldInterval.innerText = getText(data.report_interval);
        this.fieldUpdated.innerText = getText(data.updated_at);
    }

    unmount() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
        this.container.innerHTML = '';
    }
}
