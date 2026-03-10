import { GetConnections } from '../../wailsjs/go/main/App.js';

export default class ConnectionsView {
    constructor(container) {
        this.container = container;
        this.pollIntervalId = null;

        // 最新快照
        this.allConnections = [];

        // UI 状态
        this.pinnedProcs = new Set();    // [procName] 置顶大组
        this.collapsedProcs = new Set(); // [procName] 折叠大组
        this.collapsedPids = new Set();  // [pid] 折叠细分组

        // 历史连接上下文 (仅针对 Pinned Procs)
        // procName -> Map(connKey -> { ...conn, _tombstone: true, _diedAt: timestamp })
        this.historyLog = new Map();

        this.filterText = '';
        this.showUdp = true;
        this.showListen = true;
        this.sortKey = 'procName';
        this.sortAsc = true;
        this._lastRenderKey = '';
    }

    mount() {
        const tpl = document.getElementById('tpl-connections').content.cloneNode(true);
        this.container.appendChild(tpl);

        this.bindDOM();
        this.bindEvents();

        this.poll();
        this.pollIntervalId = setInterval(() => this.poll(), 1500);
    }

    unmount() {
        this.container.innerHTML = '';
        if (this.pollIntervalId) {
            clearInterval(this.pollIntervalId);
            this.pollIntervalId = null;
        }
    }

    bindDOM() {
        this.tbody        = document.getElementById('conn-tbody');
        this.loadingEl    = document.getElementById('loading');
        this.emptyHint    = document.getElementById('empty-hint');
        this.connCount    = document.getElementById('conn-count');
        this.procCount    = document.getElementById('proc-count');
        this.lastUpdate   = document.getElementById('last-update');
        this.searchInput  = document.getElementById('search-input');
        this.toggleUdp    = document.getElementById('toggle-udp');
        this.toggleListen = document.getElementById('toggle-listen');

        if (!document.getElementById('ctx-menu')) {
            const menu = document.createElement('div');
            menu.id = 'ctx-menu';
            menu.innerHTML = `
                <div class="menu-item" id="ctx-copy">📋 复制行</div>
            `;
            document.body.appendChild(menu);
        }
        this.ctxMenu = document.getElementById('ctx-menu');
    }

    bindEvents() {
        this.searchInput.addEventListener('input', () => {
            this.filterText = this.searchInput.value.trim().toLowerCase();
            this._lastRenderKey = '';
            this.render();
        });

        this.toggleUdp.addEventListener('change', () => {
            this.showUdp = this.toggleUdp.checked;
            this._lastRenderKey = '';
            this.render();
        });

        this.toggleListen.addEventListener('change', () => {
            this.showListen = this.toggleListen.checked;
            this._lastRenderKey = '';
            this.render();
        });

        document.querySelectorAll('#conn-table thead th[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                const key = th.dataset.sort;
                if (this.sortKey === key) {
                    this.sortAsc = !this.sortAsc;
                } else {
                    this.sortKey = key;
                    this.sortAsc = true;
                }
                document.querySelectorAll('#conn-table thead th').forEach(h => {
                    h.classList.remove('sort-asc', 'sort-desc');
                });
                th.classList.add(this.sortAsc ? 'sort-asc' : 'sort-desc');

                this._lastRenderKey = '';
                this.render();
            });
        });

        document.addEventListener('click', (e) => {
            if (this.ctxMenu && !e.target.closest('#ctx-menu')) {
                this.ctxMenu.style.display = 'none';
            }
        });

        document.getElementById('ctx-copy').addEventListener('click', () => {
            if (!this.ctxTarget) return;
            const c = this.ctxTarget;
            const line = `${c.procName}\t${c.pid}\t${c.protocol}\t${c.localAddr}\t${c.remoteAddr}\t${c.state}`;
            navigator.clipboard.writeText(line).catch(() => {});
            this.ctxMenu.style.display = 'none';
        });
    }

    async poll() {
        try {
            const conns = (await GetConnections()) || [];
            this.mergeHistory(conns);
            this.allConnections = conns;
            
            if (this.loadingEl) this.loadingEl.style.display = 'none';
            this.render();
        } catch (err) {
            console.error('GetConnections error:', err);
        }
    }

    // 核心历史合并逻辑
    mergeHistory(liveConns) {
        // 构建最新的被置顶进程的活跃连接字典，用于比对
        const livePinnedKeys = new Set();
        for (const c of liveConns) {
            if (this.pinnedProcs.has(c.procName)) {
                // 如果当前历史不存在此 proc 的 Map，创建
                if (!this.historyLog.has(c.procName)) {
                    this.historyLog.set(c.procName, new Map());
                }
                const key = `${c.pid}-${c.protocol}-${c.localAddr}-${c.remoteAddr}`;
                livePinnedKeys.add(key);
                
                // 只要还活着的，更新历史表为存活状态
                this.historyLog.get(c.procName).set(key, { ...c, _tombstone: false });
            }
        }

        // 把消失的连接转为 tombstone (墓碑状态)
        for (const [procName, connMap] of this.historyLog.entries()) {
            if (!this.pinnedProcs.has(procName)) {
                // 如果用户取消了置顶，清理它的历史即可
                this.historyLog.delete(procName);
                continue;
            }
            for (const [key, c] of connMap.entries()) {
                if (!livePinnedKeys.has(key)) {
                    // 如果这个连接刚刚断开（即曾经活过，现在没活在 liveConns 里）
                    if (!c._tombstone) {
                        c._tombstone = true;
                        c._diedAt = new Date().toLocaleTimeString('zh-CN', { hour12: false });
                        c.state = 'DISCONNECTED'; // 强行改写状态
                    }
                }
            }
        }
    }

    applyFilters(conns) {
        let result = conns.slice();

        // 注入历史墓碑数据
        for (const [procName, connMap] of this.historyLog.entries()) {
            if (this.pinnedProcs.has(procName)) {
                for (const c of connMap.values()) {
                    if (c._tombstone) result.push(c);
                }
            }
        }

        if (!this.showUdp) result = result.filter(c => c.protocol !== 'UDP');
        if (!this.showListen) result = result.filter(c => c.state !== 'LISTEN' || c._tombstone);
        if (this.filterText) {
            const q = this.filterText;
            result = result.filter(c => 
                c.procName.toLowerCase().includes(q) ||
                c.localAddr.toLowerCase().includes(q) ||
                c.remoteAddr.toLowerCase().includes(q) ||
                String(c.pid).includes(q)
            );
        }

        // 排序
        const key = this.sortKey;
        const asc = this.sortAsc;
        result.sort((a, b) => {
            // 优先按是否置顶排序
            const pa = this.pinnedProcs.has(a.procName) ? 1 : 0;
            const pb = this.pinnedProcs.has(b.procName) ? 1 : 0;
            if (pa !== pb) return pb - pa;

            const va = String(a[key] ?? '');
            const vb = String(b[key] ?? '');
            return asc ? va.localeCompare(vb) : vb.localeCompare(va);
        });

        return result;
    }

    buildTree(filtered) {
        // tree: { procName -> { pids: { pid -> [conn, ...] }, isPinned } }
        const tree = new Map();
        for (const c of filtered) {
            if (!tree.has(c.procName)) {
                tree.set(c.procName, { 
                    procName: c.procName, 
                    isPinned: this.pinnedProcs.has(c.procName),
                    pids: new Map() 
                });
            }
            const procGroup = tree.get(c.procName);
            if (!procGroup.pids.has(c.pid)) {
                procGroup.pids.set(c.pid, []);
            }
            procGroup.pids.get(c.pid).push(c);
        }
        
        // 分组大类排序: 优先置顶，后按字母
        const groups = [...tree.values()];
        groups.sort((a, b) => {
            if (a.isPinned !== b.isPinned) return b.isPinned ? 1 : -1;
            return a.procName.localeCompare(b.procName);
        });
        
        return groups;
    }

    render() {
        const filtered = this.applyFilters(this.allConnections);
        
        // 简易渲染指纹
        const renderKey = filtered.map(c => `${c.pid}${c.localAddr}${c.remoteAddr}${c.state}${c._tombstone}`).join();
        if (renderKey === this._lastRenderKey) return;
        this._lastRenderKey = renderKey;

        const groups = this.buildTree(filtered);
        
        const panel = document.getElementById('connection-panel');
        const scrollTop = panel.scrollTop;

        const fragment = document.createDocumentFragment();

        let liveConnCount = 0;

        for (const procGroup of groups) {
            const procCollapsed = this.collapsedProcs.has(procGroup.procName);
            const icon = procGroup.procName.endsWith('.exe') ? '💻' : '🔧';
            const pinIcon = procGroup.isPinned ? '📌' : '📍';
            
            let totalConns = 0;
            for (const conns of procGroup.pids.values()) totalConns += conns.length;

            // 1) 进程名大组行
            const ptr = document.createElement('tr');
            ptr.className = 'group-row';
            ptr.style.background = procGroup.isPinned ? 'var(--bg-hover)' : 'var(--bg-group)';
            ptr.innerHTML = `
                <td colspan="7">
                    <div class="proc-label">
                        <span class="expand-btn ${procCollapsed ? '' : 'open'}" data-action="toggle-proc" data-name="${procGroup.procName}">▶</span>
                        <span class="pin-btn" data-action="pin-proc" data-name="${procGroup.procName}" title="置顶并记录断开历史" style="cursor:pointer">${pinIcon}</span>
                        <span class="proc-icon">${icon}</span>
                        <strong style="color: ${procGroup.isPinned ? 'var(--warning)' : 'var(--accent)'}">${this.escHtml(procGroup.procName)}</strong>
                        <span class="badge">${totalConns}</span>
                        ${procGroup.isPinned ? '<span style="color:var(--text-muted);font-size:10px;margin-left:8px">(历史记录中)</span>' : ''}
                    </div>
                </td>
            `;
            fragment.appendChild(ptr);

            if (procCollapsed) continue;

            // 2) PID 细分组行
            for (const [pid, conns] of procGroup.pids.entries()) {
                const pidCollapsed = this.collapsedPids.has(pid);
                
                const pidtr = document.createElement('tr');
                pidtr.className = 'group-row pid-row';
                pidtr.style.background = 'var(--bg-row-alt)';
                pidtr.innerHTML = `
                    <td colspan="7">
                        <div class="proc-label" style="padding-left: 20px;">
                            <span class="expand-btn ${pidCollapsed ? '' : 'open'}" data-action="toggle-pid" data-pid="${pid}">▶</span>
                            <span style="color:var(--text-muted);font-weight:500;font-size:11px;font-family:var(--font-mono)">PID: ${pid}</span>
                            <span class="badge" style="background:rgba(255,255,255,0.05);color:var(--text-muted)">${conns.length}</span>
                        </div>
                    </td>
                `;
                fragment.appendChild(pidtr);

                if (pidCollapsed) continue;

                // 3) 连接实例
                for (const conn of conns) {
                    if (!conn._tombstone) liveConnCount++;

                    const ctr = document.createElement('tr');
                    ctr.className = 'conn-row';
                    if (conn._tombstone) {
                        ctr.style.opacity = '0.5';
                        ctr.style.filter = 'grayscale(1)';
                    }
                    ctr.innerHTML = `
                        <td></td>
                        <td title="${this.escHtml(conn.procName)}">${this.escHtml(conn.procName)}</td>
                        <td style="color:var(--text-muted)">${conn.pid}</td>
                        <td><span class="proto-badge ${conn.protocol.toLowerCase()}">${conn.protocol}</span></td>
                        <td title="${this.escHtml(conn.localAddr)}">${this.escHtml(conn.localAddr)}</td>
                        <td title="${this.escHtml(conn.remoteAddr)}">${this.escHtml(conn.remoteAddr)}</td>
                        <td>
                            <span class="state-badge ${this.stateClass(conn.state)}">${this.escHtml(conn.state)}</span>
                            ${conn._tombstone ? `<span style="font-size:9px;color:red;margin-left:4px">[断开于 ${conn._diedAt}]</span>` : ''}
                        </td>
                    `;
                    ctr.addEventListener('contextmenu', (e) => this.showCtxMenu(e, conn));
                    fragment.appendChild(ctr);
                }
            }
        }

        this.tbody.innerHTML = '';
        this.tbody.appendChild(fragment);

        // 重新绑定点击事件（使用事件委托更佳，这里直接查询添加）
        this.tbody.querySelectorAll('[data-action="toggle-proc"]').forEach(el => {
            el.addEventListener('click', (e) => {
                const name = el.dataset.name;
                if (this.collapsedProcs.has(name)) this.collapsedProcs.delete(name);
                else this.collapsedProcs.add(name);
                this._lastRenderKey = '';
                this.render();
            });
        });

        this.tbody.querySelectorAll('[data-action="pin-proc"]').forEach(el => {
            el.addEventListener('click', (e) => {
                const name = el.dataset.name;
                if (this.pinnedProcs.has(name)) this.pinnedProcs.delete(name);
                else this.pinnedProcs.add(name);
                this._lastRenderKey = '';
                this.render();
            });
        });

        this.tbody.querySelectorAll('[data-action="toggle-pid"]').forEach(el => {
            el.addEventListener('click', (e) => {
                const pid = parseInt(el.dataset.pid);
                if (this.collapsedPids.has(pid)) this.collapsedPids.delete(pid);
                else this.collapsedPids.add(pid);
                this._lastRenderKey = '';
                this.render();
            });
        });

        panel.scrollTop = scrollTop;

        this.connCount.textContent  = `活动连接: ${liveConnCount}`;
        this.procCount.textContent  = `置顶常驻: ${this.pinnedProcs.size} | 瞬时进程: ${groups.length}`;
        const d = new Date();
        this.lastUpdate.textContent = `上次采集: ${d.toLocaleTimeString('zh-CN', { hour12: false })}`;
        
        if (filtered.length === 0) {
            this.emptyHint.style.display = 'block';
        } else {
            this.emptyHint.style.display = 'none';
        }
    }

    stateClass(state) {
        switch (state) {
            case 'ESTABLISHED': return 'established';
            case 'LISTEN':      return 'listen';
            case 'TIME_WAIT':   return 'time-wait';
            case 'CLOSE_WAIT':  return 'close-wait';
            case 'DISCONNECTED': return 'other'; // red handled via inline style
            default:            return 'other';
        }
    }

    escHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    showCtxMenu(e, conn) {
        e.preventDefault();
        this.ctxTarget = conn;
        this.ctxMenu.style.left = `${e.clientX}px`;
        this.ctxMenu.style.top  = `${e.clientY}px`;
        this.ctxMenu.style.display = 'block';
    }
}
