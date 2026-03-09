/**
 * NetHelper — F7 连接面板 (main.js)
 * 轮询 GetConnections()，按进程分组渲染可折叠表格
 */

import { GetConnections } from '../wailsjs/go/main/App';

// ── 状态 ──────────────────────────────────────────────────
let allConnections = [];   // 最新快照
let collapsed = new Set(); // 已折叠的 PID
let sortKey = 'procName';
let sortAsc = true;
let filterText = '';
let showUdp = true;
let showListen = true;

// ── DOM ───────────────────────────────────────────────────
const tbody        = document.getElementById('conn-tbody');
const loadingEl    = document.getElementById('loading');
const emptyHint    = document.getElementById('empty-hint');
const statusDot    = document.getElementById('status-indicator');
const statusText   = document.getElementById('status-text');
const connCount    = document.getElementById('conn-count');
const procCount    = document.getElementById('proc-count');
const lastUpdate   = document.getElementById('last-update');
const searchInput  = document.getElementById('search-input');
const toggleUdp    = document.getElementById('toggle-udp');
const toggleListen = document.getElementById('toggle-listen');
const ctxMenu      = document.getElementById('ctx-menu');

// ── 创建右键菜单 DOM ─────────────────────────────────────
function buildContextMenu() {
    const menu = document.createElement('div');
    menu.id = 'ctx-menu';
    menu.innerHTML = `
        <div class="menu-item" id="ctx-kill">⚡ 断开连接 <small style="color:#64748b">(占位)</small></div>
        <div class="menu-sep"></div>
        <div class="menu-item" id="ctx-trace">🔍 追踪路由 <small style="color:#64748b">(占位)</small></div>
        <div class="menu-item" id="ctx-copy">📋 复制行</div>
    `;
    document.body.appendChild(menu);
    return menu;
}
const contextMenu = buildContextMenu();

// ── 工具函数 ─────────────────────────────────────────────
function stateClass(state) {
    switch (state) {
        case 'ESTABLISHED': return 'established';
        case 'LISTEN':      return 'listen';
        case 'TIME_WAIT':   return 'time-wait';
        case 'CLOSE_WAIT':  return 'close-wait';
        default:            return 'other';
    }
}

function formatTime(d) {
    return d.toLocaleTimeString('zh-CN', { hour12: false });
}

function escHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

// ── 过滤 ─────────────────────────────────────────────────
function applyFilters(conns) {
    let result = conns;
    if (!showUdp)   result = result.filter(c => c.protocol !== 'UDP');
    if (!showListen) result = result.filter(c => c.state !== 'LISTEN');
    if (filterText) {
        const q = filterText.toLowerCase();
        result = result.filter(c =>
            c.procName.toLowerCase().includes(q) ||
            c.localAddr.toLowerCase().includes(q) ||
            c.remoteAddr.toLowerCase().includes(q) ||
            String(c.pid).includes(q)
        );
    }
    return result;
}

// ── 按进程分组 ────────────────────────────────────────────
function groupByProc(conns) {
    const map = new Map(); // pid → { procName, connections[] }
    for (const c of conns) {
        if (!map.has(c.pid)) {
            map.set(c.pid, { procName: c.procName, pid: c.pid, connections: [] });
        }
        map.get(c.pid).connections.push(c);
    }
    // 排序分组
    const groups = [...map.values()];
    groups.sort((a, b) => a.procName.localeCompare(b.procName));
    return groups;
}

// ── 渲染 ─────────────────────────────────────────────────
let _lastRenderKey = '';

function render() {
    const filtered = applyFilters(allConnections);
    const groups   = groupByProc(filtered);

    // 快速对比，避免不必要的 DOM 重绘
    const renderKey = JSON.stringify(filtered.map(c => `${c.pid}${c.localAddr}${c.remoteAddr}${c.state}`));
    if (renderKey === _lastRenderKey) return;
    _lastRenderKey = renderKey;

    // 保存当前滚动位置
    const panel = document.getElementById('connection-panel');
    const scrollTop = panel.scrollTop;

    const fragment = document.createDocumentFragment();

    for (const group of groups) {
        const isCollapsed = collapsed.has(group.pid);
        const emoji = group.procName.endsWith('.exe') ? '💻' : '🔧';

        // 进程分组行
        const gtr = document.createElement('tr');
        gtr.className = 'group-row';
        gtr.dataset.pid = group.pid;
        gtr.innerHTML = `
            <td colspan="7">
                <div class="proc-label">
                    <span class="expand-btn ${isCollapsed ? '' : 'open'}">▶</span>
                    <span class="proc-icon">${emoji}</span>
                    <strong>${escHtml(group.procName)}</strong>
                    <span style="color:var(--text-muted);font-weight:400;font-size:11px;font-family:var(--font-mono)">
                        PID: ${group.pid}
                    </span>
                    <span class="badge">${group.connections.length}</span>
                </div>
            </td>
        `;
        gtr.addEventListener('click', () => toggleGroup(group.pid));
        fragment.appendChild(gtr);

        // 连接子行
        for (const conn of group.connections) {
            const ctr = document.createElement('tr');
            ctr.className = `conn-row${isCollapsed ? ' hidden' : ''}`;
            ctr.dataset.pid = group.pid;
            ctr.dataset.local   = conn.localAddr;
            ctr.dataset.remote  = conn.remoteAddr;
            ctr.dataset.proto   = conn.protocol;
            ctr.dataset.state   = conn.state;
            ctr.innerHTML = `
                <td></td>
                <td title="${escHtml(conn.procName)}">${escHtml(conn.procName)}</td>
                <td style="color:var(--text-muted)">${conn.pid}</td>
                <td><span class="proto-badge ${conn.protocol.toLowerCase()}">${conn.protocol}</span></td>
                <td title="${escHtml(conn.localAddr)}">${escHtml(conn.localAddr)}</td>
                <td title="${escHtml(conn.remoteAddr)}">${escHtml(conn.remoteAddr)}</td>
                <td><span class="state-badge ${stateClass(conn.state)}">${escHtml(conn.state)}</span></td>
            `;
            ctr.addEventListener('contextmenu', (e) => showCtxMenu(e, conn));
            fragment.appendChild(ctr);
        }
    }

    tbody.innerHTML = '';
    tbody.appendChild(fragment);

    // 恢复滚动
    panel.scrollTop = scrollTop;

    // 状态栏
    const totalConns = filtered.length;
    const totalProcs = groups.length;
    connCount.textContent  = `连接总数: ${totalConns}`;
    procCount.textContent  = `进程数: ${totalProcs}`;
    lastUpdate.textContent = `上次刷新: ${formatTime(new Date())}`;

    emptyHint.style.display = totalConns === 0 ? 'block' : 'none';
}

function toggleGroup(pid) {
    if (collapsed.has(pid)) {
        collapsed.delete(pid);
    } else {
        collapsed.add(pid);
    }
    // 切换子行显示
    document.querySelectorAll(`tr.conn-row[data-pid="${pid}"]`).forEach(tr => {
        tr.classList.toggle('hidden', collapsed.has(pid));
    });
    // 切换按钮状态
    const gtr = document.querySelector(`tr.group-row[data-pid="${pid}"] .expand-btn`);
    if (gtr) gtr.classList.toggle('open', !collapsed.has(pid));
}

// ── 右键菜单 ─────────────────────────────────────────────
let ctxTarget = null;

function showCtxMenu(e, conn) {
    e.preventDefault();
    ctxTarget = conn;
    contextMenu.style.left = `${e.clientX}px`;
    contextMenu.style.top  = `${e.clientY}px`;
    contextMenu.style.display = 'block';
}

document.addEventListener('click', () => { contextMenu.style.display = 'none'; });

document.getElementById('ctx-copy').addEventListener('click', () => {
    if (!ctxTarget) return;
    const line = `${ctxTarget.procName}\t${ctxTarget.pid}\t${ctxTarget.protocol}\t${ctxTarget.localAddr}\t${ctxTarget.remoteAddr}\t${ctxTarget.state}`;
    navigator.clipboard.writeText(line).catch(() => {});
});

// ── 排序（表头点击） ──────────────────────────────────────
document.querySelectorAll('#conn-table thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
        const key = th.dataset.sort;
        if (sortKey === key) {
            sortAsc = !sortAsc;
        } else {
            sortKey = key;
            sortAsc = true;
        }
        // 更新表头样式
        document.querySelectorAll('#conn-table thead th').forEach(h => {
            h.classList.remove('sort-asc', 'sort-desc');
        });
        th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');

        allConnections.sort((a, b) => {
            const va = String(a[key] ?? '');
            const vb = String(b[key] ?? '');
            return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
        });
        _lastRenderKey = '';
        render();
    });
});

// ── 搜索 + 筛选 ───────────────────────────────────────────
searchInput.addEventListener('input', () => {
    filterText = searchInput.value.trim();
    _lastRenderKey = '';
    render();
});

toggleUdp.addEventListener('change', () => {
    showUdp = toggleUdp.checked;
    _lastRenderKey = '';
    render();
});

toggleListen.addEventListener('change', () => {
    showListen = toggleListen.checked;
    _lastRenderKey = '';
    render();
});

// ── 轮询 ─────────────────────────────────────────────────
async function poll() {
    try {
        const conns = await GetConnections();
        allConnections = conns || [];
        loadingEl.style.display = 'none';
        statusDot.className = 'status-dot ok';
        statusText.textContent = '已连接';
        render();
    } catch (err) {
        statusDot.className = 'status-dot err';
        statusText.textContent = '获取失败';
        console.error('GetConnections error:', err);
    }
}

// 立即执行一次，然后每 1.5s 刷新
poll();
setInterval(poll, 1500);
