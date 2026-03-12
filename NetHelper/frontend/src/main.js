import DashboardView from './views/DashboardView.js';
import ConnectionsView from './views/ConnectionsView.js';
import SettingsView from './views/SettingsView.js';

// ── 简易路由配置 ──
const routes = {
    'dashboard': DashboardView,
    'connections': ConnectionsView,
    // 其他占位:
    'proxies': class { mount() { document.getElementById('main-content').innerHTML = '<div style="padding:20px">节点配置开发中...</div>'; } unmount() {} },
    'settings': SettingsView
};

let currentView = null;

function navigateTo(target) {
    if (!routes[target]) target = 'dashboard';

    // 更新导航侧边栏高亮状态
    document.querySelectorAll('.nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.target === target);
    });

    const mainContent = document.getElementById('main-content');
    
    // 卸载旧视图 (停止其后台轮询等)
    if (currentView && typeof currentView.unmount === 'function') {
        currentView.unmount();
    }

    // 挂载新视图
    const ViewClass = routes[target];
    currentView = new ViewClass(mainContent);
    currentView.mount();
}

// ── 绑定导航事件 ──
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        const target = item.dataset.target;
        window.location.hash = target;
    });
});

window.addEventListener('hashchange', () => {
    const hash = window.location.hash.substring(1) || 'dashboard';
    navigateTo(hash);
});

// ── 初始化应用 ──
function initApp() {
    // 默认打开活动连接页面方便测试
    const initialHash = window.location.hash.substring(1) || 'connections';
    navigateTo(initialHash);
}

// 当 DOM 准备好后启动
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}
