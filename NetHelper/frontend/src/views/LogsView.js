import { GetRuntimeLogs } from '../../wailsjs/go/main/App.js';
import { EventsOn } from '../../wailsjs/runtime/runtime.js';

export default class LogsView {
    constructor(container) {
        this.container = container;
        this.unsubscribe = null;
        this.lines = [];
        this.maxLines = 1000;
        this.autoScroll = true;
    }

    async mount() {
        this.container.innerHTML = `
            <header class="topbar">
                <div class="view-title">运行日志</div>
                <div class="toolbar">
                    <label class="toggle-label">
                        <input type="checkbox" id="logs-auto-scroll" checked />
                        自动滚动
                    </label>
                    <button id="logs-clear-btn" style="padding: 6px 10px; background: var(--bg-row); color: var(--text-primary); border: 1px solid var(--border); border-radius: var(--radius-sm); cursor: pointer;">清空窗口</button>
                </div>
            </header>
            <main class="view-body" style="padding: 12px;">
                <div style="height: 100%; border: 1px solid var(--border); background: var(--bg-panel); border-radius: var(--radius); overflow: hidden; display: flex; flex-direction: column;">
                    <div style="padding: 8px 10px; border-bottom: 1px solid var(--border); color: var(--text-secondary); font-size: 12px;">
                        实时显示 NetHelper 运行日志（仅展示最近 ${this.maxLines} 条）
                    </div>
                    <pre id="runtime-logs-pre" style="margin: 0; flex: 1; padding: 10px; overflow: auto; font-family: var(--font-mono); font-size: 12px; line-height: 1.55; color: var(--text-primary);"></pre>
                </div>
            </main>
        `;

        this.logEl = document.getElementById('runtime-logs-pre');
        const autoScrollEl = document.getElementById('logs-auto-scroll');
        const clearBtn = document.getElementById('logs-clear-btn');

        autoScrollEl.addEventListener('change', () => {
            this.autoScroll = autoScrollEl.checked;
            if (this.autoScroll) {
                this.scrollToBottom();
            }
        });

        clearBtn.addEventListener('click', () => {
            this.lines = [];
            this.render();
        });

        try {
            const initial = await GetRuntimeLogs(this.maxLines);
            if (Array.isArray(initial)) {
                this.lines = initial.slice(-this.maxLines);
                this.render();
            }
        } catch (e) {
            this.pushLine(`加载历史日志失败: ${e}`);
        }

        this.unsubscribe = EventsOn('nethelper:runtime:log', (payload) => {
            const line = Array.isArray(payload) ? payload[0] : payload;
            if (!line) return;
            this.pushLine(String(line));
        });
    }

    pushLine(line) {
        this.lines.push(line);
        if (this.lines.length > this.maxLines) {
            this.lines = this.lines.slice(this.lines.length - this.maxLines);
        }
        this.render();
    }

    render() {
        if (!this.logEl) return;
        this.logEl.textContent = this.lines.join('\n');
        if (this.autoScroll) {
            this.scrollToBottom();
        }
    }

    scrollToBottom() {
        if (!this.logEl) return;
        this.logEl.scrollTop = this.logEl.scrollHeight;
    }

    unmount() {
        if (this.unsubscribe) {
            this.unsubscribe();
            this.unsubscribe = null;
        }
        this.container.innerHTML = '';
    }
}
