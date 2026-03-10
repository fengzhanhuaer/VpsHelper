export default class DashboardView {
    constructor(container) {
        this.container = container;
    }

    mount() {
        const tpl = document.getElementById('tpl-dashboard').content.cloneNode(true);
        this.container.appendChild(tpl);
    }

    unmount() {
        this.container.innerHTML = '';
    }
}
