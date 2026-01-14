/* Author: Denis Podgurskii */

export class ptk_controller_index {

    init() {
        let self = this
        return browser.runtime.sendMessage({ channel: "ptk_popup2background_dashboard", type: "init" })
            .then(function (result) {
                Object.assign(self, result)
                return self
            }).catch(e => e)
    }

    async complete(wappalyzer) {
        let self = this
        browser.runtime.sendMessage({ channel: "ptk_popup2background_dashboard", type: "analyze", info: wappalyzer }).catch(e => e)
        return Promise.resolve()
    }

    async get() {
        let self = this
        return browser.runtime.sendMessage({ channel: "ptk_popup2background_dashboard", type: "get" })
            .then(function (result) {
                Object.assign(self, result)
                return self
            }).catch(e => e)
    }

    async save(items) {
        return browser.runtime.sendMessage({ channel: "ptk_popup2background_dashboard", type: "save", items: items }).catch(e => e)
    }

    async runBackroungScan(tabId, host, domains, scans, settings) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "run_bg_scan",
            tabId: tabId,
            host: host,
            domains: domains,
            scans: scans,
            settings: settings
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async stopBackroungScan(scans) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "stop_bg_scan",
            scans: scans
        }).then(response => {
            return response
        }).catch(e => e)
    }

}
