/* Author: Denis Podgurskii */
import { ptk_utils, ptk_logger, ptk_queue, ptk_storage, ptk_ruleManager } from "../background/utils.js"
import {
    createScanResultEnvelope
} from "./common/scanResults.js"
import retire from '../packages/retire/retire.js';
import CryptoES from '../packages/crypto-es/index.js';

const worker = self

export class ptk_sca {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_sca"
        this.repoReady = null
        this.activeTabId = null
        this.resetScanResult()

        this.addMessageListeners()
    }

    async init() {

        if (!this.isScanRunning) {
            this.storage = await ptk_storage.getItem(this.storageKey) || {}
            if (Object.keys(this.storage).length > 0) {
                this.scanResult = this._normalizeEnvelope(this.storage)
            }
        }
    }

    async initRepo() {
        if (this.repoReady) {
            return this.repoReady
        }
        this.repoReady = fetch(browser.runtime.getURL('ptk/packages/retire/jsrepository.json'))
            .then(response => response.text())
            .then(data => {
                this.repo = JSON.parse(retire.replaceVersion(data))
                return this.repo
            })
            .catch(error => {
                ptk_logger.log(error, "Failed to initialize SCA repository", "warning")
                this.repo = {}
                this.repoReady = null
                throw error
            })
        return this.repoReady
    }

    resetScanResult() {
        this.urls = []
        this.repo = {}
        this.repoReady = null
        this.initRepo()
        this.hasher = {
            sha1: function (data) {
                return CryptoES.SHA1(data).toString(CryptoES.enc.Hex)
            }
        }
        this.isScanRunning = false
        this.activeTabId = null
        this.scanResult = this.getScanResultSchema()
    }

    getScanResultSchema() {
        const envelope = createScanResultEnvelope({
            engine: "SCA",
            scanId: null,
            host: null,
            tabId: null,
            startedAt: new Date().toISOString(),
            settings: {}
        })
        return {
            version: envelope.version,
            engine: "SCA",
            scanId: envelope.scanId,
            host: null,
            startedAt: envelope.startedAt,
            finishedAt: null,
            stats: {
                findingsCount: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0
            },
            findings: []
        }
    }

    _normalizeEnvelope(raw) {
        if (!raw || typeof raw !== 'object') {
            return this.getScanResultSchema()
        }
        const findings = this._normalizeFindings(raw.findings || raw.items || raw.components || [])
        const stats = this._recalculateStats(findings)
        const startedAt = raw.startedAt || raw.date || raw.started_at || raw.created_at || raw.timestamp || new Date().toISOString()
        const finishedAt = raw.finishedAt || raw.finished || raw.finished_at || raw.completed_at || null
        return {
            version: raw.version || '1.0',
            engine: raw.engine || (raw.type && raw.type.toUpperCase()) || "SCA",
            scanId: raw.scanId || raw.id || null,
            host: raw.host || raw.hostname || raw.domain || null,
            startedAt,
            finishedAt,
            stats,
            findings
        }
    }

    _normalizeFindings(list) {
        if (!list) return []
        let entries = []
        if (Array.isArray(list)) {
            entries = list
        } else if (typeof list === 'object') {
            entries = Object.values(list)
        } else {
            return []
        }
        return entries
            .map(entry => this._normalizeComponentEntry(entry))
            .filter(Boolean)
    }

    _normalizeComponentEntry(entry) {
        if (!entry || typeof entry !== 'object') return null
        const clone = Object.assign({}, entry)
        clone.file = clone.file || clone.url || clone.path || null
        clone.component = clone.component || clone.library || clone.name || null
        clone.version = clone.version || clone.libraryVersion || clone.libVersion || null
        clone.findings = this._normalizeVulnerabilities(clone.findings || clone.vulnerabilities || clone.vulns || [])
        return clone
    }

    _normalizeVulnerabilities(list) {
        if (!Array.isArray(list)) return []
        return list
            .map(vuln => {
                if (!vuln || typeof vuln !== 'object') return null
                const clone = Object.assign({}, vuln)
                if (clone.severity) {
                    clone.severity = String(clone.severity).toLowerCase()
                } else {
                    clone.severity = 'medium'
                }
                return clone
            })
            .filter(Boolean)
    }

    _recalculateStats(findings = []) {
        const stats = {
            findingsCount: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        }
        findings.forEach(component => {
            const vulns = Array.isArray(component?.findings) ? component.findings : []
            vulns.forEach(vuln => {
                stats.findingsCount += 1
                const sev = String(vuln?.severity || '').toLowerCase()
                if (sev === 'high' || sev === 'critical') stats.high += 1
                else if (sev === 'medium') stats.medium += 1
                else if (sev === 'low') stats.low += 1
                else stats.info += 1
            })
        })
        return stats
    }

    async reset() {
        await ptk_storage.setItem(this.storageKey, {})
        this.resetScanResult()
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    addListeners() {
        this.onRemoved = this.onRemoved.bind(this)
        browser.tabs.onRemoved.addListener(this.onRemoved)

        this.onUpdated = this.onUpdated.bind(this)
        browser.tabs.onUpdated.addListener(this.onUpdated)

        this.onCompleted = this.onCompleted.bind(this)
        browser.webRequest.onCompleted.addListener(
            this.onCompleted,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )
    }

    async onUpdated(tabId, info, tab) {

    }

    removeListeners() {
        browser.tabs.onRemoved.removeListener(this.onRemoved)
        browser.tabs.onUpdated.removeListener(this.onUpdated)
        browser.webRequest.onCompleted.removeListener(this.onCompleted)
    }

    onRemoved(tabId, info) {
        if (this.activeTabId === tabId) {
            this.activeTabId = null
            this.isScanRunning = false
        }
    }

    onCompleted(response) {
        let self = this
        if (this.isScanRunning && this.activeTabId === response.tabId && ptk_utils.isURL(response?.url)) {
            if (!this.urls.includes(response.url)) {
                self.urls.push(response.url)
                self.scan(response.url).then(result => {
                    if (result.vulns.length > 0) {
                        let finding = {
                            file: result.vulns[0][0],
                            component: result.vulns[0][1][0]['component'],
                            version: result.vulns[0][1][0]['version'],
                            findings: result.vulns[0][1][0].vulnerabilities
                        }
                        self.scanResult.findings.push(finding)
                        self.updateScanResult()
                    }
                })
            }
        }
    }

    updateScanResult() {

        this.scanResult.stats = this._recalculateStats(this.scanResult.findings)
        ptk_storage.setItem(this.storageKey, this.scanResult)
    }

    getFileName(url) {
        var a = new URL(url)//document.createElement("a");
        //a.href = url;
        return (a.pathname.match(/\/([^\/?#]+)$/i) || [, ""])[1];
    }

    async scan(url) {
        await this.ensureRepoReady()
        let dt = new Array()
        let fetches = []

        let results = retire.scanUri(url, this.repo)
        if (results.length > 0) {
            let hash = url + results[0].component + results[0].version
            if (dt.findIndex(u => u[2] == hash) == -1) {
                dt.push([url, results, hash])
            }
        }

        results = retire.scanFileName(this.getFileName(url), this.repo)
        if (results.length > 0) {
            let hash = url + results[0].component + results[0].version
            if (dt.findIndex(u => u[2] == hash) == -1) {
                dt.push([url, results, hash])
            }
        }

        fetches.push(
            fetch(url)
                .then(response => response.text())
                .then(content => {
                    var results = retire.scanFileContent(content, this.repo, this.hasher);
                    if (results.length > 0) {
                        let hash = url + results[0].component + results[0].version
                        if (dt.findIndex(u => u[2] == hash) == -1) {
                            dt.push([url, results, hash])
                        }
                    }
                })
                .catch(function (error) {
                    console.log(error);
                })
        )

        if (fetches.length) {
            await Promise.all(fetches).then()
        }
        return Promise.resolve({ "vulns": dt })
    }


    onMessage(message, sender, sendResponse) {
        if (message.channel == "ptk_popup2background_sca") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }
    }



    async msg_init(message) {
        await this.init()
        return Promise.resolve({
            scanResult: JSON.parse(JSON.stringify(this.scanResult)),
            isScanRunning: this.isScanRunning,
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }


    msg_reset(message) {
        this.reset()
        return Promise.resolve({
            scanResult: JSON.parse(JSON.stringify(this.scanResult)),
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }

    async msg_loadfile(message) {
        this.reset()
        //await this.init()

        return new Promise((resolve, reject) => {
            var fr = new FileReader()
            fr.onload = () => {

                resolve(this.msg_save(fr.result))
            }
            fr.onerror = reject
            fr.readAsText(message.file)
        })

    }

    async msg_save(message) {
        let res = JSON.parse(message.json)
        if (!res) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        const normalized = this._normalizeEnvelope(res)
        if (!Array.isArray(normalized.findings) || normalized.findings.length === 0) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        this.scanResult = normalized
        await ptk_storage.setItem(this.storageKey, normalized)
        return Promise.resolve({
            scanResult: JSON.parse(JSON.stringify(this.scanResult)),
            isScanRunning: this.isScanRunning,
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }

    async msg_run_bg_scan(message) {
        await this.runBackroungScan(message.tabId, message.host)
        return Promise.resolve({ isScanRunning: this.isScanRunning, scanResult: JSON.parse(JSON.stringify(this.scanResult)) })
    }

    msg_stop_bg_scan(message) {
        this.stopBackroungScan()
        return Promise.resolve({ scanResult: JSON.parse(JSON.stringify(this.scanResult)) })
    }

    async msg_get_projects(message) {
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        const url = this.buildPortalUrl(profile.projects_endpoint, profile)
        if (!url) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        const response = await fetch(url, {
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/json'
            },
            cache: 'no-cache'
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (httpResponse.ok) {
                    return { success: true, json }
                }
                return { success: false, json: json || { message: 'Unable to load projects' } }
            })
            .catch(e => ({ success: false, json: { message: 'Error while loading projects: ' + e.message } }))
        return response
    }

    async msg_save_scan(message) {
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        if (!Array.isArray(this.scanResult?.findings) || !this.scanResult.findings.length) {
            return { success: false, json: { message: "Scan result is empty" } }
        }
        const url = this.buildPortalUrl(profile.scans_endpoint, profile)
        if (!url) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        const payload = JSON.parse(JSON.stringify(this.scanResult))
        if (message?.projectId) {
            payload.projectId = message.projectId
        }
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            cache: 'no-cache',
            body: JSON.stringify(payload)
        })
            .then(async (httpResponse) => {
                if (httpResponse.status === 201) {
                    return { success: true }
                }
                const json = await httpResponse.json().catch(() => ({ message: httpResponse.statusText }))
                return { success: false, json }
            })
            .catch(e => ({ success: false, json: { message: 'Error while saving report: ' + e.message } }))
        return response
    }

    async msg_download_scans(message) {
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        const baseUrl = this.buildPortalUrl(profile.scans_endpoint, profile)
        if (!baseUrl) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        let requestUrl = baseUrl
        try {
            const url = new URL(baseUrl)
            if (message?.projectId) {
                url.searchParams.set('projectId', message.projectId)
            }
            const engine = message?.engine || 'sca'
            if (engine) {
                url.searchParams.set('engine', engine)
            }
            requestUrl = url.toString()
        } catch (err) {
            return { success: false, json: { message: "Invalid scans endpoint." } }
        }
        const response = await fetch(requestUrl, {
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/json'
            },
            cache: 'no-cache'
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (httpResponse.ok) {
                    return { success: true, json }
                }
                return { success: false, json: json || { message: 'Unable to load scans' } }
            })
            .catch(e => ({ success: false, json: { message: 'Error while loading scans: ' + e.message } }))
        return response
    }

    async msg_download_scan_by_id(message) {
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        if (!message?.scanId) {
            return { success: false, json: { message: "Scan identifier is required." } }
        }
        const baseUrl = this.buildPortalUrl(profile.scans_endpoint, profile)
        if (!baseUrl) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        const normalizedBase = baseUrl.replace(/\/+$/, "")
        const downloadUrl = `${normalizedBase}/${encodeURIComponent(message.scanId)}/download`
        const response = await fetch(downloadUrl, {
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/json'
            },
            cache: 'no-cache'
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (!httpResponse.ok) {
                    return { success: false, json: json || { message: 'Unable to download scan' } }
                }
                if (json) {
                    const normalized = this._normalizeEnvelope(json)
                    this.scanResult = normalized
                    ptk_storage.setItem(this.storageKey, normalized)
                    return normalized
                }
                return json
            })
            .catch(e => ({ success: false, json: { message: 'Error while downloading scan: ' + e.message } }))
        return response
    }

    async msg_delete_scan_by_id(message) {
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        if (!message?.scanId) {
            return { success: false, json: { message: "Scan identifier is required." } }
        }
        const baseUrl = this.buildPortalUrl(profile.storage_endpoint, profile)
        if (!baseUrl) {
            return { success: false, json: { message: "Storage endpoint is not configured." } }
        }
        const normalizedBase = baseUrl.replace(/\/+$/, "")
        const deleteUrl = `${normalizedBase}/${encodeURIComponent(message.scanId)}`
        const response = await fetch(deleteUrl, {
            method: 'DELETE',
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/json'
            },
            cache: 'no-cache'
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (!httpResponse.ok) {
                    return { success: false, json: json || { message: 'Unable to delete scan' } }
                }
                return json || { success: true }
            })
            .catch(e => ({ success: false, json: { message: 'Error while deleting scan: ' + e.message } }))
        return response
    }

    buildPortalUrl(endpoint, profile) {
        profile = profile || worker.ptk_app.settings.profile || {}
        const baseUrl = (profile.base_url || profile.api_url || "").trim()
        const apiBase = (profile.api_base || "").trim()
        const resolvedEndpoint = (endpoint || "").trim()
        if (!baseUrl || !apiBase || !resolvedEndpoint) return null
        const normalizedBase = baseUrl.replace(/\/+$/, "")
        let normalizedApiBase = apiBase.replace(/\/+$/, "")
        if (!normalizedApiBase.startsWith('/')) normalizedApiBase = '/' + normalizedApiBase
        let normalizedEndpoint = resolvedEndpoint
        if (!normalizedEndpoint.startsWith('/')) normalizedEndpoint = '/' + normalizedEndpoint
        return normalizedBase + normalizedApiBase + normalizedEndpoint
    }

    async ensureRepoReady() {
        try {
            await (this.repoReady || this.initRepo())
        } catch (_) {
            // already logged in initRepo
        }
    }

    async runBackroungScan(tabId, host) {
        await this.reset()
        await this.ensureRepoReady()
        this.isScanRunning = true
        this.scanningRequest = false
        this.activeTabId = tabId
        this.scanResult.scanId = ptk_utils.UUID()
        this.scanResult.host = host
        this.scanResult.startedAt = new Date().toISOString()
        this.scanResult.finishedAt = null
        this.addListeners()
    }

    stopBackroungScan() {
        this.isScanRunning = false
        this.activeTabId = null
        if (this.scanResult) {
            this.scanResult.finishedAt = new Date().toISOString()
        }
        ptk_storage.setItem(this.storageKey, this.scanResult)
        this.removeListeners()
    }

}
