/* Author: Denis Podgurskii */
import { ptk_utils, ptk_logger, ptk_queue, ptk_storage, ptk_ruleManager } from "../background/utils.js"
import { createFindingFromIAST, getFindingFingerprint, mergeFinding } from "./iast/modules/reporting.js"
import { loadRulepack } from "./common/moduleRegistry.js"
import {
    createScanResultEnvelope,
    addFindingToGroup
} from "./common/scanResults.js"
import {
    normalizeRulepack,
    normalizeSeverityValue,
    resolveEffectiveSeverity
} from "./common/severity_utils.js"

const activeIastTabs = new Set()
let iastModulesCache = null
function mergeLinks(baseLinks, overrideLinks) {
    const result = Object.assign({}, baseLinks || {})
    if (overrideLinks && typeof overrideLinks === "object") {
        Object.entries(overrideLinks).forEach(([key, value]) => {
            if (key) result[key] = value
        })
    }
    return Object.keys(result).length ? result : null
}

function buildIastRuleIndex(rulepack) {
    iastRuleMetaIndex = new Map()
    const modules = Array.isArray(rulepack?.modules) ? rulepack.modules : []
    modules.forEach((mod) => {
        const moduleMeta = mod?.metadata || {}
        const base = {
            moduleId: mod?.id || null,
            moduleName: mod?.name || mod?.id || null,
            vulnId: mod?.vulnId || moduleMeta.vulnId || mod?.id || null,
            category: moduleMeta.category || null,
            severity: moduleMeta.severity || null,
            owasp: moduleMeta.owasp || null,
            cwe: moduleMeta.cwe || null,
            tags: moduleMeta.tags || [],
            description: moduleMeta.description || null,
            recommendation: moduleMeta.recommendation || null,
            links: moduleMeta.links || null
        }
        const rules = Array.isArray(mod?.rules) ? mod.rules : []
        rules.forEach(rule => {
            const ruleMeta = rule?.metadata || {}
            if (!rule?.id) return
            const mergedLinks = mergeLinks(base.links, ruleMeta.links)
            iastRuleMetaIndex.set(rule.id, {
                moduleId: base.moduleId,
                moduleName: base.moduleName,
                ruleName: rule?.name || rule?.id || null,
                vulnId: base.vulnId,
                category: ruleMeta.category || base.category,
                severity: resolveEffectiveSeverity({
                    moduleMeta,
                    ruleMeta
                }),
                owasp: ruleMeta.owasp || base.owasp,
                cwe: ruleMeta.cwe || base.cwe,
                tags: ruleMeta.tags || base.tags,
                description: ruleMeta.description || base.description || null,
                recommendation: ruleMeta.recommendation || base.recommendation || null,
                links: mergedLinks,
                moduleMeta,
                ruleMeta
            })
        })
    })
}

function getIastRuleMeta(ruleId) {
    if (!ruleId) return null
    return iastRuleMetaIndex.get(ruleId) || null
}
let iastRuleMetaIndex = new Map()

function getRuntime() {
    if (typeof chrome !== 'undefined' && chrome.runtime) return chrome
    if (typeof browser !== 'undefined' && browser.runtime) return browser
    return null
}

async function loadIastModules() {
    if (iastModulesCache) return iastModulesCache
    try {
        const rulepack = await loadRulepack('IAST')
        normalizeRulepack(rulepack, { engine: 'IAST', childKey: 'rules' })
        iastModulesCache = rulepack
        buildIastRuleIndex(rulepack)
        //console.log('[PTK IAST BG] Loaded IAST rulepack')
        return iastModulesCache
    } catch (e) {
        console.error('[PTK IAST BG] Error loading IAST rulepack:', e)
        iastModulesCache = null
        return null
    }
}

async function sendIastModulesToContent(tabId, attempt = 1) {
    const modules = await loadIastModules()
    if (!modules) {
        console.warn('[PTK IAST BG] No IAST modules to send to tab', tabId)
        return
    }
    const rt = getRuntime()
    if (!rt || !rt.tabs?.sendMessage) {
        console.warn('[PTK IAST BG] tabs.sendMessage unavailable')
        return
    }
    try {
        rt.tabs.sendMessage(
            tabId,
            {
                channel: 'ptk_background_iast2content_modules',
                iastModules: modules,
            },
            () => {
                const err = rt.runtime.lastError
                if (err) {
                    console.warn('[PTK IAST BG] Error sending IAST modules to tab', tabId, err.message)
                    if (attempt < 5) {
                        setTimeout(() => {
                            sendIastModulesToContent(tabId, attempt + 1)
                        }, 700)
                    }
                } else {
                    //console.log('[PTK IAST BG] Sent IAST modules to tab', tabId)
                }
            }
        )
    } catch (e) {
        console.error('[PTK IAST BG] Exception sending IAST modules to tab', tabId, e)
    }
}


const worker = self
const MAX_HTTP_EVENTS = 1000
const MAX_TRACKED_REQUESTS = 500
const SEVERITY_ORDER = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
}

export class ptk_iast {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_iast"
        this.devtoolsAttached = false
        this.devtoolsTarget = null
        this.onDevtoolsEvent = null
        this.maxHttpEvents = MAX_HTTP_EVENTS
        this.maxTrackedRequests = MAX_TRACKED_REQUESTS
        this.requestLookup = new Map()
        this.resetScanResult()
        this.modulesCatalog = null

        this.addMessageListeners()
    }

    async init() {

        if (!this.isScanRunning) {
            const stored = await ptk_storage.getItem(this.storageKey) || {}
            if (stored && ((stored.scanResult) || Object.keys(stored).length > 0)) {
                this.normalizeScanResult(stored)
            }
        }
    }

    resetScanResult() {
        this.unregisterScript()
        this.detachDevtoolsDebugger()
        this.isScanRunning = false
        this.scanResult = this.getScanResultSchema()
        this.requestLookup = new Map()
    }

    async getDefaultModules(rulepack = null) {
        try {
            const loaded = rulepack || await loadIastModules()
            const modules = Array.isArray(loaded?.modules) ? loaded.modules : []
            return JSON.parse(JSON.stringify(modules))
        } catch (err) {
            console.warn('[PTK IAST] Failed to load default modules', err)
            return []
        }
    }

    getScanResultSchema() {
        const envelope = createScanResultEnvelope({
            engine: "IAST",
            scanId: null,
            host: null,
            tabId: null,
            startedAt: new Date().toISOString(),
            settings: {}
        })
        envelope.stats = { findingsCount: 0, high: 0, medium: 0, low: 0, info: 0 }
        envelope.httpEvents = []
        envelope.runtimeEvents = []
        envelope.requests = []
        envelope.pages = []
        envelope.files = []
        return this._normalizeEnvelope(envelope)
    }

    persistScanResult() {
        const cloned = this._cloneForStorage(this.scanResult, { dropTabId: true }) || {}
        if (Array.isArray(cloned.rawFindings)) {
            delete cloned.rawFindings
        }
        ptk_storage.setItem(this.storageKey, cloned)
    }

    _cloneForStorage(value, { dropTabId = false } = {}) {
        try {
            const cloned = JSON.parse(JSON.stringify(value ?? (Array.isArray(value) ? [] : {})))
            if (dropTabId && cloned && typeof cloned === "object") {
                delete cloned.tabId
            }
            return cloned
        } catch (_) {
            return value
        }
    }

    _getPublicScanResult() {
        return this._cloneForStorage(this.scanResult, { dropTabId: true })
    }

    _extractPersistedData(raw) {
        const fallback = { scanResult: this.getScanResultSchema(), rawFindings: [] }
        if (!raw || typeof raw !== "object") {
            return fallback
        }
        let scanPayload = null
        let legacyRaw = []
        if (raw.scanResult && typeof raw.scanResult === "object") {
            scanPayload = raw.scanResult
            legacyRaw = Array.isArray(raw.rawFindings) ? raw.rawFindings : []
        } else if (raw.engine || raw.version || Array.isArray(raw.findings)) {
            scanPayload = raw
        } else {
            scanPayload = raw
            legacyRaw = Array.isArray(raw.rawFindings) ? raw.rawFindings : Array.isArray(raw.items) ? raw.items : []
        }
        const scanClone = this._cloneForStorage(scanPayload)
        const embeddedRaw = Array.isArray(scanClone?.rawFindings) ? scanClone.rawFindings : []
        return {
            scanResult: scanClone,
            rawFindings: this._cloneForStorage(embeddedRaw.length ? embeddedRaw : legacyRaw)
        }
    }

    async reset() {
        this.resetScanResult()
        await ptk_storage.setItem(this.storageKey, {})
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
        if (this.scanResult?.tabId == tabId) {
            this.scanResult.tabId = null
            this.isScanRunning = false
            this.detachDevtoolsDebugger()
        }
    }

    onCompleted(response) {
        if (!this.isScanRunning) return
        if (!this.scanResult?.tabId || response.tabId !== this.scanResult.tabId) return

        if (this.scanResult.host) {
            try {
                const url = new URL(response.url)
                if (url.host !== this.scanResult.host) return
            } catch (e) {
                // ignore malformed URLs
            }
        }

        const evt = {
            type: "http",
            time: Date.now(),
            requestId: response.requestId,
            url: response.url,
            method: response.method || null,
            status: response.statusCode,
            ip: response.ip || null,
            fromCache: !!response.fromCache,
            tabId: response.tabId,
            host: this.scanResult.host
        }

        this.recordHttpEvent(evt)
    }

    onMessage(message, sender, sendResponse) {

        if (message.channel == "ptk_popup2background_iast") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }

        if (message.channel == "ptk_content2iast") {

            if (message.type == 'check') {
                //console.log('check iast')
                if (this.isScanRunning && this.scanResult.tabId == sender.tab.id)
                    return Promise.resolve({ loadAgent: true })
                else
                    return Promise.resolve({ loadAgent: false })
            }
        }

        if (message.channel == "ptk_content_iast2background_iast") {

            if (message.type == 'finding_report') {
                if (this.isScanRunning && this.scanResult.tabId == sender.tab.id) {
                    try {
                        const finding = createFindingFromIAST(message.finding, {
                            scanId: this.scanResult.scanId,
                            host: this.scanResult.host,
                            tabId: this.scanResult.tabId
                        })
                        this.addOrUpdateFinding(finding)
                    } catch (e) {
                        console.warn('[PTK IAST DEBUG][background] createFindingFromIAST failed', e)
                    }
                } else {
                    try { console.info('[PTK IAST DEBUG][background] finding ignored (no active scan or tab mismatch)') } catch (_) { }
                }
            }
        }

        if (message.channel === "ptk_content_iast2background_request_modules") {
            ;(async () => {
                const modules = await loadIastModules()
                if (!modules) {
                    console.warn('[PTK IAST BG] No IAST modules available for request')
                    sendResponse && sendResponse({ iastModules: null })
                    return
                }
                const tabId = sender?.tab?.id
                //console.log('[PTK IAST BG] Content requested IAST modules for tab', tabId)
                sendResponse && sendResponse({ iastModules: modules })
            })()
            return true
        }
    }

    updateScanResult({ persist = true } = {}) {
        if (!this.scanResult) {
            this.scanResult = this.getScanResultSchema()
        }
        if (!Array.isArray(this.scanResult.findings)) {
            this.scanResult.findings = []
        }
        this._rebuildGroupsFromFindings()
        const findings = this.scanResult.findings
        const stats = {
            findingsCount: findings.length,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        }
        findings.forEach(finding => {
            const severity = String(finding?.severity || "").toLowerCase()
            if (severity === "high") stats.high++
            else if (severity === "medium") stats.medium++
            else if (severity === "low") stats.low++
            else stats.info = (stats.info || 0) + 1
        })
        stats.vulnsCount = stats.findingsCount
        this.scanResult.stats = stats
        this.updatePagesFromFindings()
        if (persist) {
            this.persistScanResult()
        }
    }

    async msg_init(message) {
        await this.init()
        const defaultModules = await this.getDefaultModules()
        return Promise.resolve({
            scanResult: this._getPublicScanResult(),
            isScanRunning: this.isScanRunning,
            activeTab: worker.ptk_app.proxy.activeTab,
            default_modules: defaultModules
        })
    }


    async msg_reset(message) {
        this.reset()
        const defaultModules = await this.getDefaultModules()
        return Promise.resolve({
            scanResult: this._getPublicScanResult(),
            activeTab: worker.ptk_app.proxy.activeTab,
            default_modules: defaultModules
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
        const isIast = (typeof res.engine === "string" && res.engine.toUpperCase() === "IAST") ||
            (typeof res.type === "string" && res.type.toLowerCase() === "iast")
        const hasFindings = Array.isArray(res.findings) && res.findings.length > 0
        const hasLegacyItems = Array.isArray(res.items) && res.items.length > 0
        if (!isIast || (!hasFindings && !hasLegacyItems)) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        this.reset()
        const payload = this._extractPersistedData(res)
        this.scanResult = this._normalizeEnvelope(payload.scanResult || {})
        if (Array.isArray(this.scanResult.findings) && this.scanResult.findings.length) {
            this.scanResult.findings = this.scanResult.findings.map(item => this.prepareFindingMetadata(item))
        } else {
            this.scanResult.findings = []
        }
        this._ingestLegacyRawFindings(Array.isArray(payload.rawFindings) ? payload.rawFindings : [])
        if (Array.isArray(this.scanResult.rawFindings) && this.scanResult.rawFindings.length) {
            this._ingestLegacyRawFindings(this.scanResult.rawFindings)
            delete this.scanResult.rawFindings
        }
        this.updateScanResult({ persist: true })
        const defaultModules = await this.getDefaultModules()
        return Promise.resolve({
            scanResult: this._getPublicScanResult(),
            isScanRunning: this.isScanRunning,
            activeTab: worker.ptk_app.proxy.activeTab,
            default_modules: defaultModules
        })
    }

    msg_run_bg_scan(message) {
        return this.runBackroungScan(message.tabId, message.host).then(async () => {
            const defaultModules = await this.getDefaultModules()
            return { isScanRunning: this.isScanRunning, scanResult: this._getPublicScanResult(), default_modules: defaultModules }
        })
    }

    msg_stop_bg_scan(message) {
        this.stopBackroungScan()
        return Promise.resolve({ scanResult: this._getPublicScanResult() })
    }

    async runBackroungScan(tabId, host) {
        this.reset()
        this.isScanRunning = true
        this.scanningRequest = false
        this.scanResult.scanId = ptk_utils.UUID()
        this.scanResult.tabId = tabId
        this.scanResult.host = host
        const started = new Date().toISOString()
        this.scanResult.startedAt = started
        this.scanResult.finishedAt = null
        activeIastTabs.add(tabId)
        this.registerScript()
        this.addListeners()
        this.attachDevtoolsDebugger(tabId)
        await loadIastModules()
        await sendIastModulesToContent(tabId)
    }

    stopBackroungScan() {
        browser.tabs.sendMessage(this.scanResult.tabId, {
            channel: "ptk_background_iast2content",
            type: "clean iast result"
        }).catch(() => { })
        this.isScanRunning = false
        activeIastTabs.delete(this.scanResult.tabId)
        this.scanResult.tabId = null
        this.unregisterScript()
        this.removeListeners()
        this.detachDevtoolsDebugger()
        if (this.scanResult) {
            const finished = new Date().toISOString()
            this.scanResult.finishedAt = finished
        }
        this.persistScanResult()
    }

    recordHttpEvent(evt) {
        if (!this.scanResult.httpEvents) {
            this.scanResult.httpEvents = []
        }
        this.scanResult.httpEvents.push(evt)
        this.upsertRequestFromEvent(evt)
        if (this.scanResult.httpEvents.length > this.maxHttpEvents) {
            this.scanResult.httpEvents.shift()
        }
        this.persistScanResult()
    }

    addOrUpdateFinding(finding) {
        if (!finding) return
        let prepared
        try {
            prepared = this.prepareFindingMetadata(finding)
        } catch (e) {
            try { console.warn('[PTK IAST DEBUG][background] prepareFindingMetadata failed', e) } catch (_) { }
            return
        }
        this._upsertFinding(prepared)
        this.updateScanResult()
        this.broadcastScanUpdate()
    }

    normalizeScanResult(raw) {
        const payload = this._extractPersistedData(raw || {})
        this.scanResult = this._normalizeEnvelope(payload.scanResult || {})
        if (Array.isArray(this.scanResult.findings) && this.scanResult.findings.length) {
            this.scanResult.findings = this.scanResult.findings.map(item => this.prepareFindingMetadata(item))
        } else {
            this.scanResult.findings = []
        }
        this._ingestLegacyRawFindings(Array.isArray(payload.rawFindings) ? payload.rawFindings : [])
        if (Array.isArray(this.scanResult.rawFindings) && this.scanResult.rawFindings.length) {
            this._ingestLegacyRawFindings(this.scanResult.rawFindings)
            delete this.scanResult.rawFindings
        }
        this.requestLookup = new Map()
        if (Array.isArray(this.scanResult.requests)) {
            this.scanResult.requests.forEach(entry => {
                if (entry?.key) {
                    this.requestLookup.set(entry.key, entry)
                }
            })
        }
        this.updateScanResult({ persist: false })
        return this.scanResult
    }

    normalizeRequestUrl(url) {
        if (!url) return ""
        try {
            const u = new URL(url)
            u.hash = ""
            return u.toString()
        } catch (e) {
            try {
                return String(url).split('#')[0]
            } catch (_) {
                return ""
            }
        }
    }

    buildRequestKey(method, url) {
        const normalizedUrl = this.normalizeRequestUrl(url)
        if (!normalizedUrl) return null
        const normalizedMethod = (method || 'GET').toUpperCase()
        return normalizedMethod + ' ' + normalizedUrl
    }

    trimTrackedRequests() {
        if (!Array.isArray(this.scanResult.requests)) return
        if (this.scanResult.requests.length <= this.maxTrackedRequests) return
        const overflow = this.scanResult.requests.length - this.maxTrackedRequests
        if (overflow <= 0) return
        const removed = this.scanResult.requests.splice(0, overflow)
        removed.forEach(entry => {
            if (entry?.key) {
                this.requestLookup.delete(entry.key)
            }
        })
    }

    _ingestLegacyRawFindings(rawList) {
        if (!Array.isArray(rawList) || !rawList.length) return
        rawList.forEach(item => {
            if (!item) return
            try {
                const prepared = this.prepareFindingMetadata(item)
                this._upsertFinding(prepared)
            } catch (e) {
                try { console.warn('[PTK IAST DEBUG][background] failed to ingest legacy finding', e) } catch (_) { }
            }
        })
    }

    upsertRequestFromEvent(evt) {
        if (!evt) return
        if (!Array.isArray(this.scanResult.requests)) {
            this.scanResult.requests = []
        }
        const url = evt?.url
        if (!url) return
        const method = evt?.method || 'GET'
        const key = this.buildRequestKey(method, url)
        if (!key) return
        let entry = this.requestLookup.get(key)
        const status = evt?.status || evt?.statusCode || null
        const lastSeen = evt?.time || Date.now()
        if (entry) {
            if (status) entry.status = status
            entry.lastSeen = lastSeen
            entry.type = evt?.type || entry.type
        } else {
            entry = {
                key,
                method: (method || 'GET').toUpperCase(),
                url: this.normalizeRequestUrl(url),
                displayUrl: url,
                status,
                host: evt?.host || this.scanResult.host || null,
                type: evt?.type || 'http',
                mimeType: evt?.mimeType || null,
                lastSeen
            }
            this.scanResult.requests.push(entry)
            this.requestLookup.set(key, entry)
            this.trimTrackedRequests()
        }
    }

    _upsertFinding(finding) {
        if (!finding) return
        const findings = Array.isArray(this.scanResult.findings) ? this.scanResult.findings : (this.scanResult.findings = [])
        const fingerprint = finding.fingerprint || getFindingFingerprint(finding)
        const idx = findings.findIndex(item => (item?.fingerprint || getFindingFingerprint(item || {})) === fingerprint)
        if (idx === -1) {
            findings.push(finding)
        } else {
            const merged = mergeFinding(findings[idx], finding)
            findings[idx] = this.prepareFindingMetadata(merged)
        }
    }

    _rebuildGroupsFromFindings() {
        this.scanResult.groups = []
        const findings = Array.isArray(this.scanResult.findings) ? this.scanResult.findings : []
        findings.forEach(finding => {
            const evidenceList = Array.isArray(finding?.evidence) ? finding.evidence : []
            const primaryEvidence = evidenceList.find(ev => String(ev?.source || '').toLowerCase() === 'iast') || evidenceList[0] || {}
            const taintSource = primaryEvidence?.taintSource || primaryEvidence?.raw?.taintSource || finding?.taintSource || finding?.source || null
            const sinkId = primaryEvidence?.sinkId || primaryEvidence?.raw?.sinkId || finding?.sinkId || null
            const locationUrl = finding?.location?.url || ""
            const groupKey = [
                "IAST",
                finding?.vulnId || finding?.category || 'runtime_issue',
                locationUrl,
                taintSource || "",
                sinkId || finding?.ruleId || ""
            ].join('@@')
            addFindingToGroup(this.scanResult, finding, groupKey, {
                url: locationUrl || null,
                param: taintSource || null,
                sink: sinkId || null
            })
        })
    }

    prepareFindingMetadata(finding) {
        if (!finding) return finding
        if (!finding.location || typeof finding.location !== "object" || Array.isArray(finding.location)) {
            const rawValue = typeof finding.location === "string" ? finding.location : null
            finding.location = { url: rawValue }
        }
        let classificationMeta = null
        if (finding.ruleId) {
            classificationMeta = getIastRuleMeta(finding.ruleId) || null
        }
        if (!finding.ruleName && classificationMeta) {
            finding.ruleName = classificationMeta.ruleName || classificationMeta?.ruleMeta?.name || finding.ruleId
        }
        if (!finding.moduleName && classificationMeta) {
            finding.moduleName = classificationMeta.moduleName || finding.moduleName || null
        }
        const urls = this.collectFindingUrls(finding)
        if (urls.length > 0) {
            finding.location.url = urls[0]
        }
        finding.affectedUrls = urls
        const summary = this.buildTaintAndSinkSummaries(finding)
        finding.taintSummary = summary.taintSummary
        finding.sinkSummary = summary.sinkSummary
        if (!Array.isArray(finding.evidence)) {
            finding.evidence = []
        }
        return finding
    }

    collectFindingUrls(finding) {
        const urls = new Set()
        const add = (value) => {
            if (!value) return
            const normalized = this.normalizeFindingUrl(value)
            if (normalized) urls.add(normalized)
        }
        const baseLocation = finding?.location
        if (typeof baseLocation === "string") add(baseLocation)
        if (baseLocation && typeof baseLocation === "object") {
            add(baseLocation.url || baseLocation.href)
        }
        if (Array.isArray(finding?.affectedUrls)) {
            finding.affectedUrls.forEach(add)
        }
        if (Array.isArray(finding?.evidence)) {
            finding.evidence.forEach(ev => {
                add(ev?.raw?.location)
                add(ev?.raw?.context?.url)
                add(ev?.context?.url)
                add(ev?.context?.location)
            })
        }
        if (urls.size === 0 && baseLocation?.url) {
            add(baseLocation.url)
        }
        return Array.from(urls).sort((a, b) => {
            if (a.length !== b.length) return b.length - a.length
            return a.localeCompare(b)
        })
    }

    normalizeFindingUrl(rawUrl) {
        if (!rawUrl) return ""
        const value = String(rawUrl).trim()
        const candidates = [value]
        if (this.scanResult?.host && !/^https?:\/\//i.test(value)) {
            const base = this.scanResult.host.match(/^https?:\/\//i) ? this.scanResult.host : `http://${this.scanResult.host}`
            try {
                candidates.push(new URL(value, base).toString())
            } catch (_) { }
        }
        for (const candidate of candidates) {
            try {
                const u = new URL(candidate)
                let pathname = u.pathname || "/"
                pathname = pathname.replace(/\/{2,}/g, "/")
                if (pathname.length > 1 && pathname.endsWith("/")) pathname = pathname.slice(0, -1)
                u.pathname = pathname
                return `${u.origin}${u.pathname}${u.search || ""}${u.hash || ""}`
            } catch (_) { }
        }
        return value
    }

    buildTaintAndSinkSummaries(finding) {
        const sources = new Set()
        const sinks = new Set()
        const directSources = [finding?.source, finding?.taintSource]
        directSources.forEach(src => { if (src) sources.add(String(src)) })
        const directSinks = [finding?.sink, finding?.sinkId]
        directSinks.forEach(sink => { if (sink) sinks.add(String(sink)) })
        if (Array.isArray(finding?.evidence)) {
            finding.evidence.forEach(ev => {
                const safeEv = ev || {}
                const raw = safeEv.raw || {}
                ;[safeEv.taintSource, raw.taintSource, raw.source].forEach(src => {
                    if (src) sources.add(String(src))
                })
                ;[safeEv.sinkId, raw.sinkId, raw.sink].forEach(sink => {
                    if (sink) sinks.add(String(sink))
                })
            })
        }
        const sourcesArr = Array.from(sources)
        const sinksArr = Array.from(sinks)
        return {
            taintSummary: {
                sources: sourcesArr,
                primarySource: sourcesArr.length ? sourcesArr[0] : null
            },
            sinkSummary: {
                sinks: sinksArr,
                primarySink: sinksArr.length ? sinksArr[0] : null
            }
        }
    }

    updatePagesFromFindings() {
        const items = Array.isArray(this.scanResult.findings) ? this.scanResult.findings : []
        const map = new Map()
        items.forEach((finding, index) => {
            if (!finding) return
            const pageUrl = finding?.location?.url || this.normalizeFindingUrl(finding?.affectedUrls?.[0])
            const key = pageUrl || `__missing_url__${index}`
            if (!map.has(key)) {
                map.set(key, {
                    url: pageUrl || null,
                    stats: {
                        totalFindings: 0,
                        byCategory: {},
                        bySeverity: {}
                    },
                    findingIds: [],
                    requestKey: null,
                    requestMeta: {}
                })
            }
            const page = map.get(key)
            const category = finding?.category || "runtime_issue"
            const severity = String(finding?.severity || "info").toLowerCase()
            const findingId = finding?.id || `${index}`
            page.stats.totalFindings += 1
            page.stats.byCategory[category] = (page.stats.byCategory[category] || 0) + 1
            page.stats.bySeverity[severity] = (page.stats.bySeverity[severity] || 0) + 1
            page.findingIds.push(findingId)
        })
        const pages = Array.from(map.values()).map(page => {
            const match = this.findRequestMetaForUrl(page.url)
            if (match) {
                page.requestKey = match.key || null
                page.requestMeta = {
                    method: match.method || null,
                    status: match.status || null,
                    mimeType: match.mimeType || null
                }
            }
            return page
        })
        this.scanResult.pages = pages
    }

    findRequestMetaForUrl(url) {
        if (!url || !Array.isArray(this.scanResult.requests)) return null
        const normalized = this.normalizeRequestUrl(url)
        if (!normalized) return null
        let best = null
        for (const req of this.scanResult.requests) {
            if (!req?.url) continue
            if (req.url === normalized) {
                best = req
                break
            }
        }
        if (!best) {
            best = this.scanResult.requests.find(req => req?.displayUrl === url) || null
        }
        return best
    }

    broadcastScanUpdate() {
        try {
            browser.runtime.sendMessage({
                channel: "ptk_background_iast2popup",
                type: "scan_update",
                scanResult: this._getPublicScanResult(),
                isScanRunning: this.isScanRunning
            }).catch(() => { })
        } catch (_) { }
    }

    attachDevtoolsDebugger(tabId) {
        if (worker.isFirefox) return
        if (typeof chrome === "undefined" || !chrome.debugger) return
        if (this.devtoolsAttached && this.devtoolsTarget && this.devtoolsTarget.tabId === tabId) return

        const target = { tabId }
        chrome.debugger.attach(target, "1.3", () => {
            if (chrome.runtime.lastError) {
                console.warn("[PTK IAST] DevTools attach failed:", chrome.runtime.lastError.message)
                return
            }

            this.devtoolsAttached = true
            this.devtoolsTarget = target

            chrome.debugger.sendCommand(target, "Network.enable", {}, () => {
                if (chrome.runtime.lastError) {
                    console.warn("[PTK IAST] Network.enable failed:", chrome.runtime.lastError.message)
                }
            })

            if (!this.onDevtoolsEvent) {
                this.onDevtoolsEvent = this.handleDevtoolsEvent.bind(this)
            }
            chrome.debugger.onEvent.addListener(this.onDevtoolsEvent)
        })
    }

    async loadModules() {
        return loadIastModules()
    }

    async sendModulesToContent(tabId) {
        return sendIastModulesToContent(tabId)
    }

    detachDevtoolsDebugger() {
        if (!this.devtoolsAttached || !this.devtoolsTarget) return
        if (typeof chrome === "undefined" || !chrome.debugger) return

        try {
            if (this.onDevtoolsEvent) {
                chrome.debugger.onEvent.removeListener(this.onDevtoolsEvent)
            }
        } catch (e) {
            // ignore listener removal errors
        }

        chrome.debugger.detach(this.devtoolsTarget, () => {
            if (chrome.runtime.lastError) {
                console.warn("[PTK IAST] DevTools detach error:", chrome.runtime.lastError.message)
            }
            this.devtoolsAttached = false
            this.devtoolsTarget = null
            this.onDevtoolsEvent = null
        })
    }

    handleDevtoolsEvent(source, method, params) {
        if (!this.devtoolsTarget || source.tabId !== this.devtoolsTarget.tabId) return
        if (!this.isScanRunning || !this.scanResult?.tabId || source.tabId !== this.scanResult.tabId) return

        if (method === "Network.requestWillBeSent") {
            const request = params && params.request ? params.request : {}
            const evt = {
                type: "devtools-http-request",
                time: Date.now(),
                requestId: params && params.requestId ? params.requestId : undefined,
                url: request.url,
                method: request.method,
                tabId: source.tabId
            }
            this.recordHttpEvent(evt)
        }

        if (method === "Network.responseReceived") {
            const response = params && params.response ? params.response : {}
            const evt = {
                type: "devtools-http-response",
                time: Date.now(),
                requestId: params && params.requestId ? params.requestId : undefined,
                url: response.url,
                status: response.status,
                mimeType: response.mimeType,
                tabId: source.tabId
            }
            this.recordHttpEvent(evt)
        }
    }

    _normalizeEnvelope(envelope) {
        const out = envelope && typeof envelope === "object" ? envelope : {}
        if (!Array.isArray(out.httpEvents)) out.httpEvents = []
        if (!Array.isArray(out.runtimeEvents)) out.runtimeEvents = []
        if (!Array.isArray(out.requests)) out.requests = []
        if (!Array.isArray(out.pages)) out.pages = []
        if (!Array.isArray(out.findings)) out.findings = []
        if (!Array.isArray(out.groups)) out.groups = []
        if (!Array.isArray(out.files)) out.files = []
        if (out.items !== undefined) delete out.items
        if (out.vulns !== undefined) delete out.vulns
        out.version = out.version || "1.0"
        out.engine = out.engine || "IAST"
        out.startedAt = out.startedAt || out.date || new Date().toISOString()
        if (out.date) delete out.date
        if (typeof out.finishedAt === "undefined") out.finishedAt = out.finished || null
        if (out.finished) delete out.finished
        if (out.type !== undefined) delete out.type
        if (!out.settings || typeof out.settings !== "object") out.settings = {}
        if (!out.stats || typeof out.stats !== "object") {
            out.stats = { findingsCount: 0, high: 0, medium: 0, low: 0 }
        }
        return out
    }

    registerScript() {
        let file = !worker.isFirefox ? 'ptk/content/iast.js' : 'content/iast.js'
        try {
            browser.scripting.registerContentScripts([{
                id: 'iast-agent',
                js: [file],
                matches: ['<all_urls>'],
                runAt: 'document_start',
                world: 'MAIN'
            }]).then(s => {
                console.log(s)
            });
        } catch (e) {
            console.log('Failed to register IAST script:', e);
        }
    }

    async unregisterScript() {
        try {
            await browser.scripting.unregisterContentScripts({
                ids: ["iast-agent"],
            });
        } catch (err) {
            //console.log(`failed to unregister content scripts: ${err}`);
        }

    }

}
