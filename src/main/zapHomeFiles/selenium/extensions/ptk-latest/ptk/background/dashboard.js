/* Author: Denis Podgurskii */
import { Wappalyzer } from "../packages/wappalyzer/wappalyzer.js"
import { buildCssPlan } from "../packages/wappalyzer/cssRules.js"
import { buildHtmlPlan } from "../packages/wappalyzer/htmlRules.js"
import { analyzeHeadersForTab } from "./headerAnalysis/headerAnalyzer.js"
import { setWappalyzerTechnologiesForHeaders } from "./headerAnalysis/wappalyzerHeadersEvaluator.js"
import { setCveTechnologiesForHeaders } from "./headerAnalysis/cveHeadersEvaluator.js"
import { ptk_utils } from "./utils.js"


const worker = self

export class ptk_dashboard {
    constructor() {

        fetch(browser.runtime.getURL('ptk/packages/wappalyzer/technologies.json'))
            .then(response => response.json())
            .then(data => {
                this.technologies = data.technologies
                this.categories = data.categories
                this.wappalyzerCssRules = []
                const htmlData = buildHtmlPlan(this.technologies, 'technologies')
                this.wappalyzerHtmlPlan = htmlData.plan
                this.wappalyzerHtmlPatterns = htmlData.patternIndex
                setWappalyzerTechnologiesForHeaders(this.technologies)
            })

        fetch(browser.runtime.getURL('ptk/packages/wappalyzer/waf.json'))
            .then(response => response.json())
            .then(data => {
                this.wafTechnologies = data.technologies
                this.wafCategories = data.categories
                const htmlData = buildHtmlPlan(this.wafTechnologies, 'waf')
                this.wappalyzerWafHtmlPlan = htmlData.plan
                this.wappalyzerWafHtmlPatterns = htmlData.patternIndex
            })

        fetch(browser.runtime.getURL('ptk/packages/wappalyzer/cves.json'))
            .then(response => response.json())
            .then(data => {
                this.cveRaw = data
                this.cveTechnologies = data.technologies || {}
                this.cveCategories = data.categories || []
                const htmlData = buildHtmlPlan(this.cveTechnologies, 'cve')
                this.cveHtmlPlan = htmlData.plan
                this.cveHtmlPatterns = htmlData.patternIndex
                setCveTechnologiesForHeaders(this.cveTechnologies)
            })

        this.addMessageListiners()
    }

    async initCookies(urls) {
        let merged = []
        let promises = []
        for (let i = 0; i < urls.length; i++) {
            promises.push(browser.cookies.getAll({ 'url': urls[i] }))
        }
        let self = this
        return Promise.all(promises).then(function (cookie) {
            let merged = [].concat.apply([], cookie)
            let cookies = merged.filter((v, i, a) => a.findIndex(v2 => (JSON.stringify(v) === JSON.stringify(v2))) === i).sort((a, b) => a.name.localeCompare(b.name));
            self.tab.cookies = cookies
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_dashboard",
                type: "init_complete",
                data: Object.assign({}, { cookies: cookies })
            }).catch(e => e)
        })
    }

    async analyzeTab(message) {
        this.setWappalyzer(this.technologies, this.categories)

        if (!this.tab) {
            this.tab = {}
        }

        const proxyTab = worker.ptk_app.proxy.getTab(this.activeTab?.tabId || this.tab?.tabId)
        const headerAnalysis = await this.runHeaderAnalysis(proxyTab)
        const techHeaderMatches = headerAnalysis.techHeaderMatches || []
        const cveHeaderMatches = headerAnalysis.cveHeaderMatches || []
        this.tab.findings = headerAnalysis.securityFindings || []
        this.tab.techHeaderMatches = techHeaderMatches
        this.tab.cveHeaderMatches = cveHeaderMatches
        this.tab.headerAnalysisEvidence = headerAnalysis.evidence
        if (!message.info) {
            message.info = {}
        }
        message.info.headers = techHeaderMatches

        let cookies = {}
        if (this.tab.cookies)
            Object.values(this.tab.cookies).forEach(function (c) {
                cookies[c.name.toLowerCase()] = [c.value]
            })


        let detections = Wappalyzer.analyze({
            headers: this.tab.responseHeaders,
            meta: message.info.meta,
            scriptSrc: message.info.scriptSrc,
            scripts: message.info.scripts,
            html: message.info.html,
            js: message.info.js,
            dom: message.info.dom,
            cookies: cookies
        })
        detections = Wappalyzer.resolve(detections)

        const htmlMatches = message.info?.htmlMatches?.technologies?.matched || []
        const htmlDetections = this.buildHtmlDetections(htmlMatches, this.wappalyzerHtmlPatterns)
        detections = detections.concat(htmlDetections)


        let technologies = Array.prototype.concat.apply(
            [],
            message.info.dom.map(({ name, selector, exists, text, property, attribute, value }) => {

                const technology = Wappalyzer.technologies.find(({ name: _name }) => name === _name)
                if (!technology) return []
                if (typeof exists !== 'undefined') {
                    return Wappalyzer.analyzeManyToMany(technology, 'dom.exists', { [selector]: [''], })
                }

                if (text) {
                    return Wappalyzer.analyzeManyToMany(technology, 'dom.text', { [selector]: [text], })
                }

                if (property) {
                    return Wappalyzer.analyzeManyToMany(technology, `dom.properties.${property}`, { [selector]: [value], })
                }

                if (attribute) {
                    return Wappalyzer.analyzeManyToMany(technology, `dom.attributes.${attribute}`, { [selector]: [value], })
                }

                return []
            })
        )

        technologies = Array.prototype.concat.apply(
            technologies,
            message.info.js
                .map(({ name, chain, value }) => {
                    const technology = Wappalyzer.technologies.find(({ name: _name }) => name === _name)
                    if (!technology) return []
                    if (name) {
                        return Wappalyzer.analyzeManyToMany(technology, 'js', { [chain]: [value], })
                    }

                    return []
                })
        )

        const cssMatches = Array.isArray(message.info?.css?.matched) ? message.info.css.matched : []

        technologies = Array.prototype.concat.apply(
            technologies,
            cssMatches
                .map(({ tech, name, selector, prop, value, pattern }) => {
                    const techName = tech || name

                    const technology = Wappalyzer.technologies.find(({ name: _name }) => techName === _name)
                    if (!technology) return []

                    return [{
                        technology,
                        pattern: {
                            type: 'css',
                            selector,
                            prop,
                            value: value || '',
                            pattern: pattern || '',
                        },
                        version: ''
                    }]
                })
        )

        const headerMatches = Array.isArray(message.info?.headers)
            ? message.info.headers
            : []

        technologies = Array.prototype.concat.apply(
            technologies,
            headerMatches.map(({ techId, techName, matches }) => {
                if (!Array.isArray(matches) || !matches.length) {
                    return []
                }

                const resolvedName = techId || techName
                if (!resolvedName) {
                    return []
                }

                const technology =
                    Wappalyzer.technologies.find(({ name: _name }) => _name === resolvedName) ||
                    this.createTechnologyStub(resolvedName)

                return matches.map(({ header, value, pattern }) => ({
                    technology,
                    pattern: {
                        type: 'header',
                        header,
                        value: value || '',
                        pattern: pattern || '',
                    },
                    version: ''
                }))
            })
        )

        let technologyEntries = technologies
            .map((item) => ({
                name: item.technology?.name || "",
                version: item.version ? item.version : "",
                category: this.resolveTechnologyCategory(item.technology),
            }))
            .filter((item) => item.name)

        const resolvedEntries = Object.keys(detections).map((key) => {
            const detection = detections[key]
            return {
                name: detection.name,
                version: detection.version || "",
                category: this.resolveTechnologyCategory(detection),
            }
        })

        technologyEntries = technologyEntries.concat(resolvedEntries)


        //WAF
        let wafDetections = {}
        this.setWappalyzer(this.wafTechnologies, this.wafCategories)

        wafDetections = await Wappalyzer.analyze({
            headers: this.tab.responseHeaders,
            meta: message.info.meta,
            scriptSrc: message.info.scriptSrc,
            scripts: message.info.scripts,
            html: message.info.html,
            js: message.info.js,
            dom: message.info.dom,
            cookies: cookies
        })

        const wafHtmlMatches = message.info?.htmlMatches?.waf?.matched || []
        const wafHtmlDetections = this.buildHtmlDetections(wafHtmlMatches, this.wappalyzerWafHtmlPatterns)
        wafDetections = wafDetections.concat(wafHtmlDetections)


        this.tab.waf = Wappalyzer.resolve(wafDetections)

        const wafEntries = (Array.isArray(this.tab.waf) ? this.tab.waf : Object.values(this.tab.waf || {}))
            .map((item) => ({
                name: item?.name || "",
                version: item?.version || "",
                category: "WAF",
            }))
            .filter((item) => item.name)

        technologyEntries = technologyEntries.concat(wafEntries)
        this.tab.technologies = this.mergeTechnologyEntries(technologyEntries)

        const hasCveSignatures = this.cveTechnologies && Object.keys(this.cveTechnologies).length > 0
        if (hasCveSignatures) {
            this.setWappalyzer(this.cveTechnologies, this.cveCategories || [])
            const cveEvidence = {
                js: new Map(),
                html: new Map(),
                headers: new Map()
            }

            const incrementEvidence = (bucket, techName) => {
                if (!techName) {
                    return
                }
                bucket.set(techName, (bucket.get(techName) || 0) + 1)
            }

            const jsInputs = Array.isArray(message.info.js) ? message.info.js : []
            const jsDetections = Array.prototype.concat.apply([],
                jsInputs.map(({ name, chain, value }) => {
                    const technology = Wappalyzer.technologies.find(({ name: _name }) => name === _name)
                    if (!technology) {
                        return []
                    }
                    const detectionsForTech = Wappalyzer.analyzeManyToMany(technology, 'js', { [chain]: [value] }) || []
                    detectionsForTech.forEach((detection) => {
                        incrementEvidence(cveEvidence.js, detection?.technology?.name)
                    })
                    return detectionsForTech
                })
            )

            const cveHtmlMatches = message.info?.htmlMatches?.cve?.matched || []
            const cveHtmlDetections = this.buildHtmlDetections(cveHtmlMatches, this.cveHtmlPatterns)
            cveHtmlDetections.forEach((detection) => {
                incrementEvidence(cveEvidence.html, detection?.technology?.name)
            })

            const cveHeaderDetections = Array.prototype.concat.apply([],
                cveHeaderMatches.map(({ techId, techName, matches }) => {
                    if (!Array.isArray(matches) || !matches.length) {
                        return []
                    }
                    const resolvedName = techId || techName
                    if (!resolvedName) {
                        return []
                    }
                    const technology =
                        Wappalyzer.technologies.find(({ name: _name }) => _name === resolvedName) ||
                        this.createTechnologyStub(resolvedName)

                    return matches.map(({ header, value, pattern }) => ({
                        technology,
                        pattern: {
                            type: 'header',
                            header,
                            value: value || '',
                            pattern: pattern || '',
                        },
                        version: ''
                    }))
                })
            )
            cveHeaderDetections.forEach((detection) => {
                incrementEvidence(cveEvidence.headers, detection?.technology?.name)
            })

            let cveDetections = []
            cveDetections = cveDetections.concat(jsDetections).concat(cveHtmlDetections).concat(cveHeaderDetections)

            const resolvedCves = Wappalyzer.resolve(cveDetections) || []
            const cveDefinitions = this.cveTechnologies || {}

            this.tab.cves = (Array.isArray(resolvedCves) ? resolvedCves : []).map((item) => {
                const id = item.name
                const raw = cveDefinitions[id] || {}
                const meta = raw.ptk || {}
                const evidence = {
                    js: cveEvidence.js.get(id) || 0,
                    html: cveEvidence.html.get(id) || 0,
                    headers: cveEvidence.headers.get(id) || 0
                }

                return {
                    id,
                    title: raw.name || item.description || id,
                    severity: meta.severity || '',
                    category: meta.category || '',
                    confidence: item.confidence || 0,
                    evidence,
                    references: meta.references || {},
                    verify: meta.verify || null
                }
            })
        } else {
            this.tab.cves = []
        }

        this.setWappalyzer(this.technologies, this.categories)

        this.tab.storage = message.info.auth
        this.tab.wappalyzerMatches = {
            dom: message.info.dom,
            js: message.info.js,
            css: message.info.css,
            headers: techHeaderMatches
        }

        let self = this
        try {
            self = JSON.parse(JSON.stringify(this))//FF fix
        } catch (e) {

        }
        browser.runtime.sendMessage({
            channel: "ptk_background2popup_dashboard",
            type: "analyze_complete",
            data: Object.assign({}, self)
        }).catch(e => e)

        return Promise.resolve()
    }

    setWappalyzer(technologies, categories) {
        Wappalyzer.technologies = []
        Wappalyzer.categories = []
        Wappalyzer.requires = []
        Wappalyzer.categoryRequires = []
        Wappalyzer.setTechnologies(technologies)
        Wappalyzer.setCategories(categories)
    }

    resolveTechnologyCategory(technology, fallback = "") {
        if (!technology) {
            return fallback || ""
        }

        const categories = Array.isArray(technology.categories) ? technology.categories : []
        if (!categories.length) {
            return fallback || ""
        }

        if (typeof categories[0] === "object") {
            const names = categories.map((category) => category?.name).filter(Boolean)
            return names.length ? names.join(", ") : fallback || ""
        }

        const names = categories
            .map((categoryId) => Wappalyzer.getCategory(categoryId))
            .filter((category) => !!category)
            .map((category) => category.name)
            .filter(Boolean)

        return names.length ? names.join(", ") : fallback || ""
    }

    createTechnologyStub(name) {
        return {
            name: name || "unknown",
            categories: [],
            icon: 'default.svg',
            excludes: [],
            implies: [],
            requires: [],
            requiresCategory: []
        }
    }

    mergeTechnologyEntries(entries = []) {
        const dedupe = new Map()

        entries.forEach((entry) => {
            if (!entry || !entry.name) {
                return
            }

            const normalized = {
                name: entry.name,
                version: entry.version || "",
                category: entry.category || "",
            }

            const existing = dedupe.get(normalized.name)
            if (!existing) {
                dedupe.set(normalized.name, normalized)
                return
            }

            if (!existing.version && normalized.version) {
                existing.version = normalized.version
            }

            if (!existing.category && normalized.category) {
                existing.category = normalized.category
            }
        })

        return Array.from(dedupe.values())
    }

    collectTabRequestsForHeaders(tabInstance) {
        const entries = []
        if (!tabInstance?.frames) {
            return entries
        }

        tabInstance.frames.forEach((requestMap, frameId) => {
            requestMap.forEach((events) => {
                if (!Array.isArray(events)) {
                    return
                }

                events.forEach((event) => {
                    if (!event || !Array.isArray(event.responseHeaders) || !event.responseHeaders.length) {
                        return
                    }

                    entries.push({
                        url: event.url,
                        method: event.method,
                        statusCode: event.statusCode,
                        requestHeaders: event.requestHeaders || [],
                        responseHeaders: event.responseHeaders || [],
                        type: event.type,
                        frameId: frameId,
                        tabId: tabInstance.tabId,
                        timeStamp: event.timeStamp || Date.now()
                    })
                })
            })
        })

        return entries
    }

    async runHeaderAnalysis(tabInstance) {
        if (!tabInstance) {
            return { securityFindings: [], techHeaderMatches: [], cveHeaderMatches: [], evidence: { evaluatedResponses: 0 } }
        }

        const requests = this.collectTabRequestsForHeaders(tabInstance)
        if (!requests.length) {
            return { securityFindings: [], techHeaderMatches: [], cveHeaderMatches: [], evidence: { evaluatedResponses: 0 } }
        }

        try {
            return await analyzeHeadersForTab({
                tabId: tabInstance.tabId || this.activeTab?.tabId,
                url: this.activeTab?.url || worker.ptk_app.proxy.activeTab?.url || "",
                requests
            })
        } catch (err) {
            console.warn('[PTK][Dashboard] Header analysis failed', err)
            return { securityFindings: [], techHeaderMatches: [], cveHeaderMatches: [], evidence: { error: err?.message } }
        }
    }

    buildHtmlDetections(matches = [], patternIndex) {
        if (!Array.isArray(matches) || !patternIndex) {
            return []
        }

        return matches.reduce((detections, { id, match }) => {
            if (!id) {
                return detections
            }

            const meta = patternIndex.get(id)

            if (!meta || !meta.pattern) {
                return detections
            }

            const technology =
                Wappalyzer.technologies.find(({ name }) => name === meta.tech) ||
                this.createTechnologyStub(meta.tech)

            const snippet = (match || '').toString()
            const resolvedMatch = snippet || meta.pattern.value || ''
            const version = Wappalyzer.resolveVersion(meta.pattern, resolvedMatch) || ''

            detections.push({
                technology,
                pattern: {
                    ...meta.pattern,
                    type: 'html',
                    value: meta.pattern.value,
                    match: resolvedMatch
                },
                version
            })

            return detections
        }, [])
    }



    /* Listeners */

    addMessageListiners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    onMessage(message, sender, sendResponse) {

        if (!ptk_utils.isTrustedOrigin(sender))
            return Promise.reject({ success: false, error: 'Error origin value' })

        if (message.channel == "ptk_popup2background_dashboard") {
            //console.log(message)
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve()
        }
    }

    async msg_run_bg_scan(message) {

        if (message.scans.dast) worker.ptk_app.rattacker.runBackroungScan(message.tabId, message.host, message.domains, message.settings)
        if (message.scans.iast) worker.ptk_app.iast.runBackroungScan(message.tabId, message.host)
        if (message.scans.sast) {
            worker.ptk_app.sast.msg_run_bg_scan({tabId: message.tabId, host: message.host, policy: message.settings.policy})
        } 
        if (message.scans.sca) worker.ptk_app.sca.runBackroungScan(message.tabId, message.host)

        let scans = {
            dast: worker.ptk_app.rattacker.engine.isRunning,
            iast: worker.ptk_app.iast.isScanRunning,
            sast: worker.ptk_app.sast.isScanRunning,
            sca: worker.ptk_app.sca.isScanRunning
        }

        return Promise.resolve(Object.assign({}, self, worker.ptk_app.proxy.activeTab, { scans: scans }))
    }

    async msg_stop_bg_scan(message) {

        if (message.scans.dast) worker.ptk_app.rattacker.stopBackroungScan()
        if (message.scans.iast) worker.ptk_app.iast.stopBackroungScan()
        if (message.scans.sast) worker.ptk_app.sast.stopBackroungScan()
        if (message.scans.sca) worker.ptk_app.sca.stopBackroungScan()

        let scans = {
            dast: worker.ptk_app.rattacker.engine.isRunning,
            iast: worker.ptk_app.iast.isScanRunning,
            sast: worker.ptk_app.sast.isScanRunning,
            sca: worker.ptk_app.sca.isScanRunning
        }

        return Promise.resolve(Object.assign({}, { scans: JSON.parse(JSON.stringify(scans)) }))
    }

    async msg_get(message) {
        return Promise.resolve(Object.assign({},
            this,
            worker.ptk_app.proxy.activeTab))
    }

    async msg_save(message) {
        if (message.items)
            this.items = message.items
        return Promise.resolve(Object.assign({},
            this,
            worker.ptk_app.proxy.activeTab))
    }

    async msg_init(message) {
        if (worker.ptk_app?.settings?.history?.route != 'index') {
            let link = ""
            if (['session', 'sca', 'iast', 'sast', 'proxy', 'rbuilder', 'rattacker', 'recording', 'decoder', 'swagger-editor', 'portscanner', 'jwt', 'xss', 'sql'].includes(worker.ptk_app.settings.history.route)) {
                link = worker.ptk_app.settings.history.route + ".html"
                if (worker.ptk_app.settings.history.hash) {
                    link += "#" + worker.ptk_app.settings.history.hash
                }
            }
            if (link != "")
                return Promise.resolve({ redirect: link, items: this.items })
        }

        let scans = {
            dast: worker.ptk_app.rattacker.engine.isRunning,
            iast: worker.ptk_app.iast.isScanRunning,
            sast: worker.ptk_app.sast.isScanRunning,
            sca: worker.ptk_app.sca.isScanRunning,
            dastSettings: worker.ptk_app.rattacker.settings
        }
        //this.Wappalyzer = Wappalyzer

        this.activeTab = worker.ptk_app.proxy.activeTab

        this.privacy = worker.ptk_app.settings.privacy

        this.setWappalyzer(this.technologies, this.categories)

        const activeTechnologies = new Set(Wappalyzer.technologies.map(({ name }) => name))

        if (!this.wappalyzerHtmlPlan?.length && this.technologies) {
            const htmlData = buildHtmlPlan(this.technologies, 'technologies')
            this.wappalyzerHtmlPlan = htmlData.plan
            this.wappalyzerHtmlPatterns = htmlData.patternIndex
        }

        if (!this.wappalyzerWafHtmlPlan?.length && this.wafTechnologies) {
            const htmlData = buildHtmlPlan(this.wafTechnologies, 'waf')
            this.wappalyzerWafHtmlPlan = htmlData.plan
            this.wappalyzerWafHtmlPatterns = htmlData.patternIndex
        }

        if (!this.cveHtmlPlan?.length && this.cveTechnologies) {
            const htmlData = buildHtmlPlan(this.cveTechnologies, 'cve')
            this.cveHtmlPlan = htmlData.plan
            this.cveHtmlPatterns = htmlData.patternIndex
        }

        this.wappalyzerDomRules = Wappalyzer.technologies
            .filter(({ dom }) => dom)
            .map(({ name, dom }) => ({ name, dom }))
            .filter(item => item.dom != "")

        this.wappalyzerJsRules = Wappalyzer.technologies
            .filter(({ js }) => js)
            .map(({ name, js }) => ({ name, js }))
            .filter(item => item.js != "")

        this.cveJsRules = Object.entries(this.cveTechnologies || {})
            .filter(([_, definition]) => definition && definition.js)
            .map(([name, definition]) => ({ name, js: definition.js }))

        if (this.technologies) {
            this.wappalyzerCssRules = buildCssPlan(this.technologies, activeTechnologies)
        } else {
            this.wappalyzerCssRules = []
        }

        if (this.activeTab?.tabId) {

            const requestId = `ptk-wappalyzer-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

            browser.tabs.sendMessage(this.activeTab.tabId, {
                channel: "ptk_background2content",
                type: "init",
                dom: this.wappalyzerDomRules,
                js: [
                    ...(this.wappalyzerJsRules || []),
                    ...(this.cveJsRules || [])
                ],
                css: this.wappalyzerCssRules,
                html: {
                    technologies: this.wappalyzerHtmlPlan || [],
                    waf: this.wappalyzerWafHtmlPlan || [],
                    cve: this.cveHtmlPlan || []
                },
                requestId: requestId
            }).catch(() => { })

            const tab = worker.ptk_app.proxy.getTab(this.activeTab.tabId)
            if (tab) {
                const result = await tab.analyze()
                this['tab'] = result
                this.tab.tabId = this.activeTab.tabId
                const headerAnalysis = await this.runHeaderAnalysis(tab)
                this.tab.findings = headerAnalysis.securityFindings
                this.tab.techHeaderMatches = headerAnalysis.techHeaderMatches
                this.tab.headerAnalysisEvidence = headerAnalysis.evidence
                this.initCookies(result.urls)

                return Object.assign({}, this, worker.ptk_app.proxy.activeTab, { findings: this.tab.findings }, { scans: scans })
            }
        }

        return Object.assign({}, worker.ptk_app.proxy.activeTab, { privacy: this.privacy }, { scans: scans })
    }

    msg_analyze(message, tab) {
        if (!this.tab) return
        this.analyzeTab(message)
        return Promise.resolve(Object.assign({}, this))
    }

    /* End Listeners */
}

