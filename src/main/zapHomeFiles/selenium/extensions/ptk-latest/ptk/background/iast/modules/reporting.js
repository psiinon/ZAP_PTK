import CryptoES from "../../../packages/crypto-es/index.js"

const ENGINE_IAST = "IAST"
const DEFAULT_CATEGORY = "runtime_issue"
const SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]
const SEVERITY_RANK = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
}

export function createFindingFromIAST(details = {}, meta = {}) {
    const now = new Date().toISOString()
    const severity = normalizeSeverity(details?.severity)
    const category = inferCategoryFromIAST(details)
    const location = buildLocation(details)
    const sinkId = details?.sinkId || details?.sink || null
    const taintSource = details?.taintSource || details?.source || details?.matched || null
    const cwe = details?.cwe || null
    const owasp = details?.owasp || null
    const ruleId = details?.ruleId || null
    const moduleId = details?.moduleId || null
    const moduleName = details?.moduleName || details?.meta?.moduleName || null
    const ruleName = details?.ruleName || details?.meta?.ruleName || null
    const message = details?.message || null
    const description = details?.description || details?.meta?.description || null
    const recommendation = details?.recommendation || details?.meta?.recommendation || null
    const links = details?.links || details?.meta?.links || null
    const contextKey = extractContextKey(details?.context)
    const fingerprint = buildFingerprint({
        url: location.url,
        sink: sinkId,
        category,
        source: taintSource,
        contextKey
    })
    const evidence = buildIASTEvidence(details)

    return {
        id: `${fingerprint}:${details?.timestamp || Date.now()}`,
        fingerprint,
        category,
        severity,
        cwe,
        owasp,
        location,
        ruleId,
        ruleName,
        moduleId,
        moduleName,
        message,
        description,
        recommendation,
        links,
        sinkId,
        source: taintSource,
        taintSource,
        engines: [ENGINE_IAST],
        evidence: [evidence],
        scanId: meta?.scanId || null,
        attackId: null,
        policyId: null,
        createdAt: now,
        updatedAt: now
    }
}

export function getFindingFingerprint(finding = {}) {
    if (finding?.fingerprint) return finding.fingerprint
    const evidence = getPrimaryEvidence(finding)
    const fallbackSource = finding?.taintSummary?.primarySource || finding?.source || null
    const contextKey =
        extractContextKey(evidence?.context) ||
        extractContextKey(evidence?.raw?.context) ||
        extractContextKey(finding?.location) ||
        null
    return buildFingerprint({
        url: extractLocationUrl(finding?.location),
        sink: evidence?.sinkId || evidence?.raw?.sinkId || evidence?.raw?.sink || finding?.sinkId || null,
        category: finding?.category || evidence?.raw?.type || null,
        source: evidence?.taintSource || evidence?.raw?.taintSource || evidence?.raw?.source || fallbackSource,
        contextKey
    })
}

export function mergeFinding(existingFinding, newFinding) {
    if (!existingFinding) return newFinding
    if (!newFinding) return existingFinding

    existingFinding.severity = pickHigherSeverity(existingFinding.severity, newFinding.severity)
    existingFinding.category = existingFinding.category || newFinding.category
    existingFinding.location = existingFinding.location || newFinding.location
    existingFinding.cwe = existingFinding.cwe || newFinding.cwe
    existingFinding.owasp = existingFinding.owasp || newFinding.owasp
    existingFinding.ruleId = existingFinding.ruleId || newFinding.ruleId
    existingFinding.moduleId = existingFinding.moduleId || newFinding.moduleId
    existingFinding.moduleName = existingFinding.moduleName || newFinding.moduleName
    existingFinding.message = existingFinding.message || newFinding.message
    existingFinding.description = existingFinding.description || newFinding.description
    existingFinding.recommendation = existingFinding.recommendation || newFinding.recommendation
    existingFinding.links = existingFinding.links || newFinding.links || null
    existingFinding.sinkId = existingFinding.sinkId || newFinding.sinkId
    existingFinding.source = existingFinding.source || newFinding.source
    existingFinding.taintSource = existingFinding.taintSource || newFinding.taintSource
    existingFinding.scanId = existingFinding.scanId || newFinding.scanId
    existingFinding.updatedAt = newFinding.updatedAt || new Date().toISOString()
    existingFinding.engines = mergeEngines(existingFinding.engines, newFinding.engines)
    existingFinding.evidence = mergeEvidence(existingFinding.evidence, newFinding.evidence)

    return existingFinding
}

function buildIASTEvidence(details = {}) {
    const sinkId = details?.sinkId || details?.sink || null
    const taintSource = details?.taintSource || details?.source || null
    return {
        source: ENGINE_IAST,
        type: "iast_sink",
        sinkId,
        matched: details?.matched || null,
        taintSource,
        context: details?.context || {},
        trace: details?.trace || null,
        ruleId: details?.ruleId || null,
        moduleId: details?.moduleId || null,
        moduleName: details?.moduleName || null,
        message: details?.message || null,
        raw: details
    }
}

function normalizeSeverity(severity) {
    if (!severity && severity !== 0) return "info"
    const normalized = String(severity).toLowerCase()
    if (SEVERITY_LEVELS.includes(normalized)) return normalized
    if (!Number.isNaN(Number(normalized))) {
        const numeric = Number(normalized)
        if (numeric >= 8) return "high"
        if (numeric >= 5) return "medium"
        if (numeric > 0) return "low"
    }
    return "info"
}

function inferCategoryFromIAST(details = {}) {
    const sink = String(details?.sink || "").toLowerCase()
    const type = String(details?.type || "").toLowerCase()
    if (sink.includes("innerhtml") || sink.includes("document.write") || type.includes("xss")) {
        return "xss"
    }
    if (sink.includes("location") || sink.includes("href") || type.includes("redirect")) {
        return "open_redirect"
    }
    if (type) return type
    return DEFAULT_CATEGORY
}

function buildLocation(details = {}) {
    const location = details?.location
    if (location && typeof location === "object" && !Array.isArray(location)) {
        return {
            url: extractLocationUrl(location.url || location.href || null),
            scriptUrl: location.scriptUrl || null,
            line: sanitizeNumber(location.line),
            column: sanitizeNumber(location.column),
            domPath: location.domPath || null
        }
    }

    const context = details?.context || {}
    return {
        url: extractLocationUrl(location),
        scriptUrl: context.scriptUrl || null,
        line: sanitizeNumber(context.line),
        column: sanitizeNumber(context.column),
        domPath: context.domPath || context.element || null
    }
}

function buildFingerprint({ url = "", sink = "", category = "", source = "", contextKey = "" }) {
    const normalizedUrl = normalizeUrl(url)
    const payload = [normalizedUrl, sink || "", category || "", source || "", contextKey || ""].join("|")
    return CryptoES.SHA1(payload).toString(CryptoES.enc.Hex)
}

function normalizeUrl(url) {
    if (!url) return ""
    try {
        const u = new URL(url)
        u.hash = ""
        return u.toString()
    } catch (e) {
        return String(url)
    }
}

function extractContextKey(context = {}) {
    if (!context) return null
    if (typeof context !== "object") {
        try {
            return String(context)
        } catch (_) {
            return null
        }
    }
    return context.domPath || context.elementId || context.attribute || context.property || context.method || null
}

function sanitizeNumber(value) {
    if (Number.isFinite(value)) return value
    const parsed = Number(value)
    return Number.isFinite(parsed) ? parsed : null
}

function extractLocationUrl(location) {
    if (!location) return null
    if (typeof location === "string") return location
    if (typeof location === "object") {
        return location.url || location.href || null
    }
    return null
}

function mergeEngines(existing = [], incoming = []) {
    const merged = new Set()
    if (Array.isArray(existing)) existing.forEach(engine => merged.add(engine))
    if (Array.isArray(incoming)) incoming.forEach(engine => merged.add(engine))
    return Array.from(merged)
}

function mergeEvidence(existing = [], incoming = []) {
    const evidence = Array.isArray(existing) ? [...existing] : []
    const incomingEvidence = Array.isArray(incoming) ? incoming : []
    incomingEvidence.forEach(ev => {
        if (!ev) return
        if (!hasEvidence(evidence, ev)) {
            evidence.push(ev)
        }
    })
    return evidence
}

function hasEvidence(collection, candidate) {
    return collection.some(item => (
        item?.source === candidate?.source &&
        item?.type === candidate?.type &&
        item?.sinkId === candidate?.sinkId &&
        item?.matched === candidate?.matched &&
        item?.trace === candidate?.trace
    ))
}

function getPrimaryEvidence(finding = {}) {
    if (!Array.isArray(finding?.evidence)) return null
    return finding.evidence.find(e => e?.source === ENGINE_IAST) || finding.evidence[0]
}

function pickHigherSeverity(existing, incoming) {
    const existingKey = normalizeSeverity(existing)
    const incomingKey = normalizeSeverity(incoming)
    return SEVERITY_RANK[incomingKey] > SEVERITY_RANK[existingKey] ? incomingKey : existingKey
}
