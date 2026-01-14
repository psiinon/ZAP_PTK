/* Author: Denis Podgurskii */

const __PTK_IAST_DBG_PREFIX__ = '[PTK IAST DEBUG]';
const __PTK_IAST_DBG__ = (...args) => { try { console.info(__PTK_IAST_DBG_PREFIX__, ...args); } catch (_) { } };

__PTK_IAST_DBG__('agent init start');
let __IAST_DISABLE_HOOKS__ = false;
// Dynamic IAST modules + rule registry, populated from background at runtime.
let IAST_MODULES = null;
const IAST_RULE_INDEX = {
    bySinkId: Object.create(null),
    byRuleId: Object.create(null),
};
let __IAST_LAST_MODULES_REQUEST__ = 0;

function resetIastRuleIndex() {
    IAST_MODULES = null;
    IAST_RULE_INDEX.bySinkId = Object.create(null);
    IAST_RULE_INDEX.byRuleId = Object.create(null);
}

function initIastRuleIndex(modulesJson) {
    resetIastRuleIndex();
    if (!modulesJson || !Array.isArray(modulesJson.modules)) {
        __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: invalid modulesJson', modulesJson);
        return;
    }

    IAST_MODULES = modulesJson;

    for (const mod of modulesJson.modules) {
        const moduleId = mod.id;
        const moduleName = mod.name;
        const moduleMeta = mod.metadata || {};

        if (!Array.isArray(mod.rules)) continue;

        for (const rule of mod.rules) {
            const entry = {
                moduleId,
                moduleName,
                moduleMeta,
                ruleId: rule.id,
                ruleName: rule.name,
                sinkId: rule.sinkId || null,
                ruleMeta: rule.metadata || {},
                hook: rule.hook || null,
                conditions: rule.conditions || {},
            };

            if (entry.sinkId) {
                IAST_RULE_INDEX.bySinkId[entry.sinkId] = entry;
            }
            if (entry.ruleId) {
                IAST_RULE_INDEX.byRuleId[entry.ruleId] = entry;
            }
        }
    }

    //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: rule index initialised', IAST_RULE_INDEX);
}

function mergeLinks(baseLinks, overrideLinks) {
    const result = Object.assign({}, baseLinks || {})
    if (overrideLinks && typeof overrideLinks === 'object') {
        Object.entries(overrideLinks).forEach(([key, value]) => {
            if (key) result[key] = value
        })
    }
    return Object.keys(result).length ? result : null
}

const IAST_SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info']

function normalizeIastSeverityValue(value, fallback = 'medium') {
    if (value === null || value === undefined) return fallback
    const normalized = String(value).trim().toLowerCase()
    if (IAST_SEVERITY_LEVELS.includes(normalized)) return normalized
    if (!Number.isNaN(Number(normalized))) {
        const numeric = Number(normalized)
        if (numeric >= 8) return 'high'
        if (numeric >= 5) return 'medium'
        if (numeric > 0) return 'low'
    }
    return fallback
}

function resolveIastEffectiveSeverity({ override, moduleMeta = {}, ruleMeta = {} } = {}) {
    if (override !== null && override !== undefined) {
        return normalizeIastSeverityValue(override)
    }
    if (ruleMeta?.severity != null) {
        return normalizeIastSeverityValue(ruleMeta.severity)
    }
    if (moduleMeta?.severity != null) {
        return normalizeIastSeverityValue(moduleMeta.severity)
    }
    return 'medium'
}

function getIastRuleBySinkId(sinkId) {
    return sinkId ? IAST_RULE_INDEX.bySinkId[sinkId] || null : null;
}

function getIastRuleByRuleId(ruleId) {
    return ruleId ? IAST_RULE_INDEX.byRuleId[ruleId] || null : null;
}

window.addEventListener('message', (event) => {
    const data = event.data || {}
    if (data.channel === 'ptk_background_iast2content_modules' && data.iastModules) {
        initIastRuleIndex(data.iastModules)
        //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: modules received from bridge')
    }
})

// On load, request the current IAST modules from background (helps after reloads)
try {
    requestModulesFromBackground(true)
} catch (_) {
    // ignore if not in extension context
}

function requestModulesFromBackground(force = false) {
    const now = Date.now();
    if (!force && now - __IAST_LAST_MODULES_REQUEST__ < 2000) {
        return;
    }
    __IAST_LAST_MODULES_REQUEST__ = now;
    try {
        window.postMessage({ channel: 'ptk_content_iast_request_modules' }, '*');
    } catch (e) {
        __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: modules request exception', e);
    }
}

// Deduplication set for mutation hooks
const __IAST_REPORTED_NODES__ = new Set();

// Encoding helpers
function withoutHooks(fn) {
    const prev = __IAST_DISABLE_HOOKS__;
    __IAST_DISABLE_HOOKS__ = true;
    try {
        return fn();
    } finally {
        __IAST_DISABLE_HOOKS__ = prev;
    }
}

// Re-write htmlDecode & htmlEncode

function htmlDecode(input) {
    return withoutHooks(() => {
        const ta = document.createElement('textarea');
        ta.innerHTML = input;
        return ta.value;
    });
}

function htmlEncode(input) {
    return withoutHooks(() => {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    });
}

let __IAST_MATCH_COUNT__ = 0;

function getDomPath(node) {
    try {
        if (!node || node.nodeType !== 1) return null;
        const parts = [];
        let el = node;
        while (el && el.nodeType === 1 && parts.length < 10) {
            let part = el.tagName.toLowerCase();
            if (el.id) {
                part += `#${el.id}`;
                parts.unshift(part);
                break;
            }
            if (el.classList && el.classList.length) {
                part += '.' + Array.from(el.classList).slice(0, 3).join('.');
            }
            if (el.parentElement) {
                const siblings = Array.from(el.parentElement.children).filter(c => c.tagName === el.tagName);
                if (siblings.length > 1) {
                    const idx = siblings.indexOf(el);
                    part += `:nth-of-type(${idx + 1})`;
                }
            }
            parts.unshift(part);
            el = el.parentElement;
        }
        return parts.length ? parts.join(' > ') : null;
    } catch (_) {
        return null;
    }
}

function computeDomPath(el) {
    try {
        if (!el || el.nodeType !== 1) return null;
        const segments = [];
        let node = el;
        let safety = 0;
        while (node && node.nodeType === 1 && safety < 50) {
            safety++;
            const tag = (node.tagName || '').toLowerCase();
            if (!tag) break;
            let part = tag;
            if (node.id) {
                part += `#${node.id}`;
            } else if (node.classList && node.classList.length) {
                part += '.' + Array.from(node.classList).slice(0, 3).join('.');
            }
            if (!node.id && node.parentElement) {
                let idx = 1;
                let sib = node;
                while ((sib = sib.previousElementSibling)) {
                    if (sib.tagName === node.tagName) idx++;
                }
                if (idx > 1) part += `:nth-of-type(${idx})`;
            }
            segments.unshift(part);
            node = node.parentElement;
            if (node === document.documentElement) {
                segments.unshift('html');
                break;
            }
        }
        return segments.join(' > ');
    } catch (_) {
        return null;
    }
}

function enrichContext(ctx = {}) {
    const context = Object.assign({}, ctx);
    const el = context.element;
    if (el && el.nodeType === 1) {
        context.tagName = el.tagName ? el.tagName.toLowerCase() : context.tagName;
        context.elementId = el.id || context.elementId || null;
        if (el.classList && el.classList.length) {
            context.elementClasses = Array.from(el.classList);
        }
        if (!context.domPath) {
            context.domPath = computeDomPath(el);
        }
        if (el.outerHTML && !context.elementOuterHTML) {
            const html = String(el.outerHTML);
            context.elementOuterHTML = html.length > 1024 ? html.slice(0, 1024) : html;
        }
    } else if (context.element && typeof context.element === 'string' && !context.domPath) {
        try {
            const tmp = document.createElement('div');
            tmp.innerHTML = context.element;
            const first = tmp.firstElementChild;
            const path = computeDomPath(first);
            if (path) context.domPath = path;
        } catch (_) { }
    }
    if (!context.domPath && context.target && context.target.nodeType === 1) {
        const path = computeDomPath(context.target);
        if (path) context.domPath = path;
    }
    delete context.element;
    delete context.target;
    return context;
}

// Taint collection
window.__IAST_TAINT_META__ = window.__IAST_TAINT_META__ || {};

function getTaintMetaEntry(key) {
    if (!key) return null;
    return window.__IAST_TAINT_META__?.[key] || null;
}

function updateTaintMetaEntry(key, extras = {}) {
    if (!key) return null;
    const store = window.__IAST_TAINT_META__ = window.__IAST_TAINT_META__ || {};
    const current = store[key] || {};
    if (extras && typeof extras === 'object') {
        Object.entries(extras).forEach(([k, v]) => {
            if (v !== undefined && v !== null) {
                current[k] = v;
            }
        });
    }
    current.lastUpdated = Date.now();
    store[key] = current;
    return current;
}

function collectTaintedSources() {
    const raw = {};
    const add = (key, valRaw, metaOverride = null) => {
        if (!valRaw) return;
        let val = String(valRaw).trim().replace(/^#/, '');
        const hasAlnum = /[A-Za-z0-9]/.test(val);
        if (!hasAlnum && val !== '/') return;
        raw[key] = val;
        const meta = Object.assign({}, metaOverride || describeSourceKey(key, val));
        updateTaintMetaEntry(key, { taintKind: meta.taintKind });
        registerTaintSource(key, val, meta);
    };
    for (const [k, v] of new URLSearchParams(location.search)) add(`query:${k}`, v);
    purgeHashTaintEntries();
    collectHashSources().forEach(src => add(src.key, src.value, src.meta));
    if (document.referrer) add('referrer', document.referrer);
    document.cookie.split(';').forEach(c => {
        const [k, v] = c.split('=').map(s => s.trim());
        const decodedVal = decodeURIComponent(v || '');
        add(`cookie:${k}`, decodedVal, createCookieSourceMeta(k, decodedVal));
    });
    ['localStorage', 'sessionStorage'].forEach(store => {
        try {
            for (let i = 0; i < window[store].length; i++) {
                const key = window[store].key(i), val = window[store].getItem(key);
                add(`${store}:${key}`, val);
            }
        } catch { };
    });
    if (window.name) add('window.name', window.name);
    //console.info('[IAST] Collected taints', raw);
    return raw;
}
window.__IAST_TAINT_GRAPH__ = window.__IAST_TAINT_GRAPH__ || {};
window.__IAST_TAINTED__ = collectTaintedSources();

function captureStackTrace(label = 'IAST flow') {
    try {
        return (new Error(label)).stack;
    } catch (_) {
        return null;
    }
}

function captureElementMeta(el) {
    if (!el || typeof el !== 'object') return {};
    return {
        domPath: getDomPath(el),
        elementId: el.id || null,
        elementTag: el.tagName ? el.tagName.toLowerCase() : null
    };
}

function describeSourceKey(key, rawValue) {
    if (!key) return {};
    const meta = {
        label: key,
        detail: key,
        location: window.location.href,
        value: rawValue
    };
    if (key.startsWith('query:')) {
        meta.type = 'query';
        meta.label = `Query parameter "${key.slice(6)}"`;
        meta.detail = key.slice(6) || key;
        meta.taintKind = 'user_input';
    } else if (key.startsWith('cookie:')) {
        meta.type = 'cookie';
        meta.label = `Cookie "${key.slice(7)}"`;
        meta.detail = key.slice(7) || key;
        meta.sourceKind = 'cookie';
        meta.taintKind = 'user_input';
    } else if (key.startsWith('localStorage:')) {
        meta.type = 'localStorage';
        meta.label = `localStorage["${key.slice(13)}"]`;
    } else if (key.startsWith('sessionStorage:')) {
        meta.type = 'sessionStorage';
        meta.label = `sessionStorage["${key.slice(15)}"]`;
    } else if (key === 'hash') {
        meta.type = 'hash';
        meta.label = 'Location hash';
        meta.taintKind = 'user_input';
    } else if (key === 'referrer') {
        meta.type = 'referrer';
        meta.label = 'document.referrer';
    } else if (key === 'hash:route') {
        meta.type = 'hashRoute';
        meta.label = 'Location hash route';
        meta.detail = rawValue || key;
        meta.taintKind = 'user_input';
    } else if (key.startsWith('hash:param:')) {
        const paramName = key.slice('hash:param:'.length) || 'param';
        meta.type = 'hashParam';
        meta.label = `Location hash parameter "${paramName}"`;
        meta.detail = paramName;
        meta.taintKind = 'user_input';
    } else if (key.startsWith('inline:')) {
        meta.type = 'inline';
        meta.label = `Inline value "${key.slice(7)}"`;
        meta.taintKind = 'user_input';
    }
    return meta;
}

function normalizeSourceEntry(entry, fallbackKey = null, fallbackRaw = null) {
    const provided = entry || {};
    const key = provided.key || provided.source || fallbackKey;
    if (!key) return null;
    const providedRaw = Object.prototype.hasOwnProperty.call(provided, 'raw')
        ? provided.raw
        : (Object.prototype.hasOwnProperty.call(provided, 'value') ? provided.value : undefined);
    const rawValue = providedRaw !== undefined ? providedRaw : fallbackRaw;
    const descriptor = describeSourceKey(key, rawValue);
    const storedMeta = getTaintMetaEntry(key) || {};
    const normalized = Object.assign({}, provided, {
        key,
        source: key,
        raw: rawValue,
        value: rawValue,
        label: provided.label || descriptor.label || key,
        detail: provided.detail || descriptor.detail || key,
        location: provided.location || descriptor.location || storedMeta.location || window.location.href,
        taintKind: provided.taintKind || storedMeta.taintKind || descriptor.taintKind || null,
        sourceKind: provided.sourceKind || storedMeta.sourceKind || descriptor.sourceKind || null
    });
    normalized.__normalizedSource = true;
    return normalized;
}

function normalizeTaintedSources(sourceMatches, fallbackRaw = null) {
    if (!Array.isArray(sourceMatches)) return [];
    return sourceMatches
        .map(entry => normalizeSourceEntry(entry, entry?.key || entry?.source || null, entry?.raw ?? fallbackRaw))
        .filter(Boolean);
}

function formatSourceForReport(source) {
    if (!source) return 'Unknown source';
    const key = (source.key || source.source || '').toLowerCase();
    const detail = source.detail || source.label || key || 'source';
    const rawValue = source.value != null ? String(source.value) : (source.raw != null ? String(source.raw) : '');
    if (key.startsWith('hash:param:')) {
        return `location.hash parameter "${detail}" (value: "${rawValue}")`;
    }
    if (key === 'hash') {
        return `location.hash value "${rawValue || detail}"`;
    }
    if (key === 'hash:route') {
        return `location.hash route "${rawValue || detail}"`;
    }
    if (key.startsWith('query:param:') || key.startsWith('query:')) {
        return `location.search parameter "${detail}" (value: "${rawValue}")`;
    }
    if (key.startsWith('cookie:')) {
        return `document.cookie "${detail}" (value: "${rawValue}")`;
    }
    if (key.startsWith('body:param:')) {
        return `request body parameter "${detail}" (value: "${rawValue}")`;
    }
    if (source.label && rawValue !== '') {
        return `${source.label} (${rawValue})`;
    }
    if (source.label) return source.label;
    if (source.source || source.key) return source.source || source.key;
    return 'Unknown source';
}

const DOM_XSS_SINK_IDS = new Set([
    'dom.inline_event',
    'dom.innerHTML',
    'dom.outerHTML',
    'dom.insertAdjacentHTML',
    'dom.mutation',
    'document.write',
    'nav.iframe.srcdoc'
]);

function purgeHashTaintEntries() {
    const taints = window.__IAST_TAINTED__ || {};
    const meta = window.__IAST_TAINT_META__ || {};
    const graph = window.__IAST_TAINT_GRAPH__ || {};
    Object.keys(taints).forEach(key => {
        if (key === 'hash' || key.startsWith('hash:')) {
            delete taints[key];
            delete meta[key];
            delete graph[key];
        }
    });
}

function createHashSource({ key, label, op, detail, value }) {
    return {
        key,
        value,
        meta: {
            type: 'hash',
            label: label || key,
            detail: detail || key,
            op: op || 'hash',
            location: window.location.href,
            value,
            taintKind: 'user_input'
        }
    };
}

function createCookieSourceMeta(name, value, overrides = {}) {
    const detail = (name || '').trim() || 'cookie';
    return Object.assign({
        type: 'cookie',
        label: `Cookie "${detail}"`,
        detail,
        sourceKind: 'cookie',
        taintKind: 'user_input',
        op: 'document.cookie',
        location: window.location.href,
        value
    }, overrides);
}

function collectHashSources() {
    let raw = window.location.hash || '';
    if (raw.startsWith('#')) raw = raw.slice(1);
    try {
        raw = decodeURIComponent(raw);
    } catch (_) {
        raw = raw;
    }
    const normalized = (raw || '').trim();
    // Skip trivial hashes like "#" or "#/" to avoid tainting everything with base routes.
    if (!normalized || normalized === '/' || normalized === '#/' || normalized === '#') {
        return [];
    }
    const [routePartRaw, queryPartRaw] = normalized.split('?');
    const sources = [];
    const routePart = (routePartRaw || '').trim();
    if (routePart && routePart !== '/' && routePart !== '#/') {
        sources.push(createHashSource({
            key: 'hash:route',
            label: 'Location hash route',
            op: 'hashRoute',
            detail: routePart,
            value: routePart
        }));
    }
    if (queryPartRaw && queryPartRaw.trim()) {
        const params = new URLSearchParams(queryPartRaw);
        for (const [name, value] of params.entries()) {
            const trimmedName = (name || '').trim();
            const trimmedVal = (value || '').trim();
            if (!trimmedName || !trimmedVal) continue;
            sources.push(createHashSource({
                key: `hash:param:${trimmedName}`,
                label: `Location hash parameter "${trimmedName}"`,
                op: 'hashParam',
                detail: trimmedName,
                value: trimmedVal
            }));
        }
    }
    return sources;
}

function isMeaningfulSourceValue(value) {
    if (value == null) return false;
    const trimmed = String(value).trim();
    if (!trimmed) return false;
    if (trimmed.length < 3) return false;
    if (trimmed === '/' || trimmed === '#/' || trimmed === '#') return false;
    return true;
}

function isSourceMatchingValue(sourceValue, sinkValue) {
    if (!isMeaningfulSourceValue(sourceValue)) return false;
    const sinkStr = String(sinkValue || '');
    const sourceStr = String(sourceValue || '');
    if (!sinkStr || !sourceStr) return false;
    return sinkStr.indexOf(sourceStr) !== -1;
}

function resolveUrlRelative(url) {
    if (!url) return null;
    try {
        return new URL(url, window.location.href);
    } catch (_) {
        return null;
    }
}

function isCrossOriginUrl(url) {
    const resolved = resolveUrlRelative(url);
    if (!resolved) return false;
    return resolved.origin !== window.location.origin;
}

function looksLikeInternalRoute(url) {
    if (!url) return false;
    const str = String(url).trim();
    if (!str) return false;
    if (str === '/' || str === '#/' || str === '#') return true;
    if (str.startsWith('#/')) return true;
    if (str.startsWith('/')) return true;
    return false;
}

function shouldReportNavigationSink(targetUrl) {
    if (!targetUrl) return false;
    if (looksLikeInternalRoute(targetUrl)) {
        // Ignore internal SPA routes like /login or #/search to reduce noise.
        return false;
    }
    return isCrossOriginUrl(targetUrl);
}

function looksLikeXssPayload(value) {
    if (value == null) return false;
    const str = String(value);
    const trimmed = str.trim();
    if (!trimmed) return false;
    const lower = trimmed.toLowerCase();
    const hasAngleBrackets = /[<>]/.test(trimmed);
    const hasJsScheme = lower.includes('javascript:');
    const hasOnEvent = lower.includes('onerror') || lower.includes('onload') || lower.includes('onclick') || lower.includes('onmouseover');
    const hasDangerousTags = lower.includes('<script') || lower.includes('<img') || lower.includes('<svg') || lower.includes('<iframe');
    if (hasJsScheme || hasOnEvent || hasDangerousTags) return true;
    if (hasAngleBrackets && (hasOnEvent || hasDangerousTags)) return true;
    return false;
}

function isUserControlledSource(source) {
    if (!source) return false;
    if (source.taintKind === 'user_input') return true;
    const key = (source.key || source.source || '').toLowerCase();
    if (!key) return false;
    if (key.startsWith('hash:param:')) return true;
    if (key === 'hash:route' || key === 'hash') return true;
    if (key.startsWith('query:param:') || key.startsWith('query:')) return true;
    if (key.startsWith('cookie:')) return true;
    if (key.startsWith('body:param:') || key.startsWith('body:')) return true;
    if (key.startsWith('inline:')) return true;
    return false;
}

function isCookieSource(source) {
    if (!source) return false;
    if (source.sourceKind === 'cookie') return true;
    const key = (source.key || source.source || '').toLowerCase();
    if (!key) return false;
    return key.startsWith('cookie:');
}

function shouldReportDomXss(attrName, newValue, taintedSources = []) {
    const sources = Array.isArray(taintedSources) ? taintedSources : [];
    const attr = (attrName || '').toLowerCase();
    if (attr === 'routerlink' || attr === 'routerlinkactive' || attr === 'ng-reflect-router-link') {
        // Router attributes pointing to internal routes are not interesting sinks.
        return false;
    }
    const hasUserInput = sources.some(isUserControlledSource);
    const cookieSources = sources.filter(isCookieSource);
    const hasCookieSources = cookieSources.length > 0;

    if (hasCookieSources && sources.length === cookieSources.length) {
        const cookieHasXssPayload = cookieSources.some(src => looksLikeXssPayload(src?.value ?? src?.raw));
        if (!cookieHasXssPayload) {
            return false;
        }
    }

    if (hasUserInput) {
        if (attr === 'innerhtml' || attr === 'outerhtml' || !attr) {
            return true;
        }
        if (attr === 'href' || attr === 'src' || attr.startsWith('on')) {
            return true;
        }
        return false;
    }
    const valueStr = newValue == null ? '' : String(newValue);
    if ((attr === 'href' || attr === 'src') && !looksLikeXssPayload(valueStr)) {
        return false;
    }
    return looksLikeXssPayload(valueStr);
}

function isSuspiciousExfilUrl(url) {
    if (!url) return false;
    const str = String(url);
    if (isCrossOriginUrl(str)) return true;
    const lower = str.toLowerCase();
    if (lower.includes('callback') || lower.includes('webhook') || lower.includes('tracking') || lower.includes('pixel')) {
        return true;
    }
    if (lower.includes('token=') || lower.includes('session=') || lower.includes('auth=')) {
        return true;
    }
    return false;
}

function shouldSkipSinkByHeuristics(value, info = {}, context = {}, taintedSources = []) {
    const sinkId = info?.sinkId || info?.sink || null;
    if (!sinkId) return false;
    if (DOM_XSS_SINK_IDS.has(sinkId)) {
        const attrName = context.attribute || context.attr || context.attrName || context.eventType || null;
        const sources = Array.isArray(taintedSources) && taintedSources.length ? taintedSources : (context.taintedSources || []);
        if (!shouldReportDomXss(attrName, value, sources)) {
            return true;
        }
    }
    return false;
}

function registerTaintSource(key, value, meta = {}) {
    if (!key) return;
    updateTaintMetaEntry(key, { taintKind: meta.taintKind });
    window.__IAST_TAINT_GRAPH__[key] = {
        node: {
            key,
            label: meta.label || key,
            type: meta.type || 'source',
            detail: meta.detail || key,
            domPath: meta.domPath || null,
            elementId: meta.elementId || null,
            attribute: meta.attribute || null,
            location: meta.location || window.location.href,
            value,
            op: meta.op || meta.type || 'source',
            stack: meta.stack || captureStackTrace('IAST source'),
            timestamp: Date.now()
        },
        parents: []
    };
}

function registerTaintPropagation(key, value, matchResult, meta = {}) {
    if (!key) return;
    updateTaintMetaEntry(key, { taintKind: meta.taintKind });
    const parents = Array.isArray(matchResult?.allSources)
        ? matchResult.allSources
            .filter(src => src && src.source)
            .map(src => ({ key: src.source }))
        : [];
    window.__IAST_TAINT_GRAPH__[key] = {
        node: {
            key,
            label: meta.label || key,
            type: meta.type || 'propagation',
            detail: meta.detail || '',
            domPath: meta.domPath || null,
            elementId: meta.elementId || null,
            attribute: meta.attribute || null,
            location: meta.location || window.location.href,
            value,
            op: meta.op || 'propagation',
            stack: meta.stack || captureStackTrace(meta.op || 'propagation'),
            timestamp: Date.now()
        },
        parents
    };
}

function ensureTaintGraphEntry(key, value, meta = {}) {
    if (meta.parentsMatch) {
        registerTaintPropagation(key, value, meta.parentsMatch, meta);
    } else {
        registerTaintSource(key, value, meta);
    }
}

function buildTaintFlowChain(key, depth = 0, visited = new Set()) {
    if (!key || depth > 20 || visited.has(key)) return [];
    visited.add(key);
    const entry = window.__IAST_TAINT_GRAPH__?.[key];
    if (!entry) {
        return [{
            stage: depth === 0 ? 'source' : 'propagation',
            key,
            label: key,
            value: window.__IAST_TAINTED__?.[key] || null
        }];
    }
    const parents = entry.parents && entry.parents.length ? entry.parents : null;
    let parentChain = [];
    if (parents && parents.length) {
        parentChain = buildTaintFlowChain(parents[0].key, depth + 1, visited);
    }
    const node = Object.assign({
        stage: parents && parents.length ? 'propagation' : 'source',
        key: entry.node?.key || key,
        label: entry.node?.label || key,
        detail: entry.node?.detail || '',
        domPath: entry.node?.domPath || null,
        elementId: entry.node?.elementId || null,
        attribute: entry.node?.attribute || null,
        location: entry.node?.location || null,
        value: entry.node?.value || null,
        op: entry.node?.op || null,
        stack: entry.node?.stack || null,
        timestamp: entry.node?.timestamp || Date.now()
    });
    return parentChain.concat([node]);
}

function buildTaintFlow(match, sinkMeta = {}) {
    if (!match) return [];
    const chain = buildTaintFlowChain(match.source) || [];
    const sinkNode = {
        stage: 'sink',
        key: sinkMeta.sinkId || sinkMeta.sink || 'sink',
        label: sinkMeta.sink || sinkMeta.sinkId || 'sink',
        op: sinkMeta.ruleId || sinkMeta.type || 'sink',
        domPath: sinkMeta.domPath || null,
        elementId: sinkMeta.elementId || null,
        attribute: sinkMeta.attribute || null,
        location: sinkMeta.location || window.location.href,
        value: sinkMeta.value || null,
        detail: sinkMeta.detail || null
    };
    return chain.concat([sinkNode]);
}

function buildRuleBinding({ sinkId, ruleId, fallbackType }) {
    const ruleEntry = sinkId ? getIastRuleBySinkId(sinkId) : (ruleId ? getIastRuleByRuleId(ruleId) : null);
    const ruleMeta = ruleEntry?.ruleMeta || {};
    return {
        sink: sinkId || ruleEntry?.sinkId || ruleMeta?.sink || fallbackType || 'iast_sink',
        sinkId: ruleEntry?.sinkId || sinkId || null,
        ruleId: ruleEntry?.ruleId || ruleId || null,
        type: ruleMeta?.message || ruleEntry?.ruleName || ruleMeta?.category || fallbackType || 'iast_sink'
    };
}
// Dynamic monitoring (storage, cookie, window.name, hash)
(function () {
    const taints = window.__IAST_TAINTED__;
    const meta = window.__IAST_TAINT_META__;
    const record = (key, val, options = {}) => {
        if (!val) return;
        const s = String(val);
        const hasAlnum = /[A-Za-z0-9]/.test(s);
        if (!hasAlnum && s !== '/') return;
        taints[key] = s;
        updateTaintMetaEntry(key, { taintKind: options.taintKind });
        ensureTaintGraphEntry(key, s, options);
        //console.info('[IAST] Updated source', key, s);
    };
    const refreshHashSources = () => {
        purgeHashTaintEntries();
        const sources = collectHashSources();
        sources.forEach(src => {
            record(src.key, src.value, Object.assign({}, src.meta));
        });
    };
    // Storage wrappers
    const proto = Storage.prototype;
    ['setItem', 'removeItem', 'clear'].forEach(fn => {
        const orig = proto[fn];
        proto[fn] = function (k, v) {
            const area = this === localStorage ? 'localStorage' : 'sessionStorage';
            if (fn === 'setItem') {
                const match = matchesTaint(v);
                const elMeta = captureElementMeta(document?.activeElement || null);
                const sinkId = area === 'localStorage' ? 'storage.localStorage.setItem' : 'storage.sessionStorage.setItem';
                const ruleId = area === 'localStorage' ? 'localstorage_token_persist' : 'sessionstorage_token_persist';
                const binding = buildRuleBinding({ sinkId, ruleId, fallbackType: 'storage-token-leak' });
                record(`${area}:${k}`, v, {
                    label: `${area}:${k}`,
                    type: area,
                    op: `${area}.setItem`,
                    domPath: elMeta.domPath,
                    elementId: elMeta.elementId,
                    parentsMatch: match
                });
                maybeReportTaintedValue(v, binding, Object.assign({ storageKey: k, storageArea: area, value: v }, elMeta), match);
            }
            if (fn === 'removeItem') delete taints[`${this === localStorage ? 'localStorage' : 'sessionStorage'}:${k}`];
            if (fn === 'clear') Object.keys(taints)
                .filter(x => x.startsWith(this === localStorage ? 'localStorage:' : 'sessionStorage:'))
                .forEach(x => delete taints[x]);
            return orig.apply(this, arguments);
        };
    });
    // window.name
    if (typeof window.__defineSetter__ === 'function') {
        let cur = window.name;
        window.__defineSetter__('name', v => {
            cur = v;
            record('window.name', v, describeSourceKey('window.name', v));
        });
        window.__defineGetter__('name', () => cur);
    }
    // cookie
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (desc && desc.configurable) {
        Object.defineProperty(Document.prototype, 'cookie', {
            get() { return desc.get.call(document); },
            set(v) {
                const res = desc.set.call(document, v);
                const [p = ""] = v.split(';');
                const [k = "", rawVal = ""] = p.split('=');
                let decoded = '';
                try {
                    decoded = decodeURIComponent(rawVal || '');
                } catch (_) {
                    decoded = rawVal || '';
                }
                const match = matchesTaint(decoded);
                const elMeta = captureElementMeta(document?.activeElement || null);
                const binding = buildRuleBinding({
                    sinkId: 'storage.document.cookie',
                    ruleId: 'cookie_token_persist',
                    fallbackType: 'storage-token-leak'
                });
                record(`cookie:${k}`, decoded, Object.assign(
                    createCookieSourceMeta(k, decoded, { value: decoded }),
                    {
                        domPath: elMeta.domPath,
                        elementId: elMeta.elementId,
                        parentsMatch: match
                    }
                ));
                maybeReportTaintedValue(decoded, binding, Object.assign({ cookieName: k, rawCookie: v, value: decoded }, elMeta), match);
                return res;
            },
            configurable: true
        });
    }
    // hashchange
    window.addEventListener('hashchange', () => {
        refreshHashSources();
    });
})();

// Inline source capture: trap input.value reads
(function () {
    const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (desc && desc.get && desc.set) {
        Object.defineProperty(HTMLInputElement.prototype, 'value', {
            get: function () {
                const val = desc.get.call(this);
                if (val) {
                    const key = `inline:${this.id || this.name || 'input'}`;
                    const value = String(val);
                    window.__IAST_TAINTED__[key] = value;
                    updateTaintMetaEntry(key, { taintKind: 'user_input' });
                    const meta = Object.assign({ type: 'inline', label: key, taintKind: 'user_input' }, captureElementMeta(this));
                    registerTaintSource(key, value, meta);
                    //console.info('[IAST] Captured inline taint from', this.id || this.name || 'input', val);
                }
                return val;
            },
            set: function (v) { return desc.set.call(this, v); },
            configurable: true
        });
    }
})();


function matchesTaint(input) {
    if (__IAST_DISABLE_HOOKS__) return null;
    let rawStr = String(input || '');
    try { rawStr = htmlDecode(rawStr); } catch { }
    rawStr = rawStr.toLowerCase();
    if (!/[a-z0-9\/]/i.test(rawStr)) return null;

    const taints = Object.entries(window.__IAST_TAINTED__ || {}).filter(([, v]) => v);
    const meta = window.__IAST_TAINT_META__ || {};
    const matches = [];

    const kindOf = (key) => {
        if (key.startsWith('query:')) return 'query';
        if (key === 'hash') return 'hash';
        if (key === 'referrer') return 'referrer';
        if (key.startsWith('cookie:')) return 'cookie';
        if (key.startsWith('localStorage:')) return 'localStorage';
        if (key.startsWith('sessionStorage:')) return 'sessionStorage';
        if (key === 'window.name') return 'window.name';
        if (key.startsWith('inline:')) return 'inline';
        return 'other';
    };

    const kindPriority = (kind) => {
        switch (kind) {
            case 'query': return 100;
            case 'hash': return 90;
            case 'inline': return 80;
            case 'localStorage': return 70;
            case 'sessionStorage': return 60;
            case 'cookie': return 50;
            case 'referrer': return 40;
            case 'window.name': return 30;
            default: return 10;
        }
    };

    const matchTypePriority = (matchType) => {
        switch (matchType) {
            case 'url-eq': return 3;
            case 'exact': return 2;
            case 'token': return 1;
            case 'substring': return 0;
            default: return 0;
        }
    };

    const looksLikeUrl = (s) => /^[a-z][\w+.-]+:\/\//i.test(s);

    for (const [sourceKey, rawVal] of taints) {
        if (!rawVal) continue;
        if (!isMeaningfulSourceValue(rawVal)) continue;
        let tv = String(rawVal).trim().toLowerCase().replace(/^#/, '').replace(/;$/, '');
        if (!tv) continue;

        let rawToMatch = rawStr;
        let tvToMatch = tv;
        let matchType = null;

        if (looksLikeUrl(tv) && looksLikeUrl(rawStr)) {
            try {
                rawToMatch = new URL(rawStr, location.href).href.toLowerCase();
                tvToMatch = new URL(tv, location.href).href.toLowerCase();
                if (rawToMatch === tvToMatch) matchType = 'url-eq';
            } catch (e) {
                rawToMatch = rawStr;
                tvToMatch = tv;
            }
        }

        if (!matchType) {
            if (/^[a-z0-9]+$/i.test(tv)) {
                const esc = tv.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
                const re = new RegExp(`\\b${esc}\\b`, 'i');
                if (re.test(rawToMatch)) matchType = 'exact';
            } else if (isSourceMatchingValue(tvToMatch, rawToMatch)) {
                matchType = 'substring';
            }
        }

        if (!matchType) continue;

        const kind = kindOf(sourceKey);
        const sourceMeta = meta[sourceKey] || {};
        const baseScore = kindPriority(kind) * 100 + matchTypePriority(matchType);
        const lastUpdated = typeof meta[sourceKey]?.lastUpdated === 'number' ? meta[sourceKey].lastUpdated : 0;
        const recencyBoost = lastUpdated ? Math.min(Math.floor(lastUpdated / 1000), 1_000_000) : 0;
        const score = baseScore * 1_000_000 + recencyBoost;

        matches.push({
            source: sourceKey,
            raw: rawVal,
            kind,
            matchType,
            score,
            lastUpdated,
            taintKind: sourceMeta.taintKind || null
        });
    }

    if (!matches.length) return null;
    matches.sort((a, b) => b.score - a.score);
    const primary = matches[0];
    __IAST_MATCH_COUNT__++
    //if (__IAST_MATCH_COUNT__ <= 20) __PTK_IAST_DBG__('taint match', { primary, total: matches.length, raw: input });
    return {
        source: primary.source,
        raw: primary.raw,
        allSources: matches
    };
}

(function flushBufferedFindings() {
    const key = 'ptk_iast_buffer';
    const data = localStorage.getItem(key);
    if (!data) return;
    let arr;
    try { arr = JSON.parse(data); } catch { arr = null; }
    if (Array.isArray(arr)) {
        arr.forEach(msg => {
            try { window.postMessage(msg, '*'); }
            catch (e) {/*ignore*/ }
        });
    }
    localStorage.removeItem(key);
})();


function reportFinding({ type, sink, sinkId = null, ruleId = null, category = null, severity: severityOverride = null, matched, source, sources = null, context = {} }) {
    // Require rule catalog
    if (!IAST_MODULES) {
        //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: skip finding, modules not loaded yet', { sinkId, ruleId });
        requestModulesFromBackground();
        return;
    }
    let ruleEntry = null;
    if (ruleId) {
        ruleEntry = getIastRuleByRuleId(ruleId);
    }
    if (!ruleEntry && sinkId) {
        ruleEntry = getIastRuleBySinkId(sinkId);
    }
    if (!ruleEntry) {
        //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: skip finding, rule not found', { sinkId, ruleId });
        requestModulesFromBackground();
        return;
    }

    const loc = window.location.href;
    let trace = '';
    try {
        trace = (new Error(`Sink: ${type}`)).stack;
    } catch (e) { }
    const attackId = window.__PTK_CURRENT_ATTACK_ID__ || null;
    const moduleMeta = ruleEntry.moduleMeta || {};
    const ruleMeta = ruleEntry.ruleMeta || {};
    const resolvedSeverity = resolveIastEffectiveSeverity({
        override: severityOverride,
        moduleMeta,
        ruleMeta
    });
    const resolvedCategory = category || ruleMeta.category || moduleMeta.category || null;
    const description = ruleMeta.description || moduleMeta.description || null;
    const recommendation = ruleMeta.recommendation || moduleMeta.recommendation || null;
    const mergedLinks = mergeLinks(moduleMeta.links, ruleMeta.links);
    const findingMeta = {
        ruleId: ruleEntry.ruleId,
        ruleName: ruleEntry.ruleName,
        moduleId: ruleEntry.moduleId,
        moduleName: ruleEntry.moduleName,
        cwe: ruleMeta.cwe || moduleMeta.cwe || null,
        owasp: ruleMeta.owasp || moduleMeta.owasp || null,
        message: ruleMeta.message || null,
        tags: ruleMeta.tags || [],
        description,
        recommendation,
        links: mergedLinks
    };
    let normalizedSources = Array.isArray(sources) && sources.length ? normalizeTaintedSources(sources, matched) : [];
    const normalizedPrimarySource = (() => {
        if (!source) return null;
        if (typeof source === 'string') {
            return normalizeSourceEntry({ source, raw: matched });
        }
        if (source.__normalizedSource) return source;
        return normalizeSourceEntry(source, source?.source || source?.key || null, source?.raw ?? matched);
    })();
    if (!normalizedSources.length && normalizedPrimarySource) {
        normalizedSources = [normalizedPrimarySource];
    }
    const decoratedSources = normalizedSources.map(entry => Object.assign({}, entry, {
        display: formatSourceForReport(entry)
    }));
    const formattedSource = normalizedPrimarySource ? formatSourceForReport(normalizedPrimarySource) : 'Unknown source';
    const sourceKey = normalizedPrimarySource?.key || (typeof source === 'string' ? source : null);

    const details = {
        type: type,
        sink,
        sinkId: sinkId || sink || null,
        ruleId: ruleEntry.ruleId,
        ruleName: findingMeta.ruleName,
        moduleId: findingMeta.moduleId,
        moduleName: findingMeta.moduleName,
        matched,
        source: formattedSource,
        sourceKey,
        sources: decoratedSources,
        category: resolvedCategory,
        severity: resolvedSeverity,
        meta: findingMeta,
        context: enrichContext(context),
        location: loc,
        trace: trace,
        attackId: attackId,
        timestamp: Date.now(),
        description,
        recommendation,
        links: mergedLinks
    };
    // __PTK_IAST_DBG__('reportFinding', {
    //     sink: sinkId || sink || null,
    //     type,
    //     severity: resolvedSeverity,
    //     category: resolvedCategory,
    //     source: formattedSource,
    //     matched: matched ? String(matched).slice(0, 120) : '',
    //     location: loc
    // });

    // 1) Console output
    // console.groupCollapsed(`%cIAST%c ${type}`,
    //     'color:#d9534f;font-weight:bold', '');
    // console.log('• location:', loc);
    // console.log('• sink:    ', sink);
    // console.log('• source:  ', source);
    // console.log('• matched: ', matched);
    // // log any extra context fields
    // Object.entries(context).forEach(([k, v]) =>
    //     console.log(`• ${k}:       `, v)
    // );
    // console.groupEnd();


    // 2) PostMessage to background (sanitize non-cloneable payloads)
    const sanitized = {};
    Object.entries(details).forEach(([k, v]) => {
        if (v == null) {
            sanitized[k] = v;
        } else if (v instanceof Error) {
            sanitized[k] = v.toString();
        } else if (v instanceof Node) {
            sanitized[k] = v.outerHTML || v.textContent || String(v);
        } else if (typeof v === 'object') {
            try {
                sanitized[k] = structuredClone(v);
            } catch (e) {
                try {
                    sanitized[k] = JSON.parse(JSON.stringify(v));
                } catch (_) {
                    sanitized[k] = String(v);
                }
            }
        } else {
            sanitized[k] = v;
        }
    });
    try {
        withoutHooks(() => {
            const msg = {
                ptk_iast: 'finding_report',
                channel: 'ptk_content_iast2background_iast',
                finding: sanitized
            }
            const key = 'ptk_iast_buffer';
            let buf;
            try {
                buf = JSON.parse(localStorage.getItem(key) || '[]');
            } catch (_) {
                buf = [];
            }
            buf.push(msg);
            localStorage.setItem(key, JSON.stringify(buf));

            window.postMessage(msg, '*');
        })
    } catch (e) {
        console.log('IAST reportFinding.postMessage failed:', e);
    }
}

function safeSerializeValue(value) {
    if (value == null) return '';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    try {
        return JSON.stringify(value);
    } catch (_) {
        try {
            return String(value);
        } catch {
            return '';
        }
    }
}

function maybeReportTaintedValue(value, info = {}, contextExtras = {}, matchOverride = null) {
    if (__IAST_DISABLE_HOOKS__) return false;
    const context = Object.assign({ value }, contextExtras);
    const match = matchOverride || matchesTaint(value);
    const taintedSources = match ? normalizeTaintedSources(match.allSources, match.raw) : [];
    context.taintedSources = taintedSources;
    if (shouldSkipSinkByHeuristics(value, info, context, taintedSources)) return false;
    if (!match) return false;
    if (typeof context.element === 'undefined') {
        context.element = document?.activeElement || null;
    }
    const sinkMeta = {
        sinkId: info.sinkId || info.sink || null,
        sink: info.sink || info.sinkId || null,
        ruleId: info.ruleId || null,
        domPath: context.domPath || (context.element ? getDomPath(context.element) : null),
        elementId: context.elementId || (context.element && context.element.id ? context.element.id : null),
        attribute: context.attribute || null,
        location: window.location.href,
        value
    };
    const flow = buildTaintFlow(match, sinkMeta);
    if (flow.length) {
        context.flow = flow;
    }
    const primarySource = taintedSources.length
        ? taintedSources[0]
        : (match.source ? normalizeSourceEntry({ source: match.source, raw: match.raw }) : null);
    reportFinding({
        type: info.type || info.ruleId || info.sinkId || 'iast_sink',
        sink: info.sink || info.sinkId || 'iast_sink',
        sinkId: info.sinkId || info.sink || null,
        ruleId: info.ruleId || null,
        matched: match.raw,
        source: primarySource || match.source,
        sources: taintedSources,
        context
    });
    return true;
}


// Inline-event scanner helper
function scanInlineEvents(htmlFragment) {
    let m;
    try {
        const doc = new DOMParser().parseFromString(htmlFragment, 'text/html');
        doc.querySelectorAll('*').forEach(el => {
            Array.from(el.attributes).forEach(attr => {
                const name = attr.name.toLowerCase();
                if (!name.startsWith('on')) return;
                const val = attr.value;
                m = matchesTaint(val);
                if (!m) return;

                maybeReportTaintedValue(val, {
                    type: 'dom-inline-event-handler',
                    sink: name,
                    sinkId: 'dom.inline_event',
                    ruleId: 'dom_inline_event_handler'
                }, {
                    element: el,
                    tag: el.tagName,
                    attribute: name,
                    eventType: name,
                    value: val
                }, m);
            });
        });
    } catch (e) {
        console.log('[IAST] inline-event scan error', e);
    }
}


// Eval & Function hooks
; (function () {
    const originalEval = window.eval;
    window.eval = function (code) {
        const m = matchesTaint(code);
        if (m) {
            maybeReportTaintedValue(code, {
                type: 'xss-via-eval',
                sink: 'eval',
                sinkId: 'code.eval',
                ruleId: 'eval_js_execution'
            }, {
                element: document?.activeElement || null,
                code: code
            }, m);
        }
        return originalEval.call(this, code);
    };
})();

; (function () {
    const OriginalFunction = window.Function;
    window.Function = new Proxy(OriginalFunction, {
        construct(target, args, newTarget) {
            const body = args.slice(-1)[0] + '';
            const m = matchesTaint(body);
            if (m) {
                maybeReportTaintedValue(body, {
                    type: 'xss-via-Function',
                    sink: 'Function.constructor',
                    sinkId: 'code.function.constructor',
                    ruleId: 'function_constructor_execution'
                }, {
                    element: document?.activeElement || null,
                    code: body
                }, m);
            }
            return Reflect.construct(target, args, newTarget);
        },
        apply(target, thisArg, args) {
            const body = args.slice(-1)[0] + '';
            const m = matchesTaint(body);
            if (m) {
                maybeReportTaintedValue(body, {
                    type: 'xss-via-Function',
                    sink: 'Function.apply',
                    sinkId: 'code.function.apply',
                    ruleId: 'function_apply_execution'
                }, { element: document?.activeElement || null, code: body }, m);
            }
            return Reflect.apply(target, thisArg, args);
        }
    });
})();


// document.write
; (function () {
    const origWrite = document.write;

    document.write = function (...args) {
        const html = args.join('');
        let fragment;
        try {
            // Parse the HTML into a DocumentFragment
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            fragment = doc.body;
            // Traverse and report any taint in attributes or text nodes
            traverseAndReport(fragment, 'document.write');
        } catch (e) {
            // Fallback to the old behavior if parsing fails
            const m = matchesTaint(html);
            if (m) {
                maybeReportTaintedValue(html, {
                    type: 'xss-via-document.write',
                    sink: 'document.write',
                    sinkId: 'document.write',
                    ruleId: 'document_write_xss'
                }, { value: html, element: document?.activeElement || null }, m);
                scanInlineEvents(html);
            }
        }
        return origWrite.apply(document, args);
    };

    // Helper: walk a DOM subtree and report the first taint per node
    function traverseAndReport(root, sink) {
        const seen = new Set();  // avoid duplicates
        postOrderTraverse(root, node => {
            if (node.nodeType === Node.TEXT_NODE) {
                const txt = node.textContent;
                const m = matchesTaint(txt);
                if (m && !seen.has(node)) {
                    maybeReportTaintedValue(txt, {
                        type: 'xss-via-document.write',
                        sink: 'document.write',
                        sinkId: 'document.write',
                        ruleId: 'document_write_xss'
                    }, { value: html, element: document?.activeElement || null }, m);
                    seen.add(node);
                }
            } else if (node.nodeType === Node.ELEMENT_NODE) {
                // check each attribute
                for (const { name, value } of Array.from(node.attributes)) {
                    const m = matchesTaint(value);
                    if (m && !seen.has(node)) {
                        maybeReportTaintedValue(value, {
                            type: 'xss-via-document.write',
                            sink: 'document.write',
                            sinkId: 'document.write',
                            ruleId: 'document_write_xss'
                        }, { value: html, element: document?.activeElement || null }, m);
                        seen.add(node);
                        break;
                    }
                }
                // inline‐event handlers
                scanInlineEvents(node.outerHTML);
            }
        });
    }

    // reuse your existing postOrderTraverse
    function postOrderTraverse(node, fn) {
        node.childNodes.forEach(c => postOrderTraverse(c, fn));
        fn(node);
    }
})();

// innerHTML/outerHTML
['innerHTML', 'outerHTML'].forEach(prop => {
    const desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
    Object.defineProperty(Element.prototype, prop, {
        get: desc.get,
        set(htmlString) {
            try {
                const frag = document.createRange().createContextualFragment(htmlString);
                traverseAndReport(frag, `xss-via-${prop}`);
            } catch {
                const m = matchesTaint(htmlString);
                if (m) {
                    maybeReportTaintedValue(htmlString, {
                        type: `xss-via-${prop}`,
                        sink: prop,
                        sinkId: prop === 'innerHTML' ? 'dom.innerHTML' : 'dom.outerHTML',
                        ruleId: prop === 'innerHTML' ? 'dom_innerhtml_xss' : 'dom_outerhtml_xss'
                    }, { value: htmlString, element: this, domPath: getDomPath(this) }, m);
                    scanInlineEvents(htmlString);
                }
            }
            return desc.set.call(this, htmlString);
        },
        configurable: true,
        enumerable: desc.enumerable
    });
});


// insertAdjacentHTML
; (function () {
    const origInsert = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (pos, htmlString) {
        try {
            // parse HTML to a fragment for precise matching
            const frag = document.createRange().createContextualFragment(htmlString);
            traverseAndReport(frag, `insertAdjacentHTML(${pos})`);
        } catch {
            // fallback to simple match
            const m = matchesTaint(htmlString);
            if (m) {
                maybeReportTaintedValue(htmlString, {
                    type: 'xss-via-insertAdjacentHTML',
                    sink: 'insertAdjacentHTML',
                    sinkId: 'dom.insertAdjacentHTML',
                    ruleId: 'dom_insertadjacenthtml_xss'
                }, { value: htmlString, element: this, position: pos }, m);
                scanInlineEvents(htmlString);
            }
        }
        return origInsert.call(this, pos, htmlString);
    };
})();

// createContextualFragment & appendChild/insertBefore
; (function () {
    // 1) Walk a subtree in post-order, checking text nodes and element attributes
    function traverseAndReport(root, trigger) {
        const seen = new Set();
        function scanNode(n) {
            if (seen.has(n)) return;

            // TEXT NODE: look for taint in its textContent
            if (n.nodeType === Node.TEXT_NODE) {
                const txt = n.textContent || '';
                const m = matchesTaint(txt);
                if (m) {
                    seen.add(n);
                    maybeReportTaintedValue(txt, {
                        type: 'xss-via-mutation',
                        sink: trigger,
                        sinkId: 'dom.mutation',
                        ruleId: 'dom_mutation_xss'
                    }, {
                        element: document?.activeElement || null,
                        value: txt,
                        nodeType: 'TEXT_NODE',
                        snippet: txt.trim().slice(0, 200)
                    }, m);
                }
                return;
            }

            // ELEMENT NODE: check each attribute for taint
            if (n.nodeType === Node.ELEMENT_NODE) {
                for (const attr of n.attributes) {
                    const m = matchesTaint(attr.value);
                    if (m) {
                        seen.add(n);
                        maybeReportTaintedValue(attr.value, {
                            type: 'xss-via-mutation',
                            sink: trigger,
                            sinkId: 'dom.mutation',
                            ruleId: 'dom_mutation_xss'
                        }, {
                            element: n,
                            nodeType: 'ELEMENT_NODE',
                            tag: n.tagName,
                            attribute: attr.name,
                            value: attr.value,
                            domPath: getDomPath(n)
                        }, m);
                        return;  // one finding per element
                    }
                }
            }
        }

        // post-order traverse everything under root (including root itself if text or element)
        (function walk(n) {
            n.childNodes.forEach(walk);
            scanNode(n);
        })(root);
    }

    // 2) List of prototypes & methods to hook
    const hooks = [
        [Node.prototype, ['appendChild', 'insertBefore', 'replaceChild']],
        [Element.prototype, ['append', 'prepend', 'before', 'after', 'replaceWith']],
        [Document.prototype, ['adoptNode']]
    ];

    for (const [proto, methods] of hooks) {
        for (const name of methods) {
            const orig = proto[name];
            if (typeof orig !== 'function') continue;

            Object.defineProperty(proto, name, {
                configurable: true,
                writable: true,
                value: function (...args) {
                    //console.debug(`[IAST] mutation hook: ${name}`, this, args);

                    // figure out which Nodes are being inserted/adopted
                    const nodes = [];
                    switch (name) {
                        case 'insertBefore':
                        case 'replaceChild':
                            nodes.push(args[0]);
                            break;
                        case 'appendChild':
                        case 'adoptNode':
                            nodes.push(args[0]);
                            break;
                        default:
                            // append/prepend/before/after/replaceWith take Node or strings
                            args.forEach(a => {
                                if (typeof a === 'string') {
                                    // strings become TextNodes at runtime; scan them too
                                    const txtNode = document.createTextNode(a);
                                    nodes.push(txtNode);
                                } else if (a instanceof Node) {
                                    nodes.push(a);
                                }
                            });
                    }

                    // run our taint scan on each
                    for (const n of nodes) {
                        traverseAndReport(n, name);
                    }

                    // and finally perform the real mutation
                    return orig.apply(this, args);
                }
            });
        }
    }
})();

// DOM URL navigation sinks
; (function () {
    const NAV_SUPPRESS = { meta: null, time: 0 };
    const NAV_REPLAY_STATE = { active: false };
    function markLocationNavTrigger(meta) {
        NAV_SUPPRESS.meta = meta || null;
        NAV_SUPPRESS.time = Date.now();
    }
    function consumeLocationNavTrigger() {
        if (!NAV_SUPPRESS.meta) return null;
        if (Date.now() - NAV_SUPPRESS.time > 1500) {
            NAV_SUPPRESS.meta = null;
            return null;
        }
        const meta = NAV_SUPPRESS.meta;
        NAV_SUPPRESS.meta = null;
        return meta;
    }
    window.__IAST_CONSUME_NAV_TRIGGER__ = consumeLocationNavTrigger;
    function scheduleNavigationReplay(fn) {
        if (typeof fn !== 'function') return;
        setTimeout(() => {
            NAV_REPLAY_STATE.active = true;
            try {
                fn();
            } catch (e) {
                __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: navigation replay failed', e);
            } finally {
                NAV_REPLAY_STATE.active = false;
            }
        }, 0);
    }

    const LocationProto = typeof Location !== 'undefined' ? Location.prototype : null;

    function wrapLocationSetter(prop, ruleId, sinkId, label) {
        const targets = [];
        if (LocationProto) targets.push(LocationProto);
        try {
            if (window.location) targets.push(window.location);
        } catch (_) { }
        targets.forEach(target => {
            try {
                const desc = Object.getOwnPropertyDescriptor(target, prop);
                if (!desc || typeof desc.set !== 'function' || desc.configurable === false) return;
                Object.defineProperty(target, prop, {
                    configurable: true,
                    enumerable: desc.enumerable,
                    get: desc.get ? function () { return desc.get.call(this); } : undefined,
                    set(value) {
                        const ctx = this;
                        const runNative = () => desc.set.call(ctx, value);
                        if (NAV_REPLAY_STATE.active) {
                            return runNative();
                        }
                        if (!shouldReportNavigationSink(value)) {
                            return runNative();
                        }
                        const elMeta = captureElementMeta(document?.activeElement || null);
                        const reported = maybeReportTaintedValue(value, {
                            type: 'dom-url-navigation',
                            sink: label,
                            sinkId,
                            ruleId
                        }, Object.assign({ property: prop, value }, elMeta));
                        if (reported) markLocationNavTrigger({ sinkId, ruleId, sinkLabel: label });
                        if (reported) {
                            scheduleNavigationReplay(runNative);
                            return;
                        }
                        return runNative();
                    }
                });
            } catch (e) {
                __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: unable to wrap location property', prop);
            }
        });
    }

    function wrapLocationMethod(method, ruleId, sinkId, label) {
        const targets = [];
        try {
            if (window.location && typeof window.location[method] === 'function') {
                targets.push({ target: window.location, useBound: true });
            }
        } catch (_) { }
        if (LocationProto && typeof LocationProto[method] === 'function') {
            targets.push({ target: LocationProto, useBound: false });
        }
        let wrapped = false;
        targets.forEach(({ target, useBound }) => {
            try {
                const orig = target[method];
                if (typeof orig !== 'function') return;
                if (useBound) {
                    const bound = orig.bind(window.location);
                    target[method] = function (...args) {
                        const callArgs = args.slice(0);
                        const invokeNative = () => bound(...callArgs);
                        if (NAV_REPLAY_STATE.active) {
                            return invokeNative();
                        }
                        const url = args[0];
                        if (typeof url === 'string' && shouldReportNavigationSink(url)) {
                            const elMeta = captureElementMeta(document?.activeElement || null);
                            const reported = maybeReportTaintedValue(url, {
                                type: 'dom-url-navigation',
                                sink: label,
                                sinkId,
                                ruleId
                            }, Object.assign({ method: label, value: url }, elMeta));
                            if (reported) {
                                markLocationNavTrigger({ sinkId, ruleId, sinkLabel: label });
                                scheduleNavigationReplay(invokeNative);
                                return;
                            }
                        }
                        return invokeNative();
                    };
                } else {
                    target[method] = function (...args) {
                        const ctx = this;
                        const callArgs = args.slice(0);
                        const invokeNative = () => orig.apply(ctx, callArgs);
                        if (NAV_REPLAY_STATE.active) {
                            return invokeNative();
                        }
                        const url = args[0];
                        if (typeof url === 'string' && shouldReportNavigationSink(url)) {
                            const elMeta = captureElementMeta(document?.activeElement || null);
                            const reported = maybeReportTaintedValue(url, {
                                type: 'dom-url-navigation',
                                sink: label,
                                sinkId,
                                ruleId
                            }, Object.assign({ method: label, value: url }, elMeta));
                            if (reported) {
                                markLocationNavTrigger({ sinkId, ruleId, sinkLabel: label });
                                scheduleNavigationReplay(invokeNative);
                                return;
                            }
                        }
                        return invokeNative();
                    };
                }
                wrapped = true;
            } catch (e) {
                __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: failed to wrap location method', method, e);
            }
        });
        if (!wrapped) {
            __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: unable to patch location method', method);
        }
    }

    wrapLocationSetter('href', 'location_href_redirect', 'nav.location.href', 'location.href');
    wrapLocationMethod('assign', 'location_assign_redirect', 'nav.location.assign', 'location.assign');
    wrapLocationMethod('replace', 'location_replace_redirect', 'nav.location.replace', 'location.replace');

    const HistoryProto = typeof History !== 'undefined' ? History.prototype : null;
    if (HistoryProto && typeof HistoryProto.pushState === 'function') {
        const origPushState = HistoryProto.pushState;
        HistoryProto.pushState = function (state, title, url) {
            if (typeof url === 'string' && url && shouldReportNavigationSink(url)) {
                maybeReportTaintedValue(url, {
                    type: 'dom-url-navigation',
                    sink: 'history.pushState',
                    sinkId: 'nav.history.pushState',
                    ruleId: 'history_pushstate_open_redirect'
                }, { value: url, method: 'history.pushState' });
            }
            return origPushState.apply(this, arguments);
        };
    }
})();

// Open-Redirect Detection

; (function () {
    function isExternalRedirect(url) {
        try {
            // resolve relative URLs against current location
            const resolved = new URL(url, window.location.href);
            // only consider http(s) URLs…
            if (!/^https?:$/i.test(resolved.protocol)) return false;
            // …and only if the origin really differs
            return resolved.origin !== window.location.origin;
        } catch (e) {
            // not a valid URL at all
            return false;
        }
    }

    function recordRedirect(url, method) {
        // 1) skip anything that isn’t an external http(s) redirect
        if (!isExternalRedirect(url)) return;

        let resolvedSinkId = method === 'navigation.navigate' ? 'nav.navigation.navigate' : 'nav.window.open';
        let resolvedRuleId = method === 'navigation.navigate' ? 'navigation_api_redirect' : 'window_open_redirect';
        let resolvedSinkLabel = method === 'navigation.navigate' ? 'navigation.navigate' : method;
        if (method === 'navigation.navigate') {
            if (typeof window.__IAST_CONSUME_NAV_TRIGGER__ === 'function') {
                const recent = window.__IAST_CONSUME_NAV_TRIGGER__();
                if (recent && recent.sinkId) {
                    resolvedSinkId = recent.sinkId;
                    resolvedRuleId = recent.ruleId || resolvedRuleId;
                    resolvedSinkLabel = recent.sinkLabel || resolvedSinkLabel;
                } else {
                    resolvedSinkId = 'nav.location.href';
                    resolvedRuleId = 'location_href_redirect';
                    resolvedSinkLabel = 'location.href';
                }
            } else {
                resolvedSinkId = 'nav.location.href';
                resolvedRuleId = 'location_href_redirect';
                resolvedSinkLabel = 'location.href';
            }
        }

        const m = matchesTaint(url);
        const binding = buildRuleBinding({
            sinkId: resolvedSinkId,
            ruleId: resolvedRuleId,
            fallbackType: 'open-redirect'
        });
        if (m) {
            const meta = captureElementMeta(document?.activeElement || null);
            maybeReportTaintedValue(url, binding, Object.assign({ value: url }, meta), m);
        }
    }

    //Wrap window.open()
    const origOpen = window.open;
    window.open = function (url, ...rest) {
        if (typeof url === 'string') {
            recordRedirect(url, 'window.open');
        }
        return origOpen.call(this, url, ...rest);
    };

    if ('navigation' in window && typeof navigation.addEventListener === 'function') {
        navigation.addEventListener('navigate', event => {
            // event.destination.url is the URL we’re about to go to
            const url = event.destination.url;
            // reuse your open-redirect checker
            recordRedirect(url, 'navigation.navigate');
        });
    }

})();

// HTTP exfiltration sinks
; (function () {
    function coerceRequestUrl(input) {
        if (!input) return '';
        if (typeof input === 'string') return input;
        if (typeof URL !== 'undefined' && input instanceof URL) return input.href;
        if (typeof Request !== 'undefined' && input instanceof Request) return input.url;
        try {
            return String(input);
        } catch {
            return '';
        }
    }

    function coerceBodyString(body) {
        if (body == null) return '';
        if (typeof body === 'string') return body;
        if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
            return body.toString();
        }
        if (typeof FormData !== 'undefined' && body instanceof FormData) {
            const parts = [];
            body.forEach((val, key) => parts.push(`${key}=${val}`));
            return parts.join('&');
        }
        if (typeof Blob !== 'undefined' && body instanceof Blob) {
            // synchronous access not possible; fall back to placeholder
            return '[blob]';
        }
        return safeSerializeValue(body);
    }

    function scanHeaders(headers, cb) {
        if (!headers) return;
        if (typeof Headers !== 'undefined' && headers instanceof Headers) {
            headers.forEach((value, name) => cb(name, value));
            return;
        }
        if (Array.isArray(headers)) {
            headers.forEach(entry => {
                if (!entry) return;
                const [name, value] = entry;
                cb(name, value);
            });
            return;
        }
        if (typeof headers === 'object') {
            Object.entries(headers).forEach(([name, value]) => {
                if (Array.isArray(value)) {
                    value.forEach(v => cb(name, v));
                } else {
                    cb(name, value);
                }
            });
        }
    }

    const SAFE_HTTP_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

    function resolveAbsoluteUrl(url) {
        if (!url) return null;
        try {
            return new URL(url, window.location.href);
        } catch (_) {
            return null;
        }
    }

    function isCrossOriginUrl(url) {
        const resolved = resolveAbsoluteUrl(url);
        if (!resolved) return false;
        return resolved.origin !== window.location.origin;
    }

    function requestIsInstance(resource) {
        return typeof Request !== 'undefined' && resource instanceof Request;
    }

    function resolveRequestMethod(resource, init) {
        if (init && init.method) return String(init.method).toUpperCase();
        if (requestIsInstance(resource) && resource.method) {
            return String(resource.method).toUpperCase();
        }
        return 'GET';
    }

    function resolveRequestCredentials(resource, init) {
        if (init && init.credentials) return String(init.credentials);
        if (requestIsInstance(resource) && resource.credentials) {
            return String(resource.credentials);
        }
        return 'same-origin';
    }

    function headersIndicateProtection(headerSet) {
        let protectedSignal = false;
        scanHeaders(headerSet, (name) => {
            if (protectedSignal || !name) return;
            const lower = String(name).toLowerCase();
            if (!lower) return;
            if (lower.includes('csrf') || lower.includes('xsrf') || lower.includes('token') || lower === 'x-requested-with'
                || lower === 'authorization' || lower === 'proxy-authorization' || lower.includes('api-key')) {
                protectedSignal = true;
            }
        });
        return protectedSignal;
    }

    function summarizeHeaders(headerSets, cap = 6) {
        const summary = [];
        headerSets.forEach(set => {
            scanHeaders(set, (name, value) => {
                if (summary.length >= cap) return;
                const serialized = safeSerializeValue(value || '');
                summary.push({
                    name,
                    value: serialized.length > 200 ? serialized.slice(0, 200) : serialized
                });
            });
        });
        return summary;
    }

    function documentHasAntiCsrfCookie() {
        if (typeof document === 'undefined' || !document.cookie) return false;
        try {
            return document.cookie.split(';').some(part => {
                const key = part.split('=')[0]?.trim().toLowerCase();
                if (!key) return false;
                return key.includes('csrf') || key.includes('xsrf');
            });
        } catch (_) {
            return false;
        }
    }

    if (typeof window.fetch === 'function') {
        const origFetch = window.fetch;
        window.fetch = function (...args) {
            try {
                const resource = args[0];
                const init = args[1];
                const url = coerceRequestUrl(resource);
                const suspiciousUrl = url && isSuspiciousExfilUrl(url);
                if (url && suspiciousUrl) {
                    maybeReportTaintedValue(url, {
                        type: 'http-exfiltration',
                        sink: 'fetch(url)',
                        sinkId: 'http.fetch.url',
                        ruleId: 'fetch_url_exfiltration'
                    }, { value: url, method: 'fetch' });
                }
                const headerCandidates = [];
                if (requestIsInstance(resource)) {
                    headerCandidates.push(resource.headers);
                }
                if (init && init.headers) {
                    headerCandidates.push(init.headers);
                }
                let hasProtectiveHeader = false;
                if (suspiciousUrl) {
                    headerCandidates.forEach(candidate => {
                        if (!hasProtectiveHeader && headersIndicateProtection(candidate)) {
                            hasProtectiveHeader = true;
                        }
                        scanHeaders(candidate, (name, value) => {
                            maybeReportTaintedValue(value, {
                                type: 'http-exfiltration',
                                sink: 'fetch headers',
                                sinkId: 'http.fetch.headers',
                                ruleId: 'fetch_headers_exfiltration'
                            }, { headerName: name, value });
                        });
                    });
                }

                const method = resolveRequestMethod(resource, init);
                const credentialsMode = resolveRequestCredentials(resource, init);
                const sendsCredentials = String(credentialsMode || '').toLowerCase() === 'include';
                const hasCsrfCookie = documentHasAntiCsrfCookie();
                if (url && isCrossOriginUrl(url) && sendsCredentials && !SAFE_HTTP_METHODS.has(method)
                    && !hasProtectiveHeader && !hasCsrfCookie) {
                    reportFinding({
                        type: 'csrf-cross-site-fetch',
                        sink: 'fetch',
                        sinkId: 'csrf.fetch',
                        ruleId: 'fetch_cross_site_no_csrf',
                        matched: null,
                        source: null,
                        sources: [],
                        context: {
                            method,
                            url,
                            credentials: credentialsMode,
                            headers: summarizeHeaders(headerCandidates),
                            value: url
                        }
                    });
                }
            } catch (err) {
                __PTK_IAST_DBG__('fetch wrapper error', err);
            }
            return origFetch.apply(this, args);
        };
    }

    if (typeof XMLHttpRequest !== 'undefined') {
        const origOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function (method, url, ...rest) {
            this.__ptk_iast_method = method;
            this.__ptk_iast_url = url;
            const suspicious = isSuspiciousExfilUrl(url);
            this.__ptk_iast_exfil_suspicious = suspicious;
            if (suspicious) {
                maybeReportTaintedValue(url, {
                    type: 'http-exfiltration',
                    sink: 'XMLHttpRequest.open',
                    sinkId: 'http.xhr.open',
                    ruleId: 'xhr_url_exfiltration'
                }, { method, value: url });
            }
            return origOpen.call(this, method, url, ...rest);
        };

        const origSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function (body) {
            if (body !== undefined) {
                const serialized = coerceBodyString(body);
                if (serialized && this.__ptk_iast_exfil_suspicious) {
                    maybeReportTaintedValue(serialized, {
                        type: 'http-exfiltration',
                        sink: 'XMLHttpRequest.send',
                        sinkId: 'http.xhr.send',
                        ruleId: 'xhr_body_exfiltration'
                    }, {
                        method: this.__ptk_iast_method || null,
                        requestUrl: this.__ptk_iast_url || null,
                        value: serialized
                    });
                }
            }
            return origSend.call(this, body);
        };
    }

    if (typeof navigator !== 'undefined' && navigator && typeof navigator.sendBeacon === 'function') {
        const origSendBeacon = navigator.sendBeacon;
        navigator.sendBeacon = function (url, data) {
            if (isSuspiciousExfilUrl(url)) {
                maybeReportTaintedValue(data, {
                    type: 'http-exfiltration',
                    sink: 'navigator.sendBeacon',
                    sinkId: 'http.navigator.sendBeacon',
                    ruleId: 'sendbeacon_exfiltration'
                }, { value: coerceBodyString(data), url });
            }
            return origSendBeacon.call(this, url, data);
        };
    }

    if (typeof HTMLImageElement !== 'undefined') {
        const desc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
        if (desc && desc.set) {
            Object.defineProperty(HTMLImageElement.prototype, 'src', {
                configurable: true,
                enumerable: desc.enumerable,
                get: desc.get,
                set(value) {
                    if (isSuspiciousExfilUrl(value)) {
                        maybeReportTaintedValue(value, {
                            type: 'http-exfiltration',
                            sink: 'image.src',
                            sinkId: 'http.image.src',
                            ruleId: 'image_src_exfiltration'
                        }, { value, element: this });
                    }
                    return desc.set.call(this, value);
                }
            });
        }
    }

    if (typeof WebSocket !== 'undefined' && WebSocket.prototype && typeof WebSocket.prototype.send === 'function') {
        const origSocketSend = WebSocket.prototype.send;
        WebSocket.prototype.send = function (data) {
            const payload = safeSerializeValue(data);
            if (payload) {
                maybeReportTaintedValue(payload, {
                    type: 'realtime-exfiltration',
                    sink: 'WebSocket.send',
                    sinkId: 'realtime.websocket.send',
                    ruleId: 'websocket_send_exfiltration'
                }, {
                    value: payload,
                    url: this?.url || null,
                    protocol: this?.protocol || null
                });
            }
            return origSocketSend.apply(this, arguments);
        };
    }

    if (typeof RTCDataChannel !== 'undefined' && RTCDataChannel.prototype && typeof RTCDataChannel.prototype.send === 'function') {
        const origRtcSend = RTCDataChannel.prototype.send;
        RTCDataChannel.prototype.send = function (data) {
            const payload = safeSerializeValue(data);
            if (payload) {
                maybeReportTaintedValue(payload, {
                    type: 'realtime-exfiltration',
                    sink: 'RTCDataChannel.send',
                    sinkId: 'realtime.webrtc.send',
                    ruleId: 'webrtc_datachannel_send_exfiltration'
                }, {
                    value: payload,
                    label: this?.label || null
                });
            }
            return origRtcSend.apply(this, arguments);
        };
    }
})();

// Dynamic script loading sinks
; (function () {
    if (typeof HTMLScriptElement === 'undefined') return;
    const desc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    if (!desc || !desc.set) return;
    Object.defineProperty(HTMLScriptElement.prototype, 'src', {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set(value) {
            maybeReportTaintedValue(value, {
                type: 'dynamic-script-loading',
                sink: 'script.src',
                sinkId: 'script.element.src',
                ruleId: 'script_src_injection'
            }, { value, element: this });
            return desc.set.call(this, value);
        }
    });
})();

// Debug logging sinks
; (function () {
    if (typeof console === 'undefined') return;
    const sinks = [
        { method: 'log', ruleId: 'console_log_leak', sinkId: 'log.console.log' },
        { method: 'error', ruleId: 'console_error_leak', sinkId: 'log.console.error' }
    ];
    sinks.forEach(({ method, ruleId, sinkId }) => {
        const orig = console[method];
        if (typeof orig !== 'function') return;
        console[method] = function (...args) {
            args.forEach(arg => {
                const payload = safeSerializeValue(arg);
                if (!payload) return;
                maybeReportTaintedValue(payload, {
                    type: 'debug-logging',
                    sink: `console.${method}`,
                    sinkId,
                    ruleId
                }, { value: payload, method: `console.${method}` });
            });
            return orig.apply(this, args);
        };
    });
})();

// Clipboard exfiltration sink
; (function () {
    if (typeof navigator === 'undefined') return;
    const clip = navigator.clipboard;
    if (!clip || typeof clip.writeText !== 'function') return;
    const origWriteText = clip.writeText;
    clip.writeText = function (...args) {
        const payload = safeSerializeValue(args[0]);
        if (payload) {
            maybeReportTaintedValue(payload, {
                type: 'clipboard-exfiltration',
                sink: 'navigator.clipboard.writeText',
                sinkId: 'clipboard.writeText',
                ruleId: 'clipboard_write_text_leak'
            }, { value: payload });
        }
        return origWriteText.apply(this, args);
    };
})();

// BroadcastChannel & MessagePort sinks
; (function () {
    if (typeof BroadcastChannel !== 'undefined' && BroadcastChannel.prototype) {
        const orig = BroadcastChannel.prototype.postMessage;
        if (typeof orig === 'function') {
            BroadcastChannel.prototype.postMessage = function (message) {
                const payload = safeSerializeValue(message);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'web-messaging-channel',
                        sink: 'BroadcastChannel.postMessage',
                        sinkId: 'channel.broadcast.postMessage',
                        ruleId: 'broadcastchannel_postmessage_leak'
                    }, { value: payload, channelName: this?.name || null });
                }
                return orig.apply(this, arguments);
            };
        }
    }

    if (typeof MessagePort !== 'undefined' && MessagePort.prototype) {
        const origPortPost = MessagePort.prototype.postMessage;
        if (typeof origPortPost === 'function') {
            MessagePort.prototype.postMessage = function (message, transfer) {
                const payload = safeSerializeValue(message);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'web-messaging-channel',
                        sink: 'MessagePort.postMessage',
                        sinkId: 'channel.messageport.postMessage',
                        ruleId: 'messageport_postmessage_leak'
                    }, { value: payload });
                }
                return origPortPost.apply(this, arguments);
            };
        }
    }
})();

// Worker & ServiceWorker script loading sinks
; (function () {
    if (typeof navigator !== 'undefined' && navigator.serviceWorker && typeof navigator.serviceWorker.register === 'function') {
        const origRegister = navigator.serviceWorker.register;
        navigator.serviceWorker.register = function (...args) {
            const payload = safeSerializeValue(args[0]);
            if (payload) {
                maybeReportTaintedValue(payload, {
                    type: 'worker-script-loading',
                    sink: 'navigator.serviceWorker.register',
                    sinkId: 'worker.serviceWorker.register',
                    ruleId: 'serviceworker_register_injection'
                }, { value: payload });
            }
            return origRegister.apply(this, args);
        };
    }

    if (typeof window.Worker === 'function') {
        const OriginalWorker = window.Worker;
        window.Worker = new Proxy(OriginalWorker, {
            construct(target, args, newTarget) {
                const payload = safeSerializeValue(args[0]);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'worker-script-loading',
                        sink: 'Worker',
                        sinkId: 'worker.webworker.constructor',
                        ruleId: 'webworker_constructor_injection'
                    }, { value: payload });
                }
                return Reflect.construct(target, args, newTarget);
            }
        });
    }
})();

// window.postMessage misuse
; (function () {
    if (typeof window.postMessage !== 'function') return;
    const origPostMessage = window.postMessage;
    window.postMessage = function (message, targetOrigin, transfer) {
        const payload = safeSerializeValue(message);
        const originValue = targetOrigin == null ? '*' : targetOrigin;
        const defaultContext = { value: payload, targetOrigin: originValue };
        if (originValue === '*' || originValue === '') {
            maybeReportTaintedValue(payload, {
                type: 'postMessage-leak',
                sink: 'window.postMessage',
                sinkId: 'postmessage.anyOrigin',
                ruleId: 'postmessage_star_origin_leak'
            }, defaultContext);
        } else if (typeof originValue === 'string') {
            let destOrigin = null;
            try {
                destOrigin = new URL(originValue, window.location.href).origin;
            } catch (_) {
                destOrigin = null;
            }
            if (destOrigin && destOrigin !== window.location.origin) {
                maybeReportTaintedValue(payload, {
                    type: 'postMessage-leak',
                    sink: 'window.postMessage',
                    sinkId: 'postmessage.crossOrigin',
                    ruleId: 'postmessage_cross_origin_leak'
                }, Object.assign({}, defaultContext, { destination: destOrigin }));
            }
        }
        return origPostMessage.apply(this, arguments);
    };
})();

// IFrame navigation/content sinks
; (function () {
    if (typeof HTMLIFrameElement === 'undefined') return;
    const srcDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
    if (srcDesc && srcDesc.set) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
            configurable: true,
            enumerable: srcDesc.enumerable,
            get: srcDesc.get,
            set(value) {
                if (shouldReportNavigationSink(value)) {
                    maybeReportTaintedValue(value, {
                        type: 'iframe-navigation',
                        sink: 'iframe.src',
                        sinkId: 'nav.iframe.src',
                        ruleId: 'iframe_src_redirect'
                    }, { value, element: this });
                }
                return srcDesc.set.call(this, value);
            }
        });
    }
    const srcdocDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
    if (srcdocDesc && srcdocDesc.set) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
            configurable: true,
            enumerable: srcdocDesc.enumerable,
            get: srcdocDesc.get,
            set(value) {
                maybeReportTaintedValue(value, {
                    type: 'iframe-srcdoc',
                    sink: 'iframe.srcdoc',
                    sinkId: 'nav.iframe.srcdoc',
                    ruleId: 'iframe_srcdoc_xss'
                }, { value, element: this });
                return srcdocDesc.set.call(this, value);
            }
        });
    }
})();

// Timer-based execution sinks
; (function () {
    function wrapTimer(fnName, ruleId, sinkId) {
        if (typeof window[fnName] !== 'function') return;
        const orig = window[fnName];
        window[fnName] = function (handler, ...rest) {
            if (typeof handler === 'string' && handler) {
                maybeReportTaintedValue(handler, {
                    type: 'timer-execution',
                    sink: fnName,
                    sinkId,
                    ruleId
                }, { value: handler, method: fnName });
            }
            return orig.call(this, handler, ...rest);
        };
    }
    wrapTimer('setTimeout', 'settimeout_string_execution', 'code.setTimeout');
    wrapTimer('setInterval', 'setinterval_string_execution', 'code.setInterval');
})();
