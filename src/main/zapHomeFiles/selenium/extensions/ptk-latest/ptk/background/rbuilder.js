/* Author: Denis Podgurskii */
import { ptk_utils, ptk_storage, ptk_ruleManager, ptk_logger } from "./utils.js"
import { httpZ } from "./lib/httpZ.esm.js"
import { getSearchParamsFromUrlOrHash } from "./dast/urlUtils.js"

const worker = self

export class ptk_request_manager {

    constructor(settings) {
        this.storageKey = 'ptk_rbuilder'
        this.storage = []
        this.settings = settings
        this.init()
        this.addMessageListeners()
    }

    async init() {
        this.storage = await ptk_storage.getItem(this.storageKey)
    }

    async clear(index) {
        this.init()
        if (index) delete this.storage[index]
        else this.storage = []
        await ptk_storage.setItem(this.storageKey, this.storage)
    }

    findLastIndex(obj, requestId) {
        let l = obj.length
        while (l--) {
            if (obj[l].requestId == requestId) return l
        }
        return -1
    }

    /* Listeners */

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    onMessage(message, sender, sendResponse) {

        if (!ptk_utils.isTrustedOrigin(sender))
            return Promise.reject({ success: false, error: 'Error origin value' })

        if (message.channel == "ptk_popup2background_request") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }
    }

    resort(storage) {
        let i = 0
        Object.keys(storage).sort(function (a, b) { return storage[a].sort - storage[b].sort }).forEach(function (key) {
            storage[key].sort = i
            i++
        })
        return storage
    }

    async msg_init(message) {
        this.storage = await ptk_storage.getItem(this.storageKey)
        this.storage = this.storage ? this.resort(this.storage) : []
        return Promise.resolve(JSON.parse(JSON.stringify(this.storage)))
    }

    msg_clear(message) {
        this.clear(message.index)
        return Promise.resolve()
    }

    msg_reset_all(message) {
        this.clear()
        return Promise.resolve()
    }

    async msg_parse_request(message) {
        let rbObj = ptk_request.parseRawRequest(message.raw, message.opts)
        if (message.formId) {

            if (!this.storage[message.formId]) {
                this.storage[message.formId] = rbObj
                this.storage[message.formId].sort = Object.keys(this.storage).length
            } else {
                this.storage[message.formId].opts = message.opts
                this.storage[message.formId].request = rbObj.request
            }
            await ptk_storage.setItem(this.storageKey, this.storage)
        }
        return Promise.resolve(rbObj)
    }

    async msg_update_request(message) {
        let rbObj = ptk_request.updateRawRequest(message.schema, message.params, message.opts)
        if (message.formId) {
            if (!this.storage[message.formId]) {
                this.storage[message.formId] = rbObj
                this.storage[message.formId].sort = Object.keys(this.storage).length
            } else {
                this.storage[message.formId].opts = message.opts
                this.storage[message.formId].request = rbObj.request
            }
            await ptk_storage.setItem(this.storageKey, this.storage)
        }
        return Promise.resolve(rbObj)
    }

    async msg_delete_request(message) {
        if (this.storage[message.formId]) {
            delete this.storage[message.formId]
            await ptk_storage.setItem(this.storageKey, this.resort(this.storage))
        }
        return Promise.resolve(JSON.parse(JSON.stringify(this.storage)))
    }

    async msg_send_request(message) {
        let self = this
        let request = new ptk_request()
        if (message.useListeners) request.useListeners = true
        return request.sendRequest(message.schema).then(function (response) {
            if (message.formId) {
                if (!self.storage[message.formId]) {
                    self.storage[message.formId] = { sort: Object.keys(self.storage).length }
                }
                const sort = typeof self.storage[message.formId].sort === "number"
                    ? self.storage[message.formId].sort
                    : Object.keys(self.storage).length
                self.storage[message.formId] = response
                self.storage[message.formId].sort = sort
                delete self.storage[message.formId].scanResult
                ptk_storage.setItem(self.storageKey, self.storage)
            }
            return Promise.resolve(response)
        })
    }

    async msg_scan_request(message) {
        worker.ptk_app.rattacker.engine.onetimeScanRequest(message.schema.request.raw, true).then(scanResult => {
            let request_manager = worker.ptk_app.request_manager
            if (request_manager.storage[message.formId]) {
                request_manager.storage[message.formId]['scanResult'] = JSON.parse(JSON.stringify(scanResult))
                ptk_storage.setItem(request_manager.storageKey, request_manager.storage)
            }
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_rbuilder",
                type: "scan completed",
                scanResult: JSON.parse(JSON.stringify(scanResult))
            }).catch(e => ptk_logger.log(e, "Could not send a message", "info"))
        })
    }

    async msg_sync_storage(message) {
        if (message.storage) {
            this.storage = this.resort(message.storage)
            await ptk_storage.setItem(this.storageKey, this.storage)
        }
        return Promise.resolve(JSON.parse(JSON.stringify(this.storage)))
    }


    /* End Listeners */

}


export class ptk_request {

    constructor() {
        this.init()
    }

    async init() {
        this.useListeners = false
        this.trackingRequest = null
    }

    /* Listeners */

    addListeners() {
        let blocking = []
        if (worker.isFirefox)
            blocking.push("blocking")


        this.onBeforeRequest = this.onBeforeRequest.bind(this)
        browser.webRequest.onBeforeRequest.addListener(
            this.onBeforeRequest,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["requestBody"].concat(ptk_utils.extraInfoSpec).concat(blocking)
        )

        this.onBeforeSendHeaders = this.onBeforeSendHeaders.bind(this)
        browser.webRequest.onBeforeSendHeaders.addListener(
            this.onBeforeSendHeaders,
            { urls: ["<all_urls>"], types: ptk_utils.filterType },
            ["requestHeaders"].concat(ptk_utils.extraInfoSpec).concat(blocking)
        )

        this.onHeadersReceived = this.onHeadersReceived.bind(this);
        browser.webRequest.onHeadersReceived.addListener(
            this.onHeadersReceived,
            { urls: ["<all_urls>"], types: ptk_utils.filterType },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec).concat(blocking)
        )

    }

    removeListeners() {
        browser.webRequest.onBeforeSendHeaders.removeListener(this.onBeforeSendHeaders)
        browser.webRequest.onBeforeRequest.removeListener(this.onBeforeRequest)
        browser.webRequest.onHeadersReceived.removeListener(this.onHeadersReceived)
    }

    onBeforeRequest(request) {
        if (this.trackingRequest) {
            let item = {
                requestId: request.requestId,
                type: "main_frame",
                request: request,
                response: {}
            }
            this.trackingRequest.set(request.requestId, item)
        }
    }

    onBeforeSendHeaders(request) {
        if (this.trackingRequest?.has('originalHeaders')) {
            request.requestHeaders = this.trackingRequest.get('originalHeaders')
            this.trackingRequest.delete('originalHeaders')
        }

        if (this.trackingRequest?.has(request.requestId)) {
            this.trackingRequest.get(request.requestId).request.requestHeaders = request.requestHeaders
        }

        return { requestHeaders: request.requestHeaders }
    }


    onHeadersReceived(response) {
        if (this.trackingRequest?.has(response.requestId)) {
            this.trackingRequest.get(response.requestId).response = response
        }
        return { responseHeaders: response.responseHeaders }
    }

    /* End Listeners */

    static rbuilderScheme() {
        return {
            sort: 0,
            opts: {
                "title": "",
                "override_headers": true,
                "follow_redirect": true,
                "update_content_length": true,
                "use_content_type": true
            },
            request: {

            },
            response: {
                headers: [],
                statusLine: '',
                statusCode: '',
                body: ''
            }
        }
    }

    static getParsedRaw(request) {
        let raw = ""
        if (request.split(/\r?\n\r?\n/).length > 1)
            raw = request.split(/\r?\n/).join('\r\n')
        else
            raw = request.split(/\r?\n/).concat(['\r\n']).join('\r\n')

        return raw
    }

    static updateRawRequest(schema, params, opts) {
        if (!opts) opts = schema.opts
        else schema.opts = opts

        if (params) {
            let url = params.request_protocol + '://' + params.request_url.replace(/^https?:\/\//, '')
            schema.request.scheme = params.request_protocol
            schema.request.method = params.request_method
            schema.request.url = url
        }

        ptk_request.normalizeHeaders(schema, opts)
        schema.request.raw = httpZ.build(schema.request, opts)
        return schema
    }

    static fingerprintRawRequest(raw) {
        if (!raw) return ''
        try {
            const schema = ptk_request.parseRawRequest(raw)
            const req = schema.request || {}
            const method = (req.method || 'GET').toUpperCase()
            const scheme = req.scheme || (req.request?.scheme) || 'http'
            const baseHost = req.host || req.headers?.find(h => (h.name || '').toLowerCase() === 'host')?.value || 'localhost'
            const needsBase = !(req.url || '').startsWith('http')
            const base = `${scheme}://${baseHost}`
            const urlObj = new URL(req.url || '/', needsBase ? base : undefined)
            const protocol = (urlObj.protocol || 'http:').replace(':', '').toLowerCase()
            const host = (urlObj.host || '').toLowerCase()
            let pathname = urlObj.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            pathname = pathname.replace(/\/+/g, '/')

            const queryNames = new Set()
            if (Array.isArray(req.queryParams)) {
                req.queryParams.forEach(param => {
                    const name = param?.name
                    if (name) queryNames.add(name.toLowerCase())
                })
            } else {
                urlObj.searchParams.forEach((_, key) => queryNames.add(key.toLowerCase()))
            }
            const querySig = Array.from(queryNames).sort().join('&')
            const bodySig = ptk_request._bodyFingerprint(req.body)

            const parts = [
                protocol,
                host,
                pathname,
                method
            ]
            if (querySig) parts.push(`q:${querySig}`)
            if (bodySig) parts.push(`b:${bodySig}`)
            return parts.join('|')
        } catch (err) {
            return ptk_request._fallbackFingerprint(raw)
        }
    }

    static _fallbackFingerprint(raw) {
        try {
            const firstLine = raw.split(/\r?\n/)[0] || ''
            const parts = firstLine.trim().split(/\s+/)
            const method = (parts[0] || 'GET').toUpperCase()
            const urlStr = parts[1] || '/'
            const urlObj = new URL(urlStr, urlStr.startsWith('http') ? undefined : 'http://localhost')
            const host = (urlObj.host || '').toLowerCase()
            let pathname = urlObj.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            pathname = pathname.replace(/\/+/g, '/')
            const queryNames = new Set()
            urlObj.searchParams.forEach((_, key) => queryNames.add(key.toLowerCase()))
            const querySig = Array.from(queryNames).sort().join('&')
            const partsOut = ['http', host, pathname, method]
            if (querySig) partsOut.push(`q:${querySig}`)
            return partsOut.join('|')
        } catch (_) {
            try {
                return raw.split(/\r?\n/)[0]?.trim() || raw
            } catch {
                return raw || ''
            }
        }
    }

    static _bodyFingerprint(body) {
        if (!body) return ''

        if (Array.isArray(body.params) && body.params.length) {
            return body.params
                .map(p => (p?.name || '').toLowerCase())
                .filter(Boolean)
                .sort()
                .join('&')
        }

        if (body.json && typeof body.json === 'object') {
            const jsonPaths = []
            ptk_request._collectJsonPaths(body.json, '', jsonPaths)
            if (jsonPaths.length) {
                return jsonPaths.sort().join('&')
            }
        }

        if (typeof body.text === 'string' && body.text.length) {
            const mime = (body.mimeType || '').toLowerCase()
            const looksForm = mime.includes('application/x-www-form-urlencoded') || /[=&]/.test(body.text)
            if (looksForm) {
                try {
                    const usp = new URLSearchParams(body.text)
                    const keys = Array.from(usp.keys()).map(key => key.toLowerCase())
                    if (keys.length) return keys.sort().join('&')
                } catch { /* ignore malformed urlencoded bodies */ }
            }

            try {
                const json = JSON.parse(body.text)
                const jsonPaths = []
                ptk_request._collectJsonPaths(json, '', jsonPaths)
                if (jsonPaths.length) {
                    return jsonPaths.sort().join('&')
                }
            } catch { /* not json */ }
        }

        return ''
    }

    static _collectJsonPaths(value, prefix, acc) {
        if (value === null || value === undefined) {
            if (prefix) acc.push(prefix)
            return
        }
        if (Array.isArray(value)) {
            value.forEach((item, index) => {
                const next = prefix ? `${prefix}[${index}]` : `[${index}]`
                if (item !== null && typeof item === 'object') {
                    ptk_request._collectJsonPaths(item, next, acc)
                } else {
                    acc.push(next)
                }
            })
            return
        }
        if (typeof value === 'object') {
            const keys = Object.keys(value)
            if (!keys.length) {
                if (prefix) acc.push(prefix)
                return
            }
            keys.forEach(key => {
                const next = prefix ? `${prefix}.${key}` : key
                const item = value[key]
                if (item !== null && typeof item === 'object') {
                    ptk_request._collectJsonPaths(item, next, acc)
                } else {
                    acc.push(next)
                }
            })
            return
        }
        if (prefix) acc.push(prefix)
    }

    static parseRawRequest(raw, opts) {
        let schema = ptk_request.rbuilderScheme()
        if (!opts) opts = schema.opts
        else schema.opts = opts

        schema.request = Object.assign(httpZ.parse(ptk_request.getParsedRaw(raw), opts))
        schema.request.scheme = schema.request.url.startsWith('https://') ? 'https' : 'http'

        ptk_request.normalizeHeaders(schema, opts)
        schema.request.raw = httpZ.build(schema.request, opts)
        const urlForParams = opts?.ui_url || schema.request.url
        const params = getSearchParamsFromUrlOrHash(urlForParams)
        schema.request.queryParams = []
        params.forEach((value, name) => {
            schema.request.queryParams.push({ name, value })
        })
        schema.request.ui_url = urlForParams
        return schema
    }


    static normalizeHeaders(schema, opts) {
        //Cache - no-cache
        let cacheControl = schema.request.headers.findIndex(obj => { return obj.name.toLowerCase() == "cache-control" });
        if (cacheControl == -1) {
            schema.request.headers.push({
                "name": "Cache-Control",
                "value": "no-cache"
            })
        } else {
            schema.request.headers[cacheControl].value = "no-cache"
        }

        let pragmaControl = schema.request.headers.findIndex(obj => { return obj.name.toLowerCase() == "pragma" });
        if (pragmaControl == -1) {
            schema.request.headers.push({
                "name": "Pragma",
                "value": "no-cache"
            })
        } else {
            schema.request.headers[pragmaControl].value = "no-cache"
        }

        //Host header
        if (schema.request.host == 'unspecified-host') {
            try {
                let url = new URL(schema.request.url)
                schema.request.host = url.host
            } catch (e) {
                throw new Error('Host header not defined. Use an absolute URL or add "Host" header.')
            }
        }
        if (schema.request.headers.findIndex(x => x.name.toLowerCase() == 'host') < 0) {
            schema.request.headers.push({ name: 'Host', value: schema.request.host })
        }



        //Content-Length - FF fix
        if (opts?.update_content_length != false) {
            if (["POST", "PUT", "DELETE", "PATCH"].includes(schema.request.method)) {
                let contentLengthIndex = schema.request.headers.findIndex(obj => { return obj.name.toLowerCase() == "content-length" })
                let contentLengthVal = 0
                if (schema.request.body?.params) {
                    schema.request.bodySize = (new URLSearchParams(schema.request.body.params.map(x => `${x.name}=${x.value}`).join('&'))).toString().length
                    contentLengthVal = (new URLSearchParams(schema.request.body.params.map(x => `${x.name}=${x.value}`).join('&'))).toString().length
                } else if (schema.request.body?.text) {
                    contentLengthVal = schema.request.body.text.toString().length
                }
                schema.request.bodySize = contentLengthVal
                if (contentLengthIndex < 0) {
                    schema.request.headers.push({
                        "name": "Content-Length",
                        "value": contentLengthVal.toString()
                    })
                } else {
                    schema.request.headers[contentLengthIndex].value = contentLengthVal.toString()
                }
            }
        }

    }

    async sendRequest(schema) {
        if (this.useListeners) this.addListeners()
        // ptk_ruleManager.getDynamicRules()
        // ptk_ruleManager.getSessionRules()
        let ruleId = null
        this.trackingRequest = new Map()

        if (schema.opts.override_headers != false && schema.request.headers.length > 0) {
            ruleId = parseInt((Math.floor(Math.random() * 6) + 1) + Math.floor((Date.now() * Math.random() * 1000)).toString().substr(-8, 8))
            await ptk_ruleManager.addSessionRule(schema, ruleId)
            this.trackingRequest.set('originalHeaders', JSON.parse(JSON.stringify(schema.request.headers)))
        }


        const timeoutMs = Number(schema?.opts?.requestTimeoutMs)
        let controller = null
        let timeoutId = null
        if (timeoutMs && timeoutMs > 0) {
            controller = new AbortController()
            timeoutId = setTimeout(() => controller.abort(), timeoutMs)
        }
        let h = {}
        for (let i = 0; i < schema.request.headers.length; i++) {
            let item = schema.request.headers[i]
            h[item.name] = item.value
        }

        let params = {
            method: schema.request.method,
            credentials: 'include',
            redirect: schema.opts.follow_redirect ? "follow" : "manual",
            cache: 'no-cache',
            keepalive: true,
            headers: h,
        }
        if (controller) {
            params.signal = controller.signal
        }
        let preparedBody = null
        if (schema.request.body && !schema.request.method.toUpperCase().match(/(^GET|^HEAD)/)) {
            if (typeof schema.request.body.text === 'string') {
                preparedBody = schema.request.body.text
            } else if (Array.isArray(schema.request.body.params)) {
                preparedBody = new URLSearchParams(schema.request.body.params.map(x => `${x.name}=${x.value}`).join('&')).toString()
                // keep schema in sync so future mutations operate on text
                schema.request.body.text = preparedBody
            }
            if (preparedBody !== null) {
                params.body = preparedBody
            }
        }
        this._ensureContentLength(schema, h, preparedBody)
        let rbSchema = schema
        rbSchema.response = rbSchema.response || {}
        const startTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()
        let self = this


        return fetch(schema.request.url, params).then(async function (response) {
            let rh = []
            for (var pair of response.headers.entries()) {
                rh.push({ name: pair[0], value: pair[1] })
            }
            let trackingRequest = null
            if (self.trackingRequest) {
                //trackingRequest = {}
                for (let key of self.trackingRequest.keys()) {
                    if (key != 'originalHeaders') {
                        trackingRequest = self.trackingRequest.get(key)
                        break
                    }
                }
                // for (let value of self.trackingRequest.values()) {
                //     trackingRequest = value
                //     break
                // }
                if (!response.redirected && trackingRequest)
                    rbSchema.request.headers = trackingRequest.request.requestHeaders
            }

            rbSchema.response.body = await response.text()
            rbSchema.response.length = typeof rbSchema.response.body === 'string' ? rbSchema.response.body.length : null
            if (trackingRequest) {
                rbSchema.response.headers = trackingRequest.response.responseHeaders
                rbSchema.response.statusLine = trackingRequest.response.statusLine
                rbSchema.response.statusCode = trackingRequest.response.statusCode
            } else {
                rbSchema.response.headers = rh
                rbSchema.response.statusLine = rbSchema.request.protocolVersion + ' ' + response.statusText
                rbSchema.response.statusCode = response.status
            }
            const endTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()
            rbSchema.response.timeMs = Math.round(endTime - startTime)

            return rbSchema
        }).catch(e => {
            console.warn('ptk_request.sendRequest failed', {
                url: schema?.request?.url,
                method: schema?.request?.method,
                hasBody: preparedBody !== null,
                bodyLength: preparedBody ? preparedBody.length : 0,
                name: e?.name,
                message: e?.message,
                cause: e?.cause?.message || e?.cause || null
            }, e)
            rbSchema.response = rbSchema.response || {}
            rbSchema.response.statusLine = e.message
            return rbSchema
        }).finally(() => {
            clearTimeout(timeoutId)
            self.trackingRequest = null
            if (this.useListeners) self.removeListeners()
            if (ruleId) {
                ptk_ruleManager.removeSessionRule(ruleId)
            }

        })
    }

    _ensureContentLength(schema, headersMap, body) {
        const shouldUpdate = schema?.opts?.update_content_length !== false
        const findHeaderName = () => {
            if (!headersMap) return null
            return Object.keys(headersMap).find(key => key?.toLowerCase() === 'content-length') || null
        }
        if (!shouldUpdate) {
            return
        }
        if (!body && body !== '') {
            const headerName = findHeaderName()
            if (headerName) delete headersMap[headerName]
            return
        }
        try {
            const byteLength = Buffer.byteLength(body, 'utf8')
            const headerName = findHeaderName() || 'Content-Length'
            headersMap[headerName] = String(byteLength)
        } catch (_) {
            const headerName = findHeaderName()
            if (headerName) delete headersMap[headerName]
        }
    }


}
