/* Author: Denis Podgurskii */
import { ptk_controller_iast } from "../../../controller/iast.js"
import { ptk_controller_rbuilder } from "../../../controller/rbuilder.js"
import { ptk_utils } from "../../../background/utils.js"
import { ptk_decoder } from "../../../background/decoder.js"
import * as rutils from "../js/rutils.js"
import { normalizeScanResult } from "../js/scanResultViewModel.js"

const controller = new ptk_controller_iast()
const request_controller = new ptk_controller_rbuilder()
const decoder = new ptk_decoder()
const iastFilterState = {
    scope: 'all',
    requestKey: null
}
const IAST_SEVERITY_ORDER = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
}

function collectIastStatsFromElements($collection) {
    const counts = { findingsCount: 0, vulnsCount: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    if (!$collection || typeof $collection.length === 'undefined') return counts
    $collection.each(function () {
        counts.findingsCount += 1
        counts.vulnsCount += 1
        const severity = ($(this).attr('data-severity') || '').toLowerCase()
        if (severity === 'critical') counts.critical += 1
        else if (severity === 'high') counts.high += 1
        else if (severity === 'medium') counts.medium += 1
        else if (severity === 'low') counts.low += 1
        else if (severity === 'info' || severity === 'informational') counts.info += 1
        else counts.low += 1
    })
    return counts
}

function hasRenderableIastData(scanResult) {
    if (!scanResult) return false
    if (Array.isArray(scanResult.findings) && scanResult.findings.length) return true
    const items = scanResult.items
    if (Array.isArray(items) && items.length) return true
    if (items && typeof items === 'object' && Object.keys(items).length) return true
    if (Array.isArray(scanResult.vulns) && scanResult.vulns.length) return true
    return false
}

function formatIastSeverityLabel(value) {
    if (!value) return 'info'
    return String(value).toLowerCase()
}

function formatIastSeverityDisplay(value) {
    const normalized = formatIastSeverityLabel(value)
    return normalized.charAt(0).toUpperCase() + normalized.slice(1)
}

function convertLegacyVulnToFinding(vuln, index) {
    if (!vuln) return null
    return {
        id: vuln.id || `vuln-${index}`,
        ruleId: vuln.ruleId || vuln.id || vuln.category || `vuln-${index}`,
        ruleName: vuln.ruleName || vuln.category || `Vulnerability ${index + 1}`,
        moduleId: vuln.moduleId || null,
        moduleName: vuln.moduleName || null,
        category: vuln.category || null,
        severity: vuln.severity || 'medium',
        owasp: vuln.owasp || null,
        cwe: vuln.cwe || null,
        tags: vuln.tags || [],
        location: { url: vuln.url || null, method: vuln.method || null },
        affectedUrls: vuln.url ? [vuln.url] : [],
        evidence: {
            iast: {
                taintSource: vuln.taintSource || null,
                sinkId: vuln.sink || null,
                context: {},
                matched: null,
                trace: []
            }
        }
    }
}

function mergeLinkMaps(...sources) {
    const out = {}
    sources.forEach(src => {
        if (!src || typeof src !== 'object') return
        Object.entries(src).forEach(([key, value]) => {
            if (!key || value === undefined || value === null) return
            out[key] = value
        })
    })
    return out
}

function extractPrimaryIastEvidence(finding) {
    if (!finding) return null
    const evidence = finding.evidence
    if (Array.isArray(evidence) && evidence.length) {
        const entry = evidence.find(ev => {
            const src = String(ev?.source || ev?.type || '').toLowerCase()
            return src === 'iast'
        })
        return entry || evidence[0] || null
    }
    if (evidence && typeof evidence === 'object') {
        if (evidence.IAST) return evidence.IAST
        if (evidence.iast) return evidence.iast
    }
    return null
}

function buildIastItemFromFinding(finding, index) {
    if (!finding) return null
    const loc = finding.location || {}
    const evidenceEntry = extractPrimaryIastEvidence(finding)
    const ev = evidenceEntry || {}
    const evRaw = ev.raw || {}
    const severity = formatIastSeverityLabel(finding.severity || ev.severity || evRaw.severity)
    const metaRule =
        finding.ruleName
        || finding.metadata?.name
        || evRaw?.meta?.ruleName
        || finding.module_metadata?.name
        || finding.moduleName
        || ev.message
        || finding.category
        || finding.ruleId
        || finding.id
        || `Finding ${index + 1}`
    const taintSource = ev.taintSource || evRaw?.taintSource || finding.taintSource || finding.source || null
    const sinkId = ev.sinkId || evRaw?.sinkId || finding.sinkId || finding.sink || null
    const baseContext = Object.assign({}, evRaw?.context || {}, ev.context || {}, finding.context || {})
    const flow = Array.isArray(baseContext.flow) ? baseContext.flow : []
    const tracePayload = ev.trace || baseContext.trace || finding.trace || null
    const description = finding.description || finding.metadata?.description || ev.description || evRaw?.meta?.description || ''
    const recommendation = finding.recommendation || finding.metadata?.recommendation || ev.recommendation || evRaw?.meta?.recommendation || ''
    const links = mergeLinkMaps(
        finding.links,
        finding.metadata?.links,
        finding.module_metadata?.links,
        ev.links,
        evRaw?.meta?.links
    )
    const contextPayload = Object.assign(
        {
            flow,
            domPath: baseContext.domPath || ev.domPath || loc.domPath || null,
            elementOuterHTML: baseContext.elementOuterHTML || ev.elementOuterHTML || null,
            value: baseContext.value || ev.value || null,
            url: baseContext.url || loc.url || null,
            elementId: baseContext.elementId || loc.elementId || null
        },
        baseContext
    )
    const normalizedEvidenceEntry = {
        source: 'IAST',
        taintSource,
        sinkId,
        context: contextPayload,
        matched: ev.matched || finding.matched || null,
        trace: tracePayload,
        raw: {
            severity,
            meta: { ruleName: metaRule },
            sinkId,
            source: taintSource,
            type: finding.category || null,
            owasp: finding.owasp || null,
            cwe: finding.cwe || null,
            tags: finding.tags || [],
            location: loc,
            context: contextPayload
        }
    }
    const affectedUrls = Array.isArray(finding.affectedUrls) ? finding.affectedUrls.slice() : []
    if (loc.url) affectedUrls.unshift(loc.url)
    return {
        id: finding.id || `iast-${index}`,
        ruleId: finding.ruleId || finding.id || `rule-${index}`,
        ruleName: metaRule,
        severity,
        category: finding.category || null,
        owasp: finding.owasp || null,
        cwe: finding.cwe || null,
        tags: finding.tags || [],
        location: loc,
        affectedUrls: affectedUrls.filter(Boolean),
        evidence: [normalizedEvidenceEntry],
        context: contextPayload,
        trace: tracePayload,
        description,
        recommendation,
        links,
        metadata: {
            id: finding.ruleId || finding.id || `rule-${index}`,
            name: metaRule,
            severity,
            description,
            recommendation,
            links
        },
        module_metadata: {
            id: finding.module_metadata?.id || finding.moduleId || null,
            name: finding.module_metadata?.name || evRaw?.meta?.moduleName || finding.moduleName || null,
            links: finding.module_metadata?.links || links
        },
        requestId: index,
        __index: index,
        type: 'iast',
        source: taintSource,
        sink: sinkId
    }
}

function getIastAttackItem(index) {
    if (Number.isNaN(Number(index))) return null
    const items = Array.isArray(controller?.iastAttackItems) ? controller.iastAttackItems : null
    if (items && items[index]) return items[index]
    const legacyItems = controller?.scanResult?.scanResult?.items
    if (Array.isArray(legacyItems)) return legacyItems[index] || null
    return null
}

function triggerIastStatsEvent(rawScanResult, viewModel) {
    const raw = rawScanResult || {}
    const vm = viewModel || normalizeScanResult(raw)
    const stats = vm.stats || raw.stats || {}
    controller._iastBaseStats = stats
    $(document).trigger("bind_stats", Object.assign({}, raw, { stats }))
}


jQuery(function () {

    // initialize all modals
    $('.modal.coupled')
        .modal({
            allowMultiple: true
        })


    $(document).on("click", ".showHtml", function () {
        rutils.showHtml($(this))
    })
    $(document).on("click", ".showHtmlNew", function () {
        rutils.showHtml($(this), true)
    })

    $(document).on("click", ".generate_report", function () {
        browser.windows.create({
            type: 'popup',
            url: browser.runtime.getURL("/ptk/browser/report.html?iast_report")
        })
    })

    $(document).on("click", ".save_report", function () {
        let el = $(this).parent().find(".loader")
        el.addClass("active")
        controller.saveReport().then(function (result) {
            if (result?.success) {
                $('#result_header').text("Success")
                $('#result_message').text("Scan saved")
                $('#result_dialog').modal('show')
            } else {
                $('#result_header').text("Error")
                $('#result_message').text(result?.json?.message)
                $('#result_dialog').modal('show')
            }

            el.removeClass("active")
        })
    })

    $(document).on("click", ".run_scan_runtime", function () {
        controller.init().then(function (result) {
            if (!result?.activeTab?.url) {
                $('#result_header').text("Error")
                $('#result_message').text("Active tab not set. Reload required tab to activate tracking.")
                $('#result_dialog').modal('show')
                return false
            }

            let h = new URL(result.activeTab.url).host
            $('#scan_host').text(h)
            // $('#scan_domains').text(h)

            $('#run_scan_dlg')
                .modal({
                    allowMultiple: true,
                    onApprove: function () {
                        controller.runBackroungScan(result.activeTab.tabId, h).then(function (result) {
                            $("#request_info").html("")
                            $("#attacks_info").html("")
                            triggerIastStatsEvent(result.scanResult)
                            changeView(result)
                        })
                    }
                })
                .modal('show')
        })

        return false
    })

    $(document).on("click", ".stop_scan_runtime", function () {
        controller.stopBackroungScan().then(function (result) {
            changeView(result)
            bindScanResult(result)
        })
        return false
    })

    $('.settings.rattacker').on('click', function () {
        $('#settings').modal('show')

    })

    $('.cloud_download_scans').on('click', function () {
        $('#download_scans').modal('show')
        controller.downloadScans().then(function (result) {

            if (!result?.success) {
                $("#download_error").text(result.json.message)
                $("#download_scans_error").show()
                return
            }

            $("#download_scans_error").hide()
            let dt = new Array()
            result?.json.forEach(item => {
                item.scans.forEach(scan => {
                    let link = `<div class="ui mini icon button download_scan_by_id" style="position: relative" data-scan-id="${scan.scanId}"><i class="download alternate large icon"
                                        title="Download"></i>
                                        <div style="position:absolute; top:1px;right: 2px">
                                             <div class="ui  centered inline inverted loader"></div>
                                        </div>
                                </div>`
                    let del = ` <div class="ui mini icon button delete_scan_by_id" data-scan-id="${scan.scanId}" data-scan-host="${item.hostname}"><i  class="trash alternate large icon "
                    title="Delete"></i></div>`
                    let d = new Date(scan.scanDate)
                    dt.push([item.hostname, scan.scanId, d.toLocaleString(), link, del])
                })
            })

            dt.sort(function (a, b) {
                if (a[0] === b[0]) { return 0; }
                else { return (a[0] < b[0]) ? -1 : 1; }
            })
            var groupColumn = 0;
            let params = {
                data: dt,
                columnDefs: [{
                    "visible": false, "targets": groupColumn
                }],
                "order": [[groupColumn, 'asc']],
                "drawCallback": function (settings) {
                    var api = this.api();
                    var rows = api.rows({ page: 'current' }).nodes();
                    var last = null;

                    api.column(groupColumn, { page: 'current' }).data().each(function (group, i) {
                        if (last !== group) {
                            $(rows).eq(i).before(
                                '<tr class="group" ><td colspan="4"><div class="ui black ribbon label">' + group + '</div></td></tr>'
                            );
                            last = group;
                        }
                    });
                }
            }

            bindTable('#tbl_scans', params)


        })
    })

    $(document).on("click", ".download_scan_by_id", function () {
        $(this).parent().find(".loader").addClass("active")
        let scanId = $(this).attr("data-scan-id")
        controller.downloadScanById(scanId).then(function (result) {
            let info = { isScanRunning: false, scanResult: result }
            changeView(info)
            if (hasRenderableIastData(info.scanResult)) {
                bindScanResult(info)
            }
            $('#download_scans').modal('hide')
        })
    })

    $('.import_export').on('click', function () {

        controller.init().then(function (result) {
            if (!hasRenderableIastData(result.scanResult)) {
                $('.export_scan_btn').addClass('disabled')
            } else {
                $('.export_scan_btn').removeClass('disabled')
            }
            $('#import_export_dlg').modal('show')
        })

    })

    $('.export_scan_btn').on('click', function () {
        controller.init().then(function (result) {
            if (hasRenderableIastData(result.scanResult)) {
                let blob = new Blob([JSON.stringify(result.scanResult)], { type: 'text/plain' })
                let fName = "PTK_IAST_scan.json"

                let downloadLink = document.createElement("a")
                downloadLink.download = fName
                downloadLink.innerHTML = "Download File"
                downloadLink.href = window.URL.createObjectURL(blob)
                downloadLink.click()
            }
        })
    })

    $('.import_scan_file_btn').on('click', function (e) {
        $("#import_scan_file_input").trigger("click")
        e.stopPropagation()
        e.preventDefault()
    })

    $("#import_scan_file_input").on('change', function (e) {
        e.stopPropagation()
        e.preventDefault()
        let file = $('#import_scan_file_input').prop('files')[0]
        loadFile(file)
        $('#import_scan_file_input').val(null)
    })

    async function loadFile(file) {
        var fileReader = new FileReader()
        fileReader.onload = function () {
            controller.save(fileReader.result).then(result => {
                changeView(result)
                if (hasRenderableIastData(result.scanResult)) {
                    bindScanResult(result)
                }
                $('#import_export_dlg').modal('hide')
            }).catch(e => {
                $('#result_message').text('Could not import IAST scan')
                $('#result_dialog').modal('show')
            })
        }

        fileReader.onprogress = (event) => {
            if (event.lengthComputable) {
                let progress = ((event.loaded / event.total) * 100);
                console.log(progress);
            }
        }
        fileReader.readAsText(file)
    }

    $('.import_scan_text_btn').on('click', function () {
        let scan = $("#import_scan_json").val()
        controller.save(scan).then(result => {
            changeView(result)
            if (hasRenderableIastData(result.scanResult)) {
                bindScanResult(result)
            }
            $('#import_export_dlg').modal('hide')
        }).catch(e => {
            $('#result_message').text('Could not import IAST scan')
            $('#result_dialog').modal('show')
        })
    })





    $(document).on("click", ".delete_scan_by_id", function () {
        let scanId = $(this).attr("data-scan-id")
        let scanHost = $(this).attr("data-scan-host")
        $("#scan_hostname").val("")
        $("#scan_delete_message").text("")
        $('#delete_scan_dlg')
            .modal({
                allowMultiple: true,
                onApprove: function () {
                    if ($("#scan_hostname").val() == scanHost) {
                        return controller.deleteScanById(scanId).then(function (result) {
                            $('.cloud_download_scans').trigger("click")
                            //console.log(result)
                            return true
                        })

                    } else {
                        $("#scan_delete_message").text("Type scan hostname to confirm delete")
                        return false
                    }
                }
            })
            .modal('show')
    })


    $(document).on("click", ".reset", function () {
        $("#request_info").html("")
        $("#attacks_info").html("")
        $('.generate_report').hide()
        $('.save_report').hide()
        //$('.exchange').hide()

        hideRunningForm()
        showWelcomeForm()
        controller.reset().then(function (result) {
            triggerIastStatsEvent(result.scanResult)
            if (Array.isArray(result?.default_modules) && result.default_modules.length) {
                bindModules(result)
            }
        })
    })

    $(document).on("click", ".request_filter_toggle", function (event) {
        event.preventDefault()
        event.stopPropagation()
        const key = $(this).attr("data-request-key") || ""
        toggleRequestFilter(key)
    })

    $('.send_rbuilder').on("click", function () {
        let request = $('#raw_request').val().trim()
        window.location.href = "rbuilder.html?rawRequest=" + decoder.base64_encode(encodeURIComponent(JSON.stringify(request)))
        return false
    })


    $('#filter_all').on("click", function () {
        setIastScopeFilter('all')
    })

    $('#filter_vuln').on("click", function () {
        setIastScopeFilter('vuln')
    })


    $(document).on("click", ".btn_stacktrace", function () {
        let el = $(this).parent().find(".content.stacktrace")
        if (this.textContent.trim() == 'Stack trace') {
            this.textContent = 'Hide stack trace'
            $(el).show()
        } else {
            $(this).parent().find(".content.stacktrace").hide()
            this.textContent = 'Stack trace'
        }

    })

    $(document).on("click", ".close.icon.stacktrace", function () {
        $(this).parent().hide()
        $(this).parent().parent().find(".btn_stacktrace").text('Stack trace')
    })

    $(document).on("click", ".iast-trace-toggle", function (event) {
        event.preventDefault()
        const $toggle = $(this)
        const $content = $toggle.next(".iast-trace-content")
        if (!$content.length) return
        const isVisible = $content.is(":visible")
        if (isVisible) {
            $content.slideUp(120)
            $toggle.attr("data-visible", "false").text("Show trace")
        } else {
            $content.slideDown(120)
            $toggle.attr("data-visible", "true").text("Hide trace")
        }
    })


    $(document).on("bind_stats", function (e, scanResult) {
        if (scanResult?.stats) {
            rutils.bindStats(scanResult.stats, 'iast')
            if (scanResult.stats.vulnsCount > 0) {
                $('#filter_vuln').trigger("click")
            }
        }
        return false
    })

    $.fn.selectRange = function (start, end) {
        var e = document.getElementById($(this).attr('id')); // I don't know why... but $(this) don't want to work today :-/
        if (!e) return;
        else if (e.setSelectionRange) { e.focus(); e.setSelectionRange(start, end); } /* WebKit */
        else if (e.createTextRange) { var range = e.createTextRange(); range.collapse(true); range.moveEnd('character', end); range.moveStart('character', start); range.select(); } /* IE */
        else if (e.selectionStart) { e.selectionStart = start; e.selectionEnd = end; }
    }

    controller.init().then(function (result) {
        changeView(result)
        if (hasRenderableIastData(result.scanResult)) {
            bindScanResult(result)
        } else if (Array.isArray(result?.default_modules) && result.default_modules.length) {
            bindModules(result)
            showWelcomeForm()
        } else {
            showWelcomeForm()
        }
    }).catch(e => { console.log(e) })

})

function filterByRequestId(requestId) {
    toggleRequestFilter(requestId)
}

function showWelcomeForm() {
    $('#welcome_message').show()
    $('#run_scan_bg_control').show()
}

function hideWelcomeForm() {
    $('#welcome_message').hide()
}

function showRunningForm(result) {
    $('#scanning_url').text(result.scanResult.host)
    $('.scan_info').show()
    $('#stop_scan_bg_control').show()
}

function hideRunningForm() {
    $('#scanning_url').text("")
    $('.scan_info').hide()
    $('#stop_scan_bg_control').hide()
}

function showScanForm(result) {
    $('#run_scan_bg_control').show()
}

function hideScanForm() {
    $('#run_scan_bg_control').hide()
}


function changeView(result) {
    $('#init_loader').removeClass('active')
    if (result.isScanRunning) {
        hideWelcomeForm()
        hideScanForm()
        showRunningForm(result)
    }
    else if (hasRenderableIastData(result.scanResult)) {
        hideWelcomeForm()
        hideRunningForm(result)
        showScanForm()
    }
    else {
        hideRunningForm()
        hideScanForm()
        showWelcomeForm()
    }
}

function cleanScanResult() {
    $("#attacks_info").html("")
    rutils.bindStats({
        attacksCount: 0,
        vulnsCount: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    }, 'iast')
}

function bindScanResult(result) {
    if (!result.scanResult) return
    const raw = result.scanResult || {}
    const vm = normalizeScanResult(raw)
    controller.scanResult = result
    controller.scanViewModel = vm
    $("#progress_message").hide()
    $('.generate_report').show()
    $('.save_report').show()
    $('#request_info').html("")
    $('#attacks_info').html("")
    hideWelcomeForm()

    const requests = prepareIastRequests(vm)
    bindRequestList(requests)
    const requestIndex = buildIastRequestIndex(requests)

    const findings = Array.isArray(vm.findings) ? vm.findings : []
    const legacyItems = Array.isArray(raw.items)
        ? raw.items
        : (raw.items && typeof raw.items === 'object'
            ? Object.keys(raw.items).sort().map(key => raw.items[key]).filter(Boolean)
            : [])
    const legacyVulns = Array.isArray(raw.vulns) ? raw.vulns : []

    let attackItems = []
    if (findings.length) {
        attackItems = findings.map((finding, index) => buildIastItemFromFinding(finding, index)).filter(Boolean)
    } else if (legacyItems.length) {
        attackItems = legacyItems.map((item, index) => {
            if (!item) return null
            item.__index = Number(index)
            item.requestId = index
            return item
        }).filter(Boolean)
    } else if (legacyVulns.length) {
        attackItems = legacyVulns.map((vuln, index) => {
            const normalized = convertLegacyVulnToFinding(vuln, index)
            return buildIastItemFromFinding(normalized, index)
        }).filter(Boolean)
    }
    controller.iastAttackItems = attackItems

    attackItems.forEach((item, index) => {
        if (!item) return
        item.__index = Number(index)
        item.requestId = index
        item.requestKey = mapFindingToRequestKey(item, requestIndex)
        $("#attacks_info").append(rutils.bindIASTAttack(item, index))
    })

    rutils.sortAttacks()
    controller._iastBaseStats = collectIastStatsFromElements($('.iast_attack_card'))
    triggerIastStatsEvent(raw, vm)
    updateRequestFilterActiveState()
    applyIastFilters()
}

function bindModules(result) {
    const modules = Array.isArray(result?.default_modules)
        ? result.default_modules
        : (Array.isArray(result) ? result : [])
    const rows = []
    modules.forEach((mod) => {
        if (!mod) return
        const moduleName = mod.name || mod.metadata?.name || mod.metadata?.module_name || mod.id || 'Module'
        const moduleSeverity = formatIastSeverityLabel(mod.metadata?.severity || mod.severity)
        const rules = Array.isArray(mod.rules) ? mod.rules : []
        if (rules.length) {
            rules.forEach(rule => {
                if (!rule) return
                const ruleName = rule.name || rule.metadata?.name || rule.id || 'Rule'
                const severity = formatIastSeverityLabel(rule.severity || rule.metadata?.severity || moduleSeverity)
                rows.push([ruleName, moduleName, formatIastSeverityDisplay(severity)])
            })
        } else {
            rows.push([moduleName, moduleName, formatIastSeverityDisplay(moduleSeverity)])
        }
    })
    rows.sort((a, b) => {
        const leftSeverity = formatIastSeverityLabel(a[2])
        const rightSeverity = formatIastSeverityLabel(b[2])
        const severityDiff = (IAST_SEVERITY_ORDER[leftSeverity] ?? 99) - (IAST_SEVERITY_ORDER[rightSeverity] ?? 99)
        if (severityDiff !== 0) return severityDiff
        const leftName = String(a[0] || '').toLowerCase()
        const rightName = String(b[0] || '').toLowerCase()
        return leftName.localeCompare(rightName)
    })
    bindTable('#iast_rules_table', { data: rows })
}

function bindRequest(info) {
    if (!info || !info._uiKey) return ''
    const requestUrl = ptk_utils.escapeHtml(info.displayUrl || info.url || 'unknown request')
    return `
        <div>
        <div class="title short_message_text request_filter_toggle" data-request-key="${ptk_utils.escapeHtml(info._uiKey)}" style="overflow-y: hidden;height: 34px;background-color: #eeeeee;margin:1px 0 0 0;cursor:pointer; position: relative">
            ${requestUrl}<i class="filter icon" style="float:right; position: absolute; top: 3px; right: -3px;" title="Filter by request"></i>
            
        </div>
    `
}



function bindAttackProgress(message) {
    $("#progress_attack_name").text(message.info.name)
    $("#progress_message").show()
}

function extractIastDataset(source) {
    if (!source) return []
    if (Array.isArray(source.findings) && source.findings.length) return source.findings
    if (source.legacy) {
        const legacyData = extractIastDataset(source.legacy)
        if (legacyData.length) return legacyData
    }
    const items = Array.isArray(source.items)
        ? source.items
        : (source.items && typeof source.items === 'object'
            ? Object.keys(source.items).sort().map(key => source.items[key]).filter(Boolean)
            : [])
    if (items.length) return items
    const vulns = Array.isArray(source.vulns) ? source.vulns : []
    if (vulns.length) {
        return vulns.map((vuln, index) => convertLegacyVulnToFinding(vuln, index)).filter(Boolean)
    }
    return []
}

function extractIastPrimaryUrl(item) {
    if (item?.location?.url) return item.location.url
    if (Array.isArray(item?.affectedUrls) && item.affectedUrls.length) return item.affectedUrls[0]
    if (Array.isArray(item?.evidence)) {
        const ev = item.evidence.find(e => e?.source === 'IAST') || item.evidence[0]
        if (ev) {
            const resolved = rutils.resolveIASTLocation(item, ev)
            if (resolved) return resolved
        }
    }
    return ''
}

function extractIastMethod(item) {
    if (item?.location?.method) return String(item.location.method).toUpperCase()
    if (item?.request?.method) return String(item.request.method).toUpperCase()
    return 'GET'
}

function prepareIastRequests(source) {
    const dataset = extractIastDataset(source)
    const requestMap = new Map()
    dataset.forEach(item => {
        if (!item) return
        const primaryUrl = extractIastPrimaryUrl(item)
        const candidateUrls = Array.isArray(item?.affectedUrls) && item.affectedUrls.length
            ? item.affectedUrls.filter(Boolean)
            : (primaryUrl ? [primaryUrl] : [])
        if (!candidateUrls.length) return
        const normalizedUrl = canonicalizeIastUrl(primaryUrl || candidateUrls[0])
        if (!normalizedUrl) return
        const method = extractIastMethod(item)
        const key = `${method} ${normalizedUrl}`
        const lastSeenTs = Date.parse(item?.updatedAt || item?.createdAt || Date.now())
        if (!requestMap.has(normalizedUrl)) {
            let host = ''
            try {
                const parsed = new URL(normalizedUrl)
                host = parsed.host || ''
            } catch (_) {
                try {
                    const parsedRaw = new URL(primaryUrl || candidateUrls[0])
                    host = parsedRaw.host || ''
                } catch (_) { }
            }
            requestMap.set(normalizedUrl, {
                key,
                method,
                displayUrl: primaryUrl || candidateUrls[0] || normalizedUrl,
                host,
                status: null,
                type: 'finding',
                url: normalizedUrl,
                lastSeen: Number.isNaN(lastSeenTs) ? Date.now() : lastSeenTs,
                _normalizedUrl: normalizedUrl,
                _uiKey: key
            })
        } else {
            const existing = requestMap.get(normalizedUrl)
            if (!Number.isNaN(lastSeenTs) && lastSeenTs > (existing.lastSeen || 0)) {
                existing.lastSeen = lastSeenTs
            }
        }
    })
    return Array.from(requestMap.values()).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))
}

function bindRequestList(requests) {
    const $container = $('#request_info')
    $container.html("")
    if (!requests.length) {
        //$container.append(`<div class="item"><div class="content"><div class="description">No requests captured yet.</div></div></div>`)
        return
    }
    requests.forEach(req => {
        $container.append(bindRequest(req))
    })
}

function buildIastRequestIndex(requests) {
    const index = new Map()
    requests.forEach(req => {
        if (!req?._normalizedUrl) return
        if (!index.has(req._normalizedUrl)) {
            index.set(req._normalizedUrl, [])
        }
        index.get(req._normalizedUrl).push(req)
    })
    return index
}

function mapFindingToRequestKey(finding, requestIndex) {
    if (!finding || !(requestIndex instanceof Map)) return null
    const primaryUrl = finding?.location?.url || (Array.isArray(finding?.affectedUrls) && finding.affectedUrls.length ? finding.affectedUrls[0] : null) || (Array.isArray(finding?.evidence) ? rutils.resolveIASTLocation(finding, finding.evidence.find(e => e?.source === 'IAST')) : null)
    const url = canonicalizeIastUrl(primaryUrl)
    if (!url) return null
    const matches = requestIndex.get(url)
    if (!matches || !matches.length) return null
    return matches[0]._uiKey || matches[0].key || null
}

function canonicalizeIastUrl(url) {
    if (!url) return ''
    try {
        const parsed = new URL(url)
        let pathname = parsed.pathname || '/'
        pathname = pathname.replace(/\/{2,}/g, '/')
        if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1)
        parsed.pathname = pathname
        return `${parsed.origin}${parsed.pathname}${parsed.search || ''}${parsed.hash || ''}`
    } catch (err) {
        try {
                const normalized = new URL(url, window.location.href)
                let pathname = normalized.pathname || '/'
                pathname = pathname.replace(/\/{2,}/g, '/')
                if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1)
                normalized.pathname = pathname
                return `${normalized.origin}${normalized.pathname}${normalized.search || ''}${normalized.hash || ''}`
        } catch (_) {
            return ''
        }
    }
}

function canonicalizeRequestKey(rawKey) {
    return rawKey ? String(rawKey) : ''
}

function toggleRequestFilter(rawKey) {
    const key = canonicalizeRequestKey(rawKey)
    if (!key) {
        clearRequestFilter()
        return
    }
    if (iastFilterState.requestKey === key) {
        clearRequestFilter()
        return
    }
    iastFilterState.requestKey = key
    updateRequestFilterActiveState()
    applyIastFilters()
}

function clearRequestFilter() {
    iastFilterState.requestKey = null
    updateRequestFilterActiveState()
    applyIastFilters()
}

function updateRequestFilterActiveState() {
    const key = iastFilterState.requestKey
    const $toggles = $('.request_filter_toggle')
    if (!$toggles.length) {
        iastFilterState.requestKey = null
        return
    }
    let found = false
    $toggles.each(function () {
        const matches = key && $(this).attr('data-request-key') === key
        $(this).toggleClass('active', !!matches)
        $(this).find('.filter.icon').toggleClass('primary', !!matches)
        if (matches) found = true
    })
    if (key && !found) {
        iastFilterState.requestKey = null
    }
}

function applyIastFilters() {
    const requestKey = iastFilterState.requestKey
    const scope = iastFilterState.scope
    const $cards = $('.iast_attack_card')
    $cards.each(function () {
        const $card = $(this)
        const cardKey = $card.attr('data-request-key') || ''
        const severity = ($card.attr('data-severity') || '').toLowerCase()
        let visible = true
        if (requestKey && cardKey !== requestKey) {
            visible = false
        }
        if (visible && scope === 'vuln' && severity === 'info') {
            visible = false
        }
        $card.toggle(visible)
    })
    const totalStats = controller._iastBaseStats || collectIastStatsFromElements($cards)
    const filteredStats = collectIastStatsFromElements($cards.filter(':visible'))
    const statsToShow = requestKey ? filteredStats : totalStats
    rutils.bindStats(statsToShow, 'iast')
}

$(document).on('click', '.iast-attack-details', function (event) {
    event.preventDefault()
    const indexAttr = $(this).attr('data-index')
    const index = typeof indexAttr !== 'undefined' ? Number(indexAttr) : NaN
    if (Number.isNaN(index)) {
        return
    }
    const item = getIastAttackItem(index)
    if (!item) return
    rutils.bindAttackDetails_IAST(item)
})

function setIastScopeFilter(scope) {
    const normalized = scope === 'vuln' ? 'vuln' : 'all'
    iastFilterState.scope = normalized
    $('#filter_all').toggleClass('active', normalized === 'all')
    $('#filter_vuln').toggleClass('active', normalized === 'vuln')
    applyIastFilters()
}




////////////////////////////////////
/* Chrome runtime events handlers */
////////////////////////////////////
browser.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message?.channel === 'ptk_background_iast2popup' && message?.type === 'scan_update') {
        const info = {
            scanResult: message.scanResult || {},
            isScanRunning: !!message.isScanRunning
        }
        changeView(info)
        if (hasRenderableIastData(info.scanResult)) {
            bindScanResult(info)
        }
    }
})
