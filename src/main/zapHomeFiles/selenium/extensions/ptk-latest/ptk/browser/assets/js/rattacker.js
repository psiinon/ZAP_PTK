/* Author: Denis Podgurskii */
import { ptk_controller_rattacker } from "../../../controller/rattacker.js"
import { ptk_controller_rbuilder } from "../../../controller/rbuilder.js"
import { ptk_utils } from "../../../background/utils.js"
import { ptk_decoder } from "../../../background/decoder.js"
import * as rutils from "../js/rutils.js"
import { normalizeScanResult } from "../js/scanResultViewModel.js"

const controller = new ptk_controller_rattacker()
const request_controller = new ptk_controller_rbuilder()
const decoder = new ptk_decoder()
const DAST_SEVERITY_ORDER = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
}

function formatDastSeverityLabel(value) {
    if (!value) return 'info'
    return String(value).toLowerCase()
}

function formatDastSeverityDisplay(value) {
    const normalized = formatDastSeverityLabel(value)
    return normalized.charAt(0).toUpperCase() + normalized.slice(1)
}


jQuery(function () {

    const $runCveInput = $('#ptk_dast_run_cve')
    const $runCveCheckboxWrapper = $runCveInput.closest('.ui.checkbox')
    let runCveState = false

    function setRunCveState(enabled, { updateUi = true } = {}) {
        runCveState = !!enabled
        if (!updateUi) {
            return
        }
        if ($runCveCheckboxWrapper.length && typeof $runCveCheckboxWrapper.checkbox === 'function') {
            const action = runCveState ? 'set checked' : 'set unchecked'
            $runCveCheckboxWrapper.checkbox(action)
        } else if ($runCveInput.length) {
            $runCveInput.prop('checked', runCveState)
        }
    }

    function isRunCveEnabled() {
        return !!runCveState
    }

    if ($runCveCheckboxWrapper.length && typeof $runCveCheckboxWrapper.checkbox === 'function') {
        $runCveCheckboxWrapper.checkbox({
            onChecked() {
                setRunCveState(true, { updateUi: false })
            },
            onUnchecked() {
                setRunCveState(false, { updateUi: false })
            }
        })
    } else if ($runCveInput.length) {
        $runCveInput.on('change', function () {
            setRunCveState($(this).is(':checked'), { updateUi: false })
        })
    }

    setRunCveState(false)

    // initialize all modals
    $('.modal.coupled')
        .modal({
            allowMultiple: true
        })

    const $saveScanModal = $('#save_scan_modal')
    let $saveScanProjectDropdown = $('#save_scan_project_select')
    const $saveScanModalError = $('#save_scan_modal_error')
    const saveScanProjectMap = new Map()
    const $downloadScansModal = $('#download_scans')
    let $downloadProjectDropdown = $('#download_project_select')
    const downloadProjectMap = new Map()

    function resetSemanticDropdown($dropdown) {
        if (!$dropdown || !$dropdown.length) {
            return $dropdown
        }
        const id = $dropdown.attr('id') || ''
        const classes = $dropdown.attr('class') || 'ui dropdown'
        const $newDropdown = $(`<select id="${id}" class="${classes}"></select>`)
        const $existingWrapper = $dropdown.closest('.ui.dropdown.selection')
        if ($existingWrapper.length) {
            $existingWrapper.replaceWith($newDropdown)
        } else {
            $dropdown.replaceWith($newDropdown)
        }
        return $newDropdown
    }

    function populateProjectDropdown($dropdown, projectMap, projectOptions, placeholderText) {
        let $target = resetSemanticDropdown($dropdown)
        projectMap.clear()
        if (!$target) return $dropdown
        $target.empty()
        const placeholder = document.createElement('option')
        placeholder.value = ''
        placeholder.textContent = placeholderText || 'Select a project'
        $target.append(placeholder)
        projectOptions.forEach(opt => {
            const option = document.createElement('option')
            option.value = opt.value
            option.textContent = opt.text
            projectMap.set(opt.value, opt.raw)
            $target.append(option)
        })
        $target.dropdown()
        $target.dropdown('clear')
        return $target
    }

    function showResultModal(header, message) {
        $('#result_header').text(header)
        $('#result_message').text(message || '')
        $('#result_dialog').modal('show')
    }

    function handleSaveScanResponse(result) {
        if (result instanceof Error) {
            showResultModal("Error", result.message || "Unable to save scan")
            return
        }
        if (result?.success) {
            showResultModal("Success", "Scan saved")
        } else {
            const message = result?.json?.message || result?.message || "Unable to save scan"
            showResultModal("Error", message)
        }
    }

    function extractProjectsFromPayload(payload) {
        if (!payload) return []
        if (Array.isArray(payload)) return payload
        if (typeof payload !== 'object') return []
        const containers = ['projects', 'data', 'items', 'results']
        for (const key of containers) {
            const value = payload[key]
            if (!value) continue
            if (Array.isArray(value)) {
                return value
            }
            const nested = extractProjectsFromPayload(value)
            if (nested.length) {
                return nested
            }
        }
        return []
    }

    function normalizeProjectOption(project) {
        if (project === null || project === undefined) return null
        if (typeof project === 'string' || typeof project === 'number' || typeof project === 'boolean') {
            const value = project
            return { value: String(value), text: String(value), raw: value }
        }
        if (typeof project !== 'object') return null
        const idFields = ['id', 'projectId', 'project_id', '_id', 'uuid', 'slug', 'key']
        let value = null
        for (const field of idFields) {
            if (project[field] !== undefined && project[field] !== null && project[field] !== '') {
                value = project[field]
                break
            }
        }
        if (!value && project?.name) {
            value = project.name
        }
        if (!value) return null
        const text = project.name || project.title || project.projectName || project.display_name || project.displayName || project.slug || project.key || String(value)
        return { value: String(value), text, raw: value }
    }

    function buildProjectOptions(payload) {
        const rawProjects = extractProjectsFromPayload(payload)
        const options = []
        rawProjects.forEach(project => {
            const option = normalizeProjectOption(project)
            if (option) {
                options.push(option)
            }
        })
        return options
    }

    function fetchPortalProjects() {
        return controller.getProjects().then(result => {
            if (!result?.success) {
                const message = result?.json?.message || result?.message || 'Unable to load projects. Check your PTK+ configuration.'
                throw new Error(message)
            }
            const projectOptions = buildProjectOptions(result.json)
            if (!projectOptions.length) {
                throw new Error('No projects available. Create a project in the portal and try again.')
            }
            return projectOptions
        })
    }

    function populateSaveScanProjectDropdown(projectOptions) {
        $saveScanProjectDropdown = populateProjectDropdown($saveScanProjectDropdown, saveScanProjectMap, projectOptions, 'Select a project')
    }

    function populateDownloadProjectDropdown(projectOptions) {
        $downloadProjectDropdown = populateProjectDropdown($downloadProjectDropdown, downloadProjectMap, projectOptions, 'Select a project')
        if (!$downloadProjectDropdown) return
        $downloadProjectDropdown.off('change').on('change', function () {
            const selected = $(this).val()
            if (!selected) {
                clearDownloadScansTable()
                setDownloadScansError('')
                return
            }
            const projectId = downloadProjectMap.get(selected) ?? selected
            loadScansForProject(projectId)
        })
    }

    function setDownloadScansError(message) {
        if (message) {
            $('#download_error').text(message)
            $('#download_scans_error').show()
        } else {
            $('#download_error').text('')
            $('#download_scans_error').hide()
        }
    }

    function extractScans(payload, inheritedHost = '') {
        if (!payload) return []
        if (Array.isArray(payload)) {
            return payload.reduce((acc, item) => acc.concat(extractScans(item, inheritedHost)), [])
        }
        if (typeof payload !== 'object') return []
        const host = payload.hostname || payload.host || payload.domain || payload.project || payload.name || inheritedHost || ''
        if (Array.isArray(payload.scans)) {
            return payload.scans.reduce((acc, item) => acc.concat(extractScans(item, host)), [])
        }
        const scanId = payload.scanId || payload.id
        if (scanId) {
            const scanDate = payload.scanDate || payload.finished_at || payload.created_at || payload.started_at || payload.meta?.scanDate
            return [{ hostname: host, scanId, scanDate, raw: payload }]
        }
        const containers = ['items', 'data', 'results', 'entries', 'projects', 'records']
        return containers.reduce((acc, key) => {
            if (!payload[key]) return acc
            return acc.concat(extractScans(payload[key], host))
        }, [])
    }

    function renderDownloadScansTable(items) {
        const entries = extractScans(items)
        const dt = []
        entries.forEach(entry => {
            if (!entry) return
            const scanId = entry.scanId || ''
            const hostname = entry.hostname || entry.raw?.meta?.hostname || ''
            const d = entry.scanDate ? new Date(entry.scanDate) : null
            const rawDate = entry.scanDate || entry.raw?.finished_at || entry.raw?.created_at || entry.raw?.started_at
            const dateObj = rawDate ? new Date(rawDate) : null
            const scanDate = dateObj && !isNaN(dateObj.getTime()) ? dateObj.toLocaleString() : ''
            const link = `<div class="ui mini icon button download_scan_by_id" style="position: relative" data-scan-id="${scanId}"><i class="download alternate large icon"
                                        title="Download"></i>
                                        <div style="position:absolute; top:1px;right: 2px">
                                             <div class="ui  centered inline inverted loader"></div>
                                        </div>
                                </div>`
            const del = ` <div class="ui mini icon button delete_scan_by_id" data-scan-id="${scanId}" data-scan-host="${hostname}"><i  class="trash alternate large icon "
                    title="Delete"></i></div>`
            dt.push([hostname, scanId, scanDate, link, del])
        })

        dt.sort(function (a, b) {
            if (a[0] === b[0]) { return 0 } else { return (a[0] < b[0]) ? -1 : 1 }
        })
        const groupColumn = 0
        const params = {
            data: dt,
            columnDefs: [{
                "visible": false, "targets": groupColumn
            }],
            "order": [[groupColumn, 'asc']],
            "drawCallback": function (settings) {
                var api = this.api()
                var rows = api.rows({ page: 'current' }).nodes()
                var last = null

                api.column(groupColumn, { page: 'current' }).data().each(function (group, i) {
                    if (last !== group) {
                        $(rows).eq(i).before(
                            '<tr class="group" ><td colspan="4"><div class="ui black ribbon label">' + group + '</div></td></tr>'
                        )
                        last = group
                    }
                })
            }
        }
        bindTable('#tbl_scans', params)
    }

    function clearDownloadScansTable() {
        renderDownloadScansTable([])
    }

    function loadDownloadProjects() {
        setDownloadScansError('')
        clearDownloadScansTable()
        $downloadScansModal.addClass('loading')
        fetchPortalProjects()
            .then(options => {
                populateDownloadProjectDropdown(options)
            })
            .catch(err => {
                setDownloadScansError(err?.message || 'Unable to load projects. Check your PTK+ configuration.')
            })
            .finally(() => {
                $downloadScansModal.removeClass('loading')
            })
    }

    function loadScansForProject(projectId) {
        if (!projectId) {
            setDownloadScansError('Select a project to load scans.')
            clearDownloadScansTable()
            return
        }
        setDownloadScansError('')
        $downloadScansModal.addClass('loading')
        controller.downloadScans(projectId, 'dast').then(result => {
            if (!result?.success) {
                const message = result?.json?.message || result?.message || 'Unable to load scans.'
                setDownloadScansError(message)
                clearDownloadScansTable()
                return
            }
            setDownloadScansError('')
            renderDownloadScansTable(result.json)
        }).catch(err => {
            setDownloadScansError(err?.message || 'Unable to load scans.')
            clearDownloadScansTable()
        }).finally(() => {
            $downloadScansModal.removeClass('loading')
        })
    }

    function hideSaveScanModalError() {
        $saveScanModalError.hide().text('')
    }

    function showSaveScanModalError(message) {
        $saveScanModalError.text(message || '').show()
    }

    function runSaveScan(projectId, $loader) {
        hideSaveScanModalError()
        if ($loader) {
            $loader.addClass('active')
        }
        $saveScanModal.addClass('loading')
        controller.saveScan(projectId).then(result => {
            handleSaveScanResponse(result)
            $saveScanModal.modal('hide')
        }).catch(err => {
            showResultModal("Error", err?.message || "Unable to save scan")
        }).finally(() => {
            if ($loader) {
                $loader.removeClass('active')
            }
            $saveScanModal.removeClass('loading')
        })
    }

    function showSaveScanModal($loader) {
        hideSaveScanModalError()
        $saveScanModal
            .modal({
                allowMultiple: true,
                onApprove: function () {
                    const projectId = $saveScanProjectDropdown.val()
                    if (!projectId) {
                        showSaveScanModalError('Select a project to continue.')
                        return false
                    }
                    const payloadProjectId = saveScanProjectMap.get(projectId) ?? projectId
                    runSaveScan(payloadProjectId, $loader)
                    return false
                }
            })
            .modal('show')
    }

    function requestProjectsAndShowModal($loader) {
        if ($loader) {
            $loader.addClass('active')
        }
        fetchPortalProjects()
            .then(projectOptions => {
                populateSaveScanProjectDropdown(projectOptions)
                showSaveScanModal($loader)
            })
            .catch(err => {
                showResultModal('Error', err?.message || 'Unable to load projects. Check your PTK+ configuration.')
            })
            .finally(() => {
                if ($loader) {
                    $loader.removeClass('active')
                }
            })
    }


    //$('.question').popup()
    // $('.domains_example')
    //     .popup({
    //         position: 'right center',

    //         title: 'Example',
    //         content: `<i>Example: <br /> domain.com, api.domain.com, subdomain.domain.com, www.domain.com</i>
    //             <br />
    //             <b>OR</b>
    //             <br />
    //             <i>*.domain.com - to scan all subdomains</i>`
    //     })


    $(document).on("click", ".showHtml", function () {
        rutils.showHtml($(this))
    })
    $(document).on("click", ".showHtmlNew", function () {
        rutils.showHtml($(this), true)
    })

    $(document).on("click", ".generate_report", function () {
        browser.windows.create({
            type: 'popup',
            url: browser.runtime.getURL("/ptk/browser/report.html?rattacker_report")
        })
    })

    $(document).on("click", ".save_scan", function () {
        const $loader = $(this).find(".loader")
        requestProjectsAndShowModal($loader)
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
            $('#scan_domains').text(h)
            $('#maxRequestsPerSecond').val(result.settings.maxRequestsPerSecond)
            $('#concurrency').val(result.settings.concurrency)
            $('#dast-scan-strategy').val(result.settings.dastScanStrategy || 'SMART')
            setRunCveState(false)

            $('#run_scan_dlg')
                .modal({
                    allowMultiple: true,
                    onApprove: function () {
                        const settings = {
                            maxRequestsPerSecond: $('#maxRequestsPerSecond').val(),
                            concurrency: $('#concurrency').val(),
                            scanStrategy: $('#dast-scan-strategy').val() || 'SMART',
                            runCve: isRunCveEnabled()
                        }
                        controller.runBackroungScan(result.activeTab.tabId, h, $('#scan_domains').val(), settings).then(function (result) {
                            $("#request_info").html("")
                            $("#attacks_info").html("")
                            triggerDastStatsEvent(result.scanResult)
                            changeView(result)
                        })
                    }
                })
                .modal('show')
            $('#dast_form .question')
                .popup({
                    inline: true,
                    hoverable: true,
                    position: 'bottom left',
                    delay: {
                        show: 300,
                        hide: 800
                    }
                })
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
        $downloadScansModal.modal('show')
        loadDownloadProjects()
    })

    $(document).on("click", ".download_scan_by_id", function () {
        $(this).parent().find(".loader").addClass("active")
        let scanId = $(this).attr("data-scan-id")
        controller.downloadScanById(scanId).then(function (result) {
            if (result?.success === false) {
                const message = result?.json?.message || result?.message || 'Unable to download scan'
                showResultModal("Error", message)
                return
            }
            let info = { isScanRunning: false, scanResult: result }
            changeView(info)
            if (hasRenderableScanData(info.scanResult)) {
                bindScanResult(info)
            }
            $('#download_scans').modal('hide')
        }).catch(err => {
            showResultModal("Error", err?.message || 'Unable to download scan')
        })
    })

    $('.import_export').on('click', function () {

        controller.init().then(function (result) {
            if (!hasRenderableScanData(result.scanResult)) {
                $('.export_scan_btn').addClass('disabled')
            } else {
                $('.export_scan_btn').removeClass('disabled')
            }
            $('#import_export_dlg').modal('show')
        })

    })

    $('.export_scan_btn').on('click', function () {
        controller.init().then(function (result) {
            if (hasRenderableScanData(result.scanResult)) {
                let blob = new Blob([JSON.stringify(result.scanResult)], { type: 'text/plain' })
                let fName = "PTK_DAST_scan.json"

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
                if (hasRenderableScanData(result.scanResult)) {
                    bindScanResult(result)
                }
                $('#import_export_dlg').modal('hide')
            }).catch(e => {
                $('#result_message').text('Could not import DAST scan')
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
            if (hasRenderableScanData(result.scanResult)) {
                bindScanResult(result)
            }
            $('#import_export_dlg').modal('hide')
        }).catch(e => {
            $('#result_message').text('Could not import DAST scan: ')
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
        $('.save_scan').hide()
        //$('.exchange').hide()

        hideRunningForm()
        showWelcomeForm()
        controller.reset().then(function (result) {
            triggerDastStatsEvent(result.scanResult)
            bindModules(result)
        })
    })

    $('.send_rbuilder').on("click", function () {
        let request = $('#raw_request').val().trim()
        window.location.href = "rbuilder.html?rawRequest=" + decoder.base64_encode(encodeURIComponent(JSON.stringify(request)))
        return false
    })


    const attackFilterState = {
        scope: 'all',
        requestId: null
    }

    const scopeFilters = {
        all: function ($subset) {
            $subset.show()
            return $subset
        },
        vuln: function ($subset) {
            const $visible = $subset.not('.nonvuln')
            $visible.show()
            return $visible
        },
        500: function ($subset) {
            const $visible = $subset.filter('.5xx_status')
            $visible.show()
            return $visible
        },
        400: function ($subset) {
            const $visible = $subset.filter('.4xx_status')
            $visible.show()
            return $visible
        }
    }

    function collectStats($collection) {
        const successItems = $collection.filter('.success')
        const countBySeverity = (target) => successItems.filter(function () {
            const attr = ($(this).attr('data-severity') || '').toLowerCase()
            if (attr === target) return true
            const label = target.charAt(0).toUpperCase() + target.slice(1)
            return $(this).hasClass(label)
        }).length
        return {
            attacksCount: $collection.length,
            vulnsCount: successItems.length,
            critical: countBySeverity('critical'),
            high: countBySeverity('high'),
            medium: countBySeverity('medium'),
            low: countBySeverity('low'),
            info: countBySeverity('info')
        }
    }

    function applyAttackFilters() {
        const $all = $('.attack_info')
        if (!$all.length) return
        $all.hide()
        const $requestSubset = attackFilterState.requestId ? $all.filter('.' + attackFilterState.requestId) : $all
        const totalStats = collectStats($requestSubset)
        const handler = scopeFilters[attackFilterState.scope] || scopeFilters.all
        const $visible = handler($requestSubset)
        const filteredStats = collectStats($visible)
        const showFilteredStats =
            attackFilterState.scope === '400' ||
            attackFilterState.scope === '500'
        const statsToDisplay = showFilteredStats ? filteredStats : totalStats
        rutils.bindStats({
            attacksCount: statsToDisplay.attacksCount,
            vulnsCount: statsToDisplay.vulnsCount,
            critical: statsToDisplay.critical,
            high: statsToDisplay.high,
            medium: statsToDisplay.medium,
            low: statsToDisplay.low,
            info: statsToDisplay.info
        }, 'dast')
    }

    function setScopeFilter(scope) {
        attackFilterState.scope = scope in scopeFilters ? scope : 'all'
        $('[id^="filter_"]').removeClass('active primary')
        $('#filter_' + attackFilterState.scope).addClass('active primary')
        applyAttackFilters()
    }

    function setRequestFilter(requestId) {
        attackFilterState.requestId = requestId
        updateRequestFilterUI()
        applyAttackFilters()
    }

    function updateRequestFilterUI() {
        const current = attackFilterState.requestId
        const $headers = $('#request_info .title.short_message_text')
        if (!$headers.length) {
            attackFilterState.requestId = null
            return
        }
        let found = false
        $headers.each(function () {
            const headerId = $(this).attr('data-request-id')
            const matches = current != null && headerId === String(current)
            if (matches) found = true
            $(this).toggleClass('active', !!matches)
            $(this).find('.filter.icon').toggleClass('primary', !!matches)
        })
        if (current != null && !found) {
            attackFilterState.requestId = null
        }
    }

    $('[id^="filter_"]').on("click", function () {
        const scope = this.id.replace('filter_', '')
        setScopeFilter(scope)
    })

    //$('#filter_all').addClass('active')


    $(document).on("click", ".attack_details", function () {
        $('.metadata .item').tab()
        let requestId = $(this).attr("data-requestId")
        let attackId = $(this).attr("data-index")
        const requestModel = findRequestModel(requestId)
        const attack = findAttackModel(requestModel, attackId)
        if (!attack || !requestModel) return
        const original = requestModel.original || controller?.scanResult?.scanResult?.items?.[requestId]?.original
        const lookup = controller._dastFindingLookup || buildFindingLookup(controller?.scanViewModel?.findings || [])
        const enrichedAttack = attachFindingMetadataToAttack(attack, lookup)
        rutils.bindAttackDetails_DAST($(this), enrichedAttack, original)
        $('.metadata .item').tab('change tab', 'first');
    })


    $(document).on("bind_stats", function (e, scanResult) {
        if (scanResult.stats) {
            rutils.bindStats(scanResult.stats, 'dast')
            if ((scanResult.stats.vulnsCount || scanResult.stats.findingsCount || 0) > 0) {
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
        if (hasRenderableScanData(result.scanResult)) {
            bindScanResult(result)
        } else if (Array.isArray(result?.default_modules) && result.default_modules.length) {
            bindModules(result)
        } else {
            showWelcomeForm()
        }
    })
    $('.ui.accordion').accordion({
        onOpen: function () {
            const index = $(this).find('input[name="requestId"]').val()
            setRequestFilter(index)
        },
        onClose: function () {
            setRequestFilter(null)
        }
    })

    window.ptkApplyAttackFilters = applyAttackFilters
    window.ptkSetRequestFilter = setRequestFilter
    window.ptkUpdateRequestFilterUI = updateRequestFilterUI
})

function filterByRequestId(requestId) {
    if (window.ptkSetRequestFilter) {
        window.ptkSetRequestFilter(requestId || null)
    }
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
    else if (hasRenderableScanData(result.scanResult)) {
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
    }, 'dast')
}

function hasRenderableScanData(scanResult) {
    if (!scanResult) return false
    if (Array.isArray(scanResult.requests) && scanResult.requests.length) return true
    if (Array.isArray(scanResult.findings) && scanResult.findings.length) return true
    return false
}

function getViewModelRequests() {
    if (!controller?.scanViewModel) return []
    return Array.isArray(controller.scanViewModel.requests) ? controller.scanViewModel.requests : []
}

function buildFindingLookup(findings) {
    const map = new Map()
    if (Array.isArray(findings)) {
        findings.forEach((finding) => {
            if (finding && finding.id) {
                map.set(String(finding.id), finding)
            }
        })
    }
    return map
}

function attachFindingMetadataToAttack(attack, lookup) {
    if (!attack) return attack
    if (attack && attack.findingId && lookup) {
        attack.finding = lookup.get(String(attack.findingId)) || null
    } else {
        attack.finding = null
    }
    const finding = attack.finding
    const severityFromFinding = finding?.severity
    const severityFromMeta = attack.metadata && typeof attack.metadata === 'object' ? attack.metadata.severity : undefined
    attack.severity = attack.severity || severityFromFinding || severityFromMeta || 'medium'
    return attack
}

function findRequestModel(requestId) {
    if (requestId == null) return null
    const key = String(requestId)
    const requests = getViewModelRequests()
    if (requests.length) {
        const direct = requests.find(record => String(record.id) === key)
        if (direct) return direct
        const idx = Number(key)
        if (!Number.isNaN(idx) && requests[idx]) {
            return requests[idx]
        }
    }
    return null
}

function findAttackModel(requestModel, attackId) {
    if (!requestModel || attackId == null) return null
    const key = String(attackId)
    const attacks = Array.isArray(requestModel.attacks) ? requestModel.attacks : []
    if (attacks.length) {
        const direct = attacks.find(attack => String(attack.id) === key)
        if (direct) return direct
        const idx = Number(key)
        if (!Number.isNaN(idx) && attacks[idx]) {
            return attacks[idx]
        }
    }
    return null
}

function triggerDastStatsEvent(rawScanResult, viewModel) {
    const raw = rawScanResult || {}
    const vm = viewModel || normalizeScanResult(raw)
    const stats = vm.stats || raw.stats || {}
    $(document).trigger("bind_stats", Object.assign({}, raw, { stats }))
}

function bindScanResult(result) {
    if (!result.scanResult) return
    const raw = result.scanResult || {}
    const vm = normalizeScanResult(raw)
    controller.scanResult = result
    controller.scanViewModel = vm
    $("#progress_message").hide()
    $('.generate_report').show()
    $('.save_scan').show()
    $('#request_info').html("")
    $('#attacks_info').html("")
    hideWelcomeForm()

    const findings = Array.isArray(vm.findings) ? vm.findings : []
    const findingLookup = buildFindingLookup(findings)
    controller._dastFindingLookup = findingLookup
    const requests = Array.isArray(vm.requests) ? vm.requests : []
    requests.forEach((request, index) => {
        const requestKey = String(request.id ?? `req-${index}`)
        const original = request.original && request.original.request ? request.original : request.original
        if (original && original.request) {
            $("#request_info").append(bindRequest(original, requestKey))
        }
        const attacks = Array.isArray(request.attacks) ? request.attacks : []
        attacks.forEach((attack, attackIdx) => {
            const attackKey = String(attack.id ?? `${requestKey}-${attackIdx}`)
            const enrichedAttack = attachFindingMetadataToAttack(attack, findingLookup)
            $("#attacks_info").append(rutils.bindAttack(enrichedAttack, original, attackKey, requestKey))
        })
    })

    if (window.ptkUpdateRequestFilterUI) {
        window.ptkUpdateRequestFilterUI()
    }
    rutils.sortAttacks()
    triggerDastStatsEvent(raw, vm)
    if (window.ptkApplyAttackFilters) {
        window.ptkApplyAttackFilters()
    }
}

function bindModules(result) {
    const modules = Array.isArray(result?.default_modules)
        ? result.default_modules
        : (Array.isArray(result) ? result : [])
    const rows = []
    modules.forEach((mod) => {
        if (!mod) return
        const moduleName = mod.name || mod.metadata?.name || mod.metadata?.module_name || mod.id || 'Module'
        const severity = formatDastSeverityLabel(mod.metadata?.severity || mod.severity)
        const attacks = mod.attacks
        const attackCount = Array.isArray(attacks)
            ? attacks.length
            : (attacks && typeof attacks === 'object' ? Object.keys(attacks).length : 0)
        rows.push([
            moduleName,
            attackCount,
            formatDastSeverityDisplay(severity)
        ])
    })

    rows.sort((a, b) => {
        const leftSeverity = formatDastSeverityLabel(a[2])
        const rightSeverity = formatDastSeverityLabel(b[2])
        const severityDiff = (DAST_SEVERITY_ORDER[leftSeverity] ?? 99) - (DAST_SEVERITY_ORDER[rightSeverity] ?? 99)
        if (severityDiff !== 0) return severityDiff
        const leftName = String(a[0] || '').toLowerCase()
        const rightName = String(b[0] || '').toLowerCase()
        return leftName.localeCompare(rightName)
    })

    bindTable('#tbl_modules', { data: rows })
}

function bindRequest(info, requestId) {
    let item = `
                <div>
                <div class="title short_message_text" data-request-id="${requestId}" style="overflow-y: hidden;height: 34px;background-color: #eeeeee;margin:1px 0 0 0;cursor:pointer; position: relative">
                    <i class="dropdown icon"></i>${info.request.ui_url || info.request.url}<i class="filter icon" style="float:right; position: absolute; top: 3px; right: -3px;" title="Filter by request"></i>
                    
                </div>
               
                <div class="content">
                <input type="hidden" name="requestId" value="${requestId}" />
                <textarea class="ui medium input" style="width:100%; height:200px; border: solid 1px #cecece; padding: 12px;">${info.request.raw}</textarea></div>
                </div>
                `
    return item
}

function bindAttackProgress(message) {
    $("#progress_attack_name").text(message.info.name)
    $("#progress_message").show()
}




////////////////////////////////////
/* Chrome runtime events handlers */
////////////////////////////////////
browser.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.channel == "ptk_background2popup_rattacker") {
        if (message.type == "attack completed") {
            //$(document).trigger("bind_stats", message.scanResult)
            //$("#attacks_info").append(bindAttack(message.info))
            //bindScanResult(message)
            bindAttackProgress(message)
        }
        if (message.type == "all attacks completed") {
            bindScanResult(message)
        }
        if (message.type == "attack failed") {
            $('#scan_error_message').text(message.info)
            $('.mini.modal').modal('show')
        }
    }
})
