/* Author: Denis Podgurskii */
import { ptk_controller_index } from "../../../controller/index.js"
import { ptk_utils, ptk_jwtHelper } from "../../../background/utils.js"
import CryptoES from '../../../packages/crypto-es/index.js'
const controller = new ptk_controller_index()
const jwtHelper = new ptk_jwtHelper()
var tokens = new Array()
var tokenAdded = false

let $runCveInput = null
let $runCveCheckboxWrapper = null
let runCveState = false

function setRunCveState(enabled, { updateUi = true } = {}) {
    runCveState = !!enabled
    if (!updateUi) {
        return
    }
    if ($runCveCheckboxWrapper && $runCveCheckboxWrapper.length && typeof $runCveCheckboxWrapper.checkbox === 'function') {
        const action = runCveState ? 'set checked' : 'set unchecked'
        $runCveCheckboxWrapper.checkbox(action)
    } else if ($runCveInput && $runCveInput.length) {
        $runCveInput.prop('checked', runCveState)
    }
}

function isRunCveEnabled() {
    return !!runCveState
}


jQuery(function () {

    $runCveInput = $('#ptk_dast_run_cve')
    $runCveCheckboxWrapper = $runCveInput.closest('.ui.checkbox')

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
            const checked = $(this).is(':checked')
            setRunCveState(checked, { updateUi: false })
        })
    }

    setRunCveState(false)

    tokens.push = function (item) {
        if (!this.find(e => (e[0] == item[0] && e[1] == item[1] && e[2] == item[2]))) {
            Array.prototype.push.call(this, item)
            this.onPush(item)
        }
    }

    tokens.onPush = function (obj) {
        //console.log(obj)
        $('#jwt_btn').show()
    }
    $('#jwt_btn').on('click', function () {
        controller.save(JSON.parse(JSON.stringify(tokens))).then(function (res) {
            location.href = "./jwt.html?tab=1"
        })

    })


    $('.menu .item').tab()
    $('#versionInfo').text(browser.runtime.getManifest().version)

    // $("#waf_wrapper").on("click", function () {
    //     $("#waf_wrapper").addClass("fullscreen modal")
    //     $('#waf_wrapper').modal('show')
    // })

    $(document).on("click", ".storage_auth_link", function () {
        let item = this.attributes["data"].textContent
        $(".menu .item").removeClass('active')
        $.tab('change tab', item)
        $("a[data-tab='" + item + "']").addClass('active')
        $('#storage_auth').modal('show')
    })

    $(document).on("click", "#generate_report", function () {
        let report = document.getElementById("main").outerHTML

        let enc = CryptoES.enc.Base64.stringify(CryptoES.enc.Utf8.parse(report))
        browser.storage.local.set({
            "tab_full_info":
            {
                "technologies": controller.tab.technologies,
                "waf": controller.tab.waf,
                "cves": controller.tab.cves
            }
        }).then(function (res) {
            browser.windows.create({
                type: 'popup',
                url: browser.runtime.getURL("/ptk/browser/report.html?full_report")
            })

        })
        return false

    })


    bindTable('#tbl_cves', { "columns": [{ width: "30%" }, { width: "15%" }, { width: "35%" }, { width: "20%" }] })
    bindTable('#tbl_technologies', { "columns": [{ width: "45%" }, { width: "30%" }, { width: "25%" }] })
    bindTable('#tbl_owasp', { "columns": [{ width: "100%" }] })
    bindTable('#tbl_storage', { "columns": [{ width: "90%" }, { width: "10%", className: 'dt-body-center' }] })

    setTimeout(function () {
        controller.init().then((result) => {
            if (result.redirect) {
                location.href = result.redirect
            }
            //console.log (result)
            bindInfo()
            bindOWASP()

        })
    }, 150)

    setupCardToggleHandlers()
})




/* Helpers */


async function bindInfo() {
    if (controller.url) {
        $('#dashboard_message_text').text(controller.url)
        if (!controller.privacy.enable_cookie) {
            $('.dropdown.item.notifications').show()
        }
    } else {
        $('#dashboard_message_text').html(dashboardText)
    }
}

async function bindOWASP() {
    let raw = controller.tab?.findings ? controller.tab.findings : new Array()
    let dt = raw.map(item => [item[0]])
    let params = { "data": dt, "columns": [{ width: "100%" }] }
    if ($.fn.dataTable.isDataTable('#tbl_owasp')) {
        $('#tbl_owasp').DataTable().clear().destroy()
        $('#tbl_owasp tbody').remove()
        $('#tbl_owasp').append('<tbody></tbody>')
    }
    let table = bindTable('#tbl_owasp', params)
    table.columns.adjust().draw()
    $('.loader.owasp').hide()
}

function bindCookies() {
    if (Object.keys(controller.cookies).length) {
        $("a[data-tab='cookie']").show()
        $('#tbl_storage').DataTable().row.add(['Cookie', `<a href="#" class="storage_auth_link" data="cookie">View</a>`]).draw()


        let dt = new Array()
        Object.values(controller.cookies).forEach(item => {
            // Object.values(domain).forEach(item => {
            dt.push([item.domain, item.name, item.value, item.httpOnly])
            //})
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
                            '<tr class="group" ><td colspan="3"><div class="ui black ribbon label">' + group + '</div></td></tr>'
                        );
                        last = group;
                    }
                });
            }
        }

        bindTable('#tbl_cookie', params)

        let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(dt), jwtHelper.sessionRegex)
        if (jwtToken) {
            let jwt = JSON.parse(decodedToken)
            tokens.push(['cookie', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
        }
    }
    $('.loader.storage').hide()
    bindTokens()
}

function bindHeaders() {
    if (Object.keys(controller.tab.requestHeaders).length) {
        let dt = new Array()
        Object.keys(controller.tab.requestHeaders).forEach(name => {
            if (name.startsWith('x-') || name == 'authorization' || name == 'cookie') {
                dt.push([name, controller.tab.requestHeaders[name][0]])
            }
        })
        let params = {
            data: dt
        }

        bindTable('#tbl_headers', params)

        let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(dt), jwtHelper.headersRegex)
        if (jwtToken) {
            let jwt = JSON.parse(decodedToken)
            tokens.push(['headers', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
        }
        bindTokens()
    }
}

async function bindTechnologies() {
    let dt = new Array()
    if (controller.tab.technologies)
        Object.values(controller.tab.technologies).forEach(item => {
            dt.push([item.name, item.version, item.category || ''])
        })
    const priority = (category) => {
        const value = (category || '').toLowerCase()
        if (value.includes('waf')) {
            return 0
        }
        if (value.includes('security')) {
            return 1
        }
        return 2
    }
    dt.sort((a, b) => {
        const diff = priority(a[2]) - priority(b[2])
        if (diff !== 0) {
            return diff
        }
        return a[0].localeCompare(b[0])
    })
    let params = { "data": dt, "columns": [{ width: "45%" }, { width: "30%" }, { width: "25%" }] }

    bindTable('#tbl_technologies', params)
    $('.loader.technologies').hide()
}

async function bindCVEs() {
    let dt = new Array()
    if (Array.isArray(controller.tab?.cves)) {
        controller.tab.cves.forEach(item => {
            const evidence = item.evidence || {}
            const evidenceText = `H:${evidence.headers || 0} / HTML:${evidence.html || 0} / JS:${evidence.js || 0}`
            const verifyText = item.verify?.moduleId ? `DAST module: ${item.verify.moduleId}` : ''
            dt.push([
                item.id || item.title || '',
                item.severity || '',
                evidenceText,
                verifyText
            ])
        })
    }
    let params = { "data": dt }
    bindTable('#tbl_cves', params)
    $('.loader.cves').hide()
}

async function bindTokens(data) {
    if (tokens.length > 0) {
        if (!tokenAdded) {
            $('#tbl_storage').DataTable().row.add(['Tokens', `<a href="#" class="storage_auth_link" data="tokens">View</a>`]).draw()
            tokenAdded = true
        }
        $("a[data-tab='tokens']").show()
        bindTable('#tbl_tokens', { data: tokens })
        controller.save(JSON.parse(JSON.stringify(tokens)))
    }
}



function bindStorage() {
    let dt = new Array()
    Object.keys(controller.storage).forEach(key => {
        let item = JSON.parse(controller.storage[key])
        if (Object.keys(item).length > 0 && item[key] != "") {
            $(document).trigger("bind_" + key, item)
            $("a[data-tab='" + key + "']").show()
            let link = `<a href="#" class="storage_auth_link" data="${key}">View</a>`
            dt.push([key, link])
        }
    })
    let existingRows = $('#tbl_storage').DataTable().rows().data()
    for (let i = 0; i < dt.length; i++) {
        let add = true
        for (let j = 0; j < existingRows.length; j++) {
            if (dt[i][0] == existingRows[j][0]) add = false
        }

        if (add)
            $('#tbl_storage').DataTable().row.add([dt[i][0], dt[i][1]]).draw()
    }
    $('.loader.storage').hide()

    bindTokens()
}

$(document).on("bind_localStorage", function (e, item) {
    if (Object.keys(item).length > 0) {

        let output = JSON.stringify(item, null, 4)
        let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(item), jwtHelper.storageRegex)
        if (jwtToken) {
            let jwt = JSON.parse(decodedToken)
            tokens.push(['localStorage', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
        }
        $('#localStorageText').text(output.replace(/\\r?\\n/g, '<br/>'))
    }
})

$(document).on("bind_sessionStorage", function (e, item) {
    if (Object.keys(item).length > 0) {
        let output = JSON.stringify(item, null, 4)
        let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(item), jwtHelper.storageRegex)
        if (jwtToken) {
            let jwt = JSON.parse(decodedToken)
            tokens.push(['sessionStorage', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
        }
        $('#sessionStorageText').text(output.replace(/\\r?\\n/g, '<br/>'))
    }
})

function mergeTechnologyRows(entries = []) {
    const dedupe = new Map()

    entries.forEach((entry) => {
        if (!entry || !entry.name) {
            return
        }

        const normalized = {
            name: entry.name,
            version: entry.version || '',
            category: entry.category || ''
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

const cardFullscreenState = {
    current: null
}

function setupCardToggleHandlers() {
    document.addEventListener('click', (event) => {
        const toggle = event.target.closest('.ptk-card-toggle')
        if (!toggle) {
            return
        }
        const card = toggle.closest('.ptk-dashboard-card')
        if (!card) {
            return
        }
        const shouldExpand = !card.classList.contains('ptk-card-fullscreen')
        setCardFullscreen(card, shouldExpand)
    })
}

function setCardFullscreen(card, shouldExpand) {
    if (shouldExpand) {
        if (cardFullscreenState.current && cardFullscreenState.current !== card) {
            cardFullscreenState.current.classList.remove('ptk-card-fullscreen')
            updateCardToggleIcon(cardFullscreenState.current, false)
        }
        card.classList.add('ptk-card-fullscreen')
        document.body.classList.add('ptk-card-fullscreen-active')
        cardFullscreenState.current = card
        card.scrollIntoView({ behavior: 'smooth', block: 'start' })
    } else {
        card.classList.remove('ptk-card-fullscreen')
        document.body.classList.remove('ptk-card-fullscreen-active')
        cardFullscreenState.current = null
    }
    updateCardToggleIcon(card, shouldExpand)
}

function updateCardToggleIcon(card, expanded) {
    const icon = card.querySelector('.ptk-card-toggle i')
    if (!icon) {
        return
    }
    icon.classList.remove(expanded ? 'expand' : 'compress')
    icon.classList.add(expanded ? 'compress' : 'expand')
}


function changeScanView(result) {
    if (result.scans.dast) {
        $('.dast_scan_control').addClass('disable')
        $('.dast_scan_stop').show()
        $('.ui.checkbox.dast_scan').hide()
    } else {
        $('.dast_scan_control').removeClass('disable')
        $('.dast_scan_stop').hide()
        $('.ui.checkbox.dast_scan').show()
    }
    //IAST
    if (result.scans.iast) {
        $('.iast_scan_control').addClass('disable')
        $('.iast_scan_stop').show()
        $('.ui.checkbox.iast_scan').hide()
    } else {
        $('.iast_scan_control').removeClass('disable')
        $('.iast_scan_stop').hide()
        $('.ui.checkbox.iast_scan').show()
    }
    if (result.scans.sast) {
        $('.sast_scan_control').addClass('disable')
        $('.sast_scan_stop').show()
        $('.ui.checkbox.sast_scan').hide()
    } else {
        $('.sast_scan_control').removeClass('disable')
        $('.sast_scan_stop').hide()
        $('.ui.checkbox.sast_scan').show()
    }
    if (result.scans.sca) {
        $('.sca_scan_control').addClass('disable')
        $('.sca_scan_stop').show()
        $('.ui.checkbox.sca_scan').hide()
    } else {
        $('.sca_scan_control').removeClass('disable')
        $('.sca_scan_stop').hide()
        $('.ui.checkbox.sca_scan').show()
    }
}


$(document).on("click", ".dast_scan_stop, .iast_scan_stop, .sast_scan_stop, .sca_scan_stop", function () {
    let $form = $('#index_scans_form'), values = $form.form('get values')
    let s = {
        dast: $(this).hasClass('dast_scan_stop') ? true : false,
        iast: $(this).hasClass('iast_scan_stop') ? true : false,
        sast: $(this).hasClass('sast_scan_stop') ? true : false,
        sca: $(this).hasClass('sca_scan_stop') ? true : false,
    }
    controller.stopBackroungScan(s).then(function (result) {
        changeScanView(result)
    }).catch(e => {
        console.log(e)
    })
})

$(document).on("click", "#manage_scans", function () {
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
        changeScanView(result)

        let settings = result.scans.dastSettings
        $('#maxRequestsPerSecond').val(settings.maxRequestsPerSecond)
        $('#concurrency').val(settings.concurrency)
        $('#dast-scan-strategy').val(settings.dastScanStrategy || 'SMART')
        setRunCveState(false)

        $('#run_scan_dlg')
            .modal({
                allowMultiple: true,
                onApprove: function () {
                    let $form = $('#index_scans_form'), values = $form.form('get values')
                    let s = {
                        dast: values['dast_scan'] == 'on' ? true : false,
                        iast: values['iast_scan'] == 'on' ? true : false,
                        sast: values['sast_scan'] == 'on' ? true : false,
                        sca: values['sca_scan'] == 'on' ? true : false,
                    }
                    let sast_policy = $('#policy').val()
                    const settings = {
                        maxRequestsPerSecond: $('#maxRequestsPerSecond').val(),
                        concurrency: $('#concurrency').val(),
                        sast_policy: $('#policy').val(),
                        scanStrategy: $('#dast-scan-strategy').val() || 'SMART',
                        runCve: isRunCveEnabled()
                    }
                    controller.runBackroungScan(result.activeTab.tabId, h, $('#scan_domains').val(), s, settings).then(function (result) {
                        //changeView(result)
                    })
                }
            })
            .modal('show')
        $('#index_scans_form .question')
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



/* Chrome runtime events handlers */
browser.runtime.onMessage.addListener(function (message, sender, sendResponse) {

    if (message.channel == "ptk_content2popup" && message.type == "init_complete") {
        controller.storage = message.data.auth
        controller.complete(message.data)
        //setTimeout(function () { controller.complete(message.data) }, 500) //TODO - remove timeout, but keep cookies 
    }

    if (message.channel == "ptk_background2popup_dashboard") {
        //Object.assign(controller, message.data)

        if (message.type == "init_complete") {
            Object.assign(controller, message.data)
            bindCookies()
            bindHeaders()
        }

        if (message.type == "analyze_complete") {
            let technologies = []
            if (Array.isArray(controller.tab?.technologies)) {
                technologies = technologies.concat(controller.tab.technologies)
            }
            if (Array.isArray(message.data?.tab?.technologies)) {
                technologies = technologies.concat(message.data.tab.technologies)
            }
            Object.assign(controller, message.data)
            if (technologies.length > 0 && controller.tab) {
                controller.tab.technologies = mergeTechnologyRows(technologies)
            }

            bindTechnologies()
            bindCVEs()
            bindStorage()
            $('#generate_report').removeClass('disabled')
            $('#manage_scans').removeClass('disabled')

        }
    }
})
