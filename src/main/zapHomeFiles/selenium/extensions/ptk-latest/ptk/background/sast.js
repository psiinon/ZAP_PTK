/* Author: Denis Podgurskii */
import {
  ptk_utils,
  ptk_logger,
  ptk_storage,
} from "../background/utils.js";

import { sastEngine } from "./sast/sastEngine.js";
import { SastScanBus } from "./sast/sast_scan_bus.js";
import { loadRulepack } from "./common/moduleRegistry.js";
import {
  createScanResultEnvelope,
  addFindingToGroup,
} from "./common/scanResults.js";
import {
  normalizeRulepack,
  resolveEffectiveSeverity,
} from "./common/severity_utils.js";

const worker = self;

export class ptk_sast {
  constructor(settings) {
    this.settings = settings;
    this.storageKey = "ptk_sast";
    this.activeTabId = null;
    this.resetScanResult();
    this.defaultModulesCache = null;

    this.onSastWorkerMessage = this.onSastWorkerMessage.bind(this);
    this.onOffscreenMessage = this.onOffscreenMessage.bind(this);
    this.sastWorker = null;
    this.offscreenInitPromise = null;

    this.addMessageListeners();
    this.ensureFirefoxWorker();
  }

  async getDefaultModules(rulepack = null) {
    if (rulepack && Array.isArray(rulepack.modules)) {
      this.defaultModulesCache = rulepack.modules;
      return this.defaultModulesCache;
    }
    if (Array.isArray(this.defaultModulesCache) && this.defaultModulesCache.length) {
      return this.defaultModulesCache;
    }
    try {
      const localPack = await loadRulepack("SAST");
      normalizeRulepack(localPack, { engine: "SAST", childKey: "rules" });
      this.defaultModulesCache = localPack.modules || [];
    } catch (err) {
      console.warn("[PTK SAST] Failed to load default SAST modules", err);
      this.defaultModulesCache = [];
    }
    return this.defaultModulesCache;
  }

  async init() {
    if (!this.isScanRunning) {
      this.storage = await ptk_storage.getItem(this.storageKey);
      if (Object.keys(this.storage).length > 0) {
        this.scanResult = this._normalizeEnvelope(this.storage);
      }
    }
  }

  resetScanResult() {
    this.isScanRunning = false;
    this.activeTabId = null;
    this.scanResult = this.getScanResultSchema();
  }

  getScanResultSchema() {
    const envelope = createScanResultEnvelope({
      engine: "SAST",
      scanId: null,
      host: null,
      tabId: null,
      startedAt: new Date().toISOString(),
      settings: {}
    });
    delete envelope.type;
    delete envelope.tabId;
    delete envelope.items;
    envelope.files = Array.isArray(envelope.files) ? envelope.files : [];
    return this._normalizeEnvelope(envelope);
  }

  async reset() {
    ptk_storage.setItem(this.storageKey, {});
    this.resetScanResult();
  }

  addMessageListeners() {
    this.onMessage = this.onMessage.bind(this);
    browser.runtime.onMessage.addListener(this.onMessage);
  }

  addListeners() {
    this.onRemoved = this.onRemoved.bind(this);
    browser.tabs.onRemoved.addListener(this.onRemoved);

    this.onUpdated = this.onUpdated.bind(this);
    browser.tabs.onUpdated.addListener(this.onUpdated);

    this.onCompleted = this.onCompleted.bind(this);
    browser.webRequest.onCompleted.addListener(
      this.onCompleted,
      { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
      ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
    );
  }

  async onUpdated(tabId, info, tab) { }

  removeListeners() {
    browser.tabs.onRemoved.removeListener(this.onRemoved);
    browser.tabs.onUpdated.removeListener(this.onUpdated);
    browser.webRequest.onCompleted.removeListener(this.onCompleted);
  }

  onRemoved(tabId, info) {
    if (this.activeTabId === tabId) {
      this.activeTabId = null;
      this.isScanRunning = false;
    }
  }

  onCompleted(response) { }

  onMessage(message, sender, sendResponse) {
    if (message.channel == "ptk_offscreen2background_sast") {
      this.onOffscreenMessage(message);
      return;
    }

    if (message.channel == "ptk_popup2background_sast") {
      if (this["msg_" + message.type]) {
        return this["msg_" + message.type](message);
      }
      return Promise.resolve({ result: false });
    }

    if (message.channel == "ptk_content_sast2background_sast") {
      if (message.type == "scripts_collected") {
        if (this.isScanRunning && this.activeTabId == sender.tab.id) {
          this.scanCode(message.scripts, message.html, message.file).catch(e => console.error("SAST scanCode failed", e));
        }
      }
    }
  }

  onOffscreenMessage(message) {
    const { type, scanId, info, file, findings, error } = message;
    if (!this.scanResult?.scanId || scanId !== this.scanResult.scanId) return;

    if (this.isStructuredEvent(type)) {
      this.handleStructuredEvent(type, message);
      return;
    }

    if (type === "progress") {
      this.handleProgress(info);
      return;
    }

    if (type === "scan_result") {
      this.handleScanResultFromWorker(file, findings);
      return;
    }

    if (type === "error") {
      this.isScanRunning = false;
      console.error("SAST worker error", error);
    }
  }

  handleProgress(data) {
    if (data?.file && !data.file.startsWith("about:") && !this.scanResult.files.includes(data.file)) {
      this.scanResult.files.push(data.file);
    }

    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type: "progress",
      info: data,
      scanResult: JSON.parse(JSON.stringify(this.scanResult))
    }).catch(e => e);
  }

  handleScanResultFromWorker(file, findings = []) {
    const normalized = Array.isArray(findings) ? findings : [];
    const pageUrl = file || "";
    const pageCanon = this.canonicalFileId(pageUrl);

    if (!normalized.length) return;

    normalized.forEach((finding, index) => {
      finding.pageUrl = pageUrl;
      finding.pageCanon = pageCanon;
      this._addUnifiedFinding(finding, index);
    });
    this.updateScanResult();
    ptk_storage.setItem(this.storageKey, this.scanResult);
    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type: "update findings",
      scanResult: JSON.parse(JSON.stringify(this.scanResult))
    }).catch(e => e);
  }

  isStructuredEvent(type) {
    return [
      "scan:start",
      "file:start",
      "file:end",
      "module:start",
      "module:end",
      "scan:summary",
      "scan:error"
    ].includes(type);
  }

  handleStructuredEvent(type, payload) {
    const data = payload?.payload || payload || {};
    const clone = () => JSON.parse(JSON.stringify(this.scanResult));
    const file = data.file;
    if (type === "file:start") {
      if (file && !file.startsWith("about:") && !this.scanResult.files.includes(file)) {
        this.scanResult.files.push(file);
      }
      browser.runtime.sendMessage({
        channel: "ptk_background2popup_sast",
        type,
        payload: data,
        scanResult: clone()
      }).catch(() => { });
      return;
    }

    if (type === "file:end" || type === "scan:start" || type === "scan:summary") {
      browser.runtime.sendMessage({
        channel: "ptk_background2popup_sast",
        type,
        payload: data,
        scanResult: clone()
      }).catch(() => { });
      return;
    }

    if (type === "module:start" || type === "module:end") {
      browser.runtime.sendMessage({
        channel: "ptk_background2popup_sast",
        type,
        payload: data
      }).catch(() => { });
      return;
    }

    if (type === "scan:error") {
      this.isScanRunning = false;
      browser.runtime.sendMessage({
        channel: "ptk_background2popup_sast",
        type,
        payload: data
      }).catch(() => { });
    }
  }

  onSastWorkerMessage(event) {
    const { type, scanId, info, file, findings, error } = event.data || {};
    if (!this.scanResult?.scanId || scanId !== this.scanResult.scanId) return;

    if (this.isStructuredEvent(type)) {
      this.handleStructuredEvent(type, event.data);
      return;
    }

    if (type === "progress") {
      this.handleProgress(info);
      return;
    }

    if (type === "scan_result") {
      this.handleScanResultFromWorker(file, findings);
      return;
    }

    if (type === "error") {
      this.isScanRunning = false;
      console.error("SAST worker error", error);
    }
  }

  ensureFirefoxWorker() {
    if (!worker.isFirefox || typeof Worker === "undefined") return;
    if (this.sastWorker) return;

    const candidates = [
      "ptk/background/sast/sast_worker.js",
      "background/sast/sast_worker.js",
    ];

    for (const path of candidates) {
      try {
        this.sastWorker = new Worker(browser.runtime.getURL(path), { type: "module" });
        this.sastWorker.onmessage = this.onSastWorkerMessage;
        this.sastWorker.onmessageerror = (err) =>
          console.error("SAST worker message error", err, "path:", path);
        this.sastWorker.onerror = (err) =>
          console.error("SAST worker error", err, "path:", path);
        return;
      } catch (err) {
        console.error("Failed to init SAST worker", path, err);
        this.sastWorker = null;
      }
    }
  }

  async ensureSastOffscreenDocument() {
    if (worker.isFirefox) return;
    if (typeof chrome === "undefined" || !chrome?.offscreen?.createDocument) return;

    if (!this.offscreenInitPromise) {
      this.offscreenInitPromise = (async () => {
        if (chrome.offscreen.hasDocument) {
          const has = await chrome.offscreen.hasDocument();
          if (has) return;
        }

        await chrome.offscreen.createDocument({
          url: "ptk/offscreen/sast_offscreen.html",
          reasons: ["IFRAME_SCRIPTING"],
          justification: "Run CPU-heavy SAST engine outside the MV3 service worker",
        });
      })();
    }

    return this.offscreenInitPromise;
  }

  updateScanResult() {
    if (!Array.isArray(this.scanResult.findings)) {
      this.scanResult.findings = [];
    }
    this._rebuildGroupsFromFindings();
    this._recalculateStats(this.scanResult);
    ptk_storage.setItem(this.storageKey, this.scanResult);
  }

  _recalculateStats(envelope) {
    if (!envelope) return;
    const findings = Array.isArray(envelope.findings) ? envelope.findings : [];
    const stats = { findingsCount: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0, rulesCount: 0 };
    findings.forEach(finding => {
      const sev = (finding?.severity || '').toLowerCase();
      if (sev === 'critical') stats.critical += 1;
      else if (sev === 'high') stats.high += 1;
      else if (sev === 'medium') stats.medium += 1;
      else if (sev === 'low') stats.low += 1;
      else stats.info += 1;
    });
    envelope.stats = stats;
    this._setRulesCount(envelope);
  }

  _setRulesCount(envelope) {
    if (!envelope) return;
    const findings = Array.isArray(envelope.findings) ? envelope.findings : [];
    const uniqueRuleIds = new Set(findings.map((finding) => finding?.ruleId).filter(Boolean));
    if (!envelope.stats || typeof envelope.stats !== "object") {
      envelope.stats = { findingsCount: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, rulesCount: 0 };
    }
    envelope.stats.rulesCount = uniqueRuleIds.size;
  }

  // ---- URL / file canonicalization helpers ----

  // Normalize a URL so query/hash/cache-busters don't fragment duplicates
  canonicalizeUrl(raw, base) {
    if (!raw) return "";
    try {
      const u = new URL(String(raw), base || (typeof document !== "undefined" ? document.baseURI : undefined));

      // lower-case host
      u.hostname = (u.hostname || "").toLowerCase();

      // strip query + hash
      u.search = "";
      u.hash = "";

      // strip default ports
      const isHttp = u.protocol === "http:";
      const isHttps = u.protocol === "https:";
      if ((isHttp && u.port === "80") || (isHttps && u.port === "443")) {
        u.port = "";
      }

      // collapse multiple slashes in path and remove trailing slash (except root)
      let p = u.pathname || "/";
      p = p.replace(/\/{2,}/g, "/");
      if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
      u.pathname = p;

      // return schema://host[:port]/path
      return u.toString();
    } catch {
      // Fallback for non-URLs or if URL() not available
      const s = String(raw);
      const noHash = s.split("#")[0];
      const noQuery = noHash.split("?")[0];
      // best-effort trailing slash trim (not for root)
      return noQuery.length > 1 && noQuery.endsWith("/") ? noQuery.slice(0, -1) : noQuery;
    }
  }

  // Recognize our inline labels, e.g. "…/page.html :: inline-onclick[#1]"


  // Build a stable file identifier for deduping.
  // - For page/scripts: canonical URL without query/hash.
  // - For inline handlers/scripts: "<canonicalPage> :: <inline-label>"
  canonicalFileId(raw, base) {
    const INLINE_SPLIT_RE = /\s+::\s+/;
    if (!raw) return "";

    // if we already store "page :: inline-label"
    if (INLINE_SPLIT_RE.test(raw)) {
      const [page, inlinePart] = raw.split(INLINE_SPLIT_RE);
      const canonPage = this.canonicalizeUrl(page, base);
      return `${canonPage} :: ${inlinePart}`;
    }

    // plain URL/file path
    return this.canonicalizeUrl(raw, base);
  }



  async scanCode(scripts, html, file) {
    if (worker.isFirefox && this.sastWorker) {
      this.sastWorker.postMessage({
        type: "scan_code",
        scanId: this.scanResult.scanId,
        scripts,
        html,
        file
      });
      return [];
    }

    if (!worker.isFirefox) {
      await this.ensureSastOffscreenDocument();
      try {
        await browser.runtime.sendMessage({
          channel: "ptk_bg2offscreen_sast",
          type: "scan_code",
          scanId: this.scanResult.scanId,
          scripts,
          html,
          file
        });
      } catch (err) {
        console.error("Failed to send code to SAST offscreen worker", err);
      }
      return [];
    }

    if (!this.sastEngine) return [];
    const findings = await this.sastEngine.scanCode(scripts, html, file);
    this.handleScanResultFromWorker(file, findings);
    return findings;
  }

  async msg_init(message) {
    await this.init();
    const defaultModules = await this.getDefaultModules();
    return Promise.resolve({
      scanResult: JSON.parse(JSON.stringify(this.scanResult)),
      isScanRunning: this.isScanRunning,
      activeTab: worker.ptk_app.proxy.activeTab,
      default_modules: defaultModules
    });
  }

  async msg_reset(message) {
    this.reset();
    const defaultModules = await this.getDefaultModules();
    return Promise.resolve({
      scanResult: JSON.parse(JSON.stringify(this.scanResult)),
      activeTab: worker.ptk_app.proxy.activeTab,
      default_modules: defaultModules
    });
  }

  async msg_loadfile(message) {
    this.reset();
    //await this.init()

    return new Promise((resolve, reject) => {
      var fr = new FileReader();
      fr.onload = () => {
        resolve(this.msg_save(fr.result));
      };
      fr.onerror = reject;
      fr.readAsText(message.file);
    });
  }

  async msg_save(message) {
    const raw = JSON.parse(message.json || "{}");
    const imported = this._normalizeImportedScan(raw);
    if (!imported) {
      return Promise.reject(new Error("Wrong format or empty scan result"));
    }
    this.reset();
    const normalized = this._normalizeEnvelope(imported);
    this.scanResult = normalized;
    ptk_storage.setItem(this.storageKey, normalized);
    return Promise.resolve({
      scanResult: JSON.parse(JSON.stringify(this.scanResult)),
      isScanRunning: this.isScanRunning,
      activeTab: worker.ptk_app.proxy.activeTab,
    });
  }



  async msg_run_bg_scan(message) {
    try {
      const [rulepack, catalog] = await Promise.all([
        loadRulepack("SAST"),
        fetch(browser.runtime.getURL("ptk/background/sast/modules/catalog.json")).then(res => res.json())
      ]);
      normalizeRulepack(rulepack, { engine: 'SAST', childKey: 'rules' })

      await this.runBackroungScan(message.tabId, message.host, message.policy, { rulepack, catalog });
      const defaultModules = await this.getDefaultModules(rulepack);

      return {
        isScanRunning: this.isScanRunning,
        scanResult: JSON.parse(JSON.stringify(this.scanResult)),
        success: true,
        default_modules: defaultModules
      };
    } catch (err) {
      console.error("Failed to start SAST scan", err);
      this.isScanRunning = false;
      return { success: false, error: "modules_load_failed", message: err?.message || String(err) };
    }
  }

  msg_stop_bg_scan(message) {
    this.stopBackroungScan();
    return Promise.resolve({
      scanResult: JSON.parse(JSON.stringify(this.scanResult)),
    });
  }

  async msg_get_projects(message) {
    const profile = worker.ptk_app.settings.profile || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    const url = this.buildPortalUrl(profile.projects_endpoint, profile);
    if (!url) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    const response = await fetch(url, {
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json'
      },
      cache: 'no-cache'
    })
      .then(async (httpResponse) => {
        const json = await httpResponse.json().catch(() => null);
        if (httpResponse.ok) {
          return { success: true, json };
        }
        return { success: false, json: json || { message: "Unable to load projects" } };
      })
      .catch(e => ({ success: false, json: { message: "Error while loading projects: " + e.message } }));
    return response;
  }

  async msg_save_scan(message) {
    const profile = worker.ptk_app.settings.profile || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    const findingCount = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0;
    if (!findingCount) {
      return { success: false, json: { message: "Scan result is empty" } };
    }
    const url = this.buildPortalUrl(profile.scans_endpoint, profile);
    if (!url) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    const payload = JSON.parse(JSON.stringify(this.scanResult));
    if (message?.projectId) {
      payload.projectId = message.projectId;
    }
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      cache: 'no-cache',
      body: JSON.stringify(payload)
    })
      .then(async (httpResponse) => {
        if (httpResponse.status === 201) {
          return { success: true };
        }
        const json = await httpResponse.json().catch(() => ({ message: httpResponse.statusText }));
        return { success: false, json };
      })
      .catch(e => ({ success: false, json: { message: "Error while saving report: " + e.message } }));
    return response;
  }

  async msg_download_scans(message) {
    const profile = worker.ptk_app.settings.profile || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    const baseUrl = this.buildPortalUrl(profile.scans_endpoint, profile);
    if (!baseUrl) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    let requestUrl = baseUrl;
    try {
      const url = new URL(baseUrl);
      if (message?.projectId) {
        url.searchParams.set('projectId', message.projectId);
      }
      const engine = message?.engine || 'sast';
      if (engine) {
        url.searchParams.set('engine', engine);
      }
      requestUrl = url.toString();
    } catch (err) {
      return { success: false, json: { message: "Invalid scans endpoint." } };
    }
    const response = await fetch(requestUrl, {
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json'
      },
      cache: 'no-cache'
    })
      .then(async (httpResponse) => {
        const json = await httpResponse.json().catch(() => null);
        if (httpResponse.ok) {
          return { success: true, json };
        }
        return { success: false, json: json || { message: "Unable to load scans" } };
      })
      .catch(e => ({ success: false, json: { message: "Error while loading scans: " + e.message } }));
    return response;
  }

  async msg_download_scan_by_id(message) {
    const profile = worker.ptk_app.settings.profile || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    if (!message?.scanId) {
      return { success: false, json: { message: "Scan identifier is required." } };
    }
    const baseUrl = this.buildPortalUrl(profile.scans_endpoint, profile);
    if (!baseUrl) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    const normalizedBase = baseUrl.replace(/\/+$/, "");
    const downloadUrl = `${normalizedBase}/${encodeURIComponent(message.scanId)}/download`;
    const response = await fetch(downloadUrl, {
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json'
      },
      cache: 'no-cache'
    })
      .then(async (httpResponse) => {
        const json = await httpResponse.json().catch(() => null);
        if (!httpResponse.ok) {
          return { success: false, json: json || { message: "Unable to download scan" } };
        }
        if (json) {
          this.scanResult = json;
          ptk_storage.setItem(this.storageKey, json);
        }
        return json;
      })
      .catch(e => ({ success: false, json: { message: "Error while downloading scan: " + e.message } }));
    return response;
  }

  async msg_delete_scan_by_id(message) {
    const profile = worker.ptk_app.settings.profile || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    if (!message?.scanId) {
      return { success: false, json: { message: "Scan identifier is required." } };
    }
    const baseUrl = this.buildPortalUrl(profile.storage_endpoint, profile);
    if (!baseUrl) {
      return { success: false, json: { message: "Storage endpoint is not configured." } };
    }
    const normalizedBase = baseUrl.replace(/\/+$/, "");
    const deleteUrl = `${normalizedBase}/${encodeURIComponent(message.scanId)}`;
    const response = await fetch(deleteUrl, {
      method: 'DELETE',
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json'
      },
      cache: 'no-cache'
    })
      .then(async (httpResponse) => {
        const json = await httpResponse.json().catch(() => null);
        if (!httpResponse.ok) {
          return { success: false, json: json || { message: "Unable to delete scan" } };
        }
        return json || { success: true };
      })
      .catch(e => ({ success: false, json: { message: "Error while deleting scan: " + e.message } }));
    return response;
  }

  buildPortalUrl(endpoint, profile) {
    profile = profile || worker.ptk_app.settings.profile || {};
    const baseUrl = (profile.base_url || profile.api_url || "").trim();
    const apiBase = (profile.api_base || "").trim();
    const resolvedEndpoint = (endpoint || "").trim();
    if (!baseUrl || !apiBase || !resolvedEndpoint) return null;
    const normalizedBase = baseUrl.replace(/\/+$/, "");
    let normalizedApiBase = apiBase.replace(/\/+$/, "");
    if (!normalizedApiBase.startsWith('/')) normalizedApiBase = '/' + normalizedApiBase;
    let normalizedEndpoint = resolvedEndpoint;
    if (!normalizedEndpoint.startsWith('/')) normalizedEndpoint = '/' + normalizedEndpoint;
    return normalizedBase + normalizedApiBase + normalizedEndpoint;
  }

  async runBackroungScan(tabId, host, policy, opts) {
    this.reset();
    this.isScanRunning = true;
    this.scanningRequest = false;
    this.activeTabId = tabId;
    const scanId = ptk_utils.UUID();
    this.scanResult = this._normalizeEnvelope(createScanResultEnvelope({
      engine: "SAST",
      scanId,
      host,
      tabId,
      startedAt: new Date().toISOString(),
      settings: policy || {}
    }));
    this.scanResult.host = host;
    this.scanResult.policy = policy;
    opts = Object.assign({}, opts, { scanId: this.scanResult.scanId });

    if (worker.isFirefox) {
      this.ensureFirefoxWorker();
    }

    if (worker.isFirefox && this.sastWorker) {
      this.sastEngine = null;
      this.sastWorker.postMessage({
        type: "start_scan",
        scanId: this.scanResult.scanId,
        policy,
        opts
      });
    } else if (!worker.isFirefox) {
      await this.ensureSastOffscreenDocument();
      try {
        await browser.runtime.sendMessage({
          channel: "ptk_bg2offscreen_sast",
          type: "start_scan",
          scanId: this.scanResult.scanId,
          policy,
          opts
        });
      } catch (err) {
        console.error("Failed to start SAST offscreen worker", err);
      }
    } else {
      this.sastEngine = new sastEngine(policy, opts);
      if (this.scanBus) this.scanBus = null;
      this.scanBus = new SastScanBus(this, this.sastEngine);
      this.scanBus.attach();
      this.sastEngine.events.subscribe('progress', (data) => {
        this.handleProgress(data);
      });
    }
    
    this.addListeners();
  }

  stopBackroungScan() {
    if (this.scanResult?.scanId) {
      if (worker.isFirefox && this.sastWorker) {
        this.sastWorker.postMessage({ type: "stop_scan", scanId: this.scanResult.scanId });
      } else if (!worker.isFirefox) {
        browser.runtime.sendMessage({
          channel: "ptk_bg2offscreen_sast",
          type: "stop_scan",
          scanId: this.scanResult.scanId
        }).catch(e => e);
      }
    }

    this.isScanRunning = false;
    this.activeTabId = null;
    if (this.scanResult) {
      const finished = new Date().toISOString();
      this.scanResult.finishedAt = finished;
    }
    this.sastEngine = null;
    this.scanBus = null;
    ptk_storage.setItem(this.storageKey, this.scanResult);
    this.removeListeners();
  }

  _addUnifiedFinding(finding, index = 0) {
    const unifiedFinding = this._composeUnifiedFinding(finding, index, this.scanResult);
    if (!unifiedFinding) return;
    this._upsertUnifiedFinding(unifiedFinding);
  }

  _composeUnifiedFinding(finding, index = 0, targetEnvelope = null) {
    if (!finding || typeof finding !== "object") return null;
    const envelopeRef = targetEnvelope && typeof targetEnvelope === "object" ? targetEnvelope : this.scanResult;
    const moduleMeta = finding.module_metadata || {};
    const ruleMeta = finding.metadata || {};
    const locationMeta = finding.location || {};
    const moduleId = moduleMeta.id || moduleMeta.moduleId || "module";
    const ruleId = ruleMeta.id || ruleMeta.rule_id || ruleMeta.name || `rule-${index}`;
    const severity = resolveEffectiveSeverity({
      override: finding.severity,
      moduleMeta,
      ruleMeta
    });
    const description = ruleMeta.description || moduleMeta.description || null;
    const recommendation = ruleMeta.recommendation || moduleMeta.recommendation || null;
    const mergedLinks = Object.assign({}, moduleMeta.links || {}, ruleMeta.links || {});
    const links = Object.keys(mergedLinks).length ? mergedLinks : null;
    const scanId = envelopeRef?.scanId || this.scanResult?.scanId || null;
    const createdAt = envelopeRef?.finishedAt || this.scanResult?.finishedAt || new Date().toISOString();
    const fingerprint = finding.fingerprint || this._buildSastFingerprintFromRaw(finding)
    const location = {
      file: locationMeta.file || finding.codeFile || finding.file || null,
      line: locationMeta.line ?? finding?.sink?.sinkLoc?.start?.line ?? finding?.source?.sourceLoc?.start?.line ?? null,
      column: locationMeta.column ?? finding?.sink?.sinkLoc?.start?.column ?? finding?.source?.sourceLoc?.start?.column ?? null,
      pageUrl: locationMeta.pageUrl || locationMeta.url || finding.pageUrl || finding.pageCanon || null
    };
    const tracePayload = Array.isArray(finding.trace)
      ? finding.trace
      : (Array.isArray(finding?.evidence?.sast?.trace) ? finding.evidence.sast.trace : []);
    return {
      id: `${scanId || 'scan'}::SAST::${moduleId}::${ruleId}::${index}`,
      engine: "SAST",
      scanId,
      moduleId,
      moduleName: moduleMeta.name || moduleId,
      ruleId,
      ruleName: ruleMeta.name || ruleId,
      vulnId: moduleMeta.vulnId || moduleMeta.category || moduleId,
      category: moduleMeta.category || ruleMeta.category || "sast",
      severity,
      owasp: moduleMeta.owasp || null,
      cwe: moduleMeta.cwe || null,
      tags: moduleMeta.tags || ruleMeta.tags || [],
      description,
      recommendation,
      links,
      location,
      createdAt,
      fingerprint,
      evidence: {
        sast: {
          codeSnippet: finding.codeSnippet || null,
          source: finding.source || null,
          sink: finding.sink || null,
          nodeType: finding.nodeType || null,
          trace: tracePayload || [],
        }
      }
    };
  }

  _registerFindingGroup(envelope, unifiedFinding) {
    if (!envelope || !unifiedFinding) return;
    const groupKeyParts = [
      "SAST",
      unifiedFinding.vulnId,
      unifiedFinding.moduleId,
      unifiedFinding.ruleId,
      unifiedFinding.location.file || "",
      unifiedFinding.location.line || ""
    ];
    const groupKey = groupKeyParts.join('@@');
    addFindingToGroup(envelope, unifiedFinding, groupKey, {
      file: unifiedFinding.location.file,
      sink: unifiedFinding.evidence?.sast?.sink?.label || null
    });
  }

  _collectLegacyItems(rawItems) {
    if (Array.isArray(rawItems)) {
      return rawItems.filter(Boolean);
    }
    if (rawItems && typeof rawItems === "object") {
      return Object.keys(rawItems)
        .sort()
        .map((key) => rawItems[key])
        .filter(Boolean);
    }
    return [];
  }

  _normalizeImportedScan(raw) {
    if (!raw || typeof raw !== "object") return null;
    const payload = raw.scanResult && typeof raw.scanResult === "object"
      ? raw.scanResult
      : raw;
    const engineValue = typeof payload.engine === "string" ? payload.engine.toUpperCase() : "";
    const typeValue = typeof payload.type === "string" ? payload.type.toLowerCase() : "";
    const isSast = !engineValue && !typeValue
      ? true
      : (engineValue === "SAST" || typeValue === "sast");
    const hasFindings = Array.isArray(payload.findings) && payload.findings.length > 0;
    const legacyItems = this._collectLegacyItems(payload.items);
    if (!isSast && !legacyItems.length) {
      return null;
    }
    if (!hasFindings && !legacyItems.length) {
      return null;
    }
    return payload;
  }

  _buildSastFingerprintFromRaw(finding) {
    if (!finding || typeof finding !== "object") return ""
    const ruleMeta = finding.metadata || {}
    const ruleId = ruleMeta.id || ruleMeta.rule_id || ruleMeta.name || ""
    const severity = ruleMeta.severity || finding.severity || ""
    const srcFile = this.canonicalFileId(finding?.source?.sourceFileFull || finding?.source?.sourceFile || "", finding?.pageUrl)
    const sinkFile = this.canonicalFileId(finding?.sink?.sinkFileFull || finding?.sink?.sinkFile || "", finding?.pageUrl)
    const srcLoc = finding?.source?.sourceLoc ? JSON.stringify(finding.source.sourceLoc) : ""
    const sinkLoc = finding?.sink?.sinkLoc ? JSON.stringify(finding.sink.sinkLoc) : ""
    return [ruleId, severity, srcFile, sinkFile, srcLoc, sinkLoc].join('@@')
  }

  _buildSastFingerprintFromUnified(finding) {
    if (finding?.fingerprint) return finding.fingerprint
    const ruleId = finding?.ruleId || ""
    const severity = finding?.severity || ""
    const file = finding?.location?.file || ""
    const line = finding?.location?.line || ""
    const column = finding?.location?.column || ""
    const pageUrl = finding?.location?.pageUrl || finding?.location?.url || ""
    return [ruleId, severity, file, line, column, pageUrl].join('@@')
  }

  _upsertUnifiedFinding(finding) {
    if (!finding) return
    if (!Array.isArray(this.scanResult.findings)) {
      this.scanResult.findings = []
    }
    const fingerprint = this._buildSastFingerprintFromUnified(finding)
    finding.fingerprint = fingerprint
    const idx = this.scanResult.findings.findIndex(item => this._buildSastFingerprintFromUnified(item) === fingerprint)
    if (idx === -1) {
      this.scanResult.findings.push(finding)
    } else {
      this.scanResult.findings[idx] = finding
    }
  }

  _rebuildGroupsFromFindings() {
    this.scanResult.groups = []
    const findings = Array.isArray(this.scanResult.findings) ? this.scanResult.findings : []
    findings.forEach(finding => this._registerFindingGroup(this.scanResult, finding))
  }

  _normalizeEnvelope(envelope) {
    const out = envelope && typeof envelope === "object" ? envelope : {};
    if (!Array.isArray(out.files)) out.files = [];
    if (!Array.isArray(out.findings)) out.findings = [];
    if (!Array.isArray(out.groups)) out.groups = [];
    out.version = out.version || "1.0";
    out.engine = out.engine || "SAST";
    out.startedAt = out.startedAt || out.date || new Date().toISOString();
    if (out.date) delete out.date;
    if (typeof out.finishedAt === "undefined") {
      out.finishedAt = out.finished || null;
    }
    if (out.finished) delete out.finished;
    if (out.tabId !== undefined) delete out.tabId;
    if (out.type !== undefined) delete out.type;
    if (!out.settings || typeof out.settings !== "object") out.settings = {};
    const statsDefaults = { findingsCount: 0, high: 0, medium: 0, low: 0, info: 0, rulesCount: 0 };
    const legacyItems = this._collectLegacyItems(envelope?.items);
    const hasFindings = Array.isArray(out.findings) && out.findings.length > 0;
    if (!hasFindings && legacyItems.length) {
      out.findings = [];
      out.groups = [];
      out.stats = Object.assign({}, statsDefaults);
      legacyItems.forEach((item, index) => {
        const unifiedFinding = this._composeUnifiedFinding(item, index, out);
        if (!unifiedFinding) return;
        out.findings.push(unifiedFinding);
      });
    } else {
      out.stats = Object.assign({}, statsDefaults, out.stats || {});
    }
    if (Array.isArray(out.findings)) {
      out.findings = out.findings.map(f => {
        if (!f) return f
        f.fingerprint = this._buildSastFingerprintFromUnified(f)
        return f
      }).filter(Boolean)
    }
    if (out.items !== undefined) delete out.items;
    this._recalculateStats(out);
    return out;
  }
}
