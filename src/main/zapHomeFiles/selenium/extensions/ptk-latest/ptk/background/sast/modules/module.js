"use strict";

import { queryTaintForRule } from "./taint_propagation.js";
import { reportTaintFinding, reportPatternFinding, exprToShortLabel } from "./reporting.js";
import { compilePattern, calleeNameFromPattern } from "./_internals.js";

/* ────────────────────────────── Helpers ────────────────────────────── */

function _memberPropName(mem) {
  if (!mem || mem.type !== "MemberExpression" || mem.computed) return null;
  if (mem.property && mem.property.type === "Identifier") return mem.property.name;
  if (mem.property && mem.property.type === "Literal") return String(mem.property.value);
  return null;
}

function _isLocationExpression(node) {
  if (!node) return false;
  if (node.type === "Identifier" && typeof node.name === "string") {
    return node.name.toLowerCase() === "location";
  }
  if (node.type === "MemberExpression") {
    if (!node.computed && node.property && node.property.type === "Identifier") {
      if (node.property.name && node.property.name.toLowerCase() === "location") return true;
    }
    return _isLocationExpression(node.object);
  }
  return false;
}

function _guardScriptText(node) {
  if (!node || node.type !== "AssignmentExpression") return false;
  const left = node.left;
  if (!left || left.type !== "MemberExpression" || left.computed) return false;
  const prop = _memberPropName(left);
  if (prop !== "textContent" && prop !== "innerHTML") return false;
  const obj = left.object;
  if (!obj) return false;
  return !!obj._ptkIsScript;
}

function _guardExcludeLocation(node) {
  if (!node) return true;
  let target = null;
  if (node.type === "AssignmentExpression") {
    target = node.left && node.left.type === "MemberExpression" ? node.left.object : null;
  } else if (node.type === "CallExpression") {
    target = node.callee && node.callee.type === "MemberExpression" ? node.callee.object : null;
  } else if (node.type === "MemberExpression") {
    target = node.object || null;
  }
  if (!target) return true;
  return !_isLocationExpression(target);
}

function _applySinkGuard(kind, node) {
  if (!kind) return true;
  if (kind === "script_text") return _guardScriptText(node);
  if (kind === "exclude_location") return _guardExcludeLocation(node);
  return true;
}

function _normalizeSpec(spec) {
  if (typeof spec === "string") return { id: spec, overlay: null };
  if (spec && typeof spec === "object" && spec.id) return { id: spec.id, overlay: spec.overlay || null };
  throw new Error("Invalid rule reference spec: " + JSON.stringify(spec));
}

function _collectPatterns(entry) {
  if (!entry || !entry.pattern) return [];
  return Array.isArray(entry.pattern) ? entry.pattern : [entry.pattern];
}

function _applyOverlayToPattern(pattern, overlay) {
  if (!overlay) return pattern;
  try {
    const merged = JSON.parse(JSON.stringify(pattern));
    if (overlay.args && merged.call && merged.call.args) {
      const args = overlay.args;
      for (const k of Object.keys(args)) {
        const idx = String(k);
        const ov = args[k];
        if (Array.isArray(merged.call.args)) {
          const i = Number(idx);
          if (!Number.isNaN(i) && merged.call.args[i]) {
            Object.assign(merged.call.args[i], ov);
          }
        } else if (merged.call.args && merged.call.args[idx]) {
          Object.assign(merged.call.args[idx], ov);
        }
      }
    }
    return merged;
  } catch {
    return pattern;
  }
}

function selectPayload(node, pattern) {
  if (!node) return null;
  if (node.type === "AssignmentExpression") return node.right || null;
  if (node.type === "CallExpression") {
    const idx = (pattern && pattern.call && typeof pattern.call.argIndex === "number") ? pattern.call.argIndex : (node.arguments.length - 1);
    return node.arguments[idx] || null;
  }
  if (node.type === "NewExpression") {
    const idx = (pattern && pattern.new && typeof pattern.new.argIndex === "number") ? pattern.new.argIndex : 0;
    return node.arguments[idx] || null;
  }
  return null;
}

function _pickFileFromNode(node, ctx) {
  return node?.sourceFile || node?.loc?.sourceFile || ctx?.codeFile || ctx?.file || null;
}

/* ────────────────────────────── Rule compilation ────────────────────────────── */

function compileSinkMatchers(sinks, catalogs) {
  return sinks.map((spec) => {
    const { id, overlay } = _normalizeSpec(spec);
    const cat = catalogs.sinks[id];
    const pats = _collectPatterns(cat).map((p) => _applyOverlayToPattern(p, overlay));
    const compiled = pats.map((p) => {
      const match = compilePattern(p);
      return { pattern: p, match };
    });
    const guardKind = (overlay && overlay.guard) || (cat && cat.guard) || null;
    return {
      id,
      match: (node, ancestors) => {
        try {
          const hit = compiled.some((c) => c.match(node, ancestors));
          if (!hit) return false;
          if (guardKind && !_applySinkGuard(guardKind, node)) return false;
          return true;
        } catch {
          return false;
        }
      },
      payload: (node) => {
        if (guardKind && !_applySinkGuard(guardKind, node)) return null;
        const hit = compiled.find((c) => { try { return c.match(node, []); } catch { return false; } });
        const pat = hit ? hit.pattern : null;
        return selectPayload(node, pat);
      }
    };
  });
}

function buildTaintSemantics(rule, catalogs) {
  const ruleMeta = rule?.metadata || {};
  const sem = {
    sourceKinds: [],
    sanitizers: { ids: new Set(), callees: new Set() },
    depthLimit: 200,
    originLimit: 5,
    taintKinds: new Set(),
  };
  const depthVal =
    typeof ruleMeta.depthLimit === "number" ? ruleMeta.depthLimit : rule?.depthLimit;
  if (typeof depthVal === "number" && depthVal > 0) {
    sem.depthLimit = depthVal;
  }
  const originVal =
    typeof ruleMeta.originLimit === "number" ? ruleMeta.originLimit : rule?.originLimit;
  if (typeof originVal === "number" && originVal > 0) {
    sem.originLimit = originVal;
  }

  const srcIds = Array.isArray(rule.sources) ? rule.sources : [];
  for (const id of srcIds) {
    const ent = catalogs.sources[id];
    if (ent && ent.origin_kind) sem.sourceKinds.push(ent.origin_kind);
  }

  const sanIds = Array.isArray(rule.sanitizers) ? rule.sanitizers : [];
  for (const sid of sanIds) {
    sem.sanitizers.ids.add(sid);
    const ent = catalogs.sanitizers[sid];
    if (!ent) continue;
    for (const p of _collectPatterns(ent)) {
      const name = calleeNameFromPattern(p.call || p);
      if (name) sem.sanitizers.callees.add(name);
    }
  }
  const kindIds = Array.isArray(rule.taint_kinds) ? rule.taint_kinds : [];
  for (const kid of kindIds) {
    if (typeof kid === "string" && kid.trim()) {
      sem.taintKinds.add(kid.trim());
    }
  }
  return sem;
}

function compilePatternMatchers(rule, compileFn) {
  const typeOf = (pat) => pat && typeof pat === "object" ? Object.keys(pat)[0] : null;
  const out = [];
  if (!Array.isArray(rule.matches) || !compileFn) return out;
  for (const pat of rule.matches) {
    const nodeType = typeOf(pat);
    try {
      const fn = compileFn(pat);
      if (typeof fn === "function") {
        out.push({
          id: "pattern",
          nodeType,
          match: (node, ancestors) => {
            if (nodeType === "call" && node.type !== "CallExpression") return false;
            if (nodeType === "assignment" && node.type !== "AssignmentExpression") return false;
            if (nodeType === "member" && node.type !== "MemberExpression") return false;
            if (nodeType === "new" && node.type !== "NewExpression") return false;
            return !!fn(node, ancestors);
          }
        });
      }
    } catch { /* ignore bad matcher */ }
  }
  return out;
}

/* ────────────────────────────── Module class ────────────────────────────── */

export class ptk_sast_module {
  constructor(moduleJson, opts = {}) {
    if (!moduleJson || typeof moduleJson !== "object") throw new Error("moduleJson required");
    this.raw = moduleJson;
    this.id = moduleJson.id;
    this.module_metadata = Object.assign({}, moduleJson.metadata, {
      id: this.id,
      name: moduleJson.name,
      vulnId: moduleJson.vulnId || moduleJson.metadata?.vulnId || this.id
    });
    this.maxFindings = (moduleJson.metadata && moduleJson.metadata.maxFindings != null)
      ? moduleJson.metadata.maxFindings
      : moduleJson.maxFindings;

    this._catalogs = {
      sources: opts.sources || {},
      sinks: opts.sinks || {},
      sanitizers: opts.sanitizers || {},
      propagators: opts.propagators || {},
    };

    this.rules = [];
    this._taintDedup = new Map();
    this._compileAllRules(moduleJson.rules || []);
  }

  _compileRule(rule) {
    const mode = rule.mode || rule.type || "pattern";
    const sinkSpecs = Array.isArray(rule.sinks) ? rule.sinks : [];
    const metadata = Object.assign({}, rule.metadata, { id: rule.id, rule_id: rule.id, name: rule.name, mode });
    if (metadata.severity == null && rule.severity != null) {
      metadata.severity = rule.severity;
    }
    const pack = {
      metadata,
      type: rule.type || "static",
      extras: rule.extras || {},
      sinks: [],
      matches: [],
      taintSemantics: null,
    };

    if (mode === "pattern") {
      pack.matches = compilePatternMatchers(rule, compilePattern);
    } else if (mode === "taint") {
      pack.sinks = compileSinkMatchers(sinkSpecs, this._catalogs);
      pack.taintSemantics = buildTaintSemantics(rule, this._catalogs);
      pack.sourceIds = Array.isArray(rule.sources) ? [...rule.sources] : [];
      pack.taintKinds = Array.isArray(rule.taint_kinds)
        ? rule.taint_kinds.filter((k) => typeof k === "string" && k.trim())
        : [];
    } else {
      pack.sourceIds = [];
      pack.taintKinds = [];
    }
    return pack;
  }

  _compileAllRules(rules) {
    this.rules = [];
    for (const r of rules) {
      const pack = this._compileRule(r);
      if (pack) this.rules.push(pack);
    }
  }

  _buildTraceFromPath(hit, graph, codeByFile, ctx) {
    const nodes = [];
    for (const key of hit.pathKeys || []) {
      const [idStr] = String(key || "").split("|");
      const id = Number(idStr);
      if (!Number.isFinite(id)) continue;
      const node = graph.astNodeForId(id);
      if (node && typeof node.type === "string") nodes.push(node);
    }
    if (!nodes.length && hit.originNode) nodes.push(hit.originNode);
    if (hit.sinkNode && (!nodes.length || nodes[nodes.length - 1] !== hit.sinkNode)) nodes.push(hit.sinkNode);

    const trace = [];
    const codeByFiles = ctx.codeByFile || {};
    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i];
      const loc = node?.loc?.start;
      const type = node?.type;
      const label = exprToShortLabel(node, { code: codeByFiles[_pickFileFromNode(node, ctx)] });
      const prev = trace[trace.length - 1];
      const sameLoc = prev && prev.node?.type === type &&
        prev.node?.loc?.start?.line === loc?.line &&
        prev.node?.loc?.start?.column === loc?.column;
      const sameLabel = prev && prev.label === label && prev.node?.type === type;
      if (sameLoc || sameLabel) {
        continue;
      }
      trace.push({
        kind: i === 0 ? "source" : (i === nodes.length - 1 ? "sink" : "propagation"),
        node,
        label
      });
    }
    return trace;
  }

  _emitPatternFinding(pack, node, ctx) {
    const mode = "pattern";
    const context = { ...ctx, module_metadata: this.module_metadata, metadata: pack.metadata, codeFile: ctx.codeFile || ctx.file, mode };
    const code = ctx.codeByFile?.[ctx.codeFile || ctx.file];
    const extras = { mode, sinkExact: exprToShortLabel(node, { code }), module_metadata: this.module_metadata };
    return reportPatternFinding({ rule: pack, context, matchNode: node, extras });
  }

  _emitTaintFinding(pack, node, ctx, hit, globalTaintCtx, trace) {
    const mode = "taint";
    const context = { ...ctx, module_metadata: this.module_metadata, metadata: pack.metadata, codeFile: ctx.codeFile || ctx.file, mode };
    const code = ctx.codeByFile?.[ctx.codeFile || ctx.file];
    const extras = {
      mode,
      sinkExact: exprToShortLabel(node, { code }),
      sourceExact: hit.origin ? hit.origin.label : undefined,
      module_metadata: this.module_metadata,
      graph: globalTaintCtx?.graph || null,
      pathKeys: hit.pathKeys || []
    };
    return reportTaintFinding({
      rule: pack,
      context,
      sourceNode: hit.originNode || hit.origin?.node || trace?.[0]?.node || node,
      sinkNode: node,
      taintTrace: trace,
      extras
    });
  }

  _dedupKey(pack, origin, sinkNode) {
    const sinkLoc = sinkNode?.loc?.start;
    const sinkFile = _pickFileFromNode(sinkNode) || "";
    const label = exprToShortLabel(sinkNode, {});
    const normOrigin = origin?.label || origin?.kind || "";
    const originFile = origin?.node?.sourceFileFull || origin?.node?.sourceFile || "";
    const originLoc = origin?.node?.loc?.start;
    return [
      pack?.metadata?.id || "",
      normOrigin,
      originFile,
      originLoc ? `${originLoc.line ?? ""}:${originLoc.column ?? ""}` : "",
      sinkFile,
      sinkLoc ? `${sinkLoc.line}:${sinkLoc.column}` : "",
      label || ""
    ].join("|");
  }

  removeDuplicates(issues) {
    const seen = new Set();
    return issues.filter((i) => {
      const loc = i?.sink?.sinkLoc?.start;
      const srcLoc = i.source?.sourceLoc?.start || i.source?.sourceLoc;
      const key = [
        i.metadata?.rule_id || i.metadata?.id || "",
        i.source?.label || i.source?.sourceName || "",
        i.source?.sourceFileFull || "",
        srcLoc ? srcLoc.line ?? "" : "",
        srcLoc ? srcLoc.column ?? "" : "",
        loc ? `${loc.line ?? ""}:${loc.column ?? ""}` : "",
        i.sink?.sinkFileFull || "",
        i.sink?.sinkName || ""
      ].join("|");
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  runRules(masterAST, ctx, ancestorWalk, options = {}) {
    const findings = [];
    if (!masterAST || typeof ancestorWalk !== "function") return findings;

    const policy = options.policy || 0;
    const globalTaintCtx = options.globalTaintCtx || null;
    this._taintDedup.clear();

    const packs = (this.rules || []).filter(Boolean);
    if (!packs.length) return findings;

    const self = this;
    const processNode = (node, ancestors) => {
      for (const pack of packs) {
        if (pack.metadata.mode === "pattern" && policy === 0) {
          for (const m of (pack.matches || [])) {
            if (m.match(node, ancestors)) {
              const finding = self._emitPatternFinding(pack, node, ctx);
              if (finding) findings.push(finding);
              if (findings.length >= (self.maxFindings || Infinity)) return;
            }
          }
        } else if (pack.metadata.mode === "taint") {
          if (!globalTaintCtx || !pack.sinks || !pack.sinks.length) continue;
          for (const s of pack.sinks) {
            if (!s.match(node, ancestors)) continue;
            const payload = s.payload(node);
            if (!payload) continue;
            const hits = queryTaintForRule(globalTaintCtx, pack, payload, { sinkNode: node }) || [];
            for (const hit of hits) {
              const trace = this._buildTraceFromPath(hit, globalTaintCtx.graph, ctx.codeByFile || {}, ctx);
              const finding = this._emitTaintFinding(pack, node, ctx, hit, globalTaintCtx, trace);
              if (!finding) continue;
              const key = this._dedupKey(pack, hit.origin, node);
              if (this._taintDedup.has(key)) {
                console.debug("[TAINT-DEDUP] skipping duplicate", key);
                continue;
              }
              this._taintDedup.set(key, true);
              findings.push(finding);
              if (findings.length >= (self.maxFindings || Infinity)) return;
            }
          }
        }
      }
    };

    const visitors = {
      CallExpression: processNode,
      MemberExpression: processNode,
      AssignmentExpression: processNode,
      NewExpression: processNode,
    };

    try {
      ancestorWalk(masterAST, visitors);
    } catch (err) {
      console.warn("[SAST] visitor error swallowed:", err && err.message);
    }

    return this.removeDuplicates(findings);
  }
}
