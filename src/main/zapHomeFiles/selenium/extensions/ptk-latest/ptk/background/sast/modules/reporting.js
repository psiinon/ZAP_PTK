"use strict";

// reporting.js — finding builders for pattern and taint rules

/* ───────────────────────────────────── Utilities ───────────────────────────────────── */

export function exprToShortLabel(node, { code, max = 120 } = {}) {
  if (!node) return "";
  try {
    switch (node.type) {
      case "Literal":
        return typeof node.value === "string"
          ? JSON.stringify(node.value).slice(0, max)
          : String(node.value);
      case "Identifier":
        return node.name;
      case "MemberExpression": {
        const parts = [];
        let cur = node;
        while (cur && cur.type === "MemberExpression") {
          if (cur.property) {
            if (cur.property.type === "Identifier") parts.unshift(cur.property.name);
            else if (cur.property.type === "Literal") parts.unshift(String(cur.property.value));
          }
          cur = cur.object;
        }
        if (cur) {
          if (cur.type === "Identifier") parts.unshift(cur.name);
          else if (cur.type === "ThisExpression") parts.unshift("this");
        }
        return parts.join(".");
      }
      case "CallExpression":
        return exprToShortLabel(node.callee, { code, max });
      case "AssignmentExpression":
        return exprToShortLabel(node.left, { code, max });
      default:
        return (code && node.loc)
          ? getCodeSnippet(code, node.loc, { maxContextLines: 0 })
          : (node.type || "Node");
    }
  } catch {
    return "";
  }
}

function _nodeFileDisplay(node) {
  if (!node) return null;
  return node.sourceFileFull || node.sourceFile || (node.loc && node.loc.sourceFile) || null;
}

function extractPath(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") {
    const parts = [];
    let cur = node;
    while (cur && cur.type === "MemberExpression") {
      if (cur.property) {
        if (cur.property.type === "Identifier") parts.unshift(cur.property.name);
        else if (cur.property.type === "Literal") parts.unshift(String(cur.property.value));
      }
      cur = cur.object;
    }
    if (cur) {
      if (cur.type === "Identifier") parts.unshift(cur.name);
      else if (cur.type === "ThisExpression") parts.unshift("this");
    }
    return parts.join(".");
  }
  return "";
}

function _nodeType(node) {
  return node?.type || "Node";
}

// Compact snippet extractor (consistent with sastEngine helpers)
export function getCodeSnippet(code, loc, opts = {}) {
  if (!code || !loc || !loc.start || !loc.end) return "";
  const cfg = {
    maxContextLines: 2,
    maxCharsPerLine: 220,
    ...opts,
  };
  const lines = String(code).split(/\r?\n/);
  const sLine = Math.max(1, loc.start.line | 0) - 1;
  const eLine = Math.max(1, loc.end.line | 0) - 1;
  const start = Math.max(0, sLine - cfg.maxContextLines);
  const end = Math.min(lines.length - 1, eLine + cfg.maxContextLines);

  const windowLines = lines.slice(start, end + 1).map((ln) => {
    let out = String(ln);
    if (cfg.maxCharsPerLine && out.length > cfg.maxCharsPerLine) {
      const colStart = Math.max(0, (loc.start.column | 0) - Math.floor(cfg.maxCharsPerLine / 2));
      const colEnd = colStart + cfg.maxCharsPerLine;
      out = out.slice(colStart, colEnd) + "…";
    }
    return out.replace(/\s+$/u, "");
  });

  while (windowLines.length && !windowLines[0].trim()) windowLines.shift();
  while (windowLines.length && !windowLines[windowLines.length - 1].trim()) windowLines.pop();

  const indents = windowLines
    .filter((line) => /\S/.test(line))
    .map((line) => {
      const match = line.match(/^([ \t]*)/);
      return match ? match[0].replace(/\t/g, "  ").length : 0;
    });
  const baseIndent = indents.length ? Math.min(...indents) : 0;
  const snippet = windowLines.map((line) => {
    if (!baseIndent) return line;
    let idx = 0;
    let removed = 0;
    while (idx < line.length && removed < baseIndent) {
      const ch = line[idx];
      if (ch === "\t") removed += 2;
      else if (ch === " ") removed += 1;
      else break;
      idx += 1;
    }
    return line.slice(idx);
  }).join("\n");

  return snippet.trimEnd();
}

function resolveCodeForFile(codeByFile, key, fallbackFile) {
  if (!codeByFile) return "";
  if (key && codeByFile[key]) return codeByFile[key];
  if (key) {
    const noQ = String(key).split(/[?#]/)[0];
    const base = noQ.split("/").pop();
    if (codeByFile[noQ]) return codeByFile[noQ];
    if (codeByFile[base]) return codeByFile[base];
  }
  if (fallbackFile && codeByFile[fallbackFile]) return codeByFile[fallbackFile];
  const first = Object.keys(codeByFile)[0];
  return first ? codeByFile[first] : "";
}

function _pickSinkLabel({ sinkNode, code }) {
  if (!sinkNode) return "";
  if (sinkNode.type === "CallExpression") {
    const cal = sinkNode.callee;
    const label = extractPath(cal);
    return label || exprToShortLabel(cal, { code });
  }
  if (sinkNode.type === "AssignmentExpression") {
    return extractPath(sinkNode.left) || exprToShortLabel(sinkNode.left, { code });
  }
  return exprToShortLabel(sinkNode, { code });
}

function _pickSourceLabel({ sourceNode, sinkNode, code }) {
  if (sourceNode) return exprToShortLabel(sourceNode, { code });
  if (sinkNode?.type === "AssignmentExpression") return exprToShortLabel(sinkNode.right, { code });
  return exprToShortLabel(sinkNode, { code });
}

/* ───────────────────────────────────── Pattern findings ───────────────────────────────────── */

export function reportPatternFinding({ rule, context, matchNode, valueNode, extras = {} }) {
  const codeByFile = (context && context.codeByFile) || {};
  const fallbackFile = context?.codeFile || Object.keys(codeByFile)[0] || "(inline-script)";
  const preferredSourceFile = _nodeFileDisplay(valueNode || matchNode);
  const preferredSinkFile = _nodeFileDisplay(matchNode);
  const sourceFileKey = preferredSourceFile || fallbackFile;
  const sinkFileKey = preferredSinkFile || sourceFileKey;
  const sourceCode = resolveCodeForFile(codeByFile, sourceFileKey, fallbackFile);
  const sinkCode = resolveCodeForFile(codeByFile, sinkFileKey, fallbackFile);

  const sinkLabel = _pickSinkLabel({ sinkNode: matchNode, code: sinkCode });
  const sourceLoc = (valueNode || matchNode)?.loc;
  const sinkLoc = (matchNode?.type === "AssignmentExpression" ? matchNode.left : matchNode)?.loc;

  let sourceSnippet = sourceLoc ? getCodeSnippet(sourceCode, sourceLoc) : "";
  if (!sourceSnippet) {
    sourceSnippet = exprToShortLabel(valueNode || matchNode, { code: sourceCode }) || "";
  }
  let sinkSnippet = sinkLoc ? getCodeSnippet(sinkCode, sinkLoc) : "";
  if (!sinkSnippet) {
    sinkSnippet = exprToShortLabel(matchNode, { code: sinkCode }) || "";
  }

  const sourceInfo = { codeFile: sourceFileKey, snippet: sourceSnippet };
  const sinkInfo = { codeFile: sinkFileKey, snippet: sinkSnippet };

  const out = {
    async: false,
    codeFile: sourceFileKey,
    codeSnippet: `Source context:\n${sourceInfo.snippet}\n\nSink context:\n${sinkInfo.snippet}`,
    file: "",
    metadata: rule.metadata,
    module_metadata: extras.module_metadata || {},
    nodeType: _nodeType(matchNode),
    sink: {
      kind: matchNode?.type === "CallExpression" ? "call" : (matchNode?.type === "AssignmentExpression" ? "assign" : "node"),
      label: sinkLabel,
      path: [],
      sinkFile: sinkFileKey,
      sinkFileFull: sinkFileKey,
      sinkLoc,
      sinkName: sinkLabel,
      sinkSnippet: sinkInfo.snippet,
    },
    source: {
      label: exprToShortLabel(valueNode || matchNode, { code: sourceCode }),
      path: null,
      sourceFile: sourceFileKey,
      sourceFileFull: sourceFileKey,
      sourceLoc,
      sourceName: exprToShortLabel(valueNode || matchNode, { code: sourceCode }),
      sourceSnippet: sourceInfo.snippet,
    },
    success: true,
    type: _nodeType(matchNode),
  };

  if (valueNode) out.valueExpr = exprToShortLabel(valueNode, { code: sourceCode });
  return out;
}

/* ───────────────────────────────────── Taint findings ───────────────────────────────────── */

function traceFromPathKeys(pathKeys, graph) {
  if (!Array.isArray(pathKeys) || !graph) return [];
  const steps = [];
  for (let i = 0; i < pathKeys.length; i++) {
    const key = pathKeys[i];
    const [nodeIdStr] = String(key || "").split("|");
    const id = Number(nodeIdStr);
    if (!Number.isFinite(id)) continue;
    const node = graph.astNodeForId(id);
    if (!node) continue;
    const kind = i === 0 ? "source" : (i === pathKeys.length - 1 ? "sink" : "propagation");
    steps.push({ kind, node });
  }
  return steps;
}

export function reportTaintFinding({ rule, context, sourceNode, sinkNode, taintTrace, extras = {} }) {
  const graph = extras.graph || null;
  if ((!taintTrace || !taintTrace.length) && Array.isArray(extras.pathKeys) && graph) {
    taintTrace = traceFromPathKeys(extras.pathKeys, graph);
    if (!sourceNode && taintTrace.length) sourceNode = taintTrace[0].node;
  }

  const codeByFile = (context && context.codeByFile) || {};
  const sinkKey = (sinkNode && sinkNode.sourceFile) || context?.codeFile || Object.keys(codeByFile)[0] || "(inline-script)";
  const sourceKey = (sourceNode && sourceNode.sourceFile) || sinkKey;

  const sinkCode = resolveCodeForFile(codeByFile, sinkKey, context?.codeFile);
  const sourceCode = resolveCodeForFile(codeByFile, sourceKey, context?.codeFile);

  const isCall = sinkNode?.type === "CallExpression";
  const target = isCall ? sinkNode.callee : (sinkNode?.left || sinkNode);
  const sinkPath = extractPath(target);

  const sinkLabel = _pickSinkLabel({ sinkNode, code: sinkCode });
  const sourceLabel = _pickSourceLabel({ sourceNode, sinkNode, code: sourceCode });

  const sourceLoc = (sourceNode || sinkNode)?.loc;
  const sinkLoc = (sinkNode?.type === "AssignmentExpression" ? sinkNode.left : sinkNode)?.loc;

  let sourceSnippet = sourceLoc ? getCodeSnippet(sourceCode, sourceLoc) : "";
  if (!sourceSnippet) {
    sourceSnippet = exprToShortLabel(sourceNode || sinkNode, { code: sourceCode }) || "";
  }
  let sinkSnippet = sinkLoc ? getCodeSnippet(sinkCode, sinkLoc) : "";
  if (!sinkSnippet) {
    sinkSnippet = exprToShortLabel(sinkNode, { code: sinkCode }) || "";
  }

  const sourceInfo = { codeFile: sourceKey, snippet: sourceSnippet };
  const sinkInfo = { codeFile: sinkKey, snippet: sinkSnippet };

  return {
    async: false,
    codeFile: sinkKey,
    codeSnippet: `Source context:\n${sourceInfo.snippet}\n\nSink context:\n${sinkInfo.snippet}`,
    file: "",
    metadata: rule.metadata,
    module_metadata: extras.module_metadata || {},
    nodeType: _nodeType(sinkNode),
    sink: {
      kind: isCall ? "call" : (sinkNode?.type === "AssignmentExpression" ? "assign" : "node"),
      label: sinkLabel,
      path: sinkPath ? sinkPath.split(".") : [],
      sinkFile: sinkKey,
      sinkFileFull: sinkKey,
      sinkLoc,
      sinkName: sinkLabel,
      sinkSnippet: sinkInfo.snippet,
    },
    source: {
      label: sourceLabel,
      path: null,
      sourceFile: sourceKey,
      sourceFileFull: sourceKey,
      sourceLoc,
      sourceName: sourceLabel,
      sourceSnippet: sourceInfo.snippet,
    },
    success: true,
    type: _nodeType(sinkNode),
    trace: Array.isArray(taintTrace) ? taintTrace : [],
  };
}

