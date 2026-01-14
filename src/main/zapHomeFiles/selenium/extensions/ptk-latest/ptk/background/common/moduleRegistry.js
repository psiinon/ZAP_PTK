const runtimeAPI =
  typeof browser !== "undefined"
    ? browser
    : typeof chrome !== "undefined"
      ? chrome
      : null

const LOCAL_RULEPACK_PATHS = {
  DAST: "ptk/background/dast/modules/modules.json",
  SAST: "ptk/background/sast/modules/modules.json",
  IAST: "ptk/background/iast/modules/modules.json"
}

const LOCAL_RULEPACK_VARIANTS = {
  DAST: {
    cve: "ptk/background/dast/modules/modules_cve.json"
  }
}

async function fetchRulepackFromPath(path, expectedEngine) {
  if (!path) {
    throw new Error(`[PTK] Missing rulepack path for ${expectedEngine || 'unknown'} engine`)
  }
  if (!runtimeAPI?.runtime?.getURL) {
    throw new Error("[PTK] runtime.getURL unavailable to load rulepack")
  }

  const url = runtimeAPI.runtime.getURL(path)
  const resp = await fetch(url)
  if (!resp.ok) {
    throw new Error(
      `[PTK] Failed to load local rulepack for ${expectedEngine || 'engine'} from ${path}: ${resp.status}`
    )
  }

  const rulepack = await resp.json()
  if (!rulepack || typeof rulepack !== "object") {
    throw new Error(`[PTK] Local rulepack for ${expectedEngine || 'engine'} is not an object`)
  }

  if (expectedEngine && rulepack.engine && rulepack.engine !== expectedEngine) {
    console.warn("[PTK] Local rulepack engine mismatch", {
      expected: expectedEngine,
      actual: rulepack.engine
    })
  }

  if (rulepack.schema && rulepack.schema !== "ptk-modules-v1") {
    console.warn("[PTK] Local rulepack schema mismatch", {
      expected: "ptk-modules-v1",
      actual: rulepack.schema
    })
  }

  if (!Array.isArray(rulepack.modules)) {
    console.warn("[PTK] Local rulepack modules is not an array for", expectedEngine)
  }

  return rulepack
}

/**
 * Load a rulepack from the packaged extension files.
 * @param {"DAST"|"SAST"|"IAST"} engine
 * @returns {Promise<object>}
 */
export async function loadLocalRulepack(engine) {
  const path = LOCAL_RULEPACK_PATHS[engine]
  if (!path) {
    throw new Error(`[PTK] Unsupported engine for local rulepack: ${engine}`)
  }
  return fetchRulepackFromPath(path, engine)
}

async function loadLocalRulepackVariant(engine, variant) {
  const variants = LOCAL_RULEPACK_VARIANTS[engine]
  const path = variants?.[variant]
  if (!path) {
    throw new Error(`[PTK] Unsupported rulepack variant "${variant}" for engine ${engine}`)
  }
  return fetchRulepackFromPath(path, engine)
}

/**
 * Placeholder for future PTK Portal loaded rulepacks.
 * @param {"DAST"|"SAST"|"IAST"} engine
 * @param {object} [opts]
 * @returns {Promise<object|null>}
 */
export async function loadPortalRulepack(engine, opts = {}) {
  // FUTURE: call PTK Portal API once available.
  return null
}

/**
 * Unified rulepack loader that can later prefer Portal rulepacks.
 * @param {"DAST"|"SAST"|"IAST"} engine
 * @param {object} [opts]
 * @returns {Promise<object>}
 */
export async function loadRulepack(engine, opts = {}) {
  // FUTURE: check opts.preferPortal and call loadPortalRulepack first.
  if (opts?.variant) {
    return loadLocalRulepackVariant(engine, opts.variant)
  }
  return loadLocalRulepack(engine)
}
