import { ptk_module } from "../dast/modules/module.js"
import { loadRulepack } from "../common/moduleRegistry.js"
import { normalizeRulepack, resolveEffectiveSeverity } from "../common/severity_utils.js"
import { buildPassiveOriginal } from "./representativeResponseSelector.js"

let headerModulesPromise = null

async function ensureHeaderModules() {
    if (headerModulesPromise) {
        return headerModulesPromise
    }

    headerModulesPromise = loadRulepack("DAST")
        .then((rulepack) => {
            normalizeRulepack(rulepack, { engine: "DAST", childKey: "attacks" })
            const modules = Array.isArray(rulepack?.modules) ? rulepack.modules : []
            return modules
                .filter(
                    (module) =>
                        module &&
                        module.type === "passive" &&
                        (module.id === "headers" ||
                            module.metadata?.category === "security_headers")
                )
                .map((module) => new ptk_module(module))
        })
        .catch((err) => {
            console.warn("[PTK][HeaderAnalysis] Failed to load DAST header modules", err)
            return []
        })

    return headerModulesPromise
}

function describeFinding(finding) {
    const descriptionParts = []
    if (finding.description) {
        descriptionParts.push(finding.description)
    }
    if (finding.proof) {
        descriptionParts.push(`<strong>Evidence:</strong> ${finding.proof}`)
    }
    if (finding.recommendation) {
        descriptionParts.push(finding.recommendation)
    }
    if (finding.urls?.length) {
        const urlLines = finding.urls.slice(0, 3).map((url) => `<div>${url}</div>`).join("")
        descriptionParts.push(`<div><strong>URLs:</strong>${urlLines}</div>`)
    }
    return descriptionParts.join("<br/>")
}

export async function evaluatePassiveHeaders(responses = []) {
    const modules = await ensureHeaderModules()
    if (!modules.length || !Array.isArray(responses) || !responses.length) {
        return { tableRows: [], rawFindings: [] }
    }

    const findings = []
    const dedupe = new Set()

    for (const response of responses) {
        const original = buildPassiveOriginal(response)
        if (!original) continue
        const originKey = (() => {
            try {
                return new URL(response.url || "").origin
            } catch (_) {
                return response.url || ""
            }
        })()

        for (const module of modules) {
            if (!Array.isArray(module.attacks)) continue

            for (const attackDef of module.attacks) {
                const attack = module.prepareAttack(attackDef)
                const attackMeta = { metadata: Object.assign({}, attack, module.metadata) }

                if (attack.condition && !module.validateAttackConditions(attackMeta, original)) {
                    continue
                }

                const result = module.validateAttack(attackMeta, original)
                if (!result?.success) {
                    continue
                }

                const key = `${module.id || module.name}|${attack.id || attack.name}|${originKey}`
                if (dedupe.has(key)) {
                    continue
                }
                dedupe.add(key)

                const severity = resolveEffectiveSeverity({
                    moduleMeta: module.metadata || {},
                    attackMeta: attack.metadata || {},
                })

                const finding = {
                    moduleId: module.id || module.name || "headers",
                    attackId: attack.id || attack.name || "passive-check",
                    title: attack.name || attack.id || "Header finding",
                    severity,
                    description: attack.metadata?.description || module.metadata?.description || "",
                    recommendation: attack.metadata?.recommendation || module.metadata?.recommendation || "",
                    links: module.metadata?.links || attack.metadata?.links || {},
                    proof: result.proof || "",
                    urls: [response.url].filter(Boolean),
                }

                findings.push(finding)
            }
        }
    }

    const rowMap = new Map()

    findings.forEach((finding) => {
        const key = `${finding.moduleId || finding.title}|${finding.attackId || finding.title}`
        const entry = rowMap.get(key)
        const description = describeFinding(finding)
        if (entry) {
            entry.descriptions.push(description)
            return
        }
        rowMap.set(key, {
            title: finding.title,
            descriptions: [description],
        })
    })

    const tableRows = Array.from(rowMap.values()).map((entry) => [
        entry.title,
        entry.descriptions.join('<hr/>'),
    ])

    return { tableRows, rawFindings: findings }
}
