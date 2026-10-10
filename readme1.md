# CSB-03: Supply-Chain Vulnerability Propagation Graph

## Executive summary

**Problem.** A software vulnerability is not just a property of one package. It propagates through direct and transitive dependency edges, build systems, artifacts, deployments, runtime services, and supplier/customer trust relationships. CISA and NIST describe the supply-chain compromise pattern as a supplier or build compromise that inserts malicious code before delivery to downstream customers; the same graph also has to represent ordinary vulnerable components and incomplete inventory. [1][2]

**Why now.** The ecosystem has moved from static component inventories toward machine-readable SBOMs, VEX status assertions, vulnerability feeds, and graph queries, but the evidence layers remain fragmented. NIST says SBOMs complement—not replace—vulnerability management and supplier-risk controls, and warns that a retroactively generated SBOM may miss build-time dependencies. [2] OSV reported 30 supported ecosystems in its 2024 review, with API traffic peaking above 900 queries/second in October 2024; these are project-maintained coverage and usage measures, not a census of all vulnerabilities or projects. [7]

**MVP recommendation.** Build **PatchOrder**: a local, deterministic decision engine that ingests a resolved dependency graph, joins OSV with CVE aliases, CISA KEV, FIRST EPSS and CVSS where available, adds explicit project context, and ranks the **next patch by weighted risk removed per estimated change cost**. It should show every dependency path and every source behind the rank. This is deliberately a decision product, not another scanner and not an exploitability prover.

**Crisp USP.** > **“PatchOrder tells a small team which dependency patch to do next, how much propagated risk it removes, and why—with every claim and uncertainty auditable.”**

---

## 1. Problem definition: vulnerability propagation, not alert collection

### 1.1 The problem

Software supply-chain risk is exposure created by the software lifecycle and its trust relationships. An attacker can compromise a supplier, build environment, distribution channel, or update so downstream customers receive code that compromises systems or data. CISA/NIST use the SolarWinds pattern—vendor-network intrusion followed by malicious code insertion before delivery—as a canonical example and frame mitigation as coordinated supplier/customer risk management using C-SCRM and SSDF. [1]

For the narrower CSB-03 problem, **propagation** means traversing a graph from a vulnerable or compromised component to the projects, artifacts, services, data, and customers that depend on it:

- **Direct dependency:** explicitly selected by a project.
- **Transitive dependency:** pulled in by another dependency.
- **Build-time dependency:** present while constructing an artifact, even if not obvious in a runtime manifest.
- **Runtime dependency:** available to or loaded by the deployed service.
- **Operational blast radius:** affected assets, environments, secrets, data stores, or downstream customers connected to the artifact or supplier.

The scale is easy to underestimate. OpenSSF cites an illustrative 2020 GitHub observation of an average **683 indirect dependencies for 10 direct JavaScript dependencies**, while its Next.js test expanded 12 direct dependencies to 345 installed packages; these are ecosystem observations, not representative global prevalence estimates. [5]

### 1.2 Why existing tools can miss propagation

Existing tools are useful but commonly optimize for a narrower question: “Which dependency in this repository matches an advisory?” Propagation requires additional joins and provenance. The documented failure modes are:

1. **Manifest versus resolved reality.** A `package.json`, `requirements.txt`, or `pom.xml` range is not necessarily the installed version. Lockfiles provide the most reliable exact direct/transitive versions, while build-time resolution may require a resolver-generated submission. [26]
2. **Incomplete lifecycle coverage.** NIST warns that retroactive SBOM generation can miss build-time dependencies; SBOM capability and adoption were still described as nascent for some federal acquirers. [2]
3. **Direct-only mental models.** Vulnerable nested packages can affect a product owner that never selected the package directly. OpenSSF’s dependency expansion illustrates why direct-only views are inadequate. [5]
4. **Identity and feed fragmentation.** OSV, CVE/NVD, KEV, EPSS, CVSS, VEX, CycloneDX, and SPDX answer different questions and have different identifiers, update behavior, and confidence. OSV records can contain aliases and upstream relationships; those must not be collapsed indiscriminately. [11]
5. **No product/runtime context.** A component in a development-only tree is not the same operational decision as the same component in an internet-facing production service. NIST-hosted SBOM lifecycle guidance distinguishes source, build, analyzed, deployed, and runtime SBOMs; runtime inventories can include dynamically loaded components and external call-outs. [69]
6. **Reachability is not exploitability.** Static reachability can provide code-path evidence, but documented analyses have false positives/negatives and language/build limitations. “No path found” is not proof of unreachability, and unsupported analysis should remain an explicit uncertain state. [29][79]
7. **Alert overload and duplicate work.** NIST warns against too many false positives; vendor survey evidence reports duplicate alerts, manual remediation effort, and false-positive concerns, but those survey figures are not independently audited prevalence. [65][66][67]
8. **Cross-project blast radius is underexposed.** Native repository scanners, CI scanners, and artifact scanners can identify findings, while graph layers can query transitive paths. The team still needs a unified answer to: “Which patch clears the most weighted exposure across all affected roots, and what evidence supports that order?” [25][34][41]

**Design boundary:** PatchOrder estimates **potential impact and priority** from graph exposure, vulnerability intelligence, and declared context. It must never claim that a finding is exploitable merely because a package is present, nor claim safety because a static analyzer found no path.

---

## 2. Current ecosystem and data standards

### 2.1 Inventory and relationship standards

| Standard / system | What it contributes | MVP treatment |
|---|---|---|
| **SBOM** | A formal, machine-readable record of components and supply-chain relationships; CISA describes it as an ingredients list. [2][3] | Accept CycloneDX or SPDX later; normalize every imported component to PURL, version, source/integrity, scope, and provenance. |
| **CycloneDX** | Full-stack BOM model covering components, services, dependencies/graphs, vulnerabilities, provenance/formulation, annotations, declarations, citations, and extensions; the cited overview lists JSON/XML/Protobuf serializations and version 1.7. [21] | Stretch input/output format; preserve original document and spec version. |
| **SPDX** | ISO/IEC 5962:2021 open standard; current cited specification page lists version 3.0 and security profiles for CVSS, EPSS, exploit catalogs, SSVC, and VEX. [22][23] | Stretch input; preserve profile and document provenance. |
| **Package URL (PURL)** | Canonical cross-ecosystem package identity using type, namespace, name, version, and optional qualifiers. [78] | Primary component key; never match by bare package name. |
| **VEX** | Product/version-specific assertion that a vulnerability is **NOT AFFECTED, AFFECTED, FIXED, or UNDER INVESTIGATION**. CISA says AFFECTED requires an action statement and NOT AFFECTED requires an impact statement. [24] | Store status, rationale, action/impact, product version, issuer, timestamp. Treat it as contextual evidence, not a replacement for SBOM or vulnerability feeds. |

NIST recommends machine-readable vulnerability advisories such as VEX and integrating SBOMs with vulnerability databases. [4] The 2025 CISA SBOM Minimum Elements draft sought to update the 2021 NTIA baseline for current transparency and scalable processing; the cited draft’s comment window ended 3 October 2025. [6]

### 2.2 Vulnerability and exploitation intelligence

| Source | Answers | Important limitation / implementation rule |
|---|---|---|
| **OSV** | Does this ecosystem/package/version or commit match an open-source advisory? OSV supports package-version and commit queries and aggregates databases adopting its format. [10][12] | Coverage and record quality vary by ecosystem; use each record’s `modified` timestamp. Preserve OSV ID, aliases, upstream, affected ranges/events, references, and provenance. [11] |
| **CVE Services / CVE List** | Identifier and published record program; cited CVE Services page lists CVE Record Format 5.2.0 and hourly publication. [13] | CVE is an identity/publication layer, not a complete environment-risk score. |
| **NVD** | NIST CVE/CPE API and change history; year feeds are daily, while recent/modified feeds are approximately every two hours for the previous eight days. [14][15] | Older records can be less detailed; respect API synchronization guidance and retain source timestamps. |
| **CISA KEV** | Curated catalog of vulnerabilities with reliable evidence of exploitation in the wild and a remediation action. [16] | Strong exploitation signal, not a complete list of exploitable vulnerabilities. Poll catalog version/date changes; do not assume a fixed update interval. [17] |
| **FIRST EPSS** | Daily 0–1 estimate of probability a published CVE will be exploited in the next 30 days. [18][19] | Forecast, not impact or organizational risk; it omits environmental context and compensating controls. Do not multiply by CVSS. [18] |
| **FIRST CVSS v4** | Vulnerability characteristics and severity; Base, Threat, Environmental and Supplemental groups, with a 0–10 Base scale. [20] | Severity is not exploitation probability or business priority; add local context. |

**Recommended ingestion cadence:** OSV on-demand/batch plus record-modified synchronization; NVD according to its documented last-modified guidance; KEV by catalog-version change; EPSS daily; and CVE publication awareness. Store `retrieved_at`, source URL, source record timestamp, parser/schema version, and raw response for auditability. [12][15][17][19]

---

## 3. Current solutions and gap analysis

The ecosystem separates into repository-native SCA, commercial SCA/risk platforms, artifact/SBOM scanners, and graph aggregation. The comparison below is scoped to the cited official product pages; absence of a documented capability is a validation gap, not proof that a product cannot provide it through another edition, plugin, or integration.

| Solution | Strength | Documented limitation / gap for CSB-03 |
|---|---|---|
| **GitHub Dependabot** | Native dependency graph from manifests/lockfiles, graph jobs, automatic submission, and dependency-submission API; alerts include severity and fixed-version details. [25][26] | Reviewed-advisory and graph/manifest limitations; build-time dependencies may require submission. It does not present the proposed cross-project marginal patch order. |
| **GitLab dependency scanning** | Covers runtime, development, and transitive packages; SBOM mode builds CycloneDX inventory and supports continuous rescanning. [27][28] | Cited docs describe tier/ecosystem/package-manager limitations and do not establish a cross-tool, cross-project patch-value optimizer. |
| **Snyk** | Commercial SCA with application/dependency call-graph reachability, `reachable`/`no path found`/`not applicable` states, and context-rich Priority/Risk Score. [29][30] | Reachability support is language/package-manager/plan dependent; Snyk warns “no path found” is not proof of complete unreachability. |
| **Mend** | Static reachability analyzes imports and class/file relationships; Risk Factors aggregate reachability, exploitability, and maliciousness. [31] | Static analysis has uncertainty; cited docs span legacy and current product documentation, so deployment scope must be validated. |
| **Socket** | PR/install-time package behavior analysis for install scripts, obfuscation, privileged APIs, typosquats, malware, mutable dependencies; package/function-level reachability modes. [32][33] | Coverage and plan/ecosystem dependent; its docs warn AI-generated reachability specifications can trade broader coverage for more incorrect results. |
| **JFrog Xray** | Artifact dependency graph, re-evaluation after vulnerability-intelligence changes, affected artifact/build/release mapping, policies, CI integrations, and contextual applicability analysis. [34][35] | Strongest in indexed/retained Artifactory scope; contextual statuses include unsupported/not-covered/undetermined. |
| **OWASP Dependency-Track** | API-first, SBOM-centered portfolio tracking; cited docs describe CycloneDX BOM/VEX, multiple intelligence sources, EPSS prioritization, policies, notifications, and integrations. [36][37] | Cited model is component/SBOM-centric; source-level call-graph reachability is not documented as a core feature. Validate v5 against detailed v4 integration docs. |
| **OSV-Scanner** | Open CLI/library for OSV matching across source and images, guided remediation, JSON/HTML output, license scanning, pre-commit, and optional transitive resolution. [38] | A strong matching building block, not by itself a cross-project graph, contextual priority dashboard, or governance workflow. Its guided remediation is experimental. [83] |
| **Grype / Trivy** | Open scanners for images/filesystems/SBOMs; Grype documents EPSS/KEV/risk scoring/OpenVEX, while Trivy covers vulnerabilities, secrets, licenses, optional misconfiguration, and CI integrations. [39][40] | Cited pages are scan/result focused and do not document application call-graph reachability plus centralized propagation and patch-value ranking. |
| **GUAC** | Graph aggregation for SBOM/security metadata; can query transitive paths to vulnerabilities and enrich with deps.dev, Scorecard, and OSV. [41] | Closest graph-centric foundation, but coverage, prioritization, and enforcement depend on what metadata and policies are ingested or built above it. |

### Gap that is defensible for a 24-hour team

Do **not** claim that commercial platforms cannot perform ranking or graph analysis. The defensible wedge is narrower:

- A small, open, reproducible **cross-source decision layer** over a resolved graph.
- An explicit separation of **potential impact**, **static/runtime reachability evidence**, and **exploitability signals**.
- A transparent **marginal risk removed per change cost** patch order, not just a finding list or generic “fix available” recommendation.
- A visible **counterfactual**: simulate patch A, recompute the graph, and show which findings and downstream roots disappear.
- Evidence-preserving output that a judge or engineer can audit without trusting an opaque score.

---

## 4. Real-world incidents and propagation-graph lessons

| Incident and date | What propagated | Documented response | Graph lesson |
|---|---|---|---|
| **Log4Shell — disclosure 10 Dec 2021** | CISA described RCE in Log4j 2.0-beta9–2.14.1 through attacker-controlled JNDI lookups; Java’s extensive IT/OT use made scope potentially broad. [42] | Inventory, patch/update, threat hunt, and notify vendors. [42] | Link vendor-embedded/transitive Log4j copies to products, assets, environments, and owners; prioritize exposed production roots rather than package names alone. |
| **SolarWinds SUNBURST — activity at least 2020; CISA alert 17 Dec 2020** | Malicious DLL inserted into specified Orion releases and distributed through the software-update path; CISA reported government, critical-infrastructure, and private-organization compromises. [45] | Emergency Directive 21-01, disconnect affected devices, IOCs, coordination, and remediation; GAO found information sharing was slow/difficult/time-consuming. [45][46] | Version-to-installation-to-network/identity relationships make common exposure and follow-on paths visible. |
| **Codecov Bash Uploader — unauthorized alterations 31 Jan–1 Apr 2021; customer notice 15 Apr 2021** | Attacker used an HMAC key from a Docker image layer to alter the uploader; Codecov identified Bash Uploader, GitHub Action, CircleCI Orb, and Bitrise Step delivery paths and possible CI secret/token exposure. [47] | Key rotation, customer notification, credential rotation and auditing, malicious server decommissioning. [47] | Connect tool variants to CI workflows, repositories, secrets, and downstream services; the package graph alone is insufficient. |
| **event-stream/flatmap-stream — 2018** | A new maintainer added malicious `flatmap-stream@0.1.1` to `event-stream@3.3.6`; npm reported targeted Copay 5.0.2–5.1.0 key/data theft. [48] | Registry removal, package ownership action, avoid affected Copay, update/audit. [48] | Build-time consumers and transitive edges connect a nested package to a release pipeline and product. |
| **ua-parser-js — 22 Oct 2021 alert** | CISA identified malicious versions 0.7.29, 0.8.0 and 1.0.0; GitHub’s reviewed advisory said machines that installed or ran them should be treated as fully compromised and secrets rotated from another machine. [49][50] | Patch to fixed versions, investigate, rotate secrets. [49][50] | Map package versions to lockfiles, build jobs, deployed apps, and secrets; package-wide broadcast is less precise than affected-root enumeration. |
| **XZ Utils backdoor — 29 Mar 2024 alert** | Malicious code in 5.6.0/5.6.1 used an obfuscated build step to modify `liblzma`; CISA warned about Linux distribution presence and recommended downgrade to 5.4.6. [43][44] | Downgrade, hunt, and report; NVD describes the build-time object-extraction mechanism. [43][44] | Include distribution packages and build artifacts, not only source manifests; build-time edges can change downstream authentication-adjacent risk. |
| **3CX DesktopApp — reports 29–30 Mar 2023** | Trojanized installers formed a multistage chain; Mandiant linked the initial compromise to malicious X_TRADER software, with affected 3CX 18.12.416-and-earlier exposure and Windows/macOS build-environment compromise. [51][52] | Uninstall app, use browser PWA, scan with AV/EDR, hunt IOCs. [51] | Model supplier-to-build-system-to-signed-installer-to-endpoint cascades, including one compromise leading to another. |
| **MOVEit Transfer/CL0P — exploitation began 27 May 2023; advisory 7 Jun 2023** | CISA/FBI described unauthenticated SQL injection CVE-2023-34362, LEMURLOOT web shell, database enumeration and data theft; widespread exploitation was expected. [53] | Disable HTTP/HTTPS until patched, remove shells/accounts, review logs, reset credentials, apply fixed versions. [53][54] | Link exposed instances to tenants, files, owners, and processors so patching and notification follow data impact, not only software version. |

**Common pattern:** the fastest response requires queries such as “affected version → all assets,” “package → all build/deployment paths,” “compromised tool → exposed secrets/data,” and “supplier → downstream customers.” Those are propagation queries, not ordinary package vulnerability lookups. [1][42][43][45][47][48][51][53]

---

## 5. Quantitative evidence

The table deliberately labels source type, population, and date. Vendor telemetry and surveys are directional, not universal prevalence estimates.

| Metric | Value | Date / period | Source and methodology |
|---|---:|---|---|
| FOSS production-library observations | **>12 million observations** across **>10,000 companies** | Published 4 Dec 2024 | Census III / OpenSSF and academic collaboration; supports pervasive use, not a universal percentage. [55] |
| Estimated package requests across Maven, npm, PyPI, NuGet | **6.689 trillion** for 2023 / 2024 projection framing | Sonatype data collected July 2024 | **Vendor telemetry/regression estimate**, not measured global usage; table estimates 1.5T Maven, 4.5T npm, 530B PyPI, 159B NuGet. [56] |
| Average components in a Java application | **About 150** direct + transitive components | Sonatype 2024 report | **Vendor telemetry**; not a random sample of all Java applications. [56] |
| Dependencies un-upgraded for over a year | **80%** | Analysis of >20,000 enterprise applications; 2024 report | **Sonatype vendor analysis**. [57] |
| Vulnerable components with a fixed version available | **94.9%** | Same Sonatype analysis | **Vendor analysis**, cohort-specific. [57] |
| OSS components with no available update | **0.5%** | Same Sonatype analysis | **Vendor analysis**, not a universal rate. [57] |
| Dependencies updated to another insecure version | **3.6%** | Same Sonatype analysis | **Vendor analysis**. [57] |
| Log4j downloads still on known-vulnerable versions | **13%** | Nearly three years after Log4Shell | **Sonatype download telemetry**, not all deployments. [58] |
| Node.js vulnerabilities found in transitive dependencies | **86%** | Snyk State of Open Source Security 2022 | **Vendor report / analyzed-data figure**; public explainer does not expose denominator, so directional only. [59] |
| Organizations producing or consuming SBOMs | **47%** | Q3 2021 survey; published Feb 2022 | Linux Foundation survey of **412 organizations worldwide**, 65 questions. Historical baseline, not current adoption. [60][61] |
| Organizations expecting to produce/consume SBOMs in 2022 | **78%** | Q3 2021 survey | Same Linux Foundation survey; question denominator differs from other SBOM-readiness measures. [60][61] |
| Confirmed breaches involving a third party | **15%** | 2024 DBIR | Verizon dataset: **30,458 incidents / 10,626 confirmed breaches**; expanded definition includes partner infrastructure, software supply chain, and third-party software vulnerabilities. [63] |
| Year-over-year increase in vulnerability exploitation as way in | **180%** | 2024 DBIR | Verizon incident dataset; use the report’s definition and period. [63] |
| Average global breach cost | **$4.88 million** | IBM/Ponemon 2024 study | **Vendor study**; public page does not expose full sampling methodology. [64] |
| Average time to identify / contain a breach | **194 / 64 days** | IBM/Ponemon 2024 study | **Vendor study**; not a government statistic or universal benchmark. [64] |
| Overall EU cyber incidents | **4,875** | 1 Jul 2024–30 Jun 2025; ENISA report published 1 Oct 2025 | **ENISA official overall threat-landscape count, not supply-chain-only.** [8] |
| Historical supply-chain attack increase | **4× in 2021 versus 2020; half attributed to APT actors** | Report covering Jan 2020–early Jul 2021; published 29 Jul 2021 | **ENISA historical estimate/forecast**, not current prevalence. [9] |
| OSV supported ecosystems / API peak | **30 ecosystems; >900 QPS peak** | 2024 review; published 13 Jan 2025 | OSV project-maintained coverage/usage measures; at least 140 QPS attributed to OSV-Scanner; slightly over 50% of in-scope CVEs converted under then-current NVD implementation. [7] |

**Use in the pitch:** these statistics justify the problem’s scale and persistence, but the MVP should not claim that any one vendor percentage describes the entire software industry.

---

## 6. Proposed product: PatchOrder

### 6.1 Personas

1. **Security/developer lead at a small team:** has a backlog of dependency findings, limited patch capacity, and needs a defensible order of work.
2. **Application maintainer:** owns a repository and wants to know which upgrade removes the most downstream risk without manually reconciling OSV, KEV, EPSS, CVSS, lockfiles, and deployment context.
3. **Incident responder (secondary):** needs the reverse query from an advisory or compromised component to affected roots, artifacts, and secrets.

### 6.2 User journey

1. Upload a repository or lockfile; choose a fixture or local file.
2. Parse the resolved graph and show direct/transitive/build/runtime uncertainty.
3. Query OSV in batch; retain raw responses and timestamps.
4. Join CVE aliases to KEV and EPSS; retain CVSS if present.
5. Enter context: production versus development, internet-facing versus internal, and criticality.
6. View a graph and ranked findings; open an evidence drawer for every score component.
7. Select **Rank fixes**; inspect “why now?” and affected dependents.
8. Click **Simulate patch**; recompute findings, risk, and patch order without mutating the repository.
9. Export Markdown, JSON, and CSV patch plans.

### 6.3 Demo acceptance targets (proposed, not market facts)

- Prepared fixture completes in 60 seconds or less.
- Every ranked row has an OSV evidence link.
- Every target is an OSV fixed event or explicitly marked “no fixed version.”
- Stable, deterministic JSON ordering for the same fixture and cached evidence.
- A judge can state why the top item is first within 30 seconds.
- Cached evidence supports an offline re-demo.

### 6.4 Concrete input recommendations

#### `package.json` and `package-lock.json`

- Parse `dependencies`, `devDependencies`, `optionalDependencies`, and `peerDependencies` as distinct edge attributes; npm documents these as package-name to version-range maps. [72]
- Prefer `package-lock.json` as resolved truth. npm documents that npm v7+ lockfiles contain enough information for a complete package tree plus version, resolved source, integrity, and dev/optional metadata. [73]
- Preserve the declared range, resolved version, lockfile path, integrity, and whether the edge is direct or transitive.
- If a range and lockfile disagree, show **manifest/lock drift** rather than silently selecting one.

#### `requirements.txt` and Python lockfiles

- Do not parse every line as `name==version`. pip supports specifiers, URLs, editable/VCS entries, recursive `-r` includes, constraints, environment markers, and hashes. [74]
- Treat `requirements.txt` as install input unless a resolver-generated lock is present. If `pylock.toml` is available, ingest its reproducible package records and supported environments/markers. [75]
- Preserve Python markers, extras, source URL, hashes, and whether the dependency is runtime, development, or constraint-only.

#### `pom.xml` and Maven resolution

- Model `groupId`, `artifactId`, version, scope, exclusions, optionality, parent/BOM inheritance, and dependency-management overrides.
- Maven’s effective classpath is not an edge union: transitive dependencies, nearest-definition mediation, first declaration at equal depth, exclusions, optional dependencies, and scopes affect propagation. [76]
- For a faithful result, run native resolution in a sandbox and capture `mvn dependency:tree`; the official plugin supports JSON/GraphML/DOT/TGF, filters, and verbose omitted-node output. [77]

#### Lockfiles and resolved artifacts

A range is an intent; a lockfile or native resolver output is the evidence of what was selected. Store both. For build-time and private dependencies, accept resolver-generated submission or artifact/SBOM evidence and label absence as **unknown**, not safe. [26][68]

#### OSV

- Normalize to ecosystem/name/version or PURL and use OSV batch queries where possible. [12]
- Evaluate both enumerated versions and range events such as introduced/fixed/last_affected/limit; retain aliases and upstream relationships exactly as represented. [11]
- Match on ecosystem and canonical coordinate, never a bare package name.
- If a finding has no CVE alias, keep the OSV-native finding visible; EPSS/KEV may not apply, and confidence should reflect the missing signal.
- Cache raw OSV JSON by package/version and retrieval time; show the record’s `modified` timestamp.

---

## 7. Graph/data model and scoring

### 7.1 Minimal graph schema

**Nodes**

- `Component`: `purl`, ecosystem, namespace/name, version, source URL, digest/integrity, package-manager, provenance.
- `Vulnerability`: OSV ID, CVE aliases, source, published/modified, affected ranges, fixed events, CVSS vector/score, EPSS score/percentile/as-of, KEV status/date/action, VEX status/action/impact.
- `Project`: repository, commit, owner, criticality, environment.
- `Artifact`: image/package/build output, digest, SBOM document ID.
- `Deployment`: service, environment, exposure, asset owner.
- `Evidence`: source URL, raw record hash, retrieved timestamp, parser/schema version.

**Edges**

- `Project -[DECLARES {range, scope}]-> Component`
- `Component -[RESOLVES_TO {lockfile_path, integrity}]-> Component@version`
- `Component -[DEPENDS_ON {direct, transitive, optional, peer, exclusion, scope, marker}]-> Component`
- `Artifact -[BUILT_FROM]-> Component`
- `Deployment -[RUNS]-> Artifact`
- `Vulnerability -[AFFECTS {range_source, fixed_version}]-> Component`
- `VEX -[ASSESSES]-> Vulnerability + ProductVersion`
- `Evidence -[SUPPORTS]-> any node/edge/assessment`

Keep reverse indexes from each vulnerable component to all project roots, artifacts, deployments, and owners. Display shortest paths plus all equivalent parent paths where useful.

### 7.2 Reachability states

Use a conservative three-state MVP label:

- **Reachable:** resolved runtime graph plus import/require evidence or runtime artifact evidence.
- **Potentially reachable:** dependency is in a runtime-capable path but import/call analysis is unavailable, unsupported, or ambiguous.
- **Unreachable:** explicit dev-only/build-only scope or a verified exclusion, with evidence.

Do not label “no path found” as proof of safety. Static call-graph research documents false positives/negatives and Java/Maven/large-project limitations. [29][79] Runtime reachability also does not prove exploitability; it only changes the potential impact/context of the finding.

### 7.3 Transparent scoring formula

This is a **hackathon policy proposal**, not a validated industry threshold:

\[
P(v) = 100 \times \frac{0.35K + 0.25E + 0.20C + 0.10X + 0.10R}{\sum \text{observed weights}}
\]

Where:

- `K = 1` if a returned CVE alias is in KEV; otherwise `0`.
- `E = EPSS probability` in `[0,1]`, if available.
- `C = CVSS / 10`, if a compatible CVSS score is available.
- `X = exposure`: `1.0` internet-facing production, `0.7` internal production, `0.3` development-only, or an explicit user override.
- `R = min(1, affected_dependents / 10)` as a transparent graph-reach proxy.
- The denominator renormalizes over observed signals; `confidence = observed_weight_sum / total_weight`.

**Policy gate before score:** KEV + runtime-reachable + internet-exposed findings go first. Then sort by score, affected production roots, and shortest evidence-backed path. KEV is historical confirmed exploitation evidence; EPSS is a forecast; CVSS is severity; VEX is a product-context assertion. [16][18][20][24]

Display each score component, missing fields, and confidence. Never treat missing EPSS/KEV/CVSS as zero-risk certainty.

---

## 8. Patch-order algorithm

### 8.1 Candidate generation

For each vulnerable component:

1. Read the OSV affected range and first fixed event, if any. [11]
2. Generate candidate target versions satisfying the manifest constraint or, if necessary, propose a constraint change explicitly.
3. Simulate the native resolver/lockfile update in a sandbox.
4. Recompute the graph and OSV matches.
5. Record findings removed, findings introduced, changed dependents, and test/resolution status.

OSV-Scanner’s guided remediation is itself marked experimental and warns that package-manager operations can be risky; PatchOrder should therefore **simulate and export** a plan, not mutate a user repository automatically. [83]

### 8.2 Change-cost heuristic

Use an explicit, tunable heuristic:

```text
cost(p) = 1 + 0.5 * major_jump
            + 0.3 * direct_dependency
            + 0.2 * unknown_test_impact
```

Each term is a product choice, not an empirical benchmark. Explain it in the UI and permit policy overrides.

### 8.3 Greedy selection

```text
remaining = all_current_findings
plan = []

while remaining:
    candidates = simulate_available_patches(remaining)
    if candidates is empty:
        break

    for patch in candidates:
        newly_removed = remaining - patch.findings_after
        patch.marginal_value = sum(P(v) for v in newly_removed) / patch.cost

    chosen = max(candidates, key=marginal_value)
    plan.append(chosen)
    remaining = chosen.findings_after
```

Tie-breakers: KEV/runtime/exposure policy gate, more affected production roots, fewer new findings, lower change cost, then stable package-name ordering. Output:

| Field | Purpose |
|---|---|
| `order` | Recommended sequence |
| `package`, `current_version`, `target_version` | Exact patch action |
| `OSV_IDs_removed` | Findings removed by simulation |
| `KEV_flag`, `EPSS`, `CVSS` | Evidence signals and dates |
| `exposure`, `reachability`, `confidence` | Context and uncertainty |
| `estimated_cost`, `marginal_value` | Explainable ranking |
| `why_now` | Human-readable decision explanation |
| `evidence_urls` | Direct source links |

The output is a **patch plan**, not proof of exploitability, automatic code modification, or a guarantee that the target version is safe in every environment.

---

## 9. 24-hour build plan

| Time | Deliverable | Definition of done |
|---|---|---|
| 0–1 h | Scope and fixture | Repo layout, CLI contract, one npm fixture, one Python fixture, clean fixture, cached evidence directory. |
| 1–4 h | Parsers and normalized model | `package-lock.json` guaranteed; `requirements.txt` basic grammar plus explicit unknowns; optional `pom.xml` native-tree adapter if time permits. Unit tests for direct/transitive/scope/provenance. |
| 4–7 h | OSV integration | Batch query, raw JSON cache, OSV ID/aliases/ranges/fixed events, error and rate-limit handling, deterministic fixture output. |
| 7–9 h | KEV/EPSS/CVSS enrichment | CVE alias join, timestamped KEV/EPSS fetch, CVSS extraction, missing-signal states. |
| 9–12 h | Graph and reverse impact | Dependency DAG, vulnerable-node reverse traversal, affected roots, shortest paths, reachable/potential/unreachable label. |
| 12–15 h | Score and patch simulator | Configurable formula, confidence, candidate upgrades, simulated recompute, greedy patch order, residual findings. |
| 15–18 h | UI and exports | Streamlit or equivalent local UI, graph view, evidence drawer, before/after chart, Markdown/JSON/CSV export. |
| 18–20 h | Hardening | Offline cache demo, parser edge cases, stable ordering, clear unsupported/unknown labels, unit tests. |
| 20–22 h | Demo rehearsal | 3-minute script, one live network run and one cached fallback; verify every citation/evidence URL. |
| 22–24 h | Polish and pitch | README, architecture diagram, limitations, USP slide, backup recording/screenshots if allowed. |

**Suggested architecture:** Python service; `httpx` or `requests`; small parsers; SQLite/JSON evidence cache; pure-Python scoring and simulation with tests; Streamlit/Plotly UI; CLI exports. Keep raw evidence and retrieval timestamps in every result object.

### Demo script (approximately 3 minutes)

1. **Open with the problem:** “This repository has alerts, but the team still does not know which fix removes the most propagated risk.”
2. Upload the fixture and show the direct/transitive graph.
3. Show raw OSV matches and the reverse path from vulnerable node to production root.
4. Toggle profile: internet-facing production, runtime, high criticality.
5. Click **Rank fixes**; open the top row to show OSV range/fixed event, CVE alias, KEV, EPSS, CVSS, exposure, confidence, and evidence URLs.
6. Say explicitly: “This is potential impact plus exploitation context; it does not prove exploitability.”
7. Click **Simulate patch**; show the top patch removing several findings and the second-place item changing.
8. Toggle off exposure or KEV to demonstrate policy sensitivity—not to claim the feed is truth by itself.
9. Export `patch-order.md` and `patch-order.json`.
10. Close with: “The product turns fragmented evidence into an auditable next action.”

---

## 10. Risks, limitations, and stretch goals

### 10.1 Risks and mitigations

- **Incomplete graph:** manifests, private registries, generated/vendor code, build-time tools, dynamic loading, and stale lockfiles can be missed. Mitigation: prefer lockfiles/native resolvers, preserve provenance, and expose unknown states. [2][26][68]
- **Advisory coverage gaps:** OSV matching can miss unpublished, withdrawn, proprietary, repackaged, vendored, generated, native, or incorrectly identified components. Mitigation: retain source identity and no-match/unknown states; never claim completeness. [11]
- **False confidence from reachability:** static evidence has false positives/negatives and unsupported language/build cases. Mitigation: use reachable/potentially reachable/unreachable, never “proven exploitable.” [29][79]
- **Signal conflation:** KEV, EPSS, CVSS, and VEX answer different questions. Mitigation: separate columns, timestamps, and explanations; do not multiply EPSS by CVSS. [16][18][20][24]
- **Scoring bias:** weights and exposure bins are unvalidated design choices. Mitigation: configurable weights, sensitivity toggle, confidence display, and policy gate. [20][81]
- **Unsafe remediation:** upgrades can break compatibility or introduce a different vulnerability. Mitigation: simulate in a sandbox, show tests/resolution status, and require human approval. [83]
- **Live-feed instability:** public feeds, schemas, and commercial documentation change. Mitigation: cache raw evidence, pin parser/schema versions, and show retrieval dates. [7][11][19][21][22]
- **Overclaiming statistics:** vendor telemetry/surveys have their own populations and methods. Mitigation: label source type, cohort, date, denominator, and caveat in the UI/report. [56][57][60][63][64][66][67]

### 10.2 Stretch goals after the core path is reliable

1. CycloneDX/SPDX SBOM import/export with VEX status ingestion. [21][22][24]
2. `pom.xml` native resolver and `pylock.toml` support. [75][77]
3. GitHub Action that comments the ranked plan on a pull request; do not duplicate dependency-review’s basic check. [84]
4. Registry/build/deployment joins and reverse blast-radius queries.
5. Optional GUAC/deps.dev graph enrichment, clearly marked as external provenance. [41]
6. OpenSSF Scorecard context as an optional heuristic, never a hard verdict; Scorecard documents false positives/negatives and says aggregate scores are not definitive. [85]
7. Organization policy profiles, SSVC-style decisions, and human-reviewed PR creation. [81]
8. Language-specific call graphs after measuring runtime, memory, false positives, and false negatives. [79]

---

## 11. Crisp judging pitch

### One sentence

> **PatchOrder is the explainable propagation graph that ranks the next dependency patch by expected risk removed per change, joining OSV, KEV, EPSS, CVSS, lockfiles, and project context without claiming exploitability.**

### 30-second pitch

“Most teams can find vulnerable packages; the hard part is deciding what to fix first when one nested dependency affects many services and the feeds disagree. PatchOrder resolves the actual dependency graph, follows a finding to its affected roots, joins exploitation and severity evidence, and simulates candidate upgrades. The result is not another alert list: it is an auditable patch order showing which change removes the most weighted propagated risk, at what estimated cost, with every uncertainty visible.”

### What judges should remember

- **Detection exists; decision quality is the wedge.** OSV-Scanner, Dependabot, GitLab, commercial SCA, artifact scanners, and GUAC already cover important parts of detection, scanning, or graph aggregation. [25][27][38][41]
- **Propagation is the user-visible insight.** The incident record repeatedly shows that a package or supplier compromise matters because it reaches builds, artifacts, deployments, secrets, customers, or data. [42][45][47][48][51][53]
- **Trust is explainability.** Every rank has a path, formula, source, timestamp, and missing-data state.
- **Safety is honest scope.** Potential impact and runtime reachability are not proof of exploitability; the product says exactly what it knows and what it does not.

---

## References

[1]: https://www.cisa.gov/news-events/alerts/2021/04/26/cisa-and-nist-release-new-interagency-resource-defending-against-software-supply-chain-attacks "CISA and NIST Release New Interagency Resource on Defending Against Software Supply Chain Attacks"
[2]: https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-supply-chain-security-guidance-20 "Software Supply Chain Security Guidance: SBOM and C-SCRM"
[3]: https://www.cisa.gov/topics/information-communications-technology-supply-chain-security/sbom "Software Bill of Materials (SBOM)"
[4]: https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-supply-chain-security-guidance-23 "Software Supply Chain Security Guidance: Vulnerability Advisories"
[5]: https://openssf.org/blog/2023/08/18/the-rising-threat-of-software-supply-chain-attacks-managing-dependencies-of-open-source-projects/ "The Rising Threat of Software Supply Chain Attacks: Managing Dependencies of Open Source Projects"
[6]: https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom "2025 Minimum Elements for a Software Bill of Materials (SBOM)"
[7]: https://osv.dev/blog/posts/2024-in-review/ "OSV 2024 in Review"
[8]: https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025 "ENISA Threat Landscape 2025"
[9]: https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks "Threat Landscape for Supply Chain Attacks"
[10]: https://osv.dev/docs/ "OSV Documentation"
[11]: https://ossf.github.io/osv-schema/ "OSV Schema"
[12]: https://google.github.io/osv.dev/api/ "OSV API"
[13]: https://www.cve.org/allresources/cveservices "CVE Services"
[14]: https://nvd.nist.gov/developers/vulnerabilities "NVD Vulnerabilities API"
[15]: https://nvd.nist.gov/vuln/data-feeds "NVD Data Feeds"
[16]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog "Known Exploited Vulnerabilities Catalog"
[17]: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json "Known Exploited Vulnerabilities JSON Schema"
[18]: https://www.first.org/epss/faq "EPSS FAQ"
[19]: https://www.first.org/epss/data "EPSS Data"
[20]: https://www.first.org/cvss/v4.0/specification-document "CVSS v4.0 Specification Document"
[21]: https://cyclonedx.org/specification/overview/ "CycloneDX Specification Overview"
[22]: https://spdx.dev/specifications/ "SPDX Specifications"
[23]: https://github.com/spdx/spdx-3-model "SPDX 3 Model"
[24]: https://www.cisa.gov/sites/default/files/publications/VEX_Use_Cases_Document_508c.pdf "VEX Use Cases Document"
[25]: https://docs.github.com/code-security/dependabot/dependabot-alerts/about-dependabot-alerts "About Dependabot Alerts"
[26]: https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-graph-data "Dependency Graph Data"
[27]: https://docs.gitlab.com/user/application_security/dependency_scanning/ "GitLab Dependency Scanning"
[28]: https://docs.gitlab.com/user/application_security/dependency_scanning/dependency_scanning_sbom/ "GitLab Dependency Scanning SBOM"
[29]: https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing/reachability-analysis "Snyk Reachability Analysis"
[30]: https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing "Snyk Prioritization"
[31]: https://docs.mend.io/legacy-sca/latest/sca-reachability "Mend SCA Reachability"
[32]: https://docs.socket.dev/docs/socket-for-github "Socket for GitHub"
[33]: https://docs.socket.dev/docs/reachability-analysis "Socket Reachability Analysis"
[34]: https://docs.jfrog.com/security/docs/continuous-monitoring "JFrog Xray Continuous Monitoring"
[35]: https://docs.jfrog.com/security/docs/contextual-analysis-of-cves-1 "JFrog Xray Contextual Analysis of CVEs"
[36]: https://dependencytrack.github.io/docs/next/ "Dependency-Track Documentation"
[37]: https://docs.dependencytrack.org/ "Dependency-Track Documentation (v4)"
[38]: https://google.github.io/osv-scanner/ "OSV-Scanner Documentation"
[39]: https://github.com/anchore/grype "Anchore Grype"
[40]: https://trivy.dev/docs/latest/target/filesystem/ "Trivy Filesystem Scanning"
[41]: https://docs.guac.sh/guac/ "GUAC Documentation"
[42]: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a "Apache Log4j Vulnerability Guidance"
[43]: https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094 "Reported Supply Chain Compromise Affecting XZ Utils Data Compression Library"
[44]: https://nvd.nist.gov/vuln/detail/cve-2024-3094 "CVE-2024-3094"
[45]: https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a "Advanced Persistent Threat Compromise of Government Agencies, Critical Infrastructure, and Private Sector Organizations"
[46]: https://www.gao.gov/products/gao-22-104746 "SolarWinds Cyberattack: Federal Response and Key Actions"
[47]: https://about.codecov.io/apr-2021-post-mortem/ "Codecov April 2021 Post-Mortem"
[48]: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident "Details about the event-stream Incident"
[49]: https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js "Malware Discovered in Popular npm Package ua-parser-js"
[50]: https://github.com/advisories/GHSA-pjwm-rvh2-c87w "Malicious Code in ua-parser-js"
[51]: https://www.cisa.gov/news-events/alerts/2023/03/30/supply-chain-attack-against-3cxdesktopapp "Supply Chain Attack against 3CX DesktopApp"
[52]: https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise "Investigating the 3CX Software Supply Chain Compromise"
[53]: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a "CL0P Ransomware Gang Exploits Progress MOVEit Transfer Vulnerability"
[54]: https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023 "MOVEit Transfer Critical Vulnerability"
[55]: https://openssf.org/press-release/2024/12/04/open-source-usage-trends-and-security-challenges-revealed-in-new-study/ "Open Source Usage Trends and Security Challenges Revealed in New Study"
[56]: https://www.sonatype.com/state-of-the-software-supply-chain/2024/scale "State of the Software Supply Chain 2024: Scale"
[57]: https://sonatype.com/hubfs/SSCR-2024/SSCR_2024-FINAL-optimized.pdf "State of the Software Supply Chain Report 2024"
[58]: https://www.sonatype.com/state-of-the-software-supply-chain/2024/10-year-look "State of the Software Supply Chain: 10-Year Look"
[59]: https://snyk.io/articles/open-source-security/software-composition-analysis-sca/ "Software Composition Analysis and Transitive Dependencies"
[60]: https://www.linuxfoundation.org/press/press-release/the-linux-foundation-releases-the-state-of-software-bill-of-materials-sbom-and-cybersecurity-readiness-research "The State of SBOM and Cybersecurity Readiness Research"
[61]: https://www.linuxfoundation.org/hubfs/LF%20Research/State%20of%20Software%20Bill%20of%20Materials%20-%20Report.pdf?hsLang=en "State of Software Bill of Materials Report"
[62]: https://www.cisa.gov/sites/default/files/2024-10/SBOM%20Framing%20Software%20Component%20Transparency%202024.pdf "SBOM Framing: Software Component Transparency"
[63]: https://www.verizon.com/business/resources/reports/2024-dbir-data-breach-investigations-report.pdf "2024 Data Breach Investigations Report"
[64]: https://www.ibm.com/think/insights/cost-of-a-data-breach-2024-financial-industry "Cost of a Data Breach 2024"
[65]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204D.pdf "NIST SP 800-204D: Strategies for Software Supply Chain Security"
[66]: https://snyk.io/blog/snyk-state-of-open-source-security-2023/ "Snyk State of Open Source Security 2023"
[67]: https://cloudsecurityalliance.org/artifacts/the-state-of-security-remediation-survey-report "The State of Security Remediation Survey Report"
[68]: https://docs.cloud.google.com/software-supply-chain-security/docs/dependencies "Software Dependencies Guidance"
[69]: https://csrc.nist.gov/csrc/media/Presentations/2023/sbom-lifecycle/images-media/ADiglio-ssca-forum-053123.pdf "SBOM Lifecycle"
[70]: https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report_0.pdf "The Minimum Elements for a Software Bill of Materials"
[71]: https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem "Widespread Supply Chain Compromise Impacting npm Ecosystem"
[72]: https://docs.npmjs.com/cli/v11/configuring-npm/package-json/ "package.json"
[73]: https://docs.npmjs.com/cli/v9/configuring-npm/package-lock-json "package-lock.json"
[74]: https://pip.pypa.io/en/stable/reference/requirements-file-format/ "Requirements File Format"
[75]: https://packaging.python.org/en/latest/specifications/pylock-toml/ "pylock.toml Specification"
[76]: https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html "Introduction to the Dependency Mechanism"
[77]: https://maven.apache.org/plugins/maven-dependency-plugin/tree-mojo.html "Maven Dependency Tree Plugin"
[78]: https://github.com/package-url/purl-spec "Package URL Specification"
[79]: https://arxiv.org/html/2506.17798v1 "SAVANT: Static Analysis for Vulnerability Reachability"
[80]: https://docs.endorlabs.com/scan/sca/reachability-analysis "Endor Labs Reachability Analysis"
[81]: https://www.cisa.gov/resources-tools/resources/stakeholder-specific-vulnerability-categorization-ssvc "Stakeholder-Specific Vulnerability Categorization (SSVC)"
[82]: https://google.github.io/osv.dev/post-v1-query/ "OSV Query API"
[83]: https://google.github.io/osv-scanner/experimental/guided-remediation/ "OSV-Scanner Guided Remediation"
[84]: https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review "GitHub Dependency Review"
[85]: https://github.com/ossf/scorecard "OpenSSF Scorecard"
