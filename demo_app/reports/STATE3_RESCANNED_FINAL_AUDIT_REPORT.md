# PatchOrder Supply-Chain Security & Remediation Report
**Project:** `demo-service-remediated`  
**Analysis ID:** `1d155d81-27dc-45fc-8b9d-10c567e71fca`  
**Scanned at:** 2026-10-09T13:32:41.975513+00:00  
**Environment:** `production` | **Exposure:** `internet-facing` | **Criticality:** `high`  
**Manifest Type:** `npm` (resolved)  

---

## 1. Executive Summary

- **Total Components Scanned:** 93 (3 direct, 90 transitive)
- **Vulnerable Components:** 0 (Unique packages: 0, Instances: 0)
- **Total Vulnerability Advisories:** 0 (Raw records: 0, Distinct vulnerability groups: 0)
- **Confirmed CISA KEV Exploitations:** **0**
- **Cyclic Dependencies (Tarjan SCC):** 0 components
- **High/Critical Priority Findings:** 0
- **Analysis Latency:** 1312.9 ms (Cache hits: 70)

## 2. Ranked Patch Plan (Risk Removed per Change Cost)

PatchOrder ranks fixes by **marginal risk removed per estimated change cost**, prioritizing KEV matches and blast-radius reach.

| Rank | Package | Current | Target Fix | Risk Removed | Est. Cost | Marginal Value | Why Now |
|---|---|---|---|---|---|---|---|


## 3. Verified Vulnerabilities & Propagation Paths

| Package | Version | Type | Advisory ID | CVE | Score | Tier | Propagation Path |
|---|---|---|---|---|---|---|---|


## 4. Prioritization Method & Formula

Findings are prioritized using the transparent CSB-03 policy formula:
```text
P(v) = 100 * (0.35*K + 0.25*E + 0.20*C + 0.10*X + 0.10*R) / (observed_weights)
```
- **K**: CISA KEV exploitation signal (0.35)
- **E**: FIRST EPSS 30-day forecast probability (0.25)
- **C**: Normalized CVSS base severity (0.20)
- **X**: Declared project exposure context (0.10)
- **R**: Graph propagation reach proxy (0.10)

## 5. Audit Boundaries & Disclaimer

> **Important:** PatchOrder estimates potential impact and prioritization from graph propagation, OSV intelligence, and declared context. It does not prove runtime exploitability, nor does it guarantee that simulated updates are free from regressions without testing.