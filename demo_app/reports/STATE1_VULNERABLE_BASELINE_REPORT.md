# PatchOrder Supply-Chain Security & Remediation Report
**Project:** `demo-service-baseline`  
**Analysis ID:** `39c7a347-9f5d-4e8c-90e9-a8e062da74c2`  
**Scanned at:** 2026-10-09T13:29:01.568212+00:00  
**Environment:** `production` | **Exposure:** `internet-facing` | **Criticality:** `high`  
**Manifest Type:** `npm` (resolved)  

---

## 1. Executive Summary

- **Total Components Scanned:** 237 (3 direct, 234 transitive)
- **Vulnerable Components:** 15 (Unique packages: 15, Instances: 15)
- **Total Vulnerability Advisories:** 34 (Raw records: 34, Distinct vulnerability groups: 34)
- **Confirmed CISA KEV Exploitations:** **3**
- **Cyclic Dependencies (Tarjan SCC):** 6 components
- **High/Critical Priority Findings:** 3
- **Analysis Latency:** 4672.94 ms (Cache hits: 127)

## 2. Ranked Patch Plan (Risk Removed per Change Cost)

PatchOrder ranks fixes by **marginal risk removed per estimated change cost**, prioritizing KEV matches and blast-radius reach.

| Rank | Package | Current | Target Fix | Risk Removed | Est. Cost | Marginal Value | Why Now |
|---|---|---|---|---|---|---|---|
| **#1** | `lodash` | `4.17.15` | **`4.18.0`** | 301.0 pts | 1.5 | **200.67** | Contains verified CISA KEV exploitation in the wild. Removes 6 distinct vulnerability advisories in one patch. Protects 1 direct application project root(s). Estimated change cost is 1.5 with marginal value 200.67 pts/cost. |
| **#2** | `qs` | `6.5.1` | **`6.16.0`** | 76.8 pts | 1.2 | **64.0** | Removes 3 distinct vulnerability advisories in one patch. Protects 1 direct application project root(s). Estimated change cost is 1.2 with marginal value 64.0 pts/cost. |
| **#3** | `js-yaml` | `3.13.1` | **`3.15.2`** | 74.5 pts | 1.2 | **62.08** | Removes 5 distinct vulnerability advisories in one patch. Protects 1 direct application project root(s). Estimated change cost is 1.2 with marginal value 62.08 pts/cost. |
| **#4** | `path-to-regexp` | `0.1.7` | **`0.1.13`** | 72.9 pts | 1.2 | **60.75** | Removes 3 distinct vulnerability advisories in one patch. Protects 1 direct application project root(s). Estimated change cost is 1.2 with marginal value 60.75 pts/cost. |
| **#5** | `minimatch` | `3.0.4` | **`3.1.4`** | 67.6 pts | 1.2 | **56.33** | Removes 4 distinct vulnerability advisories in one patch. Protects 1 direct application project root(s). Estimated change cost is 1.2 with marginal value 56.33 pts/cost. |
| **#6** | `body-parser` | `1.18.2` | **`1.20.6`** | 48.6 pts | 1.2 | **40.5** | Removes 2 distinct vulnerability advisories in one patch. Protects 1 direct application project root(s). Estimated change cost is 1.2 with marginal value 40.5 pts/cost. |
| **#7** | `express` | `4.16.0` | **`4.20.0`** | 45.8 pts | 1.5 | **30.53** | Removes 2 distinct vulnerability advisories in one patch. Protects 1 direct application project root(s). Estimated change cost is 1.5 with marginal value 30.53 pts/cost. |
| **#8** | `send` | `0.16.0` | **`0.19.0`** | 25.6 pts | 1.2 | **21.33** | Removes confirmed vulnerability advisory. Protects 1 direct application project root(s). Estimated change cost is 1.2 with marginal value 21.33 pts/cost. |
| **#9** | `serve-static` | `1.13.0` | **`1.16.0`** | 24.3 pts | 1.2 | **20.25** | Removes confirmed vulnerability advisory. Protects 1 direct application project root(s). Estimated change cost is 1.2 with marginal value 20.25 pts/cost. |
| **#10** | `cookie` | `0.3.1` | **`0.7.0`** | 21.8 pts | 1.2 | **18.17** | Removes confirmed vulnerability advisory. Protects 1 direct application project root(s). Estimated change cost is 1.2 with marginal value 18.17 pts/cost. |
| **#11** | `serialize-javascript` | `3.0.0` | **`7.0.3`** | 29.8 pts | 1.7 | **17.53** | Removes 2 distinct vulnerability advisories in one patch. Protects 1 direct application project root(s). Estimated change cost is 1.7 with marginal value 17.53 pts/cost. |
| **#12** | `diff` | `4.0.2` | **`3.5.1`** | 17.3 pts | 1.7 | **10.18** | Removes confirmed vulnerability advisory. Protects 1 direct application project root(s). Estimated change cost is 1.7 with marginal value 10.18 pts/cost. |
| **#13** | `debug` | `3.2.6` | **`2.6.9`** | 14.9 pts | 1.7 | **8.76** | Removes confirmed vulnerability advisory. Protects 1 direct application project root(s). Estimated change cost is 1.7 with marginal value 8.76 pts/cost. |
| **#14** | `sprintf-js` | `1.0.3` | **`No known fixed version`** | 0.0 pts | 1.2 | **0.0** | Removes confirmed vulnerability advisory. Protects 1 direct application project root(s). Estimated change cost is 1.2 with marginal value 0.0 pts/cost. |
| **#15** | `braces` | `3.0.3` | **`No known fixed version`** | 0.0 pts | 1.2 | **0.0** | Removes confirmed vulnerability advisory. Protects 1 direct application project root(s). Estimated change cost is 1.2 with marginal value 0.0 pts/cost. |


## 3. Verified Vulnerabilities & Propagation Paths

| Package | Version | Type | Advisory ID | CVE | Score | Tier | Propagation Path |
|---|---|---|---|---|---|---|---|
| `lodash` | `4.17.15` | Direct | `GHSA-35jh-r3h4-6jhm` | `CVE-2021-23337` | 76.5 | `CRITICAL_URGENT` | `lodash` |
| `lodash` | `4.17.15` | Direct | `GHSA-r5fr-rjxr-66jc` | `CVE-2021-23337` | 76.5 | `CRITICAL_URGENT` | `lodash` |
| `lodash` | `4.17.15` | Direct | `GHSA-p6mc-m468-83gw` | `CVE-2020-8203` | 71.2 | `CRITICAL_URGENT` | `lodash` |
| `lodash` | `4.17.15` | Direct | `GHSA-29mw-wpgm-hmr9` | `CVE-2020-28500` | 25.6 | `LOW` | `lodash` |
| `lodash` | `4.17.15` | Direct | `GHSA-f23m-r3pf-42rh` | `CVE-2025-13465` | 25.6 | `LOW` | `lodash` |
| `lodash` | `4.17.15` | Direct | `GHSA-xxjr-mmjv-4gpg` | `CVE-2025-13465` | 25.6 | `LOW` | `lodash` |
| `qs` | `6.5.1` | Transitive | `GHSA-4mjr-xmp4-gh2g` | `CVE-2026-82417` | 25.6 | `LOW` | `express -> body-parser -> qs` |
| `qs` | `6.5.1` | Transitive | `GHSA-6rw7-vpxm-498p` | `CVE-2025-15284` | 25.6 | `LOW` | `express -> body-parser -> qs` |
| `qs` | `6.5.1` | Transitive | `GHSA-hrpp-h998-j3pp` | `CVE-2022-24999` | 25.6 | `LOW` | `express -> body-parser -> qs` |
| `send` | `0.16.0` | Transitive | `GHSA-m6fv-jmcg-4jfg` | `CVE-2024-43799` | 25.6 | `LOW` | `express -> send` |
| `body-parser` | `1.18.2` | Transitive | `GHSA-qwcr-r2fm-qrc7` | `CVE-2024-45590` | 24.3 | `LOW` | `express -> body-parser` |
| `body-parser` | `1.18.2` | Transitive | `GHSA-v422-hmwv-36x6` | `CVE-2026-12590` | 24.3 | `LOW` | `express -> body-parser` |
| `path-to-regexp` | `0.1.7` | Transitive | `GHSA-37ch-88jc-xwx2` | `CVE-2024-45296` | 24.3 | `LOW` | `express -> path-to-regexp` |
| `path-to-regexp` | `0.1.7` | Transitive | `GHSA-9wv6-86v2-598j` | `CVE-2024-45296` | 24.3 | `LOW` | `express -> path-to-regexp` |
| `path-to-regexp` | `0.1.7` | Transitive | `GHSA-rhx6-c78j-4q9w` | `CVE-2024-52798` | 24.3 | `LOW` | `express -> path-to-regexp` |
| `serve-static` | `1.13.0` | Transitive | `GHSA-cm22-4g7w-348p` | `CVE-2024-43800` | 24.3 | `LOW` | `express -> serve-static` |
| `express` | `4.16.0` | Direct | `GHSA-qw6h-vgh9-j6wx` | `CVE-2024-43796` | 22.9 | `LOW` | `express` |
| `express` | `4.16.0` | Direct | `GHSA-rv95-896h-c2vc` | `CVE-2024-29041` | 22.9 | `LOW` | `express` |
| `cookie` | `0.3.1` | Transitive | `GHSA-pxg6-pf52-xh8x` | `CVE-2024-47764` | 21.8 | `LOW` | `express -> cookie` |
| `minimatch` | `3.0.4` | Transitive | `GHSA-3ppc-4f35-3m26` | `CVE-2026-26996` | 18.7 | `LOW` | `mocha -> glob -> minimatch` |
| `sprintf-js` | `1.0.3` | Transitive | `GHSA-hp3w-g68c-fv3c` | `CVE-2026-97058` | 17.6 | `LOW` | `mocha -> js-yaml -> argparse -> sprintf-js` |
| `diff` | `4.0.2` | Transitive | `GHSA-73rr-hh4g-fpgx` | `CVE-2026-24001` | 17.3 | `LOW` | `mocha -> diff` |
| `braces` | `3.0.3` | Transitive | `GHSA-vfj7-8cjw-p6xm` | `CVE-2026-93687` | 16.3 | `LOW` | `mocha -> chokidar -> braces` |
| `minimatch` | `3.0.4` | Transitive | `GHSA-23c5-xmqv-rm74` | `CVE-2026-27904` | 16.3 | `LOW` | `mocha -> glob -> minimatch` |
| `minimatch` | `3.0.4` | Transitive | `GHSA-7r86-cg39-jmmj` | `CVE-2026-27903` | 16.3 | `LOW` | `mocha -> glob -> minimatch` |
| `minimatch` | `3.0.4` | Transitive | `GHSA-f8q6-p94x-37v3` | `CVE-2022-3517` | 16.3 | `LOW` | `mocha -> glob -> minimatch` |
| `js-yaml` | `3.13.1` | Transitive | `GHSA-2883-xcg3-v3hh` | `CVE-2026-84375` | 14.9 | `LOW` | `mocha -> js-yaml` |
| `js-yaml` | `3.13.1` | Transitive | `GHSA-52cp-r559-cp3m` | `CVE-2026-59869` | 14.9 | `LOW` | `mocha -> js-yaml` |
| `js-yaml` | `3.13.1` | Transitive | `GHSA-5p4m-2wfm-xmqj` | `-` | 14.9 | `LOW` | `mocha -> js-yaml` |
| `js-yaml` | `3.13.1` | Transitive | `GHSA-h67p-54hq-rp68` | `CVE-2026-53550` | 14.9 | `LOW` | `mocha -> js-yaml` |
| `js-yaml` | `3.13.1` | Transitive | `GHSA-mh29-5h37-fv8m` | `CVE-2025-64718` | 14.9 | `LOW` | `mocha -> js-yaml` |
| `debug` | `3.2.6` | Transitive | `GHSA-gxpj-cx7g-858c` | `CVE-2017-16137` | 14.9 | `LOW` | `mocha -> debug` |
| `serialize-javascript` | `3.0.0` | Transitive | `GHSA-5c6j-r48x-rmvq` | `-` | 14.9 | `LOW` | `mocha -> serialize-javascript` |
| `serialize-javascript` | `3.0.0` | Transitive | `GHSA-hxcc-f52p-wc94` | `CVE-2020-7660` | 14.9 | `LOW` | `mocha -> serialize-javascript` |


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