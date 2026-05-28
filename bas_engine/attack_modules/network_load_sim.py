"""
Network Load Simulation Module
MITRE ATT&CK: T1498 — Network Denial of Service (simulation only)

Simulates high-volume traffic to test:
  - Rate limiting rules
  - WAF threshold triggers
  - Network control baselines
  - DDoS mitigation effectiveness

Safe simulation — no actual packet flooding.
"""

import asyncio
import aiohttp
import time
from typing import List

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity


class NetworkLoadSimModule(BaseAttackModule):
    MODULE_NAME  = "network_load_sim"
    DESCRIPTION  = "Simulates high-volume HTTP traffic to test rate limiting and WAF thresholds (T1498)"
    MITRE_TACTIC = "Impact"
    MITRE_IDS    = ["T1498", "T1499"]

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        port        = int(self.options.get("port", 443))
        req_count   = int(self.options.get("request_count", 50))
        concurrency = int(self.options.get("concurrency", 10))

        self.logger.info(f"[network_load_sim] Starting {req_count} requests to {target} (concurrency={concurrency})")

        connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
        timeout   = aiohttp.ClientTimeout(total=5)

        status_counts  = {}
        blocked_count  = 0
        success_count  = 0
        start_time     = time.time()

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/1.0 (authorized security testing)"},
        ) as session:

            async def single_request(i: int):
                nonlocal blocked_count, success_count
                url = f"{target}?_bas_load_test={i}"
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        status_counts[resp.status] = status_counts.get(resp.status, 0) + 1
                        if resp.status == 429:
                            blocked_count += 1
                        elif resp.status < 400:
                            success_count += 1
                except Exception:
                    status_counts["error"] = status_counts.get("error", 0) + 1

            # Send requests in batches
            for batch_start in range(0, req_count, concurrency):
                batch = [single_request(i) for i in range(batch_start, min(batch_start + concurrency, req_count))]
                await asyncio.gather(*batch)
                await asyncio.sleep(0.1)

        elapsed     = time.time() - start_time
        rps         = req_count / elapsed if elapsed > 0 else 0
        block_rate  = (blocked_count / req_count * 100) if req_count > 0 else 0

        # Finding 1: Load test summary
        findings.append(self.finding(
            title       = "Network Load Simulation Completed",
            description = (
                f"Sent {req_count} HTTP requests to {target} in {elapsed:.1f}s "
                f"({rps:.1f} req/s). "
                f"Status distribution: {status_counts}. "
                f"Rate-limited (429): {blocked_count} requests ({block_rate:.1f}%)."
            ),
            severity    = Severity.INFO,
            mitre_id    = "T1498",
            evidence    = f"{req_count} requests @ {rps:.1f} req/s → {status_counts}",
            remediation = "Review rate limiting thresholds and DDoS mitigation rules.",
            raw_data    = {
                "total_requests": req_count,
                "elapsed_s":      round(elapsed, 2),
                "rps":            round(rps, 1),
                "status_counts":  status_counts,
                "blocked":        blocked_count,
            },
        ))

        # Finding 2: Rate limiting assessment
        if blocked_count == 0:
            findings.append(self.finding(
                title       = "No Rate Limiting Detected",
                description = (
                    f"All {req_count} requests succeeded without any HTTP 429 responses. "
                    "The target does not appear to enforce rate limiting, making it "
                    "vulnerable to DoS and credential stuffing attacks."
                ),
                severity    = Severity.HIGH,
                mitre_id    = "T1499",
                evidence    = f"0 rate-limited responses out of {req_count} requests",
                remediation = (
                    "1. Implement rate limiting (e.g., nginx limit_req_zone).\n"
                    "2. Configure WAF rate-based rules.\n"
                    "3. Deploy a CDN/DDoS protection service.\n"
                    "4. Set threshold alerts in your SIEM for request spikes."
                ),
            ))
        elif block_rate > 50:
            findings.append(self.finding(
                title       = "Rate Limiting Active and Effective",
                description = (
                    f"Rate limiting blocked {block_rate:.1f}% of requests with HTTP 429. "
                    "The target has effective request throttling in place."
                ),
                severity    = Severity.INFO,
                mitre_id    = "T1499",
                evidence    = f"{blocked_count}/{req_count} requests rate-limited",
                remediation = "Rate limiting is functioning. Continue monitoring thresholds.",
            ))

        return findings
