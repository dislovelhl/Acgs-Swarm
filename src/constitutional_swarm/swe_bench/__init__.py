"""SWE-bench scaffolding for Constitutional Swarm evaluation.

This sub-package provides the agent and harness interfaces for evaluating
constitutional governance on SWE-bench Lite tasks.  No Docker or live
execution is performed here — the harness is designed for unit-testable
scaffolding that decouples the agent protocol from external infrastructure.

Exports
-------
SWEBenchAgent       : Single-agent solver with optional BODES governance.
SWEPatch            : Structured output from a solve attempt.
SWEBenchHarness     : Task-loading, agent-running, result-aggregation.
SwarmCoordinator    : Multi-agent MerkleCRDT coordinator (swe_bench.swarm).
"""

from __future__ import annotations

from constitutional_swarm.swe_bench.agent import SWEBenchAgent, SWEPatch
from constitutional_swarm.swe_bench.codex_agent import CodexSWEBenchAgent
from constitutional_swarm.swe_bench.harness import SWEBenchHarness

__all__ = ["CodexSWEBenchAgent", "SWEBenchAgent", "SWEBenchHarness", "SWEPatch"]
