# Papers Claims Map

Scope: B2 from `.omc/specs/deep-interview-remaining-tasks.md`.

Definition used here: `mapped` means an existing `scripts/` entry or pytest test directly exercises the named empirical behavior. Rows marked `unmapped` have no existing artifact that reproduces the reported scale, exact numeric result, or pending benchmark outcome.

## ICLR 2027

| claim-id | section/line | one-line claim text | repro_artifact | status |
|---|---:|---|---|---|
| ICLR-01 | `sections/abstract.tex:5` | In controlled experiments with `n=50`, Sinkhorn-normalized trust reaches `0%` variance retention by cycle 10. | `tests/test_manifold_degeneration.py::test_birkhoff_uniformity_collapse` | mapped |
| ICLR-02 | `sections/abstract.tex:13` | SpectralSphere plus residual achieves stable `142%` variance retention for `n=50` and `20%` for `n=10`. | `tests/test_spectral_sphere_retention.py::test_residual_compose_retains_variance` | mapped |
| ICLR-03 | `sections/abstract.tex:18` | The Neural ODE achieves `2,656%` topological capacity relative to the Sinkhorn baseline. | none | unmapped |
| ICLR-04 | `sections/abstract.tex:24` | Residual injection at `alpha=0.1` reduces epsilon-DP noise requirements by exactly `10%`. | `tests/test_rule_consistency.py::TestDPNoiseHelpers::test_calibrate_sigma_decreases_with_alpha` | mapped |
| ICLR-05 | `sections/introduction.tex:20` | For `n=50`, variance retention falls from `100%` to `0%` by cycle 10, and for `n=10` reaches `0%` by cycle 6. | `tests/test_manifold_degeneration.py::test_birkhoff_uniformity_collapse` | mapped |
| ICLR-06 | `sections/introduction.tex:39` | Iterated Sinkhorn collapses variance to zero while SpectralSphere with residual converges to a non-degenerate equilibrium. | `tests/test_manifold_degeneration.py::test_birkhoff_uniformity_collapse`; `tests/test_spectral_sphere_retention.py::test_residual_compose_retains_variance` | mapped |
| ICLR-07 | `sections/introduction.tex:65` | The ODE achieves `2,656%` topological capacity relative to Sinkhorn. | none | unmapped |
| ICLR-08 | `sections/experiments.tex:24` | Experiments run `30` random seeds for each swarm size `n in {10, 50}` and report mean plus standard deviation. | none | unmapped |
| ICLR-09 | `sections/experiments.tex:47` | Variance-retention table results are means over `30` seeds with standard deviations `< 3%` for non-collapsed rows. | none | unmapped |
| ICLR-10 | `sections/experiments.tex:57` | Sinkhorn table rows report collapse to `0%` by cycle 10 for both `n=50` and `n=10`. | `tests/test_manifold_degeneration.py::test_birkhoff_uniformity_collapse` | mapped |
| ICLR-11 | `sections/experiments.tex:60` | SpectralSphere plus residual at `alpha=0.1` stabilizes at `142%` for `n=50` and `20%` for `n=10`. | `tests/test_spectral_sphere_retention.py::test_residual_compose_retains_variance` | mapped |
| ICLR-12 | `sections/experiments.tex:62` | SpectralSphere without residual initially amplifies variance but collapses to `0%` by cycle 50. | none | unmapped |
| ICLR-13 | `sections/experiments.tex:96` | Equilibrium variance retention decreases at smaller scale, and practical swarms with `n >= 20` exceed `50%` retention. | none | unmapped |
| ICLR-14 | `sections/experiments.tex:118` | Neural ODE topological capacity is `2,656%`, about `26x` Sinkhorn, at cycle 10. | none | unmapped |
| ICLR-15 | `sections/experiments.tex:144` | DP-noise table reports exact sigma values and `-10%`, `-20%`, and `-50%` reductions for alpha values `0.1`, `0.2`, and `0.5`. | none | unmapped |
| ICLR-16 | `sections/experiments.tex:160` | Radius sensitivity gives `71%`, `142%`, and `287%` equilibrium variance retention for `r=0.5`, `1.0`, and `2.0`. | none | unmapped |
| ICLR-17 | `sections/experiments.tex:166` | Increasing `alpha` from `0.1` to `0.5` reduces `n=50` variance retention from `142%` to `38%`. | none | unmapped |
| ICLR-18 | `sections/conclusion.tex:6` | Sinkhorn empirically collapses to `0%` variance retention by cycle 10 for `n in {10, 50}` with no recovery. | `tests/test_manifold_degeneration.py::test_birkhoff_uniformity_collapse` | mapped |
| ICLR-19 | `sections/conclusion.tex:10` | SpectralSphere with residual achieves `142%` stable retention for `n=50`, `20%` for `n=10`, and ODE capacity of `2,656%`. | none | unmapped |
| ICLR-20 | `sections/conclusion.tex:20` | At `alpha=0.1`, the stability fix reduces required DP noise by `10%`. | `tests/test_rule_consistency.py::TestDPNoiseHelpers::test_calibrate_sigma_decreases_with_alpha` | mapped |

## NDSS 2027

| claim-id | section/line | one-line claim text | repro_artifact | status |
|---|---:|---|---|---|
| NDSS-01 | `sections/abstract.tex:17` | Honest replicas converge to identical governance state in `O(log N)` gossip rounds despite up to `floor(N/3)` Byzantine nodes. | `tests/test_merkle_crdt.py::test_gossip_convergence_large`; `tests/test_merkle_crdt.py::test_gossip_byzantine_agent_excluded` | mapped |
| NDSS-02 | `sections/abstract.tex:20` | DP noise uses `sigma = 2(1-alpha)r*sqrt(2ln(1.25/delta))/epsilon`, and `alpha=0.1` reduces noise by `10%`. | `tests/test_rule_consistency.py::TestDPNoiseHelpers::test_calibrate_sigma_decreases_with_alpha` | mapped |
| NDSS-03 | `sections/abstract.tex:25` | The protocol is evaluated on a synthetic `N`-agent swarm benchmark and later on SWE-bench coding tasks. | `scripts/eval_swe_bench_synthetic.py`; `scripts/run_swe_bench_swarm_lite.py`; `scripts/run_official_swarm_swebench.py` | mapped |
| NDSS-04 | `sections/introduction.tex:48` | Merkle-CRDT gossip converges honest replicas to identical state in `O(log N)` rounds. | `tests/test_merkle_crdt.py::test_gossip_convergence_large`; `tests/test_gossip_protocol.py::test_five_node_convergence` | mapped |
| NDSS-05 | `sections/introduction.tex:53` | Residual injection reduces l2 sensitivity from `2r` to `2(1-alpha)r`, giving a `10%` noise reduction at `alpha=0.1`. | `tests/test_rule_consistency.py::TestDPNoiseHelpers::test_calibrate_sigma_decreases_with_alpha` | mapped |
| NDSS-06 | `sections/introduction.tex:76` | Empirical evaluation covers synthetic swarm benchmarks and SWE-bench coding tasks, with SWE-bench pending Phase 3/4 completion. | `scripts/eval_swe_bench_synthetic.py`; `scripts/run_swe_bench_swarm_lite.py` | mapped |
| NDSS-07 | `sections/protocol.tex:82` | Spectral projection enforces `||H_proj||_2 <= r` and prevents Birkhoff Uniformity Collapse. | `tests/test_spectral_sphere_retention.py::TestSpectralNormGuaranteeAfterProjection::test_projected_norm_within_radius`; `tests/test_spectral_sphere_retention.py::test_residual_compose_retains_variance` | mapped |
| NDSS-08 | `sections/protocol.tex:92` | Residual injection tightens DP sensitivity by factor `(1-alpha)`. | `tests/test_rule_consistency.py::TestDPNoiseHelpers::test_calibrate_sigma_decreases_with_alpha` | mapped |
| NDSS-09 | `sections/protocol.tex:132` | Multiple-round privacy composition is approximately `(epsilon*sqrt(2k*ln(1/delta)), k*delta)` under standard composition. | none | unmapped |
| NDSS-10 | `sections/protocol.tex:147` | For `sigma <= r/sqrt(n)`, expected spectral norm of noise stays within the spectral ball. | none | unmapped |
| NDSS-11 | `sections/security_analysis.tex:50` | With a connected graph and at most `floor(N/3)` Byzantine agents, EEC occurs within `O(log N)` gossip rounds in expectation. | `tests/test_merkle_crdt.py::test_gossip_convergence_large`; `tests/test_gossip_protocol.py::test_byzantine_node_does_not_corrupt_swarm` | mapped |
| NDSS-12 | `sections/security_analysis.tex:130` | Security summary claims `f < N/3` Byzantine tolerance, EEC in `O(log N)`, `VR > 0`, and `-10%` noise at `alpha=0.1`. | `tests/test_merkle_crdt.py::test_gossip_byzantine_agent_excluded`; `tests/test_spectral_sphere_retention.py::test_residual_compose_retains_variance`; `tests/test_rule_consistency.py::TestDPNoiseHelpers::test_calibrate_sigma_decreases_with_alpha` | mapped |
| NDSS-13 | `sections/evaluation.tex:18` | Network evaluation uses random 4-regular graphs with `N in {10, 50, 100, 500}` and push-pull gossip with `3` peers per round. | none | unmapped |
| NDSS-14 | `sections/evaluation.tex:29` | Protocol-correctness table reports `20` seeds, `100%` acceptance, and convergence rounds from `3.2 +/- 0.4` to `8.7 +/- 1.2`. | none | unmapped |
| NDSS-15 | `sections/evaluation.tex:46` | Across all tested configurations, Byzantine tuples have `0` false acceptances and EEC matches the `log2(500) ~= 9` prediction at `N=500`. | none | unmapped |
| NDSS-16 | `sections/evaluation.tex:52` | Injecting `1,000` tampered tuples per seed yields zero accepted tampered tuples across all runs. | none | unmapped |
| NDSS-17 | `sections/evaluation.tex:61` | DP accuracy table reports exact theoretical and empirical sigma values with relative error from `0.12%` to `0.23%`. | none | unmapped |
| NDSS-18 | `sections/evaluation.tex:77` | Empirical noise matches theory within `0.23%`, and at `epsilon=2.0`, residual injection reduces sigma from `1.92` to `1.73`. | none | unmapped |
| NDSS-19 | `sections/evaluation.tex:86` | Phase 3/4 SWE-bench results are pending. | `scripts/run_swe_bench_swarm_lite.py`; `scripts/run_official_swarm_swebench.py` | mapped |
| NDSS-20 | `sections/evaluation.tex:115` | Expected SWE-bench outcomes: Sinkhorn-CRDT converges to uniform routing within `10` rounds and FedSink exceeds Sinkhorn-CRDT task success by `15`--`30%`. | none | unmapped |
| NDSS-21 | `sections/evaluation.tex:130` | SWE-bench placeholder table expects flat routing at `0%`, Sinkhorn-CRDT near `0%`, FedSink routing diversity `>100%`, and `O(log N)` convergence. | none | unmapped |
| NDSS-22 | `sections/evaluation.tex:142` | Protocol latency table reports `1.2 +/- 0.1 ms` SVD, `<0.1 ms` residual injection, `0.3 +/- 0.05 ms` DP sampling, and `~2.5 ms` total excluding zk-SNARK. | none | unmapped |
| NDSS-23 | `sections/evaluation.tex:160` | For 10-second tasks the governance overhead is `0.025%`, and at `n=500` SVD scales to approximately `1.2 s`. | none | unmapped |
| NDSS-24 | `sections/conclusion.tex:55` | Correctness tests for CID integrity, EEC convergence, and DP calibration pass in the Phase 2 suite with `1018` tests and `2` expected failures. | none | unmapped |

## Unmapped Suggestions

| claim-id | suggestion |
|---|---|
| ICLR-03 | add `scripts/repro_iclr_03.py` |
| ICLR-07 | add `scripts/repro_iclr_07.py` |
| ICLR-08 | add `scripts/repro_iclr_08.py` |
| ICLR-09 | add `scripts/repro_iclr_09.py` |
| ICLR-12 | add `scripts/repro_iclr_12.py` |
| ICLR-13 | add `scripts/repro_iclr_13.py` |
| ICLR-14 | add `scripts/repro_iclr_14.py` |
| ICLR-15 | add `scripts/repro_iclr_15.py` |
| ICLR-16 | add `scripts/repro_iclr_16.py` |
| ICLR-17 | add `scripts/repro_iclr_17.py` |
| ICLR-19 | add `scripts/repro_iclr_19.py` |
| NDSS-09 | add `test_id` in `tests/test_privacy_accountant.py` |
| NDSS-10 | add `test_id` in `tests/test_swarm_ode.py` |
| NDSS-13 | add `scripts/repro_ndss_13.py` |
| NDSS-14 | add `scripts/repro_ndss_14.py` |
| NDSS-15 | add `scripts/repro_ndss_15.py` |
| NDSS-16 | add `scripts/repro_ndss_16.py` |
| NDSS-17 | add `scripts/repro_ndss_17.py` |
| NDSS-18 | add `scripts/repro_ndss_18.py` |
| NDSS-20 | add `scripts/repro_ndss_20.py` |
| NDSS-21 | add `scripts/repro_ndss_21.py` |
| NDSS-22 | add `scripts/repro_ndss_22.py` |
| NDSS-23 | add `scripts/repro_ndss_23.py` |
| NDSS-24 | add `test_id` in `tests/test_paper_reproducibility.py` |

## Summary

| paper | total claims | mapped | unmapped |
|---|---:|---:|---:|
| ICLR 2027 | 20 | 9 | 11 |
| NDSS 2027 | 24 | 11 | 13 |
| Total | 44 | 20 | 24 |

## Verification

| paper | command | exit code | result |
|---|---|---:|---|
| ICLR 2027 | `python scripts/verify_citations.py --root papers/iclr2027` | 1 | 18 citations scanned; 18 failed with `URLError: gaierror` because DNS/network resolution was unavailable in this environment. |
| ICLR 2027 | `python scripts/verify_citations.py --root papers/iclr2027 --skip-network` | 0 | 18 citation identifiers found; lint-only citation scan passed. |
| NDSS 2027 | `python scripts/verify_citations.py --root papers/ndss2027` | 1 | 18 citations scanned; 18 failed with `URLError: gaierror` because DNS/network resolution was unavailable in this environment. |
| NDSS 2027 | `python scripts/verify_citations.py --root papers/ndss2027 --skip-network` | 0 | 18 citation identifiers found; lint-only citation scan passed. |

## Task B4 Citation Verification

- `python scripts/verify_citations.py --root papers/iclr2027`
  - exit code: 1
  - result: 18 citations found, 18 failed (`URLError: gaierror`)
- `python scripts/verify_citations.py --root papers/ndss2027`
  - exit code: 1
  - result: 18 citations found, 18 failed (`URLError: gaierror`)
- `python scripts/verify_citations.py --root papers/iclr2027 --skip-network`
  - exit code: 0
  - result: 18 citations found, OK
- `python scripts/verify_citations.py --root papers/ndss2027 --skip-network`
  - exit code: 0
  - result: 18 citations found, OK
