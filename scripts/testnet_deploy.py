#!/usr/bin/env python3
"""Bittensor Testnet Deployment Script for Constitutional Governance Subnet.

Usage:
    # Register subnet on testnet
    python scripts/testnet_deploy.py register --wallet-name <name> --wallet-hotkey <key>

    # Start miner
    python scripts/testnet_deploy.py miner --wallet-name <name> --wallet-hotkey <key> \
        --constitution constitution.yaml --netuid <id>

    # Start validator
    python scripts/testnet_deploy.py validator --wallet-name <name> --wallet-hotkey <key> \
        --constitution constitution.yaml --netuid <id>

Requirements:
    pip install bittensor>=7.0.0
"""

from __future__ import annotations

import argparse
import sys

_BT_RUNTIME_ERRORS = (ConnectionError, OSError, RuntimeError, TimeoutError, ValueError)


def _check_bittensor() -> None:
    """Verify bittensor package is installed."""
    try:
        import bittensor  # noqa: F401
    except ImportError:
        print("ERROR: bittensor package not installed.")
        print("  pip install bittensor>=7.0.0")
        sys.exit(1)


def cmd_register(args: argparse.Namespace) -> None:
    """Register a new subnet on testnet."""
    _check_bittensor()
    import bittensor as bt

    wallet = bt.wallet(name=args.wallet_name, hotkey=args.wallet_hotkey)

    try:
        subtensor = bt.subtensor(network="test")
    except _BT_RUNTIME_ERRORS as exc:
        print(f"ERROR: Could not connect to Bittensor testnet: {exc}")
        print("  Check: network connectivity, testnet RPC availability.")
        sys.exit(1)

    print(f"Registering subnet on testnet with wallet {wallet.name}...")
    print(f"  Wallet coldkey: {wallet.coldkeypub.ss58_address}")
    print("  Network: test")

    try:
        result = subtensor.register_subnet(wallet=wallet)
    except _BT_RUNTIME_ERRORS as exc:
        print(f"ERROR: Subnet registration failed: {exc}")
        print("  Check: TAO balance (need ~1 TAO for registration), wallet configuration.")
        print("  Testnet faucet: https://test.taostats.io/faucet")
        sys.exit(1)

    if not result:
        print("ERROR: Subnet registration returned failure.")
        sys.exit(1)

    if isinstance(result, int):
        print(f"  Subnet registered. netuid={result}")
        print(f"  Use --netuid {result} with the miner/validator commands.")
    else:
        print("  Subnet registered successfully.")
        print("  Check the Bittensor dashboard for your assigned netuid,")
        print("  then use --netuid <id> with the miner/validator commands.")


def cmd_miner(args: argparse.Namespace) -> None:
    """Start a constitutional governance miner on testnet."""
    _check_bittensor()
    import asyncio
    import os

    import bittensor as bt
    from constitutional_swarm.bittensor.axon_server import MinerAxonServer
    from constitutional_swarm.bittensor.miner import ConstitutionalMiner
    from constitutional_swarm.bittensor.protocol import MinerConfig

    if not os.path.exists(args.constitution):
        print(f"ERROR: Constitution file not found: {args.constitution}")
        print("  Create a constitution.yaml or use the sample in examples/constitution.yaml")
        sys.exit(1)

    wallet = bt.wallet(name=args.wallet_name, hotkey=args.wallet_hotkey)

    try:
        subtensor = bt.subtensor(network="test")
    except _BT_RUNTIME_ERRORS as exc:
        print(f"ERROR: Could not connect to Bittensor testnet: {exc}")
        sys.exit(1)

    print(f"Starting Constitutional Miner on testnet (netuid={args.netuid})...")
    print(f"  Constitution: {args.constitution}")
    print(f"  Wallet: {wallet.name} / {wallet.hotkey_str}")

    async def _deliberation_handler(task: str, context: str, meta: dict) -> tuple[str, str]:
        """Default AI-assisted deliberation handler.

        In production, replace with human-in-the-loop or
        specialized LLM pipeline.
        """
        return (
            f"Governance judgment for domain {context}: "
            "this case requires balancing competing constitutional principles. "
            "After analysis, the recommended approach prioritizes safety "
            "while maintaining transparency.",
            "Balanced analysis considering all stakeholder perspectives "
            "and constitutional requirements.",
        )

    config = MinerConfig(
        constitution_path=args.constitution,
        agent_id=wallet.hotkey_str,
        capabilities=tuple(args.capabilities.split(","))
        if args.capabilities
        else ("governance-judgment",),
        domains=tuple(args.domains.split(",")) if args.domains else ("general",),
    )

    miner = ConstitutionalMiner(
        config=config,
        deliberation_handler=_deliberation_handler,
    )
    server = MinerAxonServer(miner)

    print(f"  Constitution hash: {miner.constitution_hash}")
    print(f"  Agent ID: {config.agent_id}")
    print(f"  Capabilities: {config.capabilities}")
    print(f"  Domains: {config.domains}")

    # Register on the metagraph
    subtensor.register(wallet=wallet, netuid=args.netuid)
    print(f"  Registered on metagraph (netuid={args.netuid})")

    # Set up axon with adapter layer handlers
    axon = bt.axon(wallet=wallet, port=args.port)
    axon.attach(
        forward_fn=server.forward,
        blacklist_fn=server.blacklist,
        verify_fn=server.verify,
        priority_fn=server.priority,
    )
    axon.serve(netuid=args.netuid, subtensor=subtensor)
    axon.start()

    print(f"  Axon serving on port {args.port}")
    print("  Miner is running. Press Ctrl+C to stop.")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        bt.logging.info("Miner running...")
        loop.run_forever()
    except KeyboardInterrupt:
        print("\nShutting down miner...")
        axon.stop()
        print(f"  Final stats: {miner.stats}")
    finally:
        loop.close()


def cmd_validator(args: argparse.Namespace) -> None:
    """Start a constitutional governance validator on testnet."""
    _check_bittensor()
    import asyncio
    import os
    import time

    import bittensor as bt
    from constitutional_swarm.bittensor.protocol import ValidatorConfig
    from constitutional_swarm.bittensor.subnet_owner import SubnetOwner
    from constitutional_swarm.bittensor.synapse_adapter import (
        GovernanceDeliberation,
        bt_to_judgment,
        deliberation_to_bt,
    )
    from constitutional_swarm.bittensor.validator import ConstitutionalValidator

    if not os.path.exists(args.constitution):
        print(f"ERROR: Constitution file not found: {args.constitution}")
        print("  Create a constitution.yaml or use the sample in examples/constitution.yaml")
        sys.exit(1)

    wallet = bt.wallet(name=args.wallet_name, hotkey=args.wallet_hotkey)

    try:
        subtensor = bt.subtensor(network="test")
    except _BT_RUNTIME_ERRORS as exc:
        print(f"ERROR: Could not connect to Bittensor testnet: {exc}")
        sys.exit(1)

    print(f"Starting Constitutional Validator on testnet (netuid={args.netuid})...")
    print(f"  Constitution: {args.constitution}")

    config = ValidatorConfig(
        constitution_path=args.constitution,
        peers_per_validation=args.peers,
        quorum=args.quorum,
        use_manifold=True,
    )

    validator = ConstitutionalValidator(config=config)
    owner = SubnetOwner(args.constitution)

    print(f"  Constitution hash: {validator.constitution_hash}")

    # Register on the metagraph
    subtensor.register(wallet=wallet, netuid=args.netuid)
    metagraph = subtensor.metagraph(netuid=args.netuid)

    print(f"  Registered. Metagraph has {metagraph.n} neurons.")
    print("  Validator is running. Press Ctrl+C to stop.")

    dendrite = bt.Dendrite(wallet=wallet)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        while True:
            # Refresh metagraph with retry/backoff
            for _attempt in range(3):
                try:
                    metagraph.sync()
                    break
                except _BT_RUNTIME_ERRORS as _exc:
                    if _attempt == 2:
                        print(f"  WARNING: metagraph.sync() failed after 3 attempts: {_exc}")
                    time.sleep(2**_attempt)

            # Register any new miners we discover
            for uid in range(metagraph.n):
                hotkey = metagraph.hotkeys[uid]
                if hotkey not in validator._known_miners:
                    validator.register_miner(hotkey)

            # Query miners with a governance case via adapter layer
            if metagraph.n > 0:
                case = owner.package_case(
                    "Periodic governance validation",
                    "general",
                )
                bt_syn = deliberation_to_bt(case.synapse)

                try:
                    responses = loop.run_until_complete(
                        dendrite(
                            axons=metagraph.axons,
                            synapse=bt_syn,
                            timeout=args.epoch_seconds * 0.8,
                        )
                    )
                except _BT_RUNTIME_ERRORS as _exc:
                    print(f"  WARNING: dendrite query failed: {_exc}")
                    responses = []

                for resp in responses:
                    if not isinstance(resp, GovernanceDeliberation):
                        continue
                    if not resp.has_response or resp.error_message is not None:
                        continue
                    try:
                        judgment = bt_to_judgment(resp)
                        validation = validator.validate(judgment)
                        owner.record_result(case, judgment, validation)
                    except (ValueError, KeyError):
                        continue

            # Compute and set weights every epoch
            weights = validator.compute_emission_weights()
            if weights:
                uids = list(range(metagraph.n))
                weight_values = [weights.get(metagraph.hotkeys[uid], 0.0) for uid in uids]
                try:
                    subtensor.set_weights(
                        wallet=wallet,
                        netuid=args.netuid,
                        uids=uids,
                        weights=weight_values,
                    )
                    print(f"  Set weights for {len(weights)} miners")
                except _BT_RUNTIME_ERRORS as _exc:
                    print(f"  WARNING: set_weights failed: {_exc}")

            print(f"  Stats: {validator.stats}")
            time.sleep(args.epoch_seconds)

    except KeyboardInterrupt:
        print("\nShutting down validator...")
        print(f"  Final stats: {validator.stats}")
    finally:
        loop.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Constitutional Governance Subnet - Testnet Deployment",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Register
    reg = subparsers.add_parser("register", help="Register subnet on testnet")
    reg.add_argument("--wallet-name", required=True)
    reg.add_argument("--wallet-hotkey", required=True)

    # Miner
    miner = subparsers.add_parser("miner", help="Start miner")
    miner.add_argument("--wallet-name", required=True)
    miner.add_argument("--wallet-hotkey", required=True)
    miner.add_argument("--constitution", required=True, help="Path to constitution YAML")
    miner.add_argument("--netuid", type=int, required=True)
    miner.add_argument("--port", type=int, default=8091)
    miner.add_argument("--capabilities", default="governance-judgment")
    miner.add_argument("--domains", default="general")

    # Validator
    val = subparsers.add_parser("validator", help="Start validator")
    val.add_argument("--wallet-name", required=True)
    val.add_argument("--wallet-hotkey", required=True)
    val.add_argument("--constitution", required=True, help="Path to constitution YAML")
    val.add_argument("--netuid", type=int, required=True)
    val.add_argument("--peers", type=int, default=3)
    val.add_argument("--quorum", type=int, default=2)
    val.add_argument("--epoch-seconds", type=int, default=60)

    args = parser.parse_args()

    if args.command == "register":
        cmd_register(args)
    elif args.command == "miner":
        cmd_miner(args)
    elif args.command == "validator":
        cmd_validator(args)


if __name__ == "__main__":
    main()
