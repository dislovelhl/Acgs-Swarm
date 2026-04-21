"""Convert run_swe_bench_swarm_lite.py JSON output to SWE-bench predictions format.

Examples
--------
Write filtered predictions to JSON::

    python scripts/convert_swarm_output_to_swebench_predictions.py run.json predictions.json

Write JSONL predictions for the official harness::

    python scripts/convert_swarm_output_to_swebench_predictions.py run.json predictions.jsonl

Include rows without generated patches and override the model name::

    python scripts/convert_swarm_output_to_swebench_predictions.py \
        run.json predictions.json --include-empty --model-name-or-path codex-default
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_swarm_output(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _extract_model_name(
    row: dict[str, Any],
    *,
    default_model_name: str | None,
) -> str:
    model_name = row.get("patch_metadata", {}).get("model")
    if model_name:
        return str(model_name)
    if default_model_name:
        return default_model_name
    instance_id = row.get("instance_id", "<unknown>")
    raise ValueError(
        f"Missing model_name_or_path for instance_id={instance_id}; "
        "set patch_metadata.model or pass --model-name-or-path."
    )


def _has_non_empty_patch(row: dict[str, Any]) -> bool:
    patch = row.get("patch", "")
    return isinstance(patch, str) and bool(patch.strip())


def convert_rows_to_predictions(
    rows: list[dict[str, Any]],
    *,
    include_empty: bool = False,
    default_model_name: str | None = None,
) -> list[dict[str, str]]:
    predictions: list[dict[str, str]] = []
    for row in rows:
        patch = row.get("patch", "")
        if not isinstance(patch, str):
            raise ValueError(
                f"Expected string patch for instance_id={row.get('instance_id', '<unknown>')}"
            )
        if not include_empty and not patch.strip():
            continue
        predictions.append(
            {
                "instance_id": str(row["instance_id"]),
                "model_patch": patch,
                "model_name_or_path": _extract_model_name(
                    row,
                    default_model_name=default_model_name,
                ),
            }
        )
    return predictions


def write_predictions(
    predictions: list[dict[str, str]],
    output_path: Path,
    *,
    output_format: str,
) -> None:
    if output_format == "jsonl":
        content = "".join(f"{json.dumps(prediction)}\n" for prediction in predictions)
    elif output_format == "json":
        content = json.dumps(predictions, indent=2)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")
    output_path.write_text(content)


def _infer_output_format(output_path: Path) -> str:
    suffix = output_path.suffix.lower()
    if suffix == ".jsonl":
        return "jsonl"
    return "json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Path to swarm runner summary JSON.")
    parser.add_argument("output", type=Path, help="Where to write SWE-bench predictions.")
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=["json", "jsonl"],
        default=None,
        help="Output format. Defaults to the output file extension (.jsonl -> jsonl, else json).",
    )
    parser.add_argument(
        "--include-empty",
        action="store_true",
        help="Include rows with empty patches instead of filtering them out.",
    )
    parser.add_argument(
        "--model-name-or-path",
        default=None,
        help="Override fallback model_name_or_path when patch_metadata.model is missing.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    swarm_output = load_swarm_output(args.input)
    rows = swarm_output.get("rows")
    if not isinstance(rows, list):
        raise SystemExit("Input JSON must contain a top-level rows list.")

    try:
        predictions = convert_rows_to_predictions(
            rows,
            include_empty=args.include_empty,
            default_model_name=args.model_name_or_path,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    output_format = args.output_format or _infer_output_format(args.output)
    write_predictions(predictions, args.output, output_format=output_format)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
