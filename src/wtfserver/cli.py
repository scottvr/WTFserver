"""whatami CLI: collect, analyze, inspect."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import __version__
from .analysis import run_analysis
from .bundle import Bundle, BundleError
from .model import utc_now
from .timeparse import SinceParseError, parse_since


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BundleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whatami",
        description="What does this machine appear to do? "
        "Collect local evidence, analyze it offline, report with provenance.",
    )
    parser.add_argument("--version", action="version", version=f"whatami {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_collect = sub.add_parser("collect", help="collect local evidence into a .wtf bundle")
    _add_collect_args(p_collect)
    p_collect.set_defaults(func=cmd_collect)

    p_analyze = sub.add_parser("analyze", help="analyze a .wtf bundle and report")
    p_analyze.add_argument("bundle", help="path to a .wtf bundle (zip or directory)")
    _add_analyze_args(p_analyze)
    p_analyze.set_defaults(func=cmd_analyze)

    p_inspect = sub.add_parser(
        "inspect", help="collect to a temporary bundle and analyze it in one step"
    )
    _add_collect_args(p_inspect)
    _add_analyze_args(p_inspect)
    p_inspect.set_defaults(func=cmd_inspect)

    return parser


def _add_collect_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--since",
        default="72h",
        help="history window: 30m, 72h, 3d, 2w, 2026-08-01, or max (default: 72h)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="bundle output path (default: <host>-<timestamp>.wtf)",
    )
    parser.add_argument(
        "--max-events-per-channel",
        type=int,
        default=25000,
        help="cap on events collected per log channel (default: 25000)",
    )


def _add_analyze_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        nargs="?",
        const="-",
        default=None,
        metavar="PATH",
        help="emit machine-readable JSON (to PATH, or stdout if no PATH given)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="how many entries to keep in top-N frequency lists (default: 10)",
    )


def cmd_collect(args: argparse.Namespace) -> int:
    bundle_path, manifest = _do_collect(args)
    print(f"wrote {bundle_path} ({manifest['observation_count']} observations)")
    for record in manifest["collectors"]:
        status = record["status"]
        line = f"  {record['name']}: {status} ({record.get('observation_count', 0)} observations)"
        print(line)
        for err in record.get("errors", []):
            print(f"    ! {err}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    bundle = Bundle.load(args.bundle)
    return _analyze_and_report(bundle, args)


def cmd_inspect(args: argparse.Namespace) -> int:
    if args.output is None:
        tmp = Path(tempfile.mkdtemp(prefix="whatami-")) / "inspect.wtf"
        args.output = str(tmp)
    bundle_path, _ = _do_collect(args)
    bundle = Bundle.load(bundle_path)
    return _analyze_and_report(bundle, args)


def _do_collect(args: argparse.Namespace):
    from .collect import current_platform, default_output_path, run_collection

    if current_platform() != "windows":
        print(
            "error: collection currently supports Windows only "
            "(analysis of existing bundles works anywhere)",
            file=sys.stderr,
        )
        raise SystemExit(2)
    now = utc_now()
    try:
        since = parse_since(args.since, now)
    except SinceParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    output = Path(args.output) if args.output else default_output_path(now)
    return run_collection(
        since=since,
        output_path=output,
        requested_since=args.since,
        options={"max_events_per_channel": args.max_events_per_channel},
    )


def _analyze_and_report(bundle: Bundle, args: argparse.Namespace) -> int:
    from .report.json_out import render_json
    from .report.text import render_text

    result = run_analysis(bundle, options={"top_n": args.top})
    exit_code = 0
    if args.json is not None:
        payload = json.dumps(render_json(result), indent=2, ensure_ascii=False)
        if args.json == "-":
            print(payload)
        else:
            try:
                Path(args.json).write_text(payload + "\n", encoding="utf-8")
                print(f"wrote {args.json}", file=sys.stderr)
            except OSError as exc:
                print(f"error: cannot write {args.json}: {exc}", file=sys.stderr)
                exit_code = 2
    if args.json is None or args.json != "-":
        print(render_text(result))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
