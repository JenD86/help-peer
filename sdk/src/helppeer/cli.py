"""Help Peer CLI entry point."""
import argparse
import json
import sys

from . import send, receive, cancel, configure


def main():
    parser = argparse.ArgumentParser(
        prog="helppeer",
        description="Asynchronous ephemeral file transfer for AI model weights",
    )
    parser.add_argument("--relay", default=None, help="Relay server URL")
    parser.add_argument("--nodes", default=None, help="Storage node URLs (comma-separated)")
    parser.add_argument("--json", action="store_true",
                        help="Machine-readable JSON output for agents/scripts")

    sub = parser.add_subparsers(dest="command", required=True)

    send_cmd = sub.add_parser("send", help="Send a file or directory")
    send_cmd.add_argument("path", help="Path to send")
    send_cmd.add_argument("--name", default="untitled-transfer", help="Transfer name")

    recv_cmd = sub.add_parser("receive", help="Receive a transfer")
    recv_cmd.add_argument("code", help="Transfer code (e.g., orbit-velvet-zoom-candle-harbor-ember)")
    recv_cmd.add_argument("--output", default="./received", help="Output directory")

    cancel_cmd = sub.add_parser("cancel", help="Cancel a transfer before it expires")
    cancel_cmd.add_argument("code", help="Transfer code")

    args = parser.parse_args()

    # CLI flags override HELPEER_* environment variables
    nodes = None
    if args.nodes is not None:
        nodes = [n.strip() for n in args.nodes.split(",") if n.strip()]
    configure(relay=args.relay, storage_nodes=nodes)

    try:
        if args.command == "send":
            _send(args)
        elif args.command == "cancel":
            _cancel(args)
        else:
            _receive(args)
    except Exception as e:  # report any failure cleanly instead of a traceback
        if args.json:
            print(json.dumps({"status": "error", "error": str(e)}, indent=2))
        else:
            print(f"✗ {args.command.capitalize()} failed: {e}", file=sys.stderr)
        sys.exit(1)


def _send(args):
    if not args.json:
        print(f"Help Peer — Sending: {args.path}")
        print(f"Transfer name: {args.name}")
        print()

    result = send(args.path, name=args.name, return_details=True)

    if args.json:
        print(json.dumps({"status": "ok", "path": args.path, **result}, indent=2))
        return
    print("✓ Upload complete!")
    print()
    print(f"  Transfer code: {result['code']}")
    print()
    print("  Share this code with the recipient.")
    print("  The data will be available for 24 hours.")


def _receive(args):
    if not args.json:
        print(f"Help Peer — Receiving into: {args.output}")
        print()

    result = receive(args.code, output_dir=args.output)

    if args.json:
        print(json.dumps({"status": "ok", **result}, indent=2))
        return
    print("✓ Download complete!")
    print()
    print(f"  Transfer: {result['transfer_name']}")
    print(f"  Files: {result['files']}")
    print(f"  Total size: {result['total_bytes']} bytes")
    print()
    print("  File hashes (BLAKE3, verified against sender):")
    for path, h in result["file_hashes"].items():
        print(f"  {path} → {h}")


def _cancel(args):
    result = cancel(args.code)

    if args.json:
        print(json.dumps({"status": "ok", **result}, indent=2))
        return
    print(f"✓ Transfer cancelled: {result['transfer_name']}")
    print(f"  Deleted {result['shards_deleted']} shards "
          f"({result['shards_already_gone']} had already expired or been deleted)")
    if result["shards_failed"]:
        print(f"  {result['shards_failed']} shards could not be deleted (node unreachable); "
              "they expire within 24 hours")


if __name__ == "__main__":
    main()
