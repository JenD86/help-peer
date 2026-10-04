"""Help Peer CLI entry point."""
import argparse
import json
import sys

from . import send, receive, info, cancel, configure, login, logout, inbox
from .manifest import printable


def _add_global_options(p, **default):
    p.add_argument("--relay", **default,
                   help="Relay server URL (default: $HELPEER_RELAY_URL, then the logged-in site's)")
    p.add_argument("--nodes", **default,
                   help="Storage node URLs, comma-separated (default: $HELPEER_STORAGE_NODES, then the site's)")
    p.add_argument("--json", action="store_true", **default,
                   help="Machine-readable JSON on stdout (diagnostics go to stderr)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="helppeer",
        description="Asynchronous ephemeral file transfer for AI model weights",
    )
    _add_global_options(parser)
    # The same options on every subcommand, so they also work after it (like
    # the Rust CLI): `helppeer receive CODE --json`. Their default is SUPPRESS
    # so they don't overwrite a value given before the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    _add_global_options(common, default=argparse.SUPPRESS)

    sub = parser.add_subparsers(dest="command", required=True)

    send_cmd = sub.add_parser("send", parents=[common], help="Send a file or directory")
    send_cmd.add_argument("path", help="Path to send")
    send_cmd.add_argument("--name", default="untitled-transfer", help="Transfer name")
    send_cmd.add_argument("--to", help="Recipients, comma-separated: usernames (alice or @alice) get it in "
                                       "their inbox, emails get the code by email. Needs `login`.")
    send_cmd.add_argument("--message", help="A note describing the transfer (up to 2000 characters). Recipients "
                                            "see it with the files, in their inbox and in notification emails.")

    recv_cmd = sub.add_parser("receive", parents=[common], help="Receive a transfer")
    recv_cmd.add_argument("code", help="Transfer code (e.g., orbit-velvet-zoom-candle-harbor-ember)")
    recv_cmd.add_argument("--output", default="./received", help="Output directory")

    info_cmd = sub.add_parser("info", parents=[common],
                              help="Show a transfer's name, message and files without downloading it")
    info_cmd.add_argument("code", help="Transfer code")

    cancel_cmd = sub.add_parser("cancel", parents=[common], help="Cancel a transfer before it expires")
    cancel_cmd.add_argument("code", help="Transfer code")

    sub.add_parser("inbox", parents=[common], help="List transfers sent to your username (needs `login`)")

    login_cmd = sub.add_parser("login", parents=[common], help="Log in to a Help Peer website with an API token "
                                             "(create one on its Account page)")
    login_cmd.add_argument("--server", required=True, help="Website URL, e.g. https://helppeer.example.com")
    login_cmd.add_argument("--token", required=True, help="API token (hp_...)")

    sub.add_parser("logout", parents=[common], help="Forget the saved login")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # CLI flags override HELPEER_* environment variables
    nodes = None
    if args.nodes is not None:
        nodes = [n.strip() for n in args.nodes.split(",") if n.strip()]
    configure(relay=args.relay, storage_nodes=nodes)

    try:
        {
            "send": _send, "receive": _receive, "info": _info, "cancel": _cancel,
            "inbox": _inbox, "login": _login, "logout": _logout,
        }[args.command](args)
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

    to = [r.strip() for r in args.to.split(",") if r.strip()] if args.to else None
    result = send(args.path, name=args.name, to=to, message=args.message, return_details=True)

    if args.json:
        print(json.dumps({"status": "ok", "path": args.path, **result}, indent=2))
        return
    print("✓ Upload complete!")
    print()
    print(f"  Transfer code: {result['code']}")
    print()
    if result["recipients"]:
        print(f"  Sent to: {', '.join(result['recipients'])}")
        print("  (usernames get it in their inbox; email addresses get the code by email)")
    else:
        print("  Share this code with the recipient.")
    print("  The data will be available for 24 hours.")


def _receive(args):
    if not args.json:
        print(f"Help Peer — Receiving into: {args.output}")
        print()

    result = receive(args.code, output_dir=args.output)

    if args.json:
        # Same shape as the Rust CLI's output.
        print(json.dumps({
            "status": "ok",
            "transfer_name": result["transfer_name"],
            "message": result["message"],
            "total_bytes": result["total_bytes"],
            "files": result["file_list"],
            "acknowledged": result["acknowledged"],
            "resumed_segments": result["resumed_segments"],
        }, indent=2))
        return
    print("✓ Download complete!")
    print()
    print(f"  Transfer: {printable(result['transfer_name'])}")
    _print_message(result["message"])
    print(f"  Files: {result['files']}")
    print(f"  Total size: {result['total_bytes']} bytes")
    print()
    print("  File hashes (BLAKE3, verified against sender):")
    for path, h in result["file_hashes"].items():
        print(f"  {printable(path)} → {h}")


def _cancel(args):
    result = cancel(args.code)

    if args.json:
        print(json.dumps({"status": "ok", **result}, indent=2))
        return
    print(f"✓ Transfer cancelled: {result['transfer_name']}")
    print(f"  Deleted {result['shards_deleted']} shards "
          f"({result['shards_already_gone']} had already expired or been deleted)")
    if result["shards_failed"]:
        print(f"  {result['shards_failed']} shards could not be deleted (node unreachable, or the same "
              "data is shared with another transfer); "
              "they expire within 24 hours")


def _print_message(message):
    if message and message.strip():
        print("  Message from sender:")
        for line in printable(message).splitlines():
            print(f"    │ {line}")


def _info(args):
    result = info(args.code)
    if args.json:
        print(json.dumps({"status": "ok", **result}, indent=2))
        return
    print(f"Transfer: {printable(result['transfer_name'])}")
    _print_message(result["message"])
    print(f"Total size: {result['total_bytes']} bytes in {len(result['files'])} file(s)")
    for f in result["files"]:
        print(f"  {printable(f['path'])}  ({f['size']} bytes)")
    print()
    print(f"Receive with: helppeer receive {args.code}")


def _inbox(args):
    items = inbox()
    if args.json:
        print(json.dumps({"status": "ok", "items": items}, indent=2))
        return
    if not items:
        print("Nothing waiting for you.")
    for item in items:
        sender = f"@{item['sender_username']}" if item.get("sender_username") else item.get("sender_email", "?")
        print(f"{printable(item.get('transfer_name') or 'untitled')} — from {printable(sender)} "
              f"({item['files']} file(s), {item['total_bytes']} bytes, expires {item['expires_at']})")
        for line in printable(item.get("message") or "").splitlines():
            print(f"  │ {line}")
        print(f"  helppeer receive {item['code']}")


def _login(args):
    result = login(args.server, args.token)
    if args.json:
        print(json.dumps({"status": "ok", **result}, indent=2))
        return
    who = f"{result['email']} (@{result['username']})" if result["username"] else result["email"]
    print(f"✓ Logged in to {result['server']} as {who}")
    print(f"  Saved to {result['config']}")


def _logout(args):
    removed = logout()
    if args.json:
        print(json.dumps({"status": "ok", "was_logged_in": removed}, indent=2))
        return
    print("✓ Logged out" if removed else "Not logged in")


if __name__ == "__main__":
    main()
