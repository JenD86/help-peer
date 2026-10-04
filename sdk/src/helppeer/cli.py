"""Help Peer CLI entry point."""
import sys
import argparse
from . import send, receive, configure


def main():
    parser = argparse.ArgumentParser(
        prog="helppeer",
        description="Asynchronous ephemeral file transfer for AI model weights",
    )
    parser.add_argument("--relay", default="http://127.0.0.1:7000", help="Relay server URL")
    parser.add_argument("--nodes", default="http://127.0.0.1:7001",
                        help="Storage node URLs (comma-separated)")

    sub = parser.add_subcommands(dest="command", required=True)

    send_cmd = sub.add_parser("send", help="Send a file or directory")
    send_cmd.add_argument("path", help="Path to send")
    send_cmd.add_argument("--name", default="untitled-transfer", help="Transfer name")

    recv_cmd = sub.add_parser("receive", help="Receive a transfer")
    recv_cmd.add_argument("code", help="Transfer code (e.g., 38-vortex-xenon)")
    recv_cmd.add_argument("--output", default="./received", help="Output directory")

    args = parser.parse_args()

    # Configure from CLI args
    nodes = [n.strip() for n in args.nodes.split(",") if n.strip()]
    configure(relay=args.relay, storage_nodes=nodes)

    if args.command == "send":
        print(f"Help Peer — Sending: {args.path}")
        print(f"Transfer name: {args.name}")
        print(f"Relay: {args.relay}")
        print(f"Storage nodes: {len(nodes)} (total)")
        print()

        code = send(args.path, name=args.name)
        print()
        print("✓ Upload complete!")
        print()
        print(f"  Transfer code: {code}")
        print()
        print("  Share this code with the recipient.")
        print("  The data will be available for 24 hours.")

    elif args.command == "receive":
        print(f"Help Peer — Receiving with code: {args.code}")
        print(f"Output directory: {args.output}")
        print(f"Relay: {args.relay}")
        print()

        result = receive(args.code, output_dir=args.output)
        print()
        print("✓ Download complete!")
        print()
        print(f"  Transfer: {result['transfer_name']}")
        print(f"  Files: {result['files']}")
        print(f"  Total size: {result['total_bytes']} bytes")
        print()
        print("  File hashes (BLAKE3):")
        for path, h in result["file_hashes"].items():
            print(f"  {path} → {h}")


if __name__ == "__main__":
    main()
