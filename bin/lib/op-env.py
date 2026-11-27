#!/usr/bin/env python3
"""op-env -- a jailed seat's way into a signed environment.

python3 -I /engine/op-env.py --env NAME [--timeout S] -- <cmd...>

The command runs in the environment the program's charter signed, with this
seat's staged directory (/w/envwork) as /work. The engine launches it through
the one container door and files a receipt; this client only carries the ask
and brings the answer back. It holds no socket of the daemon and has no say
in anything else: the image, the devices, the mounts, the limits and the
network are the signed spec's.

usage: op-env.py --env NAME [--timeout S] -- <cmd...>
env: OPERATOR_ENV_SOCKET (the jail's environment socket; spawn.py plants it
     for a seat with env grants)
exit: the command's own code; 1 the door refused (the message names the fix);
      2 no socket in this jail, or a bad ask
"""
import json
import os
import socket
import sys

USAGE = ("usage: op-env.py --env NAME [--timeout S] -- <cmd...>\n"
         "stage what the command needs under /w/envwork (it is /work inside)")


def main(argv):
    sock_path = os.environ.get("OPERATOR_ENV_SOCKET")
    env = timeout = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--env" and i + 1 < len(argv) and argv[i + 1] != "--":
            env = argv[i + 1]
            i += 2
        elif a == "--timeout" and i + 1 < len(argv) and argv[i + 1] != "--":
            timeout = argv[i + 1]
            i += 2
        elif a == "--":
            cmd = argv[i + 1:]
            break
        else:
            print(f"op-env: {USAGE}", file=sys.stderr)
            return 2
    else:
        cmd = []
    if not env or not cmd:
        print(f"op-env: {USAGE}", file=sys.stderr)
        return 2
    req = {"env": env, "argv": cmd}
    if timeout is not None:
        try:
            req["timeout"] = float(timeout)
        except ValueError:
            print("op-env: --timeout is a number of seconds", file=sys.stderr)
            return 2
    if not sock_path or not os.path.exists(sock_path):
        print("op-env: no environment socket in this jail: the seat holds no env grant "
              "(the seat's env in team.toml, docs/charter.md)", file=sys.stderr)
        return 2
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(90000)
        s.connect(sock_path)
        s.sendall(json.dumps(req).encode("utf-8"))
        s.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > 2 * 1024 * 1024:
                break
        s.close()
    except OSError as e:
        print(f"op-env: the environment door didn't answer: {e}", file=sys.stderr)
        return 2
    try:
        ans = json.loads(data.decode("utf-8") or b"null")
    except (ValueError, UnicodeDecodeError):
        print("op-env: the environment door answered nothing readable", file=sys.stderr)
        return 2
    if not isinstance(ans, dict):
        print("op-env: the environment door answered nothing readable", file=sys.stderr)
        return 2
    if "refused" in ans:
        print(f"op-env: REFUSED: {ans['refused']}", file=sys.stderr)
        return 1
    if "void" in ans or "rc" not in ans:
        print(f"op-env: VOID: {ans.get('void', 'no exit code came back')}", file=sys.stderr)
        return 2
    sys.stdout.write(ans.get("out", ""))
    note = " (aborted with the turn)" if ans.get("aborted") else ""
    print(f"op-env: {ans['env']} rc={ans['rc']} secs={ans['secs']} receipt={ans['receipt']}{note}",
          file=sys.stderr)
    return ans["rc"] if isinstance(ans["rc"], int) else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
