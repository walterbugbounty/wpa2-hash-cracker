#!/usr/bin/env python3
"""
Wifi.py - Automated WPA/WPA2 handshake cracking wrapper around hashcat.
"""

import argparse
import os
import sys
import json
import hashlib
import subprocess

STATE_DIR = os.path.expanduser("~/.wifi_py/resume")

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def clear_terminal():
    print("\033[2J\033[H", end="")


# Rule files with a general community reputation (hashcat/pentesting circles)
# for being high-yield relative to their size. Checked in this order — the
# first entries are the ones most commonly recommended first. Anything in
# your rules folder that matches a name here runs before everything else, in
# this order. Anything not listed, or if nothing here matches, falls back to
# size-sort (biggest file first). Edit this list freely as you learn what
# actually works for your targets.
PRIORITY_RULES = [
    "best64.rule",
    "best66.rule",
    "d3ad0ne.rule",
    "rockyou-30000.rule",
    "top10_2025.rule",
    "dive.rule",
    "T0XIC.rule",
    "TOXIC.rule",
    "InsidePro-PasswordsPro.rule",
    "InsidePro-HashManager.rule",
    "combinator.rule",
    "unix-ninja-leetspeak.rule",
    "leetspeak.rule",
    "Incisive-leetspeak.rule",
    "toggles1.rule",
    "toggles2.rule",
    "toggles3.rule",
    "toggles4.rule",
    "toggles5.rule",
    "specific.rule",
]
PRIORITY_LOOKUP = {name.lower(): i for i, name in enumerate(PRIORITY_RULES)}

HELP_TEXT = """Wifi.py - Automated WPA/WPA2 handshake cracking wrapper around hashcat

Runs hashcat against a .hc22000 handshake file using a wordlist. By default
that's the only attack — pass -r to also cycle through rule files (biggest
file first) if the wordlist alone doesn't crack it. After every attack it
checks `hashcat -m 22000 --show` and stops the moment a password is
recovered.

Usage:
  python3 Wifi.py -h <path to .hc22000 file> -w <path to wordlist>
  python3 Wifi.py -h <path to .hc22000 file> -w <path to wordlist> -r <path to rules folder> -o <path to output file>
  python3 Wifi.py -h <path to .hc22000 file> -w <path to wordlist> --resume

Flags:
  -h, --hash <file>       Path to the .hc22000 handshake file to attack (required)
  -w, --wordlist <file>   Path to the wordlist to use for the base attack (required)
  -r, --rules <dir>       Path to a folder of hashcat rule files. Not used
                           unless you pass this flag — no rule attacks are
                           attempted by default. Files with a general
                           community reputation for being high-yield
                           (best64, dive, d3ad0ne, toggles, etc.) run first,
                           in that order, if present. Everything else runs
                           after, largest file first. Subfolders are ignored.
  -o, --outfile <file>    Path to a file to append the cracked password to,
                           if one is found
  --resume                Resume the last interrupted attack for this specific
                           handshake file, without re-running completed steps
  --help                  Show this help message and exit

Examples:
  python3 Wifi.py -h ~/Handshakes/Password/handshake.hc22000 -w /usr/share/wordlists/seclists/Custom/my-wordlist.txt
  python3 Wifi.py -h ~/Handshakes/Password/handshake.hc22000 -w /usr/share/wordlists/seclists/Custom/my-wordlist.txt -r /usr/share/hashcat/rules/ -o ~/Documents/password.file
  python3 Wifi.py -h ~/Handshakes/Password/handshake.hc22000 -w /usr/share/wordlists/seclists/Custom/my-wordlist.txt --resume

Resume state:
  Progress is tracked per handshake file in:
    ~/.wifi_py/resume/<sha256 of absolute handshake path>.json
  Each file stores the absolute handshake path, the index of the step that
  was last started, and the exact command for that step. This means two
  different handshake files can be interrupted and resumed independently
  without clashing with each other.
"""


def print_help_and_exit():
    print(HELP_TEXT)
    sys.exit(0)


def parse_args():
    argv = sys.argv[1:]
    if "--help" in argv:
        print_help_and_exit()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--hash", dest="hashfile", required=True)
    parser.add_argument("-w", "--wordlist", dest="wordlist", required=True)
    parser.add_argument("-r", "--rules", dest="rules_dir", default=None)
    parser.add_argument("-o", "--outfile", dest="outfile", default=None)
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args(argv)


def state_path(hashfile):
    abspath = os.path.abspath(os.path.expanduser(hashfile))
    key = hashlib.sha256(abspath.encode()).hexdigest()
    return os.path.join(STATE_DIR, f"{key}.json")


def save_state(hashfile, step_index, command):
    os.makedirs(STATE_DIR, exist_ok=True)
    data = {
        "hashfile": os.path.abspath(os.path.expanduser(hashfile)),
        "step_index": step_index,
        "command": command,
    }
    with open(state_path(hashfile), "w") as f:
        json.dump(data, f)


def load_state(hashfile):
    p = state_path(hashfile)
    if not os.path.exists(p):
        return None
    with open(p) as f:
        return json.load(f)


def clear_state(hashfile):
    p = state_path(hashfile)
    if os.path.exists(p):
        os.remove(p)


def get_rule_files(rules_dir):
    rules_dir = os.path.expanduser(rules_dir)
    if not os.path.isdir(rules_dir):
        return []
    files = []
    for entry in os.listdir(rules_dir):
        full = os.path.join(rules_dir, entry)
        if os.path.isfile(full):
            files.append(full)

    priority_files = [f for f in files if os.path.basename(f).lower() in PRIORITY_LOOKUP]
    priority_files.sort(key=lambda f: PRIORITY_LOOKUP[os.path.basename(f).lower()])

    remaining_files = [f for f in files if os.path.basename(f).lower() not in PRIORITY_LOOKUP]
    remaining_files.sort(key=os.path.getsize, reverse=True)

    return priority_files + remaining_files


def build_steps(hashfile, wordlist, rules_dir):
    hashfile = os.path.abspath(os.path.expanduser(hashfile))
    wordlist = os.path.abspath(os.path.expanduser(wordlist))
    steps = [["hashcat", "-m", "22000", "-a", "0", hashfile, wordlist]]
    if rules_dir:
        for rule in get_rule_files(rules_dir):
            steps.append(["hashcat", "-m", "22000", "-a", "0", hashfile, wordlist, "-r", rule])
    return steps


def check_show(hashfile):
    hashfile = os.path.abspath(os.path.expanduser(hashfile))
    result = subprocess.run(
        ["hashcat", "-m", "22000", hashfile, "--show"],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main():
    args = parse_args()

    if not os.path.isfile(os.path.expanduser(args.hashfile)):
        print(f"error: handshake file not found: {args.hashfile}")
        sys.exit(1)
    if not os.path.isfile(os.path.expanduser(args.wordlist)):
        print(f"error: wordlist not found: {args.wordlist}")
        sys.exit(1)

    steps = build_steps(args.hashfile, args.wordlist, args.rules_dir)
    start_index = 0
    log_lines = []  # every #started / #done line for this run, in order

    def render_log():
        clear_terminal()
        for text, color in log_lines:
            print(f"{color}{text}{RESET}")

    if args.resume:
        state = load_state(args.hashfile)
        if state is None:
            print("error: no resume file found")
            sys.exit(1)
        start_index = state["step_index"]
        print(f"{state['command']} #resuming")
    else:
        clear_state(args.hashfile)

    try:
        for i in range(start_index, len(steps)):
            cmd = steps[i]
            cmd_str = " ".join(cmd)
            started_line = f"{cmd_str} # started"

            save_state(args.hashfile, i, cmd_str)

            if not (args.resume and i == start_index):
                log_lines.append((started_line, GREEN))
                render_log()

            subprocess.run(cmd)

            done_line = f"{cmd_str} #done"
            log_lines.append((done_line, RED))
            render_log()

            found = check_show(args.hashfile)
            if found:
                for line in found.splitlines():
                    parts = line.split(":")
                    password = parts[-1] if parts else line
                    out_line = f"password --> {password}"
                    print(out_line)
                    if args.outfile:
                        with open(os.path.expanduser(args.outfile), "a") as f:
                            f.write(out_line + "\n")
                clear_state(args.hashfile)
                sys.exit(0)

        print("no matches")
        clear_state(args.hashfile)

    except KeyboardInterrupt:
        print("\ninterrupted - progress saved, resume with --resume")
        sys.exit(1)


if __name__ == "__main__":
    main()
