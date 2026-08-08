# wifi.py — Build Spec

A Python wrapper (`wifi.py`) that automates a hashcat WPA/WPA2 handshake cracking
sequence: base wordlist attack, then rule-based attacks, checking for a cracked
password after every attack and stopping the moment one is found.

## Core hashcat commands it wraps

- Base attack: `hashcat -m 22000 -a 0 <hash file> <wordlist>`
- Rule attack: `hashcat -m 22000 -a 0 <hash file> <wordlist> -r <rule file>`
- Check for a crack: `hashcat -m 22000 <hash file> --show`

## CLI flags (argparse-style, no `add_help` — see "Help flag" below)

- `-h, --hash <file>` — path to the `.hc22000` handshake file. **Required.**
  (This intentionally overrides argparse's default `-h`/help behavior — see below.)
- `-w, --wordlist <file>` — path to the wordlist for the base attack. **Required.**
- `-r, --rules <dir>` — path to a folder of hashcat rule files. **Optional,
  no default.** If omitted entirely, no rule-based attacks are attempted at
  all — only the base wordlist attack runs, followed by one `--show` check,
  then `no matches` if that didn't crack it. Rule attacks only happen when
  this flag is explicitly passed. When it is passed, only files directly
  inside that folder are used — any subfolder inside it is ignored (do not
  recurse).
- `-o, --outfile <file>` — **Optional.** If a password is cracked, append
  `password --> <password>` to this file (same format as the terminal
  output). If omitted, nothing is written to disk.
- `--resume` — resume the last interrupted run for this specific handshake
  file instead of starting over.
- `--help` — print tool description, usage, and flag definitions (ffuf-style),
  then exit. Must NOT be triggered by `-h`, since `-h` is repurposed for the
  hash file path. Check for `--help` in `sys.argv` before handing off to
  argparse, and construct the argparse parser with `add_help=False`.

## Attack sequence

1. Validate that the hash file and wordlist both exist; error out clearly if not.
2. Run the base wordlist attack (no `-r`).
3. After it finishes (exhausted or interrupted by hashcat itself), run
   `--show`. If it prints something, a password was found — stop everything.
4. If `--show` prints nothing **and `-r` was passed**, move to rule-based
   attacks: for each rule file in the rules folder (ordering — see below),
   run the wordlist+rule attack, then `--show` again. Stop as soon as
   `--show` prints something. **If `-r` was not passed, skip straight to
   step 6 (print `no matches`) instead of doing anything rule-related.**
5. If every rule file has been tried and `--show` still prints nothing after
   the last one, print `no matches` and exit.
6. (See step 4 — also reached directly when no `-r` was given.)

## Output when a password is found

Print `password --> <password>` to the terminal. `--show` output can contain
multiple lines (multiple networks in one handshake file) — print one
`password --> X` line per line returned. If `-o` was given, append each of
those lines to that file too.

## Rule ordering — "best first"

Rule files are not simply used in whatever order the OS lists them. Order is:

1. **Community-priority list first.** A hardcoded, user-editable list of rule
   filenames with a general reputation (hashcat/pentesting community) for
   being high-yield relative to their size — e.g. `best64.rule`, `best66.rule`,
   `d3ad0ne.rule`, `dive.rule`, `T0XIC.rule`/`TOXIC.rule`, `toggles1.rule`
   through `toggles5.rule`, `unix-ninja-leetspeak.rule`, `leetspeak.rule`,
   `Incisive-leetspeak.rule`, `InsidePro-PasswordsPro.rule`,
   `InsidePro-HashManager.rule`, `specific.rule`, `combinator.rule`,
   `rockyou-30000.rule`, `top10_2025.rule`. Any of these actually present in
   the rules folder run first, in this exact order. This list is meant to be
   edited freely as the user learns what actually works for their targets —
   it's a starting point, not a benchmark result.
2. **Everything else, sorted by file size descending** (biggest file first)
   — this is the fallback for any rule file not on the priority list, and it
   is also the entire ordering if nothing in the folder matches the priority
   list. Match filenames case-insensitively.

Rationale for the community-priority approach: file size or line count is not
a reliable proxy for "effectiveness" — a small, curated rule file can
outperform a much larger generated one. Effectiveness is reputation/
empirical, not something derivable from the file itself, so a hardcoded
editable list plus a sane fallback is the right shape.

## Terminal output format & live display

For every attack (base or rule-based):

- Right before it starts, print the exact hashcat command with `# started`
  appended, e.g.:
  `hashcat -m 22000 -a 0 <hash> <wordlist> -r <rule> # started`
- Right after it finishes, print the same command with `#done` appended:
  `hashcat -m 22000 -a 0 <hash> <wordlist> -r <rule> #done`

**Live display behavior (important — this took several iterations to get
right):**

- The `# started` line prints in **green**, the `#done` line prints in
  **red** (ANSI codes, e.g. `\033[92m` / `\033[91m` / reset `\033[0m`).
- Keep a running, in-memory log of every `# started`/`#done` line printed so
  far in this run, in order, each tagged with its color.
- Every time a new line is added to that log (a new `# started`, or a
  `#done`), **clear the terminal** (`\033[2J\033[H`) and **reprint the
  entire log from the top**, in order, correctly colored.
- This means: hashcat's own verbose live output (progress bars, status,
  etc.) gets wiped away each time a step finishes, and the user always sees
  the full, clean history of started/done lines at the top of the terminal
  without needing to scroll back through hashcat's noise. Do NOT just show
  the most recent 1–2 lines — show the complete history for the run.
- Do not print the `#done` line more than once — append it to the log
  exactly once, right when the step finishes (an earlier buggy version
  printed it both immediately after the step and again when redrawing for
  the next step — avoid that).
- When resuming with `--resume`, the resumed step's `# started` line is
  skipped (see below — a `#resuming` line is printed instead), but its
  `#done` line still gets logged normally as usual.

## Resume behavior

- Progress must persist across process restarts (the user may Ctrl+C at any
  point), and must be **unique per handshake file** — resuming one handshake
  file's attack must never resume or interfere with a different handshake
  file's progress.
- Implementation: a small JSON state file per handshake, stored under something
  like `~/.wifi_py/resume/<sha256 of the absolute handshake file path>.json`,
  containing at least: the absolute handshake path, the index of the step
  that was last *started* (not necessarily completed), and the exact command
  string for that step.
- State is saved right before each step starts running (not after it
  completes) — this is what makes resume correct: if the process is killed
  mid-attack, the saved step index points at the interrupted step, so resume
  reruns that exact step rather than skipping it or rerunning an earlier
  completed one.
- Without `--resume`: always start over from step 0, and discard/overwrite
  any existing state file for that handshake.
- With `--resume`: look up the state file for that specific handshake file.
  - If found: print the stored command with `#resuming` appended (plain,
    not colored/logged the same way as a normal `# started`), then resume
    execution from that exact step and continue the sequence normally from
    there (no re-running of earlier, already-completed steps).
  - If not found: print `error: no resume file found` and exit.
- On success (password found) or on exhausting all rules (`no matches`),
  clear/delete the state file — the run is complete, nothing left to resume.

## Help text

`--help` output should look like a normal CLI tool (ffuf-style): a short
description of what the tool does, a `Usage:` block with the invocation
pattern, a `Flags:` block defining every flag (short, long, and what it
does), and a couple of concrete `Examples:`. Include a short note on where
resume state lives and that it's per-handshake-file.

## Misc / edge cases worth keeping

- Validate the hash file and wordlist exist up front; fail with a clear
  `error: ...` message rather than letting hashcat produce a confusing error.
- Catch `KeyboardInterrupt` around the main loop and print something like
  `interrupted - progress saved, resume with --resume` rather than a raw
  traceback.
- Only use files directly inside the rules folder — skip subdirectories
  entirely, don't recurse into them.

  
<img width="1920" height="171" alt="image1" src="https://github.com/user-attachments/assets/26961049-55e0-41aa-b429-fb610bf88838" />







<img width="1920" height="1039" alt="image2" src="https://github.com/user-attachments/assets/458eb07f-0810-4bf6-a973-decdad83bf9a" />







<img width="1920" height="171" alt="image3" src="https://github.com/user-attachments/assets/282e28b3-dec0-42c3-a690-76778c413807" />

