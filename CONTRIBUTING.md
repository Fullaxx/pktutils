# Contributing to pktutils

Thanks for helping improve pktutils. This guide explains how to file an issue and how to send a change.

## Filing an issue

Before you file:
- Search the [existing issues](https://github.com/Fullaxx/pktutils/issues?q=is%3Aissue), open and closed. The problem may already be tracked.
- File one problem per issue. If you found three problems, file three issues and link them to each other.
- Write a title that states the symptom, for example "Port 65535 writes past the histogram array" rather than "histogram bug".

Every issue answers the five questions below, under these headings and in this order. New issues get the same headings from the [issue template](.github/ISSUE_TEMPLATE/issue.md).

### What is happening now?
Describe the current behavior:
- the tool and command line;
- the input;
- what you saw — quote output and error messages exactly.

### Why is it important?
- Who or what is affected, and how badly: wrong results, lost data, a crash, a misleading message?
- How common is the input that triggers it?

### What are the proposed changes?
Say what should change. A sketch of the fix (file, function, approach) is welcome but not required.

### What are the ramifications?
Say what else the change affects, for example:
- output or exit codes that scripts may rely on;
- other tools that share the code — every tool is built from `common/pcap_reader.c`;
- speed on large captures;
- compatibility with existing pcap files.

### What happens if we don't fix it?
Describe the cost of leaving it as it is:
- how it fails;
- how often;
- any workaround.

### Details
Finish with what someone needs to reproduce the problem:
- **Command:** the tool and its full command line, including environment variables such as `INVERTMATCH`.
- **Version:** the pktutils commit (`git rev-parse --short HEAD`).
- **Input format:** the input's link type and timestamp resolution. `capinfos file.pcap` shows both.
- **Sample:** a minimal pcap that triggers the problem.
  - Attach it zipped.
  - If the capture is sensitive, describe how to build an equivalent one (with tshark, editcap or scapy) instead. Never attach captures containing private data.
- **Output:** expected and actual output.
- **Code:** file and line references, if you know them.
- **Related:** issue numbers (`#N`).

## Labels

Each issue gets:
- one type label;
- one `priority:` label;
- at least one `area:` label;
- every category label that applies.

New issues start with `needs-triage`, which is removed once the other labels are set.

| Label | Kind | Use it for |
|---|---|---|
| `bug` | type | Something isn't working |
| `enhancement` | type | New feature, hardening, or other improvement |
| `documentation` | type | Improvements or additions to documentation |
| `question` | type | Further information is requested |
| `priority: high` | priority | Wrong results, data loss or crashes on common input; fix first |
| `priority: medium` | priority | Wrong results on less common input, or poor failure behavior |
| `priority: low` | priority | Edge cases, hardening and cleanup |
| `area: dissection` | area | Packet parsing chain: `process_*` in `pcap_reader.c`, `l1.h`-`l4.h` |
| `area: pcap-io` | area | Reading/writing pcap files: file loop, headers, `mypcap.c`, `pcap_writer.c` |
| `area: extraction` | area | `pex_*` tools and their command lines |
| `area: histogram` | area | `phist_*` tools |
| `area: build` | area | `compile.sh`, CI workflow, tests |
| `memory-safety` | category | Out-of-bounds access, undefined behavior or crashes |
| `data-integrity` | category | Input destroyed, output corrupt, or results silently incomplete |
| `wrong-results` | category | Packets matched or counted incorrectly (false positives/negatives) |
| `protocol-support` | category | Encapsulation, link type or file format not handled |
| `behavior-change` | category | The fix changes output or semantics users may rely on |
| `cleanup` | category | Code cleanup with no behavior change |
| `needs-triage` | status | New issue, not yet reviewed |
| `duplicate`, `invalid`, `wontfix` | resolution | Closing reasons |
| `good first issue`, `help wanted` | community | Good for newcomers / extra attention is needed |

## Sending a change

- Keep the tools free of dependencies beyond libc and POSIX. That is a design goal (see the [README](README.md)).
- Follow the [coding style](CODING_STYLE.md).
- Build both directories, with no new warnings:
  ```
  (cd histogram && ./compile.sh)
  (cd extraction && ./compile.sh)
  ```
- Check the change against a pcap that shows the problem, before and after. Where it helps, cross-check counts with `tcpdump` or `tshark`.
- Make one commit per issue:
  - a short imperative subject line;
  - a body that explains what changed and why;
  - a `Fixes #N` line, so the issue closes when the change reaches master.
- Call out any behavior change (output, exit status, what matches) in the commit message and in the pull request.
