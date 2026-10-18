---
name: sandbox
description: Sandbox facts the model does not know. agent-browser sessions, exec_command tty, caido_api, and the preinstalled Python environment.
template: jinja
---

# Sandbox

The tools are installed. Read `--help` before inventing flags. Do not reimplement nmap, nuclei, ffuf, sqlmap, or semgrep in Python when the tool already does the job.

## Python

`exec_command` is the Python runner. Put the interpreter in `cmd` (`python3 script.py` or `python3 -c '...'`). `shell=` selects bash, zsh, or sh. It does not select Python.

`python3` and `pip` point at `/app/.venv`. Already installed: `requests`, `httpx`, `beautifulsoup4`, `lxml`, `pyjwt`, `cryptography`. Anything else: `uv pip install --python /app/.venv/bin/python <package>` before the import.

Write a PoC to a task-unique file with `apply_patch` and rerun it. `HTTP_PROXY` already sends `curl`, `requests`, and `httpx` through Caido.

Proxy automation is the `caido_api` module, and the helpers are async:

```python
from caido_api import list_requests, view_request, repeat_request, list_sitemap, view_sitemap_entry, scope_rules
```

`repeat_request(request_id, modifications=)` accepts `url`, `params`, `headers`, `body`, and `cookies`.

## Interactive processes

`exec_command` is a fresh non-interactive shell. `sqlmap`, `ssh`, `nc`, and anything that reads stdin need `exec_command(cmd="...", tty=true)` and then `write_stdin`. `write_stdin` on a non-TTY command fails with "stdin is not available."

## agent-browser

Invoke `agent-browser` via `exec_command`. Do not pass `--proxy`; the sandbox proxy env is already set, and localhost CDP is excluded.

The default session is shared. Pass `--session <your-agent-name>` on every command or another agent will navigate your page out from under you. Hold one session and `close` it when you finish. An idle browser is reclaimed after a few minutes; cookies and refs die with it. `state save` / `--state` keeps a login across that.

Refs (`@e1`) are stale after any navigation or re-render. The loop is `open`, `snapshot -i`, act, then snapshot again. Wait on an element, a URL, or `--load networkidle`. A bare `wait 2000` is a last resort.

{% if supports_images %}
`agent-browser screenshot` only writes a PNG. Pass the printed path to `view_image`. The default directory is `/workspace/.agent-browser-screenshots/`. `view_image` rejects paths outside the workspace. Prefer `snapshot -i`; take a screenshot when you need pixels. If `view_image` says vision is unsupported, stay on the snapshot.
{% else %}
You cannot view images. Drive the page from `snapshot -i`, `eval`, and `get text`. A screenshot is only a file on disk.
{% endif %}
