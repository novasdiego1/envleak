# envleak

**Find your exposed API keys before someone else does.**

One command. No config. Nothing ever leaves your machine.

```bash
pipx run envleak
```

```
  ┌────────────────────────────────────────────┐
  │            E N V L E A K   S C A N         │
  └────────────────────────────────────────────┘

   F   █░░░░   Crítico

   5 hallazgo(s) en 128 archivos
   5 critical

   ⚡ 2 en la superficie de agentes/LLM

   ✗ ARCHIVOS DE ENTORNO RASTREADOS POR GIT:
     .env

   CRIT  Anthropic API key
         .env:2
         ANTHROPIC_API_KEY=sk-a********o9Pq

   CRIT  GitHub token
         .config/mcp.json:1
         {"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":"ghp_********3zA5"}}}}
```

---

## Why another secret scanner?

There are good ones already — `gitleaks` and `trufflehog` scan git history
and belong in your CI pipeline. `envleak` is for a different moment: **right
now, on your laptop, in ten seconds, with a grade you can screenshot.**

Two things it does that the others don't:

**1. It scans the agent surface.** Everyone is shipping AI agents in 2026,
and the credentials moved with them — MCP server configs, `claude_desktop_config.json`,
n8n and LangGraph workflows, notebooks, LLM provider keys pasted into JSON.
`envleak` knows what an OpenAI, Anthropic, Groq, LangSmith or Hugging Face key
looks like and where agent tooling hides them.

**2. It gives you a grade, not a JSON dump.** A 400-line report gets closed.
An `F` gets fixed.

## Install

```bash
pipx run envleak          # no install, just run it
pip install envleak       # or keep it around
```

Python 3.8+. Zero dependencies.

## Use

```bash
envleak                   # scan current directory
envleak ~/code/myproject  # scan somewhere else
envleak --markdown        # scorecard ready to paste in an issue or PR
envleak --json            # machine-readable, for pipelines
```

### In CI

Exits `1` when it finds anything `high` or worse:

```yaml
- run: pipx run envleak --fail-on critical
```

```bash
envleak --fail-on none    # report only, never fail
```

## What it looks for

| Surface | Examples |
|---|---|
| **AI / agents** | OpenAI, Anthropic, Google AI, Groq, Mistral, Hugging Face, Replicate, LangSmith, Perplexity, MCP configs |
| **Cloud / infra** | AWS access keys, GCP service accounts, private key blocks, Docker registry auth |
| **Classic** | GitHub, GitLab, Stripe, Slack, Telegram, SendGrid, Twilio, JWTs, database URLs with passwords |
| **Generic** | High-entropy values assigned to `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD` — in config files only |

It also flags the thing that actually causes breaches: **`.env` files tracked
by git.**

## Privacy

This is a security tool, so the guarantee matters more than the feature list:

- **It makes no network calls.** None. Read the source — it's a few hundred
  lines with zero dependencies.
- **Secrets are redacted in output.** You see `sk-a********o9Pq`, never the
  full key, so a screenshot is safe to post.
- Nothing is written anywhere except stdout.

## False positives

The generic entropy check runs **only in config files** (`.env`, `.json`,
`.yaml`, `.toml`, `.ini`). In source code it fires on ordinary expressions
like `key = key.upper()` and buries the real findings, so it doesn't run there.

Template files (`.env.example`, `*.sample`, `*.template`) are downgraded, and
documentation credentials (`user:password@localhost`) are ignored.

Found a false positive? [Open an issue](https://github.com/novasdiego1/envleak/issues)
with the pattern — that feedback is the whole roadmap.

## What it is not

`envleak` scans your **working tree**, not git history. If a key was committed
and later deleted, it's still in your history and still compromised — use
`trufflehog` for that, and rotate the key regardless.

Finding a key is step one. **Rotate it.** A key that appeared in this scan
should be considered burned.

## License

MIT
