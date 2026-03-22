# CVE Triage Agent — Security Research Project

A LangChain agent that triages CVEs from the NVD feed, then gets deliberately attacked.

Built to understand how AI agents fail in security-critical contexts — specifically the attack classes that matter for agentic AI safety research.

---

## What it does

Pulls CVE data from the NVD API, scores severity, searches for public exploits, and writes triage reports organised by date. You can point it at a specific CVE, a date, or a date range.
```bash
python3 -m agent.taskbot CVE-2021-44228
python3 -m agent.taskbot --date 2024-03-15
python3 -m agent.taskbot --range 2024-01-01 2024-01-31 --severity HIGH
```

Reports are generated as HTML files in `reports/YYYY-MM-DD/` with an index page.

---

## Why it exists

CVE triage is a good target for security research because the agent has real tools with real consequences — it reads from external APIs, scores vulnerabilities, and writes reports that humans act on. If you can manipulate its output, you can cause real vulnerabilities to go unpatched.

This project builds the agent, then attacks it across four threat categories, documents what broke and why, and implements defenses.

---

