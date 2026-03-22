import json
import os
import glob
import requests
from datetime import datetime, timedelta
from langchain.tools import tool


@tool
def fetch_cve(cve_id: str) -> str:
    """Fetch CVE details from NVD by CVE ID (e.g. CVE-2024-1234).
    Returns description, CVSS score, severity, CWE, and affected products."""
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers={"User-Agent": "cve-triage-agent/1.0"},
            timeout=15
        )
        resp.raise_for_status()
        data = resp.json()

        if not data.get("vulnerabilities"):
            return json.dumps({"error": f"{cve_id} not found in NVD"})

        vuln = data["vulnerabilities"][0]["cve"]
        description = next(
            (d["value"] for d in vuln.get("descriptions", []) if d["lang"] == "en"),
            "No description available"
        )

        metrics = vuln.get("metrics", {})
        cvss_data = (
            metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) or
            metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}) or
            metrics.get("cvssMetricV2",  [{}])[0].get("cvssData", {})
        )

        weaknesses = vuln.get("weaknesses", [])
        cwe = weaknesses[0]["description"][0]["value"] if weaknesses else "Unknown"

        configs = vuln.get("configurations", [])
        affected = []
        for config in configs:
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if cpe.get("vulnerable"):
                        affected.append(cpe.get("criteria", ""))

        return json.dumps({
            "id": cve_id,
            "description": description,
            "cvss_score": cvss_data.get("baseScore", "N/A"),
            "severity": cvss_data.get("baseSeverity", "N/A"),
            "vector": cvss_data.get("vectorString", "N/A"),
            "cwe": cwe,
            "published": vuln.get("published", "unknown"),
            "last_modified": vuln.get("lastModified", "unknown"),
            "affected_products": affected[:5],
            "references": [r["url"] for r in vuln.get("references", [])[:3]]
        })

    except requests.exceptions.Timeout:
        return json.dumps({"error": f"NVD API timed out for {cve_id}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def score_severity(cvss_score: float) -> str:
    """Convert a CVSS score (0-10) to a priority label and recommended SLA."""
    if cvss_score >= 9.0:   return "CRITICAL — patch within 24h"
    elif cvss_score >= 7.0: return "HIGH — patch within 7 days"
    elif cvss_score >= 4.0: return "MEDIUM — patch within 30 days"
    elif cvss_score >= 0.1: return "LOW — schedule for next cycle"
    else:                   return "INFORMATIONAL — no action required"


@tool
def search_exploits(cve_id: str) -> str:
    """Search OSV and NVD references for known public exploits for a CVE."""
    results = []

    try:
        osv_resp = requests.post(
            "https://api.osv.dev/v1/query",
            json={"cve_id": cve_id},
            timeout=10
        )
        if osv_resp.status_code == 200:
            osv_data = osv_resp.json()
            for vuln in osv_data.get("vulns", [])[:3]:
                results.append({
                    "source": "OSV",
                    "id": vuln.get("id"),
                    "summary": vuln.get("summary", ""),
                    "url": f"https://osv.dev/vulnerability/{vuln.get('id')}"
                })
    except Exception as e:
        results.append({"source": "OSV", "error": str(e)})

    try:
        nvd_resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers={"User-Agent": "cve-triage-agent/1.0"},
            timeout=15
        )
        if nvd_resp.status_code == 200:
            data = nvd_resp.json()
            if data.get("vulnerabilities"):
                refs = data["vulnerabilities"][0]["cve"].get("references", [])
                exploit_keywords = ["exploit", "poc", "proof-of-concept", "github.com"]
                for ref in refs:
                    url = ref.get("url", "").lower()
                    tags = [t.lower() for t in ref.get("tags", [])]
                    if any(k in url for k in exploit_keywords) or "exploit" in tags:
                        results.append({
                            "source": "NVD reference",
                            "url": ref["url"],
                            "tags": ref.get("tags", [])
                        })
    except Exception as e:
        results.append({"source": "NVD", "error": str(e)})

    return json.dumps({
        "cve": cve_id,
        "exploit_references": results,
        "count": len(results),
        "has_public_exploit": len(results) > 0
    })


@tool
def fetch_recent_cves(severity: str = "CRITICAL", start_date: str = "", end_date: str = "") -> str:
    """Fetch CVEs from NVD published between start_date and end_date, filtered by severity.
    severity options: CRITICAL, HIGH, MEDIUM, LOW
    start_date and end_date format: YYYY-MM-DD (e.g. 2024-01-01)
    If no dates given, defaults to last 24 hours."""
    try:
        if start_date and end_date:
            start = datetime.strptime(start_date, "%Y-%m-%d")
            end   = datetime.strptime(end_date, "%Y-%m-%d").replace(
                        hour=23, minute=59, second=59)
        elif start_date:
            start = datetime.strptime(start_date, "%Y-%m-%d")
            end   = start.replace(hour=23, minute=59, second=59)
        else:
            end   = datetime.utcnow()
            start = end - timedelta(hours=24)

        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate":   end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "cvssV3Severity": severity.upper(),
                "resultsPerPage": 20
            },
            headers={"User-Agent": "cve-triage-agent/1.0"},
            timeout=20
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])

        cve_list = []
        for v in vulns:
            cve = v["cve"]
            metrics = cve.get("metrics", {})
            cvss = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) or
                metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
            )
            cve_list.append({
                "id": cve["id"],
                "published": cve.get("published", ""),
                "cvss_score": cvss.get("baseScore", "N/A"),
                "severity": cvss.get("baseSeverity", severity),
                "description_preview": next(
                    (d["value"][:120] for d in cve.get("descriptions", [])
                     if d["lang"] == "en"), ""
                ) + "..."
            })

        return json.dumps({
            "period": f"{start.date()} to {end.date()}",
            "severity_filter": severity,
            "total_found": data.get("totalResults", 0),
            "returned": len(cve_list),
            "cves": cve_list
        })

    except ValueError:
        return json.dumps({"error": "Invalid date format. Use YYYY-MM-DD"})
    except requests.exceptions.Timeout:
        return json.dumps({"error": "NVD API timed out — try again"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def _rebuild_index(reports_dir: str):
    """Rebuild reports/index.html listing all reports."""
    reports = sorted(glob.glob(f"{reports_dir}/CVE-*.html"), reverse=True)

    rows = ""
    for path in reports:
        name = os.path.basename(path)
        cve_id = name.replace("_report.html", "").replace("_", "-")
        date_str = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")

        with open(path) as f:
            raw = f.read(500)

        sev, sev_color = "UNKNOWN", "#888"
        for s, c in [("CRITICAL", "#E24B4A"), ("HIGH", "#BA7517"),
                     ("MEDIUM", "#378ADD"), ("LOW", "#639922")]:
            if s in raw:
                sev, sev_color = s, c
                break

        rows += f"""
        <tr onclick="window.location='{name}'" style="cursor:pointer">
          <td><a href="{name}" style="color:#1a1a1a;text-decoration:none;
              font-weight:500">{cve_id}</a></td>
          <td><span style="color:{sev_color};font-weight:600;font-size:0.85rem">
              {sev}</span></td>
          <td style="color:#888;font-size:0.88rem">{date_str}</td>
        </tr>"""

    index_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>CVE Triage Reports</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f5f5f0; color: #1a1a1a; }}
    .header {{ background: #1a1a1a; color: white; padding: 2rem 3rem; }}
    .header h1 {{ font-size: 1.4rem; font-weight: 600; }}
    .header p {{ font-size: 0.85rem; opacity: 0.5; margin-top: 4px; }}
    .container {{ max-width: 860px; margin: 2rem auto; padding: 0 1.5rem; }}
    .card {{ background: white; border-radius: 10px; border: 1px solid #e5e5e0;
             overflow: hidden; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ font-size: 0.7rem; font-weight: 600; letter-spacing: 0.08em;
          text-transform: uppercase; color: #888; padding: 0.75rem 1.5rem;
          text-align: left; border-bottom: 1px solid #f0efe8; }}
    td {{ padding: 0.9rem 1.5rem; border-bottom: 1px solid #f5f5f0; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #fafaf7; }}
    .empty {{ text-align: center; padding: 3rem; color: #aaa; font-size: 0.9rem; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>CVE Triage Reports</h1>
    <p>{len(reports)} report{'s' if len(reports) != 1 else ''} · Last updated {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
  </div>
  <div class="container">
    <div class="card">
      {'<table><thead><tr><th>CVE ID</th><th>Severity</th><th>Triaged</th></tr></thead><tbody>' + rows + '</tbody></table>' if reports else '<div class="empty">No reports yet</div>'}
    </div>
  </div>
</body>
</html>"""

    with open(os.path.join(reports_dir, "index.html"), "w") as f:
        f.write(index_html)


@tool
def _rebuild_index(reports_dir: str):
    """Rebuild reports/index.html grouped by date."""
    all_reports = sorted(glob.glob(f"{reports_dir}/**/*.html", recursive=True), reverse=True)
    all_reports = [r for r in all_reports if "index" not in os.path.basename(r)]

    # Group by date folder
    from collections import defaultdict
    grouped = defaultdict(list)
    for path in all_reports:
        date_folder = os.path.basename(os.path.dirname(path))  # e.g. "2024-03-15"
        name = os.path.basename(path)
        cve_id = name.replace("_report.html", "").replace("_", "-")
        date_str = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%H:%M")

        with open(path) as f:
            raw = f.read(500)

        sev, sev_color = "UNKNOWN", "#888"
        for s, c in [("CRITICAL", "#E24B4A"), ("HIGH", "#BA7517"),
                     ("MEDIUM", "#378ADD"), ("LOW", "#639922")]:
            if s in raw:
                sev, sev_color = s, c
                break

        grouped[date_folder].append({
            "name": name,
            "cve_id": cve_id,
            "time": date_str,
            "sev": sev,
            "sev_color": sev_color,
            "rel_path": f"{date_folder}/{name}"
        })

    # Build grouped sections
    sections = ""
    for date_folder in sorted(grouped.keys(), reverse=True):
        entries = grouped[date_folder]
        rows = ""
        for e in entries:
            rows += f"""
            <tr onclick="window.location='{e['rel_path']}'" style="cursor:pointer">
              <td><a href="{e['rel_path']}" style="color:#1a1a1a;text-decoration:none;
                  font-weight:500">{e['cve_id']}</a></td>
              <td><span style="color:{e['sev_color']};font-weight:600;font-size:0.85rem">
                  {e['sev']}</span></td>
              <td style="color:#888;font-size:0.88rem">{e['time']}</td>
            </tr>"""

        sections += f"""
        <div class="section">
          <div class="date-header">{date_folder}
            <span class="count">{len(entries)} CVE{'s' if len(entries) != 1 else ''}</span>
          </div>
          <div class="card">
            <table>
              <thead>
                <tr>
                  <th>CVE ID</th><th>Severity</th><th>Time</th>
                </tr>
              </thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>"""

    total = sum(len(v) for v in grouped.values())

    index_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>CVE Triage Reports</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f5f5f0; color: #1a1a1a; }}
    .header {{ background: #1a1a1a; color: white; padding: 2rem 3rem; }}
    .header h1 {{ font-size: 1.4rem; font-weight: 600; }}
    .header p {{ font-size: 0.85rem; opacity: 0.5; margin-top: 4px; }}
    .container {{ max-width: 860px; margin: 2rem auto; padding: 0 1.5rem 3rem; }}
    .section {{ margin-bottom: 2rem; }}
    .date-header {{ font-size: 0.8rem; font-weight: 600; letter-spacing: 0.08em;
                    text-transform: uppercase; color: #888; padding: 0 0 0.5rem;
                    display: flex; align-items: center; gap: 10px; }}
    .count {{ background: #e5e5e0; color: #666; padding: 1px 8px;
              border-radius: 10px; font-size: 0.75rem; font-weight: 500;
              letter-spacing: 0; text-transform: none; }}
    .card {{ background: white; border-radius: 10px; border: 1px solid #e5e5e0;
             overflow: hidden; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ font-size: 0.7rem; font-weight: 600; letter-spacing: 0.08em;
          text-transform: uppercase; color: #888; padding: 0.75rem 1.5rem;
          text-align: left; border-bottom: 1px solid #f0efe8; }}
    td {{ padding: 0.9rem 1.5rem; border-bottom: 1px solid #f5f5f0; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #fafaf7; }}
    .empty {{ text-align: center; padding: 3rem; color: #aaa; font-size: 0.9rem; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>CVE Triage Reports</h1>
    <p>{total} report{'s' if total != 1 else ''} across {len(grouped)} date{'s' if len(grouped) != 1 else ''} · Last updated {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
  </div>
  <div class="container">
    {sections if sections else '<div class="empty">No reports yet</div>'}
  </div>
</body>
</html>"""

    with open(os.path.join(reports_dir, "index.html"), "w") as f:
        f.write(index_html)


@tool
def write_report(filename: str, content: str) -> str:
    """Write a triage report as a beautiful HTML file, organised by date."""
    reports_dir = "reports"

    # Create dated subfolder e.g. reports/2024-03-15/
    today = datetime.now().strftime("%Y-%m-%d")
    dated_dir = os.path.join(reports_dir, today)
    os.makedirs(dated_dir, exist_ok=True)

    clean_name = os.path.basename(filename).replace(".txt", ".html")
    filepath = os.path.join(dated_dir, clean_name)

    severity_color = {
        "CRITICAL": ("#7A1F1F", "#FCEBEB", "#E24B4A"),
        "HIGH":     ("#633806", "#FAEEDA", "#BA7517"),
        "MEDIUM":   ("#0C447C", "#E6F1FB", "#378ADD"),
        "LOW":      ("#27500A", "#EAF3DE", "#639922"),
    }
    sev = "MEDIUM"
    for s in severity_color:
        if s in content.upper():
            sev = s
            break

    text_color, bg_color, accent = severity_color[sev]
    cve_id = clean_name.replace("_report.html", "").replace("_", "-")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>{cve_id} Triage Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f5f5f0; color: #1a1a1a; line-height: 1.6; }}
    .topbar {{ background: #f5f5f0; padding: 0.75rem 3rem;
               border-bottom: 1px solid #e5e5e0; }}
    .topbar a {{ font-size: 0.85rem; color: #888; text-decoration: none; }}
    .topbar a:hover {{ color: #1a1a1a; }}
    .header {{ background: {text_color}; color: white; padding: 2rem 3rem; }}
    .header h1 {{ font-size: 1.6rem; font-weight: 600; letter-spacing: -0.02em; }}
    .header .meta {{ font-size: 0.85rem; opacity: 0.75; margin-top: 4px; }}
    .badge {{ display: inline-block; background: {bg_color}; color: {text_color};
              border: 1px solid {accent}; padding: 3px 12px; border-radius: 20px;
              font-size: 0.78rem; font-weight: 600; letter-spacing: 0.05em;
              margin-top: 10px; }}
    .container {{ max-width: 860px; margin: 2rem auto; padding: 0 1.5rem; }}
    .card {{ background: white; border-radius: 10px; border: 1px solid #e5e5e0;
             padding: 1.5rem 2rem; margin-bottom: 1.25rem; }}
    .card h2 {{ font-size: 0.7rem; font-weight: 600; letter-spacing: 0.1em;
                text-transform: uppercase; color: #888; margin-bottom: 1rem; }}
    pre {{ white-space: pre-wrap; font-size: 0.88rem; color: #333;
           font-family: inherit; line-height: 1.7; }}
    .footer {{ text-align: center; font-size: 0.8rem; color: #aaa; padding: 2rem; }}
  </style>
</head>
<body>
  <div class="topbar"><a href="../index.html">← All reports</a></div>
  <div class="header">
    <div class="meta">CVE Triage Report · {today}</div>
    <h1>{cve_id}</h1>
    <div class="badge">{sev}</div>
  </div>
  <div class="container">
    <div class="card">
      <h2>Analysis</h2>
      <pre>{content}</pre>
    </div>
  </div>
  <div class="footer">Generated by CVE Triage Agent</div>
</body>
</html>"""

    with open(filepath, "w") as f:
        f.write(html)

    _rebuild_index(reports_dir)
    return f"Report written to {filepath}"
# ```

# Now your `reports/` folder looks like this:
# ```
# reports/
# ├── index.html              ← grouped by date, click any row
# ├── 2024-03-15/
# │   └── CVE-2024-25227_report.html
# ├── 2024-03-21/
# │   └── CVE-2021-44228_report.html