import json, html
F = json.load(open("findings.json"))
SEV_COLOR = {"High":"#c2410c","Medium":"#b45309","Low":"#0e7490","Informational":"#475569"}
counts = {s: sum(1 for f in F if f["sev"]==s) for s in ["High","Medium","Low","Informational"]}

def badge(s): return f'<span class="badge" style="background:{SEV_COLOR[s]}">{s}</span>'

rows = "".join(f'<tr><td class="mono">{f["id"]}</td><td>{f["title"]}</td><td>{badge(f["sev"])}</td><td class="mono">{f["cvss"]}</td><td class="ok">Fixed</td></tr>' for f in F)

details = ""
for f in F:
    details += f'''
<section class="finding">
  <div class="fhead"><span class="mono fid">{f["id"]}</span><h3>{f["title"]}</h3></div>
  <table class="meta">
    <tr><th>Severity</th><td>{badge(f["sev"])} &nbsp;CVSS {f["cvss"]}</td></tr>
    <tr><th>Vector</th><td class="mono small">{f["vec"]}</td></tr>
    <tr><th>Component</th><td>{f["where"]}</td></tr>
    <tr><th>Status</th><td class="ok">Fixed in v0.2.0, verified on retest</td></tr>
  </table>
  <h4>Description</h4><p>{f["desc"]}</p>
  <h4>Steps to reproduce</h4><pre>{f["repro"]}</pre>
  <h4>Evidence</h4><p>{f["evidence"]}</p>
  <h4>Impact</h4><p>{f["impact"]}</p>
  <h4>Recommendation</h4><p>{f["fix"]}</p>
  <h4>Retest</h4><p>{f["fixed"]}</p>
</section>'''

retest = "".join(f'<tr><td class="mono">{f["id"]}</td><td>{f["title"]}</td><td class="bad">Vulnerable</td><td class="ok">Not vulnerable</td></tr>' for f in F)

doc = f'''<!doctype html><html><head><meta charset="utf-8"><title>Security Assessment Report - TenantDesk</title>
<style>
@page {{ size: A4; margin: 18mm 16mm 20mm; }}
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, "Helvetica Neue", Arial, sans-serif; color:#1e293b; font-size:10.5pt; line-height:1.5; margin:0; }}
h1 {{ font-size:26pt; margin:0 0 6px; color:#0f172a; }}
h2 {{ font-size:15pt; color:#0f172a; border-bottom:2px solid #0f172a; padding-bottom:4px; margin:28px 0 12px; page-break-after:avoid; }}
h3 {{ font-size:12.5pt; margin:0; }}
h4 {{ font-size:10pt; text-transform:uppercase; letter-spacing:.04em; color:#475569; margin:12px 0 2px; }}
p {{ margin:4px 0 8px; }}
code, .mono {{ font-family: "SF Mono", Menlo, Consolas, monospace; font-size:9.3pt; }}
.small {{ font-size:8.5pt; }}
pre {{ background:#0f172a; color:#e2e8f0; padding:10px 12px; border-radius:6px; font-size:8.8pt; white-space:pre-wrap; margin:4px 0 8px; }}
table {{ border-collapse:collapse; width:100%; }}
th, td {{ text-align:left; padding:6px 8px; border-bottom:1px solid #e2e8f0; vertical-align:top; }}
thead th {{ background:#f1f5f9; font-size:9pt; text-transform:uppercase; letter-spacing:.03em; }}
.badge {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:8.5pt; font-weight:600; white-space:nowrap; }}
.ok {{ color:#15803d; font-weight:600; }} .bad {{ color:#b91c1c; font-weight:600; }}
.cover {{ height:250mm; display:flex; flex-direction:column; justify-content:space-between; page-break-after:always; }}
.cover .top {{ border-left:6px solid #0f172a; padding-left:18px; margin-top:40mm; }}
.kicker {{ text-transform:uppercase; letter-spacing:.12em; color:#64748b; font-size:9pt; font-weight:600; }}
.sub {{ font-size:13pt; color:#334155; margin-top:6px; }}
.note {{ background:#fff7ed; border:1px solid #fed7aa; padding:10px 12px; border-radius:6px; font-size:9.5pt; }}
.cards {{ display:flex; gap:10px; margin:12px 0; }}
.card {{ flex:1; border:1px solid #e2e8f0; border-radius:8px; padding:10px; text-align:center; }}
.card b {{ display:block; font-size:22pt; }}
.finding {{ page-break-inside:avoid; border:1px solid #e2e8f0; border-radius:8px; padding:14px 16px; margin:14px 0; }}
.fhead {{ display:flex; gap:10px; align-items:baseline; margin-bottom:8px; }}
.fid {{ background:#0f172a; color:#fff; padding:2px 7px; border-radius:4px; }}
.meta th {{ width:110px; color:#475569; font-weight:600; border:none; padding:2px 8px 2px 0; }}
.meta td {{ border:none; padding:2px 0; }}
ul {{ margin:4px 0 8px 18px; padding:0; }}
</style></head><body>

<div class="cover">
  <div class="top">
    <div class="kicker">Application Security Assessment</div>
    <h1>TenantDesk v0.1.0</h1>
    <div class="sub">Multi-tenant SaaS: REST API, MCP server and Stripe webhook</div>
    <p style="margin-top:28px">Prepared by <b>Azeem Haider</b>, Backend Integration Engineer<br>Sample report · Version 1.0</p>
  </div>
  <div class="note"><b>Sample report.</b> TenantDesk is a demo application built for this portfolio, and the issues in v0.1.0 were introduced on purpose to show the assessment process end to end. No client systems or real customer data were involved. Code and reproduction scripts: github.com/Azeem-Haider/tenantdesk-mcp (tag v0.1.0 for the assessed build, main for the fixed build).</div>
</div>

<h2>1. Executive summary</h2>
<p>TenantDesk lets several clinics share one platform, with an AI assistant (via MCP) that reads and acts on their data. The assessment asked one question first: <b>can one clinic, or an AI acting for it, reach another clinic's data or money?</b></p>
<p>In v0.1.0 the answer was <b>yes, in three separate ways</b>: a changed parameter in the customer export, an invoice lookup without a tenant check, and an AI tool that accepted a tenant id from the model. The Stripe webhook also accepted forged payment events from anyone on the internet, and the AI refund tool let any staff member refund any amount in a single call.</p>
<div class="cards">
  <div class="card"><b style="color:{SEV_COLOR["High"]}">{counts["High"]}</b>High</div>
  <div class="card"><b style="color:{SEV_COLOR["Medium"]}">{counts["Medium"]}</b>Medium</div>
  <div class="card"><b style="color:{SEV_COLOR["Low"]}">{counts["Low"]}</b>Low</div>
  <div class="card"><b style="color:{SEV_COLOR["Informational"]}">{counts["Informational"]}</b>Informational</div>
</div>
<p><b>Outcome:</b> all {len(F)} findings were fixed in v0.2.0 and every one was retested with the same proof-of-concept script, which now reports <b>0 of {len(F)} vulnerable</b>. The fixes are structural (one tenant-scoped data layer, verified webhooks, two-step refunds), so the same classes of bug are unlikely to come back with new features.</p>

<h2>2. Scope and rules of engagement</h2>
<table>
<tr><th style="width:150px">Target</th><td>TenantDesk v0.1.0 (git tag <code>v0.1.0</code>), run locally with seeded demo data</td></tr>
<tr><th>In scope</th><td>REST API (<code>/api/customers/export</code>, <code>/api/invoices/:id</code>); MCP server over Streamable HTTP and stdio (7 tools); Stripe webhook (<code>/webhooks/stripe</code>); authentication and authorization; data layer</td></tr>
<tr><th>Out of scope</th><td>Infrastructure, hosting and network; denial-of-service; third-party services (Stripe itself, the AI model provider); social engineering</td></tr>
<tr><th>Test accounts</th><td>Two tenants (Acme Dental, Brightside Clinic) with admin, agent and viewer users</td></tr>
<tr><th>Approach</th><td>Grey box: source code available, plus authenticated testing as each role</td></tr>
<tr><th>Data</th><td>Synthetic only. No production systems were touched.</td></tr>
</table>

<h2>3. Method</h2>
<ul>
<li><b>Threat model first:</b> for each entry point, who can call it, what identity it trusts, and what it can change.</li>
<li><b>Checklists:</b> OWASP API Security Top 10 (2023), OWASP Top 10 (2021) and selected OWASP ASVS 4.0 Level 2 controls for access control, authentication, error handling and logging.</li>
<li><b>AI/MCP-specific:</b> tool arguments treated as attacker-controlled (prompt injection), privilege of AI actions, human confirmation for money-moving tools, auditability.</li>
<li><b>Payments:</b> webhook authenticity, replay windows, duplicate delivery and idempotency.</li>
<li><b>Evidence:</b> every finding is backed by a scripted proof of concept (<code>assessment/poc.ts</code>) so it can be reproduced and retested exactly.</li>
</ul>
<p><b>Severity:</b> CVSS v3.1 base score, with business impact noted where it differs (for example TD-06, which moves money).</p>

<h2>4. Findings summary</h2>
<table><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>

<h2>5. Detailed findings</h2>
{details}

<h2>6. Retest results</h2>
<p>The same script was run against the assessed build (v0.1.0) and the fixed build (v0.2.0).</p>
<table><thead><tr><th>ID</th><th>Finding</th><th>v0.1.0</th><th>v0.2.0</th></tr></thead><tbody>{retest}</tbody></table>

<h2>7. Recommendations beyond the fixes</h2>
<ul>
<li><b>Defence in depth for tenancy:</b> add Postgres row-level security keyed on a per-request tenant setting, so a missed filter in code is still blocked by the database.</li>
<li><b>Cross-tenant tests in CI:</b> keep a test per endpoint and per MCP tool that tries another tenant's ids. They are cheap and catch regressions immediately.</li>
<li><b>MCP tool design rules:</b> no identity arguments, read and write tools separated, destructive tools marked and confirmed by a human, inputs validated by schema.</li>
<li><b>Webhook checklist:</b> verify signature on the raw body, enforce a timestamp window, de-duplicate by event id, write absolute values, respond fast and process asynchronously.</li>
<li><b>Monitoring:</b> alert on spikes of denied tool calls and cross-tenant 404s; both are early signs of probing or prompt injection.</li>
<li><b>Identity:</b> move from shared-secret JWTs to the company identity provider (OAuth 2.1 / OIDC) before production.</li>
</ul>

<h2>Appendix: reproduce this report</h2>
<pre>git clone https://github.com/Azeem-Haider/tenantdesk-mcp
cd tenantdesk-mcp &amp;&amp; npm install
git checkout v0.1.0 &amp;&amp; npx tsx assessment/poc.ts   # 10 of 10 vulnerable
git checkout main   &amp;&amp; npx tsx assessment/poc.ts   # 0 of 10 vulnerable</pre>
</body></html>'''
open("report.html","w").write(doc)
print("ok", counts)
