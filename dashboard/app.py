import sys
from pathlib import Path

import pandas as pd
import streamlit as st
from sqlmodel import Session, SQLModel, create_engine, select

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.models import Finding, Scan


DATABASE_URL = f"sqlite:///{PROJECT_ROOT / 'scanner.db'}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SQLModel.metadata.create_all(engine)

st.set_page_config(
    page_title="PR Security Review",
    page_icon="◆",
    layout="wide",
)

st.html("""
<style>
:root {
  --ink: #dfe8e3;
  --muted: #93a49d;
  --panel: #111816;
  --line: #26322e;
  --safe: #79d09b;
  --warning: #e8c16c;
  --critical: #ef7b72;
  --accent: #62a8a1;
}
.stApp { background: #0b100f; }
.block-container { max-width: 1180px; padding-top: 2.25rem; }
.stMarkdown, .stMetricLabel, .stMetricValue { color: var(--ink); }
.stMetric {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 1rem;
}
[data-testid="stMetric"] {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 1rem 1.1rem;
}
.hero {
  border-left: 3px solid var(--accent);
  padding: 0.25rem 0 0.45rem 1.1rem;
  margin-bottom: 1.25rem;
}
.hero h1 {
  font-size: 2.15rem;
  line-height: 1.05;
  margin: 0;
  letter-spacing: -0.04em;
}
.hero p { color: var(--muted); margin: 0.45rem 0 0; }
.section-title { font-size: 1.02rem; font-weight: 700; margin: 1.2rem 0 0.7rem; }
.empty-state {
  border: 1px dashed var(--line);
  background: var(--panel);
  border-radius: 12px;
  padding: 2.2rem;
  text-align: center;
}
.empty-state strong { display: block; color: var(--ink); font-size: 1.1rem; }
.empty-state span { color: var(--muted); }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
</style>
""")


def load_scans() -> list[Scan]:
    with Session(engine) as session:
        return list(session.exec(select(Scan).order_by(Scan.created_at.desc())).all())


def load_findings(scan_ids: list[int]) -> list[Finding]:
    if not scan_ids:
        return []
    with Session(engine) as session:
        findings = []
        for scan_id in scan_ids:
            findings.extend(
                session.exec(select(Finding).where(Finding.scan_id == scan_id)).all()
            )
        return findings


def seed_sample_data() -> None:
    samples = [
        Scan(
            repository="acme/payments-api",
            pr_number=184,
            pr_title="Refactor payment token validation",
            pr_url="https://github.com/acme/payments-api/pull/184",
            head_sha="a184f0",
            risk_level="CRITICAL",
            security_score=42,
            summary="Found a hardcoded API token and unsafe cryptographic configuration.",
        ),
        Scan(
            repository="acme/web-store",
            pr_number=77,
            pr_title="Add customer profile filters",
            pr_url="https://github.com/acme/web-store/pull/77",
            head_sha="77bc31",
            risk_level="SAFE",
            security_score=96,
            summary="No actionable security findings were detected.",
        ),
        Scan(
            repository="acme/identity-service",
            pr_number=310,
            pr_title="Improve password reset flow",
            pr_url="https://github.com/acme/identity-service/pull/310",
            head_sha="310df2",
            risk_level="WARNING",
            security_score=71,
            summary="One authorization logic issue needs review.",
        ),
        Scan(
            repository="acme/payments-api",
            pr_number=190,
            pr_title="Add refund reconciliation job",
            pr_url="https://github.com/acme/payments-api/pull/190",
            head_sha="190e8a",
            risk_level="WARNING",
            security_score=68,
            summary="Potential SQL construction issue identified in a background job.",
        ),
    ]
    with Session(engine) as session:
        for sample in samples:
            session.add(sample)
        session.commit()
        for sample in samples:
            session.refresh(sample)
            if sample.id is None:
                continue
            if sample.risk_level == "CRITICAL":
                session.add(Finding(
                    scan_id=sample.id,
                    file="src/payments/client.py",
                    line=18,
                    severity="CRITICAL",
                    category="Hardcoded Secret",
                    issue="A third-party API credential is embedded in source.",
                    recommendation="Move the credential to a secret manager and rotate it.",
                ))
            if sample.risk_level == "WARNING" and sample.pr_number == 310:
                session.add(Finding(
                    scan_id=sample.id,
                    file="src/auth/reset.py",
                    line=42,
                    severity="MEDIUM",
                    category="Broken Authorization",
                    issue="The reset operation may not verify ownership for every account type.",
                    recommendation="Enforce a server-side owner check before issuing a new credential.",
                ))
        session.commit()


scans = load_scans()

st.markdown(
    '<div class="hero"><h1>Pull Request Security Review</h1>'
    '<p>Audit history and risk exposure across repositories</p></div>',
    unsafe_allow_html=True,
)

if not scans:
    st.markdown(
        '<div class="empty-state"><strong>No audit history yet</strong>'
        '<span>Run the webhook or load sample records to preview the portfolio dashboard.</span></div>',
        unsafe_allow_html=True,
    )
    if st.button("Load Sample Audit Data", type="primary"):
        seed_sample_data()
        st.rerun()
    st.stop()

repositories = sorted({scan.repository for scan in scans})
risk_options = ["All", "SAFE", "WARNING", "CRITICAL"]

with st.sidebar:
    st.markdown("### Filters")
    repository = st.selectbox("Repository", ["All", *repositories])
    risk = st.selectbox("Risk level", risk_options)
    st.markdown("---")
    st.caption("Data source")
    st.code("sqlite:///scanner.db", language="text")

filtered = [
    scan for scan in scans
    if (repository == "All" or scan.repository == repository)
    and (risk == "All" or scan.risk_level == risk)
]

total = len(filtered)
average = round(sum(scan.security_score for scan in filtered) / total, 1) if total else 0
critical = sum(scan.risk_level == "CRITICAL" for scan in filtered)
safe = sum(scan.risk_level == "SAFE" for scan in filtered)

kpi1, kpi2, kpi3, kpi4 = st.columns(4)
kpi1.metric("Total PR scanned", total)
kpi2.metric("Average security score", average)
kpi3.metric("Critical issues", critical)
kpi4.metric("Safe PRs", safe)

st.markdown('<div class="section-title">Risk distribution</div>', unsafe_allow_html=True)
risk_counts = pd.DataFrame({
    "Risk": ["SAFE", "WARNING", "CRITICAL"],
    "Scans": [
        sum(scan.risk_level == "SAFE" for scan in filtered),
        sum(scan.risk_level == "WARNING" for scan in filtered),
        sum(scan.risk_level == "CRITICAL" for scan in filtered),
    ],
})
st.bar_chart(risk_counts.set_index("Risk"), color="#62a8a1")

st.markdown('<div class="section-title">Audit history</div>', unsafe_allow_html=True)
history = pd.DataFrame([
    {
        "Repository": scan.repository,
        "PR": f"#{scan.pr_number}",
        "Title": scan.pr_title,
        "Risk": scan.risk_level,
        "Score": scan.security_score,
        "Scanned": scan.created_at.strftime("%Y-%m-%d %H:%M"),
        "PR link": scan.pr_url,
    }
    for scan in filtered
])
st.dataframe(history, use_container_width=True, hide_index=True)

if filtered:
    st.markdown('<div class="section-title">Latest finding details</div>', unsafe_allow_html=True)
    findings = load_findings([scan.id for scan in filtered if scan.id is not None])
    if findings:
        detail = pd.DataFrame([
            {
                "File": finding.file,
                "Line": finding.line,
                "Severity": finding.severity,
                "Category": finding.category,
                "Issue": finding.issue,
                "Recommendation": finding.recommendation,
            }
            for finding in findings
        ])
        st.dataframe(detail, use_container_width=True, hide_index=True)
    else:
        st.info("No detailed findings for the selected scans.")
