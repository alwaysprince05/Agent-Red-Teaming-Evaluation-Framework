"""Reports Package — Generates human-readable output from evaluation runs.

This package turns raw evaluation data into reports you can read and share:

  - generate.py:  Creates Markdown reports (human-readable text with tables)
                   and CSV files (spreadsheet-friendly list of findings).
  - dashboard.py: Builds a self-contained HTML dashboard page with summary cards,
                   trend charts, category breakdowns, and a findings browser.
                   Opens directly in any web browser — no server needed.

All reports are read-only views of the data saved under runs/. They never
modify the original run artifacts.
"""

from agent_redteam.reports.dashboard import generate_dashboard
from agent_redteam.reports.generate import generate_findings_csv, generate_markdown_report

__all__ = ["generate_dashboard", "generate_findings_csv", "generate_markdown_report"]
