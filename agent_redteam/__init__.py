"""Agent Red-Teaming & Evaluation Framework — Main Package.

This is the top-level package for the entire framework.
It sets the version number so other parts of the code can import it.

What this project does:
  - Tests AI agents by sending them tricky/harmful prompts (called "attacks").
  - Checks if the agent responds safely or leaks secrets / follows bad instructions.
  - Generates reports and dashboards showing how well the agent handled the attacks.

Safe by default: targets must be local mock agents or explicitly authorized endpoints.
"""

__version__ = "1.0.0"
