"""API Package — REST API for running evaluations over HTTP.

This package contains the FastAPI web server that lets you start and monitor
red-teaming evaluation runs through HTTP requests instead of the command line.

Endpoints:
  POST /runs         — Start a new evaluation run against a target agent.
  GET  /runs/{id}    — Check the status of a running evaluation.
  GET  /runs/{id}/results — Get detailed results of a completed run.
  GET  /runs/{id}/report  — Get the generated report for a run.
  GET  /healthz      — Check if the server is running and healthy.
"""
