# Common project commands. Run from the project root:
#   .\tasks.ps1 setup      install the package and dev dependencies
#   .\tasks.ps1 generate   write a synthetic dataset with a labelled intrusion
#   .\tasks.ps1 ingest     normalise it into the DuckDB warehouse
#   .\tasks.ps1 profile    describe what landed
#   .\tasks.ps1 graph      build the ontology on top of the events
#   .\tasks.ps1 test       run the test suite
#   .\tasks.ps1 demo       generate through detect, evaluate, one inconclusive

param([Parameter(Position = 0)][string]$Task = "demo")

$ErrorActionPreference = "Stop"

switch ($Task) {
    "setup"    { pip install -e ".[dev]" }
    "generate" { lmo generate --preset small --out data/raw/synthetic }
    "ingest"   { lmo ingest --source data/raw/synthetic --reset --report data/reports/ingest.json }
    "profile"  { lmo profile }
    "graph"    { lmo build-graph }
    "test"     { pytest -q }
    "clean"    {
        Remove-Item -Recurse -Force data/warehouse, data/reports, .pytest_cache -ErrorAction SilentlyContinue
    }
    "demo"     { lmo demo --preset tiny }
    default    { Write-Host "unknown task '$Task'; try: setup generate ingest graph profile test clean demo" }
}
