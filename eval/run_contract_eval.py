"""Save the exact risk-showcase results for judging. Exit nonzero on any unexpected behavior."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.contract_lab import run_showcase

if __name__ == "__main__":
    result = run_showcase()
    output = Path(__file__).resolve().parent / "contract-report.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Contract scenarios: {result['passed']}/{result['total']}")
    for row in result["comparison"]:
        print(f"{row['label']}: unsafe admitted {row['unsafe_candidates_admitted']}/{row['unsafe_candidates']}")
    print(result["methodology"])
    print(output)
    sys.exit(0 if result["passed"] == result["total"] else 1)
