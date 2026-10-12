import argparse, json, sys
from .triage import triage


def main(argv=None):
    p = argparse.ArgumentParser(description="Triage Wazuh alerts (JSONL)")
    p.add_argument("alerts"); p.add_argument("-o", "--out", default="-")
    p.add_argument("--engine", choices=["auto", "mock", "ollama"], default="auto")
    p.add_argument("--model")
    a = p.parse_args(argv)
    out = sys.stdout if a.out == "-" else open(a.out, "w")
    with open(a.alerts) as f:
        for line in f:
            if line.strip():
                out.write(json.dumps(triage(json.loads(line), a.engine, a.model).to_dict()) + "\n")
    if out is not sys.stdout:
        out.close()


if __name__ == "__main__":
    main()
