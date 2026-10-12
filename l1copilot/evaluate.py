"""Evaluate triage vs ground-truth labels: precision/recall/F1 (TP = positive class)."""
import argparse, json, time
from collections import Counter
from .triage import triage


def metrics(y_true, y_pred, pos="true_positive"):
    c = Counter((t == pos, p == pos) for t, p in zip(y_true, y_pred))
    tp, fp, fn, tn = c[(True, True)], c[(False, True)], c[(True, False)], c[(False, False)]
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(prec, 3), "recall": round(rec, 3),
            "f1": round(f1, 3), "accuracy": round((tp + tn) / max(1, len(y_true)), 3)}


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--alerts", default="data/alerts_lab.jsonl")
    p.add_argument("--engine", default="auto"); p.add_argument("--model")
    p.add_argument("--out", default="results/eval.json")
    a = p.parse_args(argv)
    alerts = [json.loads(l) for l in open(a.alerts) if l.strip()]
    t0 = time.time()
    res = [triage(x, a.engine, a.model) for x in alerts]
    el = time.time() - t0
    yt = [x["label"]["verdict"] for x in alerts]; yp = [r.verdict for r in res]
    m = metrics(yt, yp)
    tps = [(x, r) for x, r in zip(alerts, res) if x["label"]["verdict"] == "true_positive" and r.verdict == "true_positive"]
    m["mitre_accuracy_on_tp"] = round(sum(x["label"]["mitre"] == r.mitre for x, r in tps) / max(1, len(tps)), 3)
    m["engine"] = res[0].engine; m["n"] = len(alerts); m["seconds"] = round(el, 2)
    m["misses"] = [{"id": x["id"], "truth": x["label"]["verdict"], "pred": r.verdict, "note": x["label"]["note"]}
                   for x, r in zip(alerts, res) if x["label"]["verdict"] != r.verdict]
    import os; os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(m, open(a.out, "w"), indent=2)
    print(json.dumps({k: v for k, v in m.items() if k != "misses"}, indent=2))
    for x in m["misses"]:
        print("MISS", x)
    return m


if __name__ == "__main__":
    main()
