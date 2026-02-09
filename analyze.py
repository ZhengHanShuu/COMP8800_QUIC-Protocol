import argparse
import json
from collections import Counter


def read_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rotation-log", required=True)
    args = ap.parse_args()

    events = list(read_jsonl(args.rotation_log))
    c = Counter(e["event"] for e in events)
    print(f"Total events: {len(events)}")
    print("Counts:", dict(c))

    # show last few rotation attempts
    for e in events[-10:]:
        print(json.dumps(e, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
