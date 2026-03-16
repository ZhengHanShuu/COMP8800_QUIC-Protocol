import argparse
import json
from collections import Counter, defaultdict


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
    if not events:
        print("No events found.")
        return

    event_counter = Counter(e.get("event", "unknown") for e in events)
    reason_counter = Counter(e.get("reason", "n/a") for e in events if "reason" in e)

    by_event_reason = defaultdict(int)
    for e in events:
        by_event_reason[(e.get("event", "unknown"), e.get("reason", "n/a"))] += 1

    print(f"Total events: {len(events)}")
    print("Event counts:", dict(event_counter))
    print("Reason counts:", dict(reason_counter))
    print("\nEvent + reason breakdown:")
    for k, v in sorted(by_event_reason.items()):
        print(f"  {k}: {v}")

    print("\nLast 10 events:")
    for e in events[-10:]:
        print(json.dumps(e, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()