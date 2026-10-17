"""Offline OpenSSH authentication triage, using timezone-aware ISO timestamps."""
import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta
import ipaddress
import json
from pathlib import Path
import re
import sys

EVENT = re.compile(r'(?P<kind>Failed|Accepted) (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+')

def analyze(lines, threshold=5, window_seconds=300):
    if threshold < 2 or window_seconds < 1:
        raise ValueError('threshold must be >= 2; window must be positive')
    events, ignored = [], 0
    for number, line in enumerate(lines, 1):
        match = EVENT.search(line)
        if not match:
            ignored += 1
            continue
        try:
            timestamp = datetime.fromisoformat(line.split()[0].replace('Z', '+00:00'))
            if timestamp.utcoffset() is None:
                raise ValueError('timezone required')
            address = str(ipaddress.ip_address(match['ip']))
        except (ValueError, IndexError):
            ignored += 1
            continue
        events.append((timestamp, number, match['kind'], match['user'], address))
    events.sort(key=lambda item: (item[0], item[1]))
    windows = defaultdict(deque)
    active, findings = set(), []
    for timestamp, number, kind, user, address in events:
        queue = windows[address]
        cutoff = timestamp - timedelta(seconds=window_seconds)
        while queue and queue[0][0] < cutoff:
            queue.popleft()
        if len(queue) < threshold:
            active.discard(address)
        if kind == 'Failed':
            queue.append((timestamp, user, number))
            if len(queue) >= threshold and address not in active:
                findings.append(dict(type='ssh_failure_burst', ip=address,
                    time=timestamp.isoformat(), failures=len(queue),
                    users=sorted({item[1] for item in queue}),
                    evidence_lines=[item[2] for item in queue]))
                active.add(address)
        elif len(queue) >= threshold:
            findings.append(dict(type='ssh_success_after_failures', ip=address,
                time=timestamp.isoformat(), user=user, failures=len(queue),
                evidence_lines=[item[2] for item in queue] + [number]))
            queue.clear()
            active.discard(address)
    return dict(events=len(events), ignored_lines=ignored, findings=findings)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window', type=int, default=300, help='Window in seconds (inclusive)')
    args = parser.parse_args()
    try:
        with args.log.open(encoding='utf-8') as stream:
            result = analyze(stream, args.threshold, args.window)
    except (OSError, ValueError) as error:
        parser.exit(2, f'Error: {error}\n')
    print(json.dumps(result, indent=2))
    return 1 if result['findings'] else 0

if __name__ == '__main__':
    sys.exit(main())
