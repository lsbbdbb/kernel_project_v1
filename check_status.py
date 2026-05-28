import json, os
wd = '/tmp/test_workspace'
for d in sorted(os.listdir(wd)):
    sp = os.path.join(wd, d, 'state.json')
    if not os.path.isfile(sp): continue
    s = json.load(open(sp))
    ep = os.path.join(wd, d, 'events.json')
    last = '?'
    if os.path.isfile(ep):
        ev = json.load(open(ep))
        if ev: last = ev[-1]['to']
    print(f'{d:25s} {s["state"]:20s} -> {str(s.get("status")):10s} | {last}')
