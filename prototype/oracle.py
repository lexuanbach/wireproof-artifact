#!/usr/bin/env python3
"""Independent TLS ServerHello parser. Uses raw relay bytes, not ledger verdicts."""
import argparse, hashlib, json, struct
from pathlib import Path
GROUPS = {29: "X25519", 4588: "X25519MLKEM768"}
HRR = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
def selected_groups(data):
    pos, pending, groups = 0, bytearray(), []
    while pos < len(data):
        if len(data)-pos < 5: raise ValueError("truncated TLS record header")
        kind, version, length = struct.unpack("!BHH", data[pos:pos+5])
        pos += 5
        if pos+length > len(data): raise ValueError("truncated TLS record")
        record=data[pos:pos+length]; pos+=length
        if kind != 22: continue
        pending.extend(record)
        while len(pending)>=4:
            size=int.from_bytes(pending[1:4],"big")
            if len(pending)<4+size: break
            msg=bytes(pending[4:4+size]); typ=pending[0]; del pending[:4+size]
            if typ != 2: continue
            if len(msg)<38: raise ValueError("short ServerHello")
            if msg[2:34] == HRR: continue
            off=35+msg[34]+3
            if off+2>len(msg): raise ValueError("bad session id")
            size=int.from_bytes(msg[off:off+2],"big"); off+=2; end=off+size
            if end!=len(msg): raise ValueError("bad extension block")
            while off<end:
                if off+4>end: raise ValueError("short extension header")
                ext,n=struct.unpack("!HH",msg[off:off+4]);off+=4
                val=msg[off:off+n];off+=n
                if off>end: raise ValueError("short extension")
                if ext==51:
                    if len(val)<4: raise ValueError("short key share")
                    g=int.from_bytes(val[:2],"big")
                    groups.append(GROUPS.get(g, "unknown:"+str(g)))
    if pending: raise ValueError("truncated handshake message")
    return groups
def inspect(root):
    rows=[]
    for path in sorted(root.glob("*/trial.json")):
        trial=json.loads(path.read_text())
        for c in trial["Captures"] or []:
            capture=path.parent/c["ServerBytes"]
            row={"trial":path.parent.name,"connection":c["Connection"],"expected_failure":c["ExpectedFailure"]}
            try:
                data=capture.read_bytes()
                found=selected_groups(data)
                row.update(groups=found,sha256=hashlib.sha256(data).hexdigest())
                if c["ExpectedFailure"]:
                    row["pass"]=bool(c["Error"]) and not found and len(data)>0
                else:
                    row["pass"]=found==[c["Group"]]
            except (ValueError,OSError) as e:
                row.update(error=str(e), **{"pass":False})
            rows.append(row)
    result={"captures":len(rows),"passed":sum(r["pass"] for r in rows),
            "successful_handshakes":sum(r["pass"] and not r["expected_failure"] for r in rows),
            "expected_rejections":sum(r["pass"] and r["expected_failure"] for r in rows),
            "rows":rows}
    (root/"oracle.json").write_text(json.dumps(result,indent=2)+"\n")
    return result
if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("directory",type=Path)
    args=parser.parse_args();result=inspect(args.directory)
    print(json.dumps({k:v for k,v in result.items() if k!="rows"}))
    raise SystemExit(0 if result["captures"] and result["passed"]==result["captures"] else 1)
