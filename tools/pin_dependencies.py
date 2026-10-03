"""Regenerate the reviewed wheel hash lock from official version-specific PyPI metadata.

Development maintenance only; this utility is never called by import or assess.
"""
import json
from pathlib import Path
from urllib.request import urlopen

PINS={"jsonschema":"4.26.0","attrs":"26.1.0","jsonschema-specifications":"2025.9.1","referencing":"0.37.0","rpds-py":"2026.5.1","typing-extensions":"4.15.0"}
ROOT=Path(__file__).resolve().parent.parent


def main():
    lines=["# Reviewed version-specific wheel digests from https://pypi.org/pypi/<name>/<version>/json", "# Install with --require-hashes --only-binary=:all:. No sdist build/install hooks."]
    sources=[]
    for name,version in PINS.items():
        url=f"https://pypi.org/pypi/{name}/{version}/json"
        with urlopen(url,timeout=30) as response:
            raw=response.read(8*1024*1024)
        data=json.loads(raw)
        wheels=[u for u in data["urls"] if u["packagetype"]=="bdist_wheel" and not u["yanked"]]
        if not wheels:
            raise ValueError("No reviewed wheels: "+name)
        hashes=sorted({u["digests"]["sha256"] for u in wheels})
        lines.append(name+"=="+version+" \\")
        lines.extend("    --hash=sha256:"+h+(" \\" if i<len(hashes)-1 else "") for i,h in enumerate(hashes))
        sources.append({"name":name,"version":version,"metadata_url":url,"license":data["info"].get("license_expression") or data["info"].get("license"),"requires_python":data["info"]["requires_python"],"wheels":[{"filename":w["filename"],"sha256":w["digests"]["sha256"]} for w in wheels]})
    (ROOT/"requirements.lock").write_text("\n".join(lines)+"\n",encoding="utf-8")
    (ROOT/"config/python-pins.json").write_text(json.dumps({"packages":sources},indent=2)+"\n",encoding="utf-8")
    print("Pinned six Python packages to version-specific publisher wheels")


if __name__=="__main__":main()
