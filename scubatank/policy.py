"""Invoke a hash-verified OPA runtime without a shell or assessment downloads."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def runtime_platform():
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"amd64":"amd64", "x86_64":"amd64", "arm64":"arm64", "aarch64":"arm64"}.get(machine,machine)
    return system + "-" + arch


def runtime_spec():
    pins=json.loads((ROOT/"config/runtime-pins.json").read_text(encoding="utf-8"))
    key=runtime_platform()
    if key not in pins["artifacts"]:
        raise ValueError("No pinned OPA artifact for " + key)
    return pins,pins["artifacts"][key]


def opa_path(path=None):
    _,spec=runtime_spec()
    default=ROOT/".build/tools"/("opa.exe" if platform.system()=="Windows" else "opa")
    executable=Path(path).resolve() if path else default
    if not executable.is_file():
        raise ValueError("Pinned OPA runtime is missing. Run the documented bootstrap before offline assessment.")
    with executable.open("rb") as stream:
        digest=hashlib.file_digest(stream,"sha256").hexdigest()
    if digest!=spec["sha256"]:
        raise ValueError("OPA artifact digest does not match the pinned publisher release")
    return executable


def evaluate(candidates, *, opa=None):
    result=subprocess.run([str(opa_path(opa)),"eval","--format=json","--stdin-input","--data",str(ROOT/"policies/hybrid.rego"),"data.scubatank.hybrid.results"],
        input=json.dumps({"candidates":candidates}),text=True,capture_output=True,timeout=30,check=False)
    if result.returncode:
        raise ValueError("OPA evaluation failed: " + result.stderr[:2000])
    if len(result.stdout)>8*1024*1024:
        raise ValueError("OPA output exceeds limit")
    try:
        value=json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
    except (ValueError,KeyError,IndexError,TypeError) as exc:
        raise ValueError("OPA returned an invalid result envelope") from exc
    if not isinstance(value,list) or len(value)!=len(candidates):
        raise ValueError("OPA result count does not match candidate count")
    return value
