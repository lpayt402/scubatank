"""Explicit development/operator setup; never called during evidence import."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.request import urlopen
from .policy import runtime_spec

MAX_ARTIFACT_BYTES = 100 * 1024 * 1024


def fetch_runtime(output_dir):
    pins,spec=runtime_spec()
    root=Path(output_dir).resolve();root.mkdir(parents=True,exist_ok=True)
    filename="opa.exe" if spec["name"].endswith(".exe") else "opa"
    destination=root/filename
    if destination.exists():
        with destination.open("rb") as stream:
            digest=hashlib.file_digest(stream,"sha256").hexdigest()
        if digest != spec["sha256"]:
            raise ValueError("Existing OPA digest differs from the pinned artifact; remove that file before explicit setup")
        return destination
    url="https://github.com/open-policy-agent/opa/releases/download/v"+pins["opa_version"]+"/"+spec["name"]
    temporary=root/(filename+".download")
    digest=hashlib.sha256();total=0
    try:
        with urlopen(url,timeout=60) as response,temporary.open("wb") as stream:
            while chunk:=response.read(1024*1024):
                total+=len(chunk)
                if total>MAX_ARTIFACT_BYTES:
                    raise ValueError("OPA download exceeds pinned artifact size limit")
                digest.update(chunk);stream.write(chunk)
        if digest.hexdigest()!=spec["sha256"]:
            raise ValueError("Downloaded OPA digest differs from the pinned publisher artifact")
        if os.name!="nt":
            temporary.chmod(0o755)
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination


def main():
    parser=argparse.ArgumentParser(description="Download and verify the pinned OPA runtime. This setup command uses the network.")
    parser.add_argument("--output-dir",default=".build/tools")
    args=parser.parse_args()
    print(json.dumps({"opa":str(fetch_runtime(args.output_dir)),"status":"verified"}))


if __name__ == "__main__": main()
