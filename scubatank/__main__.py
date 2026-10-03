"""Local disk operator workflows. Setup is an explicit separate command."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from .assessment import assess, reverify
from .evidence import local_path, read_json, validate_bundle
from .evaluator import RULES
from .importers import import_manifest
from .reporting import validate_report, write_reports

ROOT=Path(__file__).resolve().parents[1]
BANNER = r"""          o
       o
      _||_
     /____\       ScubaTank
    |      |---.  Hybrid security assessment
    |      |   |
    |      |   '---[o]
    |______|"""


def write_json(path,value):
    path=local_path(path).resolve()
    if path.is_symlink():
        raise ValueError("Output cannot replace a symbolic link")
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=False,allow_nan=False)+"\n",encoding="utf-8")
    return path


def parser():
    cli=argparse.ArgumentParser(description="ScubaTank - Trust Assurance and Normalization Kit (TANK). Assess hybrid Microsoft security from saved, authorized exports.")
    quiet_help="Suppress the terminal banner; command output is unchanged"
    cli.add_argument("--quiet",action="store_true",help=quiet_help)
    sub=cli.add_subparsers(dest="command",required=True)
    plan=sub.add_parser("plan",help="Show implemented scope and input requirements")
    imp=sub.add_parser("import",help="Import local exports in the supported versioned formats")
    imp.add_argument("--manifest",required=True);imp.add_argument("--output",required=True)
    val=sub.add_parser("validate",help="Validate a normalized bundle and optionally reconstruct it from originals")
    val.add_argument("path");val.add_argument("--evidence-root")
    run=sub.add_parser("assess",help="Evaluate six correlations; supply original source files to verify the evidence")
    run.add_argument("--bundle",required=True);run.add_argument("--output",required=True)
    run.add_argument("--evidence-root");run.add_argument("--as-of");run.add_argument("--max-age-hours",type=float,default=24)
    run.add_argument("--opa",help="Path to the exact pinned OPA binary")
    rep=sub.add_parser("report",help="Write self-contained HTML, JSON, CSV and Markdown")
    rep.add_argument("--assessment",required=True);rep.add_argument("--output-dir",required=True)
    demo=sub.add_parser("demo",help="Import, assess and report the supplied synthetic evidence")
    demo.add_argument("--output-dir",default=".build/demo");demo.add_argument("--opa")
    for command in (plan,imp,val,run,rep,demo):
        command.add_argument("--quiet",action="store_true",default=argparse.SUPPRESS,help=quiet_help)
    return cli


def execute(args):
    if args.command=="plan":
        return {"mode":"offline import-first","network_access":False,"live_collectors_enabled":False,
            "implemented_rules":list(RULES),"validation":"synthetic-tested; no live-environment validation",
            "specified_checks":132,"remaining_specifications":126,
            "required_inputs":["ScubaGear 1.8.0 consolidated JSON","BloodHound CE 9.7.1 processed Cypher graph","Explicit stable identity links and dated operational context"],
            "next_step":"Run scripts/Demo.ps1, then review docs/import-formats.md for authorized local exports."}
    if args.command=="import":
        bundle=import_manifest(args.manifest)
        path=write_json(args.output,bundle)
        return {"bundle":str(path),"sources":len(bundle["sources"]),"entities":len(bundle["entities"]),
            "relationships":len(bundle["edges"]),"issues":len(bundle["issues"]),"synthetic":bundle["synthetic"]}
    if args.command=="validate":
        bundle=read_json(args.path);verified=reverify(bundle,args.evidence_root)
        return {"valid":True,"original_inputs_reconstructed":verified,
            "scope":"Original inputs and normalized records" if verified else "Structural and semantic normalized contract only; original bytes not reverified"}
    if args.command=="assess":
        result=assess(read_json(args.bundle),as_of=args.as_of,max_age_hours=args.max_age_hours,opa=args.opa,evidence_root=args.evidence_root)
        path=write_json(args.output,result)
        return {"assessment":str(path),"run_id":result["run_id"],"counts":result["counts"],"coverage":result["coverage"]}
    if args.command=="report":
        result=read_json(args.assessment);validate_report(result)
        return {kind:str(path) for kind,path in write_reports(result,local_path(args.output_dir)).items()}
    if args.command=="demo":
        out=local_path(args.output_dir).resolve();fixture=ROOT/"fixtures/demo"
        bundle=import_manifest(fixture/"manifest.json")
        write_json(out/"bundle.json",bundle)
        result=assess(bundle,as_of="2026-10-02T08:00:00Z",opa=args.opa,evidence_root=fixture)
        write_json(out/"assessment.json",result)
        paths=write_reports(result,out/"reports")
        return {"synthetic":True,"run_id":result["run_id"],"counts":result["counts"],
            "reports":{kind:str(path) for kind,path in paths.items()},"coverage":result["coverage"]}
    raise ValueError("Unknown command")


def main():
    banner_options=argparse.ArgumentParser(add_help=False)
    banner_options.add_argument("--quiet",action="store_true")
    presentation,_=banner_options.parse_known_args()
    # Keep JSON on stdout intact, including in an interactive terminal. Requiring
    # all three terminals also suppresses decoration in pipes and wrappers.
    if not presentation.quiet and all(stream is not None and stream.isatty() for stream in (sys.stdin,sys.stdout,sys.stderr)):
        print(BANNER + "\n",file=sys.stderr)
    args=parser().parse_args()
    try:
        result=execute(args)
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        print("ScubaTank: "+str(error),file=sys.stderr)
        return 2
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0


if __name__=="__main__":sys.exit(main())
