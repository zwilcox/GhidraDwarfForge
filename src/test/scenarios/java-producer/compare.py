#!/usr/bin/env python3
"""Validate the standalone Java writer and packaged producer on identical linked inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

HERE = Path(__file__).resolve().parent
TEST = HERE.parents[1]


def run(args, *, log=None, env=None):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    if log:
        log.write_bytes(result.stdout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}\n{result.stdout.decode(errors='replace')[-4000:]}")
    return result.stdout.decode()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(archive, sdk, output):
    libraries = output / "libraries"
    libraries.mkdir(exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        for member in ("lib/GhidraDwarfForge.jar", "os/linux_x86_64/libdwarf.so.2",
                       "os/linux_x86_64/libdwarf.so.2.3.2", "os/linux_x86_64/libdwarfp.so.2.3.2"):
            (libraries / Path(member).name).write_bytes(bundle.read("GhidraDwarfForge/" + member))
    classes = output / "classes"
    classes.mkdir(exist_ok=True)
    jars = sorted((sdk / "Ghidra").glob("*/*/lib/*.jar"))
    if not jars:
        raise ValueError(f"no SDK libraries found in {sdk}")
    cp = os.pathsep.join(map(str, [classes, libraries / "GhidraDwarfForge.jar", *jars]))
    run(["javac", "-proc:none", "-cp", cp, "-d", classes, *sorted(HERE.glob("*.java"))])
    java = ["java", "--enable-native-access=ALL-UNNAMED", "-cp", cp]
    run([*java, "evaluation.EncodingChecks"], log=output / "encoding.log")
    return libraries, java


def symbols(reference, prefix):
    result = {}
    for line in run([prefix + "nm", "-S", "-n", "--defined-only", reference]).splitlines():
        fields = line.split()
        if fields[-1] in {"eval_probe", "eval_first", "eval_second", "eval_transition", "boot_case"}:
            result[fields[-1]] = (fields[0], fields[1] if len(fields) == 4 else None)
    return result


def build(case, directory):
    prefix = "" if case == "x86_64" else "mips-linux-gnu-"
    reference = directory / "reference"
    target = directory / "original.elf"
    flags = ["-static", "-mabi=32", "-EB"] if case == "mips32be" else []
    if case == "mips64high":
        run([prefix + "as", "-64", "-march=mips64r2", "-mhard-float", HERE / "upper-half.S",
             "-o", directory / "upper.o"])
        run([prefix + "ld", "-m", "elf64btsmip", "-static", "--build-id=sha1", "-z", "max-page-size=4096",
             "-T", TEST / "fixtures/mips64-upper-half.ld", directory / "upper.o", "-o", reference])
    else:
        run([prefix + "gcc", "-g", "-O0", "-fno-pie", "-no-pie", "-fno-omit-frame-pointer",
             *flags, "-Wl,--build-id=sha1", HERE / "fixture.c", "-o", reference])
    run([prefix + "objcopy", "--strip-all", reference, target])
    return target, symbols(reference, prefix)


def compare(case, directory, libraries, java, mode):
    directory.mkdir(parents=True)
    target, names = build(case, directory)
    original = digest(target)
    start, size = names["eval_probe"]
    addresses = [start, size, *(names[key][0] for key in ("eval_transition", "eval_first", "eval_second"))]
    for backend in ("java", "libdwarf"):
        dest = directory / backend
        dest.mkdir()
        sidecar = dest / "fixture.dbg"
        args = [*java, "evaluation.EvaluationFixture", backend, libraries, target, sidecar,
                mode, "eval_probe", *addresses]
        run(args, log=dest / "export.log")
        source = sidecar.with_suffix(".dbg.c")
        before = [digest(sidecar), digest(source)]
        run(args, log=dest / "repeat.log")
        assert before == [digest(sidecar), digest(source)] and digest(target) == original
        run(["readelf", "-hSWn", "--debug-dump=info,abbrev,aranges,decodedline,loc", sidecar],
            log=dest / "readelf.log")
        checked = run(["llvm-dwarfdump", "--verify", sidecar], log=dest / "llvm.log")
        if "No errors." not in checked:
            raise ValueError(checked)
        run(["python3", TEST / "integration/check-dwarfdump.py", sidecar, dest / "strict.log",
             "--original", target], log=dest / "strict-result.log")
        run(["bash", HERE / "debug.sh", case, target, sidecar, mode, *addresses,
             names.get("boot_case", ("0",))[0]], log=dest / "gdb.log")
    results = [(directory / backend / "observations.json").read_text() for backend in ("java", "libdwarf")]
    assert json.loads(results[0]) == json.loads(results[1]), results
    print(f"{case}/{mode}: both producers PASS", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extension", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new results directory")
    parser.add_argument("--cases", nargs="+", choices=("x86_64", "mips32be", "mips64high"),
                        default=["x86_64", "mips32be", "mips64high"])
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    libraries, java = prepare(args.extension, args.ghidra, output)
    for case in args.cases:
        for mode in ("simple", "rich"):
            compare(case, output / case / mode, libraries, java, mode)


if __name__ == "__main__":
    main()
