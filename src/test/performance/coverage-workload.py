#!/usr/bin/env python3
"""Measure ordinary production coverage from a copied saved workload, with validators/GDB."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile

SOURCE = Path(__file__).resolve().parent
REPOSITORY = SOURCE.parents[2]
spec = importlib.util.spec_from_file_location('benchmark_support', SOURCE / 'export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def instrument(source):
    replacements = {
        'public class GhidraDwarfForge extends GhidraScript {':
            'public class CoverageWorkloadExport extends GhidraScript {',
        '        var functions = extraction.functions();': '''        var functions = extraction.functions();
        var decoded = ghidradwarfforge.GhidraInstructionEvidence.capture(currentProgram,
            functions, rebaseDelta, monitor, diagnostic);''',
        '            extraction.skippedFunctions(), diagnostics);': '''            extraction.skippedFunctions(), diagnostics);
        long coverageStarted = System.nanoTime();
        var coverage = ghidradwarfforge.coverage.ExportCoverage.build(typeModel, source,
            decoded, result.emission(), monitor::isCancelled);
        var profile = new ghidradwarfforge.output.CoverageReportJson.Profile(
            currentProgram.getLanguageID().getIdAsString(), currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        var claims = new ghidradwarfforge.output.CoverageReportClaims(profile, coverage);
        var observation = new com.google.gson.JsonObject();
        observation.addProperty("coverageAssemblyNanos", System.nanoTime() - coverageStarted);
        observation.addProperty("functions", coverage.functions().size());
        observation.addProperty("decodedInstructions", coverage.sourceUnion().decodedInstructions());
        observation.addProperty("recoveredVariables", coverage.variables().recoveredVariables());
        observation.addProperty("knownScopeVariables", coverage.variables().knownScopeVariables());
        observation.addProperty("unknownScopeVariables", coverage.variables().unknownScopeVariables());
        observation.addProperty("canonicalFunctionTypeNodes", coverage.functionTypeUnion().recoveredNodes());
        observation.addProperty("scope", "Instrumented copied production script, actual saved workload; ordinary exporter unchanged");
        long writeStarted = System.nanoTime();
        try {
            String payload = ghidradwarfforge.output.CoverageReportJson.write(coverage, profile, monitor::isCancelled);
            Path payloadPath = Path.of(output + ".coverage.json");
            Files.writeString(payloadPath, payload, java.nio.charset.StandardCharsets.UTF_8);
            observation.addProperty("payloadUtf8Bytes", Files.size(payloadPath));
            try (var payloadReader = new com.google.gson.stream.JsonReader(new java.io.StringReader(payload))) {
                observation.addProperty("payloadValues", countValues(payloadReader));
            }
            observation.addProperty("payloadWriteAndCountNanos", System.nanoTime() - writeStarted);
            writeStarted = System.nanoTime();
            String fullReport = report.toJsonWithCoverage(claims, monitor::isCancelled);
            Files.writeString(Path.of(output + ".schema-two.json"), fullReport, java.nio.charset.StandardCharsets.UTF_8);
            observation.addProperty("reportWriteAndPreflightNanos", System.nanoTime() - writeStarted);
            observation.addProperty("status", "ACCEPTED");
        }
        catch (IOException rejected) {
            observation.addProperty("status", "ADMISSION_REJECTED");
            observation.addProperty("diagnostic", rejected.getMessage());
        }
        Files.writeString(Path.of(output + ".coverage-observation.json"), observation.toString(), java.nio.charset.StandardCharsets.UTF_8);
        println("Coverage workload observation: " + observation);
''',
        '    private void runExport() throws Exception {': '''    private long countValues(com.google.gson.stream.JsonReader reader) throws IOException, CancelledException {
        monitor.checkCancelled();
        long count = 1;
        switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                reader.beginObject();
                while (reader.hasNext()) { reader.nextName(); count += countValues(reader); }
                reader.endObject();
            }
            case BEGIN_ARRAY -> {
                reader.beginArray();
                while (reader.hasNext()) count += countValues(reader);
                reader.endArray();
            }
            case NULL -> reader.nextNull();
            case STRING, NUMBER -> reader.nextString();
            default -> throw new IOException("unexpected generated coverage token");
        }
        return count;
    }

    private void runExport() throws Exception {''',
    }
    for old, new in replacements.items():
        assert source.count(old) == 1, 'production script boundary changed: ' + old
        source = source.replace(old, new)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=['sqlite', 'uboot'])
    parser.add_argument('reference_case', type=Path)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--historical-instrumented', action='store_true',
        help='reproduce the pre-integration probe using an older schema-one installation')
    args = parser.parse_args()
    reference = args.reference_case.resolve(strict=True)
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    summary = json.loads((reference / 'summary.json').read_text())
    assert summary['status'] == 'PASS'
    if args.kind == 'sqlite':
        binary = reference / 'sqlite-workload'
        assert support.digest(binary) == summary['inputSha256']
        provenance = json.loads((reference / 'source-provenance.json').read_text())
        assert provenance['archiveSha256'] == '77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784'
        project_name = 'SQLite'
    else:
        built = Path(summary['buildCase']).resolve(strict=True)
        provenance = json.loads((built / 'build-result.json').read_text())
        assert provenance['archiveSha256'] == 'cdef7d507c93f1bbd9f015ea9bc21fa074268481405501945abc6f854d5b686f'
        binary = built / 'u-boot.workload'
        assert support.digest(binary) == provenance['artifacts'][binary.name]['sha256']
        project_name = 'UBoot'
    root = REPOSITORY / 'build/test-results/coverage-workload'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.kind + '.', dir=root))
    print('coverage-workload-case=' + str(case), flush=True)
    protected = [binary, reference / 'summary.json', Path(__file__), SOURCE / 'export-benchmark.py']
    if args.kind == 'uboot':
        protected += [built / 'u-boot.reference', built / 'u-boot.dtb', built / 'build-result.json', reference / 'function-addresses.json']
    else:
        protected.append(reference / 'source-provenance.json')
    behavior_path = SOURCE / ('paired-saved-exports.py' if args.kind == 'sqlite' else 'uboot-benchmark.py')
    protected.append(behavior_path)
    protected += [p for directory in [reference / 'project', module] for p in directory.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    (case / 'protected-before.json').write_text(json.dumps(before, indent=4) + '\n')
    shutil.copytree(reference / 'project', case / 'project')
    project_before = {str(p.relative_to(case / 'project')): support.digest(p)
        for p in (case / 'project').rglob('*') if p.is_file()}
    scripts = case / 'scripts'
    scripts.mkdir()
    installed_script = module / 'ghidra_scripts/GhidraDwarfForge.java'
    if args.historical_instrumented:
        (scripts / 'CoverageWorkloadExport.java').write_text(instrument(installed_script.read_text()))
    sidecar = case / (binary.name + '.dbg')
    command = [ghidra / 'support/analyzeHeadless', case / 'project', project_name,
        '-process', binary.name, '-noanalysis', '-readOnly', '-max-cpu', '4', '-scriptPath', scripts,
        '-postScript', 'CoverageWorkloadExport.java' if args.historical_instrumented else 'GhidraDwarfForge.java',
        '--packaged-natives', '--input=' + str(binary), '--output=' + str(sidecar)]
    if args.kind == 'uboot':
        command.append('--gdb-loader')
    metrics = support.run(command, case / 'export.log', timeout=1800, measured=True)
    runtime = support.verify_headless(case / 'export.log', module, exported=not args.historical_instrumented)
    if args.historical_instrumented:
        observation = json.loads(Path(str(sidecar) + '.coverage-observation.json').read_text())
    else:
        bodies = [line.split('GhidraDwarfForge report: ', 1)[1]
            for line in (case / 'export.log').read_text().splitlines() if 'GhidraDwarfForge report: ' in line]
        assert len(bodies) == 1
        report, end = json.JSONDecoder().raw_decode(bodies[0])
        assert report['schemaVersion'] == 2 and report['status'] in ('SUCCESS', 'PARTIAL')
        assert report['coverage']['definitionVersion'] == 1 and report['validation'] == {'status': 'NOT_RUN'}
        assert bodies[0][end:].strip() == '(GhidraScript)'
        for kind, path in [('input', binary), ('output', sidecar), ('source', Path(str(sidecar) + '.c'))]:
            assert report['artifacts'][kind + 'Path'] == str(path)
            assert report['artifacts'][kind + 'Sha256'] == support.digest(path)
        report_path = case / 'production-report.json'
        report_path.write_text(bodies[0][:end], encoding='utf-8')
        coverage = report['coverage']
        observation = {'status': 'ACCEPTED', 'scope': 'ordinary installed production exporter, report preflight before publication',
            'functions': len(coverage['functions']), 'summary': coverage['summary'],
            'reportUtf8Bytes': report_path.stat().st_size, 'reportSha256': support.digest(report_path),
            'exportStatus': report['status'], 'functionsFailed': report['counts']['functionsFailed']}
        (case / 'coverage-observation.json').write_text(json.dumps(observation, indent=4) + '\n')
    assert observation['status'] in ('ACCEPTED', 'ADMISSION_REJECTED')
    for name, command in [('llvm', ['llvm-dwarfdump', '--verify', sidecar]),
            ('elf', ['readelf', '-hSWn', sidecar]),
            ('strict', ['python3', SOURCE.parent / 'integration/check-dwarfdump.py', sidecar, case / 'strict-checks.log', '--original', binary])]:
        support.run(command, case / (name + '.log'), timeout=300)
        support.require_clean(case / (name + '.log'))
    assert 'No errors.' in (case / 'llvm.log').read_text()
    behavior_spec = importlib.util.spec_from_file_location('coverage_workload_behavior', behavior_path)
    behavior = importlib.util.module_from_spec(behavior_spec)
    behavior_spec.loader.exec_module(behavior)
    if args.kind == 'sqlite':
        def run(name, command, **kwargs):
            return support.run(command, case / (name + '.log'), **kwargs)
        behavior.validate_sqlite_behavior(case, binary, sidecar, run)
    else:
        addresses = json.loads((reference / 'function-addresses.json').read_text())
        behavior.validate_behavior(case, built / 'u-boot.reference', binary, built / 'u-boot.dtb', sidecar, addresses)
    after = {str(p): support.digest(p) for p in protected}
    (case / 'protected-after.json').write_text(json.dumps(after, indent=4) + '\n')
    assert before == after, 'probe changed protected input/project/module'
    project_after = {str(p.relative_to(case / 'project')): support.digest(p)
        for p in (case / 'project').rglob('*') if p.is_file()}
    assert project_before == project_after, 'read-only copied project changed'
    result = {'probeStatus': 'OBSERVED', 'kind': args.kind, 'observation': observation, 'processMetrics': metrics, 'runtime': runtime,
        'referenceCase': str(reference), 'originalSha256': support.digest(binary),
        'installedScriptSha256': support.digest(installed_script),
        'probeScriptSha256': support.digest(scripts / 'CoverageWorkloadExport.java') if args.historical_instrumented else None,
        'jarSha256': support.digest(module / 'lib/GhidraDwarfForge.jar'), 'protectedFiles': len(before),
        'gdbBehavior': 'PASS',
        'limits': 'Single observation; no repeated performance medians or full coverage acceptance.'}
    (case / 'observation.json').write_text(json.dumps(result, indent=4) + '\n')
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
