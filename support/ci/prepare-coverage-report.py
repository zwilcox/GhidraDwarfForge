#!/usr/bin/env python3
"""Reuse this run's authenticated report tools without rebuilding the extension."""
import argparse
import importlib.util
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('hosted_coverage_tools',
    ROOT / 'src/test/coverage/hosted-combined-report.py')
hosted = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hosted)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--classpath', type=Path, required=True)
    args = parser.parse_args()
    bundle = args.bundle.resolve(strict=True)
    manifest = json.loads((bundle / 'collection/manifest.json').read_text())
    if (manifest.get('commit') != os.environ['GITHUB_SHA']
            or manifest.get('run') != os.environ['GITHUB_RUN_ID']):
        raise ValueError('report tools require the producing commit/run')
    classpath = hosted.tools_classpath(bundle)
    args.classpath.parent.mkdir(parents=True, exist_ok=True)
    args.classpath.write_text(classpath)


if __name__ == '__main__':
    main()
