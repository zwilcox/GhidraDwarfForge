"""Copied into an owned fixture as its Java executable; never installed in the product."""
import json
import os
from pathlib import Path
import sys
import uuid


def main():
    root = Path(__file__).resolve().parent
    configuration = json.loads((root / 'java.json').read_text(encoding='utf-8'))
    if any(argument.startswith('-javaagent:') for argument in sys.argv[1:]):
        raise ValueError('launcher JVM already has an agent')
    requests = root / 'requests'
    if len(list(requests.iterdir())) >= 16:
        raise ValueError('launcher JVM limit exceeded')
    session = 'forge-integration-' + uuid.uuid4().hex
    with (requests / (session + '.json')).open('x', encoding='utf-8') as stream:
        json.dump({'session': session}, stream)
    execution = Path(configuration['output']) / (session + '.exec')
    option = (f'-javaagent:{configuration["agent"]}=destfile={execution},append=false,'
        f'includes=ghidradwarfforge.*,excludes={":".join(configuration["excludes"])},sessionid={session}')
    java = configuration['java']
    os.execv(java, [java, option, *sys.argv[1:]])


if __name__ == '__main__':
    main()
