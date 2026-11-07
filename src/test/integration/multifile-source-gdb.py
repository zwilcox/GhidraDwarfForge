"""GDB runtime oracle for the source-built multi-file presentation fixture."""
import gdb
import json
import os
from pathlib import Path
def quote(value):
    return json.dumps(str(value), ensure_ascii=False)

sidecar=Path(os.environ['FORGE_TEST_SIDECAR'])
index=Path(str(sidecar)+'.c').read_text()
manifest_name=next(line.removeprefix(' * Manifest: ') for line in index.splitlines() if line.startswith(' * Manifest: '))
manifest=json.loads((sidecar.parent/manifest_name).read_text())
functions={item['name']:item for item in manifest['functions']}
def expected_file(name):
    return manifest['parts'][functions[name]['file']-1]['name']
gdb.execute('file '+quote(os.environ['FORGE_TEST_ORIGINAL']))
gdb.execute('set auto-solib-add off')
companion=os.environ.get('FORGE_TEST_COMPANION')
original_rules=gdb.execute('show substitute-path', to_string=True)
if companion:
    gdb.execute('starti')
    gdb.execute('source '+companion)
    registry=gdb._forge_loader_registry_v1
    binding=next(iter(registry.manifests.values()))
    old_directory=binding['source_directory']
    selected_directory=str(sidecar.parent)
    rule_case=os.environ.get('FORGE_TEST_RULE_CASE', '')
    matching_rule='set substitute-path '+quote(old_directory)+' '+quote(selected_directory)
    foreign_rule='set substitute-path '+quote(old_directory)+' /unrelated-user-source'
    if rule_case=='matching':
        gdb.execute(matching_rule)
        original_rules=gdb.execute('show substitute-path', to_string=True)
    if rule_case=='conflict':
        gdb.execute(foreign_rule)
        foreign=gdb.execute('show substitute-path', to_string=True)
        before_conflict=list(gdb.objfiles())
        try:
            gdb.execute('forge-load')
            raise AssertionError('loader overwrote conflicting source rule')
        except gdb.error as error:
            assert 'conflicts' in str(error), str(error)
        assert list(gdb.objfiles())==before_conflict
        assert gdb.execute('show substitute-path', to_string=True)==foreign
        gdb.execute('unset substitute-path '+quote(old_directory))
    before=list(gdb.objfiles())
    # Refuse missing source dependencies before installing symbols or changing mappings.
    part=sidecar.parent/manifest['parts'][0]['name']
    hidden=part.with_name(part.name+'.hidden')
    assert not hidden.exists()
    part.rename(hidden)
    try:
        try:
            gdb.execute('forge-load')
            raise AssertionError('loader accepted missing source part')
        except gdb.error as error:
            assert 'cannot verify source dependency' in str(error), str(error)
        assert list(gdb.objfiles())==before
        assert gdb.execute('show substitute-path', to_string=True)==original_rules
    finally:
        hidden.rename(part)
    gdb.execute('forge-load')
    if rule_case=='replacement':
        gdb.execute(foreign_rule)
        foreign=gdb.execute('show substitute-path', to_string=True)
        gdb.execute('forge-unload')
        assert gdb.execute('show substitute-path', to_string=True)==foreign
        gdb.execute('unset substitute-path '+quote(old_directory))
        gdb.execute('forge-load')
else:
    gdb.execute('symbol-file '+quote(sidecar))
gdb.execute('info functions recovered_')
gdb.execute('list recovered_first')
gdb.execute('list recovered_second')
gdb.execute('ptype recovered_first')
resolved=gdb.Breakpoint(expected_file('recovered_second')+':recovered_second')
assert resolved.locations and not resolved.pending
resolved.enabled=False
gdb.execute('break recovered_first')
gdb.execute('continue' if companion else 'run')
first=gdb.selected_frame().find_sal().symtab.fullname()
assert 'forge-src-' in first, first
assert Path(first).name==expected_file('recovered_first')
if companion:
    assert Path(first).parent==sidecar.parent, first
assert gdb.selected_frame().name()=='recovered_first'
for count in range(12):
    gdb.execute('step')
    if gdb.selected_frame().name()=='recovered_second': break
else: raise AssertionError('step did not enter second function')
second=gdb.selected_frame().find_sal().symtab.fullname()
assert second != first and 'forge-src-' in second, (first,second)
assert Path(second).name==expected_file('recovered_second')
if companion:
    assert Path(second).parent==sidecar.parent, second
gdb.execute('list')
gdb.execute('finish')
assert int(gdb.parse_and_eval('observed'))==10
gdb.execute('next')
gdb.execute('continue')
assert gdb.selected_inferior().pid==0
if companion:
    assert gdb.execute('show substitute-path', to_string=True)==original_rules
print('MULTIFILE_GDB_PASS '+json.dumps({'first':first,'second':second}))
