import gdb, json, os
rows=[]
for label, expected in [('scope_outer',11), ('scope_inner',23), ('scope_after',11)]:
    b=gdb.Breakpoint('*'+label,temporary=True)
    if not rows and os.environ['TARGET']=='x86_64': gdb.execute('run')
    else: gdb.execute('continue')
    assert int(gdb.parse_and_eval('shadow'))==expected
    assert int(gdb.parse_and_eval('this->value'))==7
    assert int(gdb.parse_and_eval('visits'))==1
    block=gdb.block_for_pc(int(gdb.parse_and_eval('$pc')))
    owners=[]
    while block:
        owners.append({'start':int(block.start),'end':int(block.end),'function':str(block.function),'locals':[s.name for s in block]})
        block=block.superblock
    rows.append({'label':label,'shadow':expected,'value':7,'visits':1,'blocks':owners})
assert int(gdb.parse_and_eval('first_object.member'))==5
assert int(gdb.parse_and_eval('second_object.other'))==9
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode'))==0
with open(os.environ['SCOPE_OUT'],'w') as f: json.dump(rows,f,indent=4)
print('COMPILER_SCOPE_ORACLE_PASS')
