"""Synthetic grouping metadata for oracle-admission controls; not CI evidence."""


def bind(hosted, root, jar, records, target):
    groups = hosted.grouped_coverage
    inventory = hosted.files.read(hosted.GROUP_INVENTORY)
    identity = {'commit': 'a' * 40, 'run': '7', 'attempt': 1, 'target': target,
        'group': 'primary', 'job': 'target-integration'}
    for collection in records:
        if collection.root.exists():
            collection.record['ciGroup'] = identity
            collection._save()
    summary_path = root / 'report/summary.json'
    summary = hosted.files.read(summary_path)
    summary['cohort']['job'] = 'target-coverage'
    for layer in summary['layers'].values():
        for name in layer['receipts']:
            layer['receipts'][name] = hosted.files.digest(root / 'collections' / name / 'receipt.json')
    hosted.files.save(summary_path, summary)
    manifests = {}
    for group in groups.group_names(inventory, target):
        payload = groups.collection_files(root / 'collections', jar, identity) if group == 'primary' else {
            'files': {}, 'collections': {}, 'sessions': []}
        manifests[group] = {'schema': 1, 'status': 'SEALED_GROUP_COLLECTIONS',
            'identity': dict(identity, group=group), 'inventorySha256': groups.inventory_digest(inventory),
            'productionJarSha256': groups.digest(jar), **payload}
    groups.coverage.save(root / 'groups.json', {'schema': 1, 'status': 'COMPLETE_GROUP_COLLECTIONS',
        'commit': 'a' * 40, 'run': '7', 'attempt': 1, 'target': target,
        'inventorySha256': groups.inventory_digest(inventory), 'productionJarSha256': groups.digest(jar),
        'groups': manifests})
    return summary
