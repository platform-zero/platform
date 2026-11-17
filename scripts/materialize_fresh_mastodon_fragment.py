#!/usr/bin/env python3
"""Offline, immutable r2 source derivative; never execute the pinned OLD stack."""
import json
from pathlib import Path
src = Path('src/main/resources/fragments/v3/mastodon/r2/fragment.yaml')
out = Path('src/main/resources/fragments/v3/mastodon/r3/fragment.yaml')
fragment = json.loads(src.read_text())
fragment['revision'] = 3
fragment['id'] = 'private-mastodon-shared-redis-bridge'
retired = {'mastodon-sql-adopt', 'mastodon-original-check', 'mastodon-accounts', 'mastodon-rssq-provision'}
fragment['processes'] = [p for p in fragment['processes'] if p['id'] not in retired]
init = next(p for p in fragment['processes'] if p['id'] == 'mastodon-db-init')
app = next(p for p in fragment['processes'] if p['id'] == 'mastodon')
job = {'artifact': 'mastodon', 'userId': 991, 'entrypoint': '/usr/bin/tini',
       'volumes': [{'volume': 'uploads', 'target': '/opt/mastodon/public/system'},
                   {'volume': 'mastodon-bootstrap', 'target': '/bootstrap'}],
       'tmpfs': ['/tmp', '/opt/mastodon/tmp'], 'oneShot': True, 'memoryMiB': 1536,
       'networks': ['mastodon-data', 'mastodon-bridge-cache']}
fragment['processes'].insert(1, dict(job, id='mastodon-db-migrate', entrypoint='/bin/sh', command=['-ec', 'bundle exec rails db:migrate && bundle exec rails db:seed'], environmentFile='mastodon-migrate.env'))
fragment['processes'].insert(2, dict(job, id='mastodon-fresh-users', command=['exec', 'rails', 'runner', '/run/secrets/mastodon-fresh-users.rb'], environmentFile='mastodon-migrate.env', files=[{'file':'mastodon-fresh-users.rb','target':'/run/secrets/mastodon-fresh-users.rb'}, {'file':'mastodon-users.json','target':'/run/secrets/mastodon-users.json'}]))
fragment['processes'].insert(3, dict(job, id='mastodon-rss-feature', command=['exec', 'rails', 'runner', '/run/secrets/rss-bootstrap.rb'], environmentFile='mastodon-migrate.env', files=[{'file':'rss-bootstrap.rb','target':'/run/secrets/rss-bootstrap.rb'}, {'file':'rss-accounts.json','target':'/run/secrets/rss-accounts.json'}]))
fragment['inputs'] = [v for v in fragment['inputs'] if v['name'] not in {'mastodon-sql-adopt.env','mastodon-original-check.rb', 'mastodon-accounts.rb', 'mastodon-oauth-custody.json','mastodon-rssq-provision.rb','mastodon-rssq-fixtures.json'}]
for pin in fragment['inputs']:
    if pin['name'] == 'rss-accounts.json': pin['consumers'] = ['mastodon-rss-feature']
    if pin['name'] == 'mastodon-migrate.env': pin['consumers'] = ['mastodon-db-migrate','mastodon-fresh-users','mastodon-rss-feature']
    if pin['name'] == 'mastodon-users.json': pin['consumers'] = ['mastodon-fresh-users']
    if pin['name'] == 'postgres-ca.pem': pin['consumers'] = ['mastodon-db-init','mastodon-db-migrate','mastodon-fresh-users','mastodon-rss-feature','mastodon-db-finalize','mastodon','sidekiq','streaming']
for process in fragment['processes']:
    # GraphFragment binds dependencies from install/restore phase graphs only.
    # The r2 draft carried unrecognized per-process duplicates for three daemons.
    process.pop('dependencies', None)
    if process['id'] in ('mastodon-db-migrate','mastodon-fresh-users','mastodon-rss-feature','mastodon','sidekiq','streaming'):
        process.setdefault('files', []).append({'file':'postgres-ca.pem','target':'/run/secrets/postgres-ca.pem'})
fragment['inputs'] += [ {'name': 'mastodon-fresh-users.rb', 'owner':'mastodon', 'purpose':'BOOTSTRAP', 'consumers':['mastodon-fresh-users']},
                        {'name': 'rss-bootstrap.rb', 'owner':'mastodon', 'purpose':'BOOTSTRAP','consumers':['mastodon-rss-feature']} ]
install = fragment['install']
install['processes'] = ['mastodon-db-init','mastodon-db-migrate','mastodon-fresh-users','mastodon-rss-feature','mastodon-db-finalize','mastodon','sidekiq','streaming','social','mastodon-bridge-journal-init','mastodon-redis-bridge']
install['dependencies'] = {'mastodon-db-init':['postgres'], 'mastodon-db-migrate':['mastodon-db-init','mastodon-redis-bridge'],
 'mastodon-fresh-users':['mastodon-db-migrate','mastodon-redis-bridge'], 'mastodon-rss-feature':['mastodon-fresh-users','mastodon-redis-bridge'],
 'mastodon-db-finalize':['mastodon-rss-feature'], 'mastodon':['mastodon-db-finalize','mastodon-redis-bridge'],
 'sidekiq':['mastodon-db-finalize','mastodon-redis-bridge'], 'streaming':['mastodon-db-finalize','mastodon-redis-bridge'],
 'social':['mastodon','streaming','sidekiq','caddy'], 'mastodon-bridge-journal-init':[],
 'mastodon-redis-bridge':['valkey','mastodon-bridge-journal-init']}
install['databaseAccess'] = [dict(v, consumer='mastodon-db-migrate',credentialFile='mastodon-migrate.env', network='mastodon-data') if v['consumer']=='mastodon-sql-adopt' else v for v in install['databaseAccess'] if v['consumer'] != 'mastodon-original-check']
body = json.dumps(fragment, separators=(',',':'))+'\n'
out.parent.mkdir(parents=True, exist_ok=True)
if out.exists():
    assert out.read_text() == body, 'Existing fresh fragment differs; manual review required'
else:
    with out.open('x') as stream: stream.write(body)
print(out)
