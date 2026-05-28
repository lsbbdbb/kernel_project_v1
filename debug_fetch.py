import sys, json, os, re, shutil
sys.path.insert(0, '/app')
from agent.tools.patch_fetcher import PatchFetcher, _url_to_cache_key

workdir = '/tmp/debug_cve'
cve_id = 'CVE-2026-0011'
os.makedirs(os.path.join(workdir, cve_id, 'metadata'), exist_ok=True)
os.makedirs(os.path.join(workdir, cve_id, 'patches'), exist_ok=True)

shutil.copy('/app/tests/testdata/metadata/CVE-2026-0011_metadata.json',
            os.path.join(workdir, cve_id, 'metadata', 'cve_metadata.json'))

fetcher = PatchFetcher(workdir, cve_id)
with open(os.path.join(workdir, cve_id, 'metadata', 'cve_metadata.json')) as f:
    md = json.load(f)

patch_url = None
for ref in md.get('nvd', {}).get('references', []):
    url = ref.get('url', '')
    print(f'URL: {url}')
    m = re.match(r'(https?://git\.kernel\.org)/.*?/c/([0-9a-f]+)', url)
    if m:
        patch_url = f'{m.group(1)}/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={m.group(2)}'
        print(f'Patch URL: {patch_url}')
        key = _url_to_cache_key(patch_url)
        print(f'Cache key: {key}')
        cache_path = os.path.join(fetcher._patch_cache_dir(), f'{key}.patch')
        print(f'Cache path: {cache_path}')
        print(f'Cache exists: {os.path.isfile(cache_path)}')
        break

if patch_url:
    result = fetcher.fetch_from_url(patch_url)
    print(f"Result success: {result.get('success')}")
    print(f"Result error: {result.get('error', 'none')}")
    print(f"Result path: {result.get('path', 'none')}")
else:
    print('No patch URL found!')
