#!/usr/bin/env python3
"""Fetch the pinned official Apple Silicon emulator and API35 AOSP image in verified ranges."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import zip_longest
import hashlib
import re
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
DEST=ROOT/'.toolchain/downloads'
CHUNK=4*1024*1024
PACKAGES=[
    ('emulator-darwin_aarch64-16740729.zip',416113219,'6c5e61b873e11c7d1d08683bea089f762baee070','https://dl.google.com/android/repository/'),
    ('arm64-v8a-35_r02.zip',769099654,'2026a06409db630b56711afdbffb457c1dbaed49','https://dl.google.com/android/repository/sys-img/android/'),
]

def fetch(task):
    name,total,sha,base,start=task
    end=min(total,start+CHUNK)-1
    size=end-start+1
    folder=DEST/(name+'.parts');folder.mkdir(parents=True,exist_ok=True)
    part=folder/str(start)
    if part.exists() and part.stat().st_size==size:return name,size
    tmp=part.with_suffix('.tmp');headers=part.with_suffix('.headers')
    for attempt in range(6):
        url=base+name
        if attempt>=2:url+=f'?civi_range={start}&attempt={attempt}'
        if attempt>=4:url=url.replace('https://dl.google.com/android/','https://edgedl.me.gvt1.com/edgedl/android/')
        proc=subprocess.run(['curl','--noproxy','*','-fLSs','--connect-timeout','6','--max-time','25','--max-filesize',str(size),'-H',f'Range: bytes={start}-{end}','-D',str(headers),'-o',str(tmp),url],capture_output=True)
        h=headers.read_text(errors='replace') if headers.exists() else ''
        match=re.search(r'content-range:\s*bytes\s+(\d+)-(\d+)/(\d+)',h,re.I)
        if proc.returncode==0 and tmp.exists() and tmp.stat().st_size==size and match and tuple(map(int,match.groups()))==(start,end,total):
            tmp.replace(part);headers.unlink(missing_ok=True);return name,size
        time.sleep(min(4,.5*(attempt+1)))
    raise RuntimeError(f'{name} range {start}-{end}: {proc.stderr.decode(errors="replace")[-250:]}')

def assemble(package):
    name,total,sha,base=package
    target=DEST/name
    digest=hashlib.sha1()
    with target.with_suffix('.assembling').open('wb') as out:
        for start in range(0,total,CHUNK):
            b=(DEST/(name+'.parts')/str(start)).read_bytes();digest.update(b);out.write(b)
    if digest.hexdigest()!=sha:raise RuntimeError('Official SHA1 mismatch: '+name)
    target.with_suffix('.assembling').replace(target)
    print('VERIFIED '+str(target)+' SHA1='+sha,flush=True)

def main():
    DEST.mkdir(parents=True,exist_ok=True)
    tasks=[]
    streams=[[(name,total,sha,base,start) for start in range(0,total,CHUNK)] for name,total,sha,base in PACKAGES]
    for pair in zip_longest(*streams):tasks.extend(t for t in pair if t is not None)
    progress={p[0]:0 for p in PACKAGES};last=0;assembled=set();failures=[]
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures=[pool.submit(fetch,t) for t in tasks]
        for f in as_completed(futures):
            try:name,n=f.result()
            except Exception as e:
                failures.append(str(e));print('RETRY NEEDED '+str(e),flush=True);continue
            progress[name]+=n
            package=next(p for p in PACKAGES if p[0]==name)
            if progress[name]==package[1]:assemble(package);assembled.add(name)
            if time.monotonic()-last>10:
                print(' | '.join(f'{name}: {n}/{next(p[1] for p in PACKAGES if p[0]==name)} bytes' for name,n in progress.items()),flush=True);last=time.monotonic()
    if failures:raise RuntimeError('\n'.join(failures))

if __name__=='__main__':main()
