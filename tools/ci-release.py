#!/usr/bin/env python3
"""Signing and immutable versioned Release packaging for trusted main-branch CI."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
REPO='an-stu/CiviAdShield'
CERT_SHA256='d504ff6cb479a7267f003f387c2676dec60b9536744e08b7e5b6d485c89dd096'

def prop(value: str) -> str:
    return value.replace('\\','\\\\').replace('\n','\\n').replace('\r','\\r').replace('=','\\=').replace(':','\\:')

def restore_signing():
    values={name:os.environ.get(name,'') for name in ('ANDROID_KEYSTORE_BASE64','ANDROID_STORE_PASSWORD','ANDROID_KEY_PASSWORD','ANDROID_KEY_ALIAS')}
    if not all(values.values()):raise SystemExit('Required Android signing repository secrets are missing')
    folder=ROOT/'.signing';folder.mkdir(mode=0o700,exist_ok=True)
    key=Path(os.environ['RUNNER_TEMP'])/'civi-adshield-signing.jks'
    key.write_bytes(base64.b64decode(values['ANDROID_KEYSTORE_BASE64'],validate=True));key.chmod(0o600)
    mapping={'storeFile':str(key),'storePassword':values['ANDROID_STORE_PASSWORD'],'keyAlias':values['ANDROID_KEY_ALIAS'],'keyPassword':values['ANDROID_KEY_PASSWORD']}
    props=folder/'signing.properties'
    props.write_text(''.join(k+'='+prop(v)+'\n' for k,v in mapping.items()));props.chmod(0o600)
    print('Signing configuration restored; private key is outside the checkout')

def package():
    folder=ROOT/'app/build/outputs/apk/release'
    meta=json.loads((folder/'output-metadata.json').read_text())['elements'][0]
    version=meta['versionName'];code=meta['versionCode']
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?',version):raise SystemExit('Invalid application versionName')
    if not isinstance(code,int) or not 0<code<2100000000:raise SystemExit('Invalid versionCode')
    filename=meta['outputFile']
    if Path(filename).name!=filename:raise SystemExit('Unexpected APK output path')
    apk=folder/filename
    sdk=Path(os.environ.get('ANDROID_HOME',str(ROOT/'.toolchain/android-sdk')))
    verification=subprocess.check_output([str(sdk/'build-tools/35.0.0/apksigner'),'verify','--verbose','--print-certs',str(apk)],text=True)
    if 'certificate SHA-256 digest: '+CERT_SHA256 not in verification:raise SystemExit('APK signing certificate does not match the installed application')
    out=ROOT/'release-artifacts';out.mkdir(exist_ok=True)
    target=out/f'CiviAdShield-{version}.apk';shutil.copyfile(apk,target)
    digest=hashlib.sha256(target.read_bytes()).hexdigest()
    (out/'SHA256SUMS.txt').write_text(digest+'  '+target.name+'\n')
    info={'versionName':version,'versionCode':code,'tag':'v'+version,'commit':os.environ.get('GITHUB_SHA',subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()),'apk':target.name,'sha256':digest,'signingCertificateSha256':CERT_SHA256}
    (out/'release-info.json').write_text(json.dumps(info,ensure_ascii=False,indent=2)+'\n')
    print('Prepared '+target.name+'; existing application signature verified')

def publish():
    if os.environ.get('GITHUB_REPOSITORY')!=REPO:raise SystemExit('Publishing is restricted to the configured repository')
    out=ROOT/'release-artifacts';info=json.loads((out/'release-info.json').read_text());tag=info['tag']
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?',tag):raise SystemExit('Invalid Release tag')
    head=subprocess.check_output(['gh','api',f'repos/{REPO}/git/ref/heads/main','--jq','.object.sha'],text=True).strip()
    if head!=info['commit']:
        print('Main has advanced; this build remains an artifact and the newer commit will publish the Release.')
        return
    found=subprocess.run(['gh','release','view',tag,'--repo',REPO,'--json','url'],capture_output=True,text=True)
    if found.returncode==0:
        print('Release '+tag+' already exists; versioned assets stay unchanged. Current signed APK is available in workflow artifacts.')
        return
    note=ROOT/'docs/releases'/f'{tag}.md'
    if not note.exists():
        note=out/'release-notes.md'
        note.write_text(f'# 净屏 {tag}\n\nAndroid 8.0+，免 Root。广告域名拦截使用本地 VPN；不使用无障碍或默认链接接管。\n\n源码提交：`{info["commit"]}`\n\n[权限说明](https://github.com/{REPO}/blob/{tag}/PERMISSIONS.md)\n\n已完成云端单元测试与静态检查；手机上的具体应用及 HyperOS 行为请按需验证。\n')
    command=['gh','release','create',tag,'--repo',REPO,'--target',info['commit'],'--title','净屏 '+tag,'--notes-file',str(note),str(out/info['apk']),str(out/'SHA256SUMS.txt'),str(out/'release-info.json')]
    if '-' in info['versionName']:command.append('--prerelease')
    subprocess.run(command,check=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['restore-signing','package','publish']);args=parser.parse_args()
    {'restore-signing':restore_signing,'package':package,'publish':publish}[args.action]()
