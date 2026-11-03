#!/bin/sh
set -eu
PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export JAVA_HOME=${JAVA_HOME:-/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home}
export CIVI_PROJECT_ROOT="$PROJECT_ROOT"
python3 - <<'PY'
import os, pathlib, secrets, subprocess
root=pathlib.Path(os.environ['CIVI_PROJECT_ROOT'])
signing=root/'.signing'
signing.mkdir(mode=0o700,exist_ok=True)
props=signing/'signing.properties'
key=signing/'adshield-release.jks'
if not props.exists():
    if key.exists():
        raise SystemExit('Signing key exists but properties missing. Restore signing.properties; refusing to replace key.')
    password=secrets.token_hex(24)
    secret=signing/'temporary-password'
    secret.write_text(password)
    secret.chmod(0o600)
    try:
        subprocess.run([os.environ['JAVA_HOME']+'/bin/keytool','-genkeypair','-keystore',str(key),'-storetype','JKS','-alias','civi-adshield','-keyalg','RSA','-keysize','3072','-validity','10000','-dname','CN=Civi AdShield personal build','-storepass:file',str(secret),'-keypass:file',str(secret)],check=True)
        props.write_text('storeFile='+str(key)+'\nstorePassword='+password+'\nkeyAlias=civi-adshield\nkeyPassword='+password+'\n')
        props.chmod(0o600)
        key.chmod(0o600)
    finally:
        secret.unlink(missing_ok=True)
PY
if [ -f "$PROJECT_ROOT/.toolchain/test-libs/junit-4.13.2.jar" ] && [ -f "$PROJECT_ROOT/.toolchain/test-libs/hamcrest-core-1.3.jar" ]; then
  set -- "-PciviTestLibs=$PROJECT_ROOT/.toolchain/test-libs"
else
  set --
fi
"$PROJECT_ROOT/tools/build.sh" "$@" testDebugUnitTest lintDebug assembleRelease --console=plain
mkdir -p "$PROJECT_ROOT/dist"
cp "$PROJECT_ROOT/app/build/outputs/apk/release/app-release.apk" "$PROJECT_ROOT/dist/CiviAdShield-1.0.1.apk"
"$PROJECT_ROOT/.toolchain/android-sdk/build-tools/35.0.0/apksigner" verify --verbose --print-certs "$PROJECT_ROOT/dist/CiviAdShield-1.0.1.apk"
python3 - <<'PY'
import hashlib,os,pathlib,zipfile
root=pathlib.Path(os.environ['CIVI_PROJECT_ROOT'])
dest=root/'dist'
with zipfile.ZipFile(dest/'CiviAdShield-1.0.1-source.zip','w',zipfile.ZIP_DEFLATED) as z:
    for p in sorted(root.rglob('*')):
        if not p.is_file(): continue
        rel=p.relative_to(root)
        if any(x in {'.toolchain','.gradle','.git','.signing','build','dist','__pycache__'} for x in rel.parts): continue
        if rel.name in {'local.properties','.DS_Store'}: continue
        z.write(p,'CiviAdShield/'+str(rel))
files=[dest/'CiviAdShield-1.0.1.apk',dest/'CiviAdShield-1.0.1-source.zip']
(dest/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in files))
print('APK and source package ready in '+str(dest))
PY
