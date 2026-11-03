#!/usr/bin/env python3
"""Run same-certificate instrumentation against the signed app on this project's emulator."""
from pathlib import Path
import os
import subprocess

ROOT=Path(__file__).resolve().parents[1]
ADB=ROOT/'.toolchain/android-sdk/platform-tools/adb'
SERIAL='emulator-5554'

def adb(*args,check=True):
    return subprocess.run([str(ADB),'-s',SERIAL,*args],check=check,capture_output=True,text=True)

def main():
    assert adb('shell','getprop','ro.kernel.qemu').stdout.strip()=='1','Emulator required'
    subprocess.run([str(ROOT/'tools/build.sh'),':app:assembleDebugAndroidTest','--console=plain'],cwd=ROOT,check=True)
    props=dict(l.split('=',1) for l in (ROOT/'.signing/signing.properties').read_text().splitlines() if '=' in l)
    out=ROOT/'.toolchain/test-artifacts';out.mkdir(exist_ok=True)
    secret=out/'temporary-password'
    secret.write_text(props['storePassword']+'\n'+props['keyPassword']+'\n');secret.chmod(0o600)
    env=os.environ.copy();env['JAVA_HOME']=env.get('JAVA_HOME','/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home')
    try:
        subprocess.run([str(ROOT/'.toolchain/android-sdk/build-tools/35.0.0/apksigner'),'sign','--ks',props['storeFile'],'--ks-key-alias',props['keyAlias'],'--ks-pass','file:'+str(secret),'--key-pass','file:'+str(secret),'--out',str(out/'release-instrumentation.apk'),str(ROOT/'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk')],env=env,check=True)
    finally:secret.unlink(missing_ok=True)
    adb('uninstall','cn.civi.adshield.test',check=False)
    print(adb('install','-t',str(out/'release-instrumentation.apk')).stdout,flush=True)
    result=adb('shell','am','instrument','-w','cn.civi.adshield.test/cn.civi.adshield.SmokeInstrumentation')
    print(result.stdout,flush=True)
    log=ROOT/'docs/emulator-results/release-1.0.1-passed/instrumentation.txt'
    log.parent.mkdir(parents=True,exist_ok=True);log.write_text(result.stdout+result.stderr)
    if 'PASS 24 integration checks:' not in result.stdout or 'FAILED' in result.stdout:raise SystemExit('Instrumentation failed; see '+str(log))

if __name__=='__main__':main()
