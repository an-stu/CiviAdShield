#!/usr/bin/env python3
"""Exercise the signed app on an explicitly selected disposable Android emulator.

Resets only CiviAdShield and the controlled fixture in that emulator. Never targets a phone.
Production app under test is network-only and must declare no accessibility service.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = 'cn.civi.adshield'
FIXTURE = APP + '.fixture'


class Device:
    def __init__(self, serial: str, output: Path):
        self.serial, self.output = serial, output
        self.adb = ROOT / '.toolchain/android-sdk/platform-tools/adb'
        self.results = []
        output.mkdir(parents=True, exist_ok=True)
        assert self.text('shell', 'getprop', 'ro.kernel.qemu').strip() == '1', 'Refusing to reset a physical device'
        self.text('shell','input','keyevent','KEYCODE_WAKEUP')
        self.text('shell','wm','dismiss-keyguard')
        self.text('shell','settings','put','system','screen_off_timeout','1800000')
        sizes=re.findall(r'(\d+)x(\d+)',self.text('shell','wm','size'))
        self.width,self.height=map(int,sizes[-1])

    def call(self, *args, timeout=45, check=True, binary=False):
        proc = subprocess.run([str(self.adb), '-s', self.serial, *map(str, args)], capture_output=True, timeout=timeout)
        if check and proc.returncode:
            raise RuntimeError(f'adb {args}: {proc.stdout.decode(errors="replace")} {proc.stderr.decode(errors="replace")}')
        return proc.stdout if binary else proc.stdout.decode(errors='replace')

    def text(self, *args, **kw):
        return self.call(*args, **kw)

    def check(self, condition, label, detail=None):
        self.results.append({'test': label, 'passed': bool(condition), 'detail': detail})
        (self.output/'results.json').write_text(json.dumps(self.results, ensure_ascii=False, indent=2))
        print(('PASS ' if condition else 'FAIL ') + label, flush=True)
        if not condition:
            self.screenshot('failure')
            raise AssertionError(f'{label}: {detail}')

    def screenshot(self, name):
        (self.output/(name+'.png')).write_bytes(self.call('exec-out', 'screencap', '-p', binary=True))

    def dump(self):
        self.text('shell', 'uiautomator', 'dump', '/sdcard/civi-window.xml', timeout=20)
        xml = self.text('exec-out', 'cat', '/sdcard/civi-window.xml')
        (self.output/'last-window.xml').write_text(xml)
        return ET.fromstring(xml)

    def tap(self, node):
        nums = list(map(int, re.findall(r'\d+', node.get('bounds', ''))))
        if len(nums) != 4:
            raise ValueError('Missing view bounds')
        self.text('shell', 'input', 'tap', (nums[0]+nums[2])//2, (nums[1]+nums[3])//2)
        time.sleep(.5)

    def find(self, text=None, cls=None, rid=None, scroll=False):
        for attempt in range(9 if scroll else 1):
            tree = self.dump()
            for n in tree.iter('node'):
                if text is not None and n.get('text') != text:
                    continue
                if cls is not None and n.get('class') != cls:
                    continue
                if rid is not None and n.get('resource-id') != rid:
                    continue
                bounds=list(map(int,re.findall(r'\d+',n.get('bounds',''))))
                if len(bounds)!=4 or bounds[2]<=bounds[0] or bounds[3]<=bounds[1]:
                    continue
                if scroll and bounds[3]>self.height*.90:
                    continue  # Scroll partially visible controls clear of system navigation.
                return n
            if scroll:
                self.text('shell', 'input', 'swipe', self.width//2, int(self.height*.75), self.width//2, int(self.height*.45), '300')
        raise RuntimeError(f'View not found: text={text}, cls={cls}, rid={rid}')

    def click(self, text, scroll=False):
        self.tap(self.find(text=text, scroll=scroll))

    def top(self):
        for _ in range(4):
            self.text('shell', 'input', 'swipe', self.width//2, int(self.height*.25), self.width//2, int(self.height*.85), '150')

    def main(self):
        self.text('shell', 'am', 'start', '-W', '-f', '0x24000000', '-n', APP+'/.MainActivity')
        time.sleep(.5)
        self.top()

    def fixture_prefs(self):
        raw = self.text('exec-out', 'run-as', FIXTURE, 'cat', 'shared_prefs/fixture.xml', check=False)
        if not raw.strip().startswith('<?xml'):
            return {}
        prefs = {}
        for n in ET.fromstring(raw):
            prefs[n.get('name')] = n.text if n.tag == 'string' else n.get('value')
        return prefs

    def probe(self, host, token, resolver='10.111.0.2'):
        self.text('shell', 'am', 'force-stop', FIXTURE)
        self.text('shell', 'am', 'start', '-W', '-n', FIXTURE+'/.NetworkProbeActivity', '--es', 'host', host, '--es', 'token', token, '--es', 'resolver', resolver)
        deadline = time.monotonic()+40
        while time.monotonic()<deadline:
            result = self.fixture_prefs().get('network_'+token)
            if result:
                parsed = json.loads(result)
                if 'system_lookup' in parsed.get('probes', {}):
                    (self.output/('network-'+token+'.json')).write_text(json.dumps(parsed, ensure_ascii=False, indent=2))
                    return parsed
            time.sleep(.25)
        raise TimeoutError('Network fixture did not finish: '+token)

    def dns_result(self, report, expected_blocked):
        for key in ('udp_a', 'udp_aaaa', 'tcp_a'):
            probe = report['probes'][key]
            # A normal AAAA query may legitimately return NODATA on an IPv4-only network.
            expected = probe.get('valid') and probe.get('rcode')==0 and (probe.get('answerCount')==0 if expected_blocked else key=='udp_aaaa' or probe.get('answerCount', 0)>0)
            self.check(expected, report['token']+' / '+key, probe)

    def rules(self, allow, value):
        self.main()
        self.click('编辑白名单' if allow else '添加自定义域名', scroll=True)
        field=self.find(cls='android.widget.EditText')
        self.tap(field)
        self.text('shell', 'input', 'keycombination', 'KEYCODE_CTRL_LEFT', 'KEYCODE_A')
        self.text('shell', 'input', 'keyevent', 'KEYCODE_DEL')
        if value:
            self.text('shell', 'input', 'text', value)
        self.click('保存')
        time.sleep(.8)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial',default='emulator-5554')
    parser.add_argument('--apk',type=Path,default=ROOT/'dist/CiviAdShield-1.0.3.apk')
    parser.add_argument('--output',type=Path,default=ROOT/'docs/emulator-results')
    args=parser.parse_args()
    d=Device(args.serial,args.output)
    try:
        d.text('shell','settings','delete','secure','enabled_accessibility_services')
        d.text('shell','settings','put','secure','accessibility_enabled','0')
        for pkg in (APP,FIXTURE):
            d.text('uninstall',pkg,check=False)
        d.text('install',args.apk,timeout=60)
        d.text('install',ROOT/'test-fixture/build/outputs/apk/debug/test-fixture-debug.apk',timeout=60)
        d.text('logcat','-c')
        d.main()
        d.check(d.find(text='净屏') is not None,'signed release launches')
        d.screenshot('01-launch')
        baseline=d.probe('example.com','baseline','223.5.5.5')
        d.dns_result(baseline,False)
        d.main()
        d.click('开启域名拦截')
        d.click('继续并授权 VPN')
        # Exercise actual system consent dialogs rather than presetting VPN appops.
        for _ in range(5):
            tree=d.dump()
            nodes=list(tree.iter('node'))
            dialog=[n for n in nodes if n.get('resource-id')=='com.android.permissioncontroller:id/permission_allow_button']
            if dialog:
                d.screenshot('02a-notification-permission');d.tap(dialog[0]); continue
            dialog=[n for n in nodes if n.get('resource-id')=='android:id/button1' and n.get('package')=='com.android.vpndialogs']
            if dialog:
                d.screenshot('02-vpn-permission');d.tap(dialog[0]);continue
            if any(n.get('text')=='广告域名拦截运行中' for n in nodes):
                break
            time.sleep(.5)
        d.check(d.find(text='广告域名拦截运行中') is not None,'VPN starts after real consent')
        d.screenshot('03-protection-running')
        d.dns_result(d.probe('ad.xiaomi.com','builtin-ad'),True)
        d.dns_result(d.probe('example.com','normal'),False)
        d.rules(False,'example.com')
        d.dns_result(d.probe('example.com','custom-block'),True)
        d.rules(True,'example.com')
        d.dns_result(d.probe('example.com','whitelist'),False)
        d.rules(False,'');d.rules(True,'')
        d.main();d.click('暂停域名拦截');time.sleep(1)
        d.check(d.find(text='已暂停，可使用 Clash Meta') is not None,'VPN pause updates UI')
        normal=d.probe('example.com','after-pause','223.5.5.5')
        d.dns_result(normal,False)
        d.check(normal['probes']['system_lookup'].get('valid'),'normal system networking after pause',normal['probes']['system_lookup'])
        declared=d.text('shell','dumpsys','package',APP)
        d.check('BIND_ACCESSIBILITY_SERVICE' not in declared and 'SkipAccessibilityService' not in declared,'production APK has no accessibility service')
        d.check(d.text('shell','settings','get','secure','accessibility_enabled').strip()=='0','network protection tested with accessibility disabled')
        d.main();d.screenshot('04-final-dashboard')
        d.check('FATAL EXCEPTION' not in d.text('logcat','-d','-s','AndroidRuntime:E'),'no AndroidRuntime crashes in test log')
    except Exception:
        d.screenshot('failure')
        raise
    finally:
        (d.output/'logcat.txt').write_text(d.text('logcat','-d','-v','threadtime'))
        print('Results: '+str(d.output),flush=True)


if __name__=='__main__':
    main()
