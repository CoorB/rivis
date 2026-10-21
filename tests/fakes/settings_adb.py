#!/usr/bin/python3 -I
"""One Play emulator with a small Settings screen state machine for offline setup tests."""
import os
import sys
import time

root = os.environ['FAKE_SETTINGS_DIR']
a = sys.argv[1:]
if a[:2] == ['-s', 'emulator-5554']:
    a = a[2:]
cmd = ' '.join(a)
with open(os.path.join(root, 'log'), 'a') as out:
    out.write(cmd + '\n')


def read(name, default=''):
    try:
        return open(os.path.join(root, name)).read().strip()
    except OSError:
        return default


def set_screen(value):
    open(os.path.join(root, 'screen'), 'w').write(value)


screen = read('screen', 'initial')
if cmd == 'devices':
    print('List of devices attached\nemulator-5554\tdevice')
elif cmd in ('shell getprop ro.kernel.qemu', 'shell getprop ro.boot.qemu'):
    print('1')
elif cmd == 'shell id -u':
    print('2000')
elif cmd == 'shell wm size':
    print('Physical size: 1080x2400')
elif cmd == 'shell settings get global http_proxy':
    print(read('proxy', ':0'))
elif cmd.startswith('shell settings put global http_proxy'):
    open(os.path.join(root, 'proxy'), 'w').write(a[-1])
elif 'TRUSTED_CREDENTIALS_USER' in cmd:
    if read('stall') == 'trust':
        time.sleep(30)
    set_screen('trusted')
    print('Status: ok')
elif cmd.startswith('shell am start') and 'SECURITY_SETTINGS' in cmd:
    set_screen('security')
elif cmd == 'shell dumpsys window':
    print('mCurrentFocus=com.android.settings/.SecuritySettings')
elif cmd == 'shell cat /sdcard/proxy-ui.xml':
    screen = read('screen', 'initial')
    if screen == 'trusted':
        labels = ['User'] + (['mitmproxy'] if read('installed') else [])
    elif screen == 'fingerprint':
        labels = ['User', 'mitmproxy', read('fingerprint'), 'OK']
    elif screen == 'recents':
        print('<hierarchy><node resource-id="com.android.documentsui:id/toolbar" text="Recents" bounds="[0,0][1080,100]"><node content-desc="Show roots" bounds="[0,0][100,100]" /></node><node resource-id="com.android.documentsui:id/filename" text="proxy-ca.crt" bounds="[0,300][1000,400]" /></hierarchy>')
        sys.exit(0)
    elif screen == 'roots':
        print('<hierarchy><node resource-id="com.android.documentsui:id/roots_list" bounds="[0,0][1080,1000]"><node resource-id="com.android.documentsui:id/root" text="Downloads" bounds="[0,200][1000,300]" /></node></hierarchy>')
        sys.exit(0)
    elif screen == 'downloads':
        print('<hierarchy><node resource-id="com.android.documentsui:id/toolbar" text="Downloads" bounds="[0,0][1080,100]" /><node resource-id="com.android.documentsui:id/filename" text="proxy-ca.crt" bounds="[0,300][1000,400]" /></hierarchy>')
        sys.exit(0)
    else:
        labels = {
            'security': ['More security settings'],
            'more': ['Encryption & credentials'],
            'credentials': ['Install a certificate'],
            'install': ['CA certificate'],
            'warning': ['Install anyway'],
            'downloads': ['proxy-ca.crt'],
        }.get(screen, [])
    print('<hierarchy>' + ''.join('<node text="%s" bounds="[0,%d][1000,%d]" />' %
                                 (label, 100 + i * 150, 180 + i * 150) for i, label in enumerate(labels)) + '</hierarchy>')
elif cmd.startswith('shell input tap'):
    y = int(a[-1])
    if screen == 'security':
        set_screen('more')
    elif screen == 'more':
        set_screen('credentials')
    elif screen == 'credentials':
        set_screen('install')
    elif screen == 'install':
        set_screen('warning')
    elif screen == 'warning':
        set_screen('recents')
    elif screen == 'recents':
        set_screen('roots')
    elif screen == 'roots':
        set_screen('downloads')
    elif screen == 'downloads':
        if read('stall') == 'select':
            time.sleep(30)
        open(os.path.join(root, 'installed'), 'w').write('yes')
        set_screen('trusted')
    elif screen == 'trusted' and y > 200:
        set_screen('fingerprint')
    elif screen == 'fingerprint':
        set_screen('trusted')
elif cmd == 'shell input keyevent KEYCODE_HOME':
    pass
elif cmd.startswith('emu avd name'):
    print('Test_Play\nOK')
sys.exit(0)
