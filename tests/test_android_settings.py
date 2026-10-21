"""Settings setup through a fake emulator; no device or live proxy is used."""
import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import harness

sys.path.insert(0, os.path.join(harness.REPO, 'addons'))
import devices
import android_picker


# RIVIS_ANDROID_SETUP_TIMEOUT is a per-step budget. Steps 1-3 each carry ~3 s of fixed settles plus a dozen adb/grep
# process spawns; measured 5-6 s per step at load average ~15 (identical on fix/review-a-099), so a 6 s budget kills
# step 1-3 before the stall at step 4 is reached. 20 s leaves >3x headroom and only the stalled step waits it out.
STEP_BUDGET = '20'


class Api36PickerFixture(unittest.TestCase):
    def test_recents_never_selects_certificate(self):
        base = os.path.join(harness.REPO, 'tests', 'fixtures')
        recents = open(os.path.join(base, 'android_api36_documentsui_recents.xml')).read()
        downloads = open(os.path.join(base, 'android_api36_documentsui_downloads.xml')).read()
        self.assertEqual(android_picker.choose(recents, 'drawer'), '50 50')
        self.assertEqual(android_picker.choose(recents, 'file'), '')
        self.assertEqual(android_picker.choose(downloads, 'file'), '500 350')


class SettingsRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = harness.Suite.get()

    def setUp(self):
        self.home = self.suite.new_home('settings')
        self.emu = os.path.join(self.home, 'fake-emulator')
        os.makedirs(self.emu)
        self.env = self.suite.cli_env(self.home, ADB=os.path.join(harness.REPO, 'tests', 'fakes', 'settings_adb.py'),
                                      FAKE_SETTINGS_DIR=self.emu, RIVIS_MAGISK_DIR=os.path.join(self.home, 'no-magisk'))
        cert = os.path.join(self.env['RIVIS_CONFDIR'], 'mitmproxy-ca-cert.pem')
        fp = subprocess.run(['openssl', 'x509', '-in', cert, '-noout', '-fingerprint', '-sha256'],
                            capture_output=True, text=True, check=True).stdout.split('=', 1)[1].strip()
        open(os.path.join(self.emu, 'fingerprint'), 'w').write(fp)

    def run_cli(self, *args, timeout=80):
        return self.suite.rivis('android', 'on', *args, home=self.home, env=self.env, timeout=timeout)

    def proxy(self):
        try:
            return open(os.path.join(self.emu, 'proxy')).read().strip()
        except OSError:
            return ':0'

    def test_plain_android_on_shows_steps_in_order_and_elapsed_finish(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = result.stdout
        positions = [output.index('step %d/5:' % n) for n in range(1, 6)]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('Settings route finished in ', output)
        self.assertEqual(self.proxy(), '10.0.2.2:' + self.env['RIVIS_PORT'])
        adb_log = open(os.path.join(self.emu, 'log')).read()
        self.assertIn('shell input tap 50 50', adb_log)  # open roots from Recents
        self.assertIn('shell input tap 500 250', adb_log)  # Downloads root
        self.assertIn('shell input tap 500 350', adb_log)  # file only after Downloads
        setup_log = open(os.path.join(self.home, '.rivis', 'logs', 'android-setup.log')).read()
        self.assertIn('step 4/5: opening Downloads', setup_log)
        self.assertRegex(setup_log, r'\d{4}-\d\d-\d\dT\d\d:')

    def test_serial_timeout_is_nonzero_and_proxy_remains_off(self):
        open(os.path.join(self.emu, 'stall'), 'w').write('select')
        self.env['RIVIS_ANDROID_SETUP_TIMEOUT'] = STEP_BUDGET
        result = self.run_cli('-s', 'emulator-5554', timeout=150)
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertIn('step 4/5:', result.stdout)
        self.assertIn('Settings setup timed out', result.stdout)
        self.assertIn('release zip', result.stdout)
        self.assertIn('finish the CA install by hand', result.stdout)
        self.assertEqual(self.proxy(), ':0')
        self.assertNotIn('settings put global http_proxy 10.0.2.2', open(os.path.join(self.emu, 'log')).read())

    def test_timeout_after_bundled_magisk_failure_points_to_failure(self):
        magisk = os.path.join(self.home, 'bundled-magisk')
        os.makedirs(magisk)
        self.env['RIVIS_MAGISK_DIR'] = magisk
        open(os.path.join(self.emu, 'stall'), 'w').write('select')
        self.env['RIVIS_ANDROID_SETUP_TIMEOUT'] = '6'
        result = self.run_cli('-s', 'emulator-5554')
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertIn('emulator binary not found', result.stdout + result.stderr)
        self.assertIn('emulator binary not found', open(os.path.join(self.home, '.rivis', 'logs', 'android-setup.log')).read())
        self.assertIn('Magisk was found at ' + magisk, result.stdout)
        self.assertIn('Fix that failure', result.stdout)
        self.assertNotIn('install Rivis from the release zip', result.stdout)

    def test_panel_job_reports_current_step_and_timeout_error(self):
        open(os.path.join(self.emu, 'stall'), 'w').write('select')
        self.env['RIVIS_ANDROID_SETUP_TIMEOUT'] = STEP_BUDGET
        jobs = devices.Jobs()
        jobs.start(['/bin/bash', harness.RIVIS, 'android', 'on', '-s', 'emulator-5554'],
                   'Android Test_Play', 'android', 'emulator-5554', env=self.env)
        seen = False
        deadline = time.time() + 150
        while time.time() < deadline:
            status = jobs.summary()
            if status['running'] and status['step']:
                seen = True
            if not status['running']:
                break
            time.sleep(0.05)
        self.assertTrue(seen, status)
        self.assertEqual(status['rc'], 124, status)
        self.assertIn('step 4/5:', status['step'])
        self.assertIn('Settings setup timed out', status['error'])
        self.assertIn('release zip', '\n'.join(status['lines']))

    def test_panel_shows_magisk_failure_reason(self):
        magisk = os.path.join(self.home, 'bundled-magisk')
        os.makedirs(magisk)
        self.env['RIVIS_MAGISK_DIR'] = magisk
        open(os.path.join(self.emu, 'stall'), 'w').write('select')
        self.env['RIVIS_ANDROID_SETUP_TIMEOUT'] = '6'
        jobs = devices.Jobs()
        jobs.start(['/bin/bash', harness.RIVIS, 'android', 'on', '-s', 'emulator-5554'],
                   'Android Test_Play', 'android', 'emulator-5554', env=self.env)
        deadline = time.time() + 40
        while time.time() < deadline and jobs.summary()['running']:
            time.sleep(0.05)
        self.assertIn('emulator binary not found', '\n'.join(jobs.summary()['lines']))

    def test_plain_android_on_bounds_the_initial_trust_check(self):
        open(os.path.join(self.emu, 'stall'), 'w').write('trust')
        self.env['RIVIS_ANDROID_SETUP_TIMEOUT'] = '0.2'
        before = time.monotonic()
        result = self.run_cli(timeout=20)
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertLess(time.monotonic() - before, 12)
        self.assertIn('CA trust check timed out', result.stdout)
        self.assertNotIn('step 1/5', result.stdout)
        self.assertEqual(self.proxy(), ':0')

    def test_another_mitmproxy_ca_on_the_emulator_does_not_stall_the_trust_check(self):
        # A07: the user store held one "mitmproxy" CA that was not ours (a reinstall, another workstation). The check
        # opened it, then looked for a 2nd entry with ui_tap, which scrolls 12 times (~60 s on an emulator) when there
        # is none: the 45 s limit hit and Android on stopped with the proxy off.
        open(os.path.join(self.emu, 'other'), 'w').write('yes')
        self.env['RIVIS_ANDROID_SETUP_TIMEOUT'] = STEP_BUDGET
        result = self.run_cli(timeout=200)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('timed out', result.stdout)
        log = open(os.path.join(self.emu, 'log')).read()
        check = log.split('SECURITY_SETTINGS')[0]                   # step 0, before Settings opens for the install
        self.assertNotIn('input swipe', check, 'the trust check searched for a CA entry that is not on screen')
        self.assertIn('step 5/5', result.stdout)
        self.assertEqual(self.proxy(), '10.0.2.2:' + self.env['RIVIS_PORT'])


if __name__ == '__main__':
    unittest.main()
