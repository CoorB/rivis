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

    def test_serial_timeout_is_nonzero_and_proxy_remains_off(self):
        self.env['RIVIS_ANDROID_SETUP_TIMEOUT'] = '0.2'
        result = self.run_cli('-s', 'emulator-5554')
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertIn('step 1/5:', result.stdout)
        self.assertIn('Settings setup timed out', result.stdout)
        self.assertIn('release zip', result.stdout)
        self.assertIn('finish the CA install by hand', result.stdout)
        self.assertEqual(self.proxy(), ':0')
        self.assertNotIn('settings put global http_proxy 10.0.2.2', open(os.path.join(self.emu, 'log')).read())

    def test_timeout_after_bundled_magisk_failure_points_to_failure(self):
        magisk = os.path.join(self.home, 'bundled-magisk')
        os.makedirs(magisk)
        self.env['RIVIS_MAGISK_DIR'] = magisk
        self.env['RIVIS_ANDROID_SETUP_TIMEOUT'] = '0.2'
        result = self.run_cli('-s', 'emulator-5554')
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertIn('emulator binary not found', result.stdout + result.stderr)
        self.assertIn('Magisk was found at ' + magisk, result.stdout)
        self.assertIn('Fix that failure', result.stdout)
        self.assertNotIn('install Rivis from the release zip', result.stdout)

    def test_panel_job_reports_current_step_and_timeout_error(self):
        self.env['RIVIS_ANDROID_SETUP_TIMEOUT'] = '0.5'
        jobs = devices.Jobs()
        jobs.start(['/bin/bash', harness.RIVIS, 'android', 'on', '-s', 'emulator-5554'],
                   'Android Test_Play', 'android', 'emulator-5554', env=self.env)
        seen = False
        deadline = time.time() + 20
        while time.time() < deadline:
            status = jobs.summary()
            if status['running'] and status['step']:
                seen = True
            if not status['running']:
                break
            time.sleep(0.05)
        self.assertTrue(seen, status)
        self.assertEqual(status['rc'], 124, status)
        self.assertIn('step 1/5:', status['step'])
        self.assertIn('Settings setup timed out', status['error'])
        self.assertIn('release zip', '\n'.join(status['lines']))


if __name__ == '__main__':
    unittest.main()
