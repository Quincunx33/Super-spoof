import unittest
from ua_forge import UserAgent, SPECS, make_headers, UAProfile

class TestUAForge(unittest.TestCase):
    def test_all_profiles(self):
        for s in SPECS:
            p = UAProfile(s, make_headers(s))
            self.assertTrue(p.validate().valid, (s, p.validate().as_dict()))
    def test_deterministic(self):
        self.assertEqual(UserAgent(seed=3).random, UserAgent(seed=3).random)
    def test_platform_mismatch(self):
        p = UserAgent().profile(browser="chrome", platform="android")
        h = dict(p.headers)
        h["Sec-CH-UA-Platform"] = '"Windows"'
        self.assertFalse(p.validate(headers=h).valid)
    def test_invalid_combo(self):
        with self.assertRaises(ValueError):
            UserAgent().profile(browser="safari", platform="android")
    def test_header_injection(self):
        with self.assertRaises(ValueError):
            UserAgent(locale="en\r\nX: yes")

if __name__ == "__main__":
    unittest.main()
