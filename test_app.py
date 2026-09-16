import os
import tempfile
import unittest
from pathlib import Path

os.environ["APP_DATA_DIR"] = tempfile.mkdtemp(prefix="job-ranker-test-")

import app


class ProductionSafetyTests(unittest.TestCase):
    def setUp(self):
        app.ensure_config()
        app.init_db()

    def test_database_uses_wal_and_integrity_is_ok(self):
        with app.db() as con:
            self.assertEqual(con.execute("pragma journal_mode").fetchone()[0], "wal")
            self.assertEqual(con.execute("pragma integrity_check").fetchone()[0], "ok")

    def test_config_save_is_valid_json(self):
        config = app.load_config()
        config["app"]["title"] = "Production Test"
        app.save_config(config)
        self.assertEqual(app.load_config()["app"]["title"], "Production Test")

    def test_backup_is_verified(self):
        backup = app.create_backup()
        self.assertTrue(backup.exists())
        self.assertGreater(backup.stat().st_size, 0)

    def test_non_us_location_is_blocked(self):
        result = app.location_eligibility("Hamburg, Germany", "Onsite", "", app.load_config())
        self.assertFalse(result["eligible"])
        self.assertIn("non-us", result["reason"].lower())

    def test_general_profile_matches_non_it_role(self):
        config = app.get_default_config()
        config["job_search"]["queries"] = ["project manager"]
        config["ideal_job"]["strong_titles"] = ["project manager"]
        config["ideal_job"]["desired_terms"] = ["stakeholder management", "budgeting", "risk management"]
        config["resume_profile"]["keywords"] = ["project management", "stakeholder", "budget", "risk"]
        job = {
            "title": "Senior Project Manager",
            "company": "Example Company",
            "location": "Remote - United States",
            "work_arrangement": "Remote",
            "salary_range": "$110,000 - $140,000",
            "employment_type": "Full-time",
            "environment_type": "Corporate",
            "description": "Own project delivery, stakeholder management, budgeting, schedules, and risk management."
        }
        result = app.score_job(job, config)
        self.assertGreaterEqual(result["score"], 60)
        self.assertEqual(result["details"]["role_family"]["name"], "Preference-driven")


if __name__ == "__main__":
    unittest.main()
