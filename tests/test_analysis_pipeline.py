import unittest
from pathlib import Path
import sys

# Add APP_DIR to path
APP_DIR = Path(__file__).resolve().parents[1] / "flask_phishing_app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

# Add workspace root to path
WORKSPACE_DIR = Path(__file__).resolve().parents[1]
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

from services.analysis import PhishingAnalyzer

class TestAnalysisPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize analyzer using local workspace path
        cls.analyzer = PhishingAnalyzer(
            BASE_DIR=WORKSPACE_DIR / "flask_phishing_app",
            model_dir=WORKSPACE_DIR
        )

    def test_analyzer_init(self):
        self.assertTrue(self.analyzer.model_ready)
        self.assertIsNotNone(self.analyzer.tier1_model)
        self.assertIsNotNone(self.analyzer.tier1_preprocessor)
        self.assertIsNotNone(self.analyzer.tier2_model)
        self.assertIsNotNone(self.analyzer.tier2_preprocessor)
        self.assertIsNotNone(self.analyzer.network_analyzer)
        self.assertIsNotNone(self.analyzer.security_analyzer)

    def test_lexical_feature_extraction(self):
        url = "https://www.google.com/search?q=phishing"
        features = self.analyzer._extract_tier1_features(url)
        
        # Verify 12 features are present
        expected_features = [
            "length_url", "length_hostname", "nb_dots", "nb_hyphens", "nb_www",
            "ratio_digits_url", "length_words_raw", "longest_words_raw",
            "longest_word_path", "phish_hints", "nb_slash", "shortest_word_host"
        ]
        for f in expected_features:
            self.assertIn(f, features)
            self.assertIsInstance(features[f], float)

    def test_analyze_url_legitimate(self):
        # Test a standard legitimate URL
        url = "https://www.wikipedia.org"
        result = self.analyzer.analyze_url(url)
        
        self.assertIn("verdict", result)
        self.assertIn("hybrid_score", result)
        self.assertIn("prediction", result)
        self.assertIn("tier1_score", result)
        self.assertIn("tier2_score", result)
        self.assertIn("network_score", result)
        self.assertIn("security_score", result)
        
        # Check verdict is Low Risk or Medium Risk
        self.assertIn(result["verdict"], ["Low Risk", "Medium Risk"])
        self.assertEqual(result["prediction"], "legitimate")

    def test_analyze_url_fast(self):
        url = "https://www.wikipedia.org"
        result = self.analyzer.analyze_url_fast(url)
        
        self.assertIn("verdict", result)
        self.assertIn("hybrid_score", result)
        self.assertIn("prediction", result)
        self.assertIn("tier1_score", result)
        self.assertIn("tier2_score", result)
        
        self.assertEqual(result["enrichment"]["status"], "pending")

if __name__ == "__main__":
    unittest.main()
