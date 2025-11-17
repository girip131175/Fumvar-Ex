import os
import requests
import time
import ssdeep
import hashlib
from typing import Tuple, Set, Optional, Dict
import json

SCORE_SCALE = 10
NORMALIZER = {"SSDEEP": 0.1, "SIGNATURE": 1, "HYBRID_SCORE": 1}
WEIGHT = {"SSDEEP": 1, "SIGNATURE": 1, "HYBRID_SCORE": 1}

# API configuration - USE ENVIRONMENT VARIABLE FOR SECURITY
HYBRID_API_URL = "https://hybrid-analysis.com/api/v2"
HYBRID_API_KEY = os.getenv("HYBRID_API_KEY", "jauiuk6f37828a1c6t7vvvke0b192bc14k33s7jx07262424k04273330f814d16")  # Placeholder for security

REQUEST_HEADERS = {
    "api-key": HYBRID_API_KEY,
    "User-Agent": "Falcon Sandbox",
    "accept": "application/json"
}

class Analysis:
    def __init__(self, malware_path: str, original_malware=None):
        if not isinstance(malware_path, str) or not malware_path:
            raise ValueError("Malware path must be a non-empty string")
        self.malware_path = malware_path
        if not os.path.exists(self.malware_path):
            raise FileNotFoundError(f"Malware file not found: {self.malware_path}")
        
        with open(self.malware_path, "rb") as f:
            self.exe_bytes = f.read()
        
        self.original_malware = original_malware
        self.analysis_id = None
        self.file_hash = None
        self.hybrid_score = 0
        self.ssdeep_difference = 0
        self.signature_score = 0
        self._calculate_file_hash()

    def _calculate_file_hash(self):
        """Calculate SHA256 hash of the file"""
        sha256_hash = hashlib.sha256()
        sha256_hash.update(self.exe_bytes)
        self.file_hash = sha256_hash.hexdigest()

    def evaluate_fitness_original_malware(self) -> Tuple[bool, Set[str], float]:
        """Evaluate fitness for original malware"""
        is_functional, hybrid_score = self.get_hybrid_score()
        signatures = self.get_hybrid_signature()
        return is_functional, signatures, hybrid_score

    def evaluate_fitness(self) -> Tuple[bool, float]:
        """Evaluate fitness for perturbed malware"""
        if not self.original_malware:
            print("[!] No original malware provided for comparison")
            return False, 0

        score = []
        is_functional, self.hybrid_score = self.get_hybrid_score()
        
        if not is_functional:
            return False, 0

        self.ssdeep_difference = self.calculate_ssdeep_difference()
        perturbed_signatures = self.get_hybrid_signature()
        self.signature_score = self.compare_signatures(
            self.original_malware.signature_list, 
            perturbed_signatures
        )

        score.append(self.ssdeep_difference * NORMALIZER["SSDEEP"] * WEIGHT["SSDEEP"])
        score.append(self.hybrid_score * NORMALIZER["HYBRID_SCORE"] * WEIGHT["HYBRID_SCORE"])
        score.append(self.signature_score * NORMALIZER["SIGNATURE"] * WEIGHT["SIGNATURE"])

        final_score = sum(score) / len(score) if score else 0
        return is_functional, final_score

    def calculate_ssdeep_difference(self) -> float:
        """Calculate SSDEEP difference between original and current malware"""
        if not self.original_malware:
            return 0
        try:
            hash1 = ssdeep.hash(self.exe_bytes)
            hash2 = ssdeep.hash(self.original_malware.malware_bytes)
            return 100 - ssdeep.compare(hash1, hash2)
        except Exception as e:
            print(f"Error calculating SSDEEP difference: {e}")
            return 0

    def compare_signatures(self, original_signature: Set[str], perturbed_signature: Set[str]) -> float:
        """Compare signature sets and return similarity score"""
        if not original_signature and not perturbed_signature:
            return SCORE_SCALE
        
        if not original_signature or not perturbed_signature:
            return 0
        
        intersection = original_signature.intersection(perturbed_signature)
        union = original_signature.union(perturbed_signature)
        similarity = len(intersection) / len(union) if union else 0
        return round(similarity * SCORE_SCALE, 2)

    def _make_api_request(self, url: str, method: str = "GET", data=None, files=None, params=None) -> Tuple[bool, Dict]:
        """Make API request with proper error handling"""
        try:
            if method.upper() == "POST":
                headers = {k: v for k, v in REQUEST_HEADERS.items() if k.lower() != 'content-type'}
                response = requests.post(url, headers=headers, files=files, data=data, timeout=60)
            else:
                response = requests.get(url, headers=REQUEST_HEADERS, params=params, timeout=30)
            
            print(f"[DEBUG] API Request: {method} {url}")
            if params:
                print(f"[DEBUG] Params: {params}")
            print(f"[DEBUG] Status Code: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    return True, response.json()
                except json.JSONDecodeError:
                    print("[!] Invalid JSON response")
                    return False, {}
            elif response.status_code == 401:
                print("[!] Authentication failed - Check your API key")
                return False, {}
            elif response.status_code == 403:
                print("[!] Access forbidden - Check API permissions")
                return False, {}
            elif response.status_code == 404:
                print("[!] Endpoint not found - API endpoint may have changed")
                return False, {}
            elif response.status_code == 429:
                print("[!] Rate limit exceeded - Please wait and retry")
                return False, {}
            else:
                print(f"[!] API Error: {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"[!] Error details: {error_data}")
                except:
                    print(f"[!] Error response: {response.text}")
                return False, {}
                
        except requests.exceptions.Timeout:
            print("[!] Request timeout")
            return False, {}
        except requests.exceptions.ConnectionError:
            print("[!] Connection error")
            return False, {}
        except Exception as e:
            print(f"[!] Unexpected error in API request: {e}")
            return False, {}

    def check_existing_analysis(self) -> bool:
        """Check if analysis already exists for this file hash"""
        print(f"[+] Checking existing analysis for hash: {self.file_hash}")
        
        url = f"{HYBRID_API_URL}/search/hash"
        params = {"hash": self.file_hash}
        
        success, data = self._make_api_request(url, "GET", params=params)
        
        if success and data:
            if isinstance(data, list) and len(data) > 0:
                for result in data:
                    job_id = result.get('job_id')
                    if job_id:
                        self.analysis_id = job_id
                        print(f"[+] Found existing analysis with Job ID: {self.analysis_id}")
                        return True
            elif isinstance(data, dict):
                job_id = data.get('job_id')
                if job_id:
                    self.analysis_id = job_id
                    print(f"[+] Found existing analysis with Job ID: {self.analysis_id}")
                    return True
        
        print("[+] No existing analysis found")
        return False

    def submit_file_to_hybrid(self) -> bool:
        """Submit file to Hybrid Analysis"""
        if self.check_existing_analysis():
            return True
        
        if not os.path.exists(self.malware_path):
            print(f"[!] File not found: {self.malware_path}")
            return False
            
        print(f"[+] Submitting file: {self.malware_path}")
        
        file_size = os.path.getsize(self.malware_path)
        print(f"[+] File size: {file_size} bytes")
        
        if file_size > 100 * 1024 * 1024:
            print("[!] File too large (>100MB)")
            return False
        
        return self._submit_file_for_analysis()

    def _submit_file_for_analysis(self) -> bool:
        """Submit file using multiple environment fallbacks"""
        print("[+] Submitting file for full analysis with environment fallbacks...")

        file_name = os.path.basename(self.malware_path)
        preferred_env_id = 160  # Windows 10 64-bit
        e_ids = [preferred_env_id, 200, 310, 400, 140, 120, 110, 100]
        tried_envs = set()

        for env_id in e_ids:
            if env_id in tried_envs:
                continue
            tried_envs.add(env_id)

            try:
                with open(self.malware_path, "rb") as f:
                    files = {
                        "file": (file_name, f, "application/octet-stream"),
                        "environment_id": (None, str(env_id)),
                    }
                    print(f"[+] POSTing to: {HYBRID_API_URL}/submit/file with env_id={env_id}")
                    response = requests.post(
                        f"{HYBRID_API_URL}/submit/file",
                        headers=REQUEST_HEADERS,
                        files=files,
                        timeout=60
                    )
                if response.status_code <= 299:
                    print(f"[+] Submission succeeded with environment_id={env_id}")
                    break
                else:
                    print(f"[!] Submission failed: HTTP {response.status_code}, trying next environment...")
            except Exception as e:
                print(f"[!] Error during file submission with env_id={env_id}: {e}")

        if not response or response.status_code > 299:
            print("[!] File submission failed in all environments")
            return False

        try:
            result = response.json()
        except Exception as e:
            print(f"[!] Error parsing submission response: {e}")
            return False

        job_id = result.get("job_id")
        if not job_id and "job_ids" in result and result["job_ids"]:
            job_id = result["job_ids"][0]
        if not job_id:
            print(f"[!] No job_id found in response: {result}")
            return False

        self.analysis_id = job_id
        print(f"[+] File submitted successfully - Job ID: {self.analysis_id}")
        return True

    def get_hybrid_report(self, interval: int = 30, max_attempts: int = 40) -> Tuple[bool, Dict]:
        """Get hybrid analysis report with polling"""
        if not self.analysis_id:
            print("[!] No valid analysis ID found.")
            return False, {}

        print(f"[+] Polling for report (Analysis ID: {self.analysis_id})...")
        print(f"[+] This may take several minutes. Checking every {interval} seconds...")
        
        for attempt in range(max_attempts):
            try:
                url = f"{HYBRID_API_URL}/report/{self.analysis_id}/summary"
                success, data = self._make_api_request(url, "GET")
                
                if success and data:
                    state = data.get('state', 'unknown')
                    print(f"    [+] Attempt {attempt + 1}/{max_attempts}: State = {state}")
                    
                    if state == 'SUCCESS':
                        print("[+] Analysis completed successfully")
                        return True, data
                    elif state == 'ERROR':
                        print("[!] Analysis failed")
                        return False, {}
                    elif state in ['IN_PROGRESS', 'IN_QUEUE']:
                        if attempt == 0:
                            print(f"    [+] Analysis is in progress. This typically takes 5-15 minutes.")
                        else:
                            print(f"    [+] Still processing... (elapsed: {attempt * interval // 60}m {attempt * interval % 60}s)")
                    else:
                        print(f"    [+] State: {state}")
                else:
                    print(f"    [!] No response from API (attempt {attempt + 1})")
                
                if attempt < max_attempts - 1:
                    time.sleep(interval)
                
            except Exception as e:
                print(f"    [!] Error on attempt {attempt + 1}: {e}")
                if attempt < max_attempts - 1:
                    time.sleep(interval)
                
        print(f"[!] Max polling attempts reached ({max_attempts * interval // 60} minutes)")
        return False, {}

    def get_hybrid_signature(self) -> Set[str]:
        """Get signatures from hybrid analysis"""
        if not self.analysis_id:
            print("[!] No valid analysis ID. Cannot fetch signatures.")
            return set()
        
        print("[+] Fetching signatures...")
        
        signatures = set()
        url = f"{HYBRID_API_URL}/report/{self.analysis_id}/summary"
        success, data = self._make_api_request(url, "GET")
        
        if success and data:
            signatures.update(self._extract_signatures_from_report(data))
        
        print(f"[+] Found {len(signatures)} signatures")
        return signatures

    def _extract_signatures_from_report(self, data: Dict) -> Set[str]:
        """Extract signatures from report data"""
        signatures = set()
        
        # Extract from signatures field
        if 'signatures' in data and isinstance(data['signatures'], list):
            for sig in data['signatures']:
                if isinstance(sig, dict) and 'name' in sig:
                    signatures.add(sig['name'])
                elif isinstance(sig, str):
                    signatures.add(sig)
        
        # Extract from AV detections
        if 'av_detect' in data:
            if isinstance(data['av_detect'], list):
                for detection in data['av_detect']:
                    if isinstance(detection, dict):
                        if 'scanner' in detection:
                            signatures.add(detection['scanner'])
                        if 'malware_name' in detection:
                            signatures.add(detection['malware_name'])
            elif isinstance(data['av_detect'], int):
                if data['av_detect'] > 0:
                    signatures.add(f"av_detections_{data['av_detect']}")
        
        # Extract from threat indicators
        if 'threat_indicators' in data and isinstance(data['threat_indicators'], list):
            for indicator in data['threat_indicators']:
                if isinstance(indicator, dict) and 'name' in indicator:
                    signatures.add(indicator['name'])
        
        # Extract from analysis results
        if 'analysis' in data and isinstance(data['analysis'], dict) and 'results' in data['analysis']:
            for result in data['analysis']['results']:
                if isinstance(result, dict) and 'name' in result:
                    signatures.add(result['name'])
        
        return signatures

    def get_hybrid_score(self) -> Tuple[bool, float]:
        """Get hybrid analysis score"""
        if not self.submit_file_to_hybrid():
            return False, 0

        is_functional, report = self.get_hybrid_report()
        if not is_functional or not report:
            return False, 0

        score = 0
        if 'threat_score' in report and isinstance(report['threat_score'], (int, float)):
            score = min(report['threat_score'] / 10.0, 10.0)
            print(f"[+] Threat score: {report['threat_score']}/100")
        elif 'verdict' in report and isinstance(report['verdict'], str):
            verdict = report['verdict'].lower()
            score_map = {
                'malicious': 10, 
                'suspicious': 7, 
                'unknown': 5,
                'whitelisted': 0,
                'no specific threat': 0,
                'benign': 0
            }
            score = score_map.get(verdict, 5)
            print(f"[+] Verdict: {verdict}")
        elif 'malware_family' in report and report['malware_family']:
            score = 8
            print(f"[+] Malware family detected: {report['malware_family']}")
        elif 'av_detect' in report:
            if isinstance(report['av_detect'], list):
                detection_count = len(report['av_detect'])
                score = min(detection_count * 0.5, 10)
                print(f"[+] AV detections: {detection_count}")
            elif isinstance(report['av_detect'], int):
                score = min(report['av_detect'] * 0.5, 10)
                print(f"[+] AV detection count: {report['av_detect']}")
        elif 'signatures' in report and isinstance(report['signatures'], list):
            signature_count = len(report['signatures'])
            score = min(signature_count * 0.3, 10)
            print(f"[+] Signatures detected: {signature_count}")
        else:
            print("[!] Could not determine threat score from report")
            if report:
                score = 3
        
        print(f"[+] Final Analysis Score: {score}/10")
        return True, score

def validate_api_key():
    """Validate API key by making a simple request"""
    if HYBRID_API_KEY == "your-api-key-here":
        print("\n[!] ERROR: Please set your Hybrid Analysis API key!")
        print("   1. Get your API key from: https://hybridOUSEnalysis.com/my-account?tab=api-keys")
        print("   2. Set environment variable: export HYBRID_API_KEY='your-actual-api-key'")
        return False
    
    try:
        url = f"{HYBRID_API_URL}/overview/system"
        headers = {"api-key": HYBRID_API_KEY, "User-Agent": "Falcon Sandbox"}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print("[+] API key validated successfully")
            return True
        elif response.status_code == 401:
            print("[!] ERROR: Invalid API key")
            return False
        else:
            print(f"[!] WARNING: API key validation returned status {response.status_code}")
            return True
    except Exception as e:
        print(f"[!] WARNING: Could not validate API key: {e}")
        return True

def main():
    """Main function for testing"""
    print("=== Hybrid Analysis Tool ===")
    print("Current working directory:", os.getcwd())
    
    if not validate_api_key():
        return
    
    try:
        test_file = "malwareSamples/Calculator.exe"
        
        if not os.path.exists(test_file):
            print(f"\n[!] Test file not found: {test_file}")
            print("Please ensure the file exists or modify the path in main()")
            return
        
        print(f"\n[+] Testing with file: {test_file}")
        
        anal = Analysis(test_file)
        print(f"[+] File hash: {anal.file_hash}")
        
        print(f"\n[+] Starting analysis...")
        is_functional, score = anal.get_hybrid_score()
        
        print(f"\n{'='*50}")
        print(f"[+] ANALYSIS RESULTS:")
        print(f"   File: {test_file}")
        print(f"   Hash: {anal.file_hash}")
        print(f"   Is functional: {is_functional}")
        print(f"   Score: {score}/10")
        
        if is_functional:
            signatures = anal.get_hybrid_signature()
            print(f"   Signatures found: {len(signatures)}")
            if signatures:
                print(f"   Sample signatures:")
                for i, sig in enumerate(list(signatures)[:10]):
                    print(f"     {i+1}. {sig}")
        print(f"{'='*50}")
        
    except FileNotFoundError as e:
        print(f"\n[!] File Error: {e}")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()