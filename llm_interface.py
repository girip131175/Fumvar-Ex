import subprocess
import json
import os
import hashlib
import re
import pprint

def sha256sum(filename):
    h = hashlib.sha256()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

def extract_with_7z(zip_path, output_dir, password="infected"):
    try:
        result = subprocess.run(
            ["7z", "x", f"-p{password}", zip_path, f"-o{output_dir}", "-y"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        print("[+] Extracted using 7z")
        return True
    except subprocess.CalledProcessError as e:
        print("[!] 7z extraction failed:\n", e.stderr)
        return False

def get_best_malware_sample(original_sample_path):
    sample_hash = sha256sum(original_sample_path)

    # 1. Call Gemini CLI and capture only stdout
    print("[+] Calling Gemini CLI")
    try:
        result = subprocess.run(
            [
                "gemini",
                "-y",
                "--prompt", f"{sample_hash}"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )

        gemini_result = result.stdout
        match = re.search(r"```json\s*(.*?)\s*```", gemini_result, re.DOTALL)
        if match:
            json_text = match.group(1)
            try:
                parsed_result = json.loads(json_text)
                print("[+] Reasoning obtained from LLM")
                pprint.pprint(parsed_result)
            except json.JSONDecodeError:
                print("[!] Could not parse JSON output from Gemini. Debug output given below\n", json_text)
                return original_sample_path
        else:
            print("[-] No JSON block found from LLM. Proceeding with original sample Debug output given below\n", gemini_result)
            return original_sample_path

    except subprocess.CalledProcessError as e:
        print(f"[!] Gemini CLI execution failed: {e}")
        return original_sample_path
    except Exception as e:
        print(f"[!] Unexpected error while running Gemini: {e}")
        return original_sample_path

    # 3. Parse decision and extract if needed
    try:
        decision = parsed_result["decision"]
        if decision == "use_new_file" and parsed_result["selected_sample"]:
            zip_path = parsed_result["selected_sample"]["download_path"]
            if not zip_path.endswith(".zip"):
                zip_path += ".zip"
            sample_hash = parsed_result["selected_sample"]["hash"]
            sample_dir = os.path.dirname(zip_path)
            extracted_sample_path = os.path.join(sample_dir, sample_hash + ".exe")

            if not extract_with_7z(zip_path, sample_dir, password="infected"):
                return original_sample_path

            if os.path.exists(extracted_sample_path):
                print(f"[+] Returning new sample: {extracted_sample_path}")
                return extracted_sample_path
            else:
                print("[!] Extracted file not found. Falling back to original.")
                return original_sample_path
        else:
            return original_sample_path

    except Exception as e:
        print(f"[!] Error parsing Gemini decision output: {e}")
        return original_sample_path

if __name__ == "__main__":
    print(get_best_malware_sample(os.path.abspath("malwareSamples/7599bbd665cdc3870234747f917e1ce6c194ebe8764a7c585efabccb2d2b208c.exe")))
