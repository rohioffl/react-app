import os
import subprocess
import time

OUTPUT_DIR = os.path.abspath("./output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_prowler_aws(access_key, secret_key, region):
    timestamp = int(time.time() * 1000)
    output_filename = f"aws-scan-{timestamp}"
    output_json = os.path.join(OUTPUT_DIR, f"{output_filename}.asff.json")
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = access_key
    env["AWS_SECRET_ACCESS_KEY"] = secret_key
    if region and region != "all" and region != "":
        env["AWS_DEFAULT_REGION"] = region

    prowler_cmd = [
        "prowler", "aws",
        "--output-formats", "html", "json-asff",
        "--output-filename", output_filename,
        "--output-directory", OUTPUT_DIR,
        "--ignore-exit-code-3"
    ]
    if region and region != "all" and region != "":
        prowler_cmd += ["--region", region]

    # You can print the command for debugging
    print("Running:", " ".join(prowler_cmd))

    result = subprocess.run(prowler_cmd, env=env, capture_output=True, text=True)
    print("STDOUT:", result.stdout)
    print("STDERR:", result.stderr)
    if result.returncode != 0:
        raise Exception(f"Prowler failed with exit code {result.returncode}")
    if not os.path.exists(output_json):
        raise Exception("Prowler did not generate JSON output.")
    return output_json

def run_prowler_gcp(gcp_key_file):
    import shutil
    timestamp = int(time.time() * 1000)
    output_filename = f"gcp-scan-{timestamp}"
    output_csv = os.path.join(OUTPUT_DIR, f"{output_filename}.csv")
    env = os.environ.copy()
    env["GOOGLE_APPLICATION_CREDENTIALS"] = gcp_key_file

    prowler_cmd = [
        "prowler", "gcp",
        "--output-formats", "csv", "html",
        "--output-filename", output_filename,
        "--output-directory", OUTPUT_DIR,
        "--ignore-exit-code-3"
    ]

    print("Running:", " ".join(prowler_cmd))

    result = subprocess.run(prowler_cmd, env=env, capture_output=True, text=True)
    print("STDOUT:", result.stdout)
    print("STDERR:", result.stderr)
    if result.returncode != 0:
        raise Exception(f"Prowler GCP failed with exit code {result.returncode}")
    if not os.path.exists(output_csv):
        raise Exception("Prowler did not generate CSV output.")
    return output_csv
