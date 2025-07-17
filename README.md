# CloudScan

CloudScan is a lightweight Django REST API that wraps [Prowler](https://github.com/prowler-cloud/prowler) to perform AWS and GCP security scans. Scan results are saved in MongoDB using MongoEngine.

## Requirements

- Python 3
- MongoDB running locally or accessible via a connection URI
- The `prowler` CLI

## Setup

1. **Install Python dependencies**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Install Prowler**

   Use the official install script to place the `prowler` command on your `PATH`:

   ```bash
   curl -Ls https://raw.githubusercontent.com/prowler-cloud/prowler/v3/prowler/install.sh | bash
   ```

3. **Start MongoDB**

   If you do not already have MongoDB running, you can launch one with Docker:

   ```bash
   docker run -d -p 27017:27017 --name mongo mongo:7
   ```

4. **Configure environment variables**

   Create a `.env` file in the project root or export the variables in your shell:

   ```bash
   MONGODB_URI=mongodb://localhost:27017/prowler
   AWS_ACCESS_KEY_ID=<your aws access key>
   AWS_SECRET_ACCESS_KEY=<your aws secret key>
   AWS_DEFAULT_REGION=us-east-1          # optional
   GCP_SERVICE_ACCOUNT_JSON_PATH=/path/to/gcp-key.json  # optional
   GCP_PROJECT_ID=<your gcp project id>                 # optional
   ```

5. **Run the API**

   ```bash
   python manage.py migrate      # sets up Django's internal database
   python manage.py runserver 0.0.0.0:8000
   ```

## Usage

Two endpoints are provided once the server is running:

- `POST /scan/aws` – trigger an AWS scan
- `POST /scan/gcp` – trigger a GCP scan

Both endpoints accept optional `checks` or `group` parameters which are passed
to Prowler as `-c` or `-g` flags. This lets you run a subset of checks for
faster scans. The GCP endpoint also supports an optional `projectId` parameter
that is forwarded to Prowler as `--project-ids` to scan a specific project. You
can also set the `GCP_PROJECT_ID` environment variable instead of passing it in
the request.

### Example: AWS scan

```bash
curl -X POST http://localhost:8000/scan/aws \
     -H 'Content-Type: application/json' \
     -d '{"accessKey":"AKIA...","secretKey":"abc123","region":"us-west-2","checks":"check1,check2"}'
```

### Example: GCP scan

```bash
curl -X POST http://localhost:8000/scan/gcp \
     -F keyFile=@/path/to/service-account.json \
     -F checks=check1 \
     -F projectId=my-project
# Alternatively set the environment variable:
# export GCP_PROJECT_ID=my-project
```

A successful response returns the scan ID and the number of findings. You can then query MongoDB for the stored scan results.

