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

    Create a `.env` file in the project root (see `.env.example` for a template) or export the variables in your shell:

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

### Running the React frontend

1. Install dependencies and start the Vite dev server:

   ```bash
   cd frontend
   npm install
   cp .env.example .env  # sets VITE_API_BASE_URL
   npm run dev
   ```

The API enables CORS so requests from the dev server (typically
`http://localhost:5173`) can reach Django.

## Usage

Two endpoints are provided once the server is running:

- `POST /scan/aws` – trigger an AWS scan
- `POST /scan/gcp` – trigger a GCP scan

Both endpoints accept an optional `checks` parameter which is passed to Prowler
with `-c` to run only the specified checks. The `group` flag (`-g`) is only
supported for GCP scans&mdash;Prowler v3+ does not allow groups when scanning
AWS. The GCP endpoint also supports an optional `projectId` parameter that is
forwarded to Prowler as `--project-ids` to scan a specific project. You can also
set the `GCP_PROJECT_ID` environment variable instead of passing it in the
request.

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

### Async GCP workflow

For the React frontend, scans are started asynchronously:

1. Upload a service account key to `/api/prowler/gcp/projects`.
   The response includes a `keyId` and the list of accessible `projects`.
2. Start the scan via `POST /api/prowler/scan/async/gcp/` with `keyId` and
   the chosen `projectId`.
3. Poll `/api/prowler/scan/status/<scan_id>/` until `progress` reaches 100 and
   a `result` object is returned.

The React example in `frontend/src/example/GcpAsyncScan.jsx` demonstrates this
flow.

A successful response returns the scan ID and the number of findings. You can then query MongoDB for the stored scan results.

### Persistent async workflow

The endpoints above store progress in memory. The project also includes
`cloudscan/async_views.py` which demonstrates how to persist scan jobs in
MongoDB so progress survives restarts:

1. Upload a key via `POST /api/prowler/async/projects`.
2. Start a scan with `POST /api/prowler/scan/async/gcp/db/` using the returned
   `keyId` and `projectId`.
3. Poll `/api/prowler/scan/status/db/<scan_id>/` until `progress` reaches 100.
4. Query history from `/api/prowler/scanlist/db/`.

Each scan job is stored in the `scan_jobs` collection with its status, progress
and result.

## Testing

Ensure the dependencies from `requirements.txt` are installed before running the tests:

```bash
pip install -r requirements.txt
```

Run the Django test suite with:

```bash
python manage.py test
```

You may also configure `pytest` together with `pytest-django` if you prefer using `pytest` as the test runner.

