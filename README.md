# CloudScan

A simple Django project for cloud security scanning.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Copy `.env.example` to `.env` and edit the values.

### Required environment variables

- `DJANGO_SECRET_KEY` - secret key used by Django.
- `AWS_ACCESS_KEY` - AWS access key for scanning (optional).
- `AWS_SECRET_KEY` - AWS secret key for scanning (optional).
- `AWS_DEFAULT_REGION` - default AWS region (optional).
- `GCP_KEY_PATH` - path to the GCP credentials JSON (optional).
- `MONGODB_URI` - MongoDB connection string (optional).

Some API endpoints also look for `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` or `GCP_SERVICE_ACCOUNT_JSON_PATH` if credentials are not provided in requests.

## Running

Apply migrations and start the development server:

```bash
python manage.py migrate
python manage.py runserver
```

## Deployment

Make sure the `DJANGO_SECRET_KEY` environment variable is available in your deployment environment. Use the values in `.env.example` as a reference for other variables that may be required.
