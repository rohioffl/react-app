from pathlib import Path
import os
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
ROOT_URLCONF = 'prow.urls'

load_dotenv(os.path.join(BASE_DIR, '.env'))

# The Django secret key should come from the environment for security.
# See the README for details on configuring ``DJANGO_SECRET_KEY``.
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY")

AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_DEFAULT_REGION = os.getenv('AWS_DEFAULT_REGION')
GCP_KEY_PATH = os.getenv('GCP_KEY_PATH')

DEBUG = True
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "cloudscan",
    # your custom apps here (like 'scans', etc)
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",      # << REQUIRED
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",   # << REQUIRED
    "django.contrib.messages.middleware.MessageMiddleware",      # << REQUIRED
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]



DATABASES = {
    # Django default DB (not used for Mongo)
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / "db.sqlite3",
    }
}

# MongoDB
MONGODB_URI = os.getenv("MONGODB_URI")

STATIC_URL = '/static/'

# Allow cross-origin requests from the React dev server
CORS_ALLOW_ALL_ORIGINS = True
