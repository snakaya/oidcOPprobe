"""
Django settings for RibProbe project.

Generated by 'django-admin startproject' using Django 1.11.14.

For more information on this file, see
https://docs.djangoproject.com/en/1.11/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.11/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.11/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'p=m@cj!&4+n$u)kui%c*#%b*q0tg&r0*dab-6h&brz1+uoyvwb'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ["*"]


# Application definition

INSTALLED_APPS = [
    #'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_nose',
    'rp',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'oOPp.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [ os.path.join(BASE_DIR, './rp/templates'),
            ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
            'debug': True,
        },
    },
]

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        "simple": {"format": "%(levelname)s:%(name)s:%(message)s"},
        "custom": {"format": "[%(asctime)s]:[%(levelname)s]:[%(funcName)s]:%(message)s"}
    },
    'handlers': {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "custom"
        }
    },
    'loggers': {
        "oOPp" : {
            "level": "DEBUG",
            "handlers": ["console"]
        },
    }
}

WSGI_APPLICATION = 'oOPp.wsgi.application'

# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases
RDB_NAME = os.getenv('OOPP_DB_DB_NAME', '')
RDB_USER = os.getenv('OOPP_DB_USERID', '')
RDB_PASS = os.getenv('OOPP_DB_PASSWORD', '')
RDB_SERVER = os.getenv('OOPP_DB_HOST', '')
DATABASES = {
	'default': {
		'ENGINE': 'django.db.backends.mysql', # MySQL-Python
		#'ENGINE': 'mysql.connector.django', # MySQL Connector/Python
		'NAME': RDB_NAME,
		'USER': RDB_USER,
		'PASSWORD': RDB_PASS,
		'HOST': RDB_SERVER,
		'PORT': '',
	}
}


# Password validation
# https://docs.djangoproject.com/en/1.11/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/1.11/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_URL = '/static/'
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, './static/'),
)
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    #'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

# django-nose, coverage configure
TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'
NOSE_ARGS = [
    '--verbosity=2',  # verbose output
    '--with-xunit',  # enable XUnit plugin
    '--xunit-file=oopp_testresult/xunittest.xml',  # the XUnit report file
    '--with-coverage',
    #'--cover-html',
    '--cover-package=rp',
]

#
# App Settings
#

OP_INIT_DATA = [
    {
        'opId': 'pseudoOP',
        'displayName': 'pseudoOP Name',
        'issuer': 'http://pseudoOP.loosedays.jp/pseudoOP',
        'loginLogo': 'logo-tests.png',
    },
]

OIDC_REDIRECT_URL = 'http://dpseudoOP.loosedays.jp/OIDC/redirect/'
OIDC_TOKENSTORE_COOKIENAME = 'TESTRP_TokenStore_'


