# oidcOPprobe

[![Python: 2.7](https://img.shields.io/badge/Python-2.7-4584b6.svg?style=popout&logo=python)](https://www.python.org/)
[![Python: 3.6](https://img.shields.io/badge/Python-3.6-4584b6.svg?style=popout&logo=python)](https://www.python.org/)

[![License: MIT](https://img.shields.io/badge/License-MIT-a31f34.svg?style=popout)](https://raw.githubusercontent.com/snakaya/WebAuthn-PyRP/master/LICENSE)

Probe RP for communications with OP in OpenID Connect/OAuth2.

てすと
てすと

## Feature

![Front Page](https://raw.githubusercontent.com/snakaya/oidcOPprobe/images/frontpage1.png)

## Requirement

- Python2.7 + Django ==1.11 or Python3.6 + Django >=2.2
- MySQL, PostgreSQL, Oracle or SQLite

## Installation

1.We recommend you use virtualenv. Install virtualenv.

```bash
$ sudo pip install virtualenv
$ sudo pip install virtualenvwrapper
```

2.Create virtualenv's environment, and swich to environmant.

```bash
$ export WORKON_HOME=/var/www/virtualenvs
$ mkvirtualenv --python=python3 oopp-py3
$ workon oopp-py3
(oopp-py3) $
```

3.Download source from GitHub to your app's directory.

```bash
(oopp-py3) $ cd /var/www/oOPp
(oopp-py3) $ git clone https://github.com/snakaya/oidcOPprobe.git .
```

4.Install required python modules.

```bash
(oopp-py3) $ pip install -r requirements-py3.txt
```

5.Please setup settings.py. Set SECRET_KEY and modify DATABASES.

6.Setup Database.

```bash
(oopp-py3) $ cd /var/www/oOPp/
(oopp-py3) $ python manage.py makemigrations
(oopp-py3) $ python manage.py migrate
```

7.Start development server.

```bash
(oopp-py3) $ python ./manage.py runserver 0.0.0.0:5000
```

## Environment Variables

TODO

## Configuration

TODO

## Limitations

TODO

## TODO

-[ ] Implement Introspection API.

-[ ] Containerization.

-[ ] Make setup.py.

## License
[MIT](https://raw.githubusercontent.com/snakaya/WebAuthn-PyRP/master/LICENSE)

## Author

Seiji Nakaya / LOOSEDAYS (snakaya-(^^)-loosedays.jp)