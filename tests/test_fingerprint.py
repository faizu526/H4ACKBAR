"""Fingerprinter unit tests."""

from h4ackbar.fingerprint import (
    Fingerprint,
    fingerprint_response,
)


def test_mysql_error_detected():
    body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    fp = fingerprint_response({}, {}, body)
    assert "mysql" in fp.dbms


def test_postgres_error_detected():
    body = "PostgreSQL ERROR: syntax error at or near \"'\""
    fp = fingerprint_response({}, {}, body)
    assert "postgresql" in fp.dbms


def test_mssql_error_detected():
    body = "Microsoft SQL Server Native Client error"
    fp = fingerprint_response({}, {}, body)
    assert "mssql" in fp.dbms


def test_oracle_ora_number_detected():
    body = "java.sql.SQLException: ORA-00933: SQL command not properly ended"
    fp = fingerprint_response({}, {}, body)
    assert "oracle" in fp.dbms


def test_sqlite_error_detected():
    body = 'near "\'": syntax error'
    fp = fingerprint_response({}, {}, body)
    assert "sqlite" in fp.dbms


def test_wordpress_html_detected():
    body = '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
    fp = fingerprint_response({}, {}, body)
    assert "wordpress" in fp.frameworks


def test_php_cookie_detected():
    fp = fingerprint_response({}, {"PHPSESSID": "abcd"}, "")
    assert "php" in fp.frameworks


def test_django_cookie_detected():
    fp = fingerprint_response({}, {"csrftoken": "x"}, "")
    assert "django/python" in fp.frameworks


def test_nginx_header_detected():
    fp = fingerprint_response({"Server": "nginx/1.24"}, {}, "")
    assert "nginx" in fp.frameworks
    assert fp.server == "nginx/1.24"


def test_empty_input_returns_empty_fp():
    fp = fingerprint_response({}, {}, "")
    assert fp.frameworks == []
    assert fp.dbms == []


def test_summary_format():
    fp = Fingerprint(frameworks=["php"], dbms=["mysql"], server="nginx")
    s = fp.summary()
    assert "php" in s and "mysql" in s and "nginx" in s
