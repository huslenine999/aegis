import sqlite3
import subprocess

from flask import request


def lookup(connection: sqlite3.Connection):
    owner = request.args.get("owner", "")
    statement = "SELECT id FROM reports WHERE owner = '%s'" % owner
    # ruleid: python-sqli
    connection.execute(statement)
    # ok: python-sqli
    connection.execute("SELECT id FROM reports WHERE owner = ?", (owner,))


def django_lookup(cursor, req):
    # ruleid: python-sqli
    cursor.execute("DELETE FROM reports WHERE id = " + req.GET["id"])


def archive(path):
    # ruleid: python-rce
    subprocess.run("tar czf out.tgz " + path, shell=True, check=True)
    # ruleid: python-rce
    subprocess.check_output(f"du -sh {path}", shell=True, text=True)
    # ok: python-rce
    subprocess.run(["tar", "czf", "out.tgz", path], check=True)
