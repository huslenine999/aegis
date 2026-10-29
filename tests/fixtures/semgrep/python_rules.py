import hashlib
import os
import pickle
import subprocess


def query(cursor, request):
    name = request.query_params
    # ruleid: python-sqli
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ok: python-sqli
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))


def run(host, blob, data):
    # ruleid: python-rce
    subprocess.run(f"ping -c 1 {host}", shell=True)
    # ok: python-rce
    subprocess.run(["ping", "-c", "1", host])
    # ruleid: python-rce
    os.system("ls " + host)
    # ok: python-rce
    os.system("pybabel compile -d app/translations")
    # ok: python-rce
    subprocess.run("git rev-parse HEAD", shell=True, check=True)
    # ruleid: python-eval
    eval(host)
    # ruleid: python-pickle
    pickle.loads(blob)
    # ruleid: python-weak-hash
    hashlib.md5(data)
    # ok: python-weak-hash
    hashlib.sha256(data)
