import os
import sqlite3

import requests
from fastapi import Depends, FastAPI
from fastapi.responses import RedirectResponse
from flask import Flask, make_response, redirect, request, url_for
from starlette.requests import Request
from helpers import build_url, current_user
from markupsafe import escape
from sqlalchemy import text

app = Flask(__name__)
api = FastAPI()
EXPORT_DIR = "/srv/exports"
FEEDS = {"status": "https://status.example.com/feed.json"}
DESTINATIONS = {"projects": "/projects"}


@api.get("/exports")
def read_export(name: str):
    # ruleid: python-tainted-request
    with open(os.path.join(EXPORT_DIR, name)) as handle:
        return handle.read()


@api.get("/exports-checked")
def read_export_checked(name: str):
    candidate = os.path.realpath(os.path.join(EXPORT_DIR, name))
    if not candidate.startswith(EXPORT_DIR + os.sep):
        raise ValueError(name)
    # ok: python-tainted-request
    with open(candidate) as handle:
        return handle.read()


@app.get("/exports-base")
def read_export_base():
    # ok: python-tainted-request
    with open(os.path.join(EXPORT_DIR, os.path.basename(request.args["name"]))) as handle:
        return handle.read()


@app.get("/preview")
def preview():
    target = request.args.get("url", "")
    # ruleid: python-tainted-request
    return requests.get(target, timeout=5).text


@app.get("/preview-session")
def preview_session():
    session = requests.Session()
    # ruleid: python-tainted-request
    return session.get(request.args["url"], timeout=5).text


@app.get("/preview-feed")
def preview_feed():
    feed = FEEDS.get(request.args.get("feed", ""))
    # ok: python-tainted-request
    return requests.get(feed, timeout=5).text


@app.get("/after-login")
def after_login():
    # ruleid: python-tainted-request
    return redirect(request.args.get("next", "/"))


@app.get("/after-login-mapped")
def after_login_mapped():
    # ok: python-tainted-request
    return redirect(DESTINATIONS.get(request.args.get("next", ""), "/"))


@app.get("/after-login-named")
def after_login_named():
    # ok: python-tainted-request
    return redirect(url_for("index", next=request.args.get("next")))


@api.get("/connect")
def connect(request: Request, principal=Depends(current_user)):
    # ok: python-tainted-request
    return RedirectResponse(build_url(principal.user_id, request.cookies.get("session")))


@app.get("/hello")
def hello():
    name = request.args.get("name", "friend")
    # ruleid: python-reflected-xss
    return "<h1>Hello, " + name + "</h1>"


@app.get("/hello-format")
def hello_format():
    # ruleid: python-reflected-xss
    return make_response("<h1>Hello, {}</h1>".format(request.args["name"]))


@app.get("/hello-escaped")
def hello_escaped():
    name = request.args.get("name", "friend")
    # ok: python-reflected-xss
    return "<h1>Hello, " + escape(name) + "</h1>"


@app.get("/hello-json")
def hello_json():
    # ok: python-reflected-xss
    return {"name": request.args.get("name")}


def orders_for(customer):
    connection = sqlite3.connect("orders.db")
    query = "SELECT id FROM orders WHERE customer = '{}'".format(customer)
    # ruleid: python-sql-string-from-parameter
    return connection.execute(query).fetchall()


def orders_percent(customer):
    # ruleid: python-sql-string-from-parameter
    return sqlite3.connect("orders.db").execute("SELECT id FROM orders WHERE customer = '%s'" % customer)


def orders_text(session, customer):
    # ruleid: python-sql-string-from-parameter
    return session.execute(text(f"SELECT id FROM orders WHERE customer = '{customer}'"))


def orders_params(customer):
    connection = sqlite3.connect("orders.db")
    # ok: python-sql-string-from-parameter
    return connection.execute("SELECT id FROM orders WHERE customer = ?", (customer,)).fetchall()


def orders_constant():
    # ok: python-sql-string-from-parameter
    return sqlite3.connect("orders.db").execute("SELECT {}".format("1"))
