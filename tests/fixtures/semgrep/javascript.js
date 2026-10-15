const childProcess = require('child_process');
const { exec } = require('child_process');
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const serialize = require('node-serialize');

const app = express();

function evaluate(userCode, handler) {
  // ruleid: javascript-eval
  eval(userCode);
  // ruleid: javascript-eval
  const fn = new Function('a', userCode);
  // ruleid: javascript-eval
  setTimeout('handle(' + userCode + ')', 10);
  // ok: javascript-eval
  eval("1 + 1");
  // ok: javascript-eval
  setTimeout(() => handler(), 10);
  // ok: javascript-eval
  setTimeout(handler, 10);
  return fn;
}

function run(host) {
  // ruleid: javascript-command-injection
  childProcess.exec(`ping -c 1 ${host}`);
  // ruleid: javascript-command-injection
  childProcess.spawn(host, [], { shell: true });
  // ok: javascript-command-injection
  childProcess.exec("git status");
  // ok: javascript-command-injection
  childProcess.execFile("ping", ["-c", "1", host]);
  // ruleid: javascript-command-injection
  exec("ls " + host);
  // ok: javascript-command-injection
  exec("ls -la");
}

async function findUser(db, pool, id) {
  // ruleid: javascript-sql-injection
  await db.query(`SELECT * FROM users WHERE id = ${id}`);
  // ruleid: javascript-sql-injection
  await pool.query("SELECT * FROM users WHERE id = " + id);
  // ok: javascript-sql-injection
  await db.query("SELECT * FROM users WHERE id = $1", [id]);
  // ok: javascript-sql-injection
  await cache.query(`${id}`);
}

function render(element, comment, safe) {
  // ruleid: javascript-xss-html-sink
  element.innerHTML = comment;
  // ruleid: javascript-xss-html-sink
  document.write(comment);
  // ok: javascript-xss-html-sink
  element.innerHTML = "<p>Loading</p>";
  // ok: javascript-xss-html-sink
  element.innerHTML = DOMPurify.sanitize(comment);
  // ok: javascript-xss-html-sink
  element.innerHTML = escapeHtml(comment);
  // ok: javascript-xss-html-sink
  element.textContent = comment;
  // ruleid: javascript-xss-html-sink
  element.innerHTML = `<p>${comment}</p>`;
  // ok: javascript-xss-html-sink
  element.innerHTML = `<p>${escapeHtml(comment)}</p>`;
  // ok: javascript-xss-html-sink
  element.innerHTML = `<p>static</p>`;
}

app.get('/file', (req, res) => {
  const name = req.query.name;
  // ruleid: javascript-express-tainted-request
  res.sendFile(name);
  // ruleid: javascript-express-tainted-request
  fs.readFileSync(path.join('/srv/files', req.params.file));
  // ok: javascript-express-tainted-request
  fs.readFileSync(path.join('/srv/files', path.basename(req.params.file)));
  // ruleid: javascript-express-tainted-request
  res.redirect(req.query.next);
  // ok: javascript-express-tainted-request
  res.redirect('/home');
});

app.post('/fetch', async (req, res) => {
  // ruleid: javascript-express-tainted-request
  const response = await fetch(req.body.url);
  res.json(await response.json());
});

// ruleid: javascript-tls-verification-disabled
const agentOptions = { rejectUnauthorized: false };
// ruleid: javascript-tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

function session(payload, token, cookie) {
  // ruleid: javascript-jwt-hardcoded-secret
  jwt.sign(payload, "super-secret-value");
  // ok: javascript-jwt-hardcoded-secret
  jwt.verify(token, process.env.JWT_SECRET);
  // ruleid: javascript-unsafe-deserialization
  serialize.unserialize(cookie);
  // ruleid: javascript-weak-hash
  crypto.createHash('md5').update(payload);
  // ok: javascript-weak-hash
  crypto.createHash('sha256').update(payload);
  return agentOptions;
}

module.exports = { evaluate, run, findUser, render, session };
