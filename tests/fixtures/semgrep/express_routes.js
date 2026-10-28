const express = require('express');
const fs = require('fs');
const path = require('path');
const escapeHtml = require('escape-html');
const mysql = require('mysql');
const axios = require('axios');

const app = express();
const pool = mysql.createPool({ host: 'db' });
const ATTACHMENTS = { invoice: 'invoice.pdf' };
const DESTINATIONS = { projects: '/projects' };

app.get('/products', (req, res) => {
  const sql = "SELECT id FROM products WHERE category = '" + req.query.category + "'";
  // ruleid: javascript-express-sql-injection
  pool.query(sql, (error, rows) => res.json(rows));
});

app.get('/products-bound', (req, res) => {
  // ok: javascript-express-sql-injection
  pool.query('SELECT id FROM products WHERE category = ?', [req.query.category], (error, rows) => res.json(rows));
});

app.get('/products-numeric', (req, res) => {
  const sql = 'SELECT id FROM products WHERE id = ' + parseInt(req.query.id, 10) + ' LIMIT 1';
  // ok: javascript-express-sql-injection
  pool.query(sql, (error, rows) => res.json(rows));
});

app.get('/hello', (req, res) => {
  // ruleid: javascript-express-reflected-xss
  res.send('<h1>Hello, ' + req.query.name + '</h1>');
});

app.get('/hello-template', (req, res) => {
  // ruleid: javascript-express-reflected-xss
  res.send(`<h1>Hello, ${req.query.name}</h1>`);
});

app.get('/hello-escaped', (req, res) => {
  // ok: javascript-express-reflected-xss
  res.send('<h1>Hello, ' + escapeHtml(String(req.query.name)) + '</h1>');
});

app.get('/hello-json', (req, res) => {
  // ok: javascript-express-reflected-xss
  res.send({ name: req.query.name });
});

app.get('/attachments-mapped', (req, res) => {
  const file = ATTACHMENTS[String(req.query.name)];
  if (!file) return res.sendStatus(404);
  // ok: javascript-express-tainted-request
  fs.readFile(path.join(__dirname, file), (error, data) => res.send(data));
});

app.get('/attachments-checked', (req, res) => {
  const target = path.resolve(__dirname, 'attachments', req.query.name);
  if (!target.startsWith(path.join(__dirname, 'attachments') + path.sep)) return res.sendStatus(404);
  // ok: javascript-express-tainted-request
  fs.readFile(target, (error, data) => res.send(data));
});

app.get('/return-mapped', (req, res) => {
  // ok: javascript-express-tainted-request
  res.redirect(DESTINATIONS[String(req.query.to)] || '/');
});

app.get('/return-checked', (req, res) => {
  // ruleid: javascript-express-tainted-request
  res.redirect(req.query.to);
});

function downloadReport(req, res) {
  // ruleid: javascript-express-tainted-request
  res.sendFile(req.params.file);
}

class UserController {
  async show(req, res) {
    // ruleid: javascript-express-tainted-request
    res.redirect(req.query.next);
  }

  static search(req, res) {
    const sql = "SELECT id FROM users WHERE name = '" + req.query.name + "'";
    // ruleid: javascript-express-sql-injection
    pool.query(sql, (error, rows) => res.json(rows));
  }
}

const profileController = {
  greet(req, res) {
    // ruleid: javascript-express-reflected-xss
    res.send('<p>' + req.query.name + '</p>');
  },
};

function mergeDefaults(target, source) {
  // ok: javascript-express-tainted-request
  fs.readFile(target.query, () => source);
}

app.get('/greeting-variable', (req, res) => {
  const html = `<h1>Hello, ${req.query.name}</h1>`;
  // ruleid: javascript-express-reflected-xss
  res.send(html);
});

app.get('/greeting-built', (req, res) => {
  let html = '<ul>';
  html += '<li>' + req.query.item + '</li>';
  // ruleid: javascript-express-reflected-xss
  res.send(html);
});

app.get('/greeting-escaped-variable', (req, res) => {
  const html = `<h1>Hello, ${escapeHtml(String(req.query.name))}</h1>`;
  // ok: javascript-express-reflected-xss
  res.send(html);
});

app.get('/user-record', async (req, res) => {
  const user = await pool.query('SELECT name FROM users WHERE id = ?', [req.params.id]);
  // ok: javascript-express-reflected-xss
  res.send(user);
});

app.get('/greeting-unescaped', (req, res) => {
  // ruleid: javascript-express-reflected-xss
  res.send('<h1>' + unescape(req.query.name) + '</h1>');
});

app.get('/link-uri-encoded', (req, res) => {
  // ruleid: javascript-express-reflected-xss
  res.send("<a href='" + encodeURI(req.query.url) + "'>next</a>");
});

app.get('/proxy-host', async (req, res) => {
  // ruleid: javascript-express-tainted-request
  res.json(await axios.get('https://' + encodeURIComponent(req.query.host) + '/status'));
});

app.get('/proxy-user', async (req, res) => {
  // ok: javascript-express-tainted-request
  res.json(await axios.get(`https://api.example.com/users/${encodeURIComponent(req.query.id)}`));
});

app.get('/search-redirect', (req, res) => {
  // ok: javascript-express-tainted-request
  res.redirect('/search?q=' + encodeURIComponent(req.query.q));
});
