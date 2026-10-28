const Koa = require('koa');

const app = new Koa();
const DESTINATIONS = { docs: 'https://docs.example.com' };

app.use(async (ctx) => {
  if (ctx.path === '/exit') {
    // ruleid: javascript-express-tainted-request
    ctx.redirect(ctx.query.to);
  }
});

app.use(async (ctx) => {
  if (ctx.path === '/exit-mapped') {
    // ok: javascript-express-tainted-request
    ctx.redirect(DESTINATIONS[ctx.query.to] || '/');
  }
});

app.use(async (ctx) => {
  if (ctx.path === '/exit-constant') {
    // ok: javascript-express-tainted-request
    ctx.redirect('/home');
  }
});

app.use(async (item) => {
  // ok: javascript-express-tainted-request
  item.redirect(item.query.to);
});
