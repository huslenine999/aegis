// Destructured imports only: no child_process namespace object is in scope.
const { exec, execSync, execFile } = require('child_process');

function archive(name, done) {
  // ruleid: javascript-command-injection
  exec('tar czf backup.tgz ' + name, done);
  // ruleid: javascript-command-injection
  execSync(`du -sh ${name}`);
  // ok: javascript-command-injection
  exec('uptime', done);
  // ok: javascript-command-injection
  execFile('tar', ['czf', 'backup.tgz', name], done);
}

module.exports = { archive };
