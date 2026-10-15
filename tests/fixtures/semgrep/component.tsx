import * as cp from 'child_process';
import DOMPurify from 'dompurify';

export function Comment({ html }: { html: string }) {
  // ruleid: javascript-react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function SafeComment({ html }: { html: string }) {
  // ok: javascript-react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

export function archive(name: string): void {
  // ruleid: javascript-command-injection
  cp.execSync('tar czf out.tgz ' + name);
}
