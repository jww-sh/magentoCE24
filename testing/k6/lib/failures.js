// Failure details for the run report.
//
// Every failed check prints one `K6FAIL {json}` console line with the full request and
// response (secrets masked). run-task.sh runs k6 with --log-format raw --console-output,
// so those lines land verbatim in console.log and are split out into failures.jsonl,
// which the /k6-reports viewer renders.
//
// Flows run through runIteration(): an exception is recorded (message + stack) instead of
// aborting the VU's iteration silently, and magento_failed_iterations{flow} counts every
// iteration with a failed check or an exception.
import exec from 'k6/execution';
import { Counter } from 'k6/metrics';
import { cfg } from './config.js';

export const failedIterations = new Counter('magento_failed_iterations');

const BODY_LIMIT = 4000;
let logged = 0;
let iterationFailed = false;
let currentFlow = '';

const SECRET_FIELD = /pass(word)?|token|secret|form_key|^p$/i;
const JWT = /eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}/g;

function maskText(text) {
  return String(text || '').replace(JWT, '***jwt***');
}

function maskValue(key, value) {
  if (SECRET_FIELD.test(key)) return '***';
  if (value && typeof value === 'object') return maskObject(value);
  return value;
}

function maskObject(obj) {
  if (Array.isArray(obj)) return obj.map((v) => maskValue('', v));
  const out = {};
  for (const k of Object.keys(obj)) out[k] = maskValue(k, obj[k]);
  return out;
}

function maskCookies(value) {
  return String(value)
    .split(/;\s*/)
    .map((c) => c.split('=')[0])
    .filter(Boolean)
    .map((n) => `${n}=***`)
    .join('; ');
}

function maskHeaders(headers) {
  const out = {};
  for (const name of Object.keys(headers || {})) {
    const raw = headers[name];
    const value = Array.isArray(raw) ? raw.join(', ') : String(raw);
    if (/^authorization$/i.test(name)) out[name] = value.replace(/^(\w+)\s.*$/, '$1 ***');
    else if (/^(cookie|set-cookie)$/i.test(name)) out[name] = maskCookies(value);
    else out[name] = maskText(value);
  }
  return out;
}

function maskBody(body) {
  if (body === undefined || body === null || body === '') return '';
  const text = String(body);
  try {
    return maskObject(JSON.parse(text));
  } catch (e) {
    // form-encoded body: key=value&key=value
    if (/^[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*$/.test(text)) {
      return text
        .split('&')
        .map((pair) => {
          const [k, v] = pair.split('=');
          return SECRET_FIELD.test(decodeURIComponent(k).replace(/^.*\[|\]$/g, '')) ? `${k}=***` : `${k}=${v || ''}`;
        })
        .join('&');
    }
    return maskText(text.slice(0, BODY_LIMIT));
  }
}

function context() {
  return {
    time: new Date().toISOString(),
    scenario: exec.scenario.name,
    flow: currentFlow,
    vu: exec.vu.idInTest,
    iteration: exec.vu.iterationInScenario,
  };
}

function emit(detail) {
  if (logged >= cfg.failureLogLimit) return;
  logged++;
  console.error(`K6FAIL ${JSON.stringify(detail)}`);
}

// A check on `res` failed; `failed` lists the failing check names.
export function recordFailure(res, name, failed) {
  iterationFailed = true;
  const req = (res && res.request) || {};
  const t = (res && res.timings) || {};
  emit(
    Object.assign(context(), {
      type: 'check',
      name,
      failed,
      request: { method: req.method, url: req.url, headers: maskHeaders(req.headers), body: maskBody(req.body) },
      response: {
        status: res ? res.status : 0,
        error: (res && res.error) || '',
        error_code: (res && res.error_code) || 0,
        url: res ? res.url : '',
        headers: maskHeaders(res && res.headers),
        body: maskText(((res && res.body) || '').slice(0, BODY_LIMIT)),
        timings: { duration: t.duration, waiting: t.waiting, blocked: t.blocked, connecting: t.connecting },
      },
    })
  );
}

function recordException(err) {
  iterationFailed = true;
  emit(Object.assign(context(), { type: 'exception', name: currentFlow, message: String((err && err.message) || err), stack: (err && err.stack) || '' }));
}

// Run one flow as an iteration: tracks the flow name for failure records, records
// exceptions, and counts the iteration as failed if anything in it failed.
export function runIteration(flow, fn) {
  currentFlow = flow;
  iterationFailed = false;
  try {
    fn();
  } catch (err) {
    recordException(err);
  } finally {
    if (iterationFailed) failedIterations.add(1, { flow });
    currentFlow = '';
  }
}
