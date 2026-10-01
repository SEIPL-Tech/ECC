#!/usr/bin/env node
/**
 * Run the Supply-Chain Watch alert script against a mock gh.
 *
 * The alert job runs only on schedule and on manual dispatch on main, never on
 * pull requests, so this is the only place its behaviour is exercised before a
 * real weekly failure. Run with SCW_MOCK_GH=1, this file is the mock gh itself.
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const WORKFLOW_PATH = path.join(
  __dirname,
  '..',
  '..',
  '.github',
  'workflows',
  'supply-chain-watch.yml',
);

const REPO = 'SEIPL-Tech/ECC';
const OWNER = 'SEIPL-Tech';
const BOT = 'github-actions[bot]';
const LABEL = 'supply-chain-watch';
const TITLE = 'Supply-Chain Watch is failing';
const RUN_BASE = `https://github.com/${REPO}/actions/runs`;
const ADV = 'Check production advisories';
const SIG = 'Verify registry signatures';
const INSTALL = 'Install dependencies without lifecycle scripts';
const WATCH_STEPS = [
  'Set up job',
  'Checkout',
  'Setup Node.js',
  INSTALL,
  SIG,
  ADV,
  'Validate IOC scanner fixtures',
  'Generate IOC report',
  'Validate workflow hardening rules',
  'Fingerprint findings',
  'Drill failure',
  'Upload IOC report',
  'Record watch result',
  'Complete job',
];

// ---------------------------------------------------------------------------
// Mock gh: state lives in $MOCK_DIR/state.json, behaviour switches in
// $MOCK_DIR/config.json, and every call is appended to $MOCK_DIR/calls.log.
// ---------------------------------------------------------------------------

function mockGh() {
  const dir = process.env.MOCK_DIR;
  const file = name => path.join(dir, name);
  const load = (name, fallback) => (fs.existsSync(file(name))
    ? JSON.parse(fs.readFileSync(file(name), 'utf8'))
    : fallback);
  const save = (name, value) => fs.writeFileSync(file(name), JSON.stringify(value, null, 2));
  const argv = process.argv.slice(2);
  fs.appendFileSync(file('calls.log'), `${JSON.stringify(argv)}\n`);

  const config = load('config.json', {});
  const state = load('state.json', {});

  function die(message) {
    process.stderr.write(`${message}\n`);
    process.exit(1);
  }

  // Like real gh: an HTTP error prints the JSON error body to stdout.
  function httpError(status, message) {
    process.stdout.write(`${JSON.stringify({ message })}\n`);
    die(`gh: ${message} (HTTP ${status})`);
  }

  function maybeFlaky(key) {
    const counters = load('counters.json', {});
    const count = counters[key] || 0;
    if (count < ((config.flaky || {})[key] || 0)) {
      counters[key] = count + 1;
      save('counters.json', counters);
      httpError(502, 'Server Error');
    }
  }

  function maybeFailWrite(key) {
    if ((config.failWrites || []).includes(key)) {
      httpError(500, 'Server Error');
    }
  }

  function emit(value, jq) {
    const text = JSON.stringify(value);
    if (!jq) {
      process.stdout.write(`${text}\n`);
      return;
    }
    const result = spawnSync('jq', ['-r', jq], { input: text, encoding: 'utf8' });
    if (result.status !== 0) {
      die(result.stderr);
    }
    process.stdout.write(result.stdout);
  }

  function findIssue(number) {
    const issue = state.issues.find(candidate => candidate.number === Number(number));
    if (!issue) {
      httpError(404, 'Not Found');
    }
    return issue;
  }

  function option(args, name) {
    const index = args.indexOf(name);
    return index >= 0 ? args[index + 1] : undefined;
  }

  function addComment(issue, body) {
    if (issue.locked) {
      die('GraphQL: Unable to create comment because issue is locked. (addComment)');
    }
    issue.comments.push({ author: BOT, body });
  }

  const [command, ...args] = argv;

  if (command === 'api') {
    let method;
    let jq;
    let target;
    const fields = {};
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg === '-X') {
        method = args[++i];
      } else if (arg === '--jq') {
        jq = args[++i];
      } else if (arg === '-f') {
        const raw = args[++i];
        const key = raw.slice(0, raw.indexOf('='));
        const value = raw.slice(raw.indexOf('=') + 1);
        if (key.endsWith('[]')) {
          fields[key.slice(0, -2)] = (fields[key.slice(0, -2)] || []).concat(value);
        } else {
          fields[key] = value;
        }
      } else if (arg === '--silent') {
        // No body to print.
      } else if (!target) {
        target = arg;
      } else {
        die(`mock gh: unexpected api argument ${arg}`);
      }
    }
    method = method || (Object.keys(fields).length > 0 ? 'POST' : 'GET');
    const lock = target.match(new RegExp(`^repos/${REPO}/issues/(\\d+)/lock$`));

    if (method === 'GET' && new RegExp(`^repos/${REPO}/actions/runs/\\d+/jobs$`).test(target)) {
      maybeFlaky('jobs');
      emit({ total_count: state.jobs.length, jobs: state.jobs }, jq);
    } else if (method === 'GET' && target === `repos/${REPO}`) {
      maybeFlaky('repo');
      emit({ full_name: REPO, has_issues: state.hasIssues }, jq);
    } else if (method === 'GET' && target.startsWith(`repos/${REPO}/issues?`)) {
      maybeFlaky('list');
      const query = new URLSearchParams(target.slice(target.indexOf('?') + 1));
      const label = query.get('labels');
      const open = state.issues
        .filter(issue => issue.state === 'open' && issue.labels.some(item => item.name === label))
        .sort((a, b) => b.number - a.number);
      emit(open, jq);
    } else if (method === 'POST' && target === `repos/${REPO}/issues`) {
      maybeFailWrite('create');
      const issue = {
        number: 100 + state.issues.length,
        state: 'open',
        title: fields.title,
        body: fields.body,
        labels: (fields.labels || []).map(name => ({ name })),
        assignees: config.assignDrops ? [] : (fields.assignees || []).map(login => ({ login })),
        user: { login: BOT },
        locked: false,
        comments: [],
      };
      state.issues.push(issue);
      save('state.json', state);
      emit(issue, jq);
    } else if (lock && (method === 'PUT' || method === 'DELETE')) {
      maybeFailWrite('lock');
      findIssue(lock[1]).locked = method === 'PUT';
      save('state.json', state);
    } else {
      die(`mock gh: unhandled api ${method} ${target}`);
    }
    return;
  }

  if (command === 'label' && args[0] === 'create') {
    maybeFailWrite('label');
    const name = args[1];
    if (state.labels.includes(name) && !args.includes('--force')) {
      die(`label with name "${name}" already exists; use \`--force\` to update its color and description`);
    }
    if (!state.labels.includes(name)) {
      state.labels.push(name);
    }
    save('state.json', state);
    return;
  }

  if (command === 'issue') {
    const [sub, number, ...rest] = args;
    maybeFailWrite(sub);
    const issue = findIssue(number);
    if (sub === 'edit') {
      issue.body = option(rest, '--body');
    } else if (sub === 'comment') {
      addComment(issue, option(rest, '--body'));
    } else if (sub === 'close') {
      if (option(rest, '--comment') !== undefined) {
        addComment(issue, option(rest, '--comment'));
      }
      issue.state = 'closed';
      issue.stateReason = option(rest, '--reason');
    } else {
      die(`mock gh: unhandled issue ${sub}`);
    }
    save('state.json', state);
    return;
  }

  die(`mock gh: unhandled ${argv.join(' ')}`);
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    return true;
  } catch (error) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${error.message}`);
    return false;
  }
}

function commandWorks(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  return !result.error && result.status === 0;
}

// The alert step's `run: |` block, read without a YAML parser.
function extractAlertScript(source) {
  const lines = source.split(/\r?\n/);
  const stepIndex = lines.findIndex(line => line.trim() === '- name: Open, update or close the tracking issue');
  assert.ok(stepIndex >= 0, 'missing alert step');
  const runIndex = lines.findIndex((line, index) => index > stepIndex && /^\s+run: \|\s*$/.test(line));
  assert.ok(runIndex > stepIndex, 'missing alert run block');
  const indent = lines[runIndex].search(/\S/) + 2;
  const body = [];
  for (const line of lines.slice(runIndex + 1)) {
    if (line.trim() === '') {
      body.push('');
      continue;
    }
    if (line.search(/\S/) < indent) {
      break;
    }
    body.push(line.slice(indent));
  }
  return `${body.join('\n').trimEnd()}\n`;
}

function watchJobs(conclusion, stepConclusions = {}) {
  const steps = WATCH_STEPS.map((name, index) => ({
    name,
    number: index + 1,
    status: 'completed',
    conclusion: stepConclusions[name] || (name === 'Drill failure' ? 'skipped' : 'success'),
  }));
  return [
    { name: 'IOC watch', status: 'completed', conclusion, steps },
    { name: 'Failure alert', status: 'in_progress', conclusion: null, steps: [] },
  ];
}

function failingJobs(...names) {
  return watchJobs('failure', Object.fromEntries(names.map(name => [name, 'failure'])));
}

function markerBody({ firstRun, latestRun, checks, findings }) {
  return [
    'The weekly Supply-Chain Watch found a problem.',
    '',
    `<!-- supply-chain-watch first-failing-run: ${firstRun} -->`,
    `<!-- supply-chain-watch latest-failing-run-id: ${latestRun} -->`,
    `<!-- supply-chain-watch seen-checks: ${checks} -->`,
    `<!-- supply-chain-watch seen-findings: ${findings} -->`,
  ].join('\n');
}

function trackingIssue(number, options = {}) {
  const {
    checks = ADV,
    findings = '',
    firstRun = `${RUN_BASE}/1`,
    latestRun = 1,
    assigned = true,
    locked = true,
    author = BOT,
    body,
  } = options;
  return {
    number,
    state: 'open',
    title: TITLE,
    body: body === undefined ? markerBody({ firstRun, latestRun, checks, findings }) : body,
    labels: [{ name: LABEL }],
    assignees: assigned ? [{ login: OWNER }] : [],
    user: { login: author },
    locked,
    comments: [],
  };
}

function marker(body, name) {
  const match = body.match(new RegExp(`^<!-- supply-chain-watch ${name}: (.*) -->$`, 'm'));
  return match ? match[1] : undefined;
}

function isWrite(call) {
  if (call[0] === 'label' || call[0] === 'issue') {
    return true;
  }
  return call[0] === 'api' && (call.includes('-X') || call.includes('-f'));
}

function createWorld(scriptPath, { hasIssues = true, issues = [], labels = [], config = {} } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scw-alert-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'gh'),
    `#!/bin/sh\nSCW_MOCK_GH=1 exec "${process.execPath}" "${__filename}" "$@"\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'sleep'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({ hasIssues, issues, labels, jobs: [] }));
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(config));
  return { dir, bin, scriptPath };
}

function runWeek(world, { jobs, scanStatus, findings = '', runId = 999 }) {
  const statePath = path.join(world.dir, 'state.json');
  const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  state.jobs = jobs.map((job, index) => ({ html_url: `${RUN_BASE}/${runId}/job/${5000 + index}`, ...job }));
  fs.writeFileSync(statePath, JSON.stringify(state));
  fs.rmSync(path.join(world.dir, 'calls.log'), { force: true });
  fs.rmSync(path.join(world.dir, 'counters.json'), { force: true });

  const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', world.scriptPath], {
    encoding: 'utf8',
    timeout: 60000,
    env: {
      PATH: `${world.bin}${path.delimiter}${process.env.PATH}`,
      HOME: world.dir,
      LC_ALL: 'C',
      MOCK_DIR: world.dir,
      GH_TOKEN: 'mock-token',
      GH_REPO: REPO,
      GITHUB_REPOSITORY_OWNER: OWNER,
      GITHUB_RUN_ID: String(runId),
      RUN_URL: `${RUN_BASE}/${runId}`,
      LABEL,
      TITLE,
      SCAN_STATUS: scanStatus,
      FINDINGS: findings,
    },
  });
  const callsPath = path.join(world.dir, 'calls.log');
  const calls = fs.existsSync(callsPath)
    ? fs.readFileSync(callsPath, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line))
    : [];
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    output: `${result.stdout}\n${result.stderr}`,
    state: JSON.parse(fs.readFileSync(statePath, 'utf8')),
    calls,
    writes: calls.filter(isWrite),
  };
}

function scenario(scriptPath, world, week) {
  return runWeek(createWorld(scriptPath, world), week);
}

function expectStatus(result, expected) {
  assert.strictEqual(result.status, expected, `exit ${result.status}, want ${expected}\n${result.output}`);
}

function run() {
  console.log('\n=== Testing supply-chain watch alert script ===\n');

  if (process.platform !== 'linux' || !commandWorks('bash', ['--version']) || !commandWorks('jq', ['--version'])) {
    console.log('    (skipped — not supported on this platform)');
    console.log('\nPassed: 0');
    console.log('Failed: 0');
    process.exit(0);
  }

  const scriptDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scw-script-'));
  const scriptPath = path.join(scriptDir, 'alert.sh');
  fs.writeFileSync(scriptPath, extractAlertScript(fs.readFileSync(WORKFLOW_PATH, 'utf8')));
  const go = (world, week) => scenario(scriptPath, world, week);
  let passed = 0;
  let failed = 0;
  const check = (name, fn) => {
    if (test(name, fn)) passed++; else failed++;
  };

  console.log('Issues turned off:');

  check('a passing week makes no API writes', () => {
    const result = go({ hasIssues: false }, { jobs: watchJobs('success'), scanStatus: 'success' });
    expectStatus(result, 0);
    assert.deepStrictEqual(result.writes, []);
  });

  check('a failing week fails the run and names the check, so the usual email still arrives', () => {
    const result = go({ hasIssues: false }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 1);
    assert.match(result.stdout, /::error::Supply-Chain Watch failed \(Check production advisories\)\. Issues are turned off/);
    assert.deepStrictEqual(result.writes, []);
  });

  console.log('\nIssues on, no tracking issue open:');

  check('a passing week makes no API writes', () => {
    const result = go({}, { jobs: watchJobs('success'), scanStatus: 'success' });
    expectStatus(result, 0);
    assert.deepStrictEqual(result.writes, []);
  });

  check('a failing week opens one assigned, labelled, locked issue', () => {
    const result = go({}, { jobs: failingJobs(ADV), scanStatus: 'failure', findings: 'aaaaaaaaaaaa' });
    expectStatus(result, 0);
    assert.strictEqual(result.state.issues.length, 1);
    const [issue] = result.state.issues;
    assert.strictEqual(issue.title, TITLE);
    assert.deepStrictEqual(issue.assignees, [{ login: OWNER }]);
    assert.deepStrictEqual(issue.labels, [{ name: LABEL }]);
    assert.strictEqual(issue.locked, true);
    assert.deepStrictEqual(issue.comments, []);
    assert.match(issue.body, /^- Failing checks: Check production advisories$/m, 'skipped drill step must not be listed');
    assert.match(issue.body, new RegExp(`^- Latest failing run: ${RUN_BASE}/999/job/5000 \\(`, 'm'), 'link the red job, not the green run');
    assert.strictEqual(marker(issue.body, 'first-failing-run'), `${RUN_BASE}/999`);
    assert.strictEqual(marker(issue.body, 'latest-failing-run-id'), '999');
    assert.strictEqual(marker(issue.body, 'seen-checks'), ADV);
    assert.strictEqual(marker(issue.body, 'seen-findings'), 'aaaaaaaaaaaa');
    assert.ok(!issue.body.includes('@'), 'the weekly body must never mention anyone');
    assert.deepStrictEqual(result.state.labels, [LABEL]);
    assert.match(result.stdout, /Opened tracking issue #100\./);
  });

  check('a label left from an earlier episode is reused', () => {
    const result = go({ labels: [LABEL] }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 0);
    assert.strictEqual(result.state.issues.length, 1);
  });

  check('a drill opens an issue naming the drill step', () => {
    const result = go({}, { jobs: watchJobs('failure', { 'Drill failure': 'failure' }), scanStatus: 'failure' });
    expectStatus(result, 0);
    assert.match(result.state.issues[0].body, /^- Failing checks: Drill failure$/m);
  });

  check('an issue that could not be assigned fails loudly', () => {
    const result = go({ config: { assignDrops: true } }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 1);
    assert.match(result.stdout, /could not assign it to SEIPL-Tech/);
  });

  check('an issue opened by someone else, or a pull request, is left alone', () => {
    const human = trackingIssue(7, { author: 'someone', body: 'Owner notes.' });
    const pull = { ...trackingIssue(8), pull_request: { url: 'x' } };
    const result = go({ issues: [human, pull] }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 0);
    assert.strictEqual(result.state.issues.length, 3);
    assert.strictEqual(result.state.issues[0].body, 'Owner notes.');
    assert.ok(!result.writes.some(call => call[0] === 'issue' && ['7', '8'].includes(call[2])));
  });

  console.log('\nIssues on, tracking issue already open:');

  check('the same failure updates the issue quietly', () => {
    const result = go({ issues: [trackingIssue(7)] }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 0);
    const [issue] = result.state.issues;
    assert.deepStrictEqual(issue.comments, []);
    assert.strictEqual(marker(issue.body, 'first-failing-run'), `${RUN_BASE}/1`);
    assert.strictEqual(marker(issue.body, 'latest-failing-run-id'), '999');
    assert.strictEqual(issue.locked, true);
    assert.ok(!result.calls.some(call => call.includes('-X')), 'no lock churn on a quiet week');
    assert.match(result.stdout, /Updated issue #7 quietly\./);
  });

  check('a newly failing check posts one comment that mentions the owner', () => {
    const result = go({ issues: [trackingIssue(7)] }, { jobs: failingJobs(SIG, ADV), scanStatus: 'failure' });
    expectStatus(result, 0);
    const [issue] = result.state.issues;
    assert.strictEqual(issue.comments.length, 1);
    assert.strictEqual(issue.comments[0].body,
      `@${OWNER} another check has started failing: ${SIG}. Latest run: ${RUN_BASE}/999/job/5000`);
    assert.strictEqual(marker(issue.body, 'seen-checks'), `${ADV}; ${SIG}`);
    assert.strictEqual(issue.locked, true, 'the issue is locked again after the comment');
    const order = result.writes.map(call => (call[0] === 'api' ? call[2] : call[1]));
    assert.deepStrictEqual(order, ['edit', 'DELETE', 'comment', 'PUT']);
  });

  check('fewer failing checks stay quiet', () => {
    const result = go({ issues: [trackingIssue(7, { checks: `${SIG}; ${ADV}` })] },
      { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 0);
    assert.deepStrictEqual(result.state.issues[0].comments, []);
  });

  check('a new finding inside an already-failing check posts one comment', () => {
    const result = go({ issues: [trackingIssue(7, { findings: 'aaaaaaaaaaaa' })] },
      { jobs: failingJobs(ADV), scanStatus: 'failure', findings: 'bbbbbbbbbbbb aaaaaaaaaaaa' });
    expectStatus(result, 0);
    const [issue] = result.state.issues;
    assert.strictEqual(issue.comments.length, 1);
    assert.strictEqual(issue.comments[0].body,
      `@${OWNER} 1 new finding(s) in: ${ADV}. Latest run: ${RUN_BASE}/999/job/5000`);
    assert.strictEqual(marker(issue.body, 'seen-findings'), 'aaaaaaaaaaaa bbbbbbbbbbbb');
  });

  check('the same findings again stay quiet', () => {
    const result = go({ issues: [trackingIssue(7, { findings: 'aaaaaaaaaaaa bbbbbbbbbbbb' })] },
      { jobs: failingJobs(ADV), scanStatus: 'failure', findings: 'bbbbbbbbbbbb' });
    expectStatus(result, 0);
    assert.deepStrictEqual(result.state.issues[0].comments, []);
    assert.strictEqual(marker(result.state.issues[0].body, 'seen-findings'), 'aaaaaaaaaaaa bbbbbbbbbbbb');
  });

  check('malformed finding ids are ignored', () => {
    const result = go({ issues: [trackingIssue(7)] },
      { jobs: failingJobs(ADV), scanStatus: 'failure', findings: '@someone $(touch x) aaaaaaaaaaaa1 ZZZZZZZZZZZZ' });
    expectStatus(result, 0);
    assert.deepStrictEqual(result.state.issues[0].comments, []);
    assert.strictEqual(marker(result.state.issues[0].body, 'seen-findings'), '');
    assert.ok(!result.state.issues[0].body.includes('@'));
  });

  check('a passing week closes the issue with a comment and leaves it locked', () => {
    const result = go({ issues: [trackingIssue(7)] }, { jobs: watchJobs('success'), scanStatus: 'success' });
    expectStatus(result, 0);
    const [issue] = result.state.issues;
    assert.strictEqual(issue.state, 'closed');
    assert.strictEqual(issue.stateReason, 'completed');
    assert.strictEqual(issue.comments[0].body,
      `The Supply-Chain Watch passed again in ${RUN_BASE}/999, so this issue is closed.`);
    assert.strictEqual(issue.locked, true);
  });

  check('an open issue nobody is assigned to fails loudly after the update', () => {
    const result = go({ issues: [trackingIssue(7, { assigned: false })] }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 1);
    assert.match(result.stdout, /has no assignee/);
    assert.strictEqual(marker(result.state.issues[0].body, 'latest-failing-run-id'), '999');
  });

  check('an unlocked open issue is locked again on a quiet week', () => {
    const result = go({ issues: [trackingIssue(7, { locked: false })] }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 0);
    assert.strictEqual(result.state.issues[0].locked, true);
    assert.deepStrictEqual(result.state.issues[0].comments, []);
  });

  console.log('\nSeveral weeks in a row:');

  check('two failing weeks give one issue, one create call and no comments', () => {
    const world = createWorld(scriptPath);
    const first = runWeek(world, { jobs: failingJobs(ADV), scanStatus: 'failure', runId: 1001 });
    const second = runWeek(world, { jobs: failingJobs(ADV), scanStatus: 'failure', runId: 1002 });
    expectStatus(first, 0);
    expectStatus(second, 0);
    assert.strictEqual(second.state.issues.length, 1);
    const creates = [...first.writes, ...second.writes].filter(call => call.includes('-f') && call[1] === `repos/${REPO}/issues`);
    assert.strictEqual(creates.length, 1);
    assert.deepStrictEqual(second.state.issues[0].comments, []);
    assert.strictEqual(marker(second.state.issues[0].body, 'first-failing-run'), `${RUN_BASE}/1001`);
    assert.strictEqual(marker(second.state.issues[0].body, 'latest-failing-run-id'), '1002');
  });

  check('a check that returns after a week that hid it is not announced again', () => {
    const world = createWorld(scriptPath);
    runWeek(world, { jobs: failingJobs(ADV), scanStatus: 'failure', runId: 1001 });
    const hidden = runWeek(world, { jobs: failingJobs(INSTALL), scanStatus: 'failure', runId: 1002 });
    const cancelled = runWeek(world, { jobs: watchJobs('cancelled'), scanStatus: '', runId: 1003 });
    const back = runWeek(world, { jobs: failingJobs(ADV), scanStatus: 'failure', runId: 1004 });
    [hidden, cancelled, back].forEach(result => expectStatus(result, 0));
    const comments = back.state.issues[0].comments;
    assert.strictEqual(comments.length, 1, 'only the install failure is new');
    assert.match(comments[0].body, /started failing: Install dependencies without lifecycle scripts\./);
  });

  check('a full episode: open, quiet, escalate, close, then a fresh issue next time', () => {
    const world = createWorld(scriptPath);
    runWeek(world, { jobs: failingJobs(ADV), scanStatus: 'failure', runId: 1001 });
    runWeek(world, { jobs: failingJobs(ADV), scanStatus: 'failure', runId: 1002 });
    runWeek(world, { jobs: failingJobs(SIG, ADV), scanStatus: 'failure', runId: 1003 });
    const closed = runWeek(world, { jobs: watchJobs('success'), scanStatus: 'success', runId: 1004 });
    const reopened = runWeek(world, { jobs: failingJobs(ADV), scanStatus: 'failure', runId: 1005 });
    expectStatus(closed, 0);
    expectStatus(reopened, 0);
    const [first, second] = reopened.state.issues;
    assert.strictEqual(first.state, 'closed');
    assert.strictEqual(first.comments.length, 2);
    assert.strictEqual(second.state, 'open');
    assert.strictEqual(marker(second.body, 'first-failing-run'), `${RUN_BASE}/1005`);
  });

  console.log('\nRe-runs and edited issues:');

  check('a re-run of an older passing run does not close a newer failure', () => {
    const result = go({ issues: [trackingIssue(7, { latestRun: 1005 })] },
      { jobs: watchJobs('success'), scanStatus: 'success', runId: 1003 });
    expectStatus(result, 0);
    assert.strictEqual(result.state.issues[0].state, 'open');
    assert.deepStrictEqual(result.writes, []);
    assert.match(result.stdout, /::notice::Run 1003 is older than failing run 1005/);
  });

  check('a re-run of an older failing run does not rewrite the issue', () => {
    const result = go({ issues: [trackingIssue(7, { latestRun: 1005 })] },
      { jobs: failingJobs(SIG), scanStatus: 'failure', runId: 1003 });
    expectStatus(result, 0);
    assert.deepStrictEqual(result.writes, []);
  });

  check('a body saved with CRLF line ends keeps its markers', () => {
    const body = markerBody({ firstRun: `${RUN_BASE}/1`, latestRun: 1, checks: ADV, findings: '' }).replace(/\n/g, '\r\n')
      + '\r\nOwner note added in the web editor.';
    const result = go({ issues: [trackingIssue(7, { body })] }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 0);
    assert.deepStrictEqual(result.state.issues[0].comments, []);
    assert.strictEqual(marker(result.state.issues[0].body, 'first-failing-run'), `${RUN_BASE}/1`);
  });

  check('edited markers cannot inject text or mentions into the bot body', () => {
    const body = markerBody({
      firstRun: '@SEIPL-Tech known false positive, run https://evil.example/fix.sh',
      latestRun: 1,
      checks: `@someone; ${ADV}`,
      findings: 'aaaaaaaaaaaa @x',
    });
    const result = go({ issues: [trackingIssue(7, { body })] }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 0);
    const updated = result.state.issues[0].body;
    assert.strictEqual(marker(updated, 'first-failing-run'), `${RUN_BASE}/999`);
    assert.ok(!updated.includes('evil.example'));
    assert.ok(!updated.includes('@'));
  });

  check('a job link that is not part of this run falls back to the run link', () => {
    const jobs = failingJobs(ADV).map(job => ({ ...job, html_url: 'https://evil.example/job/1' }));
    const result = go({}, { jobs, scanStatus: 'failure' });
    expectStatus(result, 0);
    assert.match(result.state.issues[0].body, new RegExp(`^- Latest failing run: ${RUN_BASE}/999 \\(`, 'm'));
    assert.ok(!result.state.issues[0].body.includes('evil.example'));
  });

  check('a first-run link to another repository is replaced', () => {
    const body = markerBody({ firstRun: 'https://github.com/other/repo/actions/runs/5', latestRun: 1, checks: ADV, findings: '' });
    const result = go({ issues: [trackingIssue(7, { body })] }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 0);
    assert.strictEqual(marker(result.state.issues[0].body, 'first-failing-run'), `${RUN_BASE}/999`);
  });

  console.log('\nVerdict is fail-closed:');

  check('a recorded success is not trusted when GitHub says the job failed', () => {
    const result = go({}, { jobs: failingJobs(ADV), scanStatus: 'success' });
    expectStatus(result, 0);
    assert.strictEqual(result.state.issues.length, 1);
  });

  check('a missing recorded result opens an issue', () => {
    const result = go({}, { jobs: watchJobs('success'), scanStatus: '' });
    expectStatus(result, 0);
    assert.match(result.state.issues[0].body, /Failing checks: not reported \(job result: success\)/);
  });

  check('a cancelled or timed-out watch opens an issue', () => {
    const result = go({}, { jobs: watchJobs('cancelled'), scanStatus: 'cancelled' });
    expectStatus(result, 0);
    assert.match(result.state.issues[0].body, /Failing checks: not reported \(job result: cancelled\)/);
  });

  check('a watch job the API does not list opens an issue', () => {
    const jobs = watchJobs('success').map(job => ({ ...job, name: job.name === 'IOC watch' ? 'Renamed' : job.name }));
    const result = go({}, { jobs, scanStatus: 'success' });
    expectStatus(result, 0);
    assert.match(result.state.issues[0].body, /job result: unknown/);
  });

  console.log('\nAPI errors:');

  check('transient read errors are retried without corrupting the result', () => {
    const result = go({ issues: [trackingIssue(7)], config: { flaky: { jobs: 2, repo: 1, list: 1 } } },
      { jobs: watchJobs('success'), scanStatus: 'success' });
    expectStatus(result, 0);
    assert.match(result.stdout, /job conclusion: success;/);
    assert.strictEqual(result.state.issues.length, 1, 'no false alarm issue');
    assert.strictEqual(result.state.issues[0].state, 'closed');
  });

  check('transient read errors on a failing week keep the check names intact', () => {
    const result = go({ issues: [trackingIssue(7)], config: { flaky: { jobs: 1 } } },
      { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 0);
    assert.deepStrictEqual(result.state.issues[0].comments, []);
    assert.strictEqual(marker(result.state.issues[0].body, 'seen-checks'), ADV);
  });

  check('a read error that persists fails loudly without writing', () => {
    const result = go({ config: { flaky: { jobs: 5 } } }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 1);
    assert.deepStrictEqual(result.writes, []);
  });

  for (const [write, world, jobs] of [
    ['create', {}, failingJobs(ADV)],
    ['edit', { issues: [trackingIssue(7)] }, failingJobs(ADV)],
    ['comment', { issues: [trackingIssue(7)] }, failingJobs(SIG, ADV)],
    ['close', { issues: [trackingIssue(7)] }, watchJobs('success')],
  ]) {
    check(`a failed ${write} fails loudly`, () => {
      const result = go({ ...world, config: { failWrites: [write] } },
        { jobs, scanStatus: write === 'close' ? 'success' : 'failure' });
      expectStatus(result, 1);
    });
  }

  check('a failed lock only warns; the issue is still opened and assigned', () => {
    const result = go({ config: { failWrites: ['lock'] } }, { jobs: failingJobs(ADV), scanStatus: 'failure' });
    expectStatus(result, 0);
    assert.match(result.stdout, /::warning::Could not lock issue #100/);
    assert.deepStrictEqual(result.state.issues[0].assignees, [{ login: OWNER }]);
  });

  console.log(`\nPassed: ${passed}`);
  console.log(`Failed: ${failed}`);

  process.exit(failed > 0 ? 1 : 0);
}

if (process.env.SCW_MOCK_GH === '1') {
  mockGh();
} else {
  run();
}
