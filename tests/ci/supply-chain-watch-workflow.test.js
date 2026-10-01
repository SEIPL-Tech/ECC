#!/usr/bin/env node
/**
 * Validate the scheduled supply-chain watch workflow contract.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const WORKFLOW_PATH = path.join(
  __dirname,
  '..',
  '..',
  '.github',
  'workflows',
  'supply-chain-watch.yml',
);

// The exact alert-job condition: scheduled runs, or manual runs on main.
// Anything broader would let other events use the issues: write token.
const ALERT_IF = "    if: ${{ !cancelled() && (github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main')) }}";

// The only continue-on-error allowed: scheduled runs and drills hand their
// failures to the tracking issue instead of failing the run.
const WATCH_CONTINUE_ON_ERROR = "    continue-on-error: ${{ github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.drill) }}";

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

// Text of one top-level job, from its two-space key to the next job key.
// Returns '' when the job is missing so each test reports it on its own.
function jobSection(source, jobId) {
  const start = source.search(new RegExp(`^ {2}${jobId}:\\s*$`, 'm'));
  if (start < 0) {
    return '';
  }
  const rest = source.slice(start + 1);
  const next = rest.search(/^ {2}[A-Za-z0-9_-]+:\s*$/m);
  return next >= 0 ? source.slice(start, start + 1 + next) : source.slice(start);
}

function stepsOf(section) {
  return section.split(/\r?\n {6}- name: /).slice(1);
}

function lines(text) {
  return text.split(/\r?\n/);
}

function run() {
  console.log('\n=== Testing supply-chain watch workflow ===\n');

  const source = fs.readFileSync(WORKFLOW_PATH, 'utf8');
  const jobsIndex = source.search(/^jobs:\s*$/m);
  const header = jobsIndex >= 0 ? source.slice(0, jobsIndex) : source;
  const watch = jobSection(source, 'ioc-watch');
  const alert = jobSection(source, 'alert');
  let passed = 0;
  let failed = 0;

  if (test('runs weekly, on manual dispatch, and on pull requests that touch the watch', () => {
    assert.match(header, /schedule:\r?\n(?:\s+#[^\n]*\r?\n)*\s+- cron: '17 18 \* \* 0'/);
    assert.doesNotMatch(source, /cron: '[^']*\*\/6/, 'the six-hourly cadence must not return');
    assert.match(header, /workflow_dispatch:\r?\n\s+inputs:\r?\n\s+drill:/);
    assert.match(header, /drill:[\s\S]*?type: boolean\r?\n\s+default: false/);
    assert.match(header, /pull_request:\r?\n\s+paths:/);
    assert.match(header, /- '\.github\/workflows\/supply-chain-watch\.yml'/);
    assert.match(header, /- 'package-lock\.json'/);
  })) passed++; else failed++;

  if (test('only schedule, manual dispatch and pull_request can start the watch', () => {
    const triggers = header.slice(header.search(/^on:\s*$/m), header.search(/^concurrency:\s*$/m));
    const events = [...triggers.matchAll(/^ {2}([a-z_]+):/gm)].map(match => match[1]);
    assert.deepStrictEqual(events, ['schedule', 'workflow_dispatch', 'pull_request']);
    assert.doesNotMatch(source, /pull_request_target|workflow_run|issue_comment|^\s+issues:\s*$/m);
  })) passed++; else failed++;

  if (test('keeps the watch read-only and scopes writes to the alert job', () => {
    assert.match(header, /permissions:\r?\n\s+contents: read/);
    assert.doesNotMatch(header, /:\s*write\b|write-all/);
    assert.ok(watch, 'missing ioc-watch job');
    assert.doesNotMatch(watch, /:\s*write\b|write-all|permissions:/);
    assert.match(alert, /\r?\n {4}permissions:\r?\n {6}actions: read\r?\n {6}issues: write\r?\n {4}env:/);
    assert.strictEqual((source.match(/:\s*write\b/g) || []).length, 1, 'issues: write must be the only write scope');
    assert.match(watch, /uses: actions\/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0/);
    assert.match(watch, /persist-credentials: false/);
    assert.doesNotMatch(source, /id-token:\s*write/);
    assert.doesNotMatch(source, /actions\/cache@/);
  })) passed++; else failed++;

  if (test('installs without lifecycle scripts and verifies registry signatures', () => {
    assert.match(watch, /npm ci --ignore-scripts/);
    assert.match(watch, /npm audit signatures/);
    assert.match(watch, /npm audit --omit=dev --audit-level=high/);
  })) passed++; else failed++;

  if (test('uses an active LTS runtime compatible with dependency engines', () => {
    assert.match(watch, /node-version: '24\.x'/);
  })) passed++; else failed++;

  if (test('runs each security check independently without hiding failures', () => {
    const steps = stepsOf(watch);
    for (const command of [
      'npm audit signatures',
      'npm audit --omit=dev --audit-level=high',
      'node tests/ci/scan-supply-chain-iocs.test.js',
      'node scripts/ci/scan-supply-chain-iocs.js --json',
      'node scripts/ci/validate-workflow-security.js',
    ]) {
      const step = steps.find(candidate => candidate.includes(command));
      assert.ok(step, `missing check: ${command}`);
      assert.match(step, /if: \$\{\{ !cancelled\(\) && steps\.(?:install|setup)\.outcome == 'success' \}\}/,
        `${command} must still run after another check fails`);
      assert.doesNotMatch(step, /continue-on-error:|\|\|\s*(?:true|exit\s+0)/);
    }
    const signatures = steps.find(step => step.includes('npm audit signatures'));
    assert.ok(!signatures.includes('npm audit --omit=dev'), 'signature failure must not skip the advisory audit');
    // A hung registry call must fail its step rather than cancel the job.
    for (const command of ['npm ci --ignore-scripts', 'npm audit signatures', 'npm audit --omit=dev']) {
      assert.match(steps.find(step => step.includes(command)), /timeout-minutes: \d+/, `${command} needs a step timeout`);
    }
    // No step may swallow a failure; the single allowed switch is job-level.
    assert.ok(lines(watch).includes(WATCH_CONTINUE_ON_ERROR), 'job-level continue-on-error must match the allowed expression');
    assert.strictEqual((source.match(/^\s*continue-on-error:/gm) || []).length, 1);
  })) passed++; else failed++;

  if (test('creates the report directory and fails when the report is missing', () => {
    const steps = stepsOf(watch);
    const report = steps.find(candidate => candidate.includes('node scripts/ci/scan-supply-chain-iocs.js'));
    assert.ok(report, 'missing IOC report step');
    assert.match(report, /mkdir -p artifacts/);
    const upload = steps.find(step => step.includes('uses: actions/upload-artifact@'));
    assert.ok(upload, 'missing upload step');
    assert.match(upload, /if: always\(\)/);
    assert.match(upload, /if-no-files-found: error/);
  })) passed++; else failed++;

  if (test('emits the IOC report artifact without upstream advisory bookkeeping', () => {
    assert.match(watch, /node scripts\/ci\/scan-supply-chain-iocs\.js --json > artifacts\/supply-chain-ioc-report\.json/);
    assert.match(watch, /uses: actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/);
    assert.match(watch, /name: supply-chain-ioc-report/);
    assert.match(watch, /retention-days: 14/);
    assert.doesNotMatch(source, /supply-chain-advisory-sources/, 'advisory-source refresh is upstream-only bookkeeping');
  })) passed++; else failed++;

  if (test('drill fails a real step and only on manual dispatch', () => {
    const drill = stepsOf(watch).find(step => step.startsWith('Drill failure'));
    assert.ok(drill, 'missing drill step');
    assert.match(drill, /if: \$\{\{ !cancelled\(\) && github\.event_name == 'workflow_dispatch' && inputs\.drill \}\}/);
    assert.match(drill, /exit 1/);
  })) passed++; else failed++;

  if (test('hands the watch result to the alert job even after a failed check', () => {
    assert.match(watch, /outputs:\r?\n\s+status: \$\{\{ steps\.result\.outputs\.status \}\}/);
    const result = stepsOf(watch).find(step => step.includes('id: result'));
    assert.ok(result, 'missing result step');
    assert.match(result, /if: always\(\)/);
    assert.match(result, /JOB_STATUS: \$\{\{ job\.status \}\}/);
    assert.match(result, /run: echo "status=\$JOB_STATUS" >> "\$GITHUB_OUTPUT"/);
  })) passed++; else failed++;

  if (test('alert job runs only for schedule and main dispatch, without repository code', () => {
    assert.ok(alert, 'missing alert job');
    assert.match(alert, /needs: ioc-watch/);
    assert.ok(lines(alert).includes(ALERT_IF), 'alert if condition must match exactly');
    assert.doesNotMatch(alert, /^\s+uses:/m, 'alert job must not run checkout or third-party actions');
    assert.doesNotMatch(alert, /\bnpm\b|\bnode\b/, 'alert job must not run repository code');
    const script = alert.slice(alert.indexOf('run: |'));
    assert.ok(script.length > 'run: |'.length, 'missing alert script');
    assert.doesNotMatch(script, /\$\{\{/, 'no expressions inside the alert script; values arrive through env');
  })) passed++; else failed++;

  if (test('alert verdict is fail-closed and never trusts needs.result', () => {
    assert.match(alert, /SCAN_STATUS: \$\{\{ needs\.ioc-watch\.outputs\.status \}\}/);
    assert.doesNotMatch(source, /needs\.ioc-watch\.result/, 'needs.result reads success under continue-on-error');
    assert.match(alert, /actions\/runs\/\$GITHUB_RUN_ID\/jobs/);
    assert.match(alert, /if \[ "\$SCAN_STATUS" = "success" \] && \[ "\$job_conclusion" = "success" \]; then\s+verdict="pass"\s+else\s+verdict="fail"/);
  })) passed++; else failed++;

  if (test('alert keeps one assigned tracking issue and stays quiet on repeats', () => {
    assert.match(alert, /\.has_issues/);
    assert.match(alert, /Issues are turned off[\s\S]*?exit 1/, 'with Issues off a failure must fail the run so email still arrives');
    assert.match(alert, /issues\?state=open&labels=\$LABEL/, 'look up the open issue through the REST list');
    assert.match(alert, /\.user\.login == "github-actions\[bot\]"/, 'only manage issues this workflow opened');
    assert.match(alert, /-f "assignees\[\]=\$GITHUB_REPOSITORY_OWNER"/, 'the owner must be assigned or nobody is notified');
    assert.match(alert, /\.assignees \| length[\s\S]*?exit 1/, 'an unassigned issue must fail loudly');
    assert.match(alert, /gh issue edit "\$number" --body "\$body"/, 'repeat failures update the issue quietly');
    assert.strictEqual((alert.match(/gh issue comment /g) || []).length, 1);
    assert.match(alert, /if \[ -n "\$newly" \]; then\s+gh issue comment /, 'comment only when another check starts failing');
    assert.match(alert, /gh issue close "\$number"/, 'a passing run closes the issue');
  })) passed++; else failed++;

  console.log(`\nPassed: ${passed}`);
  console.log(`Failed: ${failed}`);

  process.exit(failed > 0 ? 1 : 0);
}

run();
