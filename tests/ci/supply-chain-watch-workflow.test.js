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

// The only continue-on-error allowed: scheduled runs and drills on main hand
// their failures to the tracking issue instead of failing the run. A drill
// anywhere else has no alert job behind it, so it must fail red.
const WATCH_CONTINUE_ON_ERROR = "    continue-on-error: ${{ github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.drill && github.ref == 'refs/heads/main') }}";

// The alert job reads the watch job's conclusion by this display name.
const WATCH_JOB_NAME = 'IOC watch';

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
    // A drill must never cancel a scheduled run that is still in progress.
    assert.match(header, /^ {2}cancel-in-progress: false$/m);
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
    assert.match(watch, /^ {10}persist-credentials: false$/m);
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
    for (const command of [
      'npm audit signatures',
      'npm audit --omit=dev --audit-level=high',
      'node tests/ci/scan-supply-chain-iocs.test.js',
      'node scripts/ci/scan-supply-chain-iocs.js --json',
      'node scripts/ci/validate-workflow-security.js',
    ]) {
      // Any || (|| true, || :, || echo ...) or set +e could hide a failed check.
      assert.doesNotMatch(steps.find(candidate => candidate.includes(command)), /\|\||\bset \+e\b/,
        `${command} must not swallow its own failure`);
    }
    const signatures = steps.find(step => step.includes('npm audit signatures'));
    assert.ok(!signatures.includes('npm audit --omit=dev'), 'signature failure must not skip the advisory audit');
    // The step ids the checks depend on must exist, or every check is skipped.
    assert.match(steps.find(step => step.includes('npm ci --ignore-scripts')), /\r?\n {8}id: install\r?\n/);
    assert.match(steps.find(step => step.includes('uses: actions/setup-node@')), /\r?\n {8}id: setup\r?\n/);
    // A hang must fail its step rather than cancel the job: cancelled runs send no email.
    for (const step of steps) {
      assert.match(step, /\r?\n {8}timeout-minutes: \d+\r?\n/, `step "${step.split(/\r?\n/)[0]}" needs a step timeout`);
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

  if (test('fingerprints findings for the alert without ever failing the job', () => {
    assert.match(watch, /outputs:\r?\n(?:\s+[a-z]+: .*\r?\n)*?\s+findings: \$\{\{ steps\.findings\.outputs\.ids \}\}/);
    const step = stepsOf(watch).find(candidate => candidate.startsWith('Fingerprint findings'));
    assert.ok(step, 'missing fingerprint step');
    assert.match(step, /\r?\n {8}id: findings\r?\n/);
    assert.match(step, /run: \|\r?\n {10}set \+e\r?\n/);
    assert.match(step, /\r?\n {10}exit 0\s*$/, 'the fingerprint step must end with exit 0');
    assert.match(step, /timeout 60 npm audit --omit=dev --json/);
    assert.match(step, /"ioc \\\(\.filePath\) \\\(\.indicator\)"/, 'IOC fingerprints leave out line numbers');
    assert.match(step, /sed 's\/\^\/ids=\/' >> "\$GITHUB_OUTPUT"/);
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
    // A step-level if (for example failure()) would skip the alert: under
    // continue-on-error the watch job reports success to its dependents.
    assert.strictEqual(lines(alert).filter(line => /^\s+if:/.test(line)).length, 1, 'no step-level if may skip the alert');
    // A step timeout fails the job; the job timeout would only cancel it.
    assert.match(alert, /\r?\n {4}timeout-minutes: 5\r?\n/);
    assert.match(alert, /- name: Open, update or close the tracking issue\r?\n(?:\s+#[^\n]*\r?\n)*\s+timeout-minutes: 4\r?\n/);
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
    // The verdict finds the watch job by name; a rename would fail every week.
    assert.ok(lines(watch).includes(`    name: ${WATCH_JOB_NAME}`), 'watch job display name changed');
    assert.ok(alert.includes(`select(.name == "${WATCH_JOB_NAME}")`), 'alert must select the watch job by its name');
    // gh prints the error body to stdout on HTTP errors; a retry must not pass it on.
    assert.match(alert, /if out="\$\(gh api "\$@"\)"; then\s+printf '%s\\n' "\$out"/);
    assert.match(alert, /if \[ "\$SCAN_STATUS" = "success" \] && \[ "\$job_conclusion" = "success" \]; then\s+verdict="pass"\s+else\s+verdict="fail"/);
  })) passed++; else failed++;

  if (test('alert keeps one assigned tracking issue and stays quiet on repeats', () => {
    assert.match(alert, /\.has_issues/);
    assert.match(alert, /Issues are turned off[^\n]*\r?\n\s+exit 1\r?\n/, 'with Issues off a failure must fail the run so email still arrives');
    assert.match(alert, /issues\?state=open&labels=\$LABEL/, 'look up the open issue through the REST list');
    assert.match(alert, /\.user\.login == "github-actions\[bot\]"/, 'only manage issues this workflow opened');
    assert.match(alert, /-f "labels\[\]=\$LABEL" -f "assignees\[\]=\$GITHUB_REPOSITORY_OWNER"/,
      'the issue must carry the label the lookup filters on, and the owner must be assigned');
    const guards = alert.match(/\.assignees \| length' <<<"\$(?:created|open_json)"\)" -eq 0 \]; then\r?\n\s+echo "::error::[^\n]*\r?\n\s+exit 1\r?\n/g) || [];
    assert.strictEqual(guards.length, 2, 'both the new and the open issue must fail loudly when unassigned');
    assert.match(alert, /gh issue edit "\$number" --body "\$body"/, 'repeat failures update the issue quietly');
    assert.strictEqual((alert.match(/gh issue comment /g) || []).length, 1);
    assert.doesNotMatch(alert, /\/comments\b/, 'no other way to post comments');
    assert.match(alert, /if \[ -n "\$new_checks" \] \|\| \[ "\$new_findings" -gt 0 \]; then/,
      'comment only when a check starts failing or a failing check finds something new');
    assert.match(alert, /gh issue comment "\$number" --body "@\$GITHUB_REPOSITORY_OWNER /,
      'the escalation mentions the owner, which re-subscribes them');
    assert.match(alert, /gh issue close "\$number"/, 'a passing run closes the issue');
  })) passed++; else failed++;

  if (test('alert remembers what it reported and ignores edited or stale state', () => {
    for (const name of ['first-failing-run', 'latest-failing-run-id', 'seen-checks', 'seen-findings']) {
      assert.ok(alert.includes(`"<!-- supply-chain-watch ${name}: $`), `body must write the ${name} marker`);
    }
    assert.match(alert, /seen_checks="\$\(marker seen-checks \| tr -d '@'\)"/);
    assert.match(alert, /seen_findings="\$\(marker seen-findings \| tr -cd '0-9a-f '\)"/);
    assert.match(alert, /gsub\("\\r"; ""\)/, 'CRLF bodies from the web editor must still parse');
    assert.match(alert, /\[ "\$GITHUB_RUN_ID" -lt "\$last_fail" \]/, 'an older re-run must not close or rewrite a newer failure');
    assert.match(alert, /if \[ "\$run_id" = "\$first_run" \] \|\| \[\[ ! "\$run_id" =~ \^\[0-9\]\+\$ \]\]; then\s+first_run="\$RUN_URL"/,
      'only a run link of this repository is carried forward');
    assert.match(alert, /grep -oE '\\b\[0-9a-f\]\{12\}\\b' <<<"\$\{FINDINGS:-\}"/, 'finding ids are sanitised');
    assert.match(alert, /FINDINGS: \$\{\{ needs\.ioc-watch\.outputs\.findings \}\}/);
  })) passed++; else failed++;

  if (test('alert locks the issue and unlocks only around its own comments', () => {
    assert.match(alert, /gh api -X PUT "repos\/\$GH_REPO\/issues\/\$number\/lock" --silent/);
    assert.match(alert, /gh api -X DELETE "repos\/\$GH_REPO\/issues\/\$number\/lock" --silent/);
    assert.match(alert, /number="\$\(jq -r '\.number' <<<"\$created"\)"\r?\n\s+lock_issue\r?\n/, 'a new issue is locked at once');
    assert.match(alert, /\[ "\$locked" != "true" \] \|\| unlock_issue\r?\n\s+gh issue close /);
    assert.match(alert, /\[ "\$locked" != "true" \] \|\| unlock_issue\r?\n\s+gh issue comment [^\n]*\r?\n\s+lock_issue\r?\n/);
  })) passed++; else failed++;

  console.log(`\nPassed: ${passed}`);
  console.log(`Failed: ${failed}`);

  process.exit(failed > 0 ? 1 : 0);
}

run();
