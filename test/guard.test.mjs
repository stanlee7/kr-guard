import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { main } from '../kr-guard.mjs';
test('미인증 도메인은 요청 전에 거절한다', async () => {
  const old = process.cwd(),
    cwd = await mkdtemp(join(tmpdir(), 'kr-guard-'));
  try {
    process.chdir(cwd);
    await assert.rejects(main(['site', 'example.com']), /소유 인증되지 않은/);
  } finally {
    process.chdir(old);
    await rm(cwd, {
      recursive: true,
      force: true
    });
  }
});
test('로컬 워드프레스 모의 서버의 헤더와 사용자 공개를 보고한다', {
  timeout: 30000
}, async () => {
  const old = process.cwd(),
    cwd = await mkdtemp(join(tmpdir(), 'kr-guard-')),
    times = [];
  const server = createServer((req, res) => {
    times.push(Date.now());
    if (req.url === '/') res.end('<html><script src="/wp-content/plugins/foo/x.js?ver=1"></script></html>');else if (req.url === '/wp-json/wp/v2/users') {
      res.setHeader('content-type', 'application/json');
      res.end('[{"slug":"example"}]');
    } else {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise(r => server.listen(0, 'localhost', r));
  try {
    process.chdir(cwd);
    await main(['site', `localhost:${server.address().port}`]);
    await main(['report']);
    const text = await readFile(join(cwd, 'kr-guard-report.md'), 'utf8');
    assert.match(text, /^한 줄 요약:/);
    assert.match(text, /HSTS 헤더 없음/);
    assert.match(text, /워드프레스 사용자 목록 공개/);
    assert.match(text, /추정, 관리자 화면에서 확인 필요/);
    assert.ok(times.length <= 30);
    for (let i = 1; i < times.length; i++) assert.ok(times[i] - times[i - 1] >= 950);
  } finally {
    process.chdir(old);
    await new Promise(r => server.close(r));
    await rm(cwd, {
      recursive: true,
      force: true
    });
  }
});
test('일반 폴더의 가짜 비밀값을 탐지한다', async t => {
  const executable = process.env.KR_GUARD_GITLEAKS || 'gitleaks';
  const check = spawnSync(executable, ['version'], {
    encoding: 'utf8',
    windowsHide: true
  });
  if (check.error?.code === 'ENOENT' && !process.env.KR_GUARD_GITLEAKS) {
    t.skip('Gitleaks가 PATH에 없습니다.');
    return;
  }
  assert.equal(check.status, 0, check.stderr || check.error?.message);
  const old = process.cwd();
  const cwd = await mkdtemp(join(tmpdir(), 'kr-guard-'));
  try {
    const target = join(cwd, 'plain');
    await mkdir(target);
    await writeFile(join(target, 'sample.js'), 'const token = "ghp_' + '1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4rS5tU";\n');
    process.chdir(cwd);
    await main(['repos', target, '--gitleaks', executable]);
    const state = JSON.parse(await readFile(join(cwd, '.kr-guard', 'state.json'), 'utf8'));
    assert.ok(state.findings.length >= 1, '일반 폴더에서 1건 이상 탐지해야 합니다.');
    console.log(`일반 폴더 검사 결과: ${state.findings.length}건`);
    await main(['report']);
    const report = await readFile(join(cwd, 'kr-guard-report.md'), 'utf8');
    assert.match(report, /^한 줄 요약: 검사한 대상 1개,/);
    console.log(report.split('\n')[0]);
  } finally {
    process.chdir(old);
    await rm(cwd, {
      recursive: true,
      force: true
    });
  }
});
