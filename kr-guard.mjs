import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { resolveTxt } from 'node:dns/promises';
import { resolve, basename } from 'node:path';
import { pathToFileURL } from 'node:url';
const dir = () => resolve('.kr-guard');
const statePath = () => resolve(dir(), 'state.json');
const ua = 'kr-guard/0.1 (+https://github.com/stanlee7/kr-guard)';
const empty = () => ({
  tokens: {},
  verified: {},
  findings: [],
  targets: []
});
async function load() {
  try {
    return JSON.parse(await readFile(statePath(), 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return empty();
    throw e;
  }
}
async function save(s) {
  await mkdir(dir(), {
    recursive: true
  });
  await writeFile(statePath(), JSON.stringify(s, null, 2), {
    mode: 0o600
  });
}
function target(raw) {
  let u;
  try {
    u = new URL(raw.includes('://') ? raw : `https://${raw}`);
  } catch {
    throw Error('올바른 도메인을 입력하세요.');
  }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || u.pathname !== '/' || u.search || u.hash) throw Error('도메인과 선택적 포트만 입력하세요.');
  const local = ['localhost', '127.0.0.1'].includes(u.hostname);
  if (!local && (u.protocol !== 'https:' || u.port || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(u.hostname))) throw Error('공개 도메인은 HTTPS 도메인 이름만 허용합니다.');
  if (local && !raw.includes('://')) u.protocol = 'http:';
  return {
    origin: u.origin,
    host: u.hostname,
    local
  };
}
const finding = (severity, title, why, fix) => ({
  severity,
  title,
  why,
  fix
});
async function verify(raw) {
  const t = target(raw);
  if (t.local) throw Error('로컬 주소는 인증이 필요 없습니다.');
  const s = await load();
  const token = s.tokens[t.host];
  if (!token) {
    s.tokens[t.host] = randomBytes(24).toString('hex');
    await save(s);
    console.log(`https://${t.host}/.well-known/kr-guard.txt 에 다음 값을 올리거나 DNS TXT에 kr-guard=${s.tokens[t.host]} 를 추가하세요.\n설정 후 같은 verify 명령을 다시 실행하세요.`);
    return;
  }
  let ok = false;
  try {
    const r = await fetch(`https://${t.host}/.well-known/kr-guard.txt`, {
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
      headers: {
        'User-Agent': ua
      }
    });
    if (r.ok) ok = (await r.text()).trim() === token;
  } catch {}
  if (!ok) try {
    ok = (await resolveTxt(t.host)).some(parts => parts.join('') === `kr-guard=${token}`);
  } catch {}
  if (!ok) {
    console.log('인증 값을 확인하지 못했습니다. 설정 후 다시 실행하세요.');
    return;
  }
  s.verified[t.host] = true;
  delete s.tokens[t.host];
  await save(s);
  console.log(`${t.host} 소유 인증 완료`);
}
async function site(raw) {
  const t = target(raw),
    s = await load();
  if (!t.local && !s.verified[t.host]) throw Error('소유 인증되지 않은 도메인입니다. 먼저 verify 명령을 실행하세요.');
  let last = 0,
    count = 0;
  async function req(path, method = 'GET', body = false) {
    if (++count > 30) throw Error('요청 한도 초과');
    const delay = 1000 - (Date.now() - last);
    if (delay > 0) await new Promise(r => setTimeout(r, delay));
    last = Date.now();
    const r = await fetch(t.origin + path, {
      method,
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
      headers: {
        'User-Agent': ua
      }
    });
    let text = '';
    if (body && r.body) {
      const reader = r.body.getReader();
      let size = 0;
      const chunks = [];
      while (size < 262144) {
        const part = await reader.read();
        if (part.done) break;
        chunks.push(part.value);
        size += part.value.length;
      }
      await reader.cancel();
      text = Buffer.concat(chunks).toString('utf8');
    } else if (r.body) await r.body.cancel();
    return {
      status: r.status,
      headers: r.headers,
      text
    };
  }
  const f = [];
  const home = await req('/', 'GET', true);
  for (const [test, title, fix] of [[!home.headers.has('strict-transport-security'), 'HSTS 헤더 없음', 'HTTPS 서버에 HSTS를 설정하세요.'], [!home.headers.has('content-security-policy') && !home.headers.has('x-frame-options'), '화면 삽입 방지 헤더 없음', 'CSP frame-ancestors 또는 X-Frame-Options를 설정하세요.'], [!home.headers.has('x-content-type-options'), 'X-Content-Type-Options 헤더 없음', 'X-Content-Type-Options: nosniff를 설정하세요.']]) if (test) f.push(finding('중간', title, '브라우저의 보안 보호가 약해질 수 있습니다.', fix));
  const wp = /wp-content|wp-includes|wordpress/i.test(home.text) || /wordpress/i.test(home.headers.get('x-generator') || '');
  if (wp) {
    const users = await req('/wp-json/wp/v2/users', 'GET', true);
    try {
      const data = JSON.parse(users.text);
      if (users.status === 200 && Array.isArray(data) && data.some(x => x && (x.slug || x.name))) f.push(finding('중간', '워드프레스 사용자 목록 공개', '공개 사용자 정보가 로그인 계정 추측에 이용될 수 있습니다.', '사용자 API 공개 범위를 확인하고 필요한 경우 제한하세요.'));
    } catch {}
    const author = await req('/?author=1');
    if (author.status >= 300 && author.status < 400 && /\/author\//i.test(author.headers.get('location') || '')) f.push(finding('중간', '작성자 주소로 아이디 노출 가능', '작성자 리다이렉트가 계정 식별자를 드러낼 수 있습니다.', '작성자 주소 공개 여부를 확인하고 필요한 경우 제한하세요.'));
    const readme = await req('/readme.html', 'GET', true);
    if (readme.status === 200 && /wordpress/i.test(readme.text)) f.push(finding('낮음', '워드프레스 readme 공개', '제품 정보가 노출될 수 있습니다.', 'readme 공개 필요성을 검토하세요.'));
    if (/<meta\s+[^>]*name=["']generator["'][^>]*wordpress/i.test(home.text) || /<meta\s+[^>]*content=["'][^"']*wordpress[^>]*name=["']generator/i.test(home.text)) f.push(finding('낮음', '워드프레스 generator 정보 노출', '제품과 버전 정보가 노출될 수 있습니다.', 'generator 메타 공개 필요성을 검토하세요.'));
    for (const [p, title] of [['/xmlrpc.php', 'XML-RPC 접근 가능'], ['/wp-login.php', '로그인 화면 접근 가능']]) {
      const r = await req(p, 'HEAD');
      if (r.status === 200) f.push(finding('낮음', title, '공개된 기능은 보안 설정 확인이 필요합니다.', '사용 여부와 접근 제한 및 로그인 보호 설정을 확인하세요.'));
    }
    if (/wp-content\/plugins\/[^"'\s?]+[^"'\s]*[?&](?:amp;)?ver=/i.test(home.text)) f.push(finding('오탐 의심', '플러그인 자산 버전 단서', '화면 자산의 버전은 설치 버전과 다를 수 있습니다.', '추정, 관리자 화면에서 확인 필요.'));
  }
  for (const [p, title] of [['/.env', '환경 설정 파일'], ['/.git/HEAD', 'Git HEAD 파일'], ['/debug.log', '디버그 로그']]) {
    const r = await req(p, 'HEAD');
    if (r.status === 200) f.push(finding('높음', `${title} 접근 가능 의심`, '민감한 정보가 노출될 가능성이 있습니다. 상태 코드만 확인했습니다.', '서버에서 해당 경로의 외부 접근을 차단하고 노출 여부를 확인하세요.'));
  }
  s.targets = [...new Set([...(s.targets || []), `site:${t.origin}`])];
  s.findings = s.findings.filter(x => x.group !== `site:${t.origin}`);
  s.findings.push(...f.map(x => ({
    ...x,
    group: `site:${t.origin}`
  })));
  await save(s);
  console.log(`사이트 점검 완료: ${count}개 요청, ${f.length}개 항목. node kr-guard.mjs report 로 보고서를 만드세요.`);
}
async function repos(args) {
  let executable = 'gitleaks';
  const i = args.indexOf('--gitleaks');
  if (i >= 0) {
    if (!args[i + 1]) throw Error('--gitleaks 다음에 실행 파일 경로가 필요합니다.');
    executable = args[i + 1];
    args.splice(i, 2);
  }
  if (!args.length) throw Error('검사할 폴더 또는 저장소 경로를 입력하세요.');
  const check = spawnSync(executable, ['version'], {
    encoding: 'utf8',
    windowsHide: true
  });
  if (check.error?.code === 'ENOENT') {
    console.log('Gitleaks를 먼저 설치하세요.\n공식 배포 안내: https://github.com/gitleaks/gitleaks\n설치 후 PATH에 추가하거나 --gitleaks 실행파일경로를 지정하세요.');
    return;
  }
  if (check.error || check.status !== 0) throw Error('Gitleaks 실행 파일을 확인하세요.');
  const s = await load();
  for (const p of args) {
    const source = resolve(p);
    const info = await stat(source);
    if (!info.isDirectory()) throw Error('검사 대상은 폴더여야 합니다.');
    let git = false;
    try {
      await stat(resolve(source, '.git'));
      git = true;
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    const scanArgs = ['detect', '--source', source, '--redact', '--report-format', 'json', '--report-path', '-'];
    if (!git) scanArgs.push('--no-git');
    const r = spawnSync(executable, scanArgs, {
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 20 * 1024 * 1024
    });
    if (r.error || ![0, 1].includes(r.status)) throw Error(`Gitleaks 검사 실패 (종료 코드 ${r.status ?? '없음'}): ${(r.stderr || r.error?.message || '오류 정보 없음').trim()}`);
    let records = [];
    if (r.stdout.trim()) {
      try {
        records = JSON.parse(r.stdout);
      } catch {
        throw Error('Gitleaks 결과를 읽지 못했습니다.');
      }
    }
    if (!Array.isArray(records)) throw Error('Gitleaks 결과 형식이 올바르지 않습니다.');
    if (r.status === 1 && !records.length) throw Error(`Gitleaks 검사 실패 (종료 코드 1): ${(r.stderr || '결과 없음').trim()}`);
    const group = `repo:${basename(resolve(p)).replace(/[^a-zA-Z0-9가-힣_.-]/g, '_')}`;
    s.findings = s.findings.filter(x => x.group !== group);
    s.targets = [...new Set([...(s.targets || []), `repo:${source}`])];
    for (const rec of records) {
      const rule = String(rec.RuleID || '').toLowerCase();
      const suspicion = /supabase|anon/.test(rule) || /generic/.test(rule);
      s.findings.push({
        ...finding(suspicion ? '오탐 의심' : '높음', suspicion ? '비밀값 탐지: 수동 확인 필요' : '비밀값 탐지', '탐지 결과가 실제 비밀값인지 확인해야 합니다.', '원본 저장소에서 해당 항목을 확인하고 실제 비밀이면 폐기 및 교체하세요.'),
        group
      });
    }
  }
  await save(s);
  console.log('저장소 검사 완료. 원문은 저장하지 않았습니다.');
}
async function refine(findings, provider) {
  if (!provider || provider === 'anthropic' && !process.env.ANTHROPIC_API_KEY) return findings;
  if (!['anthropic', 'ollama'].includes(provider)) throw Error('--ai는 ollama 또는 anthropic만 지원합니다.');
  // Only generic, fixed descriptions leave the machine; no file paths, matches, domains, or tokens.
  const input = findings.map(({
    severity,
    title,
    why,
    fix
  }) => ({
    severity,
    title,
    why,
    fix
  }));
  const prompt = `다음 보안 점검 항목을 한국어로 다듬으세요. 각 항목의 severity,title,why,fix만 포함한 JSON 배열만 반환. 등급은 높음, 중간, 낮음, 오탐 의심 중 하나. 입력: ${JSON.stringify(input)}`;
  try {
    const anthropic = provider === 'anthropic';
    const response = await fetch(anthropic ? 'https://api.anthropic.com/v1/messages' : 'http://localhost:11434/api/generate', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(anthropic ? {
          'x-api-key': process.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        } : {})
      },
      body: JSON.stringify(anthropic ? {
        model: process.env.KR_GUARD_ANTHROPIC_MODEL || 'claude-sonnet-5-5',
        max_tokens: 2048,
        messages: [{
          role: 'user',
          content: prompt
        }]
      } : {
        model: process.env.KR_GUARD_OLLAMA_MODEL || 'llama3.1',
        prompt,
        stream: false,
        format: 'json'
      }),
      signal: AbortSignal.timeout(30000)
    });
    if (!response.ok) return findings;
    const data = await response.json();
    const parsed = JSON.parse(anthropic ? data.content?.[0]?.text : data.response);
    const list = Array.isArray(parsed) ? parsed : parsed.findings;
    if (!Array.isArray(list) || list.length !== findings.length) return findings;
    return findings.map((f, i) => {
      const x = list[i];
      if (!x || !['높음', '중간', '낮음', '오탐 의심'].includes(x.severity) || !['title', 'why', 'fix'].every(k => typeof x[k] === 'string' && x[k].length <= 300 && !/[\r\n]/.test(x[k]))) return f;
      return {
        ...f,
        severity: x.severity,
        title: x.title,
        why: x.why,
        fix: x.fix
      };
    });
  } catch {
    return findings;
  }
}
async function report(ai) {
  const s = await load();
  const f = await refine(s.findings, ai);
  const counts = ['높음', '중간', '낮음', '오탐 의심'].map(k => `${k} ${f.filter(x => x.severity === k).length}건`).join(', ');
  const lines = [`한 줄 요약: 검사한 대상 ${(s.targets || []).length}개, 총 ${f.length}건 (${counts}).`, '', '# 지킴이 점검 보고서', '', ...(f.length ? f.flatMap((x, i) => [`## ${i + 1}. ${x.title}`, `- 등급: ${x.severity}`, `- 왜 위험한가: ${x.why}`, `- 고칠 방법: ${x.fix}`, '']) : ['점검 결과가 없습니다. 먼저 repos 또는 site 명령을 실행하세요.'])];
  await writeFile('kr-guard-report.md', lines.join('\n'), 'utf8');
  console.log('kr-guard-report.md 생성 완료');
}
export async function main(argv) {
  const [cmd, ...args] = argv;
  if (cmd === 'verify' && args.length === 1) return verify(args[0]);
  if (cmd === 'site' && args.length === 1) return site(args[0]);
  if (cmd === 'repos') return repos(args);
  if (cmd === 'report') {
    if (args.length && (args.length !== 2 || args[0] !== '--ai')) throw Error('사용법: report [--ai ollama|anthropic]');
    return report(args[1]);
  }
  throw Error('사용법: node kr-guard.mjs repos <경로...> | verify <도메인> | site <도메인> | report [--ai ollama|anthropic]');
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main(process.argv.slice(2)).catch(e => {
  console.error(`오류: ${e.message}`);
  process.exitCode = 1;
});
