허락받지 않은 시스템 점검은 정보통신망법 위반입니다. 내 것만 점검하세요.

# 지킴이 kr-guard v0.1

내 저장소의 비밀값 탐지와 내 웹사이트의 공개 설정을 점검하고 한국어 보고서를 만듭니다. Node.js 22 이상이 필요하며 별도 패키지는 없습니다. 저장소 검사에는 사용자가 설치한 Gitleaks가 필요합니다.

## 30분 안에 첫 보고서: 3단계

1. Node.js 22 이상과 [Gitleaks](https://github.com/gitleaks/gitleaks)를 설치하고 이 폴더에서 터미널을 엽니다.
2. `node kr-guard.mjs repos ./내저장소`를 실행합니다. 웹사이트는 `node kr-guard.mjs verify example.com`으로 안내에 따라 인증한 후 같은 명령을 다시 실행하고 `node kr-guard.mjs site example.com`을 실행합니다.
3. `node kr-guard.mjs report`를 실행하고 현재 폴더의 `kr-guard-report.md`를 엽니다. 결과는 `.kr-guard/state.json`에 저장됩니다.

Gitleaks가 PATH에 없으면 `repos ./내저장소 --gitleaks 실행파일경로`로 지정하세요. 로컬 테스트는 `site localhost:포트` 또는 `site 127.0.0.1:포트`로 인증 없이 가능합니다. 각 공개 도메인은 별도로 인증해야 하며 인증은 현재 작업 폴더에 저장됩니다. HTTPS 소유 인증은 `.well-known/kr-guard.txt` 또는 DNS TXT로 합니다. 인증 완료 후 토큰을 서버 또는 DNS에서 지울 수 있습니다.

| 하는 일 | 하지 않는 일 |
| --- | --- |
| Gitleaks 결과의 가린 판정만 보관 | 비밀값 원문 저장 |
| 인증된 도메인의 정해진 경로를 읽기 요청으로 확인 | 공격, 암호 대입, 포트·대역 스캔, 무작위 탐색 |
| 문제 가능성과 사람이 할 조치를 보고 | 차단, 삭제, 설정 변경 |
| 플러그인 자산 버전 단서 표시 | 설치 버전 확정 또는 취약점 확정 |

사이트 점검은 요청 사이에 1초 이상 기다리고 최대 30회 요청합니다. 민감 파일은 HEAD 상태 코드만 확인하므로 실제 유출 확정이 아닙니다. 워드프레스 탐지는 홈페이지의 흔적에 의존해 일부 사이트를 놓칠 수 있습니다. 상태 코드는 설정과 서버 구성에 따라 오탐일 수 있습니다. `repos`는 Gitleaks가 지원하는 로컬 대상에 한정됩니다. 결과에는 경로와 탐지 원문을 저장하지 않으므로 원본 위치 확인에는 Gitleaks를 직접 이용하세요.

선택 사항: `node kr-guard.mjs report --ai ollama`는 로컬 Ollama(`localhost:11434`, 기본 모델 `llama3.1`, `KR_GUARD_OLLAMA_MODEL`로 변경)에, `--ai anthropic`은 환경변수 `ANTHROPIC_API_KEY`를 사용하는 외부 API에 일반화된 가림 결과만 보냅니다. 외부 전송 전 사용자 선택이 필요하며, 키가 없거나 호출이 실패하면 규칙 기반 결과를 씁니다. AI 결과는 확인이 필요합니다. 인증 상태와 보고서는 현재 컴퓨터에 저장됩니다.

## English

Inspect only assets you own or are authorized to assess. Node.js 22 and an installed Gitleaks are required for repository scans. Verify a domain with DNS or a well-known file, run `site`, then `report`. No exploit or remediation is performed.

테스트: `node --test test/guard.test.mjs`
