# Product

## Register

brand

_The design surface is the public marketing landing page (`apps/web`). Design IS
the product here. The Rust data plane, control-plane API, and dashboard are
separate product surfaces with their own conventions._

## Users
개발자·플랫폼/보안 엔지니어·오픈소스 기여자·기술 의사결정자. AI 에이전트를 프로덕션에서
운영하며 "에이전트가 위험한 행동(프로덕션 DROP, 시크릿 삭제, 데이터 유출)을 하기 전에
막는 방법"을 찾고 있다. 방문 맥락: GitHub·HN·검색에서 유입되어 5초 안에 "이게 뭔지"를
판단하고 GitHub·문서로 넘어갈지 결정한다.

## Product Purpose
Honmoon은 AI 에이전트와 프로덕션 사이의 정책 기반 방화벽 게이트웨이다. 랜딩페이지의 목적은
하나의 스크롤 내러티브(히어로 → 5개 실제 요청 판정 → 위협 → 동작 원리 → 정책 엔진 →
운영 모드 → 오픈코어 → CTA)로 제품 가치를 전달하고 GitHub·문서 전환을 유도하는 것. 성공은
방문자가 "결계에서 요청이 판정된다"는 핵심 은유를 즉시 이해하고 CTA로 전환하는 것.

## Brand Personality
정밀함(precise) · 통제감(in-control) · 기술적 진지함(technically serious). 목소리는
차분하고 단정적이며 과장 없이 실제 명령어(`DROP TABLE users`, `kubectl delete secret`)로
말한다. 감정 목표: 신뢰와 안도("이제 막혀 있다"). 결계(barrier/membrane)라는 공간 은유가
브랜드의 중심 — 요청이 막을 관통·파문·튕김·흡수되는 3/4 시점 멤브레인.

## Anti-references
- 전형적 SaaS 랜딩(파스텔 그라디언트, hero-metric 템플릿, 동일 카드 그리드, 이모지 아이콘).
- 크림/샌드/웜뉴트럴 "에디토리얼" 톤 — 이 브랜드는 딥 코스믹 다크다.
- 과장된 마케팅 카피·느낌표·"revolutionary/game-changing" 류. 실제 명령어로 보여준다.
- 화려한 bounce/elastic 모션. 모션은 은은하고 물리적(파문·드리프트).

## Design Principles
- **Show the verdict, don't claim it.** 실제 요청과 실제 판정(ALLOW/MASK/DENY/PAUSE)을
  공간으로 보여준다. 마케팅 문장보다 명령어와 결과가 설득한다.
- **The barrier is the brand.** 멤브레인/결계 은유가 히어로부터 전 섹션의 시각 언어를 통일.
- **Calm precision over loud.** 여백·리듬·정밀한 정렬로 "통제됨"을 전달. 스페이싱이 곧 톤.
- **Every request is real.** 데모 요청은 실제 시나리오(prod DROP, .env 유출)여야 한다.
- **Open by default.** 오픈코어 정직함 — "data plane never locked".

## Accessibility & Inclusion
WCAG AA 목표(본문 ≥4.5:1, 큰 텍스트 ≥3:1). 다크 배경 위 muted 텍스트의 대비를 특히 검증.
skip-to-content 링크, 섹션 aria-label, 키보드 포커스 링 유지. `prefers-reduced-motion`은
필수 — 멤브레인·스크롤 스크럽·페이드인 모두 정지/정적 대체를 제공.
