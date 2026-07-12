---
product_spec_domain: web/landing
---

# Marketing Landing Page (apps/web)

> Track: landing-page-20260712

## Overview

Honmoon의 공개 마케팅 랜딩페이지를 신규 워크스페이스 앱 `apps/web`으로 구현한다.
승인된 디자인(자기완결형 단일 HTML `index-v7-inspector.html` — 다크 테마, oklch 컬러
토큰, 인라인 CSS + canvas 애니메이션)을 **시각적·행동적으로 그대로** 재현하되, 제품
대시보드(`apps/dashboard`)와 동일한 스택(React 19 · Vite · Tailwind v4)으로 섹션별
컴포넌트화한다.

랜딩페이지의 목적은 방문자(잠재 사용자·오픈소스 기여자·의사결정자)에게 Honmoon이
"AI 에이전트와 프로덕션 사이의 정책 기반 방화벽"임을 하나의 스크롤 내러티브로 전달하고,
GitHub·문서로 전환시키는 것이다. 별도 백엔드·폼·인증 없이 정적으로 서빙되는 단일 페이지다.

원본 디자인 참조(구현 시 마크업/CSS/JS 원본): 승인된 단일 HTML 시안
`index-v7-inspector.html` — Open Design 아티팩트(로컬 시안). 저장소에 커밋되지
않으며, 구현자는 시안 파일을 로컬에서 열어 참조한다.

## User Scenarios & Testing

### User Story 1 — 방문자가 제품 가치를 한눈에 이해한다 (Priority: P1)

랜딩페이지를 처음 방문한 사람이 스크롤하며 "무엇을/왜"를 파악한다: 히어로의 한 줄
가치 제안 → barrier 섹션의 5개 실제 요청 판정 → 위협·동작 원리·정책·운영 모드·오픈코어
→ 최종 CTA. 모든 카피·섹션 순서·시각 위계가 원본과 동일하다.

**Why this priority**: 랜딩페이지의 핵심 존재 이유. 이 내러티브가 전달되지 않으면 페이지
가치가 없다.

**Independent Test**: 페이지를 로드하고 상단→하단으로 스크롤하며 10개 영역(topnav, hero,
barrier, threat, how-it-works, policy, modes, open-core, cta, footer)이 원본과 동일한
순서·카피·레이아웃으로 나타나는지 육안 및 원본 대조로 확인한다.

**Acceptance Criteria**:

1. **AC-001** — 페이지가 로드되면, 시스템은 원본의 10개 영역(topnav · hero · barrier ·
   threat · how-it-works · policy · modes · open-core · cta · footer)을 원본과 동일한
   순서로 렌더링해야 한다.
2. **AC-002** — 각 섹션이 표시될 때, 시스템은 원본의 헤드라인·본문·라벨 카피를 문자 그대로
   (동일 텍스트로) 표시해야 한다.
3. **AC-003** — 페이지가 표시되는 동안, 시스템은 원본의 컬러 토큰(oklch), 타이포 스케일,
   간격 토큰에 따른 다크 테마 시각을 재현해야 한다.

### User Story 2 — 인터랙션과 애니메이션이 원본대로 동작한다 (Priority: P2)

방문자가 페이지와 상호작용할 때 원본의 동적 경험(멤브레인 배경 애니메이션, barrier
스크롤 판정, 섹션 페이드인, 프로스트 내비, CTA 스무스 스크롤, 정책 복사)이 동일하게
재현된다.

**Why this priority**: 디자인의 "그대로" 충실도를 결정하는 차별화 요소. 정적 재현만으로는
원본 경험이 완성되지 않는다.

**Independent Test**: 마우스 이동·스크롤·버튼 클릭을 수행하며 각 인터랙션이 원본과 동일한
시각 반응을 내는지, 그리고 `prefers-reduced-motion`에서 애니메이션이 멈추는지 확인한다.

**Acceptance Criteria**:

1. **AC-004** — 페이지가 표시되는 동안, 시스템은 전체 화면 고정 배경에 결계 멤브레인
   애니메이션(요청이 막을 관통·파문·튕김·흡수)을 지속적으로 렌더링해야 한다.
2. **AC-005** — 포인터가 페이지 위에서 움직이면, 시스템은 멤브레인 애니메이션이 포인터
   위치에 반응하도록 해야 한다.
3. **AC-006** — 사용자가 barrier 섹션을 스크롤하면, 시스템은 5개 요청 행이 게이트를
   통과·판정되는 스크롤 구동 애니메이션을 진행해야 한다.
4. **AC-007** — 내러티브 섹션이 뷰포트에 진입하면, 시스템은 해당 섹션을 페이드인으로
   나타나게 해야 한다.
5. **AC-008** — 페이지가 24px 초과 스크롤되면, 시스템은 상단 내비게이션에 프로스트
   글래스(backdrop blur) 배경을 적용해야 한다.
6. **AC-009** — 사용자가 히어로의 "See the policy engine" 또는 상단 내비의 "Get started"
   버튼(원본 상 내부 스크롤 컨트롤 — 최종 CTA 섹션의 "Get started on GitHub" 외부 링크와는
   별개)을 클릭하면, 시스템은 정책 섹션으로 부드럽게 스크롤 이동해야 한다.
7. **AC-010** — 사용자가 정책 코드 카드의 Copy 버튼을 클릭하면, 시스템은 정책 코드 카드에
   표시된 `agent.yaml` 정책 전문(CEL 표현식이 포함된 YAML)을 클립보드에 복사해야 한다.

### User Story 3 — 전환 링크가 올바른 대상으로 연결된다 (Priority: P2)

방문자가 CTA·내비·푸터의 외부 링크를 통해 GitHub 저장소와 문서로 이동한다.

**Why this priority**: 랜딩페이지의 전환 목표(GitHub·Docs 방문)를 달성하는 경로.

**Independent Test**: 각 CTA·내비·푸터 링크의 대상 URL이 원본과 일치하고 새 탭에서
열리는지 확인한다.

**Acceptance Criteria**:

1. **AC-011** — 사용자가 GitHub 저장소 링크(내비 아이콘, 히어로 GitHub, CTA "Get started on
   GitHub", 푸터 GitHub)를 활성화하면, 시스템은 `https://github.com/pleaseai/honmoon`을 새
   탭에서 열어야 한다.
2. **AC-012** — 사용자가 Docs 링크(내비 없음 · CTA "Docs ↗" · 푸터 Docs)를 활성화하면,
   시스템은 `https://github.com/pleaseai/honmoon/tree/master/docs`를 새 탭에서 열어야 한다.
3. **AC-012b** — 사용자가 푸터의 Readme 링크를 활성화하면, 시스템은
   `https://github.com/pleaseai/honmoon/blob/master/README.md`를 새 탭에서 열어야 한다.

### User Story 4 — 반응형·접근성이 유지된다 (Priority: P3)

다양한 화면 폭과 보조기술 사용자가 페이지를 이용할 수 있다.

**Why this priority**: 원본이 이미 갖춘 품질 기준. 그대로 재현하려면 유지되어야 한다.

**Independent Test**: 데스크톱/태블릿/모바일 폭에서 레이아웃이 원본 브레이크포인트대로
재배치되는지, skip-link·aria-label·reduced-motion이 동작하는지 확인한다.

**Acceptance Criteria**:

1. **AC-013** — 뷰포트 폭이 원본 브레이크포인트(920px) 이하이면, 시스템은 원본과 동일한
   단일 컬럼/재배치 레이아웃으로 전환해야 한다.
2. **AC-014** — 사용자가 `prefers-reduced-motion: reduce`를 설정한 경우, 시스템은 멤브레인·
   스크롤·페이드 애니메이션을 정지하고 정적 상태를 표시해야 한다.
3. **AC-015** — 페이지는 원본의 접근성 장치(skip-to-content 링크, 섹션 aria-label)를
   제공해야 한다.

## Requirements

### Functional Requirements

- **FR-001**: 시스템은 랜딩페이지를 신규 워크스페이스 앱 `apps/web`으로 제공해야 하며,
  루트 워크스페이스에 편입되어 독립적으로 개발·빌드 가능해야 한다.
- **FR-002**: 시스템은 원본 디자인의 10개 영역을 원본 순서·카피·시각 위계로 재현해야 한다.
- **FR-003**: 시스템은 barrier 섹션에서 5개 요청(allow · mask · deny · deny · pause)의
  요청자·명령·verdict·rule·result를 원본 카피 그대로 표시해야 한다.
- **FR-004**: 시스템은 정책 섹션에 `policies/agent.yaml` 정책 예시(CEL 표현식이 포함된
  YAML)를 구문 강조와 함께 표시하고 Copy 동작을 제공해야 한다.
- **FR-005**: 시스템은 전체 화면 고정 배경 멤브레인 애니메이션을 원본과 동일한 시각 결과로
  렌더링하고 포인터에 반응해야 한다.
- **FR-006**: 시스템은 barrier 스크롤 판정, 섹션 페이드인, 내비 프로스트, CTA 스무스
  스크롤 인터랙션을 원본대로 제공해야 한다.
- **FR-007**: 시스템은 원본의 모든 외부 링크를 동일 대상 URL로, 새 탭 열림으로 연결해야
  한다 — GitHub 저장소(`.../pleaseai/honmoon`), Docs(`.../tree/master/docs`), Readme
  (`.../blob/master/README.md`). (각각 AC-011 · AC-012 · AC-012b로 검증.)
- **FR-008**: 시스템은 원본의 컬러 토큰·타이포·간격 토큰을 재현 가능한 형태로 이관해야 한다.

### Non-functional Requirements

- **NFR-001**: 시스템은 `apps/dashboard`와 동일한 스택(React 19 · Vite · Tailwind v4)을
  사용해 저장소 일관성을 유지해야 한다.
- **NFR-002**: 시스템은 `prefers-reduced-motion`을 존중하고 skip-link·aria-label 등 원본의
  접근성 수준을 유지해야 한다.
- **NFR-003**: 시스템은 원본의 반응형 거동(브레이크포인트·유동 타이포)을 유지해야 한다.

## Success Criteria

- **SC-001**: 구현된 페이지를 원본과 나란히 대조했을 때, 10개 영역 전부가 순서·카피·레이아웃
  일치한다(검토자 육안 대조 기준 불일치 0건).
- **SC-002**: 원본의 7개 인터랙션(멤브레인·포인터 반응·barrier 스크롤·섹션 페이드인·내비
  프로스트·CTA 스크롤·정책 복사)이 모두 재현되어 동작한다.
- **SC-003**: 모든 외부 링크가 원본과 동일한 대상으로 연결되고 깨진 링크가 없다.
- **SC-004**: `prefers-reduced-motion` 활성 시 애니메이션이 멈추고, 모바일 폭에서 가로
  스크롤 없이 레이아웃이 재배치된다.

## Out of Scope

- 백엔드·서버 로직·폼 제출·이메일 수집. "Get started" 등은 원본대로 링크/스크롤 동작만 한다.
- 애널리틱스/추적 스크립트 연동(향후 별도 트랙).
- 다국어/i18n. 원본 영어 카피를 그대로 사용한다.
- 배포 파이프라인(CI·호스팅·도메인 연결)은 이 트랙 범위 밖 — 앱 구현·로컬 빌드까지.
- 새 디자인 변형·카피 리라이팅. 승인된 `index-v7-inspector.html`만을 진실의 원천으로 한다.

## Assumptions

- 위치·스택 결정은 사용자 확정: 신규 `apps/web`, React 19 + Vite + Tailwind v4로 컴포넌트화.
- 대시보드의 Vite·Tailwind v4 설정을 참고 기준으로 삼되, 랜딩페이지는 대시보드와 라우팅·
  번들을 공유하지 않는 독립 앱이다.
- canvas 애니메이션은 원본 JS 로직을 React 생명주기(ref + effect)로 이관하며, 시각 결과
  동일성을 우선하고 내부 구현은 React 관용구에 맞춘다.
- 컬러/타이포/간격 토큰은 Tailwind v4 `@theme` 또는 CSS 커스텀 프로퍼티로 이관 가능하며,
  둘 중 구현상 충실도가 높은 방식을 계획 단계에서 택한다.
- 원본에 존재하나 현재 마크업에서 비활성인 요소(예: `.session-card`)는 원본 렌더 결과에
  영향이 없으면 재현 대상에서 제외한다.
