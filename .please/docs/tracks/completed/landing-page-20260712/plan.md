# Plan: Marketing Landing Page (apps/web)

> Track: landing-page-20260712
> Spec: [spec.md](./spec.md)

## Overview

- **Source**: /please:plan
- **Track**: landing-page-20260712
- **Issue**: #17
- **Created**: 2026-07-12
- **Approach**: 대시보드 툴체인을 미러링한 신규 `apps/web` Vite+React 앱 스캐폴드 위에,
  원본 단일 HTML의 CSS 토큰/스타일을 글로벌 스타일시트로 이관하고 마크업을 섹션 단위 React
  컴포넌트로 재구성. canvas·스크롤·클립보드 동작은 ref+effect 훅으로 이관.
- **Execution**: code
- **Planned At**: 5777da2

## Purpose

승인된 디자인 `index-v7-inspector.html`를 시각·행동적으로 그대로 재현하는 정적 마케팅
랜딩페이지를, 제품 대시보드와 동일한 스택(React 19 · Vite · Tailwind v4)의 신규 워크스페이스
앱 `apps/web`으로 구현한다. 결과물은 로컬 빌드 가능한 단일 페이지 앱이며, 배포 파이프라인은
범위 밖이다.

## Context

원본 디자인은 인라인 `<style>`(oklch `:root` 토큰 · reset · layout primitives · type ·
섹션별 스타일)과 인라인 `<script>`(멤브레인 canvas, gate-scene 스크롤 애니메이션,
IntersectionObserver 페이드인, 내비 프로스트, 스무스 스크롤, 클립보드 copy)를 담은
자기완결형 HTML이다(원본 경로는 spec.md Overview 참조). 대상 저장소는 bun 워크스페이스
모노레포이며 루트 `package.json`의 `workspaces`가 이미 `apps/*`를 포함한다. 참조 스캐폴드는
`apps/dashboard`: `@tailwindcss/vite` + `@vitejs/plugin-react` + TypeScript project references
(`tsconfig.json` → `tsconfig.app.json`/`tsconfig.node.json`), `src/main.tsx`가
`createRoot`로 마운트, `src/index.css`가 `@import "tailwindcss"`.

`apps/web`는 대시보드와 달리 API 프록시·rust-embed 임베딩이 불필요한 순수 정적 사이트이므로,
대시보드 `vite.config.ts`의 `server.proxy` 블록은 이관하지 않는다.

### Non-Goals (spec Out of Scope 재확인)

실행자가 플랜만 읽고도 범위를 재도입하지 않도록 spec의 Out-of-Scope를 명시한다: 백엔드·서버
로직·폼 제출·이메일 수집 없음; 애널리틱스/추적 스크립트 없음; 다국어/i18n 없음(영어 카피
그대로); 배포 파이프라인(CI·호스팅·도메인) 없음; 새 디자인 변형·카피 리라이팅 없음 —
`index-v7-inspector.html`이 유일한 진실의 원천이다.

### STOP Conditions

- 루트 `package.json`의 `workspaces`에 `apps/*`가 실제로 존재함을 T001에서 재확인한다.
  만약 glob이 아니라 앱을 개별 명시하는 형태라면, `apps/web`을 수동 등록해야 하므로 멈추고
  보고한다.

## Architecture Decision

**스타일링: 원본 CSS 이관(주) + Tailwind v4 상존(보조).** 원본은 Tailwind 유틸리티가 아니라
손으로 작성한 CSS(커스텀 프로퍼티·clamp 유동 타이포·복잡한 섹션 스타일)다. 이를 Tailwind
유틸리티로 번역하면 미세 차이·회귀 위험이 크고 "그대로" 기준을 해친다. 따라서 원본
`<style>`을 `src/styles/globals.css`로 **거의 원문 그대로** 이관해 최고 충실도를 확보한다.
`:root` oklch 토큰은 커스텀 프로퍼티로 유지한다(spec Assumptions의 두 옵션 중 CSS 커스텀
프로퍼티 채택 — 원본과 1:1, 번역 손실 0). Tailwind v4는 NFR-001(스택 일관성)을 위해 앱에
설치·구성하되 주 스타일링 수단으로 강제하지 않는다. 필요 시 `@theme inline`으로 토큰을
유틸리티에 노출할 수 있으나 이 트랙에서는 유틸리티 사용을 최소화한다.

**Tailwind preflight 계층 순서(충실도 보호).** Tailwind v4 preflight는 heading·button·margin·
font 등을 리셋하므로, 이관한 원본 reset과 충돌해 SC-001 충실도를 회귀시킬 수 있다. 따라서
`globals.css`에서 `@import "tailwindcss";`를 **먼저** 두고 원본 이관 스타일(reset·토큰·섹션)을
**그 뒤에** 배치해 캐스케이드에서 원본이 이긴다. 유틸리티를 거의 쓰지 않으므로 preflight를
아예 import하지 않는 선택도 가능하나(그 경우 유틸리티 비가용), 기본은 "import 후 원본이
덮어쓰기"로 하여 스택 일관성과 충실도를 모두 만족한다.

**컴포넌트 경계: 원본 섹션 = 컴포넌트.** 원본의 각 `<section data-od-id>`/`<header>`/
`<footer>`를 `src/sections/*.tsx` 컴포넌트 1:1로 매핑하고 `App.tsx`가 원본 순서대로 조립한다.
카피·마크업 구조·클래스명은 원본을 보존해 글로벌 CSS 셀렉터가 그대로 적용되게 한다.

**동적 동작: 명령형 로직을 훅으로 캡슐화.** 각 인터랙션의 원본 JS를 React 관용구로 이관한다.
멤브레인 canvas는 `useMembrane`(canvas ref + `requestAnimationFrame` 루프 + `pointermove`
+ `matchMedia('(prefers-reduced-motion: reduce)')` 분기 + resize 처리 + cleanup),
gate-scene는 `useGateScene`(scroll rAF 스로틀), 페이드인은 `useReveal`(IntersectionObserver),
내비 프로스트는 `useScrollFlag`, 스무스 스크롤·클립보드 copy는 핸들러로. 시각 결과 동일성을
우선하고 내부 구조만 React 생명주기에 맞춘다. 모든 훅은 effect cleanup으로 리스너·rAF를 해제한다.

## Architecture Diagram

```
apps/web/
├─ package.json                 # @honmoon/web, scripts: dev/build/typecheck/preview
├─ vite.config.ts               # react() + tailwindcss(), no proxy
├─ tsconfig.json / .app / .node # project refs (dashboard mirror)
├─ index.html                   # #root + main.tsx
└─ src/
   ├─ main.tsx                  # createRoot → <App/>
   ├─ App.tsx                   # 원본 순서로 섹션 조립 + skip-link
   ├─ styles/globals.css        # 원본 <style> 이관 (tokens·reset·sections)
   ├─ hooks/                    # useMembrane, useGateScene, useReveal, useScrollFlag
   └─ sections/                 # TopNav, Hero, Membrane(canvas), Barrier,
                                #   Threat, HowItWorks, Policy, Modes, OpenCore, Cta, Footer
```

## Tasks

- [x] T001 `apps/web` 스캐폴드 생성 — package.json(@honmoon/web) · vite.config.ts(react+tailwind, proxy 없음) · tsconfig 3종 · index.html · src/main.tsx · 빈 App.tsx · src/styles/globals.css(`@import "tailwindcss";` 스텁) (files: apps/web/package.json, apps/web/vite.config.ts, apps/web/tsconfig.json, apps/web/tsconfig.app.json, apps/web/tsconfig.node.json, apps/web/index.html, apps/web/src/main.tsx, apps/web/src/App.tsx, apps/web/src/styles/globals.css)
  STOP: 루트 package.json workspaces가 `apps/*` glob이 아니면 `apps/web` 자동 편입이 안 되므로 멈추고 보고한다.
- [x] T002 원본 디자인 토큰·전역 스타일 이관 — 원본 `<style>`의 `:root` oklch 토큰·reset·layout primitives·type·chrome 등 전역 스타일을 globals.css로 원문 이관, `@import "tailwindcss";`를 파일 최상단에 두고 원본 스타일을 그 뒤에 배치(preflight를 원본 reset이 덮어쓰도록). AC-003(토큰·타이포·간격 재현) 검증 기준점. (file: apps/web/src/styles/globals.css) (depends on T001)
- [x] T003 [P] TopNav 섹션 + 내비 프로스트/스무스 스크롤 — 로고·nav·GitHub 아이콘·Get started 버튼, `useScrollFlag`로 scrollY>24 시 `.scrolled` 토글. TopNav의 "Get started" 버튼 → #policy 스무스 스크롤. #policy 스크롤은 공용 앵커 핸들러(예: 작은 `scrollToPolicy` 유틸)로 두어 Hero의 "See the policy engine"(T004 소유)이 재사용하게 한다 — 로직 중복 금지. (files: apps/web/src/sections/TopNav.tsx, apps/web/src/hooks/useScrollFlag.ts) (depends on T002)
- [x] T004 [P] Hero 섹션 — eyebrow·h1·lead·CTA 2종. "See the policy engine"는 T003의 공용 #policy 앵커 핸들러 재사용(내부 스크롤), "GitHub ↗"는 외부 링크. 카피는 원본 문자 그대로(AC-002). (file: apps/web/src/sections/Hero.tsx) (depends on T002)
- [x] T005 [P] Membrane 배경 canvas — 전체화면 **고정(fixed) 레이어**로 렌더(콘텐츠 뒤 배경, in-flow 섹션 박스 아님), `useMembrane` 훅(rAF 루프·pointermove 반응·resize·cleanup). reduced-motion 시: 원본과 동일하게 `draw(0)` 정적 프레임 1회 + `scroll → draw(0)` 재드로우 리스너를 유지해 배경이 스크롤에 따라 갱신되게 한다(단순 정지 아님). 원본의 미사용 경로(`.session-card` 콘솔, 미호출 `emitHero`/hero-particle)는 이관하지 않는다 — 대시보드 strict tsconfig(noUnusedLocals/Parameters)에서 dead code는 빌드 실패. (files: apps/web/src/sections/Membrane.tsx, apps/web/src/hooks/useMembrane.ts) (depends on T002)
  STOP: 원본 canvas 로직을 React로 옮길 때 시각 결과가 원본과 눈에 띄게 달라지면(파문·튕김·흡수 거동 상실) 즉흥 재작성하지 말고 멈추고 보고한다.
- [x] T006 [P] Barrier 섹션 + gate-scene 스크롤 애니메이션 — 5개 요청 행(allow·mask·deny·deny·pause)의 요청자·명령·verdict·rule·result 원본 카피(AC-002), `useGateScene`로 스크롤 구동 판정 애니메이션. reduced-motion 분기를 이 훅에 개별 이관(원본대로 판정 진행도를 최종 상태로 고정하고 scroll 리스너 미등록) — 전역 처리에 의존하지 말 것. (files: apps/web/src/sections/Barrier.tsx, apps/web/src/hooks/useGateScene.ts) (depends on T002)
- [x] T007 [P] Threat·HowItWorks 섹션 — 위험 명령 밴드, 2-layer flow 다이어그램 + facts-strip (files: apps/web/src/sections/Threat.tsx, apps/web/src/sections/HowItWorks.tsx) (depends on T002)
- [x] T008 [P] Policy 섹션 + CEL YAML 코드 카드 + Copy — verdict 목록(allow/deny/pause), agent.yaml 정책 예시(CEL 표현식 포함 YAML) 구문 강조, Copy 버튼 → `navigator.clipboard`로 정책 전문 복사 (file: apps/web/src/sections/Policy.tsx) (depends on T002)
- [x] T009 [P] Modes·OpenCore 섹션 — honmoon run/gateway/join 3개 모드 행, OSS core(Apache-2.0) vs Team&Cloud 2패널 (files: apps/web/src/sections/Modes.tsx, apps/web/src/sections/OpenCore.tsx) (depends on T002)
- [x] T010 [P] Cta·Footer 섹션 — 최종 CTA(Get started on GitHub·Docs ↗), 푸터 브랜드 + Product/Resources 컬럼(GitHub·Docs·Readme 정확한 대상 URL) (files: apps/web/src/sections/Cta.tsx, apps/web/src/sections/Footer.tsx) (depends on T002)
- [x] T011 App 조립 + 페이드인 + 접근성 — App.tsx가 skip-link + Membrane + 모든 섹션을 원본 순서로 조립(AC-001), 섹션 aria-label(AC-015), 카피 원본 그대로(AC-002). `useReveal`(IntersectionObserver 페이드인, AC-007): 원본은 `.lp` 숨김 초기상태를 `<html>`에 `od-js` 클래스를 **동기적으로** 부여해 활성화한 뒤 IO로 `.in`을 추가한다. 이 `od-js` 부여를 post-paint useEffect에 넣으면 above-fold `.lp` 섹션이 보임→숨김→페이드로 깜빡인다(FOUC). 따라서 `od-js`는 index.html 인라인 스크립트 또는 모듈 최상위에서 동기 부여하고, useReveal은 관찰/`.in` 부여만 담당한다. reduced-motion 시 useReveal은 관찰을 건너뛰고 섹션을 정적 표시(개별 분기). (files: apps/web/index.html, apps/web/src/App.tsx, apps/web/src/hooks/useReveal.ts) (depends on T003, T004, T005, T006, T007, T008, T009, T010)
- [x] T012 충실도·반응형·링크 검증 패스 — 원본과 나란히 대조(10개 영역 순서·카피·레이아웃), 7개 인터랙션 동작, 920px 이하 재배치, reduced-motion 정지, 모든 외부 링크 대상 URL 확인, `bun run build`·`typecheck` 통과 (file: apps/web/src/App.tsx) (depends on T011)

## Dependencies

```
T001 → T002 → { T003, T004, T005, T006, T007, T008, T009, T010 } [P] → T011 → T012
```

T003–T010은 T002(전역 CSS·토큰) 완료 후 서로 독립이므로 병렬 실행 가능하다. T011은 모든
섹션 컴포넌트를 조립하므로 이들 전부에 의존한다. T012는 전체 통합 검증이므로 마지막이다.

## Key Files

| 파일 | 역할 |
|------|------|
| `apps/web/package.json` | `@honmoon/web` 워크스페이스 앱 매니페스트 (신규) |
| `apps/web/vite.config.ts` | Vite 구성 — react + tailwindcss 플러그인 (신규) |
| `apps/web/src/main.tsx` | React 진입점, `createRoot` (신규) |
| `apps/web/src/App.tsx` | 섹션 조립 + skip-link + 페이드인 관찰자 (신규) |
| `apps/web/src/styles/globals.css` | 원본 `<style>` 이관 — 토큰·reset·섹션 스타일 (신규) |
| `apps/web/src/hooks/useMembrane.ts` | 멤브레인 canvas rAF 루프 (신규) |
| `apps/web/src/sections/*.tsx` | 섹션별 컴포넌트 10+개 (신규) |
| `apps/dashboard/vite.config.ts` | 미러링 참조 (읽기 전용, 미수정) |
| 원본 `index-v7-inspector.html` | 마크업·CSS·JS 진실의 원천 (읽기 전용) |

## Verification

- `cd apps/web && bun run build` 성공, `bun run typecheck` 무오류(dashboard와 동일한 strict
  옵션: noUnusedLocals/Parameters).
- `bun run dev`로 로컬 구동 후 원본 HTML을 나란히 열어 육안 대조(SC-001).
- 7개 인터랙션 수동 확인(SC-002), 모든 외부 링크 대상 URL 확인(SC-003), reduced-motion·
  920px 반응형 확인(SC-004).
- 루트에서 `bun run --filter @honmoon/web build`가 워크스페이스로 인식·실행되는지 확인(FR-001).

## Test Scenarios

### T001
- Happy: `bun install` 후 `cd apps/web && bun run dev` → Vite 개발 서버가 빈 `#root`로 기동.
- Integration: 루트에서 `bun run --filter @honmoon/web typecheck` → `@honmoon/web`이 워크스페이스로 해석되어 실행.

### T002
- Happy: globals.css 이관 후 개발 서버에서 body 배경이 원본 다크(oklch --bg)로 렌더, 콘솔 CSS 파싱 오류 없음.
- Edge: `:root` 커스텀 프로퍼티(--accent 등)가 DevTools computed style에 원본과 동일 값으로 노출.

### T003
- Happy: 상단 로고·nav 링크·GitHub 아이콘·Get started 버튼이 원본 레이아웃으로 렌더.
- Action: 페이지를 24px 초과 스크롤 → topnav에 backdrop-blur 프로스트 배경 적용(AC-008).
- Action: Get started / See the policy engine 클릭 → #policy로 스무스 스크롤(AC-009).

### T004
- Happy: eyebrow·h1(2줄)·lead·CTA 2종이 원본 카피 그대로 렌더.
- Action: "GitHub ↗" → 새 탭 `github.com/pleaseai/honmoon`(AC-011). "See the policy engine" → #policy 스크롤.

### T005
- Happy: 전체화면 고정 배경에 멤브레인 애니메이션이 rAF로 지속 렌더(AC-004).
- Action: 포인터 이동 → 멤브레인이 포인터 위치에 반응(AC-005).
- Edge: `prefers-reduced-motion: reduce` → 애니메이션 정지·정적 프레임 표시(AC-014). 리마운트/언마운트 시 rAF·리스너 누수 없음(cleanup).

### T006
- Happy: 5개 요청 행이 요청자·명령·verdict chip·rule·result 원본 카피로 렌더(FR-003).
- Action: barrier 섹션 스크롤 → 토큰이 게이트 통과·판정되는 애니메이션 진행(AC-006).
- Edge: reduced-motion 시 정적 상태.

### T007
- Happy: Threat 위험 명령 밴드(DROP TABLE users 등), HowItWorks Source→L1→L2→Destination flow + facts-strip이 원본대로 렌더.

### T008
- Happy: verdict 목록·agent.yaml 코드 카드가 구문 강조와 함께 원본대로 렌더(FR-004).
- Action: Copy 버튼 클릭 → 클립보드에 정책 전문(CEL 포함 YAML) 복사됨(AC-010).
- Error: `navigator.clipboard` 미지원/거부 시 예외가 페이지를 깨뜨리지 않음.

### T009
- Happy: 3개 모드 행(run/gateway/join)과 OSS core vs Team&Cloud 2패널이 원본 카피·레이아웃으로 렌더.

### T010
- Happy: 최종 CTA와 푸터 컬럼이 원본대로 렌더.
- Action: Docs ↗ → `github.com/pleaseai/honmoon/tree/main/docs`(AC-012), Readme → `.../blob/main/README.md`(AC-012b), GitHub → repo(AC-011), 모두 새 탭.

### T011
- Happy: 10개 영역이 원본 순서로 조립(AC-001), skip-link가 첫 Tab에 노출되고 #content로 이동(AC-015).
- Action: 각 `.lp` 섹션이 뷰포트 진입 시 페이드인(AC-007).
- Edge: reduced-motion 시 페이드/스크롤/멤브레인 모두 정지(AC-014).

### T012
- Happy: 원본 대조 시 10개 영역 순서·카피·레이아웃 불일치 0건(SC-001), 7개 인터랙션 재현(SC-002).
- Edge: 뷰포트 920px 이하에서 grid-2가 단일 컬럼으로 재배치, 가로 스크롤 없음(AC-013, SC-004).
- Integration: `bun run build`·`typecheck` 통과, 모든 외부 링크 대상 URL 원본과 일치(SC-003).

## Progress

- 2026-07-12: T001–T012 완료 (Inline 전략 — apps/web는 신규 앱으로 테스트 프레임워크가
  없고 태스크가 시각 충실도 작업이라 implement-executor 대신 메인 세션이 직접 구현).
  - 스캐폴드(apps/web, React19+Vite8+Tailwind v4, tsconfig 3종) + 원본 CSS 512행을
    globals.css로 원문 이관(`.session-card` 비활성 블록 제외) + 11개 섹션 컴포넌트 +
    4개 훅(useMembrane/useGateScene/useReveal/useScrollFlag) + scrollToPolicy 유틸.
  - 검증: `bun run typecheck` 무오류, `bun run build` 성공(CSS 29KB·JS 217KB gzip 67KB),
    `eslint apps/web` 0 errors. 브라우저 렌더 대조: 10개 영역 순서·카피·레이아웃 원본 일치,
    7개 인터랙션(멤브레인+포인터·barrier 스크럽·페이드인·내비 프로스트·CTA 스크롤·정책 copy)
    동작, 콘솔 오류 0.
  - 결정 반영: Tailwind preflight를 globals 상단 import 후 원본 reset이 덮어씀, FOUC 방지
    `od-js` 동기 부여(index.html), per-hook reduced-motion 분기, dead code 미이관.
- 2026-07-12: 코드 리뷰(high, 8-angle) — 정확성 버그 0건, 충실도 회귀 0건. cleanup 3건 중
  링크 상수 중앙화(lib/links.ts) + reduced-motion 헬퍼(lib/prefersReducedMotion.ts) 적용
  (SHA: `e46781c`). useMembrane 파티클 타입화는 충실 이관 맥락상 known-minor로 보류.

## Decision Log

- 2026-07-12: 스타일링은 원본 CSS 이관(주) + Tailwind v4 상존(보조)으로 결정 — 유틸리티 번역
  시 미세 회귀 위험이 "그대로" 기준과 충돌하기 때문. 토큰은 CSS 커스텀 프로퍼티로 유지(원본
  1:1). Tailwind는 NFR-001 스택 일관성 위해 설치·구성만.
- 2026-07-12: `apps/web`는 정적 사이트이므로 대시보드 vite.config의 `server.proxy`·rust-embed
  관련 구성을 이관하지 않음.
- 2026-07-12 (플랜 리뷰): Tailwind preflight를 globals.css 최상단 import 후 원본 스타일이
  덮어쓰도록 계층 순서 확정 — preflight reset이 원본 reset과 충돌해 SC-001 충실도를 회귀시키는
  것을 방지.
- 2026-07-12 (플랜 리뷰): 페이드인 `od-js` 클래스는 동기 부여(FOUC 방지), reduced-motion
  분기는 useMembrane·useGateScene·useReveal 각 훅에 개별 이관, 멤브레인 정적 경로는
  `scroll→draw(0)` 유지, 원본 dead code(`.session-card`·`emitHero`)는 strict tsconfig 대비
  미이관 — feasibility 리뷰의 구현 gotcha를 태스크에 반영.

## Surprises & Discoveries

- 저장소 기본 브랜치가 `master`→`main`으로 마이그레이션되어 원격 `master`가 삭제된 상태.
  PR base를 `main`으로 지정해야 했다.
- Graphite가 저장소와 미동기화되어 `gt submit`이 실패 — `gh`로 브랜치 push + PR 생성/ready로 폴백.
- antfu eslint 설정의 `jsx-one-expression-per-line` auto-fix가 인라인 텍스트 주변 공백을
  깨뜨릴 수 있어, 밀집 마크업 충실 이관을 위해 `apps/web`에 한해 규칙 완화.

## Outcomes & Retrospective

### What Was Shipped
승인된 디자인을 신규 `apps/web`(React 19·Vite 8·Tailwind v4)으로 충실 재현한 정적 마케팅
랜딩페이지. 11개 섹션 컴포넌트 + 4개 인터랙션 훅 + 원문 이관 글로벌 CSS. 12/12 태스크 완료.

### What Went Well
- 원본 CSS·canvas 로직을 거의 원문 그대로 이관해 충실도 확보(브라우저 대조 불일치 0, 리뷰
  충실도 회귀 0). typecheck·build·eslint 모두 green, 정확성 버그 0.
- spec/plan 리뷰 게이트가 실질 가치를 냄: FOUC 동기 게이팅·per-hook reduced-motion·dead
  code 제외·Tailwind preflight 계층 등 구현 gotcha를 계획 단계에서 태스크에 반영.

### What Could Improve
- 프론트엔드 시각 충실도 트랙에 자동 테스트 프레임워크가 없어 검증이 브라우저 육안 대조에
  의존. 회귀 방지를 위한 스냅샷/DOM-diff 테스트는 별도 트랙으로 고려 가능.

### Tech Debt Created
- `useMembrane`의 파티클 모델이 `any[]`로 untyped — 향후 편집 시 오타가 런타임 침묵 버그가
  될 수 있음(리뷰 known-minor). `Particle`/`Ripple` 인터페이스 도입은 후속 정리 항목.
