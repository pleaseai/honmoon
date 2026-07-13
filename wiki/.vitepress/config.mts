import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

// Resolved citation base — repo + default branch (see Source Repository Resolution).
const REPO = 'https://github.com/pleaseai/honmoon'
const BRANCH = 'main'

export default withMermaid(
  defineConfig({
    title: 'Honmoon',
    description:
      'A policy-based firewall gateway guarding the boundary between AI agents and production systems.',
    lang: 'en-US',
    // Project site: served from https://pleaseai.github.io/honmoon/
    base: '/honmoon/',
    cleanUrls: true,
    ignoreDeadLinks: true,
    lastUpdated: true,

    // Keep agent-context files out of the rendered site.
    srcExclude: ['**/AGENTS.md', '**/CLAUDE.md', 'README.md'],

    head: [
      ['meta', { name: 'theme-color', content: '#6d5dfc' }],
      ['meta', { name: 'color-scheme', content: 'dark light' }],
    ],

    themeConfig: {
      siteTitle: 'Honmoon Wiki',

      nav: [
        { text: 'Overview', link: '/getting-started/overview' },
        { text: 'Architecture', link: '/deep-dive/architecture' },
        { text: 'Roadmap', link: '/deep-dive/roadmap-open-core' },
        { text: 'GitHub', link: REPO },
      ],

      sidebar: [
        {
          text: 'Onboarding',
          collapsed: false,
          items: [
            { text: 'Contributor Guide', link: '/onboarding/contributor-guide' },
            { text: 'Staff Engineer Guide', link: '/onboarding/staff-engineer-guide' },
            { text: 'Executive Guide', link: '/onboarding/executive-guide' },
            { text: 'Product Manager Guide', link: '/onboarding/product-manager-guide' },
          ],
        },
        {
          text: 'Getting Started',
          collapsed: false,
          items: [
            { text: 'Overview', link: '/getting-started/overview' },
            { text: 'Installation & Toolchain', link: '/getting-started/installation' },
            { text: 'Quick Start', link: '/getting-started/quick-start' },
            { text: 'Policy Authoring', link: '/getting-started/policy-authoring' },
          ],
        },
        {
          text: 'Deep Dive',
          collapsed: false,
          items: [
            { text: 'Architecture', link: '/deep-dive/architecture' },
            { text: 'Policy Model & Decision Engine', link: '/deep-dive/policy-engine' },
            { text: 'Protocol-Aware Parsing', link: '/deep-dive/protocol-parsing' },
            { text: 'Egress Gateway (Data Plane)', link: '/deep-dive/egress-gateway' },
            { text: 'Control Plane & Dashboard', link: '/deep-dive/control-plane' },
            { text: 'Roadmap & Open-Core Model', link: '/deep-dive/roadmap-open-core' },
          ],
        },
      ],

      socialLinks: [{ icon: 'github', link: REPO }],

      search: { provider: 'local' },

      editLink: {
        pattern: `${REPO}/edit/${BRANCH}/wiki/:path`,
        text: 'Edit this page on GitHub',
      },

      footer: {
        message: 'Open-core data plane · Apache-2.0 (target). Docs generated from source.',
        copyright: `${REPO}`,
      },
    },

    // Dark-mode Mermaid theme — matches the Daytona-inspired theme variables.
    mermaid: {
      theme: 'dark',
      themeVariables: {
        background: '#161b22',
        primaryColor: '#2d333b',
        primaryBorderColor: '#6d5dfc',
        primaryTextColor: '#e6edf3',
        lineColor: '#8b949e',
        secondaryColor: '#21262d',
        tertiaryColor: '#161b22',
        fontFamily: 'JetBrains Mono, ui-monospace, monospace',
      },
    },
    mermaidPlugin: {
      class: 'mermaid-zoom',
    },
  }),
)
