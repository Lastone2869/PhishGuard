# Workspace Engineering Guidelines: Superpowers + Ponytail + UI/UX Pro Max

This workspace integrates three complementary engineering methodologies:
1. **Superpowers**: Structured development process (Brainstorming → Planning → TDD → Subagent execution → Verification).
2. **Ponytail**: Lazy Senior Dev mindset (Smallest complete change, zero bloat, YAGNI, native primitives, robust edge-case tests).
3. **UI/UX Pro Max**: Design intelligence engine (Searchable styles, accessible palettes, typography, UI guidelines via `.agents/skills/ui-ux-pro-max/scripts/search.py`).

---

## 1. Process & Development Discipline (Superpowers)

- **Always check skills first**: Before taking action or writing code, check and invoke the applicable skill from `.agents/skills/`.
- **Brainstorming before planning**: When designing or building a new feature or component, clarify requirements and tease out the specification in readable chunks.
- **Strict TDD (Test-Driven Development)**:
  - Write a failing test first (Red).
  - Write the minimal code to pass (Green).
  - Refactor cleanly.
- **Verification before completion**: Never declare a task complete without running and verifying test suites and linting.
- **Systematic Debugging**: Reproduce bugs with a test first; never guess or make speculative fixes.

---

## 2. Code Philosophy (Ponytail: Lazy Senior Dev Mode)

- **Smallest Complete Change**: The best code is the code never written. Solve the whole problem with the least new code.
- **Check Existing First**:
  1. Already in this codebase (helper, component, pattern)? Reuse it.
  2. Standard library / platform feature? Use it.
  3. Installed dependency? Use it. Never add a new dependency for a few lines.
  4. One line that reads at a glance beats multi-line abstraction.
- **No Over-Engineering**: No speculative wrappers, premature abstractions, or "for later" configuration.
- **Non-Negotiable Quality**: Never cut input validation at boundaries, error handling that prevents crashes/data loss, security, or accessibility.
- **Self-Checking**: Every non-trivial logic branch ships with a test or an assert-based check.

---

## 3. Design & Interface Intelligence (UI/UX Pro Max)

- Whenever designing or refining UI layouts, colors, typography, or interaction components:
  - Run the design search CLI:
    ```bash
    python .agents/skills/ui-ux-pro-max/scripts/search.py "<query>" --domain <domain>
    ```
    Available domains: `style`, `color`, `typography`, `ux`, `chart`, `icons`, `gsap`, `web`.
  - For full stack guidance:
    ```bash
    python .agents/skills/ui-ux-pro-max/scripts/search.py "<query>" --stack <stack>
    ```
  - For system-wide visual directions:
    ```bash
    python .agents/skills/ui-ux-pro-max/scripts/search.py "<query>" --design-system
    ```
- **Accessibility & UX Priorities**:
  - Contrast minimum 4.5:1 (WCAG AA).
  - Touch targets minimum 44×44px with 8px+ spacing.
  - Visible focus rings and proper keyboard navigation.
  - Zero layout shift (CLS < 0.1).
