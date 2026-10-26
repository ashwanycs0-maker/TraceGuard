/**
 * Evidence Gaps and Blind Spot Radar Module (Innovation 4)
 */

const EvidenceGaps = {
  container: null,

  init() {
    this.container = document.getElementById('gapsContainer');
  },

  render(gaps) {
    if (!this.container) return;
    this.container.innerHTML = '';

    if (!gaps || gaps.length === 0) {
      this.container.innerHTML = `
        <div class="custody-card" style="text-align: center; padding: 40px;">
          <h3 class="text-green" style="margin-bottom: 8px;">✓ No Critical Evidence Gaps Detected</h3>
          <p style="color: var(--text-muted); font-size: 0.85rem;">All sequential actions across web, application, and perimeter tiers are substantiated by continuous logs.</p>
        </div>
      `;
      return;
    }

    gaps.forEach(gap => {
      const card = document.createElement('div');
      card.className = 'gap-card';

      card.innerHTML = `
        <div class="gap-card-left">
          <div class="gap-title-row">
            <span class="gap-badge-pill">${gap.severity} GAP</span>
            <div class="gap-title">${gap.title}</div>
          </div>
          <p class="gap-description">${gap.description}</p>
          <div class="gap-action-box">
            <b>Recommended Action:</b> ${gap.recommended_action}
          </div>
        </div>
        <div class="gap-card-right">
          <span class="field-label" style="margin-bottom: 4px;">Expected Evidence / Logs:</span>
          <span class="gap-expected-source">${gap.expected_log_type}</span>
          <span class="field-label" style="margin-top: 12px; margin-bottom: 4px;">Affected Explanations:</span>
          <span style="font-size: 0.76rem; color: var(--cyan);">${gap.affected_hypotheses.join(', ')}</span>
        </div>
      `;

      this.container.appendChild(card);
    });
  }
};
