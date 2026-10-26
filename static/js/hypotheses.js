/**
 * Competing Hypotheses Module (Innovation 3)
 */

const Hypotheses = {
  grid: null,
  ribbon: null,
  caseId: null,
  hypotheses: [],
  activeHypothesisId: null,

  init() {
    this.grid = document.getElementById('hypothesesGrid');
    this.ribbon = document.getElementById('hypothesisButtonsContainer');
  },

  render(caseId, hypotheses, activeId = null) {
    this.caseId = caseId;
    this.hypotheses = hypotheses || [];
    this.activeHypothesisId = activeId || (this.hypotheses[0]?.hypothesis_id || null);

    this.renderRibbon();
    this.renderGrid();
  },

  renderRibbon() {
    if (!this.ribbon) return;
    this.ribbon.innerHTML = '';

    // "All Evidence" button
    const allBtn = document.createElement('button');
    allBtn.className = `btn-toggle ${!this.activeHypothesisId || this.activeHypothesisId === 'ALL' ? 'active' : ''}`;
    allBtn.innerText = 'Full Attack Path';
    allBtn.addEventListener('click', () => this.selectHypothesis('ALL'));
    this.ribbon.appendChild(allBtn);

    this.hypotheses.forEach((hyp, idx) => {
      const btn = document.createElement('button');
      btn.className = `btn-toggle ${this.activeHypothesisId === hyp.hypothesis_id ? 'active' : ''}`;
      const pct = Math.round(hyp.likelihood_score * 100);
      btn.innerText = `${hyp.name.split(':')[0]} (${pct}%)`;
      btn.addEventListener('click', () => this.selectHypothesis(hyp.hypothesis_id));
      this.ribbon.appendChild(btn);
    });
  },

  renderGrid() {
    if (!this.grid) return;
    this.grid.innerHTML = '';

    this.hypotheses.forEach(hyp => {
      const card = document.createElement('div');
      const isActive = (this.activeHypothesisId === hyp.hypothesis_id);
      card.className = `hypothesis-card ${isActive ? 'active-hypothesis' : ''}`;

      const pct = Math.round(hyp.likelihood_score * 100);
      let likeBadgeClass = 'badge-low-like';
      if (pct >= 75) likeBadgeClass = 'badge-high-like';
      else if (pct >= 50) likeBadgeClass = 'badge-med-like';

      let chainHtml = '';
      if (hyp.mitre_attack_chain && hyp.mitre_attack_chain.length > 0) {
        chainHtml = hyp.mitre_attack_chain.map(t => `<span class="indicator-chip">${t}</span>`).join(' ');
      }

      card.innerHTML = `
        <div class="hyp-header">
          <div class="hyp-title">${hyp.name}</div>
          <span class="hyp-likelihood-badge ${likeBadgeClass}">${pct}% Confidence</span>
        </div>
        <p class="hyp-narrative">${hyp.narrative}</p>
        <div class="hyp-differentiator">
          <b>Key Distinguishing Evidence:</b> ${hyp.key_differentiator}
        </div>
        <div>
          <span class="field-label" style="display:block; margin-bottom: 6px;">Attack Chain:</span>
          <div>${chainHtml}</div>
        </div>
        <div class="hyp-stats-row">
          <div>
            <div class="hyp-stat-val text-green">${hyp.supporting_evidence_count}</div>
            <div class="hyp-stat-lbl">Evidence Links</div>
          </div>
          <div>
            <div class="hyp-stat-val text-amber">${hyp.speculative_links_count}</div>
            <div class="hyp-stat-lbl">Possible Links</div>
          </div>
          <div>
            <div class="hyp-stat-val text-red">${hyp.evidence_gaps_count}</div>
            <div class="hyp-stat-lbl">Missing Evidence</div>
          </div>
        </div>
        <button class="btn-cyber ${isActive ? 'btn-primary' : 'btn-secondary'}" style="width: 100%; justify-content: center;">
          ${isActive ? '✓ Active Explanation' : 'Focus on this Explanation'}
        </button>
      `;

      card.querySelector('button').addEventListener('click', () => {
        this.selectHypothesis(hyp.hypothesis_id);
      });

      this.grid.appendChild(card);
    });
  },

  selectHypothesis(hypId) {
    this.activeHypothesisId = hypId;
    this.renderRibbon();
    this.renderGrid();
    App.onHypothesisSelected(hypId);
  }
};
