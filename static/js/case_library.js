/**
 * Case Library Module - Manages real-world cybersecurity incident case studies
 * (Cosmos Bank 2018, AIIMS Delhi 2022, Air India / SITA 2021, CISA Log4Shell 2022, Microsoft BlackByte 2023)
 * and controlled demonstration scenarios.
 */

const CaseLibrary = {
  currentFilter: 'ALL',
  libraryData: null,

  init() {
    this.setupFilterButtons();
  },

  setupFilterButtons() {
    const filterBtns = document.querySelectorAll('.filter-pill');
    filterBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        filterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.currentFilter = btn.getAttribute('data-filter');
        this.renderCards();
      });
    });
  },

  async loadLibrary() {
    try {
      const res = await fetch('/api/case-library');
      if (!res.ok) throw new Error('Failed to load case library');
      this.libraryData = await res.json();
      this.renderCards();
    } catch (err) {
      console.error('Case library fetch error:', err);
    }
  },

  renderCards() {
    const container = document.getElementById('caseCardsGrid');
    if (!container || !this.libraryData) return;

    let casesToShow = [];
    if (this.currentFilter === 'ALL') {
      casesToShow = [...this.libraryData.all_real_cases, ...this.libraryData.demonstration_cases];
    } else if (this.currentFilter === 'INDIA') {
      casesToShow = this.libraryData.india_incidents;
    } else if (this.currentFilter === 'WORLDWIDE') {
      casesToShow = this.libraryData.worldwide_incidents;
    } else if (this.currentFilter === 'DEMO') {
      casesToShow = this.libraryData.demonstration_cases;
    }

    container.innerHTML = '';

    if (casesToShow.length === 0) {
      container.innerHTML = `
        <div style="grid-column: 1 / -1; text-align: center; padding: 40px; color: var(--text-secondary);">
          No cases found matching this filter.
        </div>
      `;
      return;
    }

    casesToShow.forEach(c => {
      const isCurrentActive = (App.currentCaseId === c.case_id);
      const isReal = (c.case_type === 'REAL_INCIDENT');

      const card = document.createElement('div');
      card.className = `case-library-card ${isCurrentActive ? 'active-case-card' : ''}`;

      const badgeHtml = isReal
        ? `<span class="badge-classification badge-public-fact">Publicly Reported Fact</span>`
        : `<span class="badge-classification badge-demo-data">Simulated Demo Data</span>`;

      // Official sources HTML
      let sourcesHtml = '';
      if (c.official_sources && c.official_sources.length > 0) {
        sourcesHtml = c.official_sources.map(s => `
          <a href="${s.url}" target="_blank" rel="noopener noreferrer" class="case-source-link" title="${s.notes || ''}">
            🔗 ${s.title} ↗
          </a>
        `).join('');
      }

      // Attack steps list preview
      let attackStepsHtml = '';
      if (c.known_attack_steps && c.known_attack_steps.length > 0) {
        attackStepsHtml = `
          <div class="case-detail-block">
            <span class="case-detail-label">Known Attack Steps (${c.known_attack_steps.length} Documented)</span>
            <ul style="padding-left: 16px; margin-top: 4px; font-size: 0.74rem; color: var(--text-main); line-height: 1.45;">
              ${c.known_attack_steps.slice(0, 3).map(st => `<li><b>${st.phase}:</b> ${st.action.slice(0, 90)}...</li>`).join('')}
            </ul>
          </div>
        `;
      }

      // Available evidence vs missing info preview
      let evidenceSummaryHtml = '';
      if (c.available_evidence && c.available_evidence.length > 0) {
        evidenceSummaryHtml = `
          <div class="case-detail-block">
            <span class="case-detail-label">Available Evidence & Missing Information</span>
            <div style="font-size: 0.73rem; color: var(--text-secondary); line-height: 1.4;">
              <span style="color: var(--verified-success);">✓ Available:</span> ${c.available_evidence[0]}<br/>
              <span style="color: var(--alert-warning);">⚠ Missing:</span> ${c.missing_information ? c.missing_information[0] : 'Granular raw network packet captures'}
            </div>
          </div>
        `;
      }

      card.innerHTML = `
        <div>
          <div class="case-card-header">
            <div class="case-meta-tags">
              <span class="meta-tag meta-tag-country">${c.country || 'Global'}</span>
              <span class="meta-tag meta-tag-year">${c.year || '2026'}</span>
              <span class="meta-tag meta-tag-industry">${c.industry || 'Technology'}</span>
            </div>
            ${badgeHtml}
          </div>

          <h3 class="case-title">${c.title}</h3>
          <p class="case-explanation">${c.simple_explanation || 'No summary available.'}</p>

          <div class="case-detail-block">
            <span class="case-detail-label">What Happened</span>
            <p class="case-detail-val">${(c.what_happened || c.simple_explanation || '').slice(0, 160)}...</p>
          </div>

          <div class="case-detail-block">
            <span class="case-detail-label">What Was Affected</span>
            <p class="case-detail-val">${(c.what_was_affected || 'Internal enterprise infrastructure').slice(0, 120)}</p>
          </div>

          ${attackStepsHtml}
          ${evidenceSummaryHtml}

          <div style="margin-top: 10px;">
            <span class="case-detail-label">Official Source Link:</span>
            ${sourcesHtml || '<span style="font-size: 0.74rem; color: var(--text-secondary);">Direct synthetic lab demonstration</span>'}
          </div>
        </div>

        <div class="case-card-actions">
          <button class="btn-cyber ${isCurrentActive ? 'btn-secondary' : 'btn-primary'} btn-open-case" data-case-id="${c.case_id}" style="flex: 1; justify-content: center;">
            ${isCurrentActive ? '✓ Currently Active' : 'Open Case'}
          </button>
          <button class="btn-cyber btn-secondary btn-upload-for-case" data-case-id="${c.case_id}" title="Upload original logs or evidence files to this case">
            Upload Evidence
          </button>
        </div>
      `;

      // Event listeners for actions
      card.querySelector('.btn-open-case').addEventListener('click', () => {
        App.selectCase(c.case_id);
      });

      card.querySelector('.btn-upload-for-case').addEventListener('click', () => {
        App.selectCase(c.case_id);
        const modal = document.getElementById('modalImport');
        if (modal) modal.classList.remove('hidden');
      });

      container.appendChild(card);
    });
  }
};
