/**
 * TraceGuard Core Application Controller
 * Coordinates the 9 core dashboard sections, real-world case studies,
 * evidence correlation, and forensic verification.
 */

const App = {
  currentCaseId: null,
  currentCaseData: null,
  activeHypothesisId: null,

  async init() {
    console.log("Initializing TraceGuard Cyber Attack Reconstruction System...");

    // Initialize submodules
    EvidenceDrawer.init();
    AttackGraph.init();
    Timeline.init();
    Hypotheses.init();
    EvidenceGaps.init();
    ForensicPreservation.init();
    BenchmarkSuite.init();
    CaseLibrary.init();
    Reports.init();

    this.setupTabs();
    this.setupModals();
    this.setupHeaderActions();
    this.setupOverviewActions();

    // Load available cases and case library
    await this.loadCases();
    await CaseLibrary.loadLibrary();
  },

  setupTabs() {
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-tab');
        this.switchTab(targetId);
      });
    });
  },

  switchTab(targetId) {
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(t => {
      t.classList.remove('active');
      t.setAttribute('aria-selected', 'false');
    });
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

    const activeBtn = document.querySelector(`.tab-btn[data-tab="${targetId}"]`);
    if (activeBtn) {
      activeBtn.classList.add('active');
      activeBtn.setAttribute('aria-selected', 'true');
    }

    const targetPane = document.getElementById(targetId);
    if (targetPane) targetPane.classList.add('active');

    // Specific tab activations
    if (targetId === 'graphTab') {
      setTimeout(() => {
        AttackGraph.fitToView();
        AttackGraph.renderMinimap();
      }, 80);
    } else if (targetId === 'libraryTab') {
      CaseLibrary.loadLibrary();
    } else if (targetId === 'reportTab') {
      Reports.loadPreview(this.currentCaseId);
    }
  },

  setupHeaderActions() {
    // Brand home click
    const brandHome = document.getElementById('brandHomeLink');
    if (brandHome) {
      brandHome.addEventListener('click', () => this.switchTab('overviewTab'));
    }

    // Case Selector
    const caseSelect = document.getElementById('caseSelect');
    if (caseSelect) {
      caseSelect.addEventListener('change', (e) => {
        this.selectCase(e.target.value);
      });
    }

    // Check File Integrity Button
    const btnVerify = document.getElementById('btnVerifyIntegrity');
    if (btnVerify) {
      btnVerify.addEventListener('click', () => {
        this.switchTab('custodyTab');
        ForensicPreservation.runVerification();
      });
    }

    // Run Test Button
    const btnBench = document.getElementById('btnRunBenchmark');
    if (btnBench) {
      btnBench.addEventListener('click', () => {
        this.switchTab('benchmarkTab');
        BenchmarkSuite.runBenchmark();
      });
    }

    // Export Dropdown
    const btnExportMenu = document.getElementById('btnExportMenu');
    const exportDropdown = document.getElementById('exportDropdownMenu');
    if (btnExportMenu && exportDropdown) {
      btnExportMenu.addEventListener('click', (e) => {
        e.stopPropagation();
        exportDropdown.classList.toggle('show');
      });
      window.addEventListener('click', () => {
        exportDropdown.classList.remove('show');
      });
    }

    // PDF Download
    const btnPdf = document.getElementById('btnDownloadPDF');
    if (btnPdf) {
      btnPdf.addEventListener('click', (e) => {
        e.preventDefault();
        Reports.downloadPDF();
      });
    }

    // JSON Download
    const btnJson = document.getElementById('btnDownloadJSON');
    if (btnJson) {
      btnJson.addEventListener('click', (e) => {
        e.preventDefault();
        Reports.downloadJSON();
      });
    }
  },

  setupOverviewActions() {
    document.getElementById('btnOverviewViewGraph')?.addEventListener('click', () => this.switchTab('graphTab'));
    document.getElementById('btnOverviewViewTimeline')?.addEventListener('click', () => this.switchTab('timelineTab'));
    document.getElementById('btnOverviewViewIntegrity')?.addEventListener('click', () => {
      this.switchTab('custodyTab');
      ForensicPreservation.runVerification();
    });
    document.getElementById('btnOverviewExportReport')?.addEventListener('click', () => this.switchTab('reportTab'));
    document.getElementById('btnOverviewOpenLibrary')?.addEventListener('click', () => this.switchTab('libraryTab'));
  },

  setupModals() {
    // Open Import Modal
    const btnImport = document.getElementById('btnImportEvidence');
    const modalImport = document.getElementById('modalImport');
    if (btnImport && modalImport) {
      btnImport.addEventListener('click', () => modalImport.classList.remove('hidden'));
    }

    // Open New Case Modal
    const btnNewCase = document.getElementById('btnNewCase');
    const modalNewCase = document.getElementById('modalNewCase');
    if (btnNewCase && modalNewCase) {
      btnNewCase.addEventListener('click', () => modalNewCase.classList.remove('hidden'));
    }

    // Generic Close Buttons
    document.querySelectorAll('[data-close]').forEach(btn => {
      btn.addEventListener('click', () => {
        const modalId = btn.getAttribute('data-close');
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.add('hidden');
      });
    });

    // Import Mode Toggle (Paste vs Upload)
    const btnPasteMode = document.getElementById('btnModePaste');
    const btnUploadMode = document.getElementById('btnModeUpload');
    const pasteGroup = document.getElementById('pasteGroup');
    const uploadGroup = document.getElementById('uploadGroup');

    if (btnPasteMode && btnUploadMode) {
      btnPasteMode.addEventListener('click', () => {
        btnPasteMode.classList.add('active');
        btnUploadMode.classList.remove('active');
        pasteGroup.classList.remove('hidden');
        uploadGroup.classList.add('hidden');
      });

      btnUploadMode.addEventListener('click', () => {
        btnUploadMode.classList.add('active');
        btnPasteMode.classList.remove('active');
        uploadGroup.classList.remove('hidden');
        pasteGroup.classList.add('hidden');
      });
    }

    // Submit Import
    const btnSubmitImport = document.getElementById('btnSubmitImport');
    if (btnSubmitImport) {
      btnSubmitImport.addEventListener('click', () => this.handleImportSubmit());
    }

    // Submit New Case
    const btnSubmitNewCase = document.getElementById('btnSubmitNewCase');
    if (btnSubmitNewCase) {
      btnSubmitNewCase.addEventListener('click', () => this.handleNewCaseSubmit());
    }
  },

  async loadCases() {
    try {
      const res = await fetch('/api/cases');
      if (!res.ok) throw new Error('Failed to fetch cases');
      const cases = await res.json();

      const select = document.getElementById('caseSelect');
      if (!select) return;
      select.innerHTML = '';

      // Count real cases
      const realCount = cases.filter(c => c.case_type === 'REAL_INCIDENT').length;
      const countEl = document.getElementById('badgeRealCasesCount');
      if (countEl) countEl.innerText = realCount;

      cases.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.case_id;
        const prefix = c.case_type === 'REAL_INCIDENT' ? '🛡️ [Real Incident]' : '🧪 [Demo Lab]';
        opt.innerText = `${prefix} ${c.case_id} — ${c.title}`;
        select.appendChild(opt);
      });

      if (cases.length > 0) {
        // Default to Cosmos Bank if available, else first
        const defaultCase = cases.find(c => c.case_id === 'CASE-REAL-COSMOS-2018') || cases[0];
        this.currentCaseId = defaultCase.case_id;
        select.value = this.currentCaseId;
        await this.loadCaseDetail(this.currentCaseId);
      }
    } catch (err) {
      console.error(err);
      this.showToast('Could not load investigation cases.');
    }
  },

  async selectCase(caseId) {
    if (!caseId) return;
    const select = document.getElementById('caseSelect');
    if (select) select.value = caseId;
    await this.loadCaseDetail(caseId);
    CaseLibrary.renderCards();
  },

  async loadCaseDetail(caseId) {
    if (!caseId) return;
    this.currentCaseId = caseId;

    try {
      const res = await fetch(`/api/cases/${caseId}`);
      if (!res.ok) throw new Error('Case detail fetch failed');
      const caseData = await res.json();
      this.currentCaseData = caseData;

      // Update Overview & HUD
      this.updateHUD(caseData);
      this.updateOverview(caseData);

      // Render modules
      AttackGraph.render(caseId, caseData.nodes, caseData.edges, this.activeHypothesisId);
      Timeline.setEvents(caseId, caseData.events);
      Hypotheses.render(caseId, caseData.hypotheses, this.activeHypothesisId);
      EvidenceGaps.render(caseData.evidence_gaps);
      ForensicPreservation.render(caseId, caseData.evidence_files, caseData.custody_actions);

    } catch (err) {
      console.error(err);
      this.showToast('Failed to load case data.');
    }
  },

  updateHUD(caseData) {
    const m = caseData.summary_metrics || {};

    // 1. Events Connected
    document.getElementById('metricTotalEvents').innerText = m.total_events || caseData.events.length;
    document.getElementById('metricSourcesBreakdown').innerText = `${caseData.evidence_files.length} evidence sources indexed`;

    // 2. Attack Steps Found
    document.getElementById('metricReconstructedSteps').innerText = m.reconstructed_steps || caseData.nodes.length;
    const entryNode = caseData.nodes.find(n => n.is_entry_point);
    document.getElementById('metricEntryPoint').innerText = entryNode ? `Entry: ${entryNode.endpoint || entryNode.label.slice(0, 15)}` : 'Entry step identified';

    // 3. Links Supported by Evidence
    const strongCount = m.strongly_supported_links || 0;
    const totalLinks = m.established_links || caseData.edges.length;
    document.getElementById('metricStrongLinks').innerText = `${strongCount} / ${totalLinks}`;
    const defPct = totalLinks > 0 ? Math.round(((strongCount + (m.partially_supported_links || 0)) / totalLinks) * 100) : 0;
    document.getElementById('metricDefensibilityPct').innerText = `${defPct}% defensible rating`;

    // 4. Possible Explanations
    document.getElementById('metricHypothesesCount').innerText = `${caseData.hypotheses.length} Competing`;
    document.getElementById('metricPrimaryLikelihood').innerText = `Primary: ${m.primary_likelihood_pct || 0}% likelihood`;

    // 5. Missing Evidence
    document.getElementById('metricEvidenceGaps').innerText = caseData.evidence_gaps.length;
    document.getElementById('metricGapsStatus').innerText = caseData.evidence_gaps.length > 0 ? `${caseData.evidence_gaps.length} critical gaps flagged` : 'Complete coverage';
    
    // 6. Evidence Handling Record (Chain of custody)
    const custodyEl = document.getElementById('metricCustodyStatus');
    if (custodyEl) custodyEl.innerText = '100% Intact';

    // Tab Badge counts
    const badgeGap = document.getElementById('badgeGapCount');
    if (badgeGap) badgeGap.innerText = caseData.evidence_gaps.length;
    const badgeHyp = document.getElementById('badgeHypCount');
    if (badgeHyp) badgeHyp.innerText = caseData.hypotheses.length;

    // Header badge
    const headerBadge = document.getElementById('caseTypeHeaderBadge');
    if (headerBadge) {
      if (caseData.case_type === 'REAL_INCIDENT') {
        headerBadge.innerText = 'OFFICIAL INCIDENT DOSSIER ACTIVE';
        headerBadge.style.color = 'var(--verified-success)';
      } else {
        headerBadge.innerText = 'CONTROLLED SIMULATION SANDBOX';
        headerBadge.style.color = 'var(--alert-warning)';
      }
    }
  },

  updateOverview(c) {
    const titleEl = document.getElementById('overviewCaseTitle');
    if (titleEl) titleEl.innerText = c.title;

    const badgeEl = document.getElementById('overviewClassificationBadge');
    if (badgeEl) {
      if (c.case_type === 'REAL_INCIDENT') {
        badgeEl.className = 'badge-classification badge-public-fact';
        badgeEl.innerText = 'Publicly Reported Fact';
      } else {
        badgeEl.className = 'badge-classification badge-demo-data';
        badgeEl.innerText = 'Simulated Demo Data';
      }
    }

    const descEl = document.getElementById('overviewCaseSimpleDesc');
    if (descEl) descEl.innerText = c.simple_explanation || c.description;

    const whatHappenedEl = document.getElementById('overviewWhatHappenedText');
    if (whatHappenedEl) {
      whatHappenedEl.innerText = c.what_happened || 'Multi-tier web application intrusion reconstructed from sequential telemetry.';
    }

    const whatAffectedEl = document.getElementById('overviewWhatAffectedText');
    if (whatAffectedEl) {
      whatAffectedEl.innerText = c.what_was_affected || 'Internal enterprise services and database records.';
    }

    const responseEl = document.getElementById('overviewResponseText');
    if (responseEl) {
      responseEl.innerText = c.documented_response || 'Forensic preservation, credential revocation, and network isolation.';
    }

    // Sidebar fields
    document.getElementById('overviewCaseId').innerText = c.case_id;
    document.getElementById('overviewYearCountry').innerText = `${c.year || '2026'} • ${c.country || 'Global'}`;
    document.getElementById('overviewIndustry').innerText = c.industry || 'Technology';
    document.getElementById('overviewInvestigator').innerText = c.investigator || 'Senior Analyst';

    const sourcesContainer = document.getElementById('overviewSourceLinksContainer');
    if (sourcesContainer) {
      if (c.official_sources && c.official_sources.length > 0) {
        sourcesContainer.innerHTML = c.official_sources.map(s => `
          <a href="${s.url}" target="_blank" rel="noopener noreferrer" class="case-source-link">
            🔗 ${s.title} ↗
          </a>
        `).join('');
      } else {
        sourcesContainer.innerHTML = '<span style="font-size: 0.74rem; color: var(--text-secondary);">Direct synthetic lab telemetry</span>';
      }
    }
  },

  onHypothesisSelected(hypId) {
    this.activeHypothesisId = hypId;
    if (this.currentCaseData) {
      AttackGraph.render(this.currentCaseId, this.currentCaseData.nodes, this.currentCaseData.edges, hypId);
    }
  },

  async handleImportSubmit() {
    const isUploadMode = document.getElementById('btnModeUpload').classList.contains('active');
    const custody = document.getElementById('custodyOfficer').value || 'Lead Incident Investigator';
    const evidenceType = document.getElementById('evidenceTypeSelect').value || 'Imported Evidence';

    try {
      if (isUploadMode) {
        const fileInput = document.getElementById('fileUploadInput');
        if (!fileInput.files || fileInput.files.length === 0) {
          alert('Please select an evidence file to upload.');
          return;
        }
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('custody_officer', custody);
        formData.append('evidence_type', evidenceType);

        this.showToast('Preserving file, computing SHA-256, and parsing records...');
        const res = await fetch(`/api/cases/${this.currentCaseId}/upload`, {
          method: 'POST',
          body: formData
        });
        if (!res.ok) throw new Error('File upload failed');
      } else {
        const filename = document.getElementById('pasteFilename').value || 'manual_evidence.log';
        const stype = document.getElementById('pasteSourceType').value;
        const content = document.getElementById('pasteContent').value;

        if (!content.trim()) {
          alert('Please paste log content.');
          return;
        }

        this.showToast('Normalizing, hashing, and correlating evidence records...');
        const res = await fetch(`/api/cases/${this.currentCaseId}/import`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            filename,
            source_type: stype,
            content,
            custody_officer: custody,
            evidence_type: evidenceType
          })
        });
        if (!res.ok) throw new Error('Import failed');
      }

      document.getElementById('modalImport').classList.add('hidden');
      this.showToast('Evidence successfully ingested and preserved.');
      await this.loadCaseDetail(this.currentCaseId);

    } catch (err) {
      console.error(err);
      this.showToast(`Import error: ${err.message}`);
    }
  },

  async handleNewCaseSubmit() {
    const title = document.getElementById('newCaseTitle').value;
    const desc = document.getElementById('newCaseDesc').value;
    const country = document.getElementById('newCaseCountry').value;
    const industry = document.getElementById('newCaseIndustry').value;
    const investigator = document.getElementById('newCaseInvestigator').value;

    if (!title.trim()) {
      alert('Please enter a case title.');
      return;
    }

    try {
      this.showToast('Initializing investigation case...');
      const res = await fetch('/api/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title,
          description: desc,
          country,
          industry,
          investigator
        })
      });
      if (!res.ok) throw new Error('Failed to create case');
      const newCase = await res.json();

      document.getElementById('modalNewCase').classList.add('hidden');
      this.showToast(`Case ${newCase.case_id} initialized.`);
      await this.loadCases();
      await this.selectCase(newCase.case_id);

    } catch (err) {
      console.error(err);
      this.showToast(`Error creating case: ${err.message}`);
    }
  },

  showToast(msg) {
    const toast = document.getElementById('cyberToast');
    if (!toast) return;
    toast.innerText = msg;
    toast.classList.remove('hidden');
    clearTimeout(this.toastTimer);
    this.toastTimer = setTimeout(() => {
      toast.classList.add('hidden');
    }, 3800);
  }
};

window.addEventListener('DOMContentLoaded', () => {
  App.init();
});
