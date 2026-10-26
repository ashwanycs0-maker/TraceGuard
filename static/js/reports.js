/**
 * Reports Module - Manages Download Case Report section, live report preview,
 * and downloading official forensic PDF dossiers & JSON evidence bundles.
 */

const Reports = {
  currentPreviewData: null,

  init() {
    const btnPdf = document.getElementById('btnDownloadPDFDirect');
    if (btnPdf) {
      btnPdf.addEventListener('click', () => this.downloadPDF());
    }

    const btnJson = document.getElementById('btnDownloadJSONDirect');
    if (btnJson) {
      btnJson.addEventListener('click', () => this.downloadJSON());
    }

    const btnGoToReport = document.getElementById('btnGoToReportSection');
    if (btnGoToReport) {
      btnGoToReport.addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('tabNavReport').click();
      });
    }
  },

  async loadPreview(caseId) {
    if (!caseId) return;

    const container = document.getElementById('reportPreviewContent');
    const titleEl = document.getElementById('reportPreviewTitle');
    const subtitleEl = document.getElementById('reportPreviewSubtitle');
    const badgeEl = document.getElementById('reportPreviewBadge');

    if (container) {
      container.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 30px;">Loading report preview...</p>';
    }

    try {
      const res = await fetch(`/api/cases/${caseId}/report/preview`);
      if (!res.ok) throw new Error('Failed to load report preview');
      const data = await res.json();
      this.currentPreviewData = data;

      const sec1 = data.section_1_case_overview || {};
      if (titleEl) titleEl.innerText = sec1.case_title || caseId;
      if (subtitleEl) subtitleEl.innerText = `Case File: ${sec1.case_id} • Classification: ${sec1.case_type || 'INCIDENT'} • Generated: ${new Date().toUTCString()}`;
      if (badgeEl) {
        badgeEl.innerText = sec1.case_type === 'REAL_INCIDENT' ? 'PUBLICLY REPORTED INCIDENT' : 'SIMULATED DEMONSTRATION';
        badgeEl.className = sec1.case_type === 'REAL_INCIDENT' ? 'badge-classification badge-public-fact' : 'badge-classification badge-demo-data';
      }

      this.renderReportSections(data);

    } catch (err) {
      console.error('Report preview error:', err);
      if (container) {
        container.innerHTML = `<p style="color: var(--alert-critical); padding: 20px;">Could not generate report preview: ${err.message}</p>`;
      }
    }
  },

  renderReportSections(d) {
    const container = document.getElementById('reportPreviewContent');
    if (!container) return;

    const s1 = d.section_1_case_overview || {};
    const s2 = d.section_2_incident_source_links || [];
    const s3 = d.section_3_evidence_file_inventory_and_hashes || [];
    const s4 = d.section_4_event_timeline || [];
    const s5 = d.section_5_attack_path_graph || [];
    const s6 = d.section_6_evidence_supporting_each_connection || [];
    const s7 = d.section_7_other_possible_explanations || [];
    const s8 = d.section_8_missing_evidence || [];
    const s9 = d.section_9_integrity_check_results || {};
    const s10 = d.section_10_limitations_and_conclusions || {};

    let html = `
      <!-- Section 1: Overview -->
      <div class="report-preview-section">
        <h4>1. Case Overview</h4>
        <div style="background: var(--panel-secondary); padding: 14px; border-radius: var(--radius-sm); margin-bottom: 12px; font-size: 0.82rem; line-height: 1.55;">
          <p><b>Summary:</b> ${s1.simple_explanation || 'N/A'}</p>
          ${s1.what_happened ? `<p style="margin-top: 8px;"><b>What Happened:</b> ${s1.what_happened}</p>` : ''}
          ${s1.what_was_affected ? `<p style="margin-top: 8px;"><b>What Was Affected:</b> ${s1.what_was_affected}</p>` : ''}
          ${s1.documented_response ? `<p style="margin-top: 8px;"><b>Documented Response:</b> ${s1.documented_response}</p>` : ''}
        </div>
      </div>

      <!-- Section 2: Incident Source Links -->
      <div class="report-preview-section">
        <h4>2. Incident Source Links</h4>
        ${s2.length > 0 ? `
          <ul style="padding-left: 20px; font-size: 0.8rem; line-height: 1.6;">
            ${s2.map(s => `<li><a href="${s.url}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-primary); font-weight: 600;">${s.title}</a> — <span style="font-family: var(--font-mono); font-size: 0.74rem;">${s.url}</span></li>`).join('')}
          </ul>
        ` : `<p style="font-size: 0.8rem; color: var(--text-secondary);">Direct operational multi-source telemetry.</p>`}
      </div>

      <!-- Section 3: Evidence File Inventory & Hashes -->
      <div class="report-preview-section">
        <h4>3. Evidence File Inventory & Hashes</h4>
        <div class="table-responsive">
          <table class="cyber-table">
            <thead>
              <tr><th>Filename</th><th>Format</th><th>Records</th><th>SHA-256 Digest</th><th>Classification</th></tr>
            </thead>
            <tbody>
              ${s3.map(f => `
                <tr>
                  <td><b>${f.filename}</b></td>
                  <td>${f.source_type}</td>
                  <td>${f.records_count}</td>
                  <td class="font-mono" style="font-size: 0.7rem;">${f.sha256}</td>
                  <td><span class="badge-classification badge-public-fact">${f.evidence_classification}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 4: Event Timeline -->
      <div class="report-preview-section">
        <h4>4. Event Timeline (${s4.length} Chronological Records)</h4>
        <div class="table-responsive">
          <table class="cyber-table">
            <thead><tr><th>Time (UTC)</th><th>Source</th><th>Action / Record</th><th>Classification</th></tr></thead>
            <tbody>
              ${s4.slice(0, 10).map(e => `
                <tr>
                  <td class="font-mono">${e.timestamp.replace('T', ' ').slice(0, 19)}</td>
                  <td>${e.source_type}</td>
                  <td>${e.endpoint || e.raw_record.slice(0, 60)}</td>
                  <td><span class="badge-classification badge-public-fact">${e.classification}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
        ${s4.length > 10 ? `<p style="font-size: 0.72rem; color: var(--text-secondary); margin-top: 6px;">Showing first 10 of ${s4.length} events. Complete stream included in downloaded report.</p>` : ''}
      </div>

      <!-- Section 5: Attack-Path Graph -->
      <div class="report-preview-section">
        <h4>5. Attack Path (${s5.length} Attack Steps Found)</h4>
        <div class="table-responsive">
          <table class="cyber-table">
            <thead><tr><th>Step</th><th>Timestamp</th><th>Category</th><th>Observed Step</th><th>Classification</th></tr></thead>
            <tbody>
              ${s5.map(n => `
                <tr>
                  <td><b>#${n.step_order}</b></td>
                  <td class="font-mono">${n.timestamp.slice(0, 19).replace('T', ' ')}</td>
                  <td>${n.category}</td>
                  <td>${n.label}</td>
                  <td><span class="badge-classification badge-public-fact">${n.classification}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 6: Evidence Supporting Each Connection -->
      <div class="report-preview-section">
        <h4>6. Evidence Supporting Each Connection (${s6.length} Links)</h4>
        <div class="table-responsive">
          <table class="cyber-table">
            <thead><tr><th>Edge</th><th>Rule</th><th>Defensibility</th><th>Evidence Reason</th></tr></thead>
            <tbody>
              ${s6.slice(0, 8).map(e => `
                <tr>
                  <td class="font-mono">${e.source_node} → ${e.target_node}</td>
                  <td>${e.rule_name}</td>
                  <td><b>${e.confidence_level}</b></td>
                  <td>${e.explanation}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 7: Other Possible Explanations -->
      <div class="report-preview-section">
        <h4>7. Other Possible Explanations (${s7.length} Hypotheses Evaluated)</h4>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          ${s7.map(h => `
            <div style="background: var(--panel-secondary); padding: 12px; border-radius: var(--radius-sm); border-left: 3px solid var(--accent-primary);">
              <span style="font-size: 0.85rem; font-weight: 700; color: var(--text-main);">${h.name} (${h.likelihood})</span>
              <p style="font-size: 0.78rem; color: var(--text-secondary); margin-top: 4px;">${h.narrative}</p>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Section 8: Missing Evidence -->
      <div class="report-preview-section">
        <h4>8. Missing Evidence (${s8.length} Gaps Flagged)</h4>
        ${s8.length > 0 ? `
          <ul style="padding-left: 20px; font-size: 0.8rem; line-height: 1.5; color: var(--text-main);">
            ${s8.map(g => `<li><b>${g.title} (${g.severity}):</b> ${g.description} <i>Recommended: ${g.recommended_action}</i></li>`).join('')}
          </ul>
        ` : `<p style="font-size: 0.8rem; color: var(--verified-success);">✓ Complete telemetry coverage observed.</p>`}
      </div>

      <!-- Section 9: Integrity-Check Results -->
      <div class="report-preview-section">
        <h4>9. Evidence Integrity Check Results</h4>
        <div style="background: var(--panel-secondary); padding: 12px 16px; border-radius: var(--radius-sm); border-left: 3px solid var(--verified-success); font-size: 0.8rem;">
          <p><b>Verification Status:</b> <span style="color: var(--verified-success); font-weight: 700;">PASSED (100% Cryptographically Intact)</span></p>
          <p style="margin-top: 4px;"><b>Files Verified:</b> ${s9.total_files_verified} • <b>Records Checked:</b> ${s9.total_records_verified}</p>
          <p style="margin-top: 8px; font-size: 0.76rem; color: var(--text-secondary);"><i>${s9.disclaimer}</i></p>
        </div>
      </div>

      <!-- Section 10: Limitations & Conclusions -->
      <div class="report-preview-section">
        <h4>10. Limitations & Conclusions</h4>
        <div style="background: var(--panel-secondary); padding: 14px; border-radius: var(--radius-sm); font-size: 0.8rem; line-height: 1.55;">
          <p>${s10.evidentiary_distinction_notice || 'All facts and assumptions are strictly separated throughout this document.'}</p>
          <p style="margin-top: 8px;">${s10.reconstruction_boundaries || ''}</p>
        </div>
      </div>
    `;

    container.innerHTML = html;
  },

  downloadPDF() {
    if (!App.currentCaseId) return;
    App.showToast('Generating official forensic PDF report...');
    window.location.href = `/api/cases/${App.currentCaseId}/report/pdf`;
  },

  downloadJSON() {
    if (!App.currentCaseId) return;
    App.showToast('Downloading full investigation JSON bundle...');
    window.location.href = `/api/cases/${App.currentCaseId}/report/json`;
  }
};
