/**
 * Evidence Drawer Module - Handles event and correlation link inspection
 * Displays event time, source IP and destination, HTTP method and endpoint,
 * user or session identifier, event type and severity, original evidence file and line/record number,
 * reason for connecting, confidence or uncertainty, and clear distinction between facts and assumptions.
 */

const EvidenceDrawer = {
  drawer: null,
  backdrop: null,

  init() {
    this.drawer = document.getElementById('evidenceDrawer');
    this.backdrop = document.getElementById('drawerBackdrop');

    const btnClose = document.getElementById('btnCloseDrawer');
    if (btnClose) {
      btnClose.addEventListener('click', () => this.close());
    }

    if (this.backdrop) {
      this.backdrop.addEventListener('click', () => this.close());
    }

    const btnCopy = document.getElementById('btnCopyRawLog');
    if (btnCopy) {
      btnCopy.addEventListener('click', () => {
        const rawText = document.getElementById('drawerRawLog').innerText;
        navigator.clipboard.writeText(rawText).then(() => {
          App.showToast('Verbatim record copied to clipboard');
        });
      });
    }
  },

  async inspectEvent(caseId, eventId) {
    if (!caseId || !eventId) return;

    this.open();
    document.getElementById('drawerTitle').innerText = 'Loading evidence record...';
    document.getElementById('drawerRawLog').innerText = 'Fetching raw cryptographic record...';

    try {
      const res = await fetch(`/api/cases/${caseId}/evidence/${eventId}`);
      if (!res.ok) throw new Error('Evidence fetch failed');
      const data = await res.json();

      const classification = data.evidence_classification || 'Imported Evidence';
      let badgeClass = 'badge-imported-evidence';
      if (classification === 'Publicly Reported Fact') badgeClass = 'badge-public-fact';
      else if (classification === 'Simulated Demo Data') badgeClass = 'badge-demo-data';
      else if (classification === 'Analyst\'s Interpretation') badgeClass = 'badge-analyst-interp';
      else if (classification === 'Unverified Information') badgeClass = 'badge-unverified';

      const drawerBadge = document.getElementById('drawerBadge');
      drawerBadge.innerText = `${classification.toUpperCase()}`;
      drawerBadge.className = `badge-classification ${badgeClass}`;

      document.getElementById('drawerTitle').innerText = `${data.extracted_fields.http_method || data.source_type.toUpperCase()} ${data.extracted_fields.endpoint || ''}`;
      
      // Proof Card
      document.getElementById('drawerHash').innerText = data.raw_hash;
      document.getElementById('drawerSourceFile').innerText = data.source_file;
      document.getElementById('drawerLineOffset').innerText = `Record / Line ${data.line_number} (Offset: ${data.byte_offset || 0})`;
      
      const tamperEl = document.getElementById('drawerTamperStatus');
      if (data.is_tamper_free) {
        tamperEl.innerText = 'VERIFIED UNTOUCHED (SHA-256 MATCH)';
        tamperEl.className = 'proof-val badge-verified';
      } else {
        tamperEl.innerText = 'TAMPER DETECTED';
        tamperEl.className = 'proof-val text-red';
      }

      // Verbatim Record
      document.getElementById('drawerRawLog').innerText = data.raw_record;

      // Extracted Fields Grid
      const grid = document.getElementById('drawerFieldsGrid');
      grid.innerHTML = '';

      const fields = [
        { label: 'Event Classification', val: classification },
        { label: 'Timestamp (UTC)', val: data.timestamp },
        { label: 'Source IP', val: data.extracted_fields.source_ip || 'Internal / Not Recorded' },
        { label: 'Destination', val: data.extracted_fields.dest_ip || 'Internal System' },
        { label: 'Status Code', val: data.extracted_fields.status_code || 'N/A' },
        { label: 'Session ID', val: data.extracted_fields.session_id || 'None' },
        { label: 'Request Trace ID', val: data.extracted_fields.request_id || 'None' },
        { label: 'User / Account', val: data.extracted_fields.user || 'None' },
        { label: 'HTTP Method', val: data.extracted_fields.http_method || 'N/A' },
        { label: 'Endpoint / Target', val: data.extracted_fields.endpoint || '/' },
        { label: 'Event Category', val: data.extracted_fields.event_category },
        { label: 'Severity Level', val: data.extracted_fields.severity },
      ];

      fields.forEach(f => {
        if (f.val !== undefined && f.val !== null && f.val !== '') {
          const item = document.createElement('div');
          item.className = 'field-item';
          item.innerHTML = `
            <span class="field-label">${f.label}</span>
            <span class="field-value">${f.val}</span>
          `;
          grid.appendChild(item);
        }
      });

      // Source Citation link if real report
      if (data.factual_source_url) {
        const item = document.createElement('div');
        item.className = 'field-item';
        item.style.gridColumn = '1 / -1';
        item.innerHTML = `
          <span class="field-label">Official Source Citation</span>
          <span class="field-value">
            <a href="${data.factual_source_url}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-primary); font-weight: 600; text-decoration: underline;">
              ${data.source_citation || data.factual_source_url} ↗
            </a>
          </span>
        `;
        grid.appendChild(item);
      }

      // Indicators & MITRE
      if (data.extracted_fields.attack_indicators && data.extracted_fields.attack_indicators.length > 0) {
        const item = document.createElement('div');
        item.className = 'field-item';
        item.style.gridColumn = '1 / -1';
        item.innerHTML = `
          <span class="field-label">Threat Indicators</span>
          <span class="field-value text-red">${data.extracted_fields.attack_indicators.join(', ')}</span>
        `;
        grid.appendChild(item);
      }

      if (data.extracted_fields.mitre_techniques && data.extracted_fields.mitre_techniques.length > 0) {
        const item = document.createElement('div');
        item.className = 'field-item';
        item.style.gridColumn = '1 / -1';
        item.innerHTML = `
          <span class="field-label">MITRE ATT&CK Technique</span>
          <span class="field-value text-cyan">${data.extracted_fields.mitre_techniques.join(', ')}</span>
        `;
        grid.appendChild(item);
      }

      // Hide correlation section for simple event inspection
      document.getElementById('drawerCorrelationSection').classList.add('hidden');

    } catch (err) {
      console.error(err);
      document.getElementById('drawerTitle').innerText = 'Error loading evidence';
      document.getElementById('drawerRawLog').innerText = 'Could not load record proof.';
    }
  },

  inspectEdge(caseId, edge) {
    if (!edge) return;
    this.open();

    const drawerBadge = document.getElementById('drawerBadge');
    drawerBadge.innerText = 'CORRELATION EVIDENCE LINK';
    drawerBadge.className = 'badge-classification badge-analyst-interp';

    document.getElementById('drawerTitle').innerText = `${edge.rule_name.replace(/_/g, ' ')}`;

    // Proof Card
    document.getElementById('drawerHash').innerText = `Edge ID: ${edge.edge_id}`;
    document.getElementById('drawerSourceFile').innerText = `Connection: ${edge.source_event_id} ➔ ${edge.target_event_id}`;
    document.getElementById('drawerLineOffset').innerText = `Time Delta: ${edge.time_delta_seconds.toFixed(2)}s`;
    
    const tamperEl = document.getElementById('drawerTamperStatus');
    const isStrong = edge.confidence_level === 'STRONGLY_SUPPORTED';
    const isPartial = edge.confidence_level === 'PARTIALLY_SUPPORTED';

    tamperEl.innerText = `${edge.confidence_level.replace(/_/g, ' ')} (${Math.round(edge.confidence_score * 100)}% Confidence)`;
    tamperEl.className = isStrong ? 'proof-val badge-verified' : (isPartial ? 'proof-val text-amber' : 'proof-val text-purple');

    // Raw correlation details
    document.getElementById('drawerRawLog').innerText = JSON.stringify({
      edge_id: edge.edge_id,
      source_event_id: edge.source_event_id,
      target_event_id: edge.target_event_id,
      rule_name: edge.rule_name,
      confidence_level: edge.confidence_level,
      confidence_score: edge.confidence_score,
      time_delta_seconds: edge.time_delta_seconds,
      matching_fields: edge.matching_fields,
      classification: "Analyst's Interpretation (Correlation Rule Inference)"
    }, null, 2);

    // Grid
    const grid = document.getElementById('drawerFieldsGrid');
    grid.innerHTML = `
      <div class="field-item">
        <span class="field-label">Source Step</span>
        <span class="field-value">${edge.source_event_id}</span>
      </div>
      <div class="field-item">
        <span class="field-label">Target Step</span>
        <span class="field-value">${edge.target_event_id}</span>
      </div>
      <div class="field-item">
        <span class="field-label">Defensibility Rating</span>
        <span class="field-value" style="color: ${isStrong ? '#36C995' : (isPartial ? '#F2A541' : '#B794F6')}; font-weight: 700;">
          ${edge.confidence_level.replace(/_/g, ' ')}
        </span>
      </div>
      <div class="field-item">
        <span class="field-label">Confidence Score</span>
        <span class="field-value">${Math.round(edge.confidence_score * 100)}%</span>
      </div>
      <div class="field-item" style="grid-column: 1 / -1;">
        <span class="field-label">Evidence Matching Fields</span>
        <span class="field-value text-cyan">${JSON.stringify(edge.matching_fields)}</span>
      </div>
      <div class="field-item" style="grid-column: 1 / -1; display:flex; flex-direction:row; gap:10px; padding: 10px;">
        <button id="btnInspectEdgeSource" class="btn-cyber-xs" style="flex:1; padding:6px 10px;">🔍 View Source (${edge.source_event_id})</button>
        <button id="btnInspectEdgeTarget" class="btn-cyber-xs" style="flex:1; padding:6px 10px;">🔍 View Target (${edge.target_event_id})</button>
      </div>
    `;

    // Hook up jump buttons
    document.getElementById('btnInspectEdgeSource')?.addEventListener('click', () => {
      this.inspectEvent(caseId, edge.source_event_id);
    });
    document.getElementById('btnInspectEdgeTarget')?.addEventListener('click', () => {
      this.inspectEvent(caseId, edge.target_event_id);
    });

    // Correlation reasoning box
    const corrSec = document.getElementById('drawerCorrelationSection');
    corrSec.classList.remove('hidden');
    document.getElementById('drawerRuleName').innerText = `Correlation Rule: ${edge.rule_name}`;
    document.getElementById('drawerConfidenceBadge').innerText = `Defensibility: ${edge.confidence_level.replace(/_/g, ' ')} (${Math.round(edge.confidence_score * 100)}%)`;

    let limitationsText = '';
    if (edge.confidence_level === 'STRONGLY_SUPPORTED') {
      limitationsText = '<br/><br/><span style="color: #36C995;"><b>Defensibility Note:</b> Deterministic correlation substantiated by identical cryptographic trace/session identifiers or verified public investigation records.</span>';
    } else if (edge.confidence_level === 'PARTIALLY_SUPPORTED') {
      limitationsText = '<br/><br/><span style="color: #F2A541;"><b>Evidentiary Limitation:</b> Operational correlation within IP/user sequence burst. Lacks cryptographic trace ID or unique session token.</span>';
    } else {
      limitationsText = '<br/><br/><span style="color: #B794F6;"><b>Evidentiary Limitation:</b> Inferred contextual relationship based on target endpoint alignment. Telemetry gaps prevent definitive confirmation of adversary continuity.</span>';
    }

    document.getElementById('drawerExplanation').innerHTML = `${edge.explanation}${limitationsText}`;
  },

  open() {
    if (this.drawer) this.drawer.classList.add('open');
    if (this.backdrop) this.backdrop.classList.add('show');
  },

  close() {
    if (this.drawer) this.drawer.classList.remove('open');
    if (this.backdrop) this.backdrop.classList.remove('show');
  }
};
