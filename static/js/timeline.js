/**
 * Event Timeline Module - Displays chronological event stream
 * Shows event classification, source, verbatim records, and evidence links.
 */

const Timeline = {
  container: null,
  events: [],
  caseId: null,

  init() {
    this.container = document.getElementById('timelineStream');

    const searchInput = document.getElementById('timelineSearch');
    const filterSource = document.getElementById('filterSource');
    const filterSeverity = document.getElementById('filterSeverity');

    if (searchInput) {
      searchInput.addEventListener('input', () => this.filterAndRender());
    }
    if (filterSource) {
      filterSource.addEventListener('change', () => this.filterAndRender());
    }
    if (filterSeverity) {
      filterSeverity.addEventListener('change', () => this.filterAndRender());
    }
  },

  setEvents(caseId, events) {
    this.caseId = caseId;
    this.events = events || [];
    this.filterAndRender();
  },

  filterAndRender() {
    if (!this.container) return;

    const searchTerm = (document.getElementById('timelineSearch')?.value || '').toLowerCase();
    const sourceFilter = document.getElementById('filterSource')?.value || '';
    const severityFilter = document.getElementById('filterSeverity')?.value || '';

    const filtered = this.events.filter(e => {
      if (sourceFilter && e.source_type.toLowerCase() !== sourceFilter.toLowerCase()) return false;
      if (severityFilter && e.severity.toUpperCase() !== severityFilter.toUpperCase()) return false;
      if (searchTerm) {
        const text = `${e.endpoint || ''} ${e.source_ip || ''} ${e.raw_record || ''} ${e.evidence_classification || ''} ${e.attack_indicators?.join(' ') || ''}`.toLowerCase();
        if (!text.includes(searchTerm)) return false;
      }
      return true;
    });

    this.container.innerHTML = '';

    if (filtered.length === 0) {
      this.container.innerHTML = `
        <div style="text-align: center; padding: 40px; color: var(--text-secondary); background: var(--panel-card); border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
          No events found matching the search and filter criteria.
        </div>
      `;
      return;
    }

    filtered.forEach(evt => {
      const card = document.createElement('div');
      card.className = 'timeline-item-card';

      const timeStr = evt.timestamp ? evt.timestamp.replace('T', ' ').slice(0, 19) + ' UTC' : '--:--:--';
      const titleStr = evt.endpoint ? `${evt.http_method || ''} ${evt.endpoint}` : `[${evt.source_type.toUpperCase()}] ${evt.event_category}`;

      const classification = evt.evidence_classification || 'Imported Evidence';
      let badgeClass = 'badge-imported-evidence';
      if (classification === 'Publicly Reported Fact') badgeClass = 'badge-public-fact';
      else if (classification === 'Simulated Demo Data') badgeClass = 'badge-demo-data';
      else if (classification === 'Analyst\'s Interpretation') badgeClass = 'badge-analyst-interp';
      else if (classification === 'Unverified Information') badgeClass = 'badge-unverified';

      let sevColor = 'var(--text-secondary)';
      if (evt.severity === 'CRITICAL') sevColor = 'var(--alert-critical)';
      else if (evt.severity === 'HIGH') sevColor = 'var(--alert-warning)';
      else if (evt.severity === 'MEDIUM') sevColor = 'var(--link-possible)';

      card.innerHTML = `
        <div class="timeline-item-header">
          <div class="timeline-item-left">
            <span class="timeline-time-badge">${timeStr}</span>
            <span class="badge-classification ${badgeClass}">${classification}</span>
            <span style="font-size: 0.75rem; color: var(--text-secondary); font-weight: 600;">[${evt.source_type.toUpperCase()}]</span>
          </div>
          <div>
            <span style="font-size: 0.74rem; font-weight: 700; color: ${sevColor}; padding: 2px 8px; border-radius: var(--radius-full); background: rgba(38, 61, 82, 0.6);">${evt.severity}</span>
          </div>
        </div>

        <div class="timeline-item-title">${titleStr}</div>

        <div style="display: flex; gap: 14px; font-size: 0.74rem; color: var(--text-secondary); flex-wrap: wrap;">
          <span>Source IP: <b style="color: var(--text-main);">${evt.source_ip || 'Internal'}</b></span>
          ${evt.status_code ? `<span>HTTP Status: <b style="color: var(--text-main);">${evt.status_code}</b></span>` : ''}
          ${evt.user ? `<span>User: <b style="color: var(--text-main);">${evt.user}</b></span>` : ''}
          ${evt.attack_indicators && evt.attack_indicators.length > 0 ? `<span style="color: var(--alert-critical);">Threat: ${evt.attack_indicators.join(', ')}</span>` : ''}
        </div>

        <div class="timeline-item-body">
          ${evt.raw_record}
        </div>
      `;

      card.addEventListener('click', () => {
        EvidenceDrawer.inspectEvent(this.caseId, evt.event_id);
      });

      this.container.appendChild(card);
    });
  }
};
