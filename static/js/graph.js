/**
 * TraceGuard Attack Graph Engine (Production Grade)
 * 
 * Features:
 * - Chronological left-to-right layered directed DAG layout
 * - Responsive sizing with minimum desktop height ~720px
 * - Automatic Fit-to-View with accurate bounding box calculation
 * - Smooth pan and zoom without page scroll conflicts
 * - Fullscreen canvas mode with Escape listener
 * - Interactive link filters (Strong, Partial, Speculative) with live counts
 * - Rich floating tooltip with forensic metadata on node/edge hover
 * - Real-time radar minimap with interactive viewport pan
 * - Evidence Drawer integration for nodes and edges
 */

const AttackGraph = {
  svg: null,
  container: null,
  zoomGroup: null,
  edgesLayer: null,
  nodesLayer: null,
  tooltip: null,
  minimap: null,
  minimapSvg: null,
  minimapContent: null,
  minimapViewport: null,

  caseId: null,
  rawNodes: [],
  rawEdges: [],
  nodes: [],
  edges: [],
  nodeMap: {},
  activeHypothesisId: null,

  // Transform state: Pan (x, y) and Zoom (k)
  transform: { x: 40, y: 40, k: 1 },
  isPanning: false,
  startPan: { x: 0, y: 0 },
  draggedNode: null,
  hasDragged: false,
  nodeDragStart: { x: 0, y: 0 },

  // Link visibility filter state
  linkFilters: {
    STRONGLY_SUPPORTED: true,
    PARTIALLY_SUPPORTED: true,
    SPECULATIVE: true
  },

  isFullscreen: false,
  minimapVisible: true,
  selectedNodeId: null,
  selectedEdgeId: null,

  // Node card physical dimensions
  NODE_WIDTH: 210,
  NODE_HEIGHT: 66,

  init() {
    this.container = document.getElementById('graphContainer');
    this.svg = document.getElementById('attackGraphSvg');
    this.zoomGroup = document.getElementById('graphZoomGroup');
    this.edgesLayer = document.getElementById('edgesLayer');
    this.nodesLayer = document.getElementById('nodesLayer');
    this.tooltip = document.getElementById('graphTooltip');

    this.minimap = document.getElementById('graphMinimap');
    this.minimapSvg = document.getElementById('minimapSvg');
    this.minimapContent = document.getElementById('minimapContent');
    this.minimapViewport = document.getElementById('minimapViewport');

    this.setupPanAndZoom();
    this.setupToolbarControls();
    this.setupLinkFilterButtons();
    this.setupMinimapInteraction();

    window.addEventListener('resize', () => {
      if (document.getElementById('graphTab')?.classList.contains('active')) {
        this.updateMinimap();
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.isFullscreen) {
        this.toggleFullscreen(false);
      }
    });
  },

  setupToolbarControls() {
    const btnIn = document.getElementById('btnZoomIn');
    const btnOut = document.getElementById('btnZoomOut');
    const btnFit = document.getElementById('btnFitView');
    const btnReset = document.getElementById('btnResetLayout');
    const btnFull = document.getElementById('btnFullscreen');
    const btnToggleMap = document.getElementById('btnToggleMinimap');
    const btnCloseMap = document.getElementById('btnCloseMinimap');

    if (btnIn) btnIn.addEventListener('click', () => this.zoom(1.2));
    if (btnOut) btnOut.addEventListener('click', () => this.zoom(0.8));
    if (btnFit) btnFit.addEventListener('click', () => this.fitToView());
    if (btnReset) btnReset.addEventListener('click', () => this.resetLayout());
    if (btnFull) btnFull.addEventListener('click', () => this.toggleFullscreen());
    
    if (btnToggleMap) {
      btnToggleMap.addEventListener('click', () => this.toggleMinimap());
    }
    if (btnCloseMap) {
      btnCloseMap.addEventListener('click', () => this.toggleMinimap(false));
    }
  },

  setupLinkFilterButtons() {
    const filters = [
      { id: 'btnFilterStrong', type: 'STRONGLY_SUPPORTED' },
      { id: 'btnFilterPartial', type: 'PARTIALLY_SUPPORTED' },
      { id: 'btnFilterSpeculative', type: 'SPECULATIVE' }
    ];

    filters.forEach(({ id, type }) => {
      const btn = document.getElementById(id);
      if (btn) {
        btn.addEventListener('click', () => {
          this.linkFilters[type] = !this.linkFilters[type];
          btn.classList.toggle('active', this.linkFilters[type]);
          this.applyLinkFilters();
          App.showToast(`${type.replace('_', ' ')} links ${this.linkFilters[type] ? 'enabled' : 'hidden'}`);
        });
      }
    });
  },

  setupPanAndZoom() {
    // Mouse Down on canvas -> initiate pan
    this.svg.addEventListener('mousedown', (e) => {
      if (e.target.closest('.graph-node-group')) return; // handled by node drag
      this.isPanning = true;
      this.startPan = { x: e.clientX - this.transform.x, y: e.clientY - this.transform.y };
      this.svg.style.cursor = 'grabbing';
      this.hideTooltip();
    });

    // Window Mouse Move -> handle pan and node dragging
    window.addEventListener('mousemove', (e) => {
      if (this.isPanning) {
        this.transform.x = e.clientX - this.startPan.x;
        this.transform.y = e.clientY - this.startPan.y;
        this.applyTransform();
        this.updateMinimapViewport();
      } else if (this.draggedNode) {
        this.hasDragged = true;
        const pt = this.clientToSvgCoords(e.clientX, e.clientY);
        this.draggedNode.x = pt.x - this.nodeDragStart.x;
        this.draggedNode.y = pt.y - this.nodeDragStart.y;
        this.updateNodeAndEdgePositions(this.draggedNode);
        this.updateMinimap();
      }
    });

    // Window Mouse Up -> end pan or drag
    window.addEventListener('mouseup', () => {
      if (this.isPanning) {
        this.isPanning = false;
        if (this.svg) this.svg.style.cursor = 'grab';
      }
      this.draggedNode = null;
    });

    // Mouse Wheel -> zoom towards cursor position
    this.svg.addEventListener('wheel', (e) => {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.12 : 0.89;
      this.zoom(factor, e.clientX, e.clientY);
    }, { passive: false });
  },

  setupMinimapInteraction() {
    if (!this.minimapSvg) return;

    let isMinimapDragging = false;

    const navigateFromMinimap = (e) => {
      const rect = this.minimapSvg.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const clickY = e.clientY - rect.top;

      const scaleX = (this.bounds.maxX - this.bounds.minX + 200) / rect.width;
      const scaleY = (this.bounds.maxY - this.bounds.minY + 200) / rect.height;

      const targetGraphX = this.bounds.minX - 100 + clickX * scaleX;
      const targetGraphY = this.bounds.minY - 100 + clickY * scaleY;

      const containerRect = this.container.getBoundingClientRect();
      this.transform.x = (containerRect.width / 2) - targetGraphX * this.transform.k;
      this.transform.y = (containerRect.height / 2) - targetGraphY * this.transform.k;

      this.applyTransform();
      this.updateMinimapViewport();
    };

    this.minimapSvg.addEventListener('mousedown', (e) => {
      isMinimapDragging = true;
      navigateFromMinimap(e);
    });

    window.addEventListener('mousemove', (e) => {
      if (isMinimapDragging) {
        navigateFromMinimap(e);
      }
    });

    window.addEventListener('mouseup', () => {
      isMinimapDragging = false;
    });
  },

  clientToSvgCoords(clientX, clientY) {
    const rect = this.svg.getBoundingClientRect();
    const x = (clientX - rect.left - this.transform.x) / this.transform.k;
    const y = (clientY - rect.top - this.transform.y) / this.transform.k;
    return { x, y };
  },

  zoom(factor, pivotX, pivotY) {
    const rect = this.svg.getBoundingClientRect();
    const cx = pivotX !== undefined ? (pivotX - rect.left) : (rect.width / 2);
    const cy = pivotY !== undefined ? (pivotY - rect.top) : (rect.height / 2);

    const newK = Math.min(Math.max(this.transform.k * factor, 0.15), 3.5);
    this.transform.x = cx - (cx - this.transform.x) * (newK / this.transform.k);
    this.transform.y = cy - (cy - this.transform.y) * (newK / this.transform.k);
    this.transform.k = newK;

    this.applyTransform();
    this.updateMinimapViewport();
    this.updateHUDZoomStatus();
  },

  applyTransform() {
    this.zoomGroup.setAttribute(
      'transform',
      `translate(${this.transform.x}, ${this.transform.y}) scale(${this.transform.k})`
    );
  },

  updateHUDZoomStatus() {
    const zoomEl = document.getElementById('graphZoomStatus');
    if (zoomEl) {
      zoomEl.innerText = `Zoom: ${Math.round(this.transform.k * 100)}%`;
    }
  },

  toggleFullscreen(force) {
    this.isFullscreen = (force !== undefined) ? force : !this.isFullscreen;
    this.container.classList.toggle('fullscreen', this.isFullscreen);

    const icon = document.getElementById('iconFullscreen');
    if (icon) {
      icon.innerHTML = this.isFullscreen
        ? '<polyline points="4 14 10 14 10 20"></polyline><polyline points="20 10 14 10 14 4"></polyline><line x1="14" y1="10" x2="21" y2="3"></line><line x1="3" y1="21" x2="10" y2="14"></line>'
        : '<polyline points="15 3 21 3 21 9"></polyline><polyline points="9 21 3 21 3 15"></polyline><line x1="21" y1="3" x2="14" y2="10"></line><line x1="3" y1="21" x2="10" y2="14"></line>';
    }

    // Allow CSS transition then fit
    setTimeout(() => {
      this.fitToView();
      this.updateMinimap();
    }, 150);
  },

  toggleMinimap(force) {
    this.minimapVisible = (force !== undefined) ? force : !this.minimapVisible;
    if (this.minimap) {
      this.minimap.classList.toggle('hidden', !this.minimapVisible);
    }
    const btn = document.getElementById('btnToggleMinimap');
    if (btn) btn.classList.toggle('active', this.minimapVisible);
  },

  // ==========================================
  // Layout and Render Pipeline
  // ==========================================

  render(caseId, nodes, edges, activeHypothesisId = null) {
    this.caseId = caseId;
    this.rawNodes = nodes || [];
    this.rawEdges = edges || [];
    this.activeHypothesisId = activeHypothesisId;

    if (!nodes || nodes.length === 0) {
      this.edgesLayer.innerHTML = '';
      this.nodesLayer.innerHTML = '';
      document.getElementById('graphNodeCountStatus').innerText = '0 Nodes • 0 Links';
      return;
    }

    // Filter edges by hypothesis if active
    let displayEdges = this.rawEdges;
    if (activeHypothesisId && activeHypothesisId !== 'ALL') {
      displayEdges = this.rawEdges.filter(e => 
        !e.hypothesis_tags || e.hypothesis_tags.includes(activeHypothesisId)
      );
    }

    this.edges = displayEdges;
    this.updateFilterCounts();

    // Compute Clean Chronological Left-to-Right Layered Layout
    this.computeChronologicalLayout(this.rawNodes, this.edges);

    // Draw SVG Elements
    this.drawEdges();
    this.drawNodes();

    // Update Overlays
    document.getElementById('graphNodeCountStatus').innerText = `${this.nodes.length} Nodes • ${this.edges.length} Correlated Links`;
    this.applyLinkFilters();

    // Fit view automatically on initial render
    setTimeout(() => {
      this.fitToView();
      this.renderMinimap();
    }, 40);
  },

  updateFilterCounts() {
    const strongCount = this.edges.filter(e => e.confidence_level === 'STRONGLY_SUPPORTED').length;
    const partialCount = this.edges.filter(e => e.confidence_level === 'PARTIALLY_SUPPORTED').length;
    const speculativeCount = this.edges.filter(e => e.confidence_level === 'SPECULATIVE').length;

    const elS = document.getElementById('countStrong');
    const elP = document.getElementById('countPartial');
    const elSp = document.getElementById('countSpeculative');

    if (elS) elS.innerText = strongCount;
    if (elP) elP.innerText = partialCount;
    if (elSp) elSp.innerText = speculativeCount;
  },

  /**
   * Chronological Left-to-Right Directed Layered Layout Algorithm
   * Groups events into chronological stages, distributes them cleanly into swimlanes,
   * and prevents any node or label clipping.
   */
  computeChronologicalLayout(nodes, edges) {
    // 1. Sort strictly by timestamp
    const sorted = [...nodes].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    // 2. Identify chronological columns based on time delta & cross-source clustering
    const columns = [];
    let currentColumn = [];
    let lastTime = null;

    sorted.forEach((node) => {
      const nodeTime = new Date(node.timestamp).getTime();
      if (lastTime === null) {
        currentColumn.push(node);
        lastTime = nodeTime;
      } else {
        const deltaSeconds = Math.abs(nodeTime - lastTime) / 1000;
        // Group events occurring within 1s or cross-source pairs into same column, up to 3 nodes
        if (deltaSeconds <= 1.0 && currentColumn.length < 3) {
          currentColumn.push(node);
        } else {
          columns.push(currentColumn);
          currentColumn = [node];
          lastTime = nodeTime;
        }
      }
    });
    if (currentColumn.length > 0) columns.push(currentColumn);

    // 3. Compute (x, y) coordinates
    const COL_SPACING = 270; // 270px horizontal spacing ensures 90px clear gap between 180px cards
    const BASE_Y = 320;      // Center baseline
    const ROW_SPACING = 140; // 140px vertical spacing ensures 80px clear gap between 60px cards

    this.nodes = [];
    this.nodeMap = {};

    columns.forEach((colNodes, colIdx) => {
      const x = 120 + colIdx * COL_SPACING;
      const count = colNodes.length;

      colNodes.forEach((node, rowIdx) => {
        // Center the vertical cluster around BASE_Y
        const totalHeight = (count - 1) * ROW_SPACING;
        const startY = BASE_Y - (totalHeight / 2);
        const y = startY + rowIdx * ROW_SPACING;

        const layoutNode = {
          ...node,
          x,
          y,
          colIdx,
          rowIdx,
          origX: x,
          origY: y
        };

        this.nodes.push(layoutNode);
        this.nodeMap[node.id] = layoutNode;
      });
    });

    this.calculateBounds();
  },

  calculateBounds() {
    if (this.nodes.length === 0) {
      this.bounds = { minX: 0, maxX: 800, minY: 0, maxY: 600 };
      return;
    }

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    this.nodes.forEach(n => {
      minX = Math.min(minX, n.x - this.NODE_WIDTH / 2);
      maxX = Math.max(maxX, n.x + this.NODE_WIDTH / 2);
      minY = Math.min(minY, n.y - this.NODE_HEIGHT / 2);
      maxY = Math.max(maxY, n.y + this.NODE_HEIGHT / 2);
    });

    this.bounds = { minX, maxX, minY, maxY };
  },

  fitToView() {
    this.calculateBounds();
    const containerRect = this.container.getBoundingClientRect();
    const width = containerRect.width || 900;
    const height = containerRect.height || 720;

    const padX = 100;
    const padY = 90;

    const graphWidth = (this.bounds.maxX - this.bounds.minX) + padX * 2;
    const graphHeight = (this.bounds.maxY - this.bounds.minY) + padY * 2;

    const scaleX = width / Math.max(graphWidth, 400);
    const scaleY = height / Math.max(graphHeight, 350);

    // Pick best fit scale with sensible maximum
    const k = Math.min(scaleX, scaleY, 1.15) * 0.95;

    // Center graph within visible viewport
    const centerX = (this.bounds.minX + this.bounds.maxX) / 2;
    const centerY = (this.bounds.minY + this.bounds.maxY) / 2;

    this.transform.k = k;
    this.transform.x = (width / 2) - centerX * k;
    this.transform.y = (height / 2) - centerY * k;

    this.applyTransform();
    this.updateMinimapViewport();
    this.updateHUDZoomStatus();
  },

  resetLayout() {
    this.nodes.forEach(n => {
      n.x = n.origX;
      n.y = n.origY;
    });
    this.updateAllPositions();
    this.fitToView();
    this.renderMinimap();
    App.showToast('Graph layout reset to pristine chronological sequence.');
  },

  // ==========================================
  // Edge Rendering with Smooth Curves
  // ==========================================

  drawEdges() {
    this.edgesLayer.innerHTML = '';

    this.edges.forEach(edge => {
      const source = this.nodeMap[edge.source_event_id];
      const target = this.nodeMap[edge.target_event_id];
      if (!source || !target) return;

      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', `graph-edge-group edge-${edge.edge_id}`);
      g.setAttribute('data-confidence', edge.confidence_level);

      let marker = 'url(#arrow-strong)';
      let cls = 'graph-edge-path edge-strong';
      if (edge.confidence_level === 'PARTIALLY_SUPPORTED') {
        marker = 'url(#arrow-partial)';
        cls = 'graph-edge-path edge-partial';
      } else if (edge.confidence_level === 'SPECULATIVE') {
        marker = 'url(#arrow-speculative)';
        cls = 'graph-edge-path edge-speculative';
      }

      // 1. Transparent wider hit area for easy hover and click
      const hitPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      hitPath.setAttribute('class', 'edge-hit-area');
      hitPath.setAttribute('id', `edge-hit-${edge.edge_id}`);

      // 2. Visible styled curved stroke path
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('id', `edge-${edge.edge_id}`);
      path.setAttribute('class', cls);
      path.setAttribute('marker-end', marker);

      const d = this.computeEdgeCurve(source, target);
      hitPath.setAttribute('d', d);
      path.setAttribute('d', d);

      // Event handlers for Edge (Hover Tooltip & Click Inspection)
      const onEdgeOver = (e) => {
        path.style.strokeWidth = '4px';
        this.showEdgeTooltip(e, edge);
      };
      const onEdgeOut = () => {
        path.style.strokeWidth = '';
        this.hideTooltip();
      };
      const onEdgeClick = (e) => {
        e.stopPropagation();
        this.selectedEdgeId = edge.edge_id;
        EvidenceDrawer.inspectEdge(this.caseId, edge);
      };

      hitPath.addEventListener('mouseenter', onEdgeOver);
      hitPath.addEventListener('mousemove', (e) => this.updateTooltipPosition(e));
      hitPath.addEventListener('mouseleave', onEdgeOut);
      hitPath.addEventListener('click', onEdgeClick);

      path.addEventListener('mouseenter', onEdgeOver);
      path.addEventListener('mouseleave', onEdgeOut);
      path.addEventListener('click', onEdgeClick);

      g.appendChild(hitPath);
      g.appendChild(path);
      this.edgesLayer.appendChild(g);
    });
  },

  computeEdgeCurve(s, t) {
    const halfW = this.NODE_WIDTH / 2;
    const halfH = this.NODE_HEIGHT / 2;

    // Check direction
    const isForward = t.x >= s.x;

    let p1x, p1y, p2x, p2y;

    if (isForward) {
      // Connect right side of source to left side of target
      p1x = s.x + halfW;
      p1y = s.y;
      p2x = t.x - halfW - 4; // leave 4px for arrow tip
      p2y = t.y;
    } else {
      // Backward or same column loop
      p1x = s.x;
      p1y = s.y + halfH;
      p2x = t.x;
      p2y = t.y + halfH + 4;
    }

    const dx = Math.abs(p2x - p1x);
    const dy = p2y - p1y;

    // Smooth cubic Bézier control points
    let cx1, cy1, cx2, cy2;

    if (isForward) {
      const colDist = Math.abs(t.colIdx - s.colIdx);
      // If jumping across 2 or more columns, arc slightly upward to prevent collision
      const arcOffset = colDist > 1 ? -Math.min(colDist * 18, 60) : 0;
      
      cx1 = p1x + Math.max(dx * 0.45, 40);
      cy1 = p1y + arcOffset;
      cx2 = p2x - Math.max(dx * 0.45, 40);
      cy2 = p2y + arcOffset;
    } else {
      cx1 = p1x;
      cy1 = p1y + 60;
      cx2 = p2x;
      cy2 = p2y + 60;
    }

    return `M ${p1x} ${p1y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${p2x} ${p2y}`;
  },

  applyLinkFilters() {
    this.edges.forEach(edge => {
      const g = document.querySelector(`.edge-${edge.edge_id}`);
      if (g) {
        const isVisible = this.linkFilters[edge.confidence_level] !== false;
        g.classList.toggle('graph-edge-hidden', !isVisible);
      }
    });
    this.renderMinimap();
  },

  // ==========================================
  // Node Card Rendering (No text clipping)
  // ==========================================

  drawNodes() {
    this.nodesLayer.innerHTML = '';

    const W = this.NODE_WIDTH;
    const H = this.NODE_HEIGHT;

    this.nodes.forEach((node, idx) => {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', `graph-node-group node-${node.id}`);
      g.setAttribute('id', `node-group-${node.id}`);
      g.setAttribute('transform', `translate(${node.x}, ${node.y})`);

      const catColor = this.getNodeColor(node.event_category);
      const isSelected = (this.selectedNodeId === node.id);

      // 1. Card Background (High contrast dark graphite)
      const card = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      card.setAttribute('class', 'node-card-rect');
      card.setAttribute('x', -W / 2);
      card.setAttribute('y', -H / 2);
      card.setAttribute('width', W);
      card.setAttribute('height', H);
      card.setAttribute('rx', '8');
      card.setAttribute('ry', '8');
      card.setAttribute('fill', '#161B22');
      card.setAttribute('stroke', catColor);
      card.setAttribute('stroke-width', isSelected ? '2.5' : '1.8');
      if (isSelected) card.classList.add('selected');

      // 1b. Header Strip (Subtle graphite header for badge and source)
      const headerBar = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      headerBar.setAttribute('class', 'node-card-header');
      const r = 8;
      const x0 = -W / 2, y0 = -H / 2, x1 = W / 2, y1 = -H / 2 + 22;
      headerBar.setAttribute('d', `M ${x0 + r} ${y0} L ${x1 - r} ${y0} Q ${x1} ${y0} ${x1} ${y0 + r} L ${x1} ${y1} L ${x0} ${y1} L ${x0} ${y0 + r} Q ${x0} ${y0} ${x0 + r} ${y0} Z`);
      headerBar.setAttribute('fill', '#1F242D');

      // 2. Step Badge (Pill)
      const stepPill = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      stepPill.setAttribute('class', 'node-step-badge');
      stepPill.setAttribute('x', -W / 2 + 8);
      stepPill.setAttribute('y', -H / 2 + 4);
      stepPill.setAttribute('width', 22);
      stepPill.setAttribute('height', 15);
      stepPill.setAttribute('rx', '4');
      stepPill.setAttribute('ry', '4');
      stepPill.setAttribute('fill', catColor);

      const stepText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      stepText.setAttribute('class', 'node-step-text');
      stepText.setAttribute('x', -W / 2 + 19);
      stepText.setAttribute('y', -H / 2 + 15);
      stepText.setAttribute('text-anchor', 'middle');
      stepText.setAttribute('fill', '#0A0D12');
      stepText.setAttribute('font-weight', '800');
      stepText.setAttribute('font-size', '10px');
      stepText.textContent = idx + 1;

      // 3. Source Pill (e.g. APACHE, NGINX, NODE, WAF)
      const srcText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      srcText.setAttribute('class', 'node-source-text');
      srcText.setAttribute('x', -W / 2 + 36);
      srcText.setAttribute('y', -H / 2 + 15);
      srcText.setAttribute('fill', '#9FAEC0');
      srcText.setAttribute('font-size', '9.5px');
      srcText.setAttribute('font-weight', '700');
      srcText.textContent = (node.source_type || 'LOG').toUpperCase().slice(0, 10);

      // 4. Status Code Pill (if HTTP status exists)
      let statusGroup = null;
      if (node.status_code) {
        statusGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        const sc = parseInt(node.status_code);
        let statusColor = '#36C995'; // 200s
        let statusBg = 'rgba(54, 201, 149, 0.18)';
        if (sc >= 500) { statusColor = '#E45865'; statusBg = 'rgba(228, 88, 101, 0.22)'; }
        else if (sc >= 400) { statusColor = '#F2A541'; statusBg = 'rgba(242, 165, 65, 0.22)'; }

        const statusPill = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        statusPill.setAttribute('class', 'node-status-pill');
        statusPill.setAttribute('x', W / 2 - 38);
        statusPill.setAttribute('y', -H / 2 + 4);
        statusPill.setAttribute('width', 30);
        statusPill.setAttribute('height', 15);
        statusPill.setAttribute('rx', '4');
        statusPill.setAttribute('ry', '4');
        statusPill.setAttribute('fill', statusBg);
        statusPill.setAttribute('stroke', statusColor);
        statusPill.setAttribute('stroke-width', '0.8');

        const statusText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        statusText.setAttribute('class', 'node-status-text');
        statusText.setAttribute('x', W / 2 - 23);
        statusText.setAttribute('y', -H / 2 + 15);
        statusText.setAttribute('text-anchor', 'middle');
        statusText.setAttribute('fill', statusColor);
        statusText.setAttribute('font-weight', '700');
        statusText.setAttribute('font-size', '9.5px');
        statusText.textContent = sc;

        statusGroup.appendChild(statusPill);
        statusGroup.appendChild(statusText);
      }

      // 5. Main Title Text (e.g. "POST /portal/upload.php" or "Impact (Ransomware Execution)")
      const titleText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      titleText.setAttribute('class', 'node-title-text');
      titleText.setAttribute('x', -W / 2 + 10);
      titleText.setAttribute('y', 9);
      titleText.setAttribute('fill', '#F5F7FA');
      titleText.setAttribute('font-size', '11.5px');
      titleText.setAttribute('font-weight', '600');
      titleText.textContent = this.truncate(node.label || node.id, 24);

      // 6. Subtitle Text (Timestamp & IP)
      const subText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      subText.setAttribute('class', 'node-sub-text');
      subText.setAttribute('x', -W / 2 + 10);
      subText.setAttribute('y', 23);
      subText.setAttribute('fill', '#7E8D9F');
      subText.setAttribute('font-size', '9.5px');
      const timeStr = node.timestamp ? node.timestamp.slice(11, 19) + ' UTC' : '--:--:--';
      const ipStr = node.source_ip ? ` • ${node.source_ip}` : '';
      subText.textContent = `${timeStr}${ipStr}`;

      g.appendChild(card);
      g.appendChild(headerBar);
      g.appendChild(stepPill);
      g.appendChild(stepText);
      g.appendChild(srcText);
      if (statusGroup) g.appendChild(statusGroup);
      g.appendChild(titleText);
      g.appendChild(subText);

      // Node Event Listeners
      let clickStartX = 0, clickStartY = 0;

      g.addEventListener('mousedown', (e) => {
        e.stopPropagation();
        this.draggedNode = node;
        this.hasDragged = false;
        clickStartX = e.clientX;
        clickStartY = e.clientY;

        const pt = this.clientToSvgCoords(e.clientX, e.clientY);
        this.nodeDragStart = { x: pt.x - node.x, y: pt.y - node.y };
      });

      g.addEventListener('mouseenter', (e) => {
        this.showNodeTooltip(e, node);
      });

      g.addEventListener('mousemove', (e) => {
        this.updateTooltipPosition(e);
      });

      g.addEventListener('mouseleave', () => {
        this.hideTooltip();
      });

      g.addEventListener('mouseup', (e) => {
        e.stopPropagation();
        const dist = Math.hypot(e.clientX - clickStartX, e.clientY - clickStartY);
        if (dist < 5) {
          // Genuine click -> open Evidence Inspector
          this.selectedNodeId = node.id;
          document.querySelectorAll('.graph-node-group').forEach(el => el.classList.remove('selected'));
          g.classList.add('selected');
          EvidenceDrawer.inspectEvent(this.caseId, node.id);
        }
      });

      this.nodesLayer.appendChild(g);
    });
  },

  updateNodeAndEdgePositions(node) {
    const g = document.getElementById(`node-group-${node.id}`);
    if (g) {
      g.setAttribute('transform', `translate(${node.x}, ${node.y})`);
    }

    // Update connected edges
    this.edges.forEach(edge => {
      if (edge.source_event_id === node.id || edge.target_event_id === node.id) {
        const s = this.nodeMap[edge.source_event_id];
        const t = this.nodeMap[edge.target_event_id];
        if (s && t) {
          const d = this.computeEdgeCurve(s, t);
          const hit = document.getElementById(`edge-hit-${edge.edge_id}`);
          const p = document.getElementById(`edge-${edge.edge_id}`);
          if (hit) hit.setAttribute('d', d);
          if (p) p.setAttribute('d', d);
        }
      }
    });
  },

  updateAllPositions() {
    this.nodes.forEach(n => {
      const g = document.getElementById(`node-group-${n.id}`);
      if (g) g.setAttribute('transform', `translate(${n.x}, ${n.y})`);
    });

    this.edges.forEach(edge => {
      const s = this.nodeMap[edge.source_event_id];
      const t = this.nodeMap[edge.target_event_id];
      if (s && t) {
        const d = this.computeEdgeCurve(s, t);
        const hit = document.getElementById(`edge-hit-${edge.edge_id}`);
        const p = document.getElementById(`edge-${edge.edge_id}`);
        if (hit) hit.setAttribute('d', d);
        if (p) p.setAttribute('d', d);
      }
    });
  },

  // ==========================================
  // Rich Tooltips (Node & Edge)
  // ==========================================

  showNodeTooltip(e, node) {
    if (!this.tooltip) return;

    const catPill = document.getElementById('ttCategoryPill');
    const ttId = document.getElementById('ttId');
    const ttTitle = document.getElementById('ttTitle');
    const ttTime = document.getElementById('ttTime');
    const ttIp = document.getElementById('ttIp');
    const ttStatus = document.getElementById('ttStatus');
    const ttFile = document.getElementById('ttFile');
    const ttSession = document.getElementById('ttSession');
    const ttTrace = document.getElementById('ttTrace');
    const ttIndicators = document.getElementById('ttIndicators');
    const ttMitre = document.getElementById('ttMitre');
    const ttHash = document.getElementById('ttHash');
    const ttFooter = document.getElementById('ttFooter');

    const catColor = this.getNodeColor(node.event_category);
    catPill.innerText = node.event_category;
    catPill.style.background = `${catColor}22`;
    catPill.style.color = catColor;
    catPill.style.border = `1px solid ${catColor}`;

    ttId.innerText = node.id;
    ttTitle.innerText = `${node.endpoint ? (node.details?.http_method || '') + ' ' + node.endpoint : node.label}`;
    ttTime.innerText = node.timestamp ? node.timestamp.replace('T', ' ').slice(0, 19) + ' UTC' : '--';
    ttIp.innerText = node.source_ip || 'Internal / Local';
    ttStatus.innerText = node.status_code ? `${node.status_code}` : 'N/A';
    ttFile.innerText = `${node.details?.source_file || node.source_type}${node.details?.line_number ? ':' + node.details.line_number : ''}`;

    const sessionVal = node.session_id || node.details?.user || null;
    document.getElementById('ttRowSession').style.display = sessionVal ? 'flex' : 'none';
    if (sessionVal) ttSession.innerText = sessionVal;

    const traceVal = node.details?.request_id || null;
    document.getElementById('ttRowTrace').style.display = traceVal ? 'flex' : 'none';
    if (traceVal) ttTrace.innerText = traceVal;

    const indVal = node.attack_indicators?.length > 0 ? node.attack_indicators.join(', ') : null;
    document.getElementById('ttRowIndicators').style.display = indVal ? 'flex' : 'none';
    if (indVal) ttIndicators.innerText = indVal;

    const mitreVal = node.mitre_technique || null;
    document.getElementById('ttRowMitre').style.display = mitreVal ? 'flex' : 'none';
    if (mitreVal) ttMitre.innerText = mitreVal;

    ttHash.innerText = `${node.raw_hash.slice(0, 20)}...`;
    ttFooter.innerText = '👉 Click node to open full forensic evidence drawer';

    this.tooltip.classList.remove('hidden');
    this.updateTooltipPosition(e);
  },

  showEdgeTooltip(e, edge) {
    if (!this.tooltip) return;

    const catPill = document.getElementById('ttCategoryPill');
    const ttId = document.getElementById('ttId');
    const ttTitle = document.getElementById('ttTitle');
    const ttTime = document.getElementById('ttTime');
    const ttIp = document.getElementById('ttIp');
    const ttStatus = document.getElementById('ttStatus');
    const ttFile = document.getElementById('ttFile');
    const ttFooter = document.getElementById('ttFooter');

    let confColor = '#36C995'; // Strong: green
    if (edge.confidence_level === 'PARTIALLY_SUPPORTED') confColor = '#F2A541'; // Partial: amber
    else if (edge.confidence_level === 'SPECULATIVE') confColor = '#B794F6'; // Possible: purple

    catPill.innerText = edge.confidence_level.replace('_', ' ');
    catPill.style.background = `${confColor}22`;
    catPill.style.color = confColor;
    catPill.style.border = `1px solid ${confColor}`;

    ttId.innerText = edge.edge_id;
    ttTitle.innerText = `Rule: ${edge.rule_name}`;
    ttTime.innerText = `Delta: +${edge.time_delta_seconds.toFixed(2)}s`;
    ttIp.innerText = `Confidence: ${Math.round(edge.confidence_score * 100)}%`;
    ttStatus.innerText = `${edge.source_event_id} ➔ ${edge.target_event_id}`;
    ttFile.innerText = edge.explanation;

    document.getElementById('ttRowSession').style.display = 'none';
    document.getElementById('ttRowTrace').style.display = 'none';
    document.getElementById('ttRowIndicators').style.display = 'none';
    document.getElementById('ttRowMitre').style.display = 'none';
    document.getElementById('ttHash').innerText = JSON.stringify(edge.matching_fields);
    ttFooter.innerText = '👉 Click edge to view correlation proof & limitations';

    this.tooltip.classList.remove('hidden');
    this.updateTooltipPosition(e);
  },

  updateTooltipPosition(e) {
    if (!this.tooltip || this.tooltip.classList.contains('hidden')) return;

    const containerRect = this.container.getBoundingClientRect();
    let left = e.clientX - containerRect.left + 16;
    let top = e.clientY - containerRect.top + 16;

    const ttW = 320;
    const ttH = 260;

    // Prevent overflow past container right edge
    if (left + ttW > containerRect.width - 20) {
      left = (e.clientX - containerRect.left) - ttW - 16;
    }
    // Prevent overflow past container bottom edge
    if (top + ttH > containerRect.height - 20) {
      top = (e.clientY - containerRect.top) - ttH - 16;
    }

    this.tooltip.style.left = `${Math.max(10, left)}px`;
    this.tooltip.style.top = `${Math.max(10, top)}px`;
  },

  hideTooltip() {
    if (this.tooltip) {
      this.tooltip.classList.add('hidden');
    }
  },

  // ==========================================
  // Radar Minimap
  // ==========================================

  renderMinimap() {
    if (!this.minimapContent || !this.minimapVisible) return;
    this.calculateBounds();

    this.minimapContent.innerHTML = '';
    const mapW = this.minimapSvg.clientWidth || 190;
    const mapH = this.minimapSvg.clientHeight || 130;

    const pad = 120;
    const gW = (this.bounds.maxX - this.bounds.minX) + pad * 2;
    const gH = (this.bounds.maxY - this.bounds.minY) + pad * 2;

    const sX = mapW / Math.max(gW, 100);
    const sY = mapH / Math.max(gH, 100);
    this.minimapScale = Math.min(sX, sY);

    this.minimapOffsetX = (mapW - gW * this.minimapScale) / 2 - (this.bounds.minX - pad) * this.minimapScale;
    this.minimapOffsetY = (mapH - gH * this.minimapScale) / 2 - (this.bounds.minY - pad) * this.minimapScale;

    // Draw miniature edges
    this.edges.forEach(edge => {
      if (this.linkFilters[edge.confidence_level] === false) return;
      const s = this.nodeMap[edge.source_event_id];
      const t = this.nodeMap[edge.target_event_id];
      if (!s || !t) return;

      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', s.x * this.minimapScale + this.minimapOffsetX);
      line.setAttribute('y1', s.y * this.minimapScale + this.minimapOffsetY);
      line.setAttribute('x2', t.x * this.minimapScale + this.minimapOffsetX);
      line.setAttribute('y2', t.y * this.minimapScale + this.minimapOffsetY);
      line.setAttribute('stroke', edge.confidence_level === 'STRONGLY_SUPPORTED' ? '#36C995' : (edge.confidence_level === 'PARTIALLY_SUPPORTED' ? '#F2A541' : '#B794F6'));
      line.setAttribute('stroke-width', '0.8');
      line.setAttribute('opacity', '0.6');
      this.minimapContent.appendChild(line);
    });

    // Draw miniature nodes
    this.nodes.forEach(n => {
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', n.x * this.minimapScale + this.minimapOffsetX);
      circle.setAttribute('cy', n.y * this.minimapScale + this.minimapOffsetY);
      circle.setAttribute('r', '2.5');
      circle.setAttribute('fill', this.getNodeColor(n.event_category));
      this.minimapContent.appendChild(circle);
    });

    this.updateMinimapViewport();
  },

  updateMinimap() {
    this.renderMinimap();
  },

  updateMinimapViewport() {
    if (!this.minimapViewport || !this.minimapScale) return;

    const containerRect = this.container.getBoundingClientRect();
    const cW = containerRect.width || 900;
    const cH = containerRect.height || 720;

    // Viewport box in graph coordinates:
    const graphLeft = -this.transform.x / this.transform.k;
    const graphTop = -this.transform.y / this.transform.k;
    const graphWidth = cW / this.transform.k;
    const graphHeight = cH / this.transform.k;

    // Map to minimap coordinates:
    const vx = graphLeft * this.minimapScale + this.minimapOffsetX;
    const vy = graphTop * this.minimapScale + this.minimapOffsetY;
    const vw = graphWidth * this.minimapScale;
    const vh = graphHeight * this.minimapScale;

    this.minimapViewport.setAttribute('x', Math.max(0, vx));
    this.minimapViewport.setAttribute('y', Math.max(0, vy));
    this.minimapViewport.setAttribute('width', Math.max(12, vw));
    this.minimapViewport.setAttribute('height', Math.max(8, vh));
  },

  getNodeColor(cat) {
    switch (cat) {
      case 'RECONNAISSANCE': return '#20B8A8';
      case 'AUTHENTICATION': return '#20B8A8';
      case 'EXPLOITATION': return '#E45865';
      case 'PERSISTENCE': return '#B794F6';
      case 'EXECUTION': return '#F2A541';
      case 'EXFILTRATION': return '#E45865';
      case 'SYSTEM_ERROR': return '#F2A541';
      default: return '#36C995';
    }
  },

  truncate(str, max) {
    if (!str) return '';
    return str.length > max ? str.slice(0, max - 1) + '…' : str;
  }
};
