(function () {
    'use strict';

    if (typeof d3 === 'undefined') {
        console.error('D3.js required for graph');
        return;
    }

    const CONFIG = {
        // "radius" = half-size reference used for collision & label offset
        nodeRadius: {
            user_admin: 30, user_staff: 26, user: 22,
            device: 22, credential: 18,
            device_file: 15, config_template: 20, config_file: 15
        },
        colors: {
            user_admin: '#ef4444', user_staff: '#f97316', user: '#009f8c',
            device: '#6366f1', credential: '#f59e0b',
            device_file: '#8b5cf6', config_template: '#22c55e', config_file: '#16a34a'
        },
        linkColors: {
            owner: '#009f8c', assigned: '#6366f1', has_credential: '#f59e0b',
            has_file: '#8b5cf6', owns_template: '#22c55e', owns_config_file: '#16a34a'
        },
        // Short letter shown inside each shape \u2014 always renders regardless of fonts
        letters: {
            user_admin: 'A', user_staff: 'S', user: 'U',
            device: 'D', credential: 'K',
            device_file: 'F', config_template: 'T', config_file: 'C'
        }
    };

    // Draw the distinctive shape for each node type
    function drawNodeShape(g, d) {
        const r = CONFIG.nodeRadius[d.type] || 16;
        const color = CONFIG.colors[d.type] || '#94a3b8';
        const stroke = { stroke: '#fff', 'stroke-width': 2 };

        if (d.type.startsWith('user')) {
            // \u25cf Circle \u2014 all user subtypes, size encodes role
            g.append('circle').attr('class', 'node-shape')
                .attr('r', r).attr('fill', color)
                .attr('stroke', stroke.stroke).attr('stroke-width', stroke['stroke-width']);

        } else if (d.type === 'device') {
            // \u25ac Rounded rectangle \u2014 hardware
            g.append('rect').attr('class', 'node-shape')
                .attr('x', -r).attr('y', -r * 0.8)
                .attr('width', r * 2).attr('height', r * 1.6)
                .attr('rx', 7).attr('fill', color)
                .attr('stroke', stroke.stroke).attr('stroke-width', stroke['stroke-width']);

        } else if (d.type === 'credential') {
            // \u25c6 Diamond \u2014 key/credential
            g.append('polygon').attr('class', 'node-shape')
                .attr('points', `0,${-r} ${r * 1.15},0 0,${r} ${-r * 1.15},0`)
                .attr('fill', color)
                .attr('stroke', stroke.stroke).attr('stroke-width', stroke['stroke-width']);

        } else if (d.type === 'config_template') {
            // \u2b21 Hexagon \u2014 structured template
            const pts = Array.from({ length: 6 }, (_, i) => {
                const a = Math.PI / 180 * (60 * i - 30);
                return `${r * Math.cos(a)},${r * Math.sin(a)}`;
            }).join(' ');
            g.append('polygon').attr('class', 'node-shape')
                .attr('points', pts).attr('fill', color)
                .attr('stroke', stroke.stroke).attr('stroke-width', stroke['stroke-width']);

        } else {
            // \ud83d\udcc4 Document shape (folded corner) \u2014 files
            const w = r * 1.55, h = r * 1.85, fold = r * 0.45;
            g.append('polygon').attr('class', 'node-shape')
                .attr('points', [
                    `${-w / 2},${-h / 2}`,
                    `${w / 2 - fold},${-h / 2}`,
                    `${w / 2},${-h / 2 + fold}`,
                    `${w / 2},${h / 2}`,
                    `${-w / 2},${h / 2}`
                ].join(' '))
                .attr('fill', color)
                .attr('stroke', stroke.stroke).attr('stroke-width', stroke['stroke-width']);
            // Fold line accent
            g.append('polyline')
                .attr('points', `${w / 2 - fold},${-h / 2} ${w / 2 - fold},${-h / 2 + fold} ${w / 2},${-h / 2 + fold}`)
                .attr('fill', 'none')
                .attr('stroke', 'rgba(255,255,255,0.5)').attr('stroke-width', 1.5)
                .style('pointer-events', 'none');
        }
    }

    function createTooltip(container) {
        let t = container.querySelector('.graph-tooltip');
        if (!t) {
            t = document.createElement('div');
            t.className = 'graph-tooltip';
            t.style.display = 'none';
            container.appendChild(t);
        }
        return t;
    }

    function formatTooltip(n) {
        const d = n.data || {};
        const typeLabels = {
            user_admin: 'ADMIN', user_staff: 'STAFF', user: 'USUARIO',
            device: 'DISPOSITIVO', credential: 'CREDENCIAL',
            device_file: 'ARCHIVO DE DISPOSITIVO', config_template: 'TEMPLATE', config_file: 'ARCHIVO CONFIG'
        };
        let h = `<div class="tt-head"><strong>${n.label}</strong></div>`;
        h += `<div class="tt-type">${typeLabels[n.type] || n.type.toUpperCase()}</div><div class="tt-body">`;
        if (n.type === 'user' || n.type === 'user_admin' || n.type === 'user_staff') {
            if (d.email) h += `<div><span class="lbl">Email:</span> ${d.email}</div>`;
            if (d.role) h += `<div><span class="lbl">Rol:</span> ${d.role}</div>`;
            h += `<div><span class="lbl">Estado:</span> ${d.is_active !== false ? '✓ Activo' : '✗ Inactivo'}</div>`;
        } else if (n.type === 'device') {
            if (d.manufacturer) h += `<div><span class="lbl">Fabricante:</span> ${d.manufacturer}</div>`;
            if (d.networks?.length) h += `<div><span class="lbl">Redes:</span> ${d.networks.join(', ')}</div>`;
            if (d.serial_number) h += `<div><span class="lbl">Serie:</span> ${d.serial_number}</div>`;
        } else if (n.type === 'credential') {
            if (d.cred_type) h += `<div><span class="lbl">Tipo:</span> ${d.cred_type}</div>`;
            if (d.expires_at) h += `<div><span class="lbl">Expira:</span> ${new Date(d.expires_at).toLocaleDateString()}</div>`;
            h += `<div><span class="lbl">Cifrado:</span> ${d.is_encrypted ? 'Sí' : 'No'}</div>`;
        } else if (n.type === 'device_file' || n.type === 'config_file') {
            if (d.filename) h += `<div><span class="lbl">Archivo:</span> ${d.filename}</div>`;
            if (d.size) h += `<div><span class="lbl">Tamaño:</span> ${d.size < 1048576 ? (d.size / 1024).toFixed(1) + ' KB' : (d.size / 1048576).toFixed(1) + ' MB'}</div>`;
        } else if (n.type === 'config_template') {
            if (d.file_type) h += `<div><span class="lbl">Tipo:</span> .${d.file_type}</div>`;
            if (d.description) h += `<div><span class="lbl">Desc:</span> ${d.description}</div>`;
        }
        return h + '</div>';
    }

    function renderGraph(container, data, opts = {}) {
        const w = opts.width || container.clientWidth || 600;
        const h = opts.height || container.clientHeight || 450;
        const hiddenTypes = new Set(opts.hiddenTypes || []);
        const onNodeClick = opts.onNodeClick || null;
        const chargeStrength = opts.chargeStrength || -250;
        const linkDistance = opts.linkDistance || 90;

        container.innerHTML = '';
        const tooltip = createTooltip(container);

        const svg = d3.select(container).append('svg')
            .attr('width', '100%').attr('height', '100%')
            .attr('viewBox', [0, 0, w, h]);

        const zoomBehavior = d3.zoom().scaleExtent([0.1, 4]).on('zoom', e => g.attr('transform', e.transform));
        svg.call(zoomBehavior);
        const g = svg.append('g');

        // Filter by hidden types
        const nodes = data.nodes.filter(n => !hiddenTypes.has(n.type)).map(n => ({ ...n }));
        const nodeIds = new Set(nodes.map(n => n.id));
        const links = data.links.filter(l => nodeIds.has(l.source) && nodeIds.has(l.target)).map(l => ({ ...l }));

        const sim = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(linkDistance))
            .force('charge', d3.forceManyBody().strength(chargeStrength))
            .force('center', d3.forceCenter(w / 2, h / 2))
            .force('collision', d3.forceCollide().radius(d => (CONFIG.nodeRadius[d.type] || 16) + 12));

        const link = g.append('g').selectAll('line').data(links).enter().append('line')
            .attr('stroke', d => CONFIG.linkColors[d.relation] || '#cbd5e1')
            .attr('stroke-width', 1.5).attr('stroke-opacity', 0.5);

        const node = g.append('g').selectAll('g').data(nodes).enter().append('g')
            .attr('class', d => `node node-${d.type}`)
            .style('cursor', onNodeClick ? 'pointer' : 'grab')
            .call(d3.drag()
                .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
                .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
                .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));

        // Draw distinctive shape per type
        node.each(function (d) { drawNodeShape(d3.select(this), d); });

        // Letter label inside the shape
        node.append('text')
            .attr('text-anchor', 'middle').attr('dy', '0.38em')
            .attr('fill', '#fff')
            .attr('font-family', 'system-ui, -apple-system, sans-serif')
            .attr('font-weight', '700')
            .attr('font-size', d => Math.max(10, (CONFIG.nodeRadius[d.type] || 16) * 0.68) + 'px')
            .text(d => CONFIG.letters[d.type] || '?')
            .style('pointer-events', 'none');

        node.on('mouseenter', function (e, d) {
            d3.select(this).select('.node-shape').style('filter', 'brightness(1.25) drop-shadow(0 4px 12px rgba(0,0,0,0.35))');
            tooltip.innerHTML = formatTooltip(d);
            tooltip.style.display = 'block';
        }).on('mousemove', function (e) {
            const r = container.getBoundingClientRect();
            let x = e.clientX - r.left + 12, y = e.clientY - r.top + 12;
            if (x + 260 > r.width) x = e.clientX - r.left - 270;
            if (y + 160 > r.height) y = e.clientY - r.top - 170;
            tooltip.style.left = x + 'px'; tooltip.style.top = y + 'px';
        }).on('mouseleave', function () {
            d3.select(this).select('.node-shape').style('filter', 'none');
            tooltip.style.display = 'none';
        }).on('click', function (e, d) {
            if (onNodeClick) onNodeClick(d);
        });

        node.append('text')
            .attr('text-anchor', 'middle').attr('dy', d => (CONFIG.nodeRadius[d.type] || 16) + 14)
            .attr('fill', '#334155').attr('font-size', '10px').attr('font-weight', '500')
            .text(d => d.label.length > 14 ? d.label.substring(0, 13) + '…' : d.label)
            .style('pointer-events', 'none');

        sim.on('tick', () => {
            link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
            node.attr('transform', d => `translate(${d.x},${d.y})`);
        });

        function zoomToFit() {
            const bounds = g.node().getBBox();
            if (!bounds.width || !bounds.height) return;
            const scale = Math.min(0.9, Math.min(w / bounds.width, h / bounds.height) * 0.9);
            const tx = (w - bounds.width * scale) / 2 - bounds.x * scale;
            const ty = (h - bounds.height * scale) / 2 - bounds.y * scale;
            svg.transition().duration(600).call(zoomBehavior.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
        }

        // Auto fit after simulation settles
        sim.on('end', zoomToFit);

        return { svg, sim, zoomBehavior, zoomToFit };
    }

    window.RelationshipGraph = { render: renderGraph, CONFIG };
})();
