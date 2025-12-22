(function () {
    'use strict';

    if (typeof d3 === 'undefined') {
        console.error('D3.js required for graph');
        return;
    }

    const CONFIG = {
        nodeRadius: { user: 28, device: 22, credential: 16 },
        colors: { user: '#009f8c', device: '#6366f1', credential: '#f59e0b' },
        linkColors: { owner: '#009f8c', assigned: '#6366f1', has_credential: '#f59e0b' },
        icons: { user: '\uf007', device: '\uf2db', credential: '\uf084' }
    };

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
        let h = `<div class="tt-head"><strong>${n.label}</strong></div>`;
        h += `<div class="tt-type">${n.type.toUpperCase()}</div><div class="tt-body">`;
        if (n.type === 'user') {
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
        }
        return h + '</div>';
    }

    function renderGraph(container, data, opts = {}) {
        const w = opts.width || container.clientWidth || 600;
        const h = opts.height || container.clientHeight || 450;
        container.innerHTML = '';
        const tooltip = createTooltip(container);

        const svg = d3.select(container).append('svg')
            .attr('width', '100%').attr('height', '100%')
            .attr('viewBox', [0, 0, w, h]);

        const g = svg.append('g');
        svg.call(d3.zoom().scaleExtent([0.3, 3]).on('zoom', e => g.attr('transform', e.transform)));

        const nodes = data.nodes.map(n => ({ ...n }));
        const links = data.links.map(l => ({ ...l }));

        const sim = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(90))
            .force('charge', d3.forceManyBody().strength(-250))
            .force('center', d3.forceCenter(w / 2, h / 2))
            .force('collision', d3.forceCollide().radius(d => CONFIG.nodeRadius[d.type] + 8));

        const link = g.append('g').selectAll('line').data(links).enter().append('line')
            .attr('stroke', d => CONFIG.linkColors[d.relation] || '#999')
            .attr('stroke-width', 2).attr('stroke-opacity', 0.6);

        const node = g.append('g').selectAll('g').data(nodes).enter().append('g')
            .attr('class', d => `node node-${d.type}`)
            .call(d3.drag()
                .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
                .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
                .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));

        node.append('circle')
            .attr('r', d => CONFIG.nodeRadius[d.type])
            .attr('fill', d => CONFIG.colors[d.type])
            .attr('stroke', '#fff').attr('stroke-width', 2)
            .style('cursor', 'pointer');

        node.append('text')
            .attr('text-anchor', 'middle').attr('dy', '0.35em')
            .attr('fill', '#fff').attr('font-family', 'Font Awesome 6 Free, FontAwesome')
            .attr('font-weight', '900').attr('font-size', d => CONFIG.nodeRadius[d.type] * 0.7 + 'px')
            .text(d => CONFIG.icons[d.type]).style('pointer-events', 'none');

        node.on('mouseenter', function (e, d) {
            d3.select(this).select('circle').style('filter', 'brightness(1.2) drop-shadow(0 4px 8px rgba(0,0,0,0.3))');
            tooltip.innerHTML = formatTooltip(d);
            tooltip.style.display = 'block';
        }).on('mousemove', function (e) {
            const r = container.getBoundingClientRect();
            let x = e.clientX - r.left + 12, y = e.clientY - r.top + 12;
            if (x + 260 > r.width) x = e.clientX - r.left - 270;
            if (y + 140 > r.height) y = e.clientY - r.top - 150;
            tooltip.style.left = x + 'px'; tooltip.style.top = y + 'px';
        }).on('mouseleave', function () {
            d3.select(this).select('circle').style('filter', 'none');
            tooltip.style.display = 'none';
        });

        node.append('text')
            .attr('text-anchor', 'middle').attr('dy', d => CONFIG.nodeRadius[d.type] + 14)
            .attr('fill', '#334155').attr('font-size', '10px').attr('font-weight', '500')
            .text(d => d.label.length > 12 ? d.label.substring(0, 11) + '…' : d.label)
            .style('pointer-events', 'none');

        sim.on('tick', () => {
            link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
            node.attr('transform', d => `translate(${d.x},${d.y})`);
        });

        return { svg, sim };
    }

    window.RelationshipGraph = { render: renderGraph, CONFIG };
})();
