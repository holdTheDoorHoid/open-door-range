/*
 * topology.js — the physical truth, drawn.
 *
 * The one thing this view must get right: an INLINE tap cuts the link and sits
 * between the two halves. That is why the implant works, and a learner who has
 * seen the link severed understands it without being told. A sniff tap does not
 * cut anything — it hangs off the link on a lead — and the difference has to be
 * visible at a glance from the back of a room.
 */

import { svg, clear, prefersReducedMotion } from '../util.js';

const W = 1120, H = 200;
const NODE_W = 140, NODE_H = 76;
const Y = 70;                       // node top
const CY = Y + NODE_H / 2;          // link centreline

const POS = {
  card: 30,
  reader: 250,
  controller: 560,
  door: 880,
};

const TAP_W = 120, TAP_H = 48;

export function renderTopology(host, { topology, state, onNode, onLink, onTap }) {
  clear(host);
  const root = svg('svg', {
    viewBox: `0 0 ${W} ${H}`, role: 'group',
    'aria-label': 'Card, reader, link, controller, door — with the taps you have placed',
  });

  // ---- links first so nodes sit on top -------------------------------
  for (const link of topology.links) {
    const x1 = POS[link.from] + NODE_W;
    const x2 = POS[link.to];
    const tap = topology.taps.find((t) => t.linkId === link.id);
    const inline = tap && tap.mode === 'inline';
    const kindClass = link.id === 'card-reader' ? 'rf' : (link.protocol === 'osdp' ? 'osdp' : 'wire');
    const mid = (x1 + x2) / 2;

    const g = svg('g', {
      class: 'link',
      tabindex: link.tappable ? '0' : null,
      role: link.tappable ? 'button' : 'presentation',
      'aria-label': link.tappable
        ? `${linkName(link)} link. ${tap ? `Tap placed: ${tap.mode}.` : 'No tap placed.'} Activate to place or change a tap.`
        : null,
    });

    if (inline) {
      // The link is CUT. Two stubs, a gap, and the implant sitting in the gap.
      const gapL = mid - TAP_W / 2 - 10;
      const gapR = mid + TAP_W / 2 + 10;
      g.append(svg('line', { class: `link__line link__line--${kindClass}`, x1, y1: CY, x2: gapL, y2: CY }));
      g.append(svg('line', { class: `link__line link__line--${kindClass}`, x1: gapR, y1: CY, x2, y2: CY }));
      // the severed ends, drawn as ends rather than a continuous run
      g.append(svg('line', { x1: gapL, y1: CY - 9, x2: gapL, y2: CY + 9, stroke: 'var(--attack)', 'stroke-width': 3 }));
      g.append(svg('line', { x1: gapR, y1: CY - 9, x2: gapR, y2: CY + 9, stroke: 'var(--attack)', 'stroke-width': 3 }));
    } else {
      g.append(svg('line', { class: `link__line link__line--${kindClass}`, x1, y1: CY, x2, y2: CY }));
      g.append(svg('polygon', {
        points: `${x2},${CY} ${x2 - 12},${CY - 7} ${x2 - 12},${CY + 7}`,
        fill: 'var(--border-strong)',
      }));
    }
    g.append(svg('text', { class: 'link__label', x: mid, y: CY - 16 }, linkName(link)));
    if (link.tappable) {
      const hit = svg('line', { class: 'link__hit', x1, y1: CY, x2, y2: CY });
      g.append(hit);
      g.addEventListener('click', () => onLink(link));
      g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onLink(link); } });
    }
    root.append(g);

    if (tap) root.append(tapGroup(tap, link, mid, onTap));
  }

  // ---- nodes ----------------------------------------------------------
  for (const node of topology.nodes) {
    if (node.id === 'door') { root.append(doorGroup(node, state, onNode)); continue; }
    const x = POS[node.id];
    const g = svg('g', {
      class: 'node', tabindex: '0', role: 'button',
      'aria-label': `${node.label} (${node.sub}). Activate to configure.`,
      onclick: () => onNode(node),
      onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onNode(node); } },
    });
    g.append(svg('rect', { x, y: Y, width: NODE_W, height: NODE_H, rx: 8 }));
    g.append(svg('text', { x: x + NODE_W / 2, y: Y + 32, 'text-anchor': 'middle', 'font-size': 20, 'font-weight': 650 }, node.label));
    g.append(svg('text', { class: 'node__sub', x: x + NODE_W / 2, y: Y + 54, 'text-anchor': 'middle' }, node.sub));
    root.append(g);
  }

  host.append(root);
  return root;
}

function linkName(link) {
  if (link.id === 'card-reader') return 'rf';
  if (link.id === 'controller-door') return 'strike';
  return link.protocol === 'osdp' ? 'osdp / rs-485' : (link.protocol === 'clockdata' ? 'clock+data' : 'wiegand d0/d1');
}

function tapGroup(tap, link, mid, onTap) {
  const inline = tap.mode === 'inline';
  const boxY = inline ? CY - TAP_H / 2 : CY + 34;
  const g = svg('g', {
    class: 'tap', tabindex: '0', role: 'button',
    'aria-label': `${tap.mode} tap on the ${linkName(link)} link${inline ? ', cutting it' : ''}. Activate to change or remove.`,
    onclick: () => onTap(tap),
    onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onTap(tap); } },
  });
  if (!inline) {
    g.append(svg('path', { class: 'tap__lead', d: `M ${mid} ${CY} L ${mid} ${boxY}` }));
  }
  g.append(svg('rect', { x: mid - TAP_W / 2, y: boxY, width: TAP_W, height: TAP_H, rx: 6 }));
  g.append(svg('text', { x: mid, y: boxY + 20 }, tap.mode.toUpperCase()));
  g.append(svg('text', { x: mid, y: boxY + 37, 'font-size': 11, 'font-weight': 400 },
    inline ? 'link cut — in path' : (tap.mode === 'inject' ? 'writes to the link' : 'listening only')));
  return g;
}

function doorGroup(node, state, onNode) {
  const x = POS.door;
  const open = state.door === 'open';
  const hingeX = x + 20, hingeY = CY;
  const g = svg('g', {
    class: 'node node--door', tabindex: '0', role: 'button',
    'aria-label': `Door: ${open ? 'OPEN, strike energised' : 'closed and locked'}. Activate to configure the controller.`,
    onclick: () => onNode(node),
    onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onNode(node); } },
  });
  // frame, in plan view: wall, gap, wall
  g.append(svg('rect', { class: 'focusable', x: x - 10, y: CY - 26, width: 20, height: 52, fill: 'var(--surface-3)', stroke: 'var(--border-strong)', 'stroke-width': 2 }));
  g.append(svg('rect', { x: x + 168, y: CY - 26, width: 20, height: 52, fill: 'var(--surface-3)', stroke: 'var(--border-strong)', 'stroke-width': 2 }));

  const leaf = svg('rect', {
    class: 'doorleaf' + (open ? ' doorleaf--open' : ''),
    x: hingeX, y: hingeY - 6, width: 128, height: 12, rx: 2,
  });
  leaf.style.transformOrigin = `${hingeX}px ${hingeY}px`;
  leaf.style.transformBox = 'view-box';
  if (prefersReducedMotion()) leaf.style.transition = 'none';
  g.append(leaf);

  // The state is also a word and a shape, never colour alone.
  g.append(svg('text', {
    class: `door-state door-state--${open ? 'open' : 'closed'}`,
    x: x + 94, y: CY + 56,
  }, open ? '▲ OPEN — strike energised' : '■ CLOSED — locked'));
  g.append(svg('text', { class: 'node__sub', x: x + 94, y: Y + 6, 'text-anchor': 'middle' }, 'Door'));
  return g;
}
