import { EXERCISES, getExercise, type ExerciseMeta, type GradeResult, type StartResult } from '../shared/exercises';
import { inspect } from './inspector';

// --- Types & state -------------------------------------------------------------------------------

interface Me {
  signedIn: boolean;
  fingerprint?: string;
  uid?: string;
  algo?: string;
  progress?: Record<string, number>;
  expiresAt?: string;
}
interface ServerKey {
  fingerprint: string;
  grouped: string;
  email: string;
  armored: string;
}
interface Pending {
  fingerprint: string;
  uid: string;
  algo: string;
  challenge: string;
  returning: boolean;
}

const state: { me: Me; server?: ServerKey; starts: Record<string, StartResult> } = { me: { signedIn: false }, starts: {} };
const PENDING_KEY = 'pgpractice.pending';

class ApiError extends Error {
  constructor(message: string, public hint?: string, public status = 0) {
    super(message);
  }
}

async function api<T>(path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  const res = await fetch(path, {
    method: init?.method ?? (init?.body ? 'POST' : 'GET'),
    headers: init?.body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
    credentials: 'same-origin',
  });
  let data: any = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON */
  }
  if (!res.ok) throw new ApiError(data?.error ?? `Request failed (${res.status})`, data?.hint, res.status);
  return data as T;
}

const storage = {
  get<T>(k: string): T | null {
    try {
      const v = sessionStorage.getItem(k);
      return v ? (JSON.parse(v) as T) : null;
    } catch {
      return null;
    }
  },
  set(k: string, v: unknown) {
    try {
      if (v === null) sessionStorage.removeItem(k);
      else sessionStorage.setItem(k, JSON.stringify(v));
    } catch {
      /* storage unavailable */
    }
  },
};

// --- DOM helpers -------------------------------------------------------------------------------

type Child = Node | string | null | undefined | false;
function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, unknown> = {},
  ...children: (Child | Child[])[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = String(v);
    else if (k === 'style') el.style.cssText = String(v); // CSSOM is allowed under our strict CSP; style attributes are not
    else if (k === 'html') el.innerHTML = String(v); // ONLY used for static, trusted lesson text
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v as EventListener);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(c));
  }
  return el;
}

function toast(msg: string) {
  const t = h('div', { class: 'toast', role: 'status' }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), 1800);
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied');
  } catch {
    toast('Copy failed — select the text manually');
  }
}

function download(name: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: 'text/plain' }));
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function fill(template: string, phrase?: string): string {
  return template
    .replaceAll('{SERVER_EMAIL}', state.server?.email ?? 'practice@pgpractice.appfarms.org')
    .replaceAll('{SERVER_FPR}', state.server?.fingerprint ?? '<server-fingerprint>')
    .replaceAll('{MY_FPR}', state.me.fingerprint ?? '<your-fingerprint>')
    .replaceAll('{ORIGIN}', location.origin)
    .replaceAll('{PHRASE}', phrase ?? '<phrase>');
}

function codeBlock(cmd: string) {
  return h('div', { class: 'code' }, h('pre', {}, h('code', {}, cmd)), h('button', { class: 'copy small', type: 'button', onclick: () => copy(cmd), 'aria-label': 'Copy command' }, 'Copy'));
}

function armoredBlock(name: string, content: string) {
  const slot = h('div');
  return h(
    'div',
    {},
    h(
      'div',
      { class: 'block-head' },
      h('strong', {}, name),
      h(
        'div',
        { class: 'actions' },
        h('button', { class: 'small secondary', type: 'button', onclick: () => copy(content) }, 'Copy'),
        h('button', { class: 'small secondary', type: 'button', onclick: () => download(name, content) }, 'Download'),
        h('button', { class: 'small ghost', type: 'button', onclick: () => toggleInspector(slot, content) }, 'Inspect packets'),
      ),
    ),
    h('div', { class: 'code' }, h('pre', { class: 'wrap' }, h('code', {}, content))),
    slot,
  );
}

async function toggleInspector(slot: HTMLElement, text: string) {
  if (slot.firstChild) {
    slot.replaceChildren();
    return;
  }
  try {
    const { type, packets, cleartext } = await inspect(text);
    const box = h(
      'div',
      { class: 'inspector' },
      h('p', { class: 'muted' }, `Armor type: ${type} — ${packets.length} packet(s). Parsed locally in your browser, like gpg --list-packets.`),
      cleartext !== undefined ? h('p', {}, h('strong', {}, 'Signed text: '), cleartext.slice(0, 300)) : null,
      packets.map((p) =>
        h(
          'div',
          { class: `packet${p.warning ? ' warn' : ''}`, style: `margin-left:${p.depth * 16}px` },
          h('div', { class: 'ptitle' }, `${p.name} `, h('small', {}, `tag ${p.tag}, ${p.length} bytes`)),
          p.warning ? h('div', {}, p.warning) : null,
          p.fields.length ? h('dl', { class: 'kv' }, p.fields.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])) : null,
        ),
      ),
    );
    slot.replaceChildren(box);
  } catch (e) {
    slot.replaceChildren(h('div', { class: 'inspector' }, `Could not parse: ${(e as Error).message}`));
  }
}

function resultPanel(r: GradeResult) {
  return h(
    'div',
    { class: `result ${r.ok ? 'ok' : 'bad'}`, role: 'status' },
    h('h3', {}, (r.ok ? '✓ ' : '✗ ') + r.headline),
    r.details.length ? h('ul', {}, r.details.map((d) => h('li', {}, d))) : null,
    r.plaintext !== undefined ? h('div', {}, h('strong', {}, 'Decrypted text:'), h('div', { class: 'code' }, h('pre', { class: 'wrap' }, h('code', {}, r.plaintext)))) : null,
    r.hint ? h('p', { class: 'hint' }, r.hint) : null,
  );
}

function errorPanel(e: unknown) {
  const err = e instanceof ApiError ? e : new ApiError((e as Error)?.message ?? String(e));
  return h('div', { class: 'result bad', role: 'alert' }, h('h3', {}, '✗ ' + err.message), err.hint ? h('p', { class: 'hint' }, err.hint) : null);
}

/** Refuse private keys before they ever leave the browser. */
function guardTextarea(ta: HTMLTextAreaElement, out: HTMLElement) {
  ta.addEventListener('input', () => {
    if (/-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(ta.value)) {
      ta.value = '';
      out.replaceChildren(
        h(
          'div',
          { class: 'result bad', role: 'alert' },
          h('h3', {}, '⚠ That was a PRIVATE key — it has been cleared and was not sent.'),
          h('p', {}, 'Your private key must never leave your machine. Export only the public key with gpg --armor --export <email>. If you pasted a real secret key into another site, consider it compromised.'),
        ),
      );
    }
  });
}

async function withBusy(btn: HTMLButtonElement, fn: () => Promise<void>) {
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Working…';
  try {
    await fn();
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
}

// --- Navigation & account ------------------------------------------------------------------------

const done = (id: string) => !!state.me.progress?.[id];
const doneCount = () => EXERCISES.filter((e) => done(e.id)).length;
const isDesktop = () => window.matchMedia('(min-width: 861px)').matches;

function renderNav(currentId?: string) {
  const nav = document.getElementById('nav')!;
  const pct = Math.round((doneCount() / EXERCISES.length) * 100);
  const details = h(
    'details',
    { open: isDesktop() },
    h('summary', {}, h('span', {}, `Exercises · ${doneCount()}/${EXERCISES.length}`), h('span', { class: 'toggle', 'aria-hidden': 'true' }, '▾')),
    h('div', { class: 'progressbar', role: 'progressbar', 'aria-valuenow': pct, 'aria-valuemin': 0, 'aria-valuemax': 100 }, h('span', { style: `width:${pct}%` })),
    h(
      'ol',
      {},
      h('li', {}, h('a', { href: '#/', 'aria-current': currentId === undefined ? 'page' : undefined }, h('span', { class: 'badge' }, '⌂'), 'Home')),
      EXERCISES.map((e, i) =>
        h(
          'li',
          {},
          h(
            'a',
            { href: `#/ex/${e.id}`, 'aria-current': currentId === e.id ? 'page' : undefined },
            h('span', { class: `badge${done(e.id) ? ' done' : ''}`, 'aria-label': done(e.id) ? 'completed' : undefined }, done(e.id) ? '✓' : String(i + 1)),
            e.title,
          ),
        ),
      ),
    ),
  );
  nav.replaceChildren(details);
}

function renderAccount() {
  const el = document.getElementById('account')!;
  if (!state.me.signedIn) {
    el.replaceChildren(h('span', { class: 'muted label' }, 'Not signed in'));
    return;
  }
  el.replaceChildren(
    h('span', { class: 'chip', title: state.me.fingerprint }, `🔑 …${state.me.fingerprint!.slice(-16)}`),
    h('button', { class: 'small secondary', type: 'button', onclick: logout }, 'Sign out'),
  );
}

async function logout() {
  await api('/api/logout', { body: {} }).catch(() => undefined);
  state.me = { signedIn: false };
  state.starts = {};
  location.hash = '#/';
  await refresh();
}

async function refresh() {
  state.me = await api<Me>('/api/me').catch(() => ({ signedIn: false }));
  render();
}

// --- Views -------------------------------------------------------------------------------------

function serverKeyCard() {
  const s = state.server;
  return h(
    'section',
    { class: 'card' },
    h('h2', {}, 'The PGPractice server key'),
    s
      ? h(
          'div',
          {},
          h('dl', { class: 'kv' }, h('dt', {}, 'User ID'), h('dd', {}, `PGPractice <${s.email}>`), h('dt', {}, 'Fingerprint'), h('dd', { class: 'fpr' }, s.grouped)),
          h('p', { class: 'muted', style: 'margin-top:10px' }, 'Import it with Web Key Directory or straight from this site:'),
          codeBlock(`gpg --auto-key-locate clear,wkd,nodefault --locate-keys ${s.email}`),
          codeBlock(`curl -s ${location.origin}/api/server-key.asc | gpg --import`),
          armoredBlock('pgpractice.asc', s.armored),
        )
      : h('p', { class: 'muted' }, 'Loading…'),
  );
}

function viewHomeSignedOut(main: HTMLElement) {
  const pending = storage.get<Pending>(PENDING_KEY);
  const hero = h(
    'section',
    { class: 'card hero' },
    h('h1', {}, 'Practice GnuPG with a patient partner'),
    h('p', {}, 'Upload your public key, then encrypt, sign, decrypt and verify messages with this site using the real ', h('code', {}, 'gpg'), ' command line. Each exercise checks your work and explains what went wrong.'),
    h('p', { class: 'muted' }, 'No account needed — your key is your identity. All data is deleted after 30 days of inactivity.'),
  );

  const out = h('div');
  const ta = h('textarea', { id: 'pubkey', class: 'mono', placeholder: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n…\n-----END PGP PUBLIC KEY BLOCK-----', spellcheck: 'false', autocomplete: 'off' });
  guardTextarea(ta, out);
  const uploadBtn = h('button', { type: 'submit' }, 'Upload public key');
  const upload = h(
    'form',
    {
      class: 'card',
      onsubmit: (ev: Event) => {
        ev.preventDefault();
        withBusy(uploadBtn, async () => {
          out.replaceChildren();
          try {
            const r = await api<{ key: { fingerprint: string; uid: string; algo: string }; challenge: string; returning: boolean }>('/api/keys', { body: { armored: ta.value } });
            storage.set(PENDING_KEY, { fingerprint: r.key.fingerprint, uid: r.key.uid, algo: r.key.algo, challenge: r.challenge, returning: r.returning });
            render();
            document.getElementById('step2')?.scrollIntoView({ behavior: 'smooth' });
          } catch (e) {
            out.replaceChildren(errorPanel(e));
          }
        });
      },
    },
    h('h2', {}, 'Step 1 — Upload your public key'),
    h('p', {}, "Don't have a key yet? Follow ", h('a', { href: '#/ex/upload' }, 'exercise 1'), ', then export it:'),
    codeBlock('gpg --armor --export you@example.com'),
    h('label', { for: 'pubkey', style: 'margin-top:14px' }, 'Your ASCII-armored public key'),
    ta,
    h('div', { class: 'form-row' }, uploadBtn),
    out,
  );

  const parts: Node[] = [hero, upload];
  if (pending) {
    const vout = h('div');
    const code = h('input', { type: 'text', id: 'code', placeholder: 'ABCD-EFGH-JKLM', autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false' });
    const vbtn = h('button', { type: 'submit' }, 'Verify & sign in');
    parts.push(
      h(
        'form',
        {
          class: 'card',
          id: 'step2',
          onsubmit: (ev: Event) => {
            ev.preventDefault();
            withBusy(vbtn, async () => {
              vout.replaceChildren();
              try {
                await api('/api/keys/verify', { body: { fingerprint: pending.fingerprint, code: code.value } });
                storage.set(PENDING_KEY, null);
                toast('Signed in');
                await refresh();
              } catch (e) {
                vout.replaceChildren(errorPanel(e));
              }
            });
          },
        },
        h('h2', {}, 'Step 2 — Decrypt your challenge'),
        h('dl', { class: 'kv' }, h('dt', {}, 'Key'), h('dd', { class: 'fpr' }, pending.fingerprint.replace(/(.{4})/g, '$1 ').trim()), h('dt', {}, 'User ID'), h('dd', {}, pending.uid || '—'), h('dt', {}, 'Algorithm'), h('dd', {}, pending.algo)),
        pending.returning ? h('p', { class: 'muted', style: 'margin-top:10px' }, 'Welcome back! This key is already registered, so the challenge is encrypted to the version stored on the server.') : null,
        h('p', { style: 'margin-top:10px' }, 'This message is encrypted to your key and signed by PGPractice. Save it as ', h('code', {}, 'challenge.asc'), ' and decrypt it:'),
        codeBlock('gpg --decrypt challenge.asc'),
        h('p', { class: 'muted', style: 'margin-top:8px' }, 'If GnuPG says “Can’t check signature: No public key”, that is expected — you have not imported the server key yet (that is exercise 2, below). Decryption still worked.'),
        armoredBlock('challenge.asc', pending.challenge),
        h('label', { for: 'code', style: 'margin-top:14px' }, 'Verification code from the decrypted message'),
        code,
        h('div', { class: 'form-row' }, vbtn, h('button', { type: 'button', class: 'ghost', onclick: () => { storage.set(PENDING_KEY, null); render(); } }, 'Start over')),
        vout,
      ),
    );
  }
  parts.push(serverKeyCard());
  main.replaceChildren(...parts);
}

function viewHomeSignedIn(main: HTMLElement) {
  const me = state.me;
  const next = EXERCISES.find((e) => !done(e.id));
  const forget = async () => {
    if (!confirmInline.dataset.armed) {
      confirmInline.dataset.armed = '1';
      confirmInline.textContent = 'Click again to permanently delete';
      return;
    }
    await api('/api/me', { method: 'DELETE', body: {} });
    toast('All your data was deleted');
    state.me = { signedIn: false };
    location.hash = '#/';
    await refresh();
  };
  const confirmInline = h('button', { type: 'button', class: 'danger small', onclick: forget }, 'Delete my data');
  main.replaceChildren(
    h(
      'section',
      { class: 'card hero' },
      h('h1', {}, doneCount() === EXERCISES.length ? 'All exercises complete 🎉' : 'Welcome back'),
      h('dl', { class: 'kv' }, h('dt', {}, 'Key'), h('dd', { class: 'fpr' }, me.fingerprint!.replace(/(.{4})/g, '$1 ').trim()), h('dt', {}, 'User ID'), h('dd', {}, me.uid || '—'), h('dt', {}, 'Algorithm'), h('dd', {}, me.algo ?? '')),
      h('p', { style: 'margin-top:12px' }, `Progress: ${doneCount()} of ${EXERCISES.length} exercises.`),
      h('div', { class: 'form-row' }, next ? h('a', { class: 'btn', href: `#/ex/${next.id}` }, `Next: ${next.title} →`) : null, confirmInline),
      h('p', { class: 'muted', style: 'margin-top:12px' }, `Your data will be deleted on ${new Date(me.expiresAt!).toLocaleDateString()} unless you keep practicing.`),
    ),
    h(
      'section',
      { class: 'grid' },
      EXERCISES.map((e, i) =>
        h(
          'a',
          { class: 'card ex-card', href: `#/ex/${e.id}` },
          h('div', { class: 'head' }, h('span', { class: `badge${done(e.id) ? ' done' : ''}` }, done(e.id) ? '✓' : String(i + 1)), e.title),
          h('p', {}, e.summary),
        ),
      ),
    ),
    serverKeyCard(),
  );
}

function viewExercise(main: HTMLElement, ex: ExerciseMeta) {
  const idx = EXERCISES.indexOf(ex);
  const start = state.starts[ex.id];
  const steps = h(
    'ol',
    { class: 'steps' },
    ex.steps.map((s) => h('li', {}, h('div', { html: fill(s.text) }), s.cmd ? codeBlock(fill(s.cmd, start?.phrase)) : null)),
  );
  const header = h(
    'section',
    { class: 'card' },
    h('p', { class: 'muted' }, `Exercise ${idx + 1} of ${EXERCISES.length}${done(ex.id) ? ' · ✓ completed' : ''}`),
    h('h1', {}, ex.title),
    h('p', {}, ex.summary),
    steps,
    ex.pitfalls?.length ? h('div', {}, h('h3', {}, 'Common pitfalls'), h('ul', { class: 'pitfalls' }, ex.pitfalls.map((p) => h('li', { html: p })))) : null,
  );

  const parts: Node[] = [header];
  const nextEx = EXERCISES[idx + 1];

  if (ex.input === 'none') {
    parts.push(
      h(
        'section',
        { class: 'card' },
        state.me.signedIn
          ? h('p', {}, done(ex.id) ? '✓ Completed when you signed in.' : 'Completed on the home page when you sign in.')
          : h('p', {}, 'This exercise is completed on the ', h('a', { href: '#/' }, 'home page'), ' when you upload your key and decrypt the challenge.'),
      ),
    );
  } else if (!state.me.signedIn) {
    parts.push(h('section', { class: 'result warn' }, h('h3', {}, 'Sign in first'), h('p', {}, 'Upload your public key and decrypt the challenge on the ', h('a', { href: '#/' }, 'home page'), ' to unlock the exercises.')));
  } else {
    parts.push(exerciseWork(ex, start));
  }

  if (nextEx) parts.push(h('div', { class: 'form-row' }, h('a', { class: 'btn secondary', href: `#/ex/${nextEx.id}` }, `Next: ${nextEx.title} →`)));
  main.replaceChildren(...parts);
}

function exerciseWork(ex: ExerciseMeta, start?: StartResult) {
  const out = h('div');
  const card = h('section', { class: 'card' });

  if (ex.hasStart) {
    const startBtn = h('button', { type: 'button', class: start ? 'secondary' : '' }, start ? 'New challenge' : 'Start exercise');
    startBtn.addEventListener('click', () =>
      withBusy(startBtn, async () => {
        try {
          state.starts[ex.id] = await api<StartResult>(`/api/exercises/${ex.id}/start`, { body: {} });
          render();
        } catch (e) {
          out.replaceChildren(errorPanel(e));
        }
      }),
    );
    card.append(h('div', { class: 'form-row', style: 'margin-top:0' }, startBtn));
    if (!start) {
      card.append(h('p', { class: 'muted', style: 'margin-top:10px' }, 'Press start to get your personal challenge.'), out);
      return card;
    }
    if (start.prompt) card.append(h('p', { class: 'result warn', style: 'margin-top:12px' }, start.prompt));
    if (start.file) {
      const f = start.file;
      card.append(
        h('div', { class: 'block-head' }, h('strong', {}, f.name), h('button', { type: 'button', class: 'small', onclick: () => download(f.name, f.content) }, `Download ${f.name}`)),
        h('div', { class: 'code' }, h('pre', { class: 'wrap' }, h('code', {}, f.content))),
      );
    }
    start.blocks?.forEach((b) => card.append(armoredBlock(b.name, b.content)));
  }

  const form = h('form', { style: 'margin-top:14px' });
  const submitBtn = h('button', { type: 'submit' }, 'Check');
  let getBody: () => Record<string, unknown>;

  if (ex.input === 'armored') {
    const ta = h('textarea', { id: `in-${ex.id}`, class: 'mono', spellcheck: 'false', autocomplete: 'off', placeholder: ex.inputLabel });
    guardTextarea(ta, out);
    const slot = h('div');
    form.append(
      h('label', { for: ta.id }, ex.inputLabel ?? 'Your answer'),
      ta,
      h('div', { class: 'form-row' }, submitBtn, h('button', { type: 'button', class: 'ghost', onclick: () => toggleInspector(slot, ta.value) }, 'Inspect packets')),
      slot,
    );
    getBody = () => ({ armored: ta.value });
  } else if (ex.input === 'text') {
    const inp = h('input', { type: 'text', id: `in-${ex.id}`, autocomplete: 'off', spellcheck: 'false' });
    form.append(h('label', { for: inp.id }, ex.inputLabel ?? 'Your answer'), inp, h('div', { class: 'form-row' }, submitBtn));
    getBody = () => ({ answer: inp.value });
  } else {
    const boxes = (start?.choices ?? []).map((c, i) => h('input', { type: 'checkbox', value: String(i), id: `ch-${i}` }));
    form.append(
      h('fieldset', { style: 'border:0;padding:0;margin:0' }, h('legend', { style: 'font-weight:600;margin-bottom:6px' }, ex.inputLabel ?? 'Choose'), h('div', { class: 'choices' }, boxes.map((b, i) => h('label', { for: b.id }, b, start!.choices![i])))),
      h('div', { class: 'form-row' }, submitBtn),
    );
    getBody = () => ({ choices: boxes.filter((b) => b.checked).map((b) => Number(b.value)) });
  }

  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    withBusy(submitBtn, async () => {
      out.replaceChildren();
      try {
        const r = await api<GradeResult>(`/api/exercises/${ex.id}/submit`, { body: getBody() });
        out.replaceChildren(resultPanel(r));
        if (r.ok) {
          delete state.starts[ex.id];
          state.me = await api<Me>('/api/me');
          renderNav(ex.id);
          renderAccount();
        }
      } catch (e) {
        out.replaceChildren(errorPanel(e));
        if (e instanceof ApiError && e.status === 401) await refresh();
      }
      out.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  });

  card.append(form, out);
  return card;
}

// --- Router ------------------------------------------------------------------------------------

function render() {
  const main = document.getElementById('main')!;
  const m = location.hash.match(/^#\/ex\/([\w-]+)/);
  const ex = m ? getExercise(m[1]) : undefined;
  renderAccount();
  renderNav(ex?.id);
  if (ex) viewExercise(main, ex);
  else if (state.me.signedIn) viewHomeSignedIn(main);
  else viewHomeSignedOut(main);
  document.title = ex ? `${ex.title} · PGPractice` : 'PGPractice';
}

window.addEventListener('hashchange', () => {
  render();
  window.scrollTo(0, 0);
  document.getElementById('main')?.focus({ preventScroll: true });
});
window.matchMedia('(min-width: 861px)').addEventListener('change', () => renderNav(getExercise(location.hash.split('/')[2] ?? '')?.id));

(async function init() {
  render();
  const [server] = await Promise.all([api<ServerKey>('/api/server-key').catch(() => undefined), refresh()]);
  state.server = server;
  const f = document.getElementById('footer-fpr');
  if (f && server) f.textContent = server.grouped;
  render();
})();
