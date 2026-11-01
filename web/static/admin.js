(function () {
  const $ = (id) => document.getElementById(id);
  const human = (n) => n >= 1 << 30 ? (n / (1 << 30)).toFixed(1) + 'GB'
    : n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + 'MB'
    : n >= 1 << 10 ? (n / (1 << 10)).toFixed(1) + 'KB' : n + 'B';
  const when = (s) => s ? new Date(s).toLocaleString('ko-KR', { dateStyle: 'short', timeStyle: 'short' }) : '없음';
  const el = (tag, text, cls) => { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; };

  async function api(method, url, body) {
    const res = await fetch(url, {
      method, headers: { 'X-Drop': '1', 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 204) return null;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `오류 (${res.status})`);
    return data;
  }

  document.querySelectorAll('.tabs [role=tab]').forEach((b) => b.addEventListener('click', () => {
    document.querySelectorAll('.tabs [role=tab]').forEach((x) => x.setAttribute('aria-selected', x === b));
    document.querySelectorAll('.tab').forEach((t) => { t.hidden = t.id !== b.dataset.tab; });
    if (b.dataset.tab === 't-drops') loadDrops();
    if (b.dataset.tab === 't-tokens') loadTokens();
  }));

  async function loadDrops() {
    const data = await api('GET', '/admin/api/drops');
    $('usage').textContent = `사용 ${human(data.used_bytes)} / ${human(data.max_total_bytes)}`;
    const rows = data.drops.map((d) => {
      const tr = el('tr');
      const id = el('td'); id.append(el('code', d.id)); if (d.pending) id.append(el('span', ' 업로드 중', 'muted'));
      tr.append(id, el('td', `${d.files.length}개 · ${human(d.bytes)}`), el('td', when(d.expires_at)),
        el('td', d.created_by), el('td', String(d.downloads)));
      const act = el('td'); const del = el('button', '삭제', 'ghost danger');
      del.onclick = async () => { if (confirm(`${d.id} 를 지울까요?`)) { await api('DELETE', `/admin/api/drops/${encodeURIComponent(d.id)}`); loadDrops(); } };
      act.append(del); tr.append(act);
      return tr;
    });
    $('drops').replaceChildren(...(rows.length ? rows : [emptyRow(6, '보관함이 없습니다')]));
  }

  async function loadTokens() {
    const toks = await api('GET', '/admin/api/tokens');
    const rows = toks.map((t) => {
      const tr = el('tr');
      tr.append(el('td', t.label || t.id), el('td', t.kind === 'link' ? '업로드 링크' : 'API 키'),
        el('td', t.max_uses ? `${t.uses}/${t.max_uses}` : String(t.uses)), el('td', when(t.expires_at)),
        el('td', t.revoked ? '취소됨' : t.usable ? '사용 가능' : '만료', t.usable ? '' : 'muted'));
      const act = el('td');
      if (t.usable) {
        const b = el('button', '취소', 'ghost danger');
        b.onclick = async () => { if (confirm('취소할까요?')) { await api('DELETE', `/admin/api/tokens/${t.id}`); loadTokens(); } };
        act.append(b);
      }
      tr.append(act);
      return tr;
    });
    $('tokens').replaceChildren(...(rows.length ? rows : [emptyRow(6, '발급한 링크·키가 없습니다')]));
  }

  function emptyRow(n, text) { const tr = el('tr'); const td = el('td', text, 'muted'); td.colSpan = n; tr.append(td); return tr; }

  function showSecret(title, value) {
    $('secret').hidden = false; $('secret-title').textContent = title; $('secret-value').textContent = value;
    $('secret-copy').textContent = '복사';
    $('secret-copy').onclick = () => navigator.clipboard.writeText(value).then(() => { $('secret-copy').textContent = '복사했어요'; });
  }

  function bindTokenForm(id, kind) {
    const f = $(id);
    f.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const fd = new FormData(f);
      const body = { kind, label: fd.get('label'), valid_hours: Number(fd.get('valid_hours')), max_days: Number(fd.get('max_days')) };
      if (kind === 'link') body.max_uses = Number(fd.get('max_uses'));
      try {
        const r = await api('POST', '/admin/api/tokens', body);
        showSecret(kind === 'link' ? '업로드 링크' : 'API 키', r.url || r.secret);
        f.reset(); loadTokens();
      } catch (e) { alert(e.message); }
    });
  }
  bindTokenForm('new-link', 'link');
  bindTokenForm('new-key', 'apikey');
})();
