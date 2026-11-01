// 조각 업로더. Traefik readTimeout(60초) 안에 끝나도록 파일을 chunk_bytes 단위로 나눠 보내고,
// 실패하면 서버가 받은 위치(409 의 received)부터 이어 보낸다.
(function () {
  const form = document.getElementById('uploader');
  if (!form) return;
  const api = form.dataset.api;
  const maxFile = Number(form.dataset.maxFile);
  const maxFiles = Number(form.dataset.maxFiles);
  const $ = (id) => document.getElementById(id);
  const input = $('files'), zone = $('zone'), picked = $('picked'), go = $('go');
  const bar = $('bar'), ptext = $('ptext'), progress = $('progress'), uerr = $('uerr');
  let files = [];

  const human = (n) => n >= 1 << 30 ? (n / (1 << 30)).toFixed(1) + 'GB'
    : n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + 'MB'
    : n >= 1 << 10 ? (n / (1 << 10)).toFixed(1) + 'KB' : n + 'B';

  function setFiles(list) {
    files = Array.from(list).slice(0, maxFiles);
    picked.replaceChildren(...files.map((f) => {
      const li = document.createElement('li');
      const name = document.createElement('span'); name.textContent = f.name;
      const size = document.createElement('span'); size.className = 'muted'; size.textContent = human(f.size);
      if (f.size > maxFile) { li.className = 'bad'; size.textContent += ' — 너무 큼'; }
      li.append(name, size);
      return li;
    }));
    go.disabled = files.length === 0 || files.some((f) => f.size > maxFile);
  }
  input.addEventListener('change', () => setFiles(input.files));
  ['dragenter', 'dragover'].forEach((e) => zone.addEventListener(e, (ev) => { ev.preventDefault(); zone.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((e) => zone.addEventListener(e, () => zone.classList.remove('over')));
  zone.addEventListener('drop', (ev) => { ev.preventDefault(); setFiles(ev.dataTransfer.files); });

  async function call(method, url, body, headers) {
    const res = await fetch(url, { method, body, headers: Object.assign({ 'X-Drop': '1' }, headers || {}) });
    let data = null;
    try { data = await res.json(); } catch (_) { /* 본문 없음 */ }
    return { res, data };
  }

  async function sendFile(base, n, file, chunk, onBytes) {
    let offset = 0, tries = 0;
    // 빈 파일은 시작할 때 이미 만들어져 있으므로 보낼 것이 없다.
    while (offset < file.size) {
      const end = Math.min(offset + chunk, file.size);
      let r;
      try {
        r = await call('PUT', `${base}/files/${n}?offset=${offset}`, file.slice(offset, end), { 'Content-Type': 'application/octet-stream' });
      } catch (e) {
        r = null;
      }
      if (r && r.res.ok) {
        onBytes(r.data.received - offset);
        offset = r.data.received; tries = 0;
        continue;
      }
      if (r && r.res.status === 409 && r.data && typeof r.data.received === 'number') {
        onBytes(r.data.received - offset);
        offset = r.data.received; continue;
      }
      if (r && r.res.status !== 409 && r.res.status < 500 && r.res.status !== 429) {
        throw new Error((r.data && r.data.error) || `업로드 실패 (${r.res.status})`);
      }
      if (++tries > 5) throw new Error('네트워크 오류로 업로드하지 못했습니다');
      await new Promise((ok) => setTimeout(ok, 1000 * tries));
      // 서버가 실제로 받은 위치를 다시 묻는다(Sablier 가 깨우는 중일 수도 있다).
      try {
        const s = await call('GET', `${base}/files/${n}`);
        if (s.res.ok) { onBytes(s.data.received - offset); offset = s.data.received; }
      } catch (_) { /* 다음 시도 */ }
    }
  }

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    uerr.hidden = true; go.disabled = true; progress.hidden = false;
    const total = files.reduce((a, f) => a + f.size, 0) || 1;
    let done = 0;
    const tick = (n) => { done += n; const p = Math.min(100, done / total * 100); bar.style.width = p + '%'; ptext.textContent = `${human(done)} / ${human(total)}`; };
    tick(0);
    try {
      const init = await call('POST', `${api}/uploads`, JSON.stringify({
        files: files.map((f) => ({ name: f.name, size: f.size })),
        id: $('dropid').value.trim(), password: $('droppw').value.trim(), days: Number($('days').value),
      }), { 'Content-Type': 'application/json' });
      if (!init.res.ok) throw new Error((init.data && init.data.error) || `시작 실패 (${init.res.status})`);
      const d = init.data;
      const base = `${api}/uploads/${encodeURIComponent(d.id)}/${encodeURIComponent(d.upload_key)}`;
      for (let i = 0; i < files.length; i++) {
        ptext.textContent = `${i + 1}/${files.length} ${files[i].name}`;
        await sendFile(base, i, files[i], d.chunk_bytes, tick);
      }
      const fin = await call('POST', `${base}/complete`);
      if (!fin.res.ok) throw new Error((fin.data && fin.data.error) || `완료 실패 (${fin.res.status})`);
      showResult(fin.data, d.password);
      document.dispatchEvent(new CustomEvent('drop:uploaded'));
    } catch (e) {
      uerr.textContent = e.message; uerr.hidden = false; go.disabled = false;
    }
  });

  function showResult(v, pw) {
    form.hidden = true;
    const out = $('result'); out.hidden = false;
    const exp = new Date(v.expires_at).toLocaleString('ko-KR', { dateStyle: 'medium', timeStyle: 'short' });
    $('r-url').textContent = v.url; $('r-id').textContent = v.id; $('r-pw').textContent = pw; $('r-exp').textContent = exp;
    $('r-copy').onclick = () => {
      const text = `파일 받는 곳: ${v.url}\n아이디: ${v.id}\n비밀번호: ${pw}\n(${exp}까지)`;
      navigator.clipboard.writeText(text).then(() => { $('r-copy').textContent = '복사했어요'; });
    };
    $('r-again').onclick = () => {
      out.hidden = true; form.hidden = false; form.reset(); setFiles([]);
      progress.hidden = true; bar.style.width = '0'; $('r-copy').textContent = '전달용 문구 복사';
    };
  }
})();
