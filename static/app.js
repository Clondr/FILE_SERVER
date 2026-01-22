async function api(path, {method='GET', token=null, body=null, isForm=false} = {}){
  const headers = {};
  // token can be passed explicitly or read from DOM/localStorage
  const tokenVal = token || (document.getElementById('token') ? document.getElementById('token').value : null) || localStorage.getItem('fs_token');
  if (tokenVal) headers['X-Auth-Token'] = tokenVal;
  // Basic auth from DOM or localStorage
  const basicUser = (document.getElementById('basicUser') ? document.getElementById('basicUser').value : '') || localStorage.getItem('fs_user') || '';
  const basicPass = (document.getElementById('basicPass') ? document.getElementById('basicPass').value : '') || localStorage.getItem('fs_pass') || '';
  if (basicUser && basicPass){ headers['Authorization'] = 'Basic ' + btoa(basicUser + ':' + basicPass); }
  let opts = {method, headers};
  if (body) {
    if (isForm) opts.body = body;
    else { headers['Content-Type']='application/json'; opts.body = JSON.stringify(body); }
  }
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res;
}

function $(s){return document.querySelector(s)}

async function refresh(){
  const token = $('#token').value || null;
  const list = $('#fileList');
  list.innerHTML = 'Loading...';
  try{
    const res = await api('/files', {token});
    const j = await res.json();
    if (!j.files || j.files.length===0){ list.innerHTML = '<p>No files</p>'; return }
    list.innerHTML = '';
    j.files.forEach(f=>{
      const div = document.createElement('div'); div.className='file-item';
      const meta = document.createElement('div'); meta.className='meta';
      meta.innerHTML = `<strong>${f.path}</strong><br><small>${f.size} bytes</small>`;
      const actions = document.createElement('div');
      // encode each path segment to preserve slashes
      const encodePath = (p)=> p.split('/').map(encodeURIComponent).join('/');
      const dl = document.createElement('a'); dl.href = `#`; dl.textContent='Download'; dl.className='btn';
        dl.style.marginRight='8px';
      // ensure token passed via header using fetch for download blob
      const dlBtn = document.createElement('button'); dlBtn.textContent='Download (save)';
      dlBtn.onclick = async ()=>{
        dlBtn.disabled=true; dlBtn.textContent='Downloading...';
        try{
          const filename = f.path.split('/').pop();
          const fileSize = f.size;
          const downloadUrl = `/download/${encodePath(f.path)}`;
          
          // Build auth params for URL
          const tokenVal = token || (document.getElementById('token') ? document.getElementById('token').value : null) || localStorage.getItem('fs_token');
          const basicUser = (document.getElementById('basicUser') ? document.getElementById('basicUser').value : '') || localStorage.getItem('fs_user') || '';
          const basicPass = (document.getElementById('basicPass') ? document.getElementById('basicPass').value : '') || localStorage.getItem('fs_pass') || '';
          
          // Build URL with auth params - simplest approach for reliable downloads
          let fullUrl = downloadUrl;
          const params = new URLSearchParams();
          if (tokenVal) params.set('token', tokenVal);
          if (basicUser && basicPass) {
            params.set('user', basicUser);
            params.set('pass', basicPass);
          }
          if (params.toString()) {
            fullUrl += '?' + params.toString();
          }
          
          // Use direct download via browser - most reliable for large files
          // The browser handles streaming natively without memory issues
          const a = document.createElement('a');
          a.href = fullUrl;
          a.download = filename;
          a.target = '_blank'; // Open in new tab/window for better mobile support
          a.rel = 'noopener noreferrer';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          
          // Update button to show download started
          dlBtn.textContent = 'Download started...';
          
          // Reset after a delay
          setTimeout(() => {
            dlBtn.textContent = 'Download (save)';
          }, 3000);
          
        }catch(e){ alert('Download error: '+e.message) }
        dlBtn.disabled=false;
      };
      const del = document.createElement('button'); del.textContent='Delete'; del.onclick = async ()=>{
        if (!confirm('Delete '+f.path+'?')) return;
        try{
          await api(`/delete/${encodePath(f.path)}`, {method:'DELETE', token});
          refresh();
        }catch(e){ alert('Delete error: '+e.message) }
      };
      actions.appendChild(dlBtn); actions.appendChild(del);
      div.appendChild(meta); div.appendChild(actions);
      list.appendChild(div);
    });
  }catch(e){ list.innerHTML = `<p class="error">Failed: ${e.message}</p>` }
}

window.addEventListener('DOMContentLoaded', ()=>{
  $('#refresh').addEventListener('click', refresh);
  $('#clearTokenBtn').addEventListener('click', ()=>{
    if (!confirm('Очистить сохранённый токен?')) return;
    localStorage.removeItem('fs_token');
    $('#token').value = '';
    alert('Токен удалён');
    refresh();
  });
  $('#uploadBtn').addEventListener('click', async ()=>{
    const token = $('#token').value || null;
    const input = $('#fileInput');
    const file = input.files[0];
    if (!file) { alert('Choose file'); return }
    const remote = $('#remotePath').value || file.name;
    if (remote.startsWith('/') || remote.includes('..') || remote.includes('\\')){ alert('Invalid remote path'); return }
    const fd = new FormData();
    fd.append('file', file, remote);
    $('#uploadResult').textContent = 'Uploading...';
    try{
    const r = await api('/upload', {method:'POST', token, body:fd, isForm:true});
      const j = await r.json();
      $('#uploadResult').textContent = 'Uploaded: ' + JSON.stringify(j.saved);
      input.value=''; $('#remotePath').value='';
      refresh();
    }catch(e){ $('#uploadResult').textContent = 'Upload failed: '+e.message }
  });
  // --- token modal logic ---
  const modal = document.getElementById('connectModal');
  const connectTokenInput = document.getElementById('connectToken');
  const connectUserInput = document.getElementById('connectUser');
  const connectPassInput = document.getElementById('connectPass');
  const storedToken = localStorage.getItem('fs_token');
  const storedUser = localStorage.getItem('fs_user');
  const storedPass = localStorage.getItem('fs_pass');
  if (storedToken) { $('#token').value = storedToken; }
  if (storedUser) { $('#basicUser').value = storedUser; }
  if (storedPass) { $('#basicPass').value = storedPass; }
  // show modal only if no credentials present
  if (!storedToken && !storedUser){ modal.setAttribute('aria-hidden', 'false'); }

  document.getElementById('connectBtn').addEventListener('click', ()=>{
    const t = connectTokenInput.value.trim();
    const u = connectUserInput.value.trim();
    const p = connectPassInput.value;
    if (t) { localStorage.setItem('fs_token', t); $('#token').value = t; }
    if (u && p) { localStorage.setItem('fs_user', u); localStorage.setItem('fs_pass', p); $('#basicUser').value = u; $('#basicPass').value = p; }
    modal.setAttribute('aria-hidden', 'true');
    refresh();
  });
  document.getElementById('skipBtn').addEventListener('click', ()=>{
    // proceed without token/basic
    modal.setAttribute('aria-hidden', 'true');
    // do not clear stored creds here
    refresh();
  });
  // allow pressing Enter in modal inputs
  [connectTokenInput, connectUserInput, connectPassInput].forEach(el=>{ el.addEventListener('keydown', (e)=>{ if (e.key === 'Enter') document.getElementById('connectBtn').click(); }); });

  // Save/Clear buttons for credentials in main UI
  $('#saveCredsBtn').addEventListener('click', ()=>{
    const u = $('#basicUser').value.trim();
    const p = $('#basicPass').value;
    if (!u || !p){ alert('Enter both username and password to save'); return }
    localStorage.setItem('fs_user', u); localStorage.setItem('fs_pass', p); alert('Credentials saved locally');
  });
  $('#clearCredsBtn').addEventListener('click', ()=>{
    if (!confirm('Очистить сохранённые креды?')) return;
    localStorage.removeItem('fs_user'); localStorage.removeItem('fs_pass'); $('#basicUser').value=''; $('#basicPass').value=''; alert('Credentials cleared');
  });
});
