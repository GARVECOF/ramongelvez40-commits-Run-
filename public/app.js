const app = document.querySelector('#app');
let me = null;
const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[c]));
const money = c => `$${(Number(c || 0) / 100).toFixed(2)}`;
const fmt = n => new Intl.NumberFormat('es-VE').format(Number(n || 0));

async function api(url, opt = {}) {
  const r = await fetch(url, { headers: { 'Content-Type': 'application/json', ...(opt.headers || {}) }, ...opt });
  const d = await r.json().catch(() => ({ ok: false, error: 'Respuesta inválida' }));
  if (!r.ok) throw Error(d.error || 'No se pudo completar la operación.');
  return d;
}

function toast(t) {
  let x = $('#toast');
  if (!x) {
    x = document.createElement('div');
    x.id = 'toast';
    x.className = 'toast';
    document.body.append(x);
  }
  x.textContent = t;
  x.classList.add('show');
  clearTimeout(window.toastTimer);
  window.toastTimer = setTimeout(() => x.classList.remove('show'), 2600);
}

function layout(body, title = 'run', sub = 'Recompensas y diamantes') {
  if (!app) return;
  app.innerHTML = `<div class="shell"><header class="top"><div class="brand"><div class="mark">◆</div><div><strong>${title}</strong><small>${sub}</small></div></div>${me ? '<button id="logout">Salir</button>' : ''}</header>${body}</div>`;
  $('#logout')?.addEventListener('click', async () => {
    try { await api('/api/auth/logout', { method: 'POST' }); } catch(e){}
    me = null;
    renderLogin();
  });
}

function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = '🙈';
  } else {
    input.type = 'password';
    btn.textContent = '👁️';
  }
}
window.togglePassword = togglePassword;

function renderLogin() {
  layout(`
    <section class="form-card">
      <p class="eyebrow">ENTRA A RUN</p>
      <h1>Tu recompensa empieza aquí</h1>
      <p class="muted">Ingresa con tu correo y contraseña.</p>
      <form id="loginForm">
        <div style="margin-bottom:12px;">
          <input class="input" name="email" type="email" placeholder="Correo electrónico" required style="width:100%;box-sizing:border-box;">
        </div>
        <div style="position:relative; margin-bottom:16px;">
          <input id="logPass" class="input" name="password" type="password" placeholder="Contraseña" required style="width:100%;padding-right:45px;box-sizing:border-box;">
          <button type="button" onclick="togglePassword('logPass', this)" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:18px;padding:5px;">👁️</button>
        </div>
        <button class="btn" type="submit" style="width:100%;">Entrar</button>
      </form>
      <button class="switch" id="toRegister" style="background:none;border:none;color:cyan;cursor:pointer;margin-top:15px;width:100%;">¿No tienes cuenta? Regístrate</button>
    </section>
  `);
 
  $('#loginForm')?.addEventListener('submit', async e => {
    e.preventDefault();
    const formData = Object.fromEntries(new FormData(e.target));
    try {
      const d = await api('/api/auth/login', { method: 'POST', body: JSON.stringify(formData) });
      me = d.user;
      d.kind === 'admin' ? renderAdmin() : renderUser();
    } catch (errAdmin) {
      try {
        const d2 = await api('/api/auth/user-login', { method: 'POST', body: JSON.stringify(formData) });
        me = d2.user;
        renderUser();
      } catch (errUser) {
        toast(errUser.message || 'Credenciales incorrectas');
      }
    }
  });
 
  $('#toRegister')?.addEventListener('click', renderRegister);
}

function renderRegister() {
  layout(`
    <section class="form-card">
      <p class="eyebrow">CREA TU CUENTA</p>
      <h1>Regístrate en run</h1>
      <p class="muted">Crea tu cuenta de usuario.</p>
      <form id="registerForm">
        <div style="margin-bottom:12px;">
          <input class="input" name="name" placeholder="Nombre de usuario" required style="width:100%;box-sizing:border-box;">
        </div>
        <div style="margin-bottom:12px;">
          <input class="input" name="email" type="email" placeholder="Correo electrónico" required style="width:100%;box-sizing:border-box;">
        </div>
        <div style="position:relative; margin-bottom:12px;">
          <input id="regPass" class="input" name="password" type="password" minlength="8" placeholder="Contraseña (mín 8 carac.)" required style="width:100%;padding-right:45px;box-sizing:border-box;">
          <button type="button" onclick="togglePassword('regPass', this)" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:18px;padding:5px;">👁️</button>
        </div>
        <div style="position:relative; margin-bottom:16px;">
          <input id="regConf" class="input" name="confirmPassword" type="password" minlength="8" placeholder="Repite la contraseña" required style="width:100%;padding-right:45px;box-sizing:border-box;">
          <button type="button" onclick="togglePassword('regConf', this)" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:18px;padding:5px;">👁️</button>
        </div>
        <button class="btn" type="submit" style="width:100%;">Crear cuenta</button>
      </form>
      <button class="switch" id="toLogin" style="background:none;border:none;color:cyan;cursor:pointer;margin-top:15px;width:100%;">¿Ya tienes cuenta? Entra aquí</button>
    </section>
  `);
 
  $('#registerForm')?.addEventListener('submit', async e => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(e.target));
    if (fd.password !== fd.confirmPassword) {
      return toast('Las contraseñas no coinciden.');
    }
    try {
      const d = await api('/api/auth/register', { method: 'POST', body: JSON.stringify(fd) });
      me = d.user;
      renderUser();
    } catch (e) { toast(e.message); }
  });
 
  $('#toLogin')?.addEventListener('click', renderLogin);
}

function renderAdminSetup() {
  layout(`
    <section class="form-card">
      <p class="eyebrow">PRIMERA CONFIGURACIÓN</p>
      <h1>Crea tu acceso de administrador</h1>
      <p class="muted">Este formulario aparece una sola vez.</p>
      <form id="setupForm">
        <div style="margin-bottom:12px;">
          <input class="input" name="email" type="email" placeholder="Correo de administrador" required style="width:100%;box-sizing:border-box;">
        </div>
        <div style="position:relative; margin-bottom:12px;">
          <input id="setPass" class="input" name="password" type="password" minlength="8" placeholder="Crea una contraseña" required style="width:100%;padding-right:45px;box-sizing:border-box;">
          <button type="button" onclick="togglePassword('setPass', this)" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:18px;padding:5px;">👁️</button>
        </div>
        <div style="position:relative; margin-bottom:16px;">
          <input id="setConf" class="input" name="confirmPassword" type="password" minlength="8" placeholder="Repite la contraseña" required style="width:100%;padding-right:45px;box-sizing:border-box;">
          <button type="button" onclick="togglePassword('setConf', this)" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:18px;padding:5px;">👁️</button>
        </div>
        <button class="btn" type="submit" style="width:100%;">Crear acceso y entrar</button>
      </form>
    </section>
  `, 'run — configuración inicial', 'Panel de administración');
 
  $('#setupForm')?.addEventListener('submit', async e => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(e.target));
    if (fd.password !== fd.confirmPassword) {
      return toast('Las contraseñas no coinciden.');
    }
    try {
      const d = await api('/api/setup/admin', { method: 'POST', body: JSON.stringify(fd) });
      me = d.user;
      renderAdmin();
    } catch (e) { toast(e.message); }
  });
}

async function renderUser() {
  try {
    const [cfg, red] = await Promise.all([api('/api/public/config'), api('/api/user/redemptions')]);
    layout(`
      <section class="hero">
        <p class="eyebrow">HOLA, ${esc(me.name || 'USUARIO').toUpperCase()}</p>
        <h1>Gana monedas.<br><span>Canjéalas por recompensas.</span></h1>
        <p class="muted">Completa ofertas y acumula monedas en tu cuenta.</p>
        <div class="wallet">
          <div class="balance"><div class="balance-icon">●</div><div><small>Monedas</small><strong>${fmt(me.coins)}</strong></div></div>
          <div class="balance diamond"><div class="balance-icon">◆</div><div><small>Meta de canje</small><strong>${fmt(cfg.threshold)}</strong></div></div>
        </div>
      </section>
      <section class="section">
        <div class="section-head"><div><p class="eyebrow">PLATAFORMAS</p><h2>Elige dónde participar</h2></div></div>
        <div class="grid">${cfg.platforms && cfg.platforms.length ? cfg.platforms.map(p => `<a class="platform" href="${esc(p.link)}" target="_blank" rel="noopener"><div class="logo">${esc((p.name || 'P').slice(0, 1).toUpperCase())}</div><strong>${esc(p.name)}</strong><span>Ir a la plataforma ↗</span></a>`).join('') : '<div class="card empty">No hay plataformas configuradas.</div>'}</div>
      </section>
      <section class="section card">
        <div class="section-head"><div><p class="eyebrow">CANJE</p><h2>Solicitar recompensa</h2></div><span class="pill">${fmt(cfg.threshold)} monedas</span></div>
        <p class="muted">Cuando completes la meta, elige una plataforma y solicita tu PIN.</p>
        <div class="grid">${cfg.platforms && cfg.platforms.length ? cfg.platforms.map(p => `<button class="btn cyan redeem" data-id="${p.id}" ${(me.coins || 0) < cfg.threshold ? 'disabled' : ''}>Solicitar PIN de ${esc(p.name)}</button>`).join('') : ''}</div>
      </section>
      <section class="section card">
        <div class="section-head"><div><p class="eyebrow">MIS SOLICITUDES</p><h2>Historial</h2></div></div>
        ${red.redemptions && red.redemptions.length ? red.redemptions.map(r => `<div class="offer"><div><h3>${esc(r.platform_name)}</h3><p>${esc(r.requested_at)} · ${esc(r.status)}</p></div><span class="pill">${fmt(r.coins_cost)} monedas</span></div>`).join('') : '<div class="empty">Aún no tienes solicitudes.</div>'}
      </section>
    `);
   
    document.querySelectorAll('.redeem').forEach(b => b.addEventListener('click', async () => {
      try {
        const d = await api('/api/user/redeem', { method: 'POST', body: JSON.stringify({ platformId: b.dataset.id }) });
        me = d.user;
        toast(d.message);
        renderUser();
      } catch (e) { toast(e.message); }
    }));
  } catch (err) {
    renderLogin();
  }
}

async function renderAdmin() {
  try {
    const [d, p, r, pi] = await Promise.all([
      api('/api/admin/dashboard'),
      api('/api/admin/platforms'),
      api('/api/admin/redemptions'),
      api('/api/admin/pins')
    ]);
   
    layout(`
      <section class="hero">
        <p class="eyebrow">PANEL DE CONTROL</p>
        <h1>Administra <span>run.</span></h1>
        <p class="muted">Usuarios, plataformas, producción y recompensas.</p>
        <div class="admin-grid">
          <div class="card metric"><strong>${fmt(d.users.length)}</strong><small>Usuarios</small></div>
          <div class="card metric"><strong>${fmt(d.totals.earned_coins)}</strong><small>Monedas generadas</small></div>
          <div class="card metric"><strong>${money(d.totals.generated_cents)}</strong><small>Valor generado</small></div>
          <div class="card metric"><strong>${fmt(d.pending.count)}</strong><small>Canjes pendientes</small></div>
        </div>
      </section>
      <section class="section form-card" style="max-width:none;margin-left:0;margin-right:0">
        <div class="section-head"><div><p class="eyebrow">CONFIGURACIÓN</p><h2>Plataformas</h2></div><span class="pill">1.000 monedas = $1</span></div>
        ${p.platforms.map(x => `<div class="platform-edit" style="margin-bottom:10px;"><input class="checkbox" type="checkbox" ${x.active ? 'checked' : ''} data-active="${x.id}"> <input class="input" data-name="${x.id}" value="${esc(x.name)}" placeholder="Nombre"> <input class="input" data-logo="${x.id}" value="${esc(x.logo_url)}" placeholder="Logo"> <input class="input" data-link="${x.id}" value="${esc(x.link)}" placeholder="Enlace HTTPS"> <button class="btn save-platform" data-id="${x.id}">Guardar</button></div>`).join('')}
      </section>
      <section class="section form-card" style="max-width:none;margin-left:0;margin-right:0">
        <div class="section-head"><div><p class="eyebrow">INVENTARIO</p><h2>Cargar PIN</h2></div></div>
        <form id="pinForm" class="offer" style="display:flex;gap:10px;flex-wrap:wrap;">
          <select class="input" name="platformId" required>${p.platforms.map(x => `<option value="${x.id}">${esc(x.name || `Plataforma ${x.slot}`)}</option>`).join('')}</select>
          <input class="input" name="code" placeholder="Pega el PIN aquí" required>
          <input class="input" name="valueCents" type="number" value="100" min="1" placeholder="Valor en centavos" required>
          <button class="btn" type="submit">Guardar PIN</button>
        </form>
        <div class="table-wrap"><table class="data"><thead><tr><th>ID</th><th>Plataforma</th><th>PIN</th><th>Valor</th><th>Estado</th></tr></thead><tbody>${pi.pins.length ? pi.pins.map(x => `<tr><td>${x.id}</td><td>${esc(x.platform_name)}</td><td>${esc(x.code)}</td><td>${money(x.value_cents)}</td><td>${esc(x.status)}</td></tr>`).join('') : '<tr><td colspan="5" class="empty">Todavía no hay PINs.</td></tr>'}</tbody></table></div>
      </section>
      <section class="section table-card">
        <div class="section-head"><div><p class="eyebrow">USUARIOS</p><h2>Producción por usuario</h2></div></div>
        <div class="table-wrap"><table class="data"><thead><tr><th>#</th><th>Usuario / correo</th><th>Monedas</th><th>Generado</th><th>Recompensas</th><th>Restante</th></tr></thead><tbody>${d.users.length ? d.users.map((u, i) => `<tr><td>${i + 1}</td><td><strong>${esc(u.name)}</strong><br>${esc(u.email)}</td><td>${fmt(u.coins)}</td><td>${money(u.generated_cents)}</td><td>${money(u.reward_cents)}</td><td>${money(u.remaining_cents)}</td></tr>`).join('') : '<tr><td colspan="6" class="empty">No hay usuarios.</td></tr>'}</tbody></table></div>
      </section>
      <section class="section table-card">
        <div class="section-head"><div><p class="eyebrow">SOLICITUDES</p><h2>Canjes pendientes</h2></div></div>
        <div class="table-wrap"><table class="data"><thead><tr><th>Usuario</th><th>Correo</th><th>Plataforma</th><th>Estado</th><th>PIN</th></tr></thead><tbody>${r.redemptions.length ? r.redemptions.map(x => `<tr><td>${esc(x.name)}</td><td>${esc(x.email)}</td><td>${esc(x.platform_name)}</td><td>${esc(x.status)}</td><td>${x.status === 'requested' ? `<button class="btn choose-pin" data-id="${x.id}">Enviar PIN</button>` : esc(x.pin_code || '—')}</td></tr>`).join('') : '<tr><td colspan="5" class="empty">No hay solicitudes.</td></tr>'}</tbody></table></div>
      </section>
    `);
   
    document.querySelectorAll('.save-platform').forEach(b => b.addEventListener('click', async () => {
      try {
        await api('/api/admin/platforms/' + b.dataset.id, {
          method: 'PUT',
          body: JSON.stringify({
            name: $(`[data-name="${b.dataset.id}"]`).value,
            logoUrl: $(`[data-logo="${b.dataset.id}"]`).value,
            link: $(`[data-link="${b.dataset.id}"]`).value,
            active: $(`[data-active="${b.dataset.id}"]`).checked
          })
        });
        toast('Plataforma guardada');
      } catch (e) { toast(e.message); }
    }));
   
    $('#pinForm')?.addEventListener('submit', async e => {
      e.preventDefault();
      try {
        await api('/api/admin/pins', { method: 'POST', body: JSON.stringify(Object.fromEntries(new FormData(e.target))) });
        toast('PIN guardado');
        renderAdmin();
      } catch (e) { toast(e.message); }
    });
   
    document.querySelectorAll('.choose-pin').forEach(b => b.addEventListener('click', async () => {
      try {
        const pins = (await api('/api/admin/pins')).pins.filter(x => x.status === 'available');
        if (!pins.length) return toast('No hay PINs disponibles.');
        const available = pins.map(x => `ID ${x.id}: ${x.platform_name} ${money(x.value_cents)}`).join('\n');
        const pinId = prompt(`Escribe el ID del PIN disponible:\n\n${available}`);
        if (!pinId) return;
        await api('/api/admin/redemptions/' + b.dataset.id + '/send', { method: 'POST', body: JSON.stringify({ pinId: Number(pinId) }) });
        toast('PIN enviado al correo');
        renderAdmin();
      } catch (e) { toast(e.message); }
    }));
  } catch (err) {
    renderLogin();
  }
}

async function start() {
  try {
    const setup = await api('/api/setup/status');
    if (!setup.configured) return renderAdminSetup();
    const d = await api('/api/me');
    me = d.user;
    d.kind === 'admin' ? renderAdmin() : renderUser();
  } catch {
    renderLogin();
  }
}

start();
