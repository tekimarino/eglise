
const API = location.origin + "/api";
let token = localStorage.getItem("token") || "";
let CFG = null;
let CURRENT = null;

let MEMBERS = [];
let USERS = [];
let CONTRIBUTIONS = [];
let DEPENSES = [];

function $(id){ return document.getElementById(id); }
function show(id){ $(id)?.classList.remove("hidden"); }
function hide(id){ $(id)?.classList.add("hidden"); }
function setText(id, v){ const el=$(id); if(el) el.textContent = v ?? ""; }

function isoToday(){
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth()+1).padStart(2,"0");
  const dd = String(d.getDate()).padStart(2,"0");
  return `${yyyy}-${mm}-${dd}`;
}

function money(n){
  const x = Number(n||0);
  try { return new Intl.NumberFormat("fr-FR").format(x); } catch { return String(x); }
}

async function api(path, opts={}){
  const headers = opts.headers || {};
  if (token) headers["Authorization"] = "Bearer " + token;
  if (!(opts.body instanceof FormData) && opts.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(API + path, {...opts, headers});
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) throw new Error(data.detail || data || "Erreur API");
  return data;
}

function setRoleUI(role){
  document.body.classList.remove("role-admin","role-member");
  if (role === "ADMIN") document.body.classList.add("role-admin");
  else document.body.classList.add("role-member");
}

function setAuthUI(isAuth){
  $("loginView").classList.toggle("hidden", isAuth);
  $("registerView").classList.add("hidden");
  $("appView").classList.toggle("hidden", !isAuth);
  $("userBox").classList.toggle("hidden", !isAuth);

  if (isAuth && CURRENT){
    setText("userName", `${CURRENT.display_name} (${CURRENT.role})`);
    setRoleUI(CURRENT.role);
  }
}

function buildTabs(){
  const tabs = $("tabs");
  tabs.innerHTML = "";

  const addTab = (key, label, emoji, viewId) => {
    const b = document.createElement("button");
    b.className = "tab";
    b.dataset.view = viewId;
    b.textContent = `${emoji} ${label}`;
    b.addEventListener("click", ()=> showView(viewId));
    tabs.appendChild(b);
  };

  addTab("dash","Tableau de bord","📊","dashboardView");
  addTab("contrib", CURRENT.role === "ADMIN" ? "Entrées" : "Mes contributions", "➕", "contribView");
  addTab("reports","Rapports","📑","rapportsView");

  if (CURRENT.role !== "ADMIN"){
    addTab("account","Mon compte","👤","accountView");
  }

  if (CURRENT.role === "ADMIN"){
    addTab("dep","Dépenses","➖","depensesView");
    addTab("accounts","Membres & Comptes","👥","adminAccountsView");
  }

  // Default view
  const saved = localStorage.getItem("activeView") || "dashboardView";
  showView(saved);
}

function showView(viewId){
  localStorage.setItem("activeView", viewId);
  document.querySelectorAll(".tab").forEach(btn=>{
    btn.classList.toggle("active", btn.dataset.view === viewId);
  });

  const views = ["dashboardView","contribView","rapportsView","accountView","depensesView","adminAccountsView"];
  views.forEach(v=>{
    const el = $(v);
    if (el) el.classList.toggle("hidden", v !== viewId);
  });

  if (viewId === "adminAccountsView") refreshAccounts().catch(()=>{});
  if (viewId === "accountView") loadMyAccount().catch(()=>{});
}

function fillSelect(selId, items, labelFn, valFn){
  const sel = $(selId);
  if (!sel) return;
  sel.innerHTML = "";
  for (const it of (items||[])){
    const opt = document.createElement("option");
    opt.value = valFn(it);
    opt.textContent = labelFn(it);
    sel.appendChild(opt);
  }
}

function renderEmpty(tblId, msg){
  const tbl = $(tblId);
  tbl.innerHTML = `<tbody><tr><td class="muted">${msg}</td></tr></tbody>`;
}

function renderTable(tblId, headers, rows, rowHtmlFn){
  const tbl = $(tblId);
  if (!rows || rows.length === 0){
    return renderEmpty(tblId, "Aucune donnée.");
  }
  const head = `<thead><tr>${headers.map(h=>`<th>${h}</th>`).join("\n")}</tr></thead>`;
  const body = `<tbody>${rows.map(rowHtmlFn).join("\n")}</tbody>`;
  tbl.innerHTML = head + body;
}

function normalize(s){ return String(s||"").toLowerCase(); }
function inRange(dateStr, from, to){
  if (!dateStr) return true;
  const d = new Date(dateStr);
  if (from && d < new Date(from)) return false;
  if (to && d > new Date(to)) return false;
  return true;
}

/* -------- Data loading -------- */
async function bootstrap(){
  CFG = await api("/config");
  CURRENT = CFG.current_user;

  setAuthUI(true);
  buildTabs();

  // fill rubrique/lieu
  fillSelect("c_rubrique", CFG.rubriques || [], x=>x, x=>x);
  fillSelect("c_lieu", CFG.lieux || [], x=>x, x=>x);

  $("c_date").value = isoToday();
  if ($("d_date")) $("d_date").value = isoToday();

  await refreshAll();
}

async function refreshAll(){
  await refreshDashboard();
  await loadContributions();
  renderContribTable();
  if (CURRENT.role === "ADMIN"){
    await loadDepenses();
    renderDepensesTable();
    await loadMembers();
    fillSelect("c_member", MEMBERS, m=>`${m.prenoms} ${m.nom}`.trim(), m=>m.member_id);
  }
  await refreshReports();
}

async function refreshDashboard(){
  const rep = await api("/reports/bilan-general");

  // Member dashboard: "total_entrees" == ses contributions -> afficher comme "Total sorties"
  if (CURRENT.role !== "ADMIN"){
    // KPI labels + visibility
    setText("kpiEntreesLabel","Total sorties");
    $("kpiBoxSorties")?.classList.add("hidden");
    $("kpiBoxSolde")?.classList.add("hidden");

    setText("kpiEntrees", money(rep.total_entrees));

    // Title + no horizontal scroll on last 5
    setText("lastEntreesTitle","Dernières sorties");
    $("lastEntreesTableWrap")?.classList.add("no-scroll");

    renderTable("lastEntreesTbl", ["Date","Rubrique","Montant"], rep.last_entrees || [], r => `
      <tr>
        <td>${r.date || ""}</td>
        <td><span class="badge">${r.rubrique || ""}</span></td>
        <td><b>${money(r.montant)}</b></td>
      </tr>
    `);
    return;
  }

  // Admin dashboard
  $("kpiBoxSorties")?.classList.remove("hidden");
  $("kpiBoxSolde")?.classList.remove("hidden");
  $("lastEntreesTableWrap")?.classList.remove("no-scroll");
  setText("kpiEntreesLabel","Total entrées");
  setText("lastEntreesTitle","Dernières entrées");

  setText("kpiEntrees", money(rep.total_entrees));
  setText("kpiSorties", money(rep.total_sorties));
  setText("kpiSolde", money(rep.solde));

  renderTable("lastEntreesTbl", ["Date","Personne","Rubrique","Montant"], rep.last_entrees || [], r => `
    <tr>
      <td>${r.date || ""}</td>
      <td>${r.personne || ""}</td>
      <td><span class="badge">${r.rubrique || ""}</span></td>
      <td><b>${money(r.montant)}</b></td>
    </tr>
  `);

  renderTable("lastDepensesTbl", ["Date","Bénéficiaire","Motif","Montant"], rep.last_depenses || [], r => `
    <tr>
      <td>${r.date || ""}</td>
      <td>${r.beneficiaire || ""}</td>
      <td><span class="badge red">${r.motif || ""}</span></td>
      <td><b>${money(r.montant)}</b></td>
    </tr>
  `);
}


async function loadMyAccount(){
  hide("mc_error"); setText("mc_error","");
  setText("mc_status","Chargement…");
  try{
    const me = await api("/me");
    setText("mc_status","");
    $("mc_username").value = me.username || "";
    $("mc_nom").value = me.nom || "";
    $("mc_prenoms").value = me.prenoms || "";
    $("mc_email").value = me.email || "";
    $("mc_residence").value = me.residence || "";
    $("mc_telephone").value = me.telephone || "";
    $("mc_fonction").value = me.fonction || "";
    $("mc_password").value = "";
  }catch(e){
    setText("mc_status","");
    setText("mc_error", e.message); show("mc_error");
  }
}

async function saveMyAccount(){
  hide("mc_error"); setText("mc_error","");
  setText("mc_status","Enregistrement…");
  const payload = {
    nom: ($("mc_nom").value || "").trim(),
    prenoms: ($("mc_prenoms").value || "").trim(),
    email: ($("mc_email").value || "").trim(),
    residence: ($("mc_residence").value || "").trim(),
    telephone: ($("mc_telephone").value || "").trim(),
    fonction: ($("mc_fonction").value || "").trim(),
    password: ($("mc_password").value || "").trim()
  };
  // ne pas envoyer password vide
  if (!payload.password) delete payload.password;

  try{
    const out = await api("/me", {method:"PUT", body: JSON.stringify(payload)});
    setText("mc_status","OK ✅");
    // refresh name in header
    if (out && out.display_name) setText("userName", out.display_name);
    $("mc_password").value = "";
  }catch(e){
    setText("mc_status","");
    setText("mc_error", e.message); show("mc_error");
  }
}


async function loadMembers(){
  MEMBERS = await api("/members");
}
async function loadUsers(){
  USERS = await api("/users");
}
async function loadContributions(){
  CONTRIBUTIONS = await api("/contributions");
}
async function loadDepenses(){
  DEPENSES = await api("/depenses");
}

/* -------- Contributions -------- */
async function addContribution(){
  hide("c_error"); setText("c_error","");
  setText("c_status","Enregistrement…");

  const rawMontant = ($("c_montant").value || "").trim();
  const montant = Number(rawMontant);
  if(!rawMontant){
    setText("c_status","");
    setText("c_error","Montant requis : entre un nombre entier ≥ 500.");
    show("c_error");
    $("c_montant").focus();
    return;
  }
  if(!Number.isFinite(montant) || !Number.isInteger(montant)){
    setText("c_status","");
    setText("c_error","Montant invalide : le montant doit être un nombre entier.");
    show("c_error");
    $("c_montant").focus();
    return;
  }
  if(montant < 500){
    setText("c_status","");
    setText("c_error","Montant trop petit : minimum 500.");
    show("c_error");
    $("c_montant").focus();
    return;
  }

  const payload = {
    member_id: CURRENT.role === "ADMIN" ? $("c_member").value : null,
    rubrique: $("c_rubrique").value,
    lieu: $("c_lieu").value,
    montant: montant,
    date: $("c_date").value || isoToday(),
    note: $("c_note").value || ""
  };

  try{
    await api("/contributions", {method:"POST", body: JSON.stringify(payload)});
    setText("c_status","OK ✅");
    $("c_montant").value = "";
    $("c_note").value = "";
    await loadContributions();
    renderContribTable();
    await refreshDashboard();
    await refreshReports();
  }catch(e){
    setText("c_status","");
    setText("c_error", e.message); show("c_error");
  }
}

function renderContribTable(){
  const q = normalize($("c_q").value);
  const from = $("c_from").value || "";
  const to = $("c_to").value || "";

  const rows = (CONTRIBUTIONS||[]).filter(r=>{
    const blob = normalize(`${r.date} ${r.prenoms||""} ${r.nom||""} ${r.rubrique||""} ${r.lieu||""} ${r.note||""} ${r.montant||""}`);
    return (!q || blob.includes(q)) && inRange(r.date, from, to);
  }).sort((a,b)=> (b.date||"").localeCompare(a.date||""));

  const title = CURRENT.role === "ADMIN" ? "Entrées" : "Mes contributions";
  setText("contribTitle", title);

  const isAdmin = CURRENT.role === "ADMIN";
  const headers = isAdmin
    ? ["Date","Membre","Rubrique","Lieu","Montant","Note","Actions"]
    : ["Date","Membre","Rubrique","Lieu","Montant","Note"];

  renderTable("contribTbl", headers, rows, r => {
    const base = `
      <td>${r.date || ""}</td>
      <td>${((r.prenoms||"") + " " + (r.nom||"")).trim()}</td>
      <td><span class="badge">${r.rubrique||""}</span></td>
      <td>${r.lieu||""}</td>
      <td><b>${money(r.montant)}</b></td>
      <td class="muted">${r.note||""}</td>
    `;
    const actions = isAdmin
      ? `<td><button class="btn secondary small" onclick="adminEditContribution('${r.id}')">✏️</button></td>`
      : ``;
    return `<tr>${base}${actions}</tr>`;
  });
}


/* -------- Depenses (admin) -------- */
async function addDepense(){
  hide("d_error"); setText("d_error","");
  setText("d_status","Enregistrement…");

  const rawMontant = ($("d_montant").value || "").trim();
  const montant = Number(rawMontant);
  if(!rawMontant){
    setText("d_status","");
    setText("d_error","Montant requis : entre un nombre entier ≥ 500.");
    show("d_error");
    $("d_montant").focus();
    return;
  }
  if(!Number.isFinite(montant) || !Number.isInteger(montant)){
    setText("d_status","");
    setText("d_error","Montant invalide : le montant doit être un nombre entier.");
    show("d_error");
    $("d_montant").focus();
    return;
  }
  if(montant < 500){
    setText("d_status","");
    setText("d_error","Montant trop petit : minimum 500.");
    show("d_error");
    $("d_montant").focus();
    return;
  }
  const payload = {
    beneficiaire: $("d_beneficiaire").value || "",
    motif: $("d_motif").value || "",
    lieu: $("d_lieu").value || "",
    montant: montant,
    date: $("d_date").value || isoToday()
  };
  try{
    await api("/depenses", {method:"POST", body: JSON.stringify(payload)});
    setText("d_status","OK ✅");
    $("d_beneficiaire").value="";
    $("d_motif").value="";
    $("d_lieu").value="";
    $("d_montant").value="";
    await loadDepenses();
    renderDepensesTable();
    await refreshDashboard();
    await refreshReports();
  }catch(e){
    setText("d_status","");
    setText("d_error", e.message); show("d_error");
  }
}

async function uploadJustif(){
  hide("j_error"); setText("j_error","");
  setText("j_status","Upload…");
  const id = $("j_depense_id").value.trim();
  const file = $("j_file").files?.[0];
  if (!id || !file){
    setText("j_status","");
    setText("j_error","ID dépense et fichier requis."); show("j_error"); return;
  }
  const fd = new FormData();
  fd.append("file", file);
  try{
    await api(`/depenses/${encodeURIComponent(id)}/justificatif`, {method:"POST", body: fd});
    setText("j_status","OK ✅");
    await loadDepenses();
    renderDepensesTable();
  }catch(e){
    setText("j_status","");
    setText("j_error", e.message); show("j_error");
  }
}

function renderDepensesTable(){
  renderTable("depTbl", ["ID","Date","Bénéficiaire","Motif","Lieu","Montant","Justif","Actions"], DEPENSES || [], r => `
    <tr>
      <td><code>${r.id||""}</code></td>
      <td>${r.date||""}</td>
      <td>${r.beneficiaire||""}</td>
      <td><span class="badge red">${r.motif||""}</span></td>
      <td>${r.lieu||""}</td>
      <td><b>${money(r.montant)}</b></td>
      <td>${r.justificatif_path ? '<span class="badge green">OK</span>' : '<span class="badge">—</span>'}</td>
      <td><button class="btn secondary small" onclick="adminEditDepense(\'${r.id}\')">✏️</button></td>
    </tr>
  `);
}

/* -------- Reports -------- */
async function refreshReports(){
  const rep = await api("/reports/bilan-general");
  setText("r_entrees", money(rep.total_entrees));
  setText("r_sorties", money(rep.total_sorties));
  setText("r_solde", money(rep.solde));
}



async function downloadExportFile(file_id, kind){
  const url = `${API}/files?file_id=${encodeURIComponent(file_id)}`;
  const headers = {};
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const res = await fetch(url, {headers});
  if (!res.ok){
    let msg = 'Erreur téléchargement.';
    try{
      const j = await res.json();
      msg = j.detail || msg;
    }catch(e){
      try{ msg = await res.text(); }catch(_){ }
    }
    throw new Error(msg);
  }
  const blob = await res.blob();
  const blobUrl = URL.createObjectURL(blob);
  if (kind === 'pdf'){
    window.open(blobUrl, '_blank');
  }else{
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = `rapport_${isoToday()}.${kind}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
  setTimeout(()=>URL.revokeObjectURL(blobUrl), 60000);
}

async function exportPdf(){
  hide("x_error"); setText("x_error","");
  setText("x_status","Génération PDF…");
  try{
    const r = await api("/exports/pdf", {method:"POST", body: JSON.stringify({})});
    await downloadExportFile(r.file_id, 'pdf');
    setText("x_status","OK ✅");
  }catch(e){
    setText("x_status","");
    setText("x_error", e.message); show("x_error");
  }
}
async function exportXlsx(){
  hide("x_error"); setText("x_error","");
  setText("x_status","Génération Excel…");
  try{
    const r = await api("/exports/xlsx", {method:"POST", body: JSON.stringify({})});
    await downloadExportFile(r.file_id, 'xlsx');
    setText("x_status","OK ✅");
  }catch(e){
    setText("x_status","");
    setText("x_error", e.message); show("x_error");
  }
}

/* -------- Admin accounts -------- */
async function refreshAccounts(){
  await loadMembers();
  await loadUsers();

  renderTable("membersTbl", ["member_id","Nom","Prénoms","Résidence","Téléphone","Fonction","Actif","Actions"], MEMBERS || [], m => `
    <tr>
      <td><code>${m.member_id||""}</code></td>
      <td>${m.nom||""}</td>
      <td>${m.prenoms||""}</td>
      <td>${m.residence||""}</td>
      <td>${m.telephone||""}</td>
      <td>${m.fonction||""}</td>
      <td>${m.active ? '<span class="badge green">Oui</span>' : '<span class="badge red">Non</span>'}</td>
      <td>
        <button class="btn secondary small" onclick="adminEditMember('${m.member_id}')">✏️</button>
        <button class="btn danger small" onclick="adminDeleteMember('${m.member_id}')">🗑️</button>
      </td>
    </tr>
  `);

  renderTable("usersTbl", ["id","username","nom affiché","role","actif","member_id","Actions"], USERS || [], u => `
    <tr>
      <td><code>${u.id||""}</code></td>
      <td><b>${u.username||""}</b></td>
      <td>${u.display_name||""}</td>
      <td><span class="badge">${u.role||""}</span></td>
      <td>${u.active ? '<span class="badge green">Oui</span>' : '<span class="badge red">Non</span>'}</td>
      <td><code>${u.member_id||""}</code></td>
      <td>
        ${u.role === 'ADMIN' ? '<span class="muted tiny">Admin</span>' : `
          <button class="btn secondary small" onclick="adminToggleUser('${u.id}', ${u.active ? 'false' : 'true'})">${u.active ? 'Désactiver' : 'Activer'}</button>
          <button class="btn secondary small" onclick="adminResetPassword('${u.id}')">🔑</button>
          <button class="btn danger small" onclick="adminDeleteUser('${u.id}')">🗑️</button>
        `}
      </td>
    </tr>
  `);

  // Admin config form
  if ($("cfg_rubriques")){
    $("cfg_rubriques").value = (CFG?.rubriques || []).join("\n");
    $("cfg_lieux").value = (CFG?.lieux || []).join("\n");
    $("cfg_currency").value = (CFG?.currency || "XOF");
  }

  // refill member select for contributions
  fillSelect("c_member", MEMBERS, m=>`${m.prenoms} ${m.nom}`.trim(), m=>m.member_id);
}

async function adminCreateMemberAccount(){
  hide("a_error"); setText("a_error","");
  setText("a_status","Création…");

  const payload = {
    nom: ($("a_nom").value || "").trim(),
    prenoms: ($("a_prenoms").value || "").trim(),
    email: ($("a_email").value || "").trim(),
    residence: ($("a_residence").value || "").trim(),
    telephone: ($("a_telephone").value || "").trim(),
    fonction: ($("a_fonction").value || "").trim(),
    username: ($("a_username").value || "").trim().toLowerCase(),
    password: ($("a_password").value || "").trim(),
    active: $("a_active").value === "true"
  };

  try{
    await api("/admin/create_member_account", {method:"POST", body: JSON.stringify(payload)});
    setText("a_status","OK ✅");
    $("a_nom").value=""; $("a_prenoms").value=""; $("a_email").value=""; $("a_residence").value="";
    $("a_telephone").value=""; $("a_fonction").value=""; $("a_username").value="";
    $("a_password").value=""; $("a_active").value="true";
    await refreshAccounts();
  }catch(e){
    setText("a_status","");
    setText("a_error", e.message); show("a_error");
  }
}


/* -------- Auth UI -------- */
async function doLogin(){
  hide("loginError");
  setText("loginHint","Connexion…");
  const username = $("loginUsername").value.trim().toLowerCase();
  const password = $("loginPassword").value.trim();

  try{
    const data = await api("/auth/login", {method:"POST", body: JSON.stringify({username, password})});
    token = data.access_token;
    localStorage.setItem("token", token);
    setText("loginHint","");
    await bootstrap();
  }catch(e){
    setText("loginHint","");
    setText("loginError", e.message);
    show("loginError");
  }
}


function doLogout(){
  token = "";
  localStorage.removeItem("token");
  localStorage.removeItem("activeView");
  CURRENT = null; CFG = null;
  document.body.classList.remove("role-admin","role-member");
  setAuthUI(false);
}

function openRegister(){
  hide("loginView");
  show("registerView");
}
function closeRegister(){
  hide("registerView");
  show("loginView");
}

async function doRegister(){
  hide("r_error"); setText("r_error","");
  setText("r_status","Création…");
  const payload = {
    nom: ($("r_nom").value || "").trim(),
    prenoms: ($("r_prenoms").value || "").trim(),
    email: ($("r_email").value || "").trim(),
    residence: ($("r_residence").value || "").trim(),
    telephone: ($("r_telephone").value || "").trim(),
    fonction: ($("r_fonction").value || "").trim(),
    username: ($("r_username").value || "").trim().toLowerCase(),
    password: ($("r_password").value || "").trim()
  };
  try{
    const data = await api("/auth/register", {method:"POST", body: JSON.stringify(payload)});
    token = data.access_token;
    localStorage.setItem("token", token);
    setText("r_status","OK ✅");
    await bootstrap();
  }catch(e){
    setText("r_status","");
    setText("r_error", e.message); show("r_error");
  }
}



/* -------- Admin actions (edit/delete) -------- */

window.adminEditContribution = async function(contrib_id){
  try{
    const c = (CONTRIBUTIONS||[]).find(x => x.id === contrib_id);
    if (!c) return alert("Contribution introuvable.");

    const raw = prompt("Nouveau montant (entier ≥ 500) :", String(c.montant ?? ""));
    if (raw === null) return;

    const clean = String(raw).trim();
    if (!clean) return alert("Montant requis.");
    const n = Number(clean);
    if (!Number.isInteger(n) || n < 500){
      return alert("Montant invalide : entre un nombre entier ≥ 500.");
    }

    const note = prompt("Note (optionnel) :", c.note || "");
    if (note === null) return;

    await api(`/contributions/${encodeURIComponent(contrib_id)}`, {
      method:"PUT",
      body: JSON.stringify({montant: n, note})
    });

    await loadContributions();
    renderContribTable();
    await refreshDashboard();
    await refreshReports();
  }catch(e){
    alert(e.message);
  }


window.adminEditDepense = async function(depense_id){
  try{
    const d = (DEPENSES||[]).find(x => x.id === depense_id);
    if (!d) return alert("Dépense introuvable.");

    const raw = prompt("Nouveau montant (entier ≥ 500) :", String(d.montant ?? ""));
    if (raw === null) return;

    const clean = String(raw).trim();
    if (!clean) return alert("Montant requis.");
    const n = Number(clean);
    if (!Number.isInteger(n) || n < 500){
      return alert("Montant invalide : entre un nombre entier ≥ 500.");
    }

    const date = prompt("Date (YYYY-MM-DD) :", d.date || "");
    if (date === null) return;
    const dateClean = String(date).trim();
    if (dateClean && !/^\d{4}-\d{2}-\d{2}$/.test(dateClean)){
      return alert("Date invalide. Format attendu : YYYY-MM-DD.");
    }

    const beneficiaire = prompt("Bénéficiaire :", d.beneficiaire || "");
    if (beneficiaire === null) return;

    const motif = prompt("Motif :", d.motif || "");
    if (motif === null) return;

    const lieu = prompt("Lieu :", d.lieu || "");
    if (lieu === null) return;

    await api(`/depenses/${encodeURIComponent(depense_id)}`, {
      method:"PUT",
      body: JSON.stringify({
        montant: n,
        date: dateClean,
        beneficiaire: String(beneficiaire).trim(),
        motif: String(motif).trim(),
        lieu: String(lieu).trim()
      })
    });

    await loadDepenses();
    renderDepensesTable();
    await refreshDashboard();
    await refreshReports();
  }catch(e){
    alert(e.message);
  }
};

};


window.adminEditMember = async function(member_id){
  try{
    const m = MEMBERS.find(x => x.member_id === member_id);
    if (!m) return alert("Membre introuvable.");
    const nom = prompt("Nom :", m.nom || "");
    if (nom === null) return;
    const prenoms = prompt("Prénoms :", m.prenoms || "");
    if (prenoms === null) return;
    const residence = prompt("Résidence :", m.residence || "");
    if (residence === null) return;
    const telephone = prompt("Téléphone :", m.telephone || "");
    if (telephone === null) return;
    const fonction = prompt("Fonction :", m.fonction || "");
    if (fonction === null) return;
    const active = confirm("Compte ACTIF ? (OK=Oui / Annuler=Non)");

    await api(`/members/${encodeURIComponent(member_id)}`, {
      method:"PUT",
      body: JSON.stringify({nom, prenoms, residence, telephone, fonction, active})
    });
    await refreshAccounts();
    await refreshAll();
  }catch(e){
    alert(e.message);
  }
};

window.adminDeleteMember = async function(member_id){
  if (!confirm("Supprimer ce profil membre ? (les contributions restent, le compte sera désactivé)")) return;
  try{
    await api(`/members/${encodeURIComponent(member_id)}`, {method:"DELETE"});
    await refreshAccounts();
    await refreshAll();
  }catch(e){
    alert(e.message);
  }
};

window.adminToggleUser = async function(user_id, active){
  try{
    await api(`/users/${encodeURIComponent(user_id)}`, {method:"PATCH", body: JSON.stringify({active})});
    await refreshAccounts();
  }catch(e){
    alert(e.message);
  }
};

window.adminResetPassword = async function(user_id){
  const pwd = prompt("Nouveau mot de passe :");
  if (pwd === null) return;
  try{
    await api(`/users/${encodeURIComponent(user_id)}`, {method:"PATCH", body: JSON.stringify({password: pwd})});
    alert("Mot de passe mis à jour ✅");
  }catch(e){
    alert(e.message);
  }
};

window.adminDeleteUser = async function(user_id){
  if (!confirm("Supprimer ce compte utilisateur ?")) return;
  try{
    await api(`/users/${encodeURIComponent(user_id)}`, {method:"DELETE"});
    await refreshAccounts();
  }catch(e){
    alert(e.message);
  }
};

async function adminSaveConfig(){
  hide("cfg_error"); setText("cfg_error","");
  setText("cfg_status","Sauvegarde…");
  try{
    const rubriques = ($("cfg_rubriques").value || "").split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
    const lieux = ($("cfg_lieux").value || "").split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
    const currency = ($("cfg_currency").value || "").trim();

    const r = await api("/admin/config", {method:"PUT", body: JSON.stringify({rubriques, lieux, currency})});
    CFG = r.config;
    setText("cfg_status","OK ✅");
    // refresh selects
    fillSelect("c_rubrique", CFG.rubriques || [], x=>x, x=>x);
    fillSelect("c_lieu", CFG.lieux || [], x=>x, x=>x);
  }catch(e){
    setText("cfg_status","");
    setText("cfg_error", e.message); show("cfg_error");
  }
}

/* -------- Wire -------- */
function wire(){
  // Empêche la molette (scroll) de modifier les champs numériques (source fréquente de -1 involontaire)
  document.querySelectorAll('input[type="number"]').forEach(inp=>{
    inp.addEventListener('wheel', (e)=>{ e.preventDefault(); inp.blur(); }, {passive:false});
  });

  $("btnLogin").addEventListener("click", doLogin);
  $("btnLogout").addEventListener("click", doLogout);
  if ($("btnMyAccount")) $("btnMyAccount").addEventListener("click", ()=> showView("accountView"));

  $("btnOpenRegister").addEventListener("click", openRegister);
  $("btnCloseRegister").addEventListener("click", closeRegister);
  $("btnRegister").addEventListener("click", doRegister);

  $("loginPassword").addEventListener("keydown", (e)=>{ if (e.key === "Enter") doLogin(); });

  $("btnRefreshDash").addEventListener("click", refreshDashboard);
  if ($("btnAccountReload")) $("btnAccountReload").addEventListener("click", loadMyAccount);
  if ($("btnAccountSave")) $("btnAccountSave").addEventListener("click", saveMyAccount);
  if ($("btnAccountClose")) $("btnAccountClose").addEventListener("click", ()=> showView("dashboardView"));

  $("btnAddContrib").addEventListener("click", addContribution);
  $("btnReloadContrib").addEventListener("click", async()=>{ await loadContributions(); renderContribTable(); });

  $("btnFilterContrib").addEventListener("click", renderContribTable);
  $("btnClearContrib").addEventListener("click", ()=>{
    $("c_q").value=""; $("c_from").value=""; $("c_to").value=""; renderContribTable();
  });

  if ($("btnAddDep")) $("btnAddDep").addEventListener("click", addDepense);
  if ($("btnReloadDep")) $("btnReloadDep").addEventListener("click", async()=>{ await loadDepenses(); renderDepensesTable(); });
  if ($("btnUploadJustif")) $("btnUploadJustif").addEventListener("click", uploadJustif);

  $("btnReloadReports").addEventListener("click", refreshReports);
  $("btnExportPDF").addEventListener("click", exportPdf);
  $("btnExportXLSX").addEventListener("click", exportXlsx);

  if ($("btnReloadAccounts")) $("btnReloadAccounts").addEventListener("click", refreshAccounts);
  if ($("btnAdminCreateAccount")) $("btnAdminCreateAccount").addEventListener("click", adminCreateMemberAccount);
  if ($("btnSaveConfig")) $("btnSaveConfig").addEventListener("click", adminSaveConfig);
}

async function init(){
  wire();

  if (token){
    try{
      await bootstrap();
      return;
    }catch{
      doLogout();
    }
  }
  setAuthUI(false);
}

init();
