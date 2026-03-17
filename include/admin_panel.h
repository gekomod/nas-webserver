static const char* ADMIN_HTML = R"HTMLEOF(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>nas-web admin</title>
<style>
/* JetBrains Mono & Syne loaded from system/fallback — no external requests */
:root{
  color-scheme: dark light;
}
:root.light{
  --bg:        #f0f2f5;
  --bg2:       #ffffff;
  --bg3:       #e8eaee;
  --panel:     #ffffff;
  --border:    #ced3de;
  --text:      #2e3440;
  --bright:    #1a1e2e;
  --dim:       #7a8499;
  --accent:    #00916e;
  --accent2:   #0055bb;
  --warn:      #b85c00;
  --red:       #bb2222;
  --green:     #006e48;
  --sidebar:   #e4e8f0;
  --nav-active:#d6dce8;
  --shadow:    0 1px 6px rgba(0,0,0,0.10);
}
:root{--bg:#0a0b0d;--bg2:#0f1114;--bg3:#151820;--border:#1e2330;--accent:#00d4aa;--accent2:#0088ff;--warn:#ff6b35;--red:#ff3355;--dim:#3a4055;--text:#c8d0e0;--bright:#eef2ff}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas','Liberation Mono',monospace;font-size:13px;min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:40px 40px;opacity:.22}
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:1;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.025) 2px,rgba(0,0,0,.025) 4px)}

/* LOGIN */
.login-wrap{position:fixed;inset:0;z-index:100;display:flex;align-items:center;justify-content:center;background:var(--bg)}
.login-wrap.hidden{display:none}
.login-card{width:360px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.login-head{padding:32px 32px 24px;text-align:center;border-bottom:1px solid var(--border);background:var(--bg3)}
.login-mark{width:48px;height:48px;background:var(--accent);clip-path:polygon(0 0,100% 0,100% 60%,60% 100%,0 100%);margin:0 auto 16px;display:flex;align-items:center;justify-content:center}
.login-mark svg{width:22px;height:22px;fill:#000}
.login-title{font-family:'Syne','Inter','Segoe UI','SF Pro Display',system-ui,sans-serif;font-size:20px;font-weight:800;color:var(--bright)}
.login-sub{font-size:11px;color:var(--dim);margin-top:4px}
.login-body{padding:28px 32px 32px}
.field{margin-bottom:16px}
.field label{display:block;font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--dim);margin-bottom:6px}
.field input{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:10px 12px;color:var(--bright);font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas','Liberation Mono',monospace;font-size:13px;outline:none;transition:border-color .15s}
.field input:focus{border-color:var(--accent)}
.login-btn{width:100%;padding:11px;background:var(--accent);border:none;border-radius:4px;color:#000;font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas','Liberation Mono',monospace;font-size:13px;font-weight:500;cursor:pointer;transition:background .15s;margin-top:8px}
.login-btn:hover{background:#00ffcc}
.login-err{color:var(--red);font-size:11px;text-align:center;margin-top:12px;min-height:16px}

/* SHELL */
.shell{position:relative;z-index:2;display:flex;flex-direction:column;min-height:100vh}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 28px;background:var(--bg2);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10}
.logo{display:flex;align-items:center;gap:12px}
.logo-mark{width:32px;height:32px;background:var(--accent);clip-path:polygon(0 0,100% 0,100% 60%,60% 100%,0 100%);display:flex;align-items:center;justify-content:center}
.logo-mark svg{width:16px;height:16px;fill:#000}
.logo-name{font-family:'Syne','Inter','Segoe UI','SF Pro Display',system-ui,sans-serif;font-weight:800;font-size:18px;color:var(--bright);letter-spacing:-.5px}
.logo-name span{color:var(--accent)}
.logo-ver{font-size:10px;color:var(--dim);background:var(--bg3);border:1px solid var(--border);padding:2px 6px;border-radius:3px}
.header-right{display:flex;align-items:center;gap:12px}
.status-pill{display:flex;align-items:center;gap:6px;padding:5px 12px;border-radius:20px;background:rgba(0,212,170,.08);border:1px solid rgba(0,212,170,.2);font-size:11px;color:var(--accent)}
.status-dot{width:6px;height:6px;border-radius:50%;background:var(--accent);box-shadow:0 0 6px var(--accent);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.hdr-time{color:var(--dim);font-size:11px}
.waf-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 7px;
border-radius:3px;font-size:10px;font-weight:700;letter-spacing:.04em;
font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas','Liberation Mono',monospace;
white-space:nowrap;cursor:default}
.logout-btn{padding:5px 12px;background:transparent;border:1px solid var(--border);border-radius:4px;color:var(--dim);font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas','Liberation Mono',monospace;font-size:11px;cursor:pointer;transition:all .15s}
.logout-btn:hover{color:var(--red);border-color:rgba(255,51,85,.3)}
.refresh-bar{height:2px;background:var(--border);position:relative}
.refresh-progress{height:100%;background:var(--accent);width:0%;transition:width linear}

main{display:grid;grid-template-columns:220px 1fr;flex:1}
nav{background:var(--bg2);border-right:1px solid var(--border);padding:20px 0;display:flex;flex-direction:column;gap:2px;overflow-y:auto}
.nav-section{padding:8px 20px 4px;font-size:9px;letter-spacing:2px;color:var(--dim);text-transform:uppercase;margin-top:4px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;cursor:pointer;color:var(--dim);transition:all .15s;border-left:2px solid transparent;font-size:12px;user-select:none}
.nav-item:hover{color:var(--text);background:var(--bg3)}
.nav-item.active{color:var(--accent);background:rgba(0,212,170,.06);border-left-color:var(--accent)}
.nav-icon{width:14px;height:14px;opacity:.7;flex-shrink:0}
.nav-item.active .nav-icon{opacity:1}

.content{padding:24px 28px;overflow-y:auto}
.section{display:none}
.section.active{display:block}
.page-title{display:flex;align-items:baseline;gap:12px;margin-bottom:24px}
.page-title h1{font-family:'Syne','Inter','Segoe UI','SF Pro Display',system-ui,sans-serif;font-weight:700;font-size:22px;color:var(--bright)}
.page-title .sub{color:var(--dim);font-size:11px}

.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.stat-card{background:var(--bg2);border:1px solid var(--border);padding:16px 18px;border-radius:6px;position:relative;overflow:hidden;transition:border-color .2s}
.stat-card:hover{border-color:var(--dim)}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.stat-card.green::before{background:var(--accent)}.stat-card.blue::before{background:var(--accent2)}.stat-card.orange::before{background:var(--warn)}.stat-card.red::before{background:var(--red)}
.stat-label{font-size:10px;color:var(--dim);letter-spacing:1px;text-transform:uppercase;margin-bottom:8px}
.stat-val{font-size:26px;color:var(--bright);font-weight:300;line-height:1}
.stat-val.sm{font-size:17px}
.stat-sub{font-size:10px;color:var(--dim);margin-top:4px}

.chart-panel{background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:16px;overflow:hidden}
.chart-head{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--bg3)}
.chart-title{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--accent)}
.chart-body{padding:12px 16px 4px;height:110px}
canvas{display:block;width:100%!important}

.panel{background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:16px;overflow:hidden}
.panel-head{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--bg3)}
.panel-title{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--accent)}

table{width:100%;border-collapse:collapse}
th{padding:9px 14px;text-align:left;font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--dim);border-bottom:1px solid var(--border);background:var(--bg3)}
td{padding:9px 14px;border-bottom:1px solid rgba(30,35,48,.6);font-size:12px;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.015)}

.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:500}
.badge.green{background:rgba(0,212,170,.12);color:var(--accent);border:1px solid rgba(0,212,170,.2)}
.badge.red{background:rgba(255,51,85,.12);color:var(--red);border:1px solid rgba(255,51,85,.2)}
.badge.blue{background:rgba(0,136,255,.12);color:var(--accent2);border:1px solid rgba(0,136,255,.2)}
.badge.orange{background:rgba(255,107,53,.12);color:var(--warn);border:1px solid rgba(255,107,53,.2)}
.badge.dim{background:rgba(58,64,85,.15);color:var(--dim);border:1px solid var(--border)}
.badge.purple{background:rgba(160,100,255,.12);color:#a064ff;border:1px solid rgba(160,100,255,.2)}

.gauge-row{display:flex;gap:12px;margin-bottom:16px}
.gauge{flex:1;background:var(--bg2);border:1px solid var(--border);border-radius:5px;padding:14px;text-align:center}
.gauge-label{font-size:10px;color:var(--dim);letter-spacing:1px;text-transform:uppercase;margin-bottom:10px}
.gauge-circle{width:80px;height:80px;margin:0 auto 8px;position:relative}
.gauge-circle svg{transform:rotate(-90deg)}
.gauge-track{fill:none;stroke:var(--bg3);stroke-width:8}
.gauge-fill{fill:none;stroke-width:8;stroke-linecap:round;transition:stroke-dashoffset 1s ease}
.gauge-text{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:15px;color:var(--bright);font-weight:500}

.worker-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;padding:16px}
.worker-card{background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:14px}
.worker-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.worker-id{font-family:'Syne','Inter','Segoe UI','SF Pro Display',system-ui,sans-serif;font-size:14px;color:var(--bright)}
.worker-stat{display:flex;justify-content:space-between;margin-bottom:5px}
.worker-key{color:var(--dim);font-size:11px}
.worker-val{color:var(--text);font-size:11px}

/* LOG VIEWER */
.log-toolbar{display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--border);background:var(--bg3);flex-wrap:wrap}
.log-filter{display:flex;gap:4px}
.log-lvl{padding:3px 10px;border-radius:3px;border:1px solid var(--border);background:transparent;color:var(--dim);font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas','Liberation Mono',monospace;font-size:10px;cursor:pointer;transition:all .15s}
.log-lvl.active-error{background:rgba(255,51,85,.12);color:var(--red);border-color:rgba(255,51,85,.3)}
.log-lvl.active-warn{background:rgba(255,107,53,.12);color:var(--warn);border-color:rgba(255,107,53,.3)}
.log-lvl.active-info{background:rgba(0,212,170,.12);color:var(--accent);border-color:rgba(0,212,170,.3)}
.log-lvl.active-debug{background:rgba(0,136,255,.12);color:var(--accent2);border-color:rgba(0,136,255,.3)}
.log-search{flex:1;min-width:140px;background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:5px 10px;color:var(--text);font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas','Liberation Mono',monospace;font-size:11px;outline:none}
.log-search:focus{border-color:var(--accent)}
.log-box{background:var(--bg);padding:10px 16px;font-size:11px;line-height:1.9;height:320px;overflow-y:auto;color:var(--dim)}
.log-box::-webkit-scrollbar{width:4px}
.log-box::-webkit-scrollbar-thumb{background:var(--border)}
.log-entry{display:flex;gap:10px;font-variant-numeric:tabular-nums;padding:1px 0}
.log-entry.hidden{display:none}
.log-ts{color:var(--dim);flex-shrink:0;width:86px;font-size:10px}
.log-lv{width:48px;flex-shrink:0;font-weight:500;font-size:10px}
.lv-error{color:var(--red)}.lv-warn{color:var(--warn)}.lv-info{color:var(--accent)}.lv-debug{color:var(--accent2)}
.log-msg{color:var(--text);flex:1}
.log-ip{color:var(--dim);flex-shrink:0;width:110px;font-size:10px}

/* CACHE */
.cache-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;padding:16px}
.cache-stat{background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:14px;text-align:center}
.cache-stat-val{font-size:24px;color:var(--bright);font-weight:300;margin-bottom:4px}
.cache-stat-key{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px}
.cache-bar{height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;margin:8px 0 4px}
.cache-bar-fill{height:100%;border-radius:3px;background:var(--accent);transition:width .8s ease}
.cache-entry{display:flex;align-items:center;gap:12px;padding:8px 16px;border-bottom:1px solid rgba(30,35,48,.5)}
.cache-entry:last-child{border-bottom:none}
.cache-key{flex:1;color:var(--text);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cache-size{color:var(--dim);font-size:11px;width:60px;text-align:right}
.cache-ttl{width:70px;text-align:right}
.cache-del{background:transparent;border:1px solid rgba(255,51,85,.2);color:var(--red);padding:2px 8px;border-radius:3px;font-size:10px;cursor:pointer;font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas','Liberation Mono',monospace;transition:all .15s}
.cache-del:hover{background:rgba(255,51,85,.1)}

/* MODULES */
.modules-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;padding:16px}
.module-card{background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:16px}
.module-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px}
.module-name{font-family:'Syne','Inter','Segoe UI','SF Pro Display',system-ui,sans-serif;font-size:14px;color:var(--bright)}
.module-ver{font-size:10px;color:var(--dim);margin-top:2px}
.module-desc{font-size:11px;color:var(--dim);line-height:1.6;margin-bottom:10px}
.module-detail{display:flex;flex-wrap:wrap;gap:6px}
.module-tag{font-size:10px;padding:2px 8px;background:var(--bg);border:1px solid var(--border);border-radius:3px;color:var(--dim)}

/* SYSTEM INFO */
.sysinfo-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;padding:16px}
.sysinfo-card{background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:14px}
.sysinfo-title{font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--accent);margin-bottom:12px}
.sysinfo-row{display:flex;justify-content:space-between;margin-bottom:7px;font-size:11px}
.sysinfo-key{color:var(--dim)}
.sysinfo-val{color:var(--text)}

/* BAR */
.bar-row{display:flex;align-items:center;gap:12px;padding:8px 16px;border-bottom:1px solid rgba(30,35,48,.5)}
.bar-row:last-child{border-bottom:none}
.bar-label{width:160px;font-size:11px;color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:4px;background:var(--bg3);border-radius:2px;overflow:hidden}
.bar-fill{height:100%;border-radius:2px;transition:width .8s ease}
.bar-val{width:60px;text-align:right;font-size:11px;color:var(--text)}

/* CONFIG */
.config-area{background:var(--bg);border:none;outline:none;resize:none;width:100%;height:340px;padding:16px;color:var(--text);font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas','Liberation Mono',monospace;font-size:12px;line-height:1.7}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:4px;border:none;cursor:pointer;font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas','Liberation Mono',monospace;font-size:12px;transition:all .15s}
.btn-primary{background:var(--accent);color:#000;font-weight:500}.btn-primary:hover{background:#00ffcc}
.btn-ghost{background:transparent;color:var(--dim);border:1px solid var(--border)}.btn-ghost:hover{color:var(--text);border-color:var(--dim)}
.btn-danger{background:transparent;color:var(--red);border:1px solid rgba(255,51,85,.3)}.btn-danger:hover{background:rgba(255,51,85,.08)}
.btn-warn{background:transparent;color:var(--warn);border:1px solid rgba(255,107,53,.3)}.btn-warn:hover{background:rgba(255,107,53,.08)}
.panel-actions{display:flex;gap:8px;padding:12px 16px;border-top:1px solid var(--border);flex-wrap:wrap}

.toast{position:fixed;bottom:24px;right:24px;background:var(--bg2);border:1px solid var(--accent);color:var(--accent);padding:10px 20px;border-radius:5px;font-size:12px;z-index:999;opacity:0;transition:opacity .3s;pointer-events:none}
.toast.show{opacity:1}

.mod-card{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:14px;display:flex;flex-direction:column;gap:6px}
.mod-title{font-weight:600;color:var(--bright);font-size:13px}
.mod-desc{font-size:11px;color:var(--dim);line-height:1.6}
.feature-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border)}
.feature-row:last-child{border-bottom:none}
.toggle-switch{position:relative;display:inline-block;width:36px;height:20px;flex-shrink:0}
.toggle-switch input{opacity:0;width:0;height:0}
.toggle-track{position:absolute;cursor:pointer;inset:0;background:var(--bg3);border-radius:20px;transition:.2s;border:1px solid var(--border)}
.toggle-track:before{content:"";position:absolute;height:14px;width:14px;left:2px;bottom:2px;background:var(--dim);border-radius:50%;transition:.2s}
.toggle-switch input:checked+.toggle-track{background:var(--accent);border-color:var(--accent)}
.toggle-switch input:checked+.toggle-track:before{transform:translateX(16px);background:#fff}
.mod-stat-card{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:12px;text-align:center}
.mod-stat-name{font-weight:600;color:var(--bright);font-size:12px}
.mod-cfg{display:block;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:8px;font-size:10px;color:var(--accent);white-space:pre;overflow-x:auto;margin:4px 0;font-family:monospace}

/* ── Hamburger button ─────────────────────────────────────────────────────── */
#nav-toggle {
  display: none;
  flex-direction: column;
  justify-content: space-between;
  width: 28px; height: 20px;
  background: none; border: none; cursor: pointer; padding: 0;
  flex-shrink: 0;
}
#nav-toggle span {
  display: block; width: 100%; height: 2px;
  background: var(--text); border-radius: 2px;
  transition: all .2s;
}
body.nav-open #nav-toggle span:nth-child(1){ transform: translateY(9px) rotate(45deg); }
body.nav-open #nav-toggle span:nth-child(2){ opacity: 0; }
body.nav-open #nav-toggle span:nth-child(3){ transform: translateY(-9px) rotate(-45deg); }

/* ── Nav overlay (mobile) ─────────────────────────────────────────────────── */
#nav-overlay {
  display: none;
  position: fixed; inset: 0; z-index: 29;
  background: rgba(0,0,0,.45);
}
body.nav-open #nav-overlay { display: block; }

/* ── Responsive breakpoints ───────────────────────────────────────────────── */
@media (max-width: 768px) {
  /* Show hamburger */
  #nav-toggle { display: flex; }

  /* Header compact */
  header { padding: 10px 14px; gap: 8px; }
  .logo-text { font-size: 14px; }
  .logo-ver  { font-size: 9px; }
  .hdr-time  { display: none; }
  #theme-toggle { padding: 4px 7px; font-size: 11px; }
  .logout-btn   { padding: 5px 10px; font-size: 11px; }

  /* Slide-in sidebar */
  main { grid-template-columns: 1fr; }
  #sidebar {
    position: fixed; top: 0; left: -240px; bottom: 0;
    width: 240px; z-index: 30;
    padding-top: 60px;
    transition: left .25s ease;
    box-shadow: 4px 0 20px rgba(0,0,0,.4);
  }
  body.nav-open #sidebar { left: 0; }

  /* Content full width */
  .content { padding: 12px; }
  .section { padding: 12px; }

  /* Overview grid: single column */
  .overview-grid,
  .stats-grid,
  .modules-grid { grid-template-columns: 1fr !important; }

  /* Charts: stack vertically */
  .chart-grid { grid-template-columns: 1fr !important; }

  /* Cards full width */
  .card { min-width: 0 !important; }

  /* Tables: scroll horizontally */
  .table-wrap, table { overflow-x: auto; display: block; }

  /* Log box smaller */
  .log-box { height: 220px !important; font-size: 10px; }
  .log-ts  { width: 60px; }
  .log-ip  { width: 80px; }

  /* Config textarea */
  .config-area { height: 220px; font-size: 11px; }

  /* SSL/TLS panel */
  .ssl-grid { grid-template-columns: 1fr !important; }

  /* Upstream / blacklist tables */
  .bar-label { width: 100px; }

  /* Buttons wrap */
  .btn-row { flex-wrap: wrap; gap: 6px; }

  /* All 2-col grids → 1 col */
  .stat-grid, .worker-grid, .cache-grid,
  .sysinfo-grid, #modules-grid { grid-template-columns: 1fr !important; }
  .stat-grid { grid-template-columns: repeat(2,1fr) !important; }

  /* Inline search inputs full width */
  input.log-search { width: 100% !important; box-sizing: border-box; }

  /* Connections table — scrollable */
  #conn-table-wrap { overflow-x: auto; }

  /* Upstream/blacklist rows wrap */
  .up-row { flex-wrap: wrap; }

  /* Section headers wrap */
  .sec-header { flex-wrap: wrap; gap: 8px; }
  .sec-header h2 { font-size: 14px; }

  /* Login card full width on small screens */
  .login-card { width: 92vw; min-width: 0; }

  /* Audit/log toolbar wrap */
  .log-toolbar { flex-wrap: wrap; gap: 6px; }
}

@media (max-width: 480px) {
  header { padding: 8px 10px; }
  .logo-mark { width: 26px; height: 26px; }
  .content { padding: 8px; }

  /* Stat boxes single col */
  .stat-box { padding: 10px; }
  .stat-val  { font-size: 20px; }

  /* Gauge smaller */
  .gauge-circle { width: 64px; height: 64px; }
  .gauge-svg    { width: 64px; height: 64px; }

  /* Log IP hidden on very small */
  .log-ip { display: none; }

  /* Dashboard canvases */
  canvas { height: 80px !important; }

  /* stat-grid single col */
  .stat-grid { grid-template-columns: 1fr !important; }

  /* Hide less important log columns */
  .log-lv  { display: none; }

  /* Header: hide version badge */
  .logo-ver { display: none; }

  /* Smaller section padding */
  .content { padding: 6px !important; }
  .section > div { padding: 10px !important; }

  /* Buttons smaller */
  .btn { padding: 5px 10px !important; font-size: 11px !important; }
}


</style>
</head>
<body>

<!-- LOGIN -->
<div class="login-wrap" id="login-wrap">
  <div class="login-card">
    <div class="login-head">
      <div class="login-mark"><svg viewBox="0 0 16 16"><path d="M2 2h5v2H4v8h8v-3h2v5H2V2z"/><path d="M8 2h6v6h-2V5.4L7.4 10 6 8.6 10.6 4H8V2z"/></svg></div>
      <div class="login-title">nas<span style="color:var(--accent)">-web</span></div>
      <div class="login-sub">Admin Panel — sign in to continue</div>
    </div>
    <div class="login-body">
      <div class="field"><label>Username</label><input type="text" id="l-user" value="admin" autocomplete="username"></div>
      <div class="field"><label>Password</label><input type="password" id="l-pass" placeholder="••••••••" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()"></div>
      <button class="login-btn" onclick="doLogin()">Sign in &#8594;</button>
      <div class="login-err" id="l-err"></div>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>

<!-- APP -->
<div class="shell" id="app" style="display:none">
<header>
  <div class="logo">
    <div class="logo-mark"><svg viewBox="0 0 16 16"><path d="M2 2h5v2H4v8h8v-3h2v5H2V2z"/><path d="M8 2h6v6h-2V5.4L7.4 10 6 8.6 10.6 4H8V2z"/></svg></div>
    <div class="logo-name">nas<span>-web</span></div>
    <div class="logo-ver" id="hdr-version">v2.2.83</div>
  </div>
  <button id="nav-toggle" onclick="toggleNav()" aria-label="Menu">
    <span></span><span></span><span></span>
  </button>
  <div class="header-right">
    <div class="status-pill"><div class="status-dot"></div><span id="hdr-status">running</span></div>
    <div id="hdr-secured-badge" style="display:none;align-items:center;gap:5px;
      padding:3px 9px;background:rgba(0,212,170,.1);border:1px solid rgba(0,212,170,.3);
      border-radius:3px;font-size:10px;font-weight:700;color:#00d4aa;
      font-family:'JetBrains Mono','Cascadia Code','Fira Code','Consolas',monospace;
      letter-spacing:.04em;cursor:default" title="WAF aktywny — ruch filtrowany">
      🛡 SECURED BY WAF
    </div>
    <div class="hdr-time" id="hdr-clock"></div>
    <button id="theme-toggle" onclick="toggleTheme()" style="background:none;border:1px solid var(--border);border-radius:4px;padding:4px 10px;cursor:pointer;color:var(--dim);font-size:13px;margin-right:6px" title="Toggle light/dark">&#9788;</button>
    <button class="logout-btn" onclick="doLogout()">&#x23CF; logout</button>
  </div>
</header>
<div class="refresh-bar"><div class="refresh-progress" id="refresh-bar"></div></div>

<div id="nav-overlay" onclick="closeNav()"></div>
<main>
<nav id="sidebar">
  <div class="nav-section">monitor</div>
  <div class="nav-item active" onclick="show('overview',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M1 1h6v6H1V1zm8 0h6v6H9V1zM1 9h6v6H1V9zm8 0h6v6H9V9z"/></svg>Overview
  </div>
  <div class="nav-item" onclick="show('connections',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M2 5h12v6H2V5zm1 1v4h10V6H3z"/></svg>Connections
  </div>
  <div class="nav-item" onclick="show('workers',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a3 3 0 100 6A3 3 0 008 1zM3 9a5 5 0 0110 0v1H3V9z"/></svg>Workers
  </div>
  <div class="nav-item" onclick="show('upstream',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1l3 5H5L8 1zm0 14l-3-5h6L8 15zM1 6h14v4H1V6z"/></svg>Upstream
  </div>
  <div class="nav-section">system</div>
  <div class="nav-item" onclick="show('logs',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M2 1h12v2H2V1zm0 4h12v2H2V5zm0 4h8v2H2V9zm0 4h10v2H2v-2z"/></svg>Logs
  </div>
  <div class="nav-item" onclick="show('cache',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1C4.7 1 2 3 2 5.5S4.7 10 8 10s6-2 6-4.5S11.3 1 8 1zm0 8c-2.8 0-5-1.6-5-3.5S5.2 2 8 2s5 1.6 5 3.5S10.8 9 8 9zm-5 2c0 2 2.2 3.5 5 3.5s5-1.5 5-3.5"/></svg>Cache
  </div>
  <div class="nav-item" onclick="show('modules',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M2 2h5v5H2V2zm7 0h5v5H9V2zM2 9h5v5H2V9zm7 0h5v5H9V9z"/></svg>Modules
  </div>
  <div class="nav-item" onclick="show('sysinfo',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 3a1 1 0 110 2 1 1 0 010-2zm-1 3h2v5H7V7z"/></svg>System Info
  </div>
  <div class="nav-item" onclick="show('config',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M6.5 1L5 3H2v2l-1 1 1 1v2h3l1.5 2h3L11 9h3V7l1-1-1-1V3h-3L9.5 1h-3zM8 5.5a2.5 2.5 0 110 5 2.5 2.5 0 010-5z"/></svg>Config
  </div>
  <div class="nav-item" onclick="show('ssl',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a4 4 0 00-4 4v1H3v9h10V6h-1V5a4 4 0 00-4-4zm0 2a2 2 0 012 2v1H6V5a2 2 0 012-2zm0 6a1 1 0 110 2 1 1 0 010-2z"/></svg>SSL / TLS
  </div>
  <div class="nav-item" onclick="show('security',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1l-6 2.5v4C2 11 5 14 8 15c3-1 6-4 6-7.5v-4L8 1zm0 2.2l4 1.6v3.7c0 2-1.8 4.1-4 5-2.2-.9-4-3-4-5V4.8l4-1.6zm-1 3.3v4h2v-4H7zm0-2v1.5h2V4.5H7z"/></svg>Security
  </div>
  <div class="nav-item" onclick="show('upstreams',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M1 3h14v2H1V3zm2 4h10v2H3V7zm2 4h6v2H5v-2z"/></svg>Upstreams
  </div>
  <div class="nav-item" onclick="show('dashboard',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M1 10h3v4H1v-4zm4-4h3v8H5V6zm4-4h3v12H9V2zm4 6h2v6h-2V8z"/></svg>Dashboard
  </div>
  <div class="nav-item" onclick="show('audit',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M2 2h12v2H2V2zm0 3h12v1H2V5zm0 2h8v1H2V7zm0 2h12v1H2V9zm0 2h6v1H2v-1zm0 2h10v1H2v-1z"/></svg>Audit
  </div>
  <div class="nav-item" onclick="show('autoban',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1l7 3v4c0 3.5-3 6.5-7 8C3 16 0 13 0 9.5V4l8-3zm0 2L2 5.5V9c0 2.5 2.5 5 6 6.5 3.5-1.5 6-4 6-6.5V5.5L8 3zm-1 4h2v4H7V7zm0-3h2v2H7V4z"/></svg>AutoBan
  </div>
  <div class="nav-item" onclick="show('waf-regex',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0L1 3v5c0 4.1 3 7.9 7 9 4-1.1 7-4.9 7-9V3L8 0zm-1 11.5l-3-3 1.1-1.1 1.9 1.9 4-4L12 6.4l-5 5.1z"/></svg>WAF Regex
  </div>
  <div class="nav-item" onclick="show('waf',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0L1 3v5c0 4.1 3 7.9 7 9 4-1.1 7-4.9 7-9V3L8 0zm0 2l5 2.2V8c0 2.8-2.2 5.3-5 6.3C5.2 13.3 3 10.8 3 8V4.2L8 2z"/></svg>WAF ModSec
  </div>
  <div class="nav-item" id="nav-db" style="display:none" onclick="show('db',this)">
    <svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 2C4.69 2 2 3.12 2 4.5S4.69 7 8 7s6-1.12 6-2.5S11.31 2 8 2zM2 6.5v2C2 9.88 4.69 11 8 11s6-1.12 6-2.5v-2C14 7.88 11.31 9 8 9S2 7.88 2 6.5zM2 10.5v2C2 13.88 4.69 15 8 15s6-1.12 6-2.5v-2C14 11.88 11.31 13 8 13s-6-1.12-6-2.5z"/></svg>SQLite — Baza
  </div>
</nav>

<div class="content">

<!-- OVERVIEW -->
<div class="section active" id="sec-overview">
  <div class="page-title"><h1>Overview</h1><span class="sub">auto-refresh 3s</span></div>
  <div class="stat-grid">
    <div class="stat-card green"><div class="stat-label">Total Requests</div><div class="stat-val" id="s-req">—</div><div class="stat-sub" id="s-rps">—</div></div>
    <div class="stat-card blue"><div class="stat-label">Cache Hits</div><div class="stat-val" id="s-cache">—</div><div class="stat-sub" id="s-cache-pct">—</div></div>
    <div class="stat-card orange"><div class="stat-label">Errors</div><div class="stat-val" id="s-err">—</div><div class="stat-sub" id="s-err-pct">—</div></div>
    <div class="stat-card green"><div class="stat-label">Uptime</div><div class="stat-val sm" id="s-uptime">—</div><div class="stat-sub" id="s-workers">—</div></div>
    <div class="stat-card"><div class="stat-label">RAM (RSS)</div><div class="stat-val sm" id="s-ram">—</div><div class="stat-sub" id="s-cpu">—</div></div>
  </div>
  <!-- WAF stats row -->
  <div id="waf-stat-row" style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">
    <div style="background:var(--bg2);border:1px solid rgba(255,68,68,.25);border-radius:8px;padding:14px 16px;cursor:pointer" onclick="show('waf-regex',null)">
      <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">WAF Blocked</div>
      <div style="font-size:24px;font-weight:700;color:#ff4444;line-height:1" id="dash-waf-blocked">—</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px" id="dash-waf-blocked-sub">regex + modsec</div>
    </div>
    <div style="background:var(--bg2);border:1px solid rgba(200,70,255,.25);border-radius:8px;padding:14px 16px;cursor:pointer" onclick="show('waf-regex',null)">
      <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">WAF Detected</div>
      <div style="font-size:24px;font-weight:700;color:#cc44ff;line-height:1" id="dash-waf-detected">—</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px">detect-only events</div>
    </div>
    <div style="background:var(--bg2);border:1px solid rgba(255,136,0,.25);border-radius:8px;padding:14px 16px;cursor:pointer" onclick="show('waf-regex',null)">
      <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Top Threat</div>
      <div style="font-size:16px;font-weight:700;color:#ff8800;line-height:1.3;margin-top:2px" id="dash-waf-top-threat">—</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px" id="dash-waf-top-sub">ostatnie zdarzenie</div>
    </div>
    <div style="background:var(--bg2);border:1px solid rgba(0,136,255,.25);border-radius:8px;padding:14px 16px;cursor:pointer" onclick="show('waf-regex',null)">
      <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">WAF Checked</div>
      <div style="font-size:24px;font-weight:700;color:#0088ff;line-height:1" id="dash-waf-checked">—</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px" id="dash-waf-mode-sub">—</div>
    </div>
  </div>

  <div class="chart-panel">
    <div class="chart-head"><span class="chart-title">Requests / second — last 60s</span><span id="chart-rps" style="font-size:11px;color:var(--accent)">0 req/s</span></div>
    <div class="chart-body"><canvas id="rps-chart" height="90"></canvas></div>
  </div>
  <div class="gauge-row">
    <div class="gauge"><div class="gauge-label">Cache Hit Rate</div><div class="gauge-circle"><svg width="80" height="80" viewBox="0 0 80 80"><circle class="gauge-track" cx="40" cy="40" r="32"/><circle class="gauge-fill" id="g-cache" cx="40" cy="40" r="32" stroke="#00d4aa" stroke-dasharray="201" stroke-dashoffset="201"/></svg><div class="gauge-text" id="g-cache-txt">0%</div></div></div>
    <div class="gauge"><div class="gauge-label">Error Rate</div><div class="gauge-circle"><svg width="80" height="80" viewBox="0 0 80 80"><circle class="gauge-track" cx="40" cy="40" r="32"/><circle class="gauge-fill" id="g-err" cx="40" cy="40" r="32" stroke="#ff3355" stroke-dasharray="201" stroke-dashoffset="201"/></svg><div class="gauge-text" id="g-err-txt">0%</div></div></div>
    <div class="gauge"><div class="gauge-label">Proxy Success</div><div class="gauge-circle"><svg width="80" height="80" viewBox="0 0 80 80"><circle class="gauge-track" cx="40" cy="40" r="32"/><circle class="gauge-fill" id="g-ok" cx="40" cy="40" r="32" stroke="#0088ff" stroke-dasharray="201" stroke-dashoffset="201"/></svg><div class="gauge-text" id="g-ok-txt">0%</div></div></div>
    <div class="gauge"><div class="gauge-label">Workers Active</div><div class="gauge-circle"><svg width="80" height="80" viewBox="0 0 80 80"><circle class="gauge-track" cx="40" cy="40" r="32"/><circle class="gauge-fill" id="g-w" cx="40" cy="40" r="32" stroke="#ff6b35" stroke-dasharray="201" stroke-dashoffset="100"/></svg><div class="gauge-text" id="g-w-txt">—</div></div></div>
  </div>
</div>

<!-- CONNECTIONS -->
<div class="section" id="sec-connections">
  <div class="page-title"><h1>Connections</h1><span class="sub">active now</span></div>
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Active</span><span class="badge green" id="conn-count">0</span></div>
    <table><thead><tr><th>IP</th><th>Method</th><th>Path</th><th>Status</th><th>Age</th><th>Type</th></tr></thead>
    <tbody id="conn-table"></tbody></table>
  </div>
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Top IPs — last 60s</span></div>
    <div id="top-ips"></div>
  </div>
</div>

<!-- WORKERS -->
<div class="section" id="sec-workers">
  <div class="page-title"><h1>Workers</h1><span class="sub">per-worker stats</span></div>
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Worker Pool</span><span class="badge green" id="w-count">—</span></div>
    <div class="worker-grid" id="worker-grid"></div>
  </div>
</div>

<!-- UPSTREAM -->
<div class="section" id="sec-upstream">
  <div class="page-title"><h1>Upstream</h1><span class="sub">backend pools</span></div>
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Pools</span></div>
    <table><thead><tr><th>Name</th><th>Address</th><th>State</th><th>Requests</th><th>Errors</th><th>Latency</th></tr></thead>
    <tbody id="upstream-pool-table">
      <tr><td>node_api</td><td style="color:var(--accent2)">127.0.0.1:1112</td><td><span class="badge green" id="up-state">healthy</span></td><td id="up-req">—</td><td id="up-err">—</td><td id="up-lat">—</td></tr>
    </tbody></table>
  </div>
</div>

<!-- LOGS -->
<div class="section" id="sec-logs">
  <div class="page-title"><h1>Logs</h1><span class="sub">server events · log files</span></div>

  <!-- ── Server Internal Log ─────────────────────────────────────────────── -->
  <div class="panel">
    <div class="panel-head">
      <span class="panel-title">⚙️ Server Log</span>
      <span class="badge dim" id="srv-log-count">0 wpisów</span>
      <div style="display:flex;gap:6px;margin-left:auto;align-items:center">
        <button class="log-lvl active-error" id="sl-error" onclick="toggleSrvFilter('error',this)">ERROR</button>
        <button class="log-lvl active-warn"  id="sl-warn"  onclick="toggleSrvFilter('warn',this)">WARN</button>
        <button class="log-lvl active-info"  id="sl-info"  onclick="toggleSrvFilter('info',this)">INFO</button>
        <button class="log-lvl active-debug" id="sl-debug" onclick="toggleSrvFilter('debug',this)">DEBUG</button>
        <input class="log-search" id="srv-search" placeholder="szukaj modułu, wiadomości..." oninput="filterSrvLog()" style="width:200px">
        <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="clearLog('server-log')">wyczyść</button>
        <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="fetchServerLogs()">↺</button>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:155px 60px 80px minmax(0,1fr);padding:4px 12px;border-bottom:1px solid var(--border);font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.05em">
      <span>Czas</span><span>Level</span><span>Moduł</span><span>Wiadomość</span>
    </div>
    <div class="log-box" id="server-log" style="max-height:460px"></div>
    <div style="padding:6px 12px;font-size:10px;color:var(--dim);border-top:1px solid var(--border)">
      Ring buffer 500 wpisów · źródło: <code>/np_logs</code> · odświeżanie co 3s
    </div>
  </div>

  <!-- ── Log Files on Disk ──────────────────────────────────────────────── -->
  <div class="panel" style="margin-top:16px">
    <div class="panel-head">
      <span class="panel-title">📁 Pliki logów</span>
      <div style="display:flex;gap:6px;margin-left:auto;align-items:center">
        <button class="btn btn-ghost" onclick="loadLogFile('access')"  style="font-size:11px">access</button>
        <button class="btn btn-ghost" onclick="loadLogFile('error')"   style="font-size:11px">error</button>
        <button class="btn btn-ghost" onclick="loadLogFile('warn')"    style="font-size:11px">warn</button>
        <button class="btn btn-ghost" onclick="loadLogFile('info')"    style="font-size:11px">info</button>
        <button class="btn btn-ghost" onclick="loadLogFile('debug')"   style="font-size:11px">debug</button>
        <span id="logfile-name" style="font-size:10px;color:var(--accent);margin-left:4px"></span>
        <input class="log-search" id="logfile-search" placeholder="szukaj..." oninput="filterLogFile()" style="width:160px">
      </div>
    </div>
    <div class="log-box" id="logfile-box" style="max-height:380px;font-family:monospace">
      <div style="color:var(--dim);padding:16px;font-size:11px">← kliknij plik aby załadować</div>
    </div>
    <div style="padding:6px 12px;font-size:10px;color:var(--dim);border-top:1px solid var(--border)">
      Źródło: <code>/var/log/nas-panel/</code> · ostatnie 300 linii · <code>/np_logfile</code>
    </div>
  </div>
</div>
<div class="section" id="sec-cache">
  <div class="page-title"><h1>Cache</h1><span class="sub">LRU response cache</span></div>
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Statistics</span>
      <div style="display:flex;gap:8px">
        <button class="btn btn-warn" onclick="flushCache()" style="padding:5px 12px;font-size:11px">&#x2715; Flush All</button>
      </div>
    </div>
    <div class="cache-grid" style="grid-template-columns:repeat(5,1fr)">
      <div class="cache-stat"><div class="cache-stat-val" id="c-entries">—</div><div class="cache-stat-key">Entries</div></div>
      <div class="cache-stat"><div class="cache-stat-val" id="c-hits">—</div><div class="cache-stat-key">Hits</div></div>
      <div class="cache-stat"><div class="cache-stat-val" id="c-misses">—</div><div class="cache-stat-key">Misses</div></div>
      <div class="cache-stat"><div class="cache-stat-val" id="c-evictions">—</div><div class="cache-stat-key">Evictions</div></div>
      <div class="cache-stat"><div class="cache-stat-val" id="c-ratio">—</div><div class="cache-stat-key">Hit Rate</div></div>
    </div>
    <div style="padding:0 16px 12px">
      <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--dim);margin-bottom:4px">
        <span>Cache Usage</span><span id="c-usage-pct">0%</span>
      </div>
      <div class="cache-bar"><div class="cache-bar-fill" id="c-usage-bar" style="width:0%"></div></div>
      <div style="font-size:10px;color:var(--dim)"><span id="c-used">0</span> / <span id="c-max">1024</span> entries</div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Cached Entries</span><span class="badge blue" id="c-count">0</span></div>
    <div id="cache-entries"></div>
  </div>
</div>

<!-- MODULES -->
<div class="section" id="sec-modules">
  <div class="page-title"><h1>Modules</h1><span class="sub">runtime feature control</span></div>

  <!-- Installed component cards -->
  <div class="panel">
    <div class="panel-head">
      <span class="panel-title">Zainstalowane komponenty</span>
      <span style="font-size:10px;color:var(--dim)">kliknij Włącz/Wyłącz aby zmienić natychmiast</span>
    </div>
    <div id="modules-grid" style="padding:16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px"></div>
  </div>

  <!-- Proposals / examples / snippets -->
  <div class="panel" style="margin-top:16px">
    <div class="panel-head">
      <span class="panel-title">Rozszerzenia i propozycje</span>
      <div style="display:flex;gap:6px">
        <button class="btn btn-ghost" onclick="showModTab('built')"  id="mbt-built"  style="font-size:10px;padding:3px 10px">Wbudowane</button>
        <button class="btn btn-ghost" onclick="showModTab('config')" id="mbt-config" style="font-size:10px;padding:3px 10px">Konfiguracja</button>
        <button class="btn btn-ghost" onclick="showModTab('lua')"    id="mbt-lua"    style="font-size:10px;padding:3px 10px">Lua snippets</button>
        <button class="btn btn-ghost" onclick="showModTab('ideas')"  id="mbt-ideas"  style="font-size:10px;padding:3px 10px">Pomysły</button>
      </div>
    </div>

    <!-- BUILT-IN -->
    <div id="mtab-built" style="padding:16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px">
      <div class="mod-card"><div class="mod-title">⚡ WebSocket Proxy</div>
        <div class="mod-desc">Pełna obsługa WebSocket do Node.js. Nagłówki Upgrade przekazywane automatycznie.</div>
        <code class="mod-cfg">location /ws {
  proxy_pass node_api;
  websocket on;
  proxy_timeout 3600;
  cache off;
}</code><span class="badge green">✓ gotowe</span></div>

      <div class="mod-card"><div class="mod-title">🔒 Rate Limiter</div>
        <div class="mod-desc">Token bucket per IP. Konfiguracja per lokacja — np. 100 req/min dla API.</div>
        <code class="mod-cfg">location /api {
  proxy_pass node_api;
  rate_limit 100/min burst=20;
}</code><span class="badge green">✓ gotowe</span></div>

      <div class="mod-card"><div class="mod-title">💾 Cache proxy</div>
        <div class="mod-desc">Cache odpowiedzi Node.js. Ignoruje no-cache gdy ustawiony max_age.</div>
        <code class="mod-cfg">location /api/static {
  proxy_pass node_api;
  cache max_age=30;
}</code><span class="badge green">✓ gotowe</span></div>

      <div class="mod-card"><div class="mod-title">🌐 Virtual Hosts</div>
        <div class="mod-desc">Wiele domen na jednym IP. Routing po Host, wildcard *.example.com.</div>
        <code class="mod-cfg">server {
  server_name app.example.com;
  location / { root /opt/app; }
}
server {
  server_name api.example.com;
  location / { proxy_pass node; }
}</code><span class="badge green">✓ gotowe</span></div>

      <div class="mod-card"><div class="mod-title">🛡 IP Blacklist</div>
        <div class="mod-desc">Blokowanie IP przez panel admina lub API.</div>
        <code class="mod-cfg">curl -X POST /np_blacklist   -d '{"action":"add",
       "ip":"1.2.3.4"}'</code><span class="badge green">✓ gotowe</span></div>

      <div class="mod-card"><div class="mod-title">📂 Autoindex</div>
        <div class="mod-desc">Listowanie plików — przydatne dla plików do pobrania.</div>
        <code class="mod-cfg">location /files {
  root /srv/files;
  autoindex on;
  cache max_age=0;
}</code><span class="badge green">✓ gotowe</span></div>

      <div class="mod-card"><div class="mod-title">🔀 Load Balancer</div>
        <div class="mod-desc">Round-robin, least-conn, weighted, ip-hash. Backup serwery. Per-backend stats.</div>
        <code class="mod-cfg">upstream cluster {
  server 127.0.0.1:3000 weight=2;
  server 127.0.0.1:3001 weight=1;
  server 127.0.0.1:3002 backup;
  strategy least_conn;
  health_check /health;
}</code><span class="badge green">✓ gotowe</span></div>

      <div class="mod-card"><div class="mod-title">🔑 ACME / Let's Encrypt</div>
        <div class="mod-desc">Automatyczne certyfikaty SSL. Auto-odnowienie gdy &lt;30 dni. Konfiguracja w SSL/TLS.</div>
        <code class="mod-cfg">acme {
  enabled on;
  email   admin@example.com;
  domains example.com;
  staging off;
}</code><span class="badge green">✓ gotowe</span></div>

      <div class="mod-card"><div class="mod-title">🗄 SQLite3 Persistence</div>
        <div class="mod-desc">Vendored SQLite3 (single-file amalgamation). Zastępuje blacklist.txt i recent_bans.txt — atomowe zapisy, WAL mode, indeksy. Migracja z plików .txt automatycznie przy pierwszym starcie.</div>
        <code class="mod-cfg"># Baza automatycznie w:
# /var/lib/nas-web/nas-web.db
#
# Build:
bash vendor/sqlite/fetch_sqlite.sh
build-deb.sh --with-sqlite</code><span class="badge green">✓ gotowe</span></div>

      <div class="mod-card"><div class="mod-title">🔣 lua-cjson</div>
        <div class="mod-desc">Szybki JSON encoder/decoder dla skryptów Lua (fork OpenResty). Dostępny jako <code>require("cjson")</code> w każdym skrypcie middleware. Obsługuje <code>cjson.safe</code> (nie rzuca błędów).</div>
        <code class="mod-cfg">-- w skrypcie Lua:
local cjson = require("cjson")
local obj = cjson.decode(req.body)
local out = cjson.encode({
  status = "ok",
  ip     = req.client_ip
})</code><span class="badge green">✓ gotowe</span></div>
    </div>

    <!-- CONFIG EXAMPLES -->
    <div id="mtab-config" style="display:none;padding:16px">
      <div class="chart-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div>
          <div style="font-size:11px;color:var(--dim);margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em">Multi-domain (vhosts)</div>
          <textarea class="config-area" style="height:300px;font-size:11px" readonly>worker_processes    0;
worker_connections  4096;
admin_user          admin;
admin_password      haslo;

upstream node_app { server 127.0.0.1:3000; }
upstream node_api { server 127.0.0.1:3001; }

server {
    listen 443;
    ssl_cert /etc/ssl/app.crt;
    ssl_key  /etc/ssl/app.key;
    server_name app.example.com;

    location /api {
        proxy_pass node_api;
        cache off;
        rate_limit 200/min burst=50;
    }
    location /ws {
        proxy_pass node_app;
        websocket on;
        proxy_timeout 3600;
    }
    location /assets {
        root /opt/app/dist;
        cache max_age=31536000;
        gzip on;
    }
    location / { root /opt/app/dist; gzip on; }
}

server {
    listen 80;
    server_name api.example.com;
    location / {
        proxy_pass node_api;
        rate_limit 500/min burst=100;
    }
}</textarea>
        </div>
        <div>
          <div style="font-size:11px;color:var(--dim);margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em">NAS z Plex / Nextcloud / Gitea</div>
          <textarea class="config-area" style="height:300px;font-size:11px" readonly>upstream plex      { server 127.0.0.1:32400; }
upstream nextcloud { server 127.0.0.1:8888; }
upstream gitea     { server 127.0.0.1:3000; }
upstream nas_panel { server 127.0.0.1:8080; }

server {
    listen 443;
    ssl_cert /etc/ssl/nas.crt;
    ssl_key  /etc/ssl/nas.key;
    server_name nas.local;

    location /plex {
        proxy_pass plex;
        proxy_timeout 300;
        websocket on; cache off;
    }
    location /cloud {
        proxy_pass nextcloud;
        client_max_body_size 10g;
        cache off;
    }
    location /git {
        proxy_pass gitea;
        websocket on; cache off;
    }
    location /files {
        root /srv/files;
        autoindex on;
        cache max_age=3600;
    }
    location / { proxy_pass nas_panel; }
}</textarea>
        </div>
      </div>
    </div>

    <!-- LUA SNIPPETS -->
    <div id="mtab-lua" style="display:none;padding:16px">
      <div class="chart-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div>
          <div style="font-size:11px;color:var(--dim);margin-bottom:6px">JWT token validation</div>
          <textarea class="config-area" style="height:180px;font-size:11px" readonly>-- jwt_auth.lua
local auth = request.headers["Authorization"]
if not auth or not auth:match("^Bearer ") then
    response.status = 401
    response.headers["WWW-Authenticate"] = "Bearer"
    response.body = '{"error":"unauthorized"}'
    return
end
local token = auth:sub(8)
if #token < 20 then
    response.status = 403
    response.body = '{"error":"invalid token"}'
    return
end
request.headers["X-User-Id"] = "from_token"</textarea>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">Użycie: <code>lua_middleware /etc/nas-web/jwt_auth.lua;</code></div>
        </div>
        <div>
          <div style="font-size:11px;color:var(--dim);margin-bottom:6px">GeoIP block</div>
          <textarea class="config-area" style="height:180px;font-size:11px" readonly>-- geoblock.lua
local ip = request.remote_addr
local allowed = {"PL","DE","NL","US"}
local function get_country(ip)
    return os.getenv("GEOIP_"..ip) or "XX"
end
local country = get_country(ip)
local ok = false
for _, c in ipairs(allowed) do
    if c == country then ok=true; break end
end
if not ok then
    response.status = 403
    response.body = '{"error":"region blocked"}'
    return
end</textarea>
        </div>
        <div>
          <div style="font-size:11px;color:var(--dim);margin-bottom:6px">Access logger</div>
          <textarea class="config-area" style="height:140px;font-size:11px" readonly>-- access_log.lua
local ts = os.date("%Y-%m-%d %H:%M:%S")
local line = string.format(
    "%s %s %s %s %d
",
    ts, request.remote_addr,
    request.method, request.path,
    response.status)
local f = io.open("/var/log/nas-panel/access.log","a")
if f then f:write(line); f:close() end</textarea>
        </div>
        <div>
          <div style="font-size:11px;color:var(--dim);margin-bottom:6px">JSON API response (cjson)</div>
          <textarea class="config-area" style="height:180px;font-size:11px" readonly>-- json_api.lua
-- Wymaga: build-deb.sh --with-lua-cjson
local cjson = require("cjson")

function on_request(req)
  if req.path ~= "/api/status" then return nil end
  local body = cjson.encode({
    status  = "ok",
    version = "2.3.0",
    ip      = req.client_ip,
    ts      = np.time()
  })
  return { status=200, body=body,
    headers={ ["Content-Type"]="application/json" } }
end

function on_response(req, resp)
  local ok, obj = pcall(cjson.decode, resp.body)
  if ok and type(obj) == "table" then
    obj["x-processed"] = true
    resp.body = cjson.encode(obj)
  end
  return resp
end</textarea>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">Użycie: <code>lua_middleware /etc/nas-web/json_api.lua;</code></div>
        </div>
        <div>
          <div style="font-size:11px;color:var(--dim);margin-bottom:6px">Prometheus /metrics</div>
          <textarea class="config-area" style="height:140px;font-size:11px" readonly>-- metrics.lua
-- location /metrics { lua_middleware ...; return 200; }
local stats = {
    "nas_requests_total "..
        (request.headers["X-Stat-Req"] or "0"),
    "nas_cache_hits_total "..
        (request.headers["X-Stat-Cache"] or "0"),
}
response.status = 200
response.headers["Content-Type"] =
    "text/plain; version=0.0.4"
response.body = table.concat(stats,"
").."
"</textarea>
        </div>
      </div>
    </div>

    <!-- ROADMAP / IDEAS -->
    <div id="mtab-ideas" style="display:none;padding:16px">
      <div style="font-size:11px;color:var(--dim);margin-bottom:12px">Moduły możliwe do dodania — każdy jako <code>WITH_XXX=ON</code> w cmake i <code>#include</code> w server.cc</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px">

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">🌍 HTTP/3 + QUIC</div>
          <div class="mod-desc">UDP transport, 0-RTT, brak Head-of-Line blocking. Wymaga biblioteki <code>quiche</code> (Cloudflare/Rust).</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">Flaga: <code>listen 443 quic;</code></div>
          <span class="badge dim">WITH_QUICHE=ON</span></div>

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">🔐 mTLS / Client certs</div>
          <div class="mod-desc">Weryfikacja certyfikatu klienta — zero-password auth dla mikroserwisów, panelu admina lub API B2B.</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">OpenSSL <code>SSL_CTX_set_verify()</code></div>
          <span class="badge dim">planowane</span></div>

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">📊 Prometheus /metrics</div>
          <div class="mod-desc">Endpoint <code>/metrics</code> eksportujący req/s, latencję p50/p99, cache ratio, błędy — gotowy na Grafanę.</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">Lua snippet już dostępny w zakładce Lua</div>
          <span class="badge green">gotowe przez Lua</span></div>

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">📤 Streaming upload</div>
          <div class="mod-desc">Pliki >1 GB zapisywane strumieniowo na dysk, omijając pamięć. Progress przez SSE lub WebSocket.</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">libuv async file write</div>
          <span class="badge dim">planowane</span></div>

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">🔑 JWT Auth middleware</div>
          <div class="mod-desc">Weryfikacja tokenów JWT (RS256/HS256) bez Node.js. Gotowy <code>jwt_auth.lua</code> w zakładce Lua snippets.</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">lib: <code>jwt-cpp</code> lub OpenSSL EVP</div>
          <span class="badge green">gotowe przez Lua</span></div>

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">🗜 Wasm middleware</div>
          <div class="mod-desc">Uruchamianie filtrów/transformacji request/response jako WebAssembly — jak Envoy/Nginx WASM.</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">Runtime: <code>wasm3</code> lub <code>wasmtime-c-api</code></div>
          <span class="badge dim">planowane</span></div>

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">🧩 GeoIP blokowanie</div>
          <div class="mod-desc">Blokowanie lub routing po kraju/ASN. Baza MaxMind GeoLite2 (mmdb). Gotowy snippet Lua.</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">lib: <code>libmaxminddb</code></div>
          <span class="badge dim">WITH_GEOIP=ON</span></div>

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">🛡 WAF / ModSecurity</div>
          <div class="mod-desc">Web Application Firewall — reguły OWASP CRS, blokowanie SQLi, XSS, path traversal.</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">lib: <code>libmodsecurity3</code></div>
          <span class="badge dim">WITH_MODSEC=ON</span></div>

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">📋 Audit log</div>
          <div class="mod-desc">Historia zmian konfiguracji z panelu: kto, kiedy, co zmienił. Eksport do syslog lub Elasticsearch.</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">ring buffer + /np_audit endpoint</div>
          <span class="badge dim">planowane</span></div>

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">🔄 Mirror / Shadow traffic</div>
          <div class="mod-desc">Kopiowanie ruchu produkcyjnego do instancji testowej — zero wpływu na odpowiedź klienta.</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">Konfiguracja: <code>mirror upstream_test;</code></div>
          <span class="badge dim">planowane</span></div>

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">📡 SSE / EventSource</div>
          <div class="mod-desc">Server-Sent Events z wbudowanym brokerem publish/subscribe — bez Node.js dla push notyfikacji.</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">Content-Type: text/event-stream</div>
          <span class="badge dim">planowane</span></div>

        <div class="mod-card" style="border-color:var(--accent2)">
          <div class="mod-title" style="color:var(--accent2)">🐍 Python scripting</div>
          <div class="mod-desc">Middleware Python 3 — dla zespołów preferujących Python zamiast Lua/JS. Embedded <code>libpython3</code>.</div>
          <div style="font-size:10px;color:var(--dim);margin-top:4px">lib: <code>libpython3-dev</code></div>
          <span class="badge dim">WITH_PYTHON=ON</span></div>

      </div>
    </div>

    <script>
    function showModTab(name){
      ['built','config','lua','ideas'].forEach(t=>{
        const d=document.getElementById('mtab-'+t);
        const b=document.getElementById('mbt-'+t);
        if(d) d.style.display = t===name ? '' : 'none';
        if(b){ b.style.background=t===name?'var(--accent)':''; b.style.color=t===name?'#fff':''; }
      });
    }
    showModTab('built');
    </script>
  </div>

</div>
<div class="section" id="sec-db">
  <div class="page-title"><h1>SQLite — Baza</h1><span class="sub">zarządzanie bazą danych</span></div>

  <!-- Status bazy -->
  <div class="panel">
    <div class="panel-head">
      <span class="panel-title">Status bazy</span>
      <div style="display:flex;gap:6px">
        <button class="btn btn-ghost" style="font-size:11px" onclick="loadDb()">↺ Odśwież</button>
      </div>
    </div>
    <div id="db-status-grid" style="padding:16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px">
      <div style="color:var(--dim);font-size:11px">Ładowanie...</div>
    </div>
  </div>

  <!-- Tabele -->
  <div class="panel" style="margin-top:16px">
    <div class="panel-head"><span class="panel-title">Tabele</span></div>
    <div id="db-tables" style="padding:16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px">
    </div>
  </div>

  <!-- Operacje -->
  <div class="panel" style="margin-top:16px">
    <div class="panel-head"><span class="panel-title">Operacje</span></div>
    <div style="padding:16px;display:flex;flex-wrap:wrap;gap:12px">

      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:16px;flex:1;min-width:200px">
        <div style="font-size:13px;font-weight:600;color:var(--bright);margin-bottom:6px">🔧 VACUUM</div>
        <div style="font-size:11px;color:var(--dim);margin-bottom:12px">Defragmentuje bazę i odzyskuje wolne miejsce. Bezpieczna operacja, może chwilę potrwać.</div>
        <button class="btn btn-ghost" style="font-size:11px" onclick="dbAction('vacuum')">Uruchom VACUUM</button>
      </div>

      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:16px;flex:1;min-width:200px">
        <div style="font-size:13px;font-weight:600;color:var(--bright);margin-bottom:6px">💾 WAL Checkpoint</div>
        <div style="font-size:11px;color:var(--dim);margin-bottom:12px">Zapisuje bufor WAL do głównego pliku bazy. Zmniejsza rozmiar pliku <code>-wal</code>.</div>
        <button class="btn btn-ghost" style="font-size:11px" onclick="dbAction('wal_checkpoint')">Checkpoint</button>
      </div>

      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:16px;flex:1;min-width:200px">
        <div style="font-size:13px;font-weight:600;color:var(--bright);margin-bottom:6px">🔍 Sprawdź integralność</div>
        <div style="font-size:11px;color:var(--dim);margin-bottom:12px">Szybki quick_check integralności struktury bazy danych.</div>
        <button class="btn btn-ghost" style="font-size:11px" onclick="dbAction('integrity_check')">Quick check</button>
      </div>

      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:16px;flex:1;min-width:200px">
        <div style="font-size:13px;font-weight:600;color:var(--bright);margin-bottom:6px">🗑 Wyczyść ban events</div>
        <div style="font-size:11px;color:var(--dim);margin-bottom:12px">Usuwa stare zdarzenia banowania (starsze niż 30 dni). Nie usuwa blacklisty.</div>
        <button class="btn" style="font-size:11px;background:rgba(255,51,85,.15);color:#ff3355;border:1px solid rgba(255,51,85,.3)" onclick="dbPruneEvents()">Wyczyść stare eventy</button>
      </div>

    </div>
    <div id="db-action-result" style="display:none;margin:0 16px 16px;padding:10px 14px;border-radius:6px;font-size:12px;font-family:monospace"></div>
  </div>

  <!-- Backup info -->
  <div class="panel" style="margin-top:16px">
    <div class="panel-head"><span class="panel-title">Backup</span></div>
    <div style="padding:16px">
      <div style="font-size:11px;color:var(--dim);line-height:1.8;margin-bottom:12px">
        SQLite3 w trybie WAL — plik bazy jest bezpieczny do kopiowania bez zatrzymywania serwera.<br>
        Pliki do skopiowania: <code id="db-path-backup">—</code> oraz <code id="db-wal-path">—</code>
      </div>
      <code style="display:block;background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:10px 14px;font-size:11px;color:var(--dim)">
# Backup bez zatrzymywania serwera:<br>
cp /var/lib/nas-web/nas-web.db /backup/nas-web-$(date +%Y%m%d).db<br>
# Lub przez sqlite3:<br>
sqlite3 /var/lib/nas-web/nas-web.db ".backup /backup/nas-web.db"
      </code>
    </div>
  </div>
</div>

<div class="section" id="sec-sysinfo">
  <div class="page-title"><h1>System Info</h1><span class="sub">server &amp; host details</span></div>
  <div class="sysinfo-grid" id="sysinfo-grid"></div>
</div>

<!-- SECURITY -->
<div class="section" id="sec-security">
  <div class="page-title"><h1>Security</h1><span class="sub">blacklist &amp; connection limits</span></div>

  <!-- Connection Limits -->
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Per-IP Connection Limit</span><span id="connlimit-badge" class="badge dim">—</span></div>
    <div style="padding:20px;display:grid;grid-template-columns:1fr 1fr auto;gap:16px;align-items:flex-end">
      <div class="field">
        <label>Max concurrent connections per IP</label>
        <input type="number" id="connlimit-val" value="0" min="0" max="1000"
          style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:9px 12px;color:var(--bright);font-family:JetBrains Mono,monospace;font-size:12px;outline:none"
          onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
        <div style="font-size:10px;color:var(--dim);margin-top:4px">0 = disabled</div>
      </div>
      <div class="field" style="display:flex;align-items:flex-end">
        <button class="btn btn-primary" onclick="saveConnLimit()" style="width:100%">Apply</button>
      </div>
      <div id="connlimit-result" style="font-size:11px;color:var(--accent)"></div>
    </div>
  </div>

  <!-- IP Blacklist -->
  <div class="panel">
    <div class="panel-head">
      <span class="panel-title">IP Blacklist</span>
      <span id="blacklist-count" class="badge dim">0 IPs</span>
    </div>
    <div style="padding:16px 20px 8px;display:grid;grid-template-columns:1fr auto auto;gap:12px;align-items:center">
      <input type="text" id="blacklist-ip" placeholder="e.g. 1.2.3.4 or 10.0.0.0/8"
        style="background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:9px 12px;color:var(--bright);font-family:JetBrains Mono,monospace;font-size:12px;outline:none;width:100%"
        onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'"
        onkeydown="if(event.key==='Enter')blacklistAdd()">
      <button class="btn btn-primary" onclick="blacklistAdd()">&#xFF0B; Block IP</button>
      <button class="btn" onclick="loadBlacklist()" style="opacity:.6">&#x21BB; Refresh</button>
    </div>
    <div id="blacklist-table" style="padding:0 20px 16px"></div>
  </div>

  <!-- IP Allowlist for admin panel -->
  <div class="panel" style="margin-top:16px">
    <div class="panel-head">
      <span class="panel-title">🛡 IP Allowlist — Panel Admina</span>
      <span class="badge dim" id="allowlist-status">wczytywanie...</span>
    </div>
    <div style="padding:12px 16px;font-size:12px;color:var(--dim)">
      Ogranicz dostęp do <code>/np_admin</code> tylko do wybranych adresów IP lub prefixów.<br>
      Dodaj w pliku konfiguracyjnym: <code>admin_allow_ips 192.168.1. 10.0.0.1;</code><br>
      Puste = dostęp dla wszystkich. Restart nie jest wymagany po przeładowaniu config.
    </div>
    <div style="padding:0 16px 12px;display:flex;gap:8px;align-items:center">
      <span style="font-size:11px;color:var(--dim)">Aktualny IP:</span>
      <span id="admin-my-ip" class="badge blue" style="font-family:monospace">—</span>
      <span style="font-size:11px;color:var(--dim);margin-left:8px">Konfiguracja: w pliku nas-web.conf</span>
    </div>
    <div id="allowlist-entries" style="padding:0 16px 12px;font-size:11px;color:var(--dim)">
      Sprawdź plik konfiguracyjny aby zobaczyć aktualną listę.
    </div>
  </div>
</div>

<!-- UPSTREAMS -->
<div class="section" id="sec-upstreams">
  <div class="page-title"><h1>Upstreams</h1><span class="sub">live upstream management</span></div>
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Backend Servers</span>
      <button class="btn btn-primary" onclick="showAddUpstream()" style="font-size:11px;padding:5px 12px">&#xFF0B; Add Server</button>
    </div>
    <div id="upstream-add-form" style="display:none;padding:16px 20px;border-bottom:1px solid var(--border);background:rgba(0,136,255,.04)">
      <div class="chart-grid" style="display:grid;grid-template-columns:1fr 1fr auto;gap:12px;align-items:flex-end">
        <div class="field">
          <label>Name (upstream group)</label>
          <input type="text" id="up-name" placeholder="e.g. node_api"
            style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:9px 12px;color:var(--bright);font-family:JetBrains Mono,monospace;font-size:12px;outline:none"
            onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
        </div>
        <div class="field">
          <label>Address (host:port)</label>
          <input type="text" id="up-addr" placeholder="e.g. 127.0.0.1:3000"
            style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:9px 12px;color:var(--bright);font-family:JetBrains Mono,monospace;font-size:12px;outline:none"
            onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'"
            onkeydown="if(event.key==='Enter')addUpstream()">
        </div>
        <button class="btn btn-primary" onclick="addUpstream()">Add</button>
      </div>
    </div>
    <div id="upstream-table" style="padding:0 4px"></div>
  </div>
  <div class="panel" style="margin-top:16px">
    <div class="panel-head"><span class="panel-title">Note on Live Upstreams</span></div>
    <div style="padding:14px 20px;font-size:11px;color:var(--dim);line-height:1.8">
      Live-added upstreams are stored in memory only — they are lost on restart.<br>
      To persist changes, edit <code style="color:var(--accent)">/etc/nas-web/nas-web.conf</code> and click <strong style="color:var(--accent)">Reload Config</strong> in the Config tab.<br>
      Config upstreams (source: <em>config</em>) cannot be removed here — edit the config file instead.
    </div>
  </div>
</div>

<!-- SSL -->
<!-- DASHBOARD -->
<div class="section" id="sec-dashboard">
  <div class="page-title"><h1>Dashboard</h1><span class="sub">req/s · błędy · latencja · cache — historia 1h</span></div>

  <div class="chart-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
    <!-- req/s chart -->
    <div class="panel">
      <div class="panel-head"><span class="panel-title">📈 Req / sec</span><span class="badge green" id="dash-rps-now">—</span></div>
      <canvas id="dash-chart-rps" height="120" style="width:100%;padding:8px 12px;box-sizing:border-box"></canvas>
    </div>
    <!-- latency chart -->
    <div class="panel">
      <div class="panel-head"><span class="panel-title">⏱ Latencja avg [ms]</span><span class="badge blue" id="dash-lat-now">—</span></div>
      <canvas id="dash-chart-lat" height="120" style="width:100%;padding:8px 12px;box-sizing:border-box"></canvas>
    </div>
    <!-- error rate chart -->
    <div class="panel">
      <div class="panel-head"><span class="panel-title">⚠ Błędy / sec</span><span class="badge orange" id="dash-err-now">—</span></div>
      <canvas id="dash-chart-err" height="120" style="width:100%;padding:8px 12px;box-sizing:border-box"></canvas>
    </div>
    <!-- active connections -->
    <div class="panel">
      <div class="panel-head"><span class="panel-title">🔌 Aktywne połączenia</span><span class="badge dim" id="dash-conn-now">—</span></div>
      <canvas id="dash-chart-conn" height="120" style="width:100%;padding:8px 12px;box-sizing:border-box"></canvas>
    </div>
  </div>

  <!-- Timerange buttons -->
  <div style="display:flex;gap:8px;margin-bottom:16px">
    <button class="btn btn-ghost" onclick="loadDashboard(120)" style="font-size:11px">2 min</button>
    <button class="btn btn-ghost" onclick="loadDashboard(600)" style="font-size:11px">10 min</button>
    <button class="btn btn-ghost" onclick="loadDashboard(3600)" style="font-size:11px">1 h</button>
    <span style="font-size:10px;color:var(--dim);align-self:center;margin-left:8px">Próbki co 1s · ring buffer 1h</span>
  </div>
</div>

<!-- AUDIT LOG -->
<div class="section" id="sec-audit">
  <div class="page-title"><h1>Audit Log</h1><span class="sub">historia zmian konfiguracji</span></div>
  <div class="panel">
    <div class="panel-head">
      <span class="panel-title">📋 Zdarzenia adminstracyjne</span>
      <span class="badge dim" id="audit-count">0</span>
      <div style="margin-left:auto;display:flex;gap:8px">
        <input class="log-search" id="audit-search" placeholder="szukaj akcji, IP..." oninput="filterAudit()" style="width:200px">
        <button class="btn btn-ghost" style="font-size:11px" onclick="loadAudit()">↺ odśwież</button>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:155px 130px 160px minmax(0,1fr);padding:4px 12px;border-bottom:1px solid var(--border);font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.05em">
      <span>Czas</span><span>IP admina</span><span>Akcja</span><span>Szczegół</span>
    </div>
    <div class="log-box" id="audit-log" style="max-height:500px"></div>
    <div style="padding:6px 12px;font-size:10px;color:var(--dim);border-top:1px solid var(--border)">
      Ring buffer 500 zdarzeń · źródło: <code>/np_audit</code>
    </div>
  </div>
</div>

<div class="section" id="sec-ssl">
  <div class="page-title"><h1>SSL / TLS</h1><span class="sub">certificate management</span></div>

  <!-- Status -->
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Current Status</span><span id="ssl-status-badge" class="badge dim">checking...</span></div>
    <div class="sysinfo-grid" style="padding:16px;grid-template-columns:repeat(2,1fr);gap:12px" id="ssl-status-grid">
      <div class="sysinfo-card">
        <div class="sysinfo-title">TLS Engine</div>
        <div class="sysinfo-row"><span class="sysinfo-key">Status</span><span class="sysinfo-val" id="ssl-tls-status">—</span></div>
        <div class="sysinfo-row"><span class="sysinfo-key">Certificate</span><span class="sysinfo-val" id="ssl-cert-path">/etc/nas-web/cert.pem</span></div>
        <div class="sysinfo-row"><span class="sysinfo-key">Private Key</span><span class="sysinfo-val" id="ssl-key-path">/etc/nas-web/key.pem</span></div>
        <div class="sysinfo-row"><span class="sysinfo-key">Expires</span><span class="sysinfo-val" id="ssl-expiry">—</span></div>
      </div>
      <div class="sysinfo-card">
        <div class="sysinfo-title">Quick Guide</div>
        <div style="font-size:11px;color:var(--dim);line-height:1.9">
          1. Generate cert below<br>
          2. Add to <code style="color:var(--accent)">nas-web.conf</code>:<br>
          <code style="color:var(--text);display:block;margin:4px 0 4px 12px">ssl_cert /etc/nas-web/cert.pem;<br>ssl_key  /etc/nas-web/key.pem;</code>
          3. Change <code style="color:var(--accent)">listen 80</code> → <code style="color:var(--accent)">listen 443</code><br>
          4. Click <strong style="color:var(--accent)">Reload Config</strong>
        </div>
      </div>
    </div>
  </div>

  <!-- Generate -->
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Generate Self-Signed Certificate</span></div>
    <div style="padding:20px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px">
      <div class="field">
        <label>Common Name (CN)</label>
        <input type="text" id="ssl-cn" value="nas-web" style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:9px 12px;color:var(--bright);font-family:JetBrains Mono,monospace;font-size:12px;outline:none" onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
      </div>
      <div class="field">
        <label>Validity (days)</label>
        <input type="number" id="ssl-days" value="365" min="1" max="3650" style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:9px 12px;color:var(--bright);font-family:JetBrains Mono,monospace;font-size:12px;outline:none" onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
      </div>
      <div class="field" style="display:flex;align-items:flex-end">
        <button class="btn btn-primary" onclick="generateSSL()" style="width:100%">&#x1F512; Generate</button>
      </div>
    </div>
    <div id="ssl-gen-result" style="display:none;margin:0 20px 16px;padding:12px 16px;border-radius:4px;font-size:12px;border:1px solid"></div>
  </div>

  <!-- Config snippet -->
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Config Snippet</span></div>
    <pre style="padding:16px;font-size:11px;color:var(--text);line-height:1.8;overflow-x:auto"><span style="color:var(--dim)"># Add inside your server {} block:</span>
<span style="color:var(--accent2)">listen</span> <span style="color:var(--warn)">443</span>;
<span style="color:var(--accent2)">ssl_cert</span> <span style="color:var(--text)">/etc/nas-web/cert.pem;</span>
<span style="color:var(--accent2)">ssl_key</span>  <span style="color:var(--text)">/etc/nas-web/key.pem;</span></pre>
  </div>

  <!-- ACME / Let's Encrypt -->
  <div class="panel" style="margin-top:16px">
    <div class="panel-head">
      <span class="panel-title">&#128272; ACME / Let's Encrypt</span>
      <span id="acme-badge" class="badge dim">sprawdzanie...</span>
    </div>
    <div style="padding:16px;display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div>
        <div class="sysinfo-card" style="margin-bottom:12px">
          <div class="sysinfo-title">Status certyfikatu</div>
          <div class="sysinfo-row"><span class="sysinfo-key">Aktywny</span><span class="sysinfo-val" id="acme-enabled">—</span></div>
          <div class="sysinfo-row"><span class="sysinfo-key">Tryb</span><span class="sysinfo-val" id="acme-mode">—</span></div>
          <div class="sysinfo-row"><span class="sysinfo-key">Domeny</span><span class="sysinfo-val" id="acme-domains">—</span></div>
          <div class="sysinfo-row"><span class="sysinfo-key">Odnowienie</span><span class="sysinfo-val" id="acme-renew">—</span></div>
          <div class="sysinfo-row"><span class="sysinfo-key">Ostatnie OK</span><span class="sysinfo-val" id="acme-last-ok" style="color:var(--accent)">—</span></div>
          <div id="acme-error-row" style="display:none;margin-top:8px;padding:8px 10px;background:rgba(255,51,85,.08);border:1px solid rgba(255,51,85,.25);border-radius:6px;font-size:11px">
            <div style="color:var(--warn);font-weight:600;margin-bottom:4px">⚠ Błąd ostatniego żądania:</div>
            <pre id="acme-last-error" style="color:var(--warn);white-space:pre-wrap;word-break:break-word;margin:0;font-size:10px;line-height:1.5"></pre>
          </div>
          <!-- Progress bar — hidden when idle -->
          <div id="acme-progress-wrap" style="display:none;margin-top:10px">
            <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--dim);margin-bottom:4px">
              <span id="acme-progress-step">…</span>
              <span id="acme-progress-pct" style="color:var(--accent);font-weight:600">0%</span>
            </div>
            <div style="height:6px;background:var(--border);border-radius:3px;overflow:hidden">
              <div id="acme-progress-bar" style="height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));width:0%;transition:width .4s ease;border-radius:3px"></div>
            </div>
          </div>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary" onclick="acmeObtain()" style="font-size:11px">&#128260; Pobierz / Odnów</button>
          <button class="btn btn-ghost" onclick="refreshAcme()" style="font-size:11px">&#8635; Odśwież</button>
          <button id="acme-diag-btn" class="btn btn-ghost" onclick="checkAcmePort()" style="font-size:11px">🔍 Sprawdź port 80</button>
        </div>
        <div id="acme-diag-result" style="font-size:11px;padding:6px 0;display:none"></div>
      </div>
      <div>
        <div style="font-size:11px;color:var(--dim);margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">Konfiguracja (nas-web.conf)</div>
        <pre style="background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:12px;font-size:10.5px;line-height:1.8;color:var(--text);overflow-x:auto"><span style="color:var(--dim)"># Blok globalny (przed server{})</span>
<span style="color:var(--accent2)">acme</span> {
  <span style="color:var(--accent2)">enabled</span>    <span style="color:var(--warn)">on</span>;
  <span style="color:var(--accent2)">email</span>      <span style="color:var(--text)">admin@example.com</span>;
  <span style="color:var(--accent2)">domains</span>    <span style="color:var(--text)">example.com www.example.com</span>;
  <span style="color:var(--accent2)">staging</span>    <span style="color:var(--warn)">off</span>;   <span style="color:var(--dim)"># on = test, off = produkcja</span>
  <span style="color:var(--accent2)">auto_renew</span> <span style="color:var(--warn)">on</span>;
}</pre>
        <div style="margin-top:8px;font-size:10px;color:var(--dim)">
          &#9432; Serwer musi być dostępny publicznie na porcie 80 dla weryfikacji HTTP-01.<br>
          Certyfikat zapisywany do <code>cert_dir</code> (domyślnie <code>/etc/nas-web/</code>).
        </div>
      </div>
    </div>
  </div>
</div>

<!-- CONFIG -->
<div class="section" id="sec-config">
  <div class="page-title"><h1>Config</h1><span class="sub">/etc/nas-web/nas-web.conf</span></div>
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Active Configuration</span>
      <span id="cfg-saved" style="font-size:10px;color:var(--accent);display:none">&#10003; saved</span>
    </div>
    <textarea class="config-area" id="config-area" spellcheck="false"></textarea>
    <div class="panel-actions">
      <button class="btn btn-primary" onclick="saveConfig()">&#128190; Save &amp; Reload</button>
      <button class="btn btn-ghost" onclick="loadConfig()">&#8635; Refresh</button>
      <button class="btn btn-danger" onclick="restartSrv()">&#9210; Restart Workers</button>
    </div>
  </div>
</div>

<!-- AUTOBAN -->
<div class="section" id="sec-autoban">
  <div class="panel" style="overflow:hidden">
  <div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
    <div>
      <h2 style="margin:0;font-size:15px;color:var(--bright)">🛡 AutoBan</h2>
      <div style="font-size:11px;color:var(--dim);margin-top:2px">Automatyczne blokowanie skanerów, bad UA, flood</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn btn-ghost" onclick="toggleAutoban()" id="autoban-toggle-btn">⏸ Wyłącz</button>
      <button class="btn btn-ghost" onclick="clearAutoban()" style="color:var(--warn)">🗑 Wyczyść</button>
      <button class="btn btn-primary" onclick="loadAutoban()">↻ Odśwież</button>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;padding:16px" class="stat-grid">
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:22px;font-weight:700;color:var(--warn)" id="ab-total-bans">0</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px">ZBANOWANYCH</div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:22px;font-weight:700;color:#ff4444" id="ab-scan-bans">0</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px">SCAN PATHS</div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:22px;font-weight:700;color:#cc44ff" id="ab-ua-bans">0</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px">BAD UA</div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:22px;font-weight:700;color:#0088ff" id="ab-rate-bans">0</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px">RATE/404</div>
    </div>
  </div>
  <div style="padding:0 16px 16px">
    <div style="font-size:11px;color:var(--dim);margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">Ostatnie bany</div>
    <div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead><tr style="color:var(--dim);border-bottom:1px solid var(--border)">
          <th style="text-align:left;padding:5px 8px;font-weight:500">Czas</th>
          <th style="text-align:left;padding:5px 8px;font-weight:500">IP</th>
          <th style="text-align:left;padding:5px 8px;font-weight:500">Powód</th>
          <th style="text-align:left;padding:5px 8px;font-weight:500">Szczegół</th>
          <th style="text-align:left;padding:5px 8px;font-weight:500">Akcja</th>
        </tr></thead>
        <tbody id="ab-bans-tbody"></tbody>
      </table>
    </div>
  </div>
</div><!-- /panel -->
</div>

<!-- WAF REGEX -->
<div class="section" id="sec-waf-regex">
  <div class="panel" style="overflow:hidden">
  <div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
    <div>
      <h2 style="margin:0;font-size:15px;color:var(--bright)">🔍 WAF Regex — SQLi / XSS / Traversal</h2>
      <div style="font-size:11px;color:var(--dim);margin-top:2px">Wbudowane wzorce regex — aktywne bez instalacji, zero zależności</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn btn-ghost" onclick="toggleWafRegex()" id="wafr-toggle-btn">⏸ Wyłącz</button>
      <button class="btn btn-ghost" onclick="clearWafRegex()" style="color:var(--warn)">🗑 Wyczyść logi</button>
      <button class="btn btn-primary" onclick="loadWafRegex()">↻ Odśwież</button>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;padding:16px" class="stat-grid">
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:22px;font-weight:700;color:#ff4444" id="wafr-blocked">0</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px">ZABLOKOWANYCH</div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:22px;font-weight:700;color:#cc44ff" id="wafr-detected">0</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px">WYKRYTYCH</div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:22px;font-weight:700;color:var(--text)" id="wafr-checked">0</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px">SPRAWDZONYCH</div>
    </div>
  </div>
  <div style="padding:0 16px 12px;display:flex;gap:8px;flex-wrap:wrap" id="wafr-cats"></div>
  <div style="padding:0 16px 16px;display:flex;align-items:center;gap:16px;flex-wrap:wrap">
    <label style="display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer">
      <input type="checkbox" id="wafr-block" checked> Tryb BLOCK (odznacz = detect-only)
    </label>
    <label style="display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer">
      <input type="checkbox" id="wafr-check-body" checked> Skanuj body
    </label>
    <button class="btn btn-primary" onclick="saveWafRegexConfig()">💾 Zapisz</button>
  </div>
  <div style="padding:0 16px 16px">
    <div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead><tr style="color:var(--dim);border-bottom:1px solid var(--border)">
          <th style="text-align:left;padding:5px 8px;font-weight:500">Czas</th>
          <th style="text-align:left;padding:5px 8px;font-weight:500">IP</th>
          <th style="text-align:left;padding:5px 8px;font-weight:500">Typ</th>
          <th style="text-align:left;padding:5px 8px;font-weight:500">URI</th>
          <th style="text-align:left;padding:5px 8px;font-weight:500">Dopasowanie</th>
        </tr></thead>
        <tbody id="wafr-tbody"></tbody>
      </table>
    </div>
  </div>
</div><!-- /panel -->
</div>

<!-- WAF MODSEC -->
<div class="section" id="sec-waf">
  <div class="panel" style="overflow:hidden">
  <div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
    <div>
      <h2 style="margin:0;font-size:15px;color:var(--bright)">🔰 WAF — ModSecurity</h2>
      <div style="font-size:11px;color:var(--dim);margin-top:2px">Web Application Firewall — OWASP CRS, SQLi, XSS, path traversal</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn btn-ghost" onclick="toggleWaf()" id="waf-toggle-btn">⏸ Wyłącz</button>
      <button class="btn btn-ghost" onclick="clearWafEvents()" style="color:var(--warn)">🗑 Wyczyść logi</button>
      <button class="btn btn-primary" onclick="loadWaf()">↻ Odśwież</button>
    </div>
  </div>
  <div style="background:rgba(255,136,0,.08);border-bottom:1px solid rgba(255,136,0,.2);padding:10px 20px;font-size:11px;color:var(--warn);display:flex;align-items:center;gap:8px">
    <span>⚠️</span>
    <span>Ta zakładka pokazuje zdarzenia <b>ModSecurity</b>. Ataki blokowane przez wbudowany <b>WAF Regex</b> (SQLi, XSS, CmdInjection itp.) widoczne są w zakładce <a href="#" onclick="show('waf-regex',null);return false" style="color:var(--accent);text-decoration:underline">🔍 WAF Regex</a>.</span>
  </div>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;padding:16px" class="stat-grid">
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:22px;font-weight:700;color:var(--warn)" id="waf-blocked">0</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px">ZABLOKOWANYCH</div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:22px;font-weight:700;color:#cc44ff" id="waf-detected">0</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px">WYKRYTYCH (detect)</div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:22px;font-weight:700;color:var(--text)" id="waf-checked">0</div>
      <div style="font-size:10px;color:var(--dim);margin-top:4px">SPRAWDZONYCH REQ</div>
    </div>
  </div>
  <div style="padding:0 16px 12px">
    <div id="waf-status-banner" style="padding:10px 14px;border-radius:6px;font-size:12px;font-family:monospace"></div>
  </div>
  <div style="padding:0 16px 16px;display:flex;align-items:center;gap:16px;flex-wrap:wrap">
    <div style="font-size:11px;color:var(--dim)">Tryb:</div>
    <label style="display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer">
      <input type="radio" name="waf-mode" id="waf-mode-block" value="block"> <span style="color:var(--warn)">🚫 Block</span>
    </label>
    <label style="display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer">
      <input type="radio" name="waf-mode" id="waf-mode-detect" value="detect"> <span style="color:#cc44ff">👁 Detect</span>
    </label>
    <button class="btn btn-primary" style="margin-left:auto" onclick="saveWafMode()">💾 Zapisz tryb</button>
  </div>
  <div id="waf-install-hint" style="display:none;padding:0 16px 16px">
    <div style="background:rgba(255,170,0,.08);border:1px solid rgba(255,170,0,.3);border-radius:6px;padding:12px 16px;font-size:11px;font-family:monospace;color:var(--warn)">
      ⚠ ModSecurity nie jest załadowane.<br><br>
      Aby włączyć WAF:<br>
      &nbsp;&nbsp;<span style="color:var(--accent)">apt install libmodsecurity3 modsecurity-crs</span><br>
      &nbsp;&nbsp;<span style="color:var(--accent)">cmake -DWITH_MODSEC=ON ..</span>
    </div>
  </div>
  <div style="padding:0 16px 16px">
    <div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead><tr style="color:var(--dim);border-bottom:1px solid var(--border)">
          <th style="text-align:left;padding:6px 8px;font-weight:500">Czas</th>
          <th style="text-align:left;padding:6px 8px;font-weight:500">IP</th>
          <th style="text-align:left;padding:6px 8px;font-weight:500">Metoda</th>
          <th style="text-align:left;padding:6px 8px;font-weight:500">URI</th>
          <th style="text-align:left;padding:6px 8px;font-weight:500">Reguła</th>
          <th style="text-align:left;padding:6px 8px;font-weight:500">Opis</th>
          <th style="text-align:left;padding:6px 8px;font-weight:500">Sev</th>
        </tr></thead>
        <tbody id="waf-events-tbody"></tbody>
      </table>
    </div>
  </div>
</div><!-- /panel -->
</div>

</div></main></div>

<script>
// ── Auth ─────────────────────────────────────────────────────────────────────
let authHeader = sessionStorage.getItem('nw_auth') || '';
let refreshTimer = null;


function toggleNav(){
  document.body.classList.toggle('nav-open');
}
function closeNav(){
  document.body.classList.remove('nav-open');
}
// Close nav on item click (mobile)
document.addEventListener('DOMContentLoaded', ()=>{
  document.querySelectorAll('.nav-item').forEach(el=>{
    el.addEventListener('click', ()=>{
      if(window.innerWidth <= 768) closeNav();
    });
  });
});


// ── AutoBan ───────────────────────────────────────────────────────────────────
let _autobanEnabled = true;

async function loadAutoban() {
  const d = await api('/np_autoban');
  if(!d) return;

  // Breakdown per reason from recent_bans
  const bans = Array.isArray(d.recent_bans) ? d.recent_bans : [];
  const scanCnt  = bans.filter(b=>b.reason==='scan').length;
  const uaCnt    = bans.filter(b=>b.reason==='bad_ua').length;
  const rateCnt  = bans.filter(b=>b.reason==='rate_limit'||b.reason==='404_flood').length;
  const set = (id,v) => { const e=document.getElementById(id); if(e) e.textContent=v; };
  set('ab-total-bans',   d.total_banned  || 0);
  set('ab-scan-bans',    scanCnt);
  set('ab-ua-bans',      uaCnt);
  set('ab-rate-bans',    rateCnt);
  set('ab-tracked',      d.tracked_ips   || 0);

  // Config
  if(d.config) {
    const c = d.config;
    _autobanEnabled = c.enabled;
    const btn = document.getElementById('autoban-toggle-btn');
    if(btn) btn.textContent = c.enabled ? '⏸ Wyłącz' : '▶ Włącz';

    const setVal = (id, v) => { const e=document.getElementById(id); if(e) e.value=v; };
    const setChk = (id, v) => { const e=document.getElementById(id); if(e) e.checked=v; };
    setVal('ab-rps',  c.rate_limit_rps);
    setVal('ab-e404', c.err404_threshold);
    setVal('ab-scan', c.scan_threshold);
    setVal('ab-win',  c.window_sec);
    setChk('ab-ch-scan', c.ban_scanpaths);
    setChk('ab-ch-rl',   c.ban_ratelimit);
    setChk('ab-ch-404',  c.ban_404flood);
    setChk('ab-ch-ua',   c.ban_bad_ua);
  }

  // Recent bans table
  const tbody = document.getElementById('ab-bans-tbody');
  if(tbody && Array.isArray(d.recent_bans)) {
    const REASON_COLOR = {
      'scan': 'var(--warn)', 'bad_ua': '#ff6b35',
      'rate_limit': '#0088ff', '404_flood': '#cc44ff'
    };
    const REASON_LABEL = {
      'scan': '🔍 Scan path', 'bad_ua': '🤖 Bad UA',
      'rate_limit': '⚡ Rate limit', '404_flood': '🌊 404 flood'
    };
    tbody.innerHTML = d.recent_bans.length === 0
      ? '<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--dim)">Brak banów — system czuwa 👁</td></tr>'
      : d.recent_bans.map(b => {
          const color = REASON_COLOR[b.reason] || 'var(--text)';
          const label = REASON_LABEL[b.reason] || b.reason;
          return `<tr style="border-bottom:1px solid var(--border)">
            <td style="padding:6px 8px;color:var(--dim);white-space:nowrap">${b.ts}</td>
            <td style="padding:6px 8px;font-family:monospace;color:var(--bright)">${b.ip}</td>
            <td style="padding:6px 8px"><span style="color:${color};font-weight:600">${label}</span></td>
            <td style="padding:6px 8px;color:var(--dim);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${b.detail}">${b.detail}</td>
            <td style="padding:6px 8px">
              <button class="btn btn-ghost" style="font-size:10px;padding:2px 8px;color:var(--warn)"
                onclick="unbanIp('${b.ip}')">unban</button>
            </td>
          </tr>`;
        }).join('');
  }
}

async function toggleAutoban() {
  _autobanEnabled = !_autobanEnabled;
  await api('/np_autoban', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({enabled: _autobanEnabled})});
  loadAutoban();
}

async function clearAutobanStats() {
  await api('/np_autoban', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({clear: true})});
  toast('✓ Statystyki AutoBan wyczyszczone');
  loadAutoban();
}

async function saveAutobanConfig() {
  const getVal = id => parseInt(document.getElementById(id)?.value)||0;
  const getChk = id => document.getElementById(id)?.checked ?? true;
  const cfg = {
    rate_limit_rps:   getVal('ab-rps'),
    err404_threshold: getVal('ab-e404'),
    scan_threshold:   getVal('ab-scan'),
    window_sec:       getVal('ab-win'),
    ban_scanpaths: getChk('ab-ch-scan'),
    ban_ratelimit: getChk('ab-ch-rl'),
    ban_404flood:  getChk('ab-ch-404'),
    ban_bad_ua:    getChk('ab-ch-ua'),
  };
  await api('/np_autoban', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(cfg)});
  toast('✓ Konfiguracja AutoBan zapisana');
  loadAutoban();
}

async function unbanIp(ip) {
  await api('/np_blacklist', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'remove', ip})});
  toast('✓ Odblokowano: ' + ip);
  loadAutoban();
}




// ── WAF Dashboard stats ───────────────────────────────────────────────────────

async function updateWafDashboard() {
  let totalBlocked = 0, totalDetected = 0, totalChecked = 0;
  let topThreat = '—', topThreatSub = '', modesStr = '';
  let lastEventCat = null;

  // Regex WAF
  try {
    const r = await api('/np_waf_regex');
    if(r) {
      totalBlocked  += (r.total_blocked  || 0);
      totalDetected += (r.total_detected || 0);
      totalChecked  += (r.total_checked  || 0);
      if(Array.isArray(r.categories) && r.categories.length) {
        const top = r.categories.reduce((a,b)=>a.count>b.count?a:b);
        topThreat = top.cat; topThreatSub = `${top.count}x wykryto`;
      }
      if(Array.isArray(r.events) && r.events.length)
        lastEventCat = r.events[0].cat;
      const m = r.enabled ? (r.block_mode ? 'BLOCK' : 'DETECT') : 'OFF';
      modesStr = `Regex: ${m}`;
    }
  } catch(e){}

  // ModSec WAF
  try {
    const m = await api('/np_waf');
    if(m && m.loaded && m.enabled) {
      totalBlocked  += (m.total_blocked  || 0);
      totalDetected += (m.total_detected || 0);
      totalChecked  += (m.total_checked  || 0);
      const ms = m.block_mode ? 'BLOCK' : 'DETECT';
      modesStr += (modesStr ? ' · ' : '') + `ModSec: ${ms}`;
    }
  } catch(e){}

  // Update cards
  const set = (id,v) => { const e=document.getElementById(id); if(e) e.textContent=v; };
  set('dash-waf-blocked',  fmt(totalBlocked));
  set('dash-waf-detected', fmt(totalDetected));
  set('dash-waf-checked',  fmt(totalChecked));
  set('dash-waf-top-threat', topThreat);
  set('dash-waf-top-sub',    lastEventCat ? `ostatnio: ${lastEventCat}` : topThreatSub || 'brak zdarzeń');
  set('dash-waf-mode-sub',   modesStr || '—');

}


// ── WAF Regex ─────────────────────────────────────────────────────────────────
async function loadWafRegex() {
  const d = await api('/np_waf_regex');
  if(!d) return;

  const set = (id,v) => { const e=document.getElementById(id); if(e) e.textContent=v; };
  set('wafr-blocked',  d.total_blocked  || 0);
  set('wafr-detected', d.total_detected || 0);
  set('wafr-checked',  d.total_checked  || 0);

  const btn = document.getElementById('wafr-toggle-btn');
  if(btn) btn.textContent = d.enabled ? '⏸ Wyłącz' : '▶ Włącz';
  const blk = document.getElementById('wafr-block');
  const cb  = document.getElementById('wafr-check-body');
  if(blk) blk.checked = !!d.block_mode;
  if(cb)  cb.checked  = true;

  // Category badges with counts
  const catsEl = document.getElementById('wafr-cats');
  if(catsEl && Array.isArray(d.categories)){
    const CAT_COLOR = {
      SQLi:'rgba(255,80,80,.2)', XSS:'rgba(255,170,0,.2)',
      PathTraversal:'rgba(0,200,100,.2)', CmdInjection:'rgba(200,70,255,.2)',
      SSRF:'rgba(0,136,255,.2)', XXE:'rgba(255,200,0,.2)'
    };
    catsEl.innerHTML = d.categories.map(c =>
      `<span style="background:${CAT_COLOR[c.cat]||'rgba(128,128,128,.2)'};
        border:1px solid rgba(128,128,128,.3);padding:3px 10px;border-radius:12px;
        font-size:11px">${c.cat}: <b>${c.count}</b></span>`
    ).join('');
  }

  // Events table
  const CAT_COLOR = {
    SQLi:'#ff8888', XSS:'var(--warn)', PathTraversal:'#00cc66',
    CmdInjection:'#cc44ff', SSRF:'#0088ff', XXE:'#ffcc00'
  };
  const tbody = document.getElementById('wafr-tbody');
  if(tbody && Array.isArray(d.events)){
    tbody.innerHTML = d.events.length === 0
      ? '<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--dim)">Brak zdarzeń 🛡</td></tr>'
      : d.events.map(e => {
          const c = CAT_COLOR[e.cat] || 'var(--text)';
          return `<tr style="border-bottom:1px solid var(--border)">
            <td style="padding:5px 8px;color:var(--dim);white-space:nowrap">${e.ts}</td>
            <td style="padding:5px 8px;font-family:monospace">${e.ip}</td>
            <td style="padding:5px 8px"><span style="color:${c};font-weight:600">${e.cat}</span></td>
            <td style="padding:5px 8px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace" title="${e.uri}">${e.uri}</td>
            <td style="padding:5px 8px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;color:var(--dim)" title="${e.detail}">${e.detail}</td>
          </tr>`;
        }).join('');
  }
}

async function toggleWafRegex() {
  const d = await api('/np_waf_regex');
  const newState = d ? !d.enabled : true;
  await api('/np_waf_regex', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({enabled: newState})});
  loadWafRegex();
}

async function saveWafRegexConfig() {
  const block = document.getElementById('wafr-block')?.checked ?? true;
  const body  = document.getElementById('wafr-check-body')?.checked ?? true;
  await api('/np_waf_regex', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({block_mode: block, check_body: body})});
  toast(block ? '✓ WAF Regex: tryb BLOCK' : '✓ WAF Regex: tryb DETECT');
  loadWafRegex();
}

async function clearWafRegex() {
  await api('/np_waf_regex', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({clear: true})});
  toast('✓ WAF Regex — logi wyczyszczone');
  loadWafRegex();
}

// ── WAF ───────────────────────────────────────────────────────────────────────
let _wafEnabled = false;

async function loadWaf() {
  const d = await api('/np_waf');
  if(!d) return;

  const set = (id,v) => { const e=document.getElementById(id); if(e) e.textContent=v; };
  set('waf-blocked',  d.total_blocked  || 0);
  set('waf-detected', d.total_detected || 0);
  set('waf-checked',  d.total_checked  || 0);

  _wafEnabled = d.enabled;
  const btn = document.getElementById('waf-toggle-btn');
  if(btn) btn.textContent = d.enabled ? '⏸ Wyłącz' : '▶ Włącz';

  // Status banner
  const banner = document.getElementById('waf-status-banner');
  const hint   = document.getElementById('waf-install-hint');
  if(banner){
    if(!d.loaded){
      banner.style.background = 'rgba(255,170,0,.08)';
      banner.style.border     = '1px solid rgba(255,170,0,.3)';
      banner.style.color      = 'var(--warn)';
      const errMsg = d.load_error && d.load_error.length > 0
        ? d.load_error
        : 'Skompiluj z WITH_MODSEC=ON lub dodaj modsec_enabled on; do nas-web.conf';
      banner.textContent = '⚠ WAF nie załadowany — ' + errMsg;
      if(hint) hint.style.display = 'block';
    } else if(!d.enabled){
      banner.style.background = 'rgba(100,100,100,.1)';
      banner.style.border     = '1px solid var(--border)';
      banner.style.color      = 'var(--dim)';
      banner.textContent = '⏸ WAF wyłączony — dodaj: modsec_enabled on; do nas-web.conf';
      if(hint) hint.style.display = 'none';
    } else {
      const modeColor = d.block_mode ? 'rgba(255,80,80,.08)' : 'rgba(200,70,255,.08)';
      const modeBorder= d.block_mode ? 'rgba(255,80,80,.3)' : 'rgba(200,70,255,.3)';
      banner.style.background = modeColor;
      banner.style.border     = `1px solid ${modeBorder}`;
      banner.style.color      = d.block_mode ? 'var(--warn)' : '#cc44ff';
      const rc = d.rules_count > 0 ? ` (${d.rules_count} reguł)` : ' ⚠ 0 reguł!';
      banner.textContent      = d.block_mode
        ? `🚫 BLOCK — reguły z: ${d.rules_dir}${rc}`
        : `👁 DETECT — reguły z: ${d.rules_dir}${rc}`;
      if(hint) hint.style.display = 'none';
    }
  }

  // Mode radio
  const blk = document.getElementById('waf-mode-block');
  const det = document.getElementById('waf-mode-detect');
  if(blk) blk.checked = !!d.block_mode;
  if(det) det.checked = !d.block_mode;

  // Events table
  const SEV_COLOR = { CRITICAL:'#ff4444', ERROR:'#ff7744', WARNING:'var(--warn)',
                      NOTICE:'#0088ff', INFO:'var(--dim)' };
  const tbody = document.getElementById('waf-events-tbody');
  if(tbody && Array.isArray(d.events)){
    tbody.innerHTML = d.events.length === 0
      ? '<tr><td colspan="7" style="padding:16px;text-align:center;color:var(--dim)">Brak zdarzeń WAF 🛡</td></tr>'
      : d.events.map(e => {
          const sc = SEV_COLOR[e.sev] || 'var(--text)';
          return `<tr style="border-bottom:1px solid var(--border)">
            <td style="padding:5px 8px;color:var(--dim);white-space:nowrap">${e.ts}</td>
            <td style="padding:5px 8px;font-family:monospace">${e.ip}</td>
            <td style="padding:5px 8px;color:var(--accent)">${e.method}</td>
            <td style="padding:5px 8px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace" title="${e.uri}">${e.uri}</td>
            <td style="padding:5px 8px;font-family:monospace;color:var(--warn)">${e.rule}</td>
            <td style="padding:5px 8px;color:var(--dim);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${e.msg}">${e.msg}</td>
            <td style="padding:5px 8px;font-weight:700;font-size:10px" style="color:${sc}">${e.sev||'-'}</td>
          </tr>`;
        }).join('');
  }
}

async function toggleWaf() {
  _wafEnabled = !_wafEnabled;
  await api('/np_waf', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({enabled: _wafEnabled})});
  loadWaf();
}

async function saveWafMode() {
  const block = document.getElementById('waf-mode-block')?.checked ?? true;
  await api('/np_waf', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({block_mode: block})});
  toast(block ? '✓ Tryb: BLOCK — aktywne blokowanie' : '✓ Tryb: DETECT — tylko logowanie');
  loadWaf();
}

async function clearWafEvents() {
  await api('/np_waf', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({clear: true})});
  toast('✓ Zdarzenia WAF wyczyszczone');
  loadWaf();
}

function toggleTheme(){
  const root = document.documentElement;
  const isLight = root.classList.toggle('light');
  localStorage.setItem('nw_theme', isLight ? 'light' : 'dark');
  document.getElementById('theme-toggle').textContent = isLight ? '☽' : '☀';
}
// Apply saved theme on load
(function(){
  if(localStorage.getItem('nw_theme')==='light'){
    document.documentElement.classList.add('light');
    // button updated after DOM ready
  }
})();

function doLogin(){
  const u=document.getElementById('l-user').value.trim();
  const p=document.getElementById('l-pass').value;
  if(!u||!p){document.getElementById('l-err').textContent='Enter credentials';return;}
  const h='Basic '+btoa(u+':'+p);
  fetch('/np_status',{headers:{Authorization:h}}).then(r=>{
    if(r.ok){authHeader=h;sessionStorage.setItem('nw_auth',h);showApp();}
    else{document.getElementById('l-err').textContent='Invalid credentials';document.getElementById('l-pass').value='';document.getElementById('l-pass').focus();}
  }).catch(()=>{document.getElementById('l-err').textContent='Connection failed';});
}
function doLogout(){
  sessionStorage.removeItem('nw_auth');authHeader='';
  if(refreshTimer)clearInterval(refreshTimer);refreshTimer=null;
  document.getElementById('login-wrap').classList.remove('hidden');
  document.getElementById('app').style.display='none';
  document.getElementById('l-pass').value='';document.getElementById('l-err').textContent='';
}
function showApp(){
  document.getElementById('login-wrap').classList.add('hidden');
  document.getElementById('app').style.display='flex';
  document.getElementById('app').style.flexDirection='column';
  init();
}
if(authHeader){fetch('/np_status',{headers:{Authorization:authHeader}}).then(r=>{if(r.ok)showApp();else{authHeader='';sessionStorage.removeItem('nw_auth');}}).catch(()=>{});}

// ── Helpers ──────────────────────────────────────────────────────────────────
// ── CSRF token cache ─────────────────────────────────────────────────────────
let _csrfToken = null;
let _csrfFetched = 0;
async function getCsrfToken() {
  const now = Date.now() / 1000;
  if(_csrfToken && now - _csrfFetched < 3500) return _csrfToken; // cache ~1h
  try {
    const r = await fetch('/np_csrf', {headers:{Authorization:authHeader}});
    if(r.ok) { const d = await r.json(); _csrfToken = d.token; _csrfFetched = now; }
  } catch(e) {}
  return _csrfToken || '';
}

function api(path, opts={}) {
  const method = (opts.method||'GET').toUpperCase();
  const needsCsrf = ['POST','PUT','DELETE'].includes(method);
  if(needsCsrf) {
    return getCsrfToken().then(tok => {
      return fetch(path, {...opts, headers: {
        Authorization: authHeader,
        'X-CSRF-Token': tok,
        ...(opts.headers||{})
      }}).then(r=>r.ok?r.json().catch(()=>null):null).catch(()=>null);
    });
  }
  return fetch(path, {...opts, headers:{Authorization:authHeader,...(opts.headers||{})}})
    .then(r=>r.ok?r.json().catch(()=>null):null)
    .catch(()=>null);
}
function fmt(n){return n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':String(n)}
function fmtUp(s){const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);if(d)return d+'d '+h+'h';if(h)return h+'h '+m+'m';return m+'m '+(s%60)+'s'}
function gauge(id,pct,txtId,lbl){const e=document.getElementById(id);if(e)e.style.strokeDashoffset=201-(pct/100)*201;const t=document.getElementById(txtId);if(t)t.textContent=lbl||Math.round(pct)+'%'}
function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2500)}
function show(id,el){
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  // waf-regex nav uses id sec-waf-regex
  const secId = id === 'waf-regex' ? 'sec-waf-regex' : 'sec-'+id;
  const sec = document.getElementById(secId);
  if(!sec){ console.warn('Section not found:', secId); return; }
  sec.classList.add('active');
  if(el && el.classList) el.classList.add('active');
  // Refresh data for the newly visible tab
  if(id==='cache')       renderCache();
  if(id==='connections'){ renderConns(); startConnRefresh(); } else stopConnRefresh();
  if(id==='overview') requestAnimationFrame(()=>{ fetchAll(); drawRpsChart(); });
  if(id==='upstream')    loadUpstreams();
  if(id==='modules')     renderModules();
  if(id==='security')  { loadBlacklist(); loadSettings(); }
  if(id==='upstreams')   loadUpstreams();
  if(id==='workers')     renderWorkers(null);
  if(id==='ssl')         refreshAcme();
  if(id==='security'){
    // Show current IP in allowlist panel
    const ipEl = document.getElementById('admin-my-ip');
    if(ipEl) {
      api('/np_status').then(d => {
        if(d && d.client_ip){
          ipEl.textContent = d.client_ip;
          ipEl.title = 'IP widziane przez serwer (może być IP proxy/gateway)';
        }
      });
    }
    // Show allowlist status from /np_status or fallback
    api('/np_status').then(d => {
      const el = document.getElementById('allowlist-status');
      if(el) el.textContent = d?.admin_allowlist_size > 0 ?
        d.admin_allowlist_size+' reguł' : 'brak ograniczeń (otwarte)';
    });
  }
  if(id==='logs'){
    fetchServerLogs();
    loadDb();  // sprawdź czy SQLite aktywne → pokaż nav item
    if(!window._logTimer) window._logTimer = setInterval(()=>{
      const active = document.getElementById('sec-logs');
      if(active && active.classList.contains('active')){
        fetchServerLogs();
        addAccessLog();
      }
    }, 4000);
  } else if(id === 'dashboard'){
    loadDashboard(120);
    if(window._dashTimer){ clearInterval(window._dashTimer); window._dashTimer=null; }
    window._dashTimer = setInterval(()=>{
      const active = document.getElementById('sec-dashboard');
      if(active && active.classList.contains('active')) loadDashboard(120);
    }, 10000);
  } else if(id === 'audit'){
    loadAudit();
  } else if(id === 'db'){
    loadDb();
  } else if(id === 'autoban'){
    loadAutoban();
  } else if(id === 'waf'){
    loadWaf();
  } else if(id === 'waf-regex'){
    loadWafRegex();
    if(window._wafrTimer){ clearInterval(window._wafrTimer); window._wafrTimer=null; }
    window._wafrTimer = setInterval(()=>{
      const active = document.getElementById('sec-waf-regex');
      if(active && active.classList.contains('active')) loadWafRegex();
    }, 4000);
  } else if(id === 'waf'){
    loadWaf();
    if(window._wafTimer){ clearInterval(window._wafTimer); window._wafTimer=null; }
    window._wafTimer = setInterval(()=>{
      const active = document.getElementById('sec-waf');
      if(active && active.classList.contains('active')) loadWaf();
    }, 4000);
  } else {
    stopSSELog();
  }
}

// ── Clock ────────────────────────────────────────────────────────────────────
setInterval(()=>{document.getElementById('hdr-clock').textContent=new Date().toTimeString().slice(0,8)},1000);

// ── RPS Chart ────────────────────────────────────────────────────────────────
const RPS=new Array(60).fill(0);let prevReq=0,prevTime=Date.now();
function drawRpsChart(){
  const c=document.getElementById('rps-chart');if(!c)return;
  const dpr=window.devicePixelRatio||1;
  // Użyj rodzica lub dokumentu jako szerokości — działa też gdy sekcja ukryta
  const parent=c.parentElement;
  const w=Math.max(parent?parent.getBoundingClientRect().width-32:300, 100);
  const h=90;
  if(c.width!==Math.round(w*dpr)||c.height!==h*dpr){
    c.width=Math.round(w*dpr);c.height=h*dpr;
    c.style.width=w+'px';c.style.height=h+'px';
  }
  const ctx=c.getContext('2d');ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,w,h);
  const max=Math.max(...RPS,1),step=w/59;
  ctx.strokeStyle='rgba(128,140,160,.25)';ctx.lineWidth=1;
  [0,1,2,3].forEach(i=>{const y=Math.round(h*i/3)+.5;ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()});
  const g=ctx.createLinearGradient(0,0,0,h);
  g.addColorStop(0,'rgba(0,212,170,.28)');g.addColorStop(1,'rgba(0,212,170,0)');
  ctx.beginPath();ctx.moveTo(0,h);
  RPS.forEach((v,i)=>{const x=i*step,y=h-(v/max)*h*.85;i?ctx.lineTo(x,y):ctx.lineTo(x,y)});
  ctx.lineTo(59*step,h);ctx.closePath();ctx.fillStyle=g;ctx.fill();
  ctx.beginPath();ctx.strokeStyle='#00d4aa';ctx.lineWidth=2;
  RPS.forEach((v,i)=>{const x=i*step,y=h-(v/max)*h*.85;i?ctx.lineTo(x,y):ctx.moveTo(x,y)});
  ctx.stroke();
  // Y-axis label top
  ctx.fillStyle='rgba(0,212,170,.6)';ctx.font=`${9*dpr/dpr}px monospace`;
  ctx.fillText(max.toFixed(max<10?1:0)+' req/s',4,10);
}

// Rysuj wykres po każdej zmianie rozmiaru okna
if(typeof ResizeObserver!=='undefined'){
  const rpsEl=document.getElementById('rps-chart');
  if(rpsEl){ new ResizeObserver(()=>drawRpsChart()).observe(rpsEl.parentElement||rpsEl); }
}

// ── Log ──────────────────────────────────────────────────────────────────────
const PATHS=['/api/files','/api/disk','/assets/index.js','/api/users','/apis/healths','/assets/main.css','/api/upload','/api/settings','/'];
const IPS=['192.168.1.101','192.168.1.54','192.168.1.200','10.0.0.5'];
// ── Log state ────────────────────────────────────────────────────────────────
let logFilters = {f2xx:true, f4xx:true, f5xx:true, fstatic:true};
let srvFilters = {error:true, warn:true, info:true, debug:false};
let _logTimer = null;
let _lastSrvTs = 0;  // last seen timestamp for incremental server log

// ── HTTP Access Log (from /np_connections history) ────────────────────────────
async function addAccessLog(){
  if(document.getElementById('log-pause')?.checked) return;
  const d = await api('/np_connections');
  if(!d) return;
  const conns = (d.connections||[]).slice().reverse(); // oldest first
  const box = document.getElementById('access-log');
  if(!box) return;

  const METHOD_CLR = {GET:'#0088ff',POST:'#ff6b35',PUT:'#f0c040',DELETE:'#ff3355',HEAD:'#888',OPTIONS:'#888'};
  const TYPE_ICON  = {proxy:'⇄', static:'📄', ws:'⚡', health:'💓'};

  box.innerHTML = conns.map(c => {
    const code = c.status||0;
    const sc   = code>=500?'lv-error':code>=400?'lv-warn':code>=200?'lv-info':'lv-debug';
    const cat  = code>=500?'5xx':code>=400?'4xx':'2xx';
    const method = c.method||'?';
    const mclr = METHOD_CLR[method]||'#aaa';
    const path = (c.path||'/').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const typeIcon = TYPE_ICON[c.type]||'?';
    const tc = c.type==='proxy'?'blue':c.type==='static'?'dim':c.type==='ws'?'green':'dim';

    // Format timestamp — age_ms since last request
    const ageMs = c.age_ms||0;
    let tsLabel;
    if(ageMs < 1000)       tsLabel = 'teraz';
    else if(ageMs < 60000) tsLabel = (ageMs/1000).toFixed(1)+'s temu';
    else                   tsLabel = Math.round(ageMs/60000)+'min temu';

    const latency = c.latency_ms != null ? c.latency_ms+'ms' : '—';
    const live = c.active ? '<span class="badge green" style="font-size:8px;padding:1px 4px">●</span>' : '';

    return `<div class="log-entry" data-cat="${cat}" data-ip="${c.ip||''}" data-path="${path}" data-method="${method}"
      style="display:grid;grid-template-columns:140px 55px 60px minmax(0,1fr) 60px 70px 60px;gap:0;padding:3px 12px;align-items:center;border-bottom:1px solid var(--border)20">
      <span class="log-ts" style="font-size:10px">${tsLabel}</span>
      <span style="font-size:10px;color:var(--accent2);font-family:monospace">${c.ip||'—'}</span>
      <span style="font-size:10px;font-weight:700;color:${mclr}">${method}</span>
      <span style="font-size:11px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${path}">${path}</span>
      <span style="text-align:center">${code?`<span class="log-lv ${sc}">${code}</span>`:live}</span>
      <span style="text-align:right;font-size:10px;color:var(--dim)">${latency}</span>
      <span style="text-align:right"><span class="badge ${tc}" style="font-size:9px">${typeIcon} ${c.type||'?'}</span></span>
    </div>`;
  }).join('');

  if(conns.length) box.scrollTop = box.scrollHeight;
  filterLog();
}

// ── Server Internal Log (from /np_logs ring buffer) ───────────────────────────
async function fetchServerLogs(){
  const box = document.getElementById('server-log');
  if(!box) return;

  // level: 0=debug,1=info,2=warn,3=error — request all if debug active
  const minLv = srvFilters.debug ? 0 : srvFilters.info ? 1 : srvFilters.warn ? 2 : 3;
  const data  = await api(`/np_logs?level=${minLv}&limit=500`);
  if(!data || !Array.isArray(data)) return;

  const LV_CLS = {error:'lv-error', warn:'lv-warn', info:'lv-info', debug:'lv-debug'};
  const LV_ICO = {error:'✗', warn:'⚠', info:'ℹ', debug:'·'};
  const MOD_CLR= {acme:'#f0c040',tls:'#00d4aa',proxy:'#0088ff',cache:'#ff6b35',
                  config:'#aa88ff',ratelimit:'#ff3355',lua:'#88cc44',js:'#ffaa00',
                  upstream:'#00ccff', features:'#ff88cc'};

  // data comes newest-first from server, reverse to show oldest→newest
  const entries = data.slice().reverse();
  box.innerHTML = entries.map(e => {
    const lv  = e.level||'info';
    const cls = LV_CLS[lv]||'lv-info';
    const ico = LV_ICO[lv]||'·';
    const mod = e.module||'';
    const mclr= MOD_CLR[mod]||'var(--dim)';
    const msg = (e.msg||'').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\n/g,' ').replace(/\r/g,'');
    return `<div class="log-entry" data-level="${lv}" data-module="${mod}" data-msg="${msg.toLowerCase()}"
      style="display:grid;grid-template-columns:155px 55px 70px minmax(0,1fr);gap:0;padding:3px 12px;align-items:center;border-bottom:1px solid var(--border)20">
      <span class="log-ts" style="font-size:10px">${e.ts||'—'}</span>
      <span class="log-lv ${cls}" style="font-size:10px">${ico} ${lv.toUpperCase()}</span>
      <span style="font-size:10px;font-weight:600;color:${mclr};font-family:monospace">[${mod}]</span>
      <span class="log-msg" style="font-size:11px">${msg}</span>
    </div>`;
  }).join('');

  const cnt = document.getElementById('srv-log-count');
  if(cnt) cnt.textContent = data.length+' wpisów';
  if(entries.length) box.scrollTop = box.scrollHeight;
  filterSrvLog();
}

// ── Log file reader ───────────────────────────────────────────────────────────
async function loadLogFile(file){
  const box = document.getElementById('logfile-box');
  const lbl = document.getElementById('logfile-name');
  if(!box) return;
  box.innerHTML = '<div style="color:var(--dim);padding:12px">Ładowanie...</div>';
  if(lbl) lbl.textContent = file+'.log';
  const data = await api('/np_logfile?file='+file+'&lines=300');
  if(!data || !Array.isArray(data)){
    box.innerHTML='<div style="color:var(--warn);padding:12px">Brak pliku lub błąd odczytu</div>';
    return;
  }
  box.innerHTML = data.map(line => {
    if(!line) return '';
    const lv = line.includes('[ERROR]')||/\berror\b/i.test(line) ? 'lv-error' :
               line.includes('[WARN]') ||/\bwarn\b/i.test(line)  ? 'lv-warn'  :
               line.includes('[DEBUG]')                           ? 'lv-debug' : 'lv-info';
    return `<div class="log-entry ${lv}" style="padding:2px 12px;font-size:11px;font-family:monospace;white-space:pre-wrap;word-break:break-all">${line.replace(/</g,'&lt;')}</div>`;
  }).join('');
  box.scrollTop = box.scrollHeight;
}

// ── Filters ───────────────────────────────────────────────────────────────────
function toggleFilter(cat,btn){
  const map={'2xx':'f2xx','4xx':'f4xx','5xx':'f5xx','static':'fstatic'};
  const k=map[cat]; logFilters[k]=!logFilters[k];
  const cls={'2xx':'active-info','4xx':'active-warn','5xx':'active-error','static':'active-debug'};
  btn.className='log-lvl'+(logFilters[k]?' '+cls[cat]:'');
  filterLog();
}

function filterLog(){
  const search=(document.getElementById('log-search')?.value||'').toLowerCase();
  document.querySelectorAll('#access-log .log-entry').forEach(r=>{
    const cat=r.dataset.cat;
    const txt=(r.dataset.ip+r.dataset.path+r.dataset.method).toLowerCase();
    const catOk = cat==='2xx'?logFilters.f2xx : cat==='4xx'?logFilters.f4xx :
                  cat==='5xx'?logFilters.f5xx : logFilters.fstatic;
    r.style.display = (catOk && (!search || txt.includes(search))) ? '' : 'none';
  });
}

function toggleSrvFilter(lv,btn){
  srvFilters[lv]=!srvFilters[lv];
  const cls={error:'active-error',warn:'active-warn',info:'active-info',debug:'active-debug'};
  btn.className='log-lvl'+(srvFilters[lv]?' '+cls[lv]:'');
  filterSrvLog();
  // reload if enabling debug (need different API level)
  fetchServerLogs();
}

function filterSrvLog(){
  const search=(document.getElementById('srv-search')?.value||'').toLowerCase();
  document.querySelectorAll('#server-log .log-entry').forEach(r=>{
    const lv=r.dataset.level;
    const ok = srvFilters[lv]!==false;
    const txt=(r.dataset.module+r.dataset.msg).toLowerCase();
    r.style.display = (ok && (!search || txt.includes(search))) ? '' : 'none';
  });
}

function clearLog(id){const b=document.getElementById(id);if(b)b.innerHTML='';}

// ── Cache ────────────────────────────────────────────────────────────────────
// cache data loaded from /np_cache
async function renderCache(){
  const d = await api('/np_cache');
  const set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
  if(!d){
    set('c-entries','err'); set('c-hits','—'); set('c-ratio','—');
    const ce=document.getElementById('cache-entries');
    if(ce)ce.innerHTML='<div style="padding:16px;color:var(--warn);text-align:center;font-size:12px">Błąd /np_cache — sprawdź czy serwer działa</div>';
    return;
  }
  // Debug: log what we got
  console.debug('/np_cache:', JSON.stringify(d).slice(0,120));
  const used=d.entries||0, max=d.max||1024;
  const hits=d.hits||0, misses=d.misses||0, evictions=d.evictions||0;
  const bytes=d.bytes_stored||0;
  const total=hits+misses||1;
  set('c-entries', used || '0');
  set('c-hits', fmt(hits));
  set('c-misses', fmt(misses));
  set('c-evictions', fmt(evictions));
  set('c-ratio', total>1 ? Math.round(hits/total*100)+'%' : '—');
  const usePct = max>0 ? Math.round(used/max*100) : 0;
  set('c-usage-pct', usePct+'%');
  const bar=document.getElementById('c-usage-bar');
  if(bar) bar.style.width=usePct+'%';
  // bytes stored label
  const bytesFmt = bytes>1048576?(bytes/1048576).toFixed(1)+' MB':bytes>1024?(bytes/1024).toFixed(0)+' KB':bytes+' B';
  set('c-used', used); set('c-max', max+(bytes>0?' ('+bytesFmt+')':'')); set('c-count', used);
  const entries=d.entries_list||[];
  const ce=document.getElementById('cache-entries');
  if(!ce) return;
  ce.innerHTML=entries.length===0
    ? '<div style="padding:16px;color:var(--dim);text-align:center;font-size:12px">Cache pusty<br><span style=\'font-size:10px;opacity:.6\'>Jeśli backend zwraca <code>Cache-Control: no-cache</code>, dodaj do lokacji w konfigu:<br><code>cache max_age=60;</code> — to wymusi cachowanie ignorując nagłówki backendu.<br>Cache działa tylko dla GET, status 200. <code>no-store</code> jest zawsze respektowane.</span></div>'
    : entries.map(e=>`
    <div class="cache-entry">
      <div class="cache-key">${e.path}</div>
      <div class="cache-size">${e.size}</div>
      <div class="cache-ttl"><span class="badge ${e.ttl>30?'green':'orange'}">${e.ttl}s</span></div>
      <div style="color:var(--dim);font-size:11px;width:60px;text-align:right">${e.hits} hits</div>
    </div>`).join('');
}
async function flushCache(){
  if(!confirm('Wyczyścić cały cache?')) return;
  await api('/np_cache',{method:'DELETE',headers:{'Content-Type':'application/json'}});
  toast('✓ Cache wyczyszczony');
  setTimeout(renderCache,500);
}
async function delCacheEntry(path){
  toast('Removed: '+path); setTimeout(renderCache,500);
}

// ── Modules ──────────────────────────────────────────────────────────────────
const MODULES=[
  {name:'libuv',ver:'1.44+',status:'loaded',color:'green',desc:'Async I/O event loop. Powers all network operations, timers, and worker threads.',tags:['event-loop','async','tcp','timers']},
  {name:'nghttp2',ver:'1.51+',status:'loaded',color:'green',desc:'HTTP/2 framing and HPACK header compression. Enables multiplexed HTTP/2 connections.',tags:['http/2','hpack','multiplexing']},
  {name:'OpenSSL',ver:'3.0+',status:'loaded',color:'green',desc:'TLS/SSL encryption for HTTPS connections. Handles certificates and cipher negotiation.',tags:['tls','ssl','https','certs']},
  {name:'zlib',ver:'1.2+',status:'loaded',color:'green',desc:'gzip/deflate compression for static files and proxy responses.',tags:['gzip','deflate','compress']},
  {name:'Lua 5.4',ver:'5.4',status:'loaded',color:'green',desc:'Embedded scripting engine for middleware. Runs admin_acl.lua and other scripts per-worker.',tags:['scripting','middleware','lua']},
  {name:'JS Engine',ver:'n/a',status:'disabled',color:'dim',desc:'JS middleware disabled — Lua 5.4 handles all scripting. No V8/QuickJS dependency, no conflict with Node.js.',tags:['lua','scripting','middleware']},
  {name:'quiche',ver:'—',status:'disabled',color:'dim',desc:'HTTP/3 / QUIC support via Cloudflare quiche. Build with -DWITH_QUICHE=ON after building quiche from source.',tags:['http/3','quic','udp']},
  {name:'Cache',ver:'built-in',status:'active',color:'blue',desc:'LRU response cache with TTL and RFC 7234 Cache-Control support. Configurable size and TTL.',tags:['lru','cache-control','ttl']},
  {name:'Rate Limiter',ver:'built-in',status:'active',color:'blue',desc:'Token bucket rate limiter per client IP. Configurable rate, burst, and window per location.',tags:['ratelimit','token-bucket','per-ip']},
  {name:'Static Handler',ver:'built-in',status:'active',color:'blue',desc:'Serves static files with gzip, ETag, Range, Last-Modified and SPA fallback to index.html.',tags:['static','gzip','etag','range','spa']},
  {name:'SQLite3',ver:'3.45+',status:'loaded',color:'green',desc:'Vendored SQLite3 amalgamation — persistent storage for IP blacklist and ban events. Replaces blacklist.txt / recent_bans.txt. WAL mode, atomic writes.',tags:['sqlite','persistence','blacklist','bans','wal']},
  {name:'lua-cjson',ver:'2.1.0',status:'loaded',color:'green',desc:'Fast JSON encoder/decoder for Lua scripts (OpenResty fork). Available as require("cjson") in all Lua middleware. Supports cjson.safe mode.',tags:['lua','json','cjson','middleware']},
];
async function toggleFeature(id, enable) {
  const r = await api('/np_features', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({module:id, enabled:enable})});
  if(r) renderModules();
}

async function renderModules(){
  const [data, flags] = await Promise.all([api('/np_module'), api('/np_features')]);
  const grid = document.getElementById('modules-grid');
  if(!data || !Array.isArray(data.modules)){
    grid.innerHTML='<div style="color:var(--warn);padding:8px">Błąd ładowania modułów</div>'; return;
  }

  // Icon map (id → emoji) — defined in JS, safe from C++ encoding issues
  const ICONS = {
    cache:'💾', ratelimit:'🔒', gzip:'📦', lua:'🌙',
    js:'⚡', tls:'🔐', h2:'🚀', healthcheck:'💓', acme:'🔑',
    waf_regex:'🔍', waf_modsec:'🛡', autoban:'🚫',
    sqlite:'🗄', 'lua-cjson':'🔣', default:'🔧'
  };

  // Pobierz stan WAF i wstaw jako wirtualne moduły
  let wafModules = [];
  try {
    const [wr, wm] = await Promise.all([api('/np_waf_regex'), api('/np_waf')]);
    if(wr) wafModules.push({
      id:'waf_regex', name:'WAF Regex', version:'built-in',
      enabled: wr.enabled && wr.compiled,
      toggleable: true,
      note: wr.compiled
        ? `SQLi / XSS / PathTraversal / CmdInj / SSRF / XXE<br>` +
          `Zablokowanych: <b>${wr.total_blocked}</b> · Sprawdzonych: ${wr.total_checked}`
        : 'Nie skompilowany',
      _waf_mode: wr.block_mode ? 'BLOCK' : 'DETECT',
      _waf_type: 'regex'
    });
    if(wm) wafModules.push({
      id:'waf_modsec', name:'WAF ModSecurity', version:'v3',
      enabled: wm.loaded && wm.enabled,
      toggleable: true,
      note: wm.loaded
        ? `OWASP CRS · ${wm.rules_count||0} reguł<br>` +
          `Zablokowanych: <b>${wm.total_blocked}</b> · z: ${wm.rules_dir}`
        : `Nie załadowany${wm.load_error ? ': '+wm.load_error : ''}`,
      _waf_mode: wm.block_mode ? 'BLOCK' : 'DETECT',
      _waf_type: 'modsec'
    });
  } catch(e){}

  const allModules = [...data.modules, ...wafModules];

  grid.innerHTML = allModules.map(m => {
    const on = m.enabled;
    const icon = ICONS[m.id] || ICONS.default;
    const border = on ? 'var(--accent)' : 'var(--border)';
    const badge = on
      ? `<span class="badge green">&#10003; aktywny</span>`
      : `<span class="badge dim">&#10007; off</span>`;
    let btn;
    if(m._waf_type === 'regex'){
      const mode = m._waf_mode||'BLOCK';
      btn = `<div style="display:flex;gap:6px;margin-top:auto;flex-wrap:wrap">
        <button class="btn ${on?'btn-ghost':'btn-primary'}" style="font-size:10px;padding:3px 10px"
          onclick="api('/np_waf_regex',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:${!on}})}).then(()=>renderModules())">
          ${on ? '⏸ Wyłącz' : '▶ Włącz'}
        </button>
        <button class="btn btn-ghost" style="font-size:10px;padding:3px 10px"
          onclick="show('waf-regex',null)">📊 Logi</button>
        <span class="badge ${mode==='BLOCK'?'orange':'dim'}" style="align-self:center">${mode}</span>
      </div>`;
    } else if(m._waf_type === 'modsec'){
      const mode = m._waf_mode||'BLOCK';
      btn = `<div style="display:flex;gap:6px;margin-top:auto;flex-wrap:wrap">
        <button class="btn ${on?'btn-ghost':'btn-primary'}" style="font-size:10px;padding:3px 10px"
          onclick="api('/np_waf',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:${!on}})}).then(()=>renderModules())">
          ${on ? '⏸ Wyłącz' : '▶ Włącz'}
        </button>
        <button class="btn btn-ghost" style="font-size:10px;padding:3px 10px"
          onclick="show('waf',null)">📊 Logi</button>
        <span class="badge ${mode==='BLOCK'?'orange':'dim'}" style="align-self:center">${mode}</span>
      </div>`;
    } else if(m.toggleable){
      btn = `<button class="btn ${on?'btn-ghost':'btn-primary'}"
           style="font-size:10px;padding:3px 10px;margin-top:auto"
           onclick="toggleFeature('${m.id}',${!on})">
           ${on ? '&#10005; Wyłącz' : '&#10003; Włącz'}
         </button>`;
    } else {
      const buildInfo = {
        'zstd':      on ? '\u2713 Aktywny — kompresja zstd dla plików statycznych'
                        : '\u2699 W\u0142\u0105cz: build-deb.sh --with-zstd',
        'janet':     on ? '\u2713 Regu\u0142y WAF z plików .janet w /etc/nas-web/scripts/'
                        : '\u2699 W\u0142\u0105cz: build-deb.sh --with-janet',
        'sqlite':    on ? '\u2713 Aktywny — /var/lib/nas-web/nas-web.db (WAL mode)'
                        : '\u2699 W\u0142\u0105cz: build-deb.sh --with-sqlite (domy\u015blnie ON)',
        'lua-cjson': on ? '\u2713 Aktywny — require(\"cjson\") dost\u0119pne w Lua middleware'
                        : '\u2699 W\u0142\u0105cz: build-deb.sh --with-lua-cjson (domy\u015blnie ON)',
        'optimizer': '\u2713 Automatyczny — CSS minify, HTML lazy-img, charset',
        'tls':       on ? '\u2713 Certyfikat za\u0142adowany — konfiguracja w nas-web.conf'
                        : '\u2699 Dodaj ssl_cert i ssl_key w nas-web.conf',
        'h2':        on ? '\u2713 HTTP/2 aktywny — brak dodatkowej konfiguracji'
                        : '\u2699 apt install libnghttp2-dev, nast\u0119pnie przebuduj',
      };
      const info = buildInfo[m.id] || (on ? '\u2713 Aktywny' : '\u2699 Wymaga przebudowania');
      btn = `<span style="font-size:9px;color:var(--dim);display:block;margin-top:auto;line-height:1.6">${info}</span>`;
    }
    return `<div style="background:var(--bg3);border:1px solid ${border};border-radius:8px;
                padding:14px;display:flex;flex-direction:column;gap:6px;
                transition:border-color .2s;min-height:140px">
      <div style="display:flex;align-items:flex-start;gap:8px">
        <span style="font-size:24px;line-height:1.1;flex-shrink:0">${icon}</span>
        <div style="flex:1;min-width:0">
          <div style="font-weight:700;color:var(--bright);font-size:12px">${m.name}</div>
          <div style="font-size:10px;color:var(--dim)">v${m.version||'?'}</div>
        </div>
        ${badge}
      </div>
      <div style="font-size:11px;color:var(--dim);line-height:1.5;flex:1">${m.note||''}</div>
      ${btn}
    </div>`;
  }).join('');
}


async function refreshAcme(){
  const acme = await api('/np_acme');
  if(!acme) return;
  const set = (id,v) => { const el=document.getElementById(id); if(el)el.textContent=v; };
  const badge = document.getElementById('acme-badge');
  const on = acme.enabled;
  let clr='dim', label='Wyłączone';
  if(on && acme.running){ clr='orange'; label='W toku…'; }
  else if(on && acme.needs_renewal){ clr='orange'; label='Wymaga odnowienia'; }
  else if(on){ clr='green'; label='OK'; }
  if(badge){ badge.className='badge '+clr; badge.textContent=label; }
  set('acme-enabled', on ? 'Tak' : 'Nie');
  set('acme-mode',    on ? (acme.staging?'⚠ Staging':'✓ Produkcja') : '—');
  set('acme-domains', on ? (acme.domains||[]).join(', ')||'—' : '—');
  set('acme-renew',   on ? (acme.needs_renewal?'Potrzebne':'OK (>30 dni)') : '—');
  if(acme.last_ok)    set('acme-last-ok',    '✓ '+acme.last_ok);
  const errRow = document.getElementById('acme-error-row');
  const errEl  = document.getElementById('acme-last-error');
  if(acme.last_error && acme.last_error.length > 0){
    if(errRow) errRow.style.display = '';
    if(errEl)  errEl.textContent = acme.last_error;
  } else {
    if(errRow) errRow.style.display = 'none';
  }
  // Progress bar
  const pbWrap=document.getElementById('acme-progress-wrap');
  const pbBar =document.getElementById('acme-progress-bar');
  const pbStep=document.getElementById('acme-progress-step');
  const pbPct =document.getElementById('acme-progress-pct');
  if(pbWrap){
    pbWrap.style.display = acme.running ? '' : 'none';
    if(acme.running){
      if(pbBar)  pbBar.style.width=(acme.pct||0)+'%';
      if(pbStep) pbStep.textContent=acme.step||'…';
      if(pbPct)  pbPct.textContent=(acme.pct||0)+'%';
      if(!window._acmePoll) window._acmePoll=setInterval(refreshAcme,2000);
    } else {
      if(window._acmePoll){ clearInterval(window._acmePoll); window._acmePoll=null; }
    }
  }
}

async function acmeObtain(){
  const r = await api('/np_acme',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"action":"obtain"}'});
  if(r===null){ toast('Błąd ACME — sprawdź logi'); return; }
  toast('✓ Żądanie certyfikatu uruchomione — czekam na postęp…');
  if(!window._acmePoll) window._acmePoll=setInterval(refreshAcme,2000);
  setTimeout(refreshAcme, 500);
}


// ── Dashboard Charts ──────────────────────────────────────────────────────────
let _dashTimer = null;
let _dashData  = [];

function drawChart(canvasId, data, color, fillColor, unit='') {
  const canvas = document.getElementById(canvasId);
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  // Wymiary: najpierw sprawdź offsetWidth (gdy section już visible),
  // fallback do parentElement, fallback do stałej
  const W = Math.max(
    canvas.offsetWidth ||
    canvas.parentElement?.offsetWidth ||
    canvas.getBoundingClientRect().width || 400, 80);
  const H = Math.max(canvas.offsetHeight || 120, 60);
  if(canvas.width !== Math.round(W*dpr) || canvas.height !== Math.round(H*dpr)){
    canvas.width  = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  if(!data || data.length < 2) {
    ctx.fillStyle = 'var(--dim)';
    ctx.font = '11px monospace';
    ctx.fillText('Brak danych...', 20, H/2);
    return;
  }

  const maxVal = Math.max(...data, 1);
  const pad = { t:8, r:8, b:20, l:36 };
  const cw = W - pad.l - pad.r;
  const ch = H - pad.t - pad.b;

  // Grid lines
  ctx.strokeStyle = 'rgba(255,255,255,.05)';
  ctx.lineWidth = 1;
  for(let i=0; i<=4; i++){
    const y = pad.t + ch - (ch/4)*i;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W-pad.r, y); ctx.stroke();
    ctx.fillStyle = 'rgba(255,255,255,.3)';
    ctx.font = '9px monospace';
    ctx.fillText(Math.round(maxVal/4*i)+unit, 2, y+3);
  }

  // Fill area
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = pad.l + (i/(data.length-1))*cw;
    const y = pad.t + ch - (v/maxVal)*ch;
    i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
  });
  ctx.lineTo(pad.l + cw, pad.t + ch);
  ctx.lineTo(pad.l,       pad.t + ch);
  ctx.closePath();
  ctx.fillStyle = fillColor;
  ctx.fill();

  // Line
  ctx.beginPath();
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  data.forEach((v, i) => {
    const x = pad.l + (i/(data.length-1))*cw;
    const y = pad.t + ch - (v/maxVal)*ch;
    i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
  });
  ctx.stroke();
}

async function loadDashboard(count=120) {
  const d = await api(`/np_stats?count=${count}`);
  if(!d || !Array.isArray(d) || d.length === 0) {
    // No history yet — show current single point from /np_status
    const s = await api('/np_status');
    if(s) {
      const now = Math.floor(Date.now()/1000);
      const seed = {ts:now, rps:s.req_per_sec||0, eps:0, cache:s.cache_hits||0, conns:0, lat:0};
      _dashData = [seed];
      const set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
      set('dash-rps-now', (s.req_per_sec||0)+' req/s');
      set('dash-lat-now', '—');
      set('dash-err-now', '—');
      set('dash-conn-now', '—');
      ['dash-chart-rps','dash-chart-lat','dash-chart-err','dash-chart-conn'].forEach(id=>{
        const c=document.getElementById(id); if(!c)return;
        const ctx=c.getContext('2d');
        ctx.fillStyle='rgba(255,255,255,.1)'; ctx.font='11px monospace';
        ctx.fillText('Zbieranie danych… (1 próbka/s)', 20, (c.offsetHeight||60)/2);
      });
    }
    return;
  }
  _dashData = d;

  const rps  = d.map(s=>s.rps);
  const lat  = d.map(s=>s.lat);
  const err  = d.map(s=>s.eps);
  const conn = d.map(s=>s.conns);

  drawChart('dash-chart-rps',  rps,  '#00d4aa', 'rgba(0,212,170,.12)', '');
  drawChart('dash-chart-lat',  lat,  '#0088ff', 'rgba(0,136,255,.12)', 'ms');
  drawChart('dash-chart-err',  err,  '#ff3355', 'rgba(255,51,85,.12)',  '');
  drawChart('dash-chart-conn', conn, '#ff6b35', 'rgba(255,107,53,.12)', '');

  const last = d[d.length-1];
  if(last) {
    const set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
    set('dash-rps-now',  last.rps+' req/s');
    set('dash-lat-now',  last.lat+'ms');
    set('dash-err-now',  last.eps+' err/s');
    set('dash-conn-now', last.conns+' conns');
  }
}

// ── Audit Log ─────────────────────────────────────────────────────────────────
async function loadAudit() {
  const data = await api('/np_audit');
  if(!data || !Array.isArray(data)) return;
  const box = document.getElementById('audit-log');
  const cnt = document.getElementById('audit-count');
  if(cnt) cnt.textContent = data.length+' wpisów';
  if(!box) return;

  const ACTION_ICON = {
    config_save:    '💾', toggle_module: '🔧', upstream_add: '➕',
    upstream_remove:'➖', blacklist_add: '🚫', reload: '🔄',
    acme_obtain:    '🔐', default:       '📝'
  };
  const ACTION_CLR = {
    config_save: 'var(--accent)', toggle_module: '#ff6b35',
    blacklist_add: '#ff3355', reload: '#0088ff',
    upstream_add: '#00d4aa', acme_obtain: '#f0c040'
  };

  box.innerHTML = data.map(e => {
    const ico = ACTION_ICON[e.action] || ACTION_ICON.default;
    const clr = ACTION_CLR[e.action] || 'var(--dim)';
    return `<div class="log-entry audit-row" data-action="${e.action}" data-ip="${e.ip}" data-detail="${(e.detail||'').toLowerCase()}"
      style="display:grid;grid-template-columns:155px 130px 160px minmax(0,1fr);padding:5px 12px;border-bottom:1px solid var(--border)20;align-items:center">
      <span class="log-ts">${e.ts}</span>
      <span style="font-family:monospace;font-size:10px;color:var(--accent2)">${e.ip||'—'}</span>
      <span style="font-size:11px;font-weight:600;color:${clr}">${ico} ${e.action}</span>
      <span style="font-size:11px;color:var(--dim)">${e.detail||'—'}</span>
    </div>`;
  }).join('') || '<div style="padding:16px;color:var(--dim);font-size:11px">Brak zdarzeń</div>';
}

function filterAudit() {
  const search = (document.getElementById('audit-search')?.value||'').toLowerCase();
  document.querySelectorAll('#audit-log .audit-row').forEach(r => {
    const txt = (r.dataset.action + r.dataset.ip + r.dataset.detail).toLowerCase();
    r.style.display = (!search || txt.includes(search)) ? '' : 'none';
  });
}

// ── SQLite Database ──────────────────────────────────────────────────────────
async function loadDb() {
  const data = await api('/np_db');
  if(!data) return;

  // Pokaż/ukryj nav item zależnie od tego czy SQLite jest włączony
  const navDb = document.getElementById('nav-db');
  if(navDb) navDb.style.display = data.enabled ? '' : 'none';
  if(!data.enabled) return;

  // Status grid
  const grid = document.getElementById('db-status-grid');
  if(grid) {
    const fmt = n => n >= 1024*1024 ? (n/1024/1024).toFixed(1)+' MB'
                   : n >= 1024 ? (n/1024).toFixed(1)+' KB' : n+' B';
    grid.innerHTML = [
      ['📁 Plik', `<span style="font-family:monospace;font-size:10px">${data.path||'—'}</span>`],
      ['💾 Rozmiar', fmt(data.size_bytes||0)],
      ['📋 Journal', `<span class="badge green">${data.journal_mode||'wal'}</span>`],
      ['🔍 Integralność', `<span class="badge ${data.integrity==='ok'?'green':'orange'}">${data.integrity||'—'}</span>`],
      ['📄 Page size', (data.page_size||4096)+' B'],
      ['📊 Pages', data.page_count||0],
    ].map(([k,v]) => `
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:12px">
        <div style="font-size:10px;color:var(--dim);margin-bottom:4px">${k}</div>
        <div style="font-size:13px;font-weight:600;color:var(--bright)">${v}</div>
      </div>`).join('');
  }

  // Tabele
  const tbls = document.getElementById('db-tables');
  if(tbls && data.tables) {
    const TABLE_DESC = {
      blacklist:   {icon:'🚫', desc:'Zbanowane adresy IP'},
      ban_events:  {icon:'📋', desc:'Historia zdarzeń banowania'},
      migrations:  {icon:'🔄', desc:'Historia migracji bazy'},
    };
    tbls.innerHTML = Object.entries(data.tables).map(([name, info]) => {
      const d = TABLE_DESC[name] || {icon:'🗃', desc:name};
      return `<div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px">
        <div style="font-size:14px;font-weight:600;color:var(--bright);margin-bottom:4px">${d.icon} ${name}</div>
        <div style="font-size:11px;color:var(--dim);margin-bottom:8px">${d.desc}</div>
        <div style="font-size:24px;font-weight:700;color:var(--accent)">${info.rows}</div>
        <div style="font-size:10px;color:var(--dim)">wierszy</div>
      </div>`;
    }).join('');
  }

  // Backup paths
  const p = data.path || '';
  const pathEl = document.getElementById('db-path-backup');
  const walEl  = document.getElementById('db-wal-path');
  if(pathEl) pathEl.textContent = p;
  if(walEl)  walEl.textContent  = p ? p+'-wal' : '—';
}

async function dbAction(action) {
  const res = document.getElementById('db-action-result');
  if(res) { res.style.display='block'; res.style.background='rgba(0,136,255,.1)'; res.style.border='1px solid rgba(0,136,255,.3)'; res.textContent='Wykonywanie...'; }
  const data = await api('/np_db?action='+action, {method:'POST'});
  if(res && data) {
    const ok = data.result && !data.result.includes('error');
    res.style.background = ok ? 'rgba(0,212,170,.1)' : 'rgba(255,51,85,.1)';
    res.style.border = ok ? '1px solid rgba(0,212,170,.3)' : '1px solid rgba(255,51,85,.3)';
    res.textContent = '✓ ' + (data.result || JSON.stringify(data));
  }
  setTimeout(loadDb, 500);
}

async function dbPruneEvents() {
  if(!confirm('Usunąć zdarzenia banowania starsze niż 30 dni?')) return;
  const data = await api('/np_db?action=prune_events', {method:'POST'});
  const res = document.getElementById('db-action-result');
  if(res && data) {
    res.style.display='block';
    res.style.background='rgba(0,212,170,.1)';
    res.style.border='1px solid rgba(0,212,170,.3)';
    res.textContent = '✓ ' + (data.result || 'Wykonano');
  }
  setTimeout(loadDb, 500);
}

// ── SSE Live Log ──────────────────────────────────────────────────────────────
let _sseSource = null;

function startSSELog() {
  if(_sseSource) return; // already connected
  const box = document.getElementById('server-log');
  if(!box) return;

  const authHdr = btoa((window._adminUser||'admin') + ':' + (window._adminPass||''));
  // EventSource doesn't support custom headers — use fetch with ReadableStream instead
  _sseSource = true; // mark as started
  const ctrl = new AbortController();
  window._sseCtrl = ctrl;

  fetch('/np_logs/stream', {
    headers: { 'Authorization': 'Basic ' + authHdr },
    signal: ctrl.signal
  }).then(async resp => {
    if(!resp.ok || !resp.body){ _sseSource=null; return; }
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    while(true) {
      const {done, value} = await reader.read();
      if(done) break;
      buf += dec.decode(value, {stream:true});
      const lines = buf.split('\n');
      buf = lines.pop();
      for(const line of lines) {
        if(!line.startsWith('data: ')) continue;
        try {
          const raw = line.slice(6);
          // Could be array (snapshot) or single object
          const parsed = JSON.parse(raw);
          const entries = Array.isArray(parsed) ? parsed : [parsed];
          appendSSEEntries(entries);
        } catch(e) {}
      }
    }
    _sseSource = null;
  }).catch(()=>{ _sseSource=null; });
}

function stopSSELog() {
  if(window._sseCtrl){ window._sseCtrl.abort(); window._sseCtrl=null; }
  _sseSource = null;
}

function appendSSEEntries(entries) {
  const box = document.getElementById('server-log');
  if(!box) return;
  const LV_CLS = {error:'lv-error', warn:'lv-warn', info:'lv-info', debug:'lv-debug'};
  const LV_ICO = {error:'✗', warn:'⚠', info:'ℹ', debug:'·'};
  const MOD_CLR = {acme:'#f0c040',tls:'#00d4aa',proxy:'#0088ff',cache:'#ff6b35',
    config:'#aa88ff',ratelimit:'#ff3355',lua:'#88cc44',js:'#ffaa00',
    upstream:'#00ccff',features:'#ff88cc',audit:'#ff9966',server:'#aaaaaa'};

  for(const e of entries) {
    const lv  = e.level||'info';
    const cls = LV_CLS[lv]||'lv-info';
    const ico = LV_ICO[lv]||'·';
    const mod = e.module||'';
    const mclr= MOD_CLR[mod]||'var(--dim)';
    const msg = (e.msg||'').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\n/g,' ').replace(/\r/g,'');
    const row = document.createElement('div');
    row.className='log-entry';
    row.dataset.level=lv; row.dataset.module=mod; row.dataset.msg=msg.toLowerCase();
    row.style.cssText='display:grid;grid-template-columns:155px 60px 80px minmax(0,1fr);padding:3px 12px;border-bottom:1px solid rgba(255,255,255,.03)';
    row.innerHTML=`<span class="log-ts" style="font-size:10px">${e.ts||'—'}</span><span class="log-lv ${cls}">${ico} ${lv.toUpperCase()}</span><span style="font-size:10px;font-weight:600;color:${mclr};font-family:monospace">[${mod}]</span><span class="log-msg" style="font-size:11px">${msg}</span>`;
    // Apply current filter
    const srvFiltersOk = srvFilters[lv] !== false;
    const search = (document.getElementById('srv-search')?.value||'').toLowerCase();
    if(!srvFiltersOk || (search && !mod.toLowerCase().includes(search) && !msg.toLowerCase().includes(search)))
      row.style.display = 'none';
    box.appendChild(row);
    // Cap at 1000 rows
    while(box.children.length > 1000) box.removeChild(box.firstChild);
  }
  box.scrollTop = box.scrollHeight;
  const cnt = document.getElementById('srv-log-count');
  if(cnt) cnt.textContent = box.children.length+' wpisów';
}

// ── ACME Port Checker ─────────────────────────────────────────────────────────
async function checkAcmePort() {
  const btn = document.getElementById('acme-diag-btn');
  const res = document.getElementById('acme-diag-result');
  if(btn) btn.textContent = '⏳ Sprawdzam...';
  if(res) res.style.display = '';
  const d = await api('/np_acme_diag');
  if(btn) btn.textContent = '🔍 Sprawdź port 80';
  if(!d){ if(res) res.innerHTML='<span style="color:var(--warn)">Błąd żądania</span>'; return; }
  const ok = d.ok;
  if(res) res.innerHTML = `<span style="color:${ok?'var(--accent)':'var(--warn)'}">${ok?'✓':'✗'} ${d.domain}: ${d.detail}</span>`;
}

// ── System Info ──────────────────────────────────────────────────────────────
function renderSysInfo(d){
  const mods = d&&d.modules ? d.modules : {};
  const cards=[
    {title:'Server',rows:[
      ['Binary','/usr/local/bin/nas-web'],['Version', (window._nasVersion||'2.2.75')],['Build','C++20 + libuv'],
      ['Config','/etc/nas-web/nas-web.conf'],['PID',d?'running':'—'],['Uptime',d?fmtUp(d.uptime||0):'—'],
    ]},
    {title:'Modules',rows:[
      ['Lua 5.4',   mods.lua    ?'&#10003; enabled':'&#10007; disabled (rebuild)'],
      ['QuickJS',   mods.quickjs?'&#10003; enabled':'&#10007; disabled (fetch_quickjs.sh)'],
      ['nghttp2',   mods.nghttp2?'&#10003; enabled':'&#10007; disabled (rebuild)'],
      ['TLS/SSL',   mods.tls    ?'&#10003; active' :'&#10007; no cert configured'],
      ['Workers',   d?(d.workers||1):'—'],['HTTP/3','disabled'],
    ]},
    {title:'Network',rows:[
      ['Listen','80 (HTTP)' + (mods.tls?' + 443 (HTTPS)':'—')],
      ['Protocol','HTTP/1.1'+(mods.nghttp2?' + HTTP/2':'')],
      ['TLS',mods.tls?'TLS 1.2/1.3':'disabled'],
      ['WebSocket','enabled'],['Max connections','4096'],['Keepalive','65s'],
    ]},
    {title:'Performance',rows:[
      ['Cache size','1024 entries'],['Cache TTL','60s'],['Buffer','64 KB'],
      ['Requests',d?fmt(d.requests||0):'—'],['Cache hits',d?fmt(d.cache_hits||0):'—'],
      ['Errors',d?fmt(d.errors||0):'—'],
    ]},
  ];
  document.getElementById('sysinfo-grid').innerHTML=cards.map(c=>`
    <div class="sysinfo-card">
      <div class="sysinfo-title">${c.title}</div>
      ${c.rows.map(([k,v])=>`<div class="sysinfo-row"><span class="sysinfo-key">${k}</span><span class="sysinfo-val">${v}</span></div>`).join('')}
    </div>`).join('');
}

// ── Connections ──────────────────────────────────────────────────────────────
// Auto-refresh connections tab every 3s when visible
let _connRefreshTimer = null;
function startConnRefresh(){ if(!_connRefreshTimer) _connRefreshTimer = setInterval(()=>{ if(document.getElementById('sec-connections')?.classList.contains('active')) renderConns(); }, 3000); }
function stopConnRefresh(){ clearInterval(_connRefreshTimer); _connRefreshTimer=null; }

async function renderConns(){
  const d = await api('/np_connections');
  const tbody = document.getElementById('conn-table'); if(!tbody) return;
  const allConns = d?.connections || [];
  const conns = allConns.filter(c => c.active || (c.age_ms != null && c.age_ms < 300000));
  const active = conns.filter(c=>c.active);
  const recent = conns.filter(c=>!c.active);
  document.getElementById('conn-count').textContent = active.length + ' live / ' + recent.length + ' recent (5min)';
  if(conns.length===0){
    tbody.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--dim);padding:20px">No connections yet</td></tr>';
  } else {
    const fmtAge = ms => ms < 1000 ? 'now' : ms < 60000 ? (ms/1000).toFixed(1)+'s ago' : Math.round(ms/1000)+'s ago';
    const rows = [];
    if(active.length > 0) {
      rows.push(`<tr><td colspan="6" style="padding:4px 8px;font-size:10px;color:var(--dim);background:var(--bg3);letter-spacing:.05em">LIVE (${active.length})</td></tr>`);
      active.forEach(c=>{
        const tc=c.type==='proxy'?'blue':c.type==='static'?'dim':'green';
        const longConn = c.age_ms > 5000;
        rows.push(`<tr style="border-left:2px solid var(--accent)">
          <td style="color:var(--accent2)">${c.ip}</td>
          <td><span class="badge dim">${c.method||'?'}</span></td>
          <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${c.path}">${c.path}</td>
          <td><span class="badge green" style="font-size:9px">live</span></td>
          <td style="color:${longConn?'var(--warn)':'var(--dim)'};font-size:11px">${fmtAge(c.age_ms)}</td>
          <td><span class="badge ${tc}">${c.type||'?'}</span></td></tr>`);
      });
    }
    if(recent.length > 0) {
      rows.push(`<tr><td colspan="6" style="padding:4px 8px;font-size:10px;color:var(--dim);background:var(--bg3);letter-spacing:.05em">OSTATNIE ${recent.length} (do 5 min)</td></tr>`);
      recent.forEach(c=>{
        const tc=c.type==='proxy'?'blue':c.type==='static'?'dim':'green';
        const sc=c.status>=500?'red':c.status>=400?'orange':c.status>=200?'green':'dim';
        rows.push(`<tr style="opacity:0.7">
          <td style="color:var(--accent2)">${c.ip}</td>
          <td><span class="badge dim">${c.method||'?'}</span></td>
          <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${c.path}">${c.path}</td>
          <td>${c.status?`<span class="badge ${sc}">${c.status}</span>`:'\xe2\x80\x94'}</td>
          <td style="color:var(--dim);font-size:11px">${fmtAge(c.age_ms)}</td>
          <td><span class="badge ${tc}">${c.type||'?'}</span></td></tr>`);
      });
    }
    tbody.innerHTML = rows.join('');
  }
    const ipC={};conns.forEach(c=>ipC[c.ip]=(ipC[c.ip]||0)+1);
  const entries=Object.entries(ipC).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const mx=Math.max(1,...Object.values(ipC));
  const cols=['#00d4aa','#0088ff','#ff6b35','#ff3355'];
  document.getElementById('top-ips').innerHTML=entries.length===0
    ? '<div style="color:var(--dim);padding:8px;font-size:11px">No data yet</div>'
    : entries.map(([ip,n],i)=>`
    <div class="bar-row"><div class="bar-label" style="color:var(--accent2)">${ip}</div>
    <div class="bar-track"><div class="bar-fill" style="width:${n/mx*100}%;background:${cols[i%4]}"></div></div>
    <div class="bar-val">${n}</div></div>`).join('');
}

// ── Workers ──────────────────────────────────────────────────────────────────
async function renderWorkers(d){
  const nw = d ? (d.workers||1) : 1;
  document.getElementById('w-count').textContent = nw+' workers';
  // Fetch real per-worker stats
  const wd = await api('/np_workers');
  const list = wd?.workers || Array.from({length:nw},(_,i)=>({id:i,req:0,err:0,cache_hit:0,lua:false,quickjs:false,tls:false}));
  document.getElementById('worker-grid').innerHTML = list.map(w=>`
    <div class="worker-card">
      <div class="worker-head">
        <span class="worker-id">Worker ${w.id}</span>
        <span class="badge green">running</span>
      </div>
      <div class="worker-stat"><span class="worker-key">Requests</span><span class="worker-val">${fmt(w.req||0)}</span></div>
      <div class="worker-stat"><span class="worker-key">Cache hits</span><span class="worker-val">${fmt(w.cache_hit||0)}</span></div>
      <div class="worker-stat"><span class="worker-key">Errors</span><span class="worker-val">${fmt(w.err||0)}</span></div>
      <div class="worker-stat"><span class="worker-key">JS engine</span>
        <span class="worker-val" style="color:${w.quickjs?'var(--accent)':'var(--warn)'}">
          ${w.quickjs?'QuickJS ES2020':'stub (disabled)'}
        </span></div>
      <div class="worker-stat"><span class="worker-key">Lua engine</span>
        <span class="worker-val" style="color:${w.lua?'var(--accent)':'var(--dim)'}">
          ${w.lua?'lua 5.4':'disabled'}
        </span></div>
      <div class="worker-stat"><span class="worker-key">TLS</span>
        <span class="worker-val" style="color:${w.tls?'var(--accent)':'var(--dim)'}">
          ${w.tls?'active':'off'}
        </span></div>
    </div>`).join('');
}

// ── Config ───────────────────────────────────────────────────────────────────
async function loadSSLStatus(){
  const d = await api('/np_ssl', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'status'})});
  const badge = document.getElementById('ssl-status-badge');
  const tlsEl = document.getElementById('ssl-tls-status');
  const expEl = document.getElementById('ssl-expiry');
  if(d&&d.cert_exists){
    badge.className='badge green'; badge.textContent='active';
    if(tlsEl) tlsEl.textContent='enabled'; if(tlsEl) tlsEl.style.color='var(--accent)';
    if(expEl) expEl.textContent=d.expiry||'unknown';
  } else {
    badge.className='badge dim'; badge.textContent='no cert';
    if(tlsEl){tlsEl.textContent='disabled';tlsEl.style.color='var(--dim)';}
    if(expEl) expEl.textContent='—';
  }
}

async function generateSSL(){
  const cn   = document.getElementById('ssl-cn').value.trim()||'nas-web';
  const days = parseInt(document.getElementById('ssl-days').value)||365;
  const res  = document.getElementById('ssl-gen-result');
  res.style.display='block';res.style.background='rgba(0,136,255,.06)';
  res.style.borderColor='rgba(0,136,255,.2)';res.style.color='var(--accent2)';
  res.textContent='Generating certificate...';
  const d = await api('/np_ssl',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'generate',cn,days})});
  if(d&&d.ok){
    res.style.background='rgba(0,212,170,.06)';res.style.borderColor='rgba(0,212,170,.2)';
    res.style.color='var(--accent)';
    res.innerHTML=`<strong>&#10003; Certificate generated</strong><br>${d.message}`;
    toast('Certificate generated!');
    loadSSLStatus();
  } else {
    res.style.background='rgba(255,51,85,.06)';res.style.borderColor='rgba(255,51,85,.2)';
    res.style.color='var(--red)';
    res.textContent='&#10007; '+(d?.error||'Generation failed');
  }
}

let _blIps=[], _blPage=0;
const BL_PER_PAGE=25;

async function loadBlacklist(){
  const d = await api('/np_blacklist');
  if(!d) return;
  _blIps = d.ips||[];
  _blPage = 0;
  const cnt = document.getElementById('blacklist-count');
  if(cnt) cnt.textContent = _blIps.length+' IPs';
  renderBlacklistPage();
}

function renderBlacklistPage(){
  const tbl = document.getElementById('blacklist-table');
  if(!tbl) return;
  if(_blIps.length===0){
    tbl.innerHTML='<div style="padding:8px 0;color:var(--dim);font-size:12px">No blocked IPs</div>'; return;
  }
  const totalPages = Math.ceil(_blIps.length/BL_PER_PAGE);
  const page = _blIps.slice(_blPage*BL_PER_PAGE, (_blPage+1)*BL_PER_PAGE);
  const rows = page.map(ip=>`<tr>
    <td style="font-family:JetBrains Mono,monospace;font-size:12px">${ip}</td>
    <td><button class="btn" onclick="blacklistRemove('${ip}')" style="font-size:10px;padding:3px 8px;color:var(--red)">Unblock</button></td>
  </tr>`).join('');
  const pagination = totalPages>1 ? `
    <div style="display:flex;align-items:center;gap:6px;padding:10px 0 4px;flex-wrap:wrap">
      <button class="btn" onclick="blGo(0)" ${_blPage===0?'disabled':''} style="font-size:11px;padding:3px 8px">&laquo;</button>
      <button class="btn" onclick="blGo(${_blPage-1})" ${_blPage===0?'disabled':''} style="font-size:11px;padding:3px 8px">&lsaquo; Prev</button>
      <span style="font-size:11px;color:var(--dim);padding:0 4px">Strona ${_blPage+1} / ${totalPages} &nbsp;(${_blIps.length} IP)</span>
      <button class="btn" onclick="blGo(${_blPage+1})" ${_blPage>=totalPages-1?'disabled':''} style="font-size:11px;padding:3px 8px">Next &rsaquo;</button>
      <button class="btn" onclick="blGo(${totalPages-1})" ${_blPage>=totalPages-1?'disabled':''} style="font-size:11px;padding:3px 8px">&raquo;</button>
    </div>` : '';
  tbl.innerHTML=`<table class="conn-table" style="width:100%">
    <thead><tr><th>IP Address</th><th style="width:80px">Action</th></tr></thead>
    <tbody>${rows}</tbody></table>${pagination}`;
}

function blGo(p){
  const totalPages=Math.ceil(_blIps.length/BL_PER_PAGE);
  _blPage=Math.max(0,Math.min(p,totalPages-1));
  renderBlacklistPage();
}
async function blacklistAdd(){
  const ip = document.getElementById('blacklist-ip').value.trim();
  if(!ip){ toast('Enter an IP address'); return; }
  await api('/np_blacklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'add',ip})});
  document.getElementById('blacklist-ip').value='';
  toast('IP blocked: '+ip); loadBlacklist();
}
async function blacklistRemove(ip){
  await api('/np_blacklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'remove',ip})});
  toast('IP unblocked: '+ip); loadBlacklist();
}
async function saveConnLimit(){
  const n = parseInt(document.getElementById('connlimit-val').value)||0;
  const d = await api('/np_settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({max_conns_per_ip:n})});
  const el = document.getElementById('connlimit-result');
  const badge = document.getElementById('connlimit-badge');
  if(d){
    if(el) el.textContent='Saved ✓';
    if(badge){ badge.textContent=n>0?`max ${n}/IP`:'disabled'; badge.className='badge '+(n>0?'green':'dim'); }
    toast('Connection limit updated');
    setTimeout(()=>{ if(el)el.textContent=''; },3000);
  }
}
async function loadSettings(){
  const d = await api('/np_settings');
  if(!d) return;
  const v = document.getElementById('connlimit-val');
  const badge = document.getElementById('connlimit-badge');
  if(v) v.value = d.max_conns_per_ip||0;
  if(badge){ const n=d.max_conns_per_ip||0; badge.textContent=n>0?`max ${n}/IP`:'disabled'; badge.className='badge '+(n>0?'green':'dim'); }
}

// Upstreams
let upstreamFormVisible = false;
function showAddUpstream(){
  upstreamFormVisible=!upstreamFormVisible;
  document.getElementById('upstream-add-form').style.display=upstreamFormVisible?'block':'none';
}
async function loadUpstreams(){
  const d = await api('/np_upstream');
  const container = document.getElementById('upstream-pool-table');
  if(!container) return;
  if(!d || !d.upstreams || d.upstreams.length===0){
    container.innerHTML='<tr><td colspan="5" style="padding:16px;color:var(--dim);text-align:center">No upstreams configured</td></tr>';
    return;
  }
  container.innerHTML = d.upstreams.map(u=>`<tr>
    <td style="font-weight:600;color:var(--bright)">${u.name}</td>
    <td style="font-family:monospace;font-size:11px">${u.address}</td>
    <td><span class="badge ${u.source==='config'?'dim':'blue'}">${u.source||'config'}</span></td>
    <td><span class="badge ${u.enabled!==false?'green':'orange'}">${u.enabled!==false?'active':'disabled'}</span></td>
    <td>${u.source==='live'?`
      <button class="btn" onclick="toggleUpstream('${u.name}')" style="font-size:10px;padding:3px 8px">${u.enabled?'Disable':'Enable'}</button>
      <button class="btn" onclick="removeUpstream('${u.name}')" style="font-size:10px;padding:3px 8px;color:var(--red);margin-left:4px">Remove</button>
    `:'<span style="color:var(--dim);font-size:10px">edit config</span>'}</td>
  </tr>`).join('');
}
async function addUpstream(){
  const name=document.getElementById('up-name').value.trim();
  const address=document.getElementById('up-addr').value.trim();
  if(!name||!address){ toast('Fill in name and address'); return; }
  await api('/np_upstream',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'add',name,address})});
  document.getElementById('up-name').value=''; document.getElementById('up-addr').value='';
  showAddUpstream(); toast('Upstream added: '+name); loadUpstreams();
}
async function removeUpstream(name){
  await api('/np_upstream',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'remove',name})});
  toast('Upstream removed: '+name); loadUpstreams();
}
async function toggleUpstream(name){
  await api('/np_upstream',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'toggle',name})});
  loadUpstreams();
}

async function loadConfig(){
  const area = document.getElementById('config-area');
  if(!area) return;
  area.value = '# Loading...';
  const d = await api('/np_config');
  if(d && d.content) {
    area.value = d.content;
    const hint = document.getElementById('config-path-hint');
    if(hint) hint.textContent = d.path || '/etc/nas-web/nas-web.conf';
  } else {
    area.value = '# Failed to load config file.\n# Edit /etc/nas-web/nas-web.conf directly.';
  }
}


function reloadConfig(){api('/np_reload',{method:'POST'}).then(()=>toast('Config reloaded')).catch(()=>toast('Reload sent'))}
async function saveConfig(){
  const area = document.getElementById('config-area');
  if(!area) return;
  const content = area.value;
  const r = await api('/np_config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content})});
  if(r !== null) {
    const hint = document.getElementById('cfg-saved');
    if(hint){hint.style.display='inline';setTimeout(()=>hint.style.display='none',3000);}
    toast('Config saved & reload triggered');
  } else {
    toast('Save failed — check permissions');
  }
}
function restartSrv(){if(confirm('Restart all workers? Connections will be dropped.'))api('/np_restart',{method:'POST'}).then(()=>toast('Workers restarting...')).catch(()=>{})}

// ── Main ─────────────────────────────────────────────────────────────────────
function animateRefresh(ms){
  const b=document.getElementById('refresh-bar');if(!b)return;
  b.style.transition='none';b.style.width='0%';
  setTimeout(()=>{b.style.transition='width '+ms+'ms linear';b.style.width='100%';},50);
}


async function updateWafHeaderBadges(){
  const secBadge = document.getElementById('hdr-secured-badge');
  if(!secBadge) return;
  let anyBlock = false;
  try {
    const r = await api('/np_waf_regex');
    if(r && r.compiled && r.enabled && r.block_mode) anyBlock = true;
  } catch(e){}
  try {
    const m = await api('/np_waf');
    if(m && m.loaded && m.enabled && m.block_mode) anyBlock = true;
  } catch(e){}
  secBadge.style.display = anyBlock ? 'flex' : 'none';
}

async function fetchAll(){
  const d=await api('/np_status');
  if(!d){document.getElementById('hdr-status').textContent='error';return;}
  // Aktualizuj wersję w headerze
  if(d.version){
    window._nasVersion = d.version;
    const verEl = document.getElementById('hdr-version');
    if(verEl) verEl.textContent = 'v' + d.version;
  }
  const now=Date.now();
  // rps — use server-provided value (aggregated across all workers)
  const rps = d.req_per_sec || 0;
  prevReq=d.requests;prevTime=now;
  RPS.push(rps);if(RPS.length>60)RPS.shift();
  const $=(id)=>document.getElementById(id);
  const set=(id,v)=>{const e=$(id);if(e)e.textContent=v;};
  if($('chart-rps'))$('chart-rps').textContent=rps+' req/s';
  drawRpsChart();
  set('s-req',fmt(d.requests)); set('s-rps',rps+' req/s');
  set('s-cache',fmt(d.cache_hits||0)); set('s-err',fmt(d.errors||0));
  set('s-uptime',fmtUp(d.uptime||0)); set('s-workers',(d.workers||1)+' workers');
  set('s-ram', ((d.rss_kb||0)/1024).toFixed(1)+' MB');
  set('s-cpu', Math.round((d.cpu_ms||0)/1000)+'s CPU');
  const tot=d.requests||1,cP=Math.round((d.cache_hits||0)/tot*100),eP=Math.round((d.errors||0)/tot*100);
  set('s-cache-pct',cP+'% hit rate'); set('s-err-pct',eP+'% error rate');
  gauge('g-cache',cP,'g-cache-txt');gauge('g-err',eP,'g-err-txt');
  gauge('g-ok',Math.max(0,100-eP),'g-ok-txt');
  gauge('g-w',Math.min(100,(d.workers||1)/4*100),'g-w-txt',d.workers||1);
  renderWorkers(d);renderConns();renderSysInfo(d);
  // Cache tab: odśwież tylko gdy aktywna (cache ma własny 1s timer)
  if(document.getElementById('sec-cache')?.classList.contains('active')) renderCache();
  // upstream
  const setEl=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
  setEl('up-req',fmt(d.requests||0));
  setEl('up-err',fmt(d.errors||0));
  setEl('up-lat','<1ms');
  addAccessLog();
  updateWafHeaderBadges();
  // Update WAF cards — zawsze (widoczne w Overview i Dashboard)
  updateWafDashboard();
}

function init(){
  // Apply theme button icon
  const btn = document.getElementById('theme-toggle');
  if(btn) btn.textContent = document.documentElement.classList.contains('light') ? '☽' : '☀';
  loadConfig();renderModules();renderSysInfo(null);loadSSLStatus();
  loadBlacklist();loadSettings();loadUpstreams();
  fetchAll();animateRefresh(3000);
  updateWafHeaderBadges();
  // Overview auto-refresh: only when overview tab active
  refreshTimer=setInterval(()=>{
    fetchAll();  // zawsze — zapewnia RPS array i WAF stats
    const ov=document.getElementById('sec-overview');
    if(ov&&ov.classList.contains('active')) animateRefresh(5000);
  },5000);
  // Logs auto-refresh: only when logs tab active  
  setInterval(()=>{
    const lv=document.getElementById('sec-logs');
    if(lv&&lv.classList.contains('active')){addAccessLog();}
  }, 6000);
  setInterval(()=>{
    const lv=document.getElementById('sec-logs');
    if(lv&&lv.classList.contains('active')){fetchServerLogs();}
  }, 6000);
}
</script>


</body>
</html>

)HTMLEOF";
