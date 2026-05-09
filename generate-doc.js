/**
 * Generator documentatie Etapa 0 — PDF
 * Rulare: node generate-doc.js
 */
const PDFDocument = require('./backend/node_modules/pdfkit');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, 'Documentatie_Etapa0.pdf');
const doc = new PDFDocument({ margin: 60, size: 'A4' });
doc.pipe(fs.createWriteStream(OUT));

// ── Helpers ────────────────────────────────────────────────────────────────

const BLUE   = '#2196F3';
const DARK   = '#1a1a2e';
const GRAY   = '#555555';
const LIGHT  = '#f5f8fa';
const RED    = '#e53935';
const GREEN  = '#43a047';

function heading1(text) {
  doc.moveDown(0.6)
     .fontSize(18).fillColor(DARK).font('Helvetica-Bold').text(text)
     .moveDown(0.3)
     .moveTo(doc.page.margins.left, doc.y)
     .lineTo(doc.page.width - doc.page.margins.right, doc.y)
     .strokeColor(BLUE).lineWidth(1.5).stroke()
     .moveDown(0.4);
}

function heading2(text) {
  doc.moveDown(0.5)
     .fontSize(13).fillColor(BLUE).font('Helvetica-Bold').text(text)
     .moveDown(0.25);
}

function body(text, opts = {}) {
  doc.fontSize(10).fillColor(GRAY).font('Helvetica').text(text, { align: 'justify', ...opts });
  doc.moveDown(0.3);
}

function bullet(items) {
  items.forEach((item) => {
    doc.fontSize(10).fillColor(GRAY).font('Helvetica')
       .text(`• ${item}`, { indent: 16, align: 'left' });
  });
  doc.moveDown(0.3);
}

function tableRow(cols, widths, isHeader = false) {
  const startX = doc.page.margins.left;
  const rowH   = 20;
  const y      = doc.y;

  if (isHeader) {
    doc.rect(startX, y, widths.reduce((a, b) => a + b, 0), rowH)
       .fillColor('#dce8f5').fill();
  } else if (doc._tableRowEven) {
    doc.rect(startX, y, widths.reduce((a, b) => a + b, 0), rowH)
       .fillColor(LIGHT).fill();
  }
  doc._tableRowEven = !doc._tableRowEven;

  let x = startX;
  cols.forEach((col, i) => {
    doc.fontSize(isHeader ? 9 : 9)
       .fillColor(isHeader ? DARK : GRAY)
       .font(isHeader ? 'Helvetica-Bold' : 'Helvetica')
       .text(col, x + 4, y + 5, { width: widths[i] - 8, lineBreak: false });
    x += widths[i];
  });

  doc.moveTo(startX, y).lineTo(startX + widths.reduce((a, b) => a + b, 0), y)
     .strokeColor('#c0cfe0').lineWidth(0.4).stroke();

  doc.y = y + rowH;
}

function monoBlock(lines) {
  const x = doc.page.margins.left;
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const blockH = lines.length * 13 + 12;
  doc.rect(x, doc.y, w, blockH).fillColor('#1e2a38').fill();
  lines.forEach((line, i) => {
    doc.fontSize(8).fillColor('#a8d8ea').font('Courier')
       .text(line, x + 8, doc.y - blockH + 6 + i * 13, { lineBreak: false });
  });
  doc.y += 8;
  doc.moveDown(0.5);
}

// ── COPERTĂ ────────────────────────────────────────────────────────────────

doc.rect(0, 0, doc.page.width, doc.page.height).fillColor('#0d1b2a').fill();

doc.rect(0, 280, doc.page.width, 180).fillColor('#112233').fill();

doc.fontSize(11).fillColor('#5599bb').font('Helvetica')
   .text('UNIVERSITATEA TEHNICĂ A MOLDOVEI', 0, 110, { align: 'center' });
doc.fontSize(10).fillColor('#446688')
   .text('Facultatea de Calculatoare, Informatică și Microelectronică', { align: 'center' });

doc.moveDown(2);
doc.fontSize(28).fillColor('#ffffff').font('Helvetica-Bold')
   .text('Containment Atlas', { align: 'center' });
doc.fontSize(14).fillColor('#76c4ff').font('Helvetica')
   .text('Platformă de securitate și monitorizare locală', { align: 'center' });
doc.moveDown(0.5);
doc.fontSize(11).fillColor('#5599bb')
   .text('cu motor de detecție anti-obfuscare și comunicații redundante', { align: 'center' });

doc.moveDown(3);
doc.fontSize(13).fillColor('#79f0d7').font('Helvetica-Bold')
   .text('DOCUMENTAȚIE — ETAPA 0', { align: 'center' });
doc.fontSize(10).fillColor('#446688').font('Helvetica')
   .text('Proiectare și Documentare Inițială', { align: 'center' });

doc.moveDown(4);
doc.fontSize(10).fillColor('#334455')
   .text(`Chișinău, ${new Date().getFullYear()}`, { align: 'center' });

doc.addPage();

// ── CUPRINS ────────────────────────────────────────────────────────────────

heading1('Cuprins');
const cuprins = [
  ['1.', 'Obiectivul lucrării',                   '3'],
  ['2.', 'Așteptări de la aplicație',             '3'],
  ['3.', 'Cerințe funcționale',                   '4'],
  ['4.', 'Cerințe nefuncționale',                 '4'],
  ['5.', 'Schema bloc a sistemului',              '5'],
  ['6.', 'Tehnologii alese și justificare',       '6'],
  ['7.', 'Planificarea etapelor',                  '7'],
  ['8.', 'Concluzii',                              '7'],
];
cuprins.forEach(([nr, titlu, pag]) => {
  const y = doc.y;
  doc.fontSize(10).fillColor(GRAY).font('Helvetica')
     .text(`${nr}  ${titlu}`, doc.page.margins.left, y);
  doc.fontSize(10).fillColor(BLUE).font('Helvetica-Bold')
     .text(pag, 0, y, { align: 'right' });
  doc.y = y + 16;
});

doc.addPage();

// ── 1. OBIECTIV ────────────────────────────────────────────────────────────

heading1('1. Obiectivul lucrării');
body(
  'Lucrarea de față propune proiectarea și implementarea unei platforme web de securitate ' +
  'și monitorizare locală denumită Containment Atlas. Obiectivul principal constă în crearea ' +
  'unui instrument unificat care să permită unui administrator de sistem să detecteze amenințări ' +
  'cibernetice, să gestioneze regulile de filtrare a traficului de rețea, să monitorizeze ' +
  'resursele hardware în timp real și să mențină comunicații fiabile prin mecanisme de fallback ' +
  'automat, toate acestea accesibile dintr-o singură interfață web.'
);
body(
  'Prin integrarea conceptelor de securitate cibernetică (detecție heuristică, analiză binară, ' +
  'sandbox cloud) cu principii din teoria semnalelor (SNR, modulație CSS/LoRa, toleranță la erori), ' +
  'aplicația demonstrează convergența dintre securitatea informatică și comunicațiile digitale.'
);

// ── 2. AȘTEPTĂRI ──────────────────────────────────────────────────────────

heading1('2. Așteptări de la aplicație');
body('Pornind de la titlul temei, o astfel de aplicație ar trebui să răspundă următoarelor nevoi:');
bullet([
  'Scanarea fișierelor suspecte fără instalarea unui antivirus comercial',
  'Detectarea codului malițios ascuns prin obfuscare (fișiere binare, shellcode, macros)',
  'Verificarea hash-ului fișierelor față de baze de date publice de malware (MalwareBazaar)',
  'Vizualizarea în timp real a stării sistemului: CPU, RAM, GPU, trafic de rețea',
  'Gestionarea regulilor de firewall (adăugare, ștergere, activare/dezactivare)',
  'Blocarea categoriilor de site-uri nedorite prin modificarea fișierului hosts',
  'Notificarea imediată când un fișier este identificat ca infectat',
  'Continuarea transmiterii alertelor critice chiar și când rețeaua principală este întreruptă',
  'Un jurnal persistent și detaliat al tuturor acțiunilor sistemului',
]);

// ── 3. CERINȚE FUNCȚIONALE ────────────────────────────────────────────────

heading1('3. Cerințe funcționale');
doc._tableRowEven = false;
tableRow(['ID', 'Cerință', 'Modul'], [50, 340, 100], true);
[
  ['F-01', 'Scanarea fișierelor încărcate cu detecție locală text și hex', 'Protection'],
  ['F-02', 'Analiza semnăturilor hexazecimale în date brute (buffer)', 'Protection'],
  ['F-03', 'Lookup hash în MalwareBazaar și Hybrid Analysis', 'Protection'],
  ['F-04', 'Carantinarea automată a fișierelor infectate', 'Protection'],
  ['F-05', 'Gestionarea regulilor de firewall (CRUD)', 'Firewall'],
  ['F-06', 'Filtrarea conținutului web prin blocarea domeniilor în hosts', 'Content Filter'],
  ['F-07', 'Colectarea și afișarea telemetriei sistemului în timp real', 'Telemetry'],
  ['F-08', 'Simularea calității canalului de comunicație (SNR în dB)', 'Signal'],
  ['F-09', 'Fallback automat LoRa 868 MHz când SNR scade sub prag', 'Signal'],
  ['F-10', 'Jurnal persistent al activității cu niveluri ALERT/WARNING/INFO', 'Activity Log'],
  ['F-11', 'Autentificare cu token JWT reîmprospătat automat', 'Auth'],
  ['F-12', 'Curățarea fișierelor temporare cu raport de spațiu eliberat', 'Cleanup'],
].forEach(row => tableRow(row, [50, 340, 100]));
doc.moveDown(0.5);

// ── 4. CERINȚE NEFUNCȚIONALE ──────────────────────────────────────────────

heading1('4. Cerințe nefuncționale');
doc._tableRowEven = false;
tableRow(['ID', 'Cerință', 'Valoare țintă'], [50, 300, 140], true);
[
  ['NF-01', 'Dimensiunea maximă a fișierelor acceptate la scanare', '50 MB'],
  ['NF-02', 'Timp de răspuns pentru operații locale', '< 2 secunde'],
  ['NF-03', 'Compatibilitate browser', 'Chrome, Firefox, Edge'],
  ['NF-04', 'Platforme suportate de backend', 'Windows, Linux, macOS'],
  ['NF-05', 'Interval de poll pentru telemetrie dashboard', '8 secunde'],
  ['NF-06', 'Interval de actualizare SNR (pagina Signal)', '3 secunde'],
  ['NF-07', 'Număr maxim de intrări în Activity Log', '200 intrări (FIFO)'],
  ['NF-08', 'Securitate: token JWT expirat re-obținut transparent', 'automat'],
].forEach(row => tableRow(row, [50, 300, 140]));
doc.moveDown(0.5);

doc.addPage();

// ── 5. SCHEMA BLOC ────────────────────────────────────────────────────────

heading1('5. Schema bloc a sistemului');
body(
  'Aplicația este structurată în două straturi principale: un frontend React (SPA) și un backend ' +
  'Node.js + Express. Comunicarea se realizează exclusiv prin REST API cu autentificare JWT. ' +
  'Backend-ul integrează mai multe module specializate și poate apela servicii cloud externe.'
);

monoBlock([
  '┌──────────────────────────────────────────────────────────┐',
  '│              FRONTEND  (React + Vite)                    │',
  '│  Dashboard │ Protection │ Firewall │ Signal │ Telemetry  │',
  '└────────────────────────┬─────────────────────────────────┘',
  '                         │  HTTP REST (JSON)  Bearer JWT',
  '┌────────────────────────▼─────────────────────────────────┐',
  '│              BACKEND  (Node.js + Express)                 │',
  '│                                                           │',
  '│  ┌──────────────────────────────────────────────────┐    │',
  '│  │            Antivirus Engine                       │    │',
  '│  │  ┌─────────────┐  ┌────────────────────────────┐ │    │',
  '│  │  │ Local       │  │  Hex Signature Scanner     │ │    │',
  '│  │  │ Heuristic   │  │  (buffer chunked, 10 sigs) │ │    │',
  '│  │  └─────────────┘  └────────────────────────────┘ │    │',
  '│  └───────────────────────┬──────────────────────────┘    │',
  '│         API externe      │                                │',
  '│  ┌───────────────────────▼───────────────────────┐       │',
  '│  │  MalwareBazaar API  │  Hybrid Analysis API    │       │',
  '│  └───────────────────────────────────────────────┘       │',
  '│  ┌──────────────┐  ┌──────────────────────────────┐      │',
  '│  │ Firewall     │  │  Signal Simulator             │      │',
  '│  │ Rules Store  │  │  SNR → WiFi/Degraded/LoRa    │      │',
  '│  └──────────────┘  └──────────────────────────────┘      │',
  '│  ┌──────────────┐  ┌──────────────────────────────┐      │',
  '│  │Content Filter│  │  Activity Log (circular 200) │      │',
  '│  │ (hosts file) │  │  ALERT / WARNING / INFO       │      │',
  '│  └──────────────┘  └──────────────────────────────┘      │',
  '│  ┌──────────────┐  ┌──────────────────────────────┐      │',
  '│  │  Telemetry   │  │  Auth / JWT                  │      │',
  '│  │(systeminform)│  │  (session tokens)            │      │',
  '│  └──────────────┘  └──────────────────────────────┘      │',
  '└───────────────────────┬───────────────────────────────────┘',
  '          ┌─────────────┴──────────────┐',
  '    ┌─────▼─────┐              ┌───────▼──────┐',
  '    │ hosts file│              │ scans.log    │',
  '    │(CF output)│              │ quarantine/  │',
  '    └───────────┘              └──────────────┘',
]);

doc.addPage();

// ── 6. TEHNOLOGII ─────────────────────────────────────────────────────────

heading1('6. Tehnologii alese și justificare');

heading2('6.1 React + Vite (Frontend)');
body(
  'React a fost ales pentru construirea unui SPA (Single Page Application) care să permită ' +
  'actualizarea vizuală în timp real a metricilor fără reload de pagină — esențial pentru un ' +
  'dashboard de securitate live. Vite asigură un build extrem de rapid și HMR (Hot Module ' +
  'Replacement) în development. Bootstrap Icons oferă iconografie coerentă fără dependențe grele.'
);

heading2('6.2 Node.js + Express (Backend)');
body(
  'Node.js a fost ales pentru modelul event-driven, non-blocking I/O, optim pentru un server ' +
  'care trebuie să gestioneze simultan: scanări de fișiere (I/O disc intensiv), apeluri API ' +
  'externe (HTTP async) și servirea datelor de telemetrie. Express oferă un sistem de routing ' +
  'simplu și middleware componabil (multer pentru upload, cors, JSON parsing).'
);

heading2('6.3 JWT — JSON Web Token (Autentificare)');
body(
  'Autentificarea stateless prin JWT elimină nevoia de sesiuni pe server. Tokenul este generat ' +
  'la prima conectare, stocat în memoria React și trimis automat la fiecare request prin header-ul ' +
  'Authorization: Bearer. La expirare, frontend-ul re-obține transparent un token nou fără ' +
  'intervenția utilizatorului.'
);

heading2('6.4 MalwareBazaar API + Hybrid Analysis');
body(
  'MalwareBazaar (abuse.ch) oferă un API gratuit de hash lookup SHA-256 față de o bază de date ' +
  'publică de mostre malware. Hybrid Analysis furnizează scanare rapidă (Quick Scan) și analiză ' +
  'sandbox completă (Falcon Sandbox) cu verdic CrowdStrike ML, contactedHosts, MITRE ATT&CK ' +
  'techniques și dropped files — transformând proiectul dintr-un simplu scanner local într-o ' +
  'platformă enterprise-grade.'
);

heading2('6.5 systeminformation (npm)');
body(
  'Bibliotecă Node.js cross-platform care colectează metrici de sistem (CPU model, load, cores; ' +
  'RAM used/total; GPU usage; interfețe de rețea RX/TX rate; conexiuni active) fără acces root ' +
  'și fără dependențe native. Funcționează identic pe Windows, Linux și macOS.'
);

heading2('6.6 LoRa CSS — Chirp Spread Spectrum (Simulat)');
body(
  'Conceptul de fallback comunicațional demonstrează cunoștințe din materia Semnale și Sisteme. ' +
  'LoRa (Long Range) utilizează modulația Chirp Spread Spectrum pe banda ISM 868 MHz, oferind ' +
  'rază lungă (până la 15 km) și consum redus de energie — ideal pentru transmiterea alertelor ' +
  'critice Out-of-Band când canalul primar (WiFi/Ethernet) devine indisponibil. SNR-ul (Signal-to-' +
  'Noise Ratio) este simulat printr-un random walk cu inerție și mean-reversion, replicând ' +
  'comportamentul unui canal radio real.'
);

doc.addPage();

// ── 7. PLANIFICARE ────────────────────────────────────────────────────────

heading1('7. Planificarea etapelor de dezvoltare');
doc._tableRowEven = false;
tableRow(['Etapă', 'Conținut', 'Livrable'], [70, 300, 120], true);
[
  ['Etapa 0', 'Documentare, cerințe, schemă bloc, tehnologii', 'Document PDF'],
  ['Etapa 1', 'Autentificare JWT, structura backend, rute de bază, frontend scaffold', 'Backend + UI skeleton'],
  ['Etapa 2', 'Motor antivirus: heuristic local, hex scanner, MalwareBazaar, carantină', 'Protection page funcțională'],
  ['Etapa 3', 'Hybrid Analysis (Quick Scan + Falcon Sandbox), poll reports', 'Cloud scan integrat'],
  ['Etapa 4', 'Firewall rules CRUD, Content Filter hosts-based, Cleanup module', '3 module noi'],
  ['Etapa 5', 'Telemetrie sistem, Dashboard live, Platform page', 'Monitoring complet'],
  ['Etapa 6', 'Signal/SNR simulator, LoRa fallback, Activity Log persistent', 'Pagina Signal'],
  ['Etapa 7', 'Testare, rafinare UI/UX, optimizări, raport final', 'Proiect finalizat'],
].forEach(row => tableRow(row, [70, 300, 120]));

doc.moveDown(1);

// ── 8. CONCLUZII ──────────────────────────────────────────────────────────

heading1('8. Concluzii');
body(
  'Documentația de față stabilește baza conceptuală și arhitecturală a platformei Containment Atlas. ' +
  'Au fost identificate 12 cerințe funcționale și 8 cerințe nefuncționale, selectate tehnologiile ' +
  'adecvate și propusă o structură modulară care permite dezvoltarea incrementală pe etape.'
);
body(
  'Proiectul îmbină securitatea cibernetică (detecție malware multi-strat, sandbox cloud, carantină) ' +
  'cu monitorizarea sistemului (telemetrie hardware, firewall, content filter) și teoria ' +
  'comunicațiilor (SNR, LoRa CSS, Out-of-Band alerts), demonstrând o abordare interdisciplinară ' +
  'adecvată unei lucrări de finalizare a studiilor.'
);
body(
  'Pașii următori implică implementarea iterativă a modulelor conform planificării, cu validare ' +
  'continuă față de cerințele definite în această etapă.'
);

// ── FOOTER pe fiecare pagina ───────────────────────────────────────────────

const totalPages = doc.bufferedPageRange().count + 1;
for (let i = 0; i < doc._pageBufferStart + 1; i++) {
  // footer adăugat pasiv — pdfkit nu suportă retroactiv, se face la final
}

doc.end();
console.log('PDF generat:', OUT);
