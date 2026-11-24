'use strict';
const $ = id => document.getElementById(id);
const names = ['Normal driving', 'Genuine obstacle', 'Shadow-induced phantom braking',
  'Simulated braking command tampering', 'Event log tampering'];
const last = 11;
const genesis = '0'.repeat(64);
const encoder = new TextEncoder();
const sealedFields = ['simulated', 'timestamp_s', 'event_id', 'speed_kmh', 'road_observation',
  'camera_observation', 'controller_command', 'actuator_command', 'previous_hash'];
const binary = value => encoder.encode(JSON.stringify(value));
const hex = buffer => Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
const unhex = str => Uint8Array.from(str.match(/../g), pair => parseInt(pair, 16));

// Explicit field order is shared by sealing and replay. Tag domains distinguish records and checkpoints.
async function hashRecord(record) {
  const input = sealedFields.map(field => record[field]);
  return hex(await crypto.subtle.digest('SHA-256', binary(input)));
}
async function tag(key, input) {
  return hex(await crypto.subtle.sign('HMAC', key, binary(input)));
}
async function authentic(key, input, mac) {
  return /^[0-9a-f]{64}$/.test(mac) &&
    crypto.subtle.verify('HMAC', key, unhex(mac), binary(input));
}
async function appendRecord(session, t) {
  const previous_hash = session.records.at(-1)?.hash ?? genesis;
  const record = {...session.drive[t], previous_hash};
  record.hash = await hashRecord(record);
  record.hmac_sha256 = await tag(session.key, ['record', record.hash]);
  session.records.push(record);
}
async function checkpoint(session) {
  const count = session.records.length;
  const head = session.records.at(-1).hash;
  return Object.freeze({count, head, mac: await tag(session.key, ['checkpoint', count, head])});
}
async function verify(session) {
  let previous = genesis;
  for (const [index, record] of session.records.entries()) {
    const failure = (stage, reason) => ({ok:false, index:index + 1, stage, reason});
    const keys = Object.keys(record);
    if (keys.length !== sealedFields.length + 2 || !sealedFields.every(field => Object.hasOwn(record, field)))
      return failure(0, 'Record fields differ from the sealed schema.');
    if (await hashRecord(record) !== record.hash)
      return failure(0, 'Recomputed SHA-256 differs from the sealed hash.');
    if (!await authentic(session.key, ['record', record.hash], record.hmac_sha256))
      return failure(1, 'The record HMAC does not authenticate this hash.');
    if (record.previous_hash !== previous)
      return failure(2, 'Previous hash does not match the preceding record.');
    previous = record.hash;
  }
  const cp = session.checkpoint;
  const fail = reason => ({ok:false, index:null, stage:3, reason});
  if (!cp || !await authentic(session.key, ['checkpoint', cp.count, cp.head], cp.mac))
    return fail('The session checkpoint is missing or its HMAC failed.');
  if (cp.count !== session.records.length)
    return fail('Checkpoint expects '+cp.count+' records. Found '+session.records.length+'.');
  if (cp.head !== previous) return fail('Final hash differs from the session checkpoint.');
  return {ok:true, reason:'All 12 hashes, HMACs and links match the authenticated checkpoint.'};
}

// Both drives consume identical noise at every second. Seed affects clear-road brightness only.
function drive(kind, seed) {
  let speed = 60, random = seed >>> 0;
  return Array.from({length:last + 1}, (_, t) => {
    random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
    const window = t >= 4 && t <= 6;
    const obstacle = kind === 1 && window;
    const shadow = kind === 2 && window;
    const brightness = obstacle || shadow ? 65 : 155 + (random % 46);
    const detected = brightness < 100;
    const controller = detected ? 'Brake' : 'Release';
    const actuator = kind === 3 && window ? 'Brake' : controller;
    const reading = {simulated:true, timestamp_s:t, event_id:'EV-'+String(t + 1).padStart(2,'0'),
      speed_kmh:speed, road_observation:obstacle ? 'Cone' : 'Clear',
      camera_observation:{brightness, obstacle_detected:detected},
      controller_command:controller, actuator_command:actuator};
    if (actuator === 'Brake') speed -= 8; // Takes effect at the next sample.
    return reading;
  });
}
function diagnose(records, audit) {
  if (!audit.ok) return ['Evidence integrity failure', 'Physical braking diagnosis withheld. The stored evidence failed verification.'];
  if (records.some(r => r.controller_command !== r.actuator_command))
    return ['Controller-to-actuator command inconsistency', 'The camera correctly saw a clear lane. The controller requested Release while the actuator received Brake. This experiment creates the mismatch deliberately. The evidence alone cannot establish malicious intent.'];
  if (records.some(r => r.road_observation === 'Clear' && r.camera_observation.obstacle_detected && r.actuator_command === 'Brake'))
    return ['Perception algorithm error', 'The lane was clear. A shadow read 65, below the threshold of 100. Both commands agreed on Brake after the false detection.'];
  if (records.some(r => r.road_observation === 'Cone' && r.camera_observation.obstacle_detected && r.actuator_command === 'Brake'))
    return ['Legitimate emergency braking', 'Road truth and camera agreed on a cone. Both commands called for braking.'];
  return ['Normal operation', 'The lane stayed clear, both commands stayed at Release and the vehicle held 60 km/h.'];
}

const parts = [
  ['Sense','Compare road truth with the camera reading and both braking commands.','Samples four channels.','Decide the cause.'],
  ['Record','Capture one sample per second for a twelve-sample drive.','Keeps the pre-command speed.','Change the vehicle.'],
  ['Secure','Chain the hashes, seal each record with HMAC and keep a separate checkpoint.','Detects changed evidence.','Prove sensor accuracy.'],
  ['Analyse','Verify the complete capture before interpreting the observations.','Explains supported findings.','Establish malicious intent.']
];
const icon = id => '<svg class="icon" aria-hidden="true"><use href="#'+id+'"/></svg>';
$('cards').innerHTML = parts.map(([name,desc,yes,no],i) =>
  '<article class="tile"><div class="tilehead">'+icon(name.toLowerCase())+'<span class="num">[ 0'+(i+1)+' ]</span></div><h3>'+name+'</h3><p>'+desc+'</p><dl><div><dt>Does</dt><dd>'+yes+'</dd></div><div><dt>Does not</dt><dd>'+no+'</dd></div></dl></article>').join('');
$('nodes').innerHTML = ['Sensors','Recorder','Hash + HMAC seal','Secure storage','Investigator'].map((name,i) =>
  '<div class="node">'+icon(['sense','record','secure','secure','analyse'][i])+name+'</div>').join('');
const preference = matchMedia('(prefers-reduced-motion: reduce)');
let manual = false;
function motion(value) {
  document.documentElement.classList.toggle('reduced', value);
  $('motion').setAttribute('aria-pressed', String(value));
}
motion(preference.matches);
preference.onchange = e => {if (!manual) motion(e.matches)};
$('motion').onclick = () => {manual = true; motion($('motion').getAttribute('aria-pressed') !== 'true')};

let active, kind = 0, timer;
names.forEach((name,i) => {
  const button = document.createElement('button');
  button.textContent = name;
  button.onclick = () => {kind = i; reset()};
  $('scenarios').append(button);
});
function pause() {
  clearTimeout(timer);
  if (active) active.running = false;
}
function schedule(s) {
  clearTimeout(timer);
  if (s === active && s.running) timer = setTimeout(() => seek(s.t + 1), 1000 / Number($('rate').value));
}
async function reset() {
  pause();
  if (!$('seed').checkValidity()) $('seed').value = '42';
  const seed = Number($('seed').value);
  const s = {kind, seed, drive:drive(kind,seed), normal:drive(0,seed), records:[],
    checkpoint:null, audit:null, running:false, busy:true, t:0, inspected:0, error:''};
  active = s; render(s);
  try {
    s.key = await crypto.subtle.generateKey({name:'HMAC',hash:'SHA-256',length:256}, false, ['sign','verify']);
    await appendRecord(s,0);
  } catch {s.error = 'Session verifier unavailable. Open the page over HTTPS or localhost and reset.'}
  if (s === active) {s.busy = false; render(s)}
}
async function seek(target) {
  const s = active;
  if (s.busy || s.error) return;
  const t = Math.max(0, Math.min(last, target));
  s.busy = true; render(s);
  try {
    // A forward scrub captures skipped seconds in order. Backward replay never overwrites evidence.
    while (s.records.length <= t) await appendRecord(s,s.records.length);
    s.t = t; s.inspected = t;
    if (t === last && !s.checkpoint) {
      s.checkpoint = await checkpoint(s);
      // Edit the stored copy after the final checkpoint. The road model is immutable during replay.
      if (s.kind === 4) s.records[6].speed_kmh = 67;
      s.audit = await verify(s);
    }
    if (t === last && s.audit?.index) s.inspected = s.audit.index - 1;
  } catch {s.error = 'Capture or verification failed. Reset to start a fresh simulated session.'}
  if (active !== s) return;
  s.busy = false;
  if (t === last || s.error) pause();
  render(s); schedule(s);
}
async function recheck() {
  const s = active;
  pause(); s.busy = true; render(s);
  try {
    s.audit = await verify(s);
    if (!s.audit.ok && s.audit.index) s.inspected = s.audit.index - 1;
  } catch {s.audit = {ok:false, stage:3, reason:'Verification could not complete.'}}
  if (s === active) {s.busy = false; render(s)}
}

const channels = [
  ['Road truth',r => r.road_observation],
  ['Camera',r => r.camera_observation.brightness+' · '+(r.camera_observation.obstacle_detected?'Obstacle':'Clear')],
  ['Controller',r => r.controller_command], ['Actuator',r => r.actuator_command]
];
function renderRoad(s,r) {
  const event = s.t >= 4 && s.t <= 6;
  const cone = event && s.kind === 1, shadow = event && s.kind === 2;
  const position = 12 + s.drive.slice(0,s.t).reduce((sum,x) => sum + x.speed_kmh * .78, 0);
  $('car').style.transform = 'translateX('+position+'px)';
  $('hazard').style.transform = 'translateX('+(position + 170 + (6-s.t)*15)+'px)';
  $('cone').style.display = cone ? '' : 'none';
  $('shadow').style.display = shadow ? '' : 'none';
  $('lights').style.display = r.actuator_command === 'Brake' ? '' : 'none';
  const speed = r.speed_kmh+' km/h';
  $('clock').textContent = s.t+' s / 11 s · '+speed;
  $('road-title').textContent = 'Simulated road at '+s.t+' seconds, '+speed+', '+(cone?'cone ahead':shadow?'shadow on clear lane':'clear lane');
  const mismatch = r.controller_command !== r.actuator_command;
  const info = mismatch ? 'Camera correct. Controller Release → actuator Brake. Intent cannot be inferred.' :
    shadow ? 'Camera wrong. Shadow detected as an obstacle. Both commands agree on Brake.' :
    cone ? 'Cone ahead. Camera and road truth agree. Both commands request Brake.' :
    'Road clear. Controller and actuator agree on Release.';
  $('status').textContent = 'Simulated · '+(s.error || info);
  $('edit-note').hidden = !(s.kind === 4 && s.checkpoint && s.t === last && s.audit && !s.audit.ok);
}
function renderGraph(s) {
  const x = t => 35 + t*31;
  const y = v => 16 + (64-v)*3.3;
  const trace = rows => rows.slice(0,s.t+1).map(r=>x(r.timestamp_s)+','+y(r.speed_kmh)).join(' ');
  const grid = [60,48,36].map(v=>'<path d="M35 '+y(v)+'h341" stroke="#d1d1c6"/><text x="9" y="'+(y(v)+4)+'">'+v+'</text>').join('');
  const axis = [0,4,7,11].map(t=>'<text x="'+(x(t)-4)+'" y="136">'+t+'s</text>').join('');
  // Draw the dashed reference on top so identical traces remain visible.
  $('graph').innerHTML = grid+axis+'<polyline fill="none" stroke="#aa3d26" stroke-width="4" points="'+trace(s.drive)+'"/>'+
    '<polyline fill="none" stroke="#33392f" stroke-width="2" stroke-dasharray="5 5" points="'+trace(s.normal)+'"/>'+
    '<circle cx="'+x(s.t)+'" cy="'+y(s.drive[s.t].speed_kmh)+'" r="4" fill="#aa3d26"/>';
  $('graph').setAttribute('aria-label','Simulated speeds at '+s.t+' seconds. Selected '+s.drive[s.t].speed_kmh+' km/h. Normal 60 km/h.');
}
function renderTables(s,r) {
  const normal = s.normal[s.t];
  $('live').innerHTML = [['Speed',v=>v.speed_kmh+' km/h'],...channels].map(([label,read])=>
    '<tr><th scope="row">'+label+'</th><td class="'+(read(r)!==read(normal)?'difference':'')+'">'+read(r)+'</td><td>'+read(normal)+'</td></tr>').join('');
  $('times').innerHTML = '<tr><th>Channel</th>'+s.drive.map((_,i)=>'<th scope="col">'+i+' s</th>').join('')+'</tr>';
  $('channels').innerHTML = channels.map(([label,read])=>'<tr><th scope="row">'+label+'</th>'+s.drive.map((v,i)=>{
    const revealed = i < s.records.length;
    const cls = (revealed && read(v)!==read(s.normal[i])?'difference ':'')+(i===s.t?'current':'');
    return '<td class="'+cls+'">'+(revealed?read(v):'—')+'</td>';
  }).join('')+'</tr>').join('');
}
function renderEvidence(s) {
  const a = s.audit;
  const finding = a ? diagnose(s.records,a) : ['Awaiting verification','Complete the simulated drive to seal and verify the full capture.'];
  $('finding').textContent = finding[0]; $('explain').textContent = finding[1];
  $('sample').innerHTML = s.records.map((_,i)=>'<option value="'+i+'">'+(i+1)+' / 12</option>').join('');
  $('sample').value = s.inspected;
  $('detail').textContent = JSON.stringify(s.records[s.inspected],null,2) || 'Preparing simulated record…';
  $('audit').textContent = !a ? 'Simulated · '+s.records.length+'/12 records captured · verification pending.' :
    a.ok ? 'Simulated · Verified. '+a.reason : 'Simulated · Failed. '+(a.index?'Record '+a.index+': ':'Checkpoint: ')+a.reason;
  Array.from($('checks').children).forEach((li,i)=>li.classList.toggle('failed',!!a && !a.ok && i===a.stage));
  $('flow-note').textContent = a ? $('audit').textContent :
    s.kind===4 ? 'Simulated experiment · After the drive, inspect record 7 at the recomputed-hash step.' :
    'Simulated evidence · HMAC authenticates each record. The separate checkpoint binds the final hash and count.';
}
function render(s) {
  const r = s.drive[s.t];
  Array.from($('scenarios').children).forEach((b,i)=>b.setAttribute('aria-pressed',String(i===s.kind)));
  $('run').disabled = s.running || s.busy || !!s.error;
  $('run').textContent = s.t === last ? 'Replay' : 'Run';
  $('pause').disabled = !s.running;
  $('step').disabled = s.running || s.busy || !!s.error || s.t===last;
  $('scrub').disabled = s.busy || !!s.error; $('scrub').value = s.t;
  $('scrub').setAttribute('aria-valuetext',s.t+' seconds');
  $('jump').disabled = s.busy || !!s.error || s.kind===0;
  $('sample').disabled = s.busy || !s.records.length;
  for (const id of ['verify','json','csv']) $(id).disabled = !s.audit || s.busy;
  renderRoad(s,r); renderGraph(s); renderTables(s,r); renderEvidence(s);
}
$('run').onclick = () => {active.running = true; seek(active.t === last ? 0 : active.t+1)};
$('pause').onclick = () => {pause(); render(active)};
$('step').onclick = () => seek(active.t+1);
$('reset').onclick = reset;
$('seed').onchange = () => {if ($('seed').reportValidity()) reset()};
$('rate').onchange = () => {if (active.running && !active.busy) schedule(active)};
$('scrub').oninput = () => {const t = Number($('scrub').value); pause(); seek(t)};
$('jump').onclick = () => {pause(); seek(active.kind===4 ? last : 4)};
$('sample').onchange = () => {pause(); active.inspected = Number($('sample').value); render(active)};
$('verify').onclick = recheck;
function download(format) {
  const s = active;
  const finding = diagnose(s.records,s.audit)[0];
  const report = {simulated:true, scenario:names[s.kind], seed:s.seed, verification:s.audit, finding, records:s.records};
  const fields = [...sealedFields,'hash','hmac_sha256'];
  const quote = v => '"'+String(typeof v==='object'?JSON.stringify(v):v).replaceAll('"','""')+'"';
  const csv = [fields.concat(['simulated_finding','simulated_verification','simulated_failure_record','simulated_verification_reason']),
    ...s.records.map(r=>[...fields.map(f=>r[f]),finding,s.audit.ok?'Verified':'Failed',s.audit.index??'',s.audit.reason])];
  const body = format==='json' ? JSON.stringify(report,null,2) : csv.map(row=>row.map(quote).join(',')).join('\r\n');
  const url = URL.createObjectURL(new Blob([body],{type:format==='json'?'application/json':'text/csv;charset=utf-8'}));
  const a = document.createElement('a');
  a.href=url; a.download='simulated-brakewitness-'+s.kind+'-seed-'+s.seed+'.'+format;
  document.body.append(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
}
$('json').onclick = () => download('json');
$('csv').onclick = () => download('csv');
reset();
