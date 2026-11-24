'use strict';
const $ = id => document.getElementById(id);
const parts = [
  ['Sense','Sample brake pedal position, wheel speed, obstacle distance and vehicle speed.','Reads simulated signals.','Decide when to brake.','Sensors'],
  ['Record','Keep recent samples in a rolling buffer. Braking starts the incident window.','Captures before and after.','Store an entire trip.','Recorder'],
  ['Secure','Link each sample to the previous digest and sign it with a session key.','Detects edits to records.','Prove sensor accuracy.','Secure storage'],
  ['Analyse','Replay each captured sample and compare its contents with the signed digest.','Locates altered evidence.','Assign responsibility.','Analyst']
];
const icon = name => '<svg class="icon" aria-hidden="true"><use href="#'+name+'"/></svg>';
parts.forEach(([name,description,does,limit,node],i)=>{
  const symbol = icon(name.toLowerCase());
  $('cards').insertAdjacentHTML('beforeend','<article class="tile"><div class="tilehead">'+symbol+'<span class="num">[ 0'+(i+1)+' ]</span></div><h3>'+name+'</h3><p>'+description+'</p><dl><div><dt>Does</dt><dd>'+does+'</dd></div><div><dt>Does not</dt><dd>'+limit+'</dd></div></dl></article>');
  $('nodes').insertAdjacentHTML('beforeend','<div class="node">'+symbol+node+'</div>');
});
const preference = matchMedia('(prefers-reduced-motion: reduce)');
let manualMotion = false;
function setMotion(reduce){
  document.documentElement.classList.toggle('reduced',reduce);
  $('motion').setAttribute('aria-pressed',String(reduce));
}
setMotion(preference.matches);
preference.addEventListener('change',e=>{if(!manualMotion)setMotion(e.matches)});
$('motion').onclick=()=>{
  manualMotion=true;
  setMotion($('motion').getAttribute('aria-pressed')!=='true');
};

const scenarios=['Normal stop','Emergency brake','Sensor fault','Log tampering'];
const labels=['Vehicle speed','Brake pedal','Obstacle distance','Log integrity','Records written','Verified','Tampered'];
$('metrics').innerHTML=labels.map((label,i)=>'<div class="'+(i===6?'wide':'')+'"><dt>'+label+'</dt><dd id="m'+i+'"></dd></div>').join('');
scenarios.forEach((label,i)=>{
  const b=document.createElement('button');
  b.textContent=label;
  b.onclick=()=>{scenario=i;reset()};
  $('scenarios').append(b);
});
// All time, distance and sensor noise are simulated. One tick is 0.5 seconds.
const dt=0.5, trigger=6, lastTick=22, preSamples=4;
let scenario=0, tick=0, rng=42, seed=42, speed=0, initialRange=0, distance=0, sample;
let buffer=[], records=[], running=false, busy=false, timer, message='', verified=[],keyPair,publicKey;
const enc=new TextEncoder();
const hex = bytes=>Array.from(new Uint8Array(bytes),v=>v.toString(16).padStart(2,'0')).join('');
const bytes = h=>Uint8Array.from(h.match(/../g)||[],s=>parseInt(s,16));
const signing={name:'ECDSA',hash:'SHA-256'};
function random(){
  rng=(Math.imul(rng,1664525)+1013904223)>>>0;
  return rng/4294967296;
}
function makeSample(brake){
  const fault=scenario===2 && tick>=trigger && tick<trigger+4;
  return {scenario:scenarios[scenario],seed,tick,time_s:tick*dt,
    speed_kmh:+speed.toFixed(1),wheel_kmh:+Math.max(0,speed+(speed?random()-.5:0)).toFixed(1),
    brake_pct:brake,distance_m:fault?null:+distance.toFixed(1)};
}
function pause(){
  running=false;
  clearTimeout(timer);
}
function reset(){
  pause();
  if(!$('seed').checkValidity() || $('seed').value==='') $('seed').value='42';
  seed=Number($('seed').value);rng=seed;tick=0;
  speed=46+Math.round(random()*8);
  initialRange=distance=scenario===1?65:105;
  buffer=[];records=[];verified=[];sample=makeSample(0);
  message='Ready. Run the scene or step through the approach.';
  $('audit').textContent='';$('cursor').value=1;render();
}
// JSON array order defines the canonical UTF-8 bytes hashed by SHA-256.
function canonical(s,previous){
  return JSON.stringify([previous,s.scenario,s.seed,s.tick,s.time_s,s.speed_kmh,s.wheel_kmh,s.brake_pct,s.distance_m]);
}
async function digest(s,previous){
  return hex(await crypto.subtle.digest('SHA-256',enc.encode(canonical(s,previous))));
}
async function append(s){
  const previous=records.at(-1)?.hash??'0'.repeat(64);
  const hash=await digest(s,previous);
  const signature=hex(await crypto.subtle.sign(signing,keyPair.privateKey,bytes(hash)));
  records.push({sample:{...s},previous,hash,signature});
}
async function verify(){
  verified=await Promise.all(records.map(async(r,i)=>{
    const prior=i?records[i-1].hash:'0'.repeat(64);
    return r.previous===prior && r.hash===await digest(r.sample,r.previous) &&
      await crypto.subtle.verify(signing,keyPair.publicKey,bytes(r.signature),bytes(r.hash));
  }));
}
async function advance(){
  if(busy || tick>=lastTick || !keyPair)return;
  busy=true;render();
  try{
    tick++;
    const before=speed;
    const brake=tick<trigger?0:scenario===1?95:50;
    speed=Math.max(0,speed-3.6*dt*(brake===95?6.5:brake===50?2.4:0));
    distance=Math.max(0,distance-(before+speed)/7.2*dt);
    sample=makeSample(brake);
    if(tick<trigger){
      buffer.push(sample);buffer=buffer.slice(-preSamples);
      message='Approaching the stop. Recent samples are held in the rolling buffer.';
    }else{
      if(tick===trigger){for(const s of buffer)await append(s);buffer=[]}
      await append(sample);
      message=sample.distance_m===null?'Range sensor offline. Wheel and pedal signals are still recorded.':
        speed===0?'Vehicle stopped. Recording the post-braking window.':
        scenario===1?'Obstacle ahead. Emergency braking is active.':'Brake pedal engaged. Recording the incident.';
      // Modify a stored copy only, after signing. Live telemetry stays intact.
      if(scenario===3 && tick===trigger+3)records[preSamples].sample.brake_pct=8;
      await verify();
      $('cursor').max=records.length;$('cursor').value=records.length;
    }
    if(tick===lastTick){pause();message='Capture complete. Use the sample slider to replay the incident.'}
    if(verified.includes(false))message+=' Integrity failure at sample '+(verified.indexOf(false)+1)+'.';
  }catch(error){pause();message='Recording failed: '+error.message}
  finally{busy=false;render()}
  if(running)timer=setTimeout(advance,500/Number($('rate').value));
}
function inspect(){
  const i=Number($('cursor').value)-1,r=records[i];
  $('detail').textContent=r?[
    'Sample '+(i+1)+' of '+records.length+' · '+(verified[i]?'Verified':'Integrity failed'),
    r.sample.time_s+' s · '+r.sample.speed_kmh+' km/h · wheel '+r.sample.wheel_kmh+' km/h · brake '+r.sample.brake_pct+'% · range '+(r.sample.distance_m??'unavailable')+(r.sample.distance_m===null?'':' m'),
    'SHA-256 '+r.hash
  ].join('\n'):'Awaiting a braking event.';
}
function render(){
  const bad=verified.filter(v=>!v).length;
  [sample.speed_kmh+' km/h',sample.brake_pct+'%',sample.distance_m===null?'Unavailable':sample.distance_m+' m',
    bad?'Failed':records.length?'Intact':'Pending',records.length,verified.length-bad,bad].forEach((v,i)=>$('m'+i).textContent=v);
  $('car').setAttribute('transform','translate('+Math.min(620,620*(1-distance/initialRange))+',0)');
  $('status').textContent=tick*dt+' s · '+message;
  $('run').textContent=running?'Ⅱ Pause':'▶ Run';
  $('run').disabled=!keyPair || tick>=lastTick || (busy&&!running);
  $('step').disabled=running || busy || !keyPair || tick>=lastTick;
  $('reset').disabled=busy;$('seed').disabled=busy||running;
  Array.from($('scenarios').children).forEach((b,i)=>{b.disabled=busy;b.setAttribute('aria-pressed',String(i===scenario))});
  for(const id of ['json','csv','verify','cursor'])$(id).disabled=!records.length||busy||running;
  $('cursor').max=Math.max(1,records.length);
  inspect();
}
$('run').onclick=()=>{if(running){pause();render()}else{running=true;advance()}};
$('step').onclick=advance;$('reset').onclick=reset;$('seed').onchange=reset;
$('cursor').oninput=inspect;
$('verify').onclick=async()=>{
  busy=true;render();
  try{await verify();$('audit').textContent='Checked '+records.length+' records. '+verified.filter(x=>!x).length+' failed.'}
  finally{busy=false;render()}
};
// Both formats include the public verification key. Private key stays in memory.
function download(format){
  const evidence={schema:'brakewitness/1',algorithm:'ECDSA P-256 / SHA-256',publicKey,
    canonicalFields:['previous',...Object.keys(records[0].sample)],records:records.map((r,i)=>({...r,verified:verified[i]}))};
  const quote=v=>'"'+String(v??'').replaceAll('"','""')+'"';
  const fields=Object.keys(records[0].sample);
  const csv=[fields.concat(['previous','hash','signature','verified','public_key_jwk']),
    ...evidence.records.map(r=>[...fields.map(f=>r.sample[f]),r.previous,r.hash,r.signature,r.verified,JSON.stringify(publicKey)])];
  const body=format==='json'?JSON.stringify(evidence,null,2):csv.map(row=>row.map(quote).join(',')).join('\r\n');
  const url=URL.createObjectURL(new Blob([body],{type:format==='json'?'application/json':'text/csv;charset=utf-8'}));
  const a=document.createElement('a');a.href=url;a.download='brakewitness-'+seed+'-'+scenario+'.'+format;a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
$('json').onclick=()=>download('json');$('csv').onclick=()=>download('csv');
async function init(){
  reset();
  try{
    keyPair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
    publicKey=await crypto.subtle.exportKey('jwk',keyPair.publicKey);
  }catch{keyPair=null;message='Signing unavailable. Open this page on localhost or HTTPS in a modern browser.'}
  render();
}
init();
