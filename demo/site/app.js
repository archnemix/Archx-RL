'use strict';
let selected = 'basic';
const names = {machine_id:'Machine ID', product_uuid:'Product UUID', board_serial:'Motherboard serial', product_serial:'Product serial', chassis_serial:'Chassis serial', disk_serial:'Disk serial', disk_wwn:'Disk WWN', filesystem_uuid:'Filesystem UUID', partition_uuid:'Partition UUID', mac_address:'MAC address', gpu_uuid_nvidia:'GPU UUID (NVIDIA)', tpm_device:'TPM device', timezone:'Timezone'};
const pretty = s => ({available:'Available', accessible:'Accessible', permission_denied:'Restricted', absent:'Not present', empty_or_placeholder:'No usable value', unreadable:'Unreadable', unavailable_or_unsupported:'Unavailable'}[s] || 'Unknown');
const badge = state => { const node=document.createElement('span'); node.className='badge '+(state==='permission_denied'?'denied':state==='available'||state==='accessible'?'':'absent'); node.textContent=pretty(state); return node; };
function renderSurvey(survey) {
  const groups=['runner-user','isolated-user','root'].map(x => survey.access_levels.find(a => a.access_level === x));
  if(groups.some(x=>!x)) throw new Error('Survey is incomplete');
  const order=['machine_id','product_uuid','board_serial','product_serial','chassis_serial','disk_serial','disk_wwn','filesystem_uuid','partition_uuid','gpu_uuid_nvidia','mac_address','tpm_device','timezone'];
  const tbody=document.querySelector('#survey-body'); tbody.replaceChildren();
  for(const key of order){const tr=document.createElement('tr');const name=document.createElement('td');name.textContent=names[key]||key;tr.append(name);for(const g of groups){const td=document.createElement('td');td.append(badge(g.signals[key]));tr.append(td)}const cls=document.createElement('td');const classNames={readable_by_both_unprivileged_users:'Normal user',runner_user_only:'Runner-specific',isolated_user_only:'Isolated user only',root_only_on_this_runner:'Elevated on this VM',unavailable_or_unverified_on_this_runner:'Not determined'};cls.textContent=classNames[survey.classification?.[key]]||'Not classified';tr.append(cls);tbody.append(tr)}
  const count=order.filter(k=>['available','accessible'].includes(groups[0].signals[k])).length;
  document.querySelector('#available-count').innerHTML=`${count} <small>signals</small>`;
  document.querySelector('#survey-caption').textContent='Readable by runner user';
  document.querySelector('#survey-meta').textContent=`${survey.environment.runner} · ${survey.environment.arch} · ${survey.environment.kernel} · normal user sudo: ${groups[0].passwordless_sudo === undefined ? 'not recorded' : groups[0].passwordless_sudo ? 'available' : 'not available'}`;
  document.querySelector('#survey-date').textContent=new Date(survey.tested_at_utc).toISOString().slice(0,16).replace('T',' ')+' UTC';
}
async function loadSurvey() {
  try {
    const response=await fetch('/api/info'); if(!response.ok) throw new Error('Failed to load survey');
    const data=await response.json();
    document.querySelector('#live-storage').textContent = data.storage_mode === 'sqlite' ? 'SQLITE DEMO' : 'IN-MEMORY DEMO';
    const surveys = [...(data.survey_history || [])];
    if(data.survey && !surveys.some(s=>s.environment.run_id===data.survey.environment.run_id)) surveys.unshift(data.survey);
    if(!surveys.length) throw new Error('No saved survey is available yet');
    const picker=document.querySelector('#survey-run');
    for(const survey of surveys){const option=document.createElement('option');option.value=survey.environment.run_id;option.textContent=new Date(survey.tested_at_utc).toISOString().slice(0,16).replace('T',' ')+' UTC';picker.append(option)}
    picker.addEventListener('change',()=>renderSurvey(surveys.find(s=>s.environment.run_id===picker.value)));
    renderSurvey(surveys[0]);
  } catch(error){document.querySelector('#survey-body').replaceChildren();const row=document.createElement('tr'),cell=document.createElement('td');cell.colSpan=5;cell.textContent=error.message;row.append(cell);document.querySelector('#survey-body').append(row);document.querySelector('#survey-meta').textContent='Survey unavailable';document.querySelector('#survey-caption').textContent='No saved survey'}
}
for(const card of document.querySelectorAll('.policy-card')) card.addEventListener('click',()=>{
  selected=card.dataset.preset;document.querySelectorAll('.policy-card').forEach(c=>c.classList.toggle('selected',c===card));
  document.querySelector('#selected-preset').textContent=selected[0].toUpperCase()+selected.slice(1);
  const count={basic:1,standard:2,hard:3}[selected];document.querySelector('#selection-threshold').textContent=count+' matching signal'+(count===1?'':'s');
});
document.querySelector('#run-simulation').addEventListener('click',async ()=>{
  const btn=document.querySelector('#run-simulation'), status=document.querySelector('#result-status'), list=document.querySelector('#result-list'), empty=document.querySelector('#result-summary');
  btn.disabled=true;status.textContent='RUNNING';list.replaceChildren();
  try{
    const raw=document.querySelector('#custom-policy').value.trim();const config=raw?JSON.parse(raw):undefined;
    const response=await fetch('/api/demo/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({preset:selected,config})});
    const result=await response.json();if(!response.ok) throw new Error(result.error || 'Simulation failed');
    empty.hidden=true;empty.style.display='none';
    result.events.forEach((event,i)=>{const row=document.createElement('div');row.className='result-row';const idx=document.createElement('span');idx.className='result-index';idx.textContent=String(i+1).padStart(2,'0');const text=document.createElement('div');const title=document.createElement('div');title.className='result-name';title.textContent=event.scenario;const detail=document.createElement('div');detail.className='result-detail';detail.textContent=event.decision==='rate_limited'?`Try again in ${event.retry_after_seconds}s`:event.relation+(event.matched_signals?.length?' · '+event.matched_signals.join(', '):'');text.append(title,detail);const pill=document.createElement('span');pill.className='pill'+(event.decision==='rate_limited'?' limited':'');pill.textContent=event.decision.replaceAll('_',' ').toUpperCase();row.append(idx,text,pill);list.append(row)});
    status.textContent='COMPLETED';
  }catch(error){empty.hidden=false;empty.style.display='flex';empty.querySelector('strong').textContent='Could not run simulation.';empty.querySelector('p').textContent=error.message;status.textContent='CHECK CONFIG'}finally{btn.disabled=false}
});
document.querySelectorAll('.nav-link').forEach(link=>link.addEventListener('click',()=>{document.querySelectorAll('.nav-link').forEach(n=>n.classList.remove('active'));link.classList.add('active')}));
loadSurvey();
