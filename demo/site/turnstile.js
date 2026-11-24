'use strict';
(async () => {
  const result=document.querySelector('#result'), button=document.querySelector('#check');
  try {
    const config=await (await fetch('/api/v2/config')).json();
    if (!config.turnstile) throw new Error('Turnstile is not configured on this server.');
    if (config.protocol !== 'raw-v2') throw new Error('This sample does not support sealed requests; use the native client or integrate a sealed-box capable frontend.');
    if (config.required.some(x => x !== 'machine_id')) throw new Error('This sample requires a policy with only machine_id required.');
    // Cloudflare's API is async; wait for it with a bounded timeout.
    const deadline=Date.now()+10000;
    while (!window.turnstile && Date.now()<deadline) await new Promise(r=>setTimeout(r,100));
    if (!window.turnstile) throw new Error('Could not load the Turnstile widget.');
    let token='';
    const widget=turnstile.render('#widget', {sitekey:config.turnstile.sitekey, action:config.turnstile.action,
      callback:value=>{token=value;button.disabled=false;result.textContent='Security check complete.';},
      'expired-callback':()=>{token='';button.disabled=true;result.textContent='Security check expired; retry.';},
      'error-callback':()=>{token='';button.disabled=true;result.textContent='Security check unavailable.';}});
    result.textContent='Complete the security check.';
    button.addEventListener('click',async()=>{
      button.disabled=true;
      try {
        const response=await fetch('/api/v2/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({signals:{machine_id:'123456789abcdef0123456789abcdef0'},turnstile_token:token})});
        const data=await response.json();result.textContent=data.message || ('Decision: '+data.decision);
      } catch (_) {result.textContent='Request failed.';} finally {token='';turnstile.reset(widget);}
    });
  } catch (error) {result.textContent=error.message;}
})();
