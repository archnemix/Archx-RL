/* Wire the sealed browser client to a synthetic, opt-in test page. */
'use strict';
(async () => {
  const result=document.querySelector('#result');
  const button=document.querySelector('#check');
  const key=document.querySelector('#public-key');
  try {
    const response=await fetch('/api/v2/config',{cache:'no-store',redirect:'error'});
    if (!response.ok) throw new Error('Could not load the server configuration.');
    const config=await response.json();
    if (config.protocol!=='sealed-v2') throw new Error('Configure the server for sealed-v2 first; no raw fallback is allowed.');
    if (!Array.isArray(config.required) || config.required.some(x=>x!=='machine_id')) throw new Error('This synthetic page requires a policy with only machine_id required.');
    let token;
    if (config.turnstile) {
      if (!window.turnstile) {
        await new Promise((resolve,reject)=>{
          const script=document.createElement('script');
          const timeout=setTimeout(()=>reject(new Error('Security widget timed out.')),10000);
          script.src='https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
          script.onload=()=>{clearTimeout(timeout);resolve();};
          script.onerror=()=>{clearTimeout(timeout);reject(new Error('Could not load the security widget.'));};
          document.head.append(script);
        });
      }
      if (!window.turnstile) throw new Error('Security widget unavailable.');
      const widget=window.turnstile.render('#widget',{sitekey:config.turnstile.sitekey,action:config.turnstile.action,
        callback:value=>{token=value;button.disabled=false;result.textContent='Security check complete.';},
        'expired-callback':()=>{token=undefined;button.disabled=true;result.textContent='Security check expired.';},
        'error-callback':()=>{token=undefined;button.disabled=true;result.textContent='Security check unavailable.';}});
      button.dataset.widget=String(widget);
      result.textContent='Complete the security check, then enter the trusted public key.';
    } else {
      button.disabled=false;result.textContent='Enter the trusted public key to run the test.';
    }
    button.addEventListener('click',async()=>{
      button.disabled=true;
      try {
        const {checkEncrypted}=await import('/browser-client.mjs');
        const out=await checkEncrypted({publicKey:key.value.trim(),signals:{machine_id:'123456789abcdef0123456789abcdef0'},turnstileToken:token});
        result.textContent=out.data.message || ('Decision: '+out.data.decision);
      } catch (_) {result.textContent='Encrypted check failed. Check the key, browser build and server configuration.';}
      finally {
        if (config.turnstile) {token=undefined;window.turnstile.reset(button.dataset.widget);}
        else button.disabled=false;
      }
    });
  } catch (error) {result.textContent=error.message;}
})();
