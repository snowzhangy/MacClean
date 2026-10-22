#!/usr/bin/env node
// Optional real-browser smoke test. Node 22+ and Chromium; no npm dependencies.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, writeFile, rm, access, realpath } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scratch = await realpath(await mkdtemp(path.join(os.tmpdir(), 'macclean-browser-')));
const fixture = path.join(scratch, 'fixture');
const chrome = process.env.CHROME_BIN || path.join(os.homedir(), 'Library/Caches/ms-playwright/chromium_headless_shell-1200/chrome-headless-shell-mac-arm64/chrome-headless-shell');
const live = process.argv.includes('--live');
let server, browser, ws;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function outputMatch(child, regex, timeout = 15000) {
  return new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error('Process startup timed out: ' + output)), timeout);
    const read = chunk => {
      output += chunk.toString();
      const match = output.match(regex);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    };
    child.stdout?.on('data', read); child.stderr?.on('data', read);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('exit', code => { clearTimeout(timer); reject(new Error(`Process exited (${code}): ${output}`)); });
  });
}
try {
  await access(chrome);
  await mkdir(path.join(fixture, 'Archive'), { recursive: true });
  await writeFile(path.join(fixture, 'Archive', 'large.bin'), Buffer.alloc(1024 * 1024, 1));
  await writeFile(path.join(fixture, 'keep.txt'), Buffer.alloc(8192, 1));
  await writeFile(path.join(fixture, '<img src=x onerror=alert(1)>.txt'), 'text');
  await Promise.all(Array.from({ length: 125 }, (_, i) => writeFile(path.join(fixture, `empty-${String(i).padStart(3, '0')}`), '')));
  server = spawn(process.env.PYTHON || 'python3', ['scripts/browser-fixture-server.py', fixture, '--port', '0', '--no-open'], { cwd: repo });
  const url = await outputMatch(server, /running at (http:\/\/127\.0\.0\.1:\d+\/)/);
  browser = spawn(chrome, ['--headless', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', `--user-data-dir=${path.join(scratch, 'profile')}`, 'about:blank']);
  const endpoint = await outputMatch(browser, /DevTools listening on (ws:\/\/[^\s]+)/);
  ws = new WebSocket(endpoint);
  await once(ws, 'open');
  let sequence = 0;
  const pending = new Map();
  const errors = [];
  const previews = [];
  const scans = [];
  let pageLoads=0;
  ws.onmessage = event => {
    const message = JSON.parse(event.data);
    if(message.method==='Page.loadEventFired') pageLoads++;
    if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails);
    if (message.method === 'Network.requestWillBeSent'){
      if(message.params.request.url.includes('/api/preview?')) previews.push(message.params.timestamp);
      if(message.params.request.url.endsWith('/api/scan') && message.params.request.postData) scans.push(JSON.parse(message.params.request.postData));
    }
    if (message.id && pending.has(message.id)) {
      const { resolve, reject, timer } = pending.get(message.id);
      pending.delete(message.id); clearTimeout(timer);
      message.error ? reject(new Error(JSON.stringify(message.error))) : resolve(message.result);
    }
  };
  function cdp(method, params = {}, sessionId) {
    const id = ++sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error('CDP timeout: ' + method)); }, 15000);
      pending.set(id, { resolve, reject, timer });
      ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  const { targetId } = await cdp('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp('Target.attachToTarget', { targetId, flatten: true });
  const send = (method, params) => cdp(method, params, sessionId);
  await send('Runtime.enable'); await send('Page.enable'); await send('Network.enable');
  const evaluate = async expression => {
    const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  async function waitFor(expression, timeout=10000) {
    const end = Date.now() + timeout;
    while (Date.now() < end) { if (await evaluate("document.readyState==='complete' && !!document.querySelector('#scan') && ("+expression+")")) return; await pause(40); }
    const state=await evaluate("JSON.stringify({notice:document.querySelector('#notice')?.textContent, progress:document.querySelector('#scanProgressText')?.textContent, page:document.querySelector('#pageInfo')?.textContent, selected:document.querySelector('#selName')?.textContent, path:document.querySelector('#path')?.value, busy:document.querySelector('#scan')?.disabled})");
    throw new Error('UI did not reach expected state: ' + expression + '\\n' + state + '\\n' + JSON.stringify(errors));
  }
  async function reloadPage(){
    const previousLoads=pageLoads;
    await send('Page.reload');
    const deadline=Date.now()+10000;
    while(pageLoads===previousLoads && Date.now()<deadline) await pause(20);
    assert.ok(pageLoads>previousLoads,'reloaded document must finish loading');
  }
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 850, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url });
  await waitFor("document.querySelector('#pageInfo')?.textContent === '1–100 of 128' && !document.querySelector('#scan').disabled");
  assert.equal(await evaluate("document.querySelectorAll('#list img').length"), 0, 'filename must be escaped');
  await evaluate("document.querySelector('#next').click()");
  await waitFor("document.querySelector('#pageInfo').textContent === '101–128 of 128'");
  await evaluate("document.querySelector('#filter').value='keep'; document.querySelector('#filter').dispatchEvent(new Event('input'))");
  await waitFor("document.querySelector('#pageInfo').textContent === '1–1 of 1'");
  await evaluate("document.querySelector('#list button').click()");
  assert.equal(await evaluate("document.querySelector('#selName').textContent"), 'keep.txt');
  assert.equal(await evaluate("document.querySelector('#refresh').disabled || document.querySelector('#finderBtn').disabled"),false);
  assert.equal(await evaluate("document.querySelector('#scanProgressText').textContent.startsWith('Done')"),true);
  assert.equal(await evaluate("document.querySelector('#finderBtn').click(); document.querySelector('#finderBtn').classList.contains('is-busy')"),true);
  await waitFor("document.querySelector('#noticeText').textContent==='Revealed in Finder.' && !document.querySelector('#finderBtn').disabled");
  assert.equal(await evaluate("document.querySelector('#finderBtn').classList.contains('is-busy')"),false);
  await evaluate("document.querySelector('#svg path').dispatchEvent(new MouseEvent('mouseenter'))");
  assert.equal(await evaluate("document.querySelector('#selName').textContent"), 'keep.txt', 'hover must preserve action selection');
  await evaluate("document.querySelector('#filter').value='<img'; document.querySelector('#filter').dispatchEvent(new Event('input'))");
  await waitFor("document.querySelector('#pageInfo').textContent==='1–1 of 1' && document.querySelector('#list .nm')?.textContent.includes('<img')");
  await evaluate("document.querySelector('#list button').click(); document.querySelector('#finderBtn').click()");
  await waitFor("document.querySelector('#noticeText').textContent==='Fixture Finder error' && !document.querySelector('#finderBtn').disabled");
  assert.equal(await evaluate("document.querySelector('#refresh').disabled"),false,'Finder errors must not lock Refresh');
  await evaluate("document.querySelector('#filter').value='Archive'; document.querySelector('#filter').dispatchEvent(new Event('input'))");
  await waitFor("document.querySelector('#list .nm')?.textContent === 'Archive /'");
  await evaluate("document.querySelector('#list button').click()");
  await waitFor("document.querySelector('#selName').textContent === 'Archive' && document.querySelector('#selMeta').textContent.startsWith('current folder') && document.querySelector('#pageInfo').textContent === '1–1 of 1' && !document.querySelector('#scan').disabled");
  const scansBeforeChartNavigation=scans.length;
  await evaluate("Array.from(document.querySelectorAll('#svg path')).find(p=>p._a.center).dispatchEvent(new MouseEvent('click'))");
  await waitFor("document.querySelector('#pageInfo').textContent === '1–100 of 128' && !document.querySelector('#scan').disabled");
  await evaluate("Array.from(document.querySelectorAll('#svg path')).find(p=>!p._a.center && p._a.node.name==='Archive').dispatchEvent(new MouseEvent('click'))");
  await waitFor("document.querySelector('#selName').textContent === 'Archive' && document.querySelector('#pageInfo').textContent === '1–1 of 1' && !document.querySelector('#scan').disabled");
  assert.equal(scans.length,scansBeforeChartNavigation,'folder navigation must not start another disk scan');
  await writeFile(path.join(fixture, 'Archive', 'new.txt'), 'new');
  await mkdir(path.join(fixture, 'Archive', 'nested', 'deep'), {recursive:true});
  await writeFile(path.join(fixture, 'Archive', 'nested', 'deep', 'added.txt'), 'nested content');
  await writeFile(path.join(fixture, 'unscanned-sibling.txt'), 'outside refresh');
  // Refresh follows the displayed folder, even with a file selected and an edited scan input.
  await evaluate(`document.querySelector('#list button').click(); document.querySelector('#path').value=${JSON.stringify(fixture)}`);
  const scansBeforeRefresh=scans.length;
  await evaluate("document.querySelector('#refresh').click()");
  await waitFor("document.querySelector('#pageInfo').textContent === '1–3 of 3' && !document.querySelector('#scan').disabled");
  assert.equal(scans.length,scansBeforeRefresh+1,'Refresh must start exactly one scan');
  assert.deepEqual(scans.at(-1),{path:path.join(fixture,'Archive'),refresh:true},'Refresh must target only the current folder');
  assert.equal(await evaluate("document.querySelector('#scanProgress').dataset.state==='done' && !document.querySelector('#refresh').disabled && !document.querySelector('#finderBtn').disabled"),true);
  assert.equal(await evaluate("document.querySelector('#path').value.endsWith('/Archive')"),true);
  assert.equal(await evaluate("document.querySelector('#scanProgressText').textContent.includes('/Archive (including subfolders)')"),true);
  assert.equal(await evaluate(`(async()=>(await api('/api/children?'+new URLSearchParams({path:${JSON.stringify(path.join(fixture,'Archive','nested','deep'))}}))).items[0].name)()`),'added.txt','refresh must discover deeply nested files');
  assert.equal(await evaluate(`(async()=>(await api('/api/children?'+new URLSearchParams({path:${JSON.stringify(fixture)},q:'unscanned-sibling'}))).total)()`),0,'refresh must leave sibling contents cached');
  assert.equal(await evaluate("document.querySelector('#crumbs button').textContent"),fixture,'refresh must preserve parent navigation');
  await evaluate("document.querySelector('#scan').click()");
  await waitFor("document.querySelector('#pageInfo').textContent === '1–3 of 3' && !document.querySelector('#scan').disabled");
  assert.ok(scans.at(-1).path.endsWith('/Archive'),'next scan must target the folder being viewed');
  await evaluate(`document.querySelector('#path').value=${JSON.stringify(path.join(scratch, 'missing'))}; document.querySelector('#scan').click()`);
  await waitFor("document.querySelector('#notice').textContent.length > 0 && !document.querySelector('#scan').disabled");
  assert.equal(await evaluate("document.querySelector('#overlay').style.display"), 'none');
  assert.equal(await evaluate("document.querySelector('#selName').textContent"), 'Archive', 'failed scan must preserve results');
  await evaluate(`document.querySelector('#path').value=${JSON.stringify(fixture)}; document.querySelector('#scan').click()`);
  await waitFor("document.querySelector('#pageInfo').textContent === '1–100 of 129' && !document.querySelector('#scan').disabled");
  // Exercise the user-facing recovery button with a per-scan entry limit.
  await evaluate(`void doScan(${JSON.stringify(fixture)},false,{max_entries:100})`);
  await waitFor("!document.querySelector('#retry').hidden && !document.querySelector('#scan').disabled");
  await evaluate("document.querySelector('#retry').click()");
  await waitFor("document.querySelector('#pageInfo').textContent === '1–100 of 129' && !document.querySelector('#scan').disabled && document.querySelector('#retry').hidden");
  const scansBeforeReload=scans.length;
  await reloadPage();
  await waitFor("document.querySelector('#scanProgressText').textContent.startsWith('Done') && document.querySelector('#pageInfo').textContent==='1–100 of 129' && !document.querySelector('#refresh').disabled");
  assert.equal(scans.length,scansBeforeReload,'reload must reuse completed results without restarting a scan');
  const desktop = await send('Page.captureScreenshot', { format: 'png' });
  await writeFile('/tmp/macclean-desktop.png', Buffer.from(desktop.data, 'base64'));
  await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  await pause(150);
  assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true, 'mobile layout must not overflow horizontally');
  const mobile = await send('Page.captureScreenshot', { format: 'png' });
  await writeFile('/tmp/macclean-mobile.png', Buffer.from(mobile.data, 'base64'));
  if(live){
    const liveRoot=path.join(fixture,'Live');
    await mkdir(path.join(liveRoot,'early'),{recursive:true});
    await mkdir(path.join(liveRoot,'later'),{recursive:true});
    await writeFile(path.join(liveRoot,'early','one.bin'),Buffer.alloc(1024*1024,1));
    await writeFile(path.join(liveRoot,'later','two.bin'),Buffer.alloc(2*1024*1024,1));
    await send('Emulation.setDeviceMetricsOverride',{width:1280,height:850,deviceScaleFactor:1,mobile:false});
    await evaluate(`document.querySelector('#path').value=${JSON.stringify(liveRoot)}; document.querySelector('#scan').click()`);
    await waitFor("document.querySelector('#status').textContent.startsWith('Partial scan') && document.querySelector('#selSize').textContent === '1.00 MiB'",17000);
    assert.equal(await evaluate("document.querySelector('#trashBtn').style.display"),'none');
    assert.equal(await evaluate("document.querySelector('#finderBtn').disabled"),false,'Finder should remain available during a scan');
    assert.equal(await evaluate("document.querySelector('#cancel').hidden"),false);
    const partial=await send('Page.captureScreenshot',{format:'png'});
    await writeFile('/tmp/macclean-live-preview.png',Buffer.from(partial.data,'base64'));
    await evaluate("Array.from(document.querySelectorAll('#list button')).find(row=>row.textContent.includes('early /')).click()");
    await waitFor("document.querySelector('#selName').textContent==='early' && document.querySelector('#selMeta').textContent.startsWith('current folder') && document.querySelector('#path').value.endsWith('/Live/early') && document.querySelector('#overlay').style.display==='none'");
    const scansBeforeResume=scans.length;
    await reloadPage();
    await waitFor("document.querySelector('#selName').textContent==='early' && document.querySelector('#pageInfo').textContent==='Largest scanned items so far'");
    assert.equal(scans.length,scansBeforeResume,'reload must reconnect to the running scan');
    await waitFor("document.querySelector('#scanProgressText').textContent.includes('3.00 MiB scanned')",10000);
    await waitFor("document.querySelector('#scanProgressText').textContent.includes('21.') || document.querySelector('#scanProgressText').textContent.includes('22.')",10000);
    assert.equal(previews.length,4,'timed previews, folder navigation and one reconnect preview');
    assert.ok(previews[3]-previews[2]>=9.9,'focused updates must not run more frequently than ten seconds');
    assert.equal(await evaluate("document.querySelector('#selName').textContent"),'early','timed update must preserve focused folder');
    assert.equal(await evaluate("document.querySelector('#selSize').textContent"),'1.00 MiB');
    await waitFor("!document.querySelector('#scan').disabled && !document.querySelector('#status').textContent.startsWith('Partial scan')",10000);
    assert.equal(await evaluate("document.querySelector('#selName').textContent"),'early','completion must preserve focused folder');
    assert.equal(await evaluate("document.querySelector('#scanProgressText').textContent.startsWith('Done') && !document.querySelector('#refresh').disabled && !document.querySelector('#finderBtn').disabled"),true,'completion must say Done and enable controls');
    await evaluate("document.querySelector('#scan').click()");
    await waitFor("!document.querySelector('#scan').disabled && document.querySelector('#selName').textContent==='early'");
    assert.ok(scans.at(-1).path.endsWith('/Live/early'),'next scan must focus on live-navigated folder');
    await evaluate(`document.querySelector('#path').value=${JSON.stringify(liveRoot)}; document.querySelector('#scan').click()`);
    await waitFor("document.querySelector('#status').textContent.startsWith('Partial scan') && document.querySelector('#selSize').textContent === '1.00 MiB'",17000);
    await evaluate("document.querySelector('#cancel').click()");
    await waitFor("!document.querySelector('#scan').disabled && document.querySelector('#noticeText').textContent.includes('previous results are unchanged')");
    assert.equal(await evaluate("document.querySelector('#selName').textContent"),'early','cancel must restore previous focused results');
    assert.equal(await evaluate("document.querySelector('#selSize').textContent"),'1.00 MiB');
    const slowRoot=path.join(fixture,'SlowPreview');
    await mkdir(path.join(slowRoot,'early'),{recursive:true});
    await writeFile(path.join(slowRoot,'early','one.bin'),Buffer.alloc(1024*1024,1));
    await evaluate(`document.querySelector('#path').value=${JSON.stringify(slowRoot)}; document.querySelector('#scan').click()`);
    await waitFor("document.querySelector('#scanProgress').dataset.state==='waiting'",18000);
    const waitingText=await evaluate("document.querySelector('#scanProgressText').textContent");
    await pause(1200);
    assert.notEqual(await evaluate("document.querySelector('#scanProgressText').textContent"),waitingText,'waiting status clock must keep advancing');
    assert.equal(await evaluate("getComputedStyle(document.querySelector('#refresh')).cursor"),'not-allowed','unavailable buttons must not imply active processing');
    await waitFor("document.querySelector('#scanProgressText').textContent.startsWith('Done') && !document.querySelector('#refresh').disabled && !document.querySelector('#finderBtn').disabled",18000);
    assert.equal(await evaluate("document.querySelectorAll('button.is-busy').length"),0,'terminal state must clear button spinners');
    console.log('Live preview passed: single-click browsing, focused 10-second updates, focused completion and next scan, disabled Trash, cancellation restoration.');
  }
  assert.deepEqual(errors, [], 'browser must not report unhandled JavaScript errors');
  console.log('Browser smoke passed: scan, pagination, search, escaping, stable selection, navigation, refresh, failure recovery, responsive layout.');
  console.log('Screenshots: /tmp/macclean-desktop.png, /tmp/macclean-mobile.png');
} finally {
  ws?.close();
  for (const child of [browser, server]) {
    if (child && child.exitCode === null) {
      const exited = once(child, 'exit'); child.kill('SIGTERM');
      await Promise.race([exited, pause(3000)]);
      if (child.exitCode === null) child.kill('SIGKILL');
    }
  }
  await rm(scratch, { recursive: true, force: true });
}
