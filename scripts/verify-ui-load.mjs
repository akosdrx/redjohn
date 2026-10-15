/* global fetch, performance, Event, window, CustomEvent */
/** Hidden real Electron renderer + local synthetic HTTP/WS fixture, no screenshot.
 * Run after pnpm build: node scripts/verify-ui-load.mjs [output.json]
 * Measures source-built production renderer, not a substitute component.
 */
import { createRequire } from 'node:module';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, URL } from 'node:url';
import { startLoadApi } from '../../rj-cloud/tests/e2e/load-api.mjs';
import { machine, summary, skillsLoad, rendered, processRss, requestMetrics } from '../../rj-cloud/tests/e2e/load-metrics.mjs';
const require=createRequire(new URL('../../rj-cloud/web/package.json',import.meta.url));
const { _electron }=require('@playwright/test');
const desktopRequire=createRequire(new URL('../app/package.json',import.meta.url));
const electronPath=desktopRequire('electron');
const scratch=await mkdtemp(join(tmpdir(),'redjohn-electron-ui-load-'));
const fixture=await startLoadApi(0);let electron,cdp;
const errors=[];const report={machine:machine(),fixture:{skills:10000,events:100000,agents:50,api:'synthetic HTTP/WS; no OV vector search'},surface:'hidden Electron; actual production renderer'};
try{
  const profile=join(scratch,'core','load');await mkdir(profile,{recursive:true});await writeFile(join(profile,'profile.lock'),JSON.stringify({port:fixture.port,token:'ui-load-fixture',pid:process.pid}));
  electron=await _electron.launch({executablePath:electronPath,args:[fileURLToPath(new URL('../app/',import.meta.url)),'--redjohn-smoke-test',`--user-data-dir=${join(scratch,'ui')}`],env:{HOME:scratch,PATH:process.env.PATH,REDJOHN_HOME:join(scratch,'core'),REDJOHN_PROFILE:'load',RJ_MEMORY_AUTO_START:'0'},cwd:scratch});
  const page=await electron.firstWindow();page.on('pageerror',error=>errors.push(error.message));
  const requests=requestMetrics(page);
  cdp=await page.context().newCDPSession(page);await cdp.send('Performance.enable');
  const rss=()=>processRss([electron.process().pid]);
  await page.getByRole('heading',{name:'Synthetic UI load',exact:true}).waitFor();
  for(let i=0;i<100;i++){if((await fetch(`http://127.0.0.1:${fixture.port}/__load/metrics`).then(r=>r.json())).clients)break;await page.waitForTimeout(50);}
  report.before={rssBytes:rss(),heap:await cdp.send('Runtime.getHeapUsage')};
  const viewport=page.getByTestId('terminal-viewport');
  report.viewportHeight=await viewport.evaluate(el=>el.getBoundingClientRect().height);
  if(report.viewportHeight<120)throw new Error(`50-agent terminal collapsed to ${report.viewportHeight}px`);
  const t=performance.now();await fetch(`http://127.0.0.1:${fixture.port}/__load/start`);await viewport.getByText(/synthetic-log-100000/).waitFor({timeout:120000});await rendered(page);
  report.logs={ingestToRenderedMs:performance.now()-t,renderedRows:await viewport.locator('.xterm-rows > div').count()};
  const switching=[];
  for(let i=0;i<50;i++){const name=`Agent ${String(i).padStart(2,'0')}`;const begin=performance.now();await page.getByRole('tab',{name,exact:true}).click();await rendered(page);await viewport.getByText(new RegExp(`\\[${name}\\]`)).first().waitFor();switching.push(performance.now()-begin);}
  report.logs.agentSwitch=summary(switching);
  await page.getByRole('tab',{name:'All agents (50)',exact:true}).click();await rendered(page);
  const search=page.getByRole('searchbox',{name:'Search logs…'});const begin=performance.now();await search.fill('synthetic-log-100000');await viewport.locator('.xterm-selection > div').first().waitFor();await rendered(page);report.logs.searchMs=performance.now()-begin;
  report.logs.searchMatchBoxes=await viewport.locator('.xterm-selection > div').count();
  await search.fill('');
  await page.getByRole('button',{name:'Following live output',exact:true}).click();
  await viewport.locator('.xterm-viewport').evaluate(el=>{el.scrollTop=0;el.dispatchEvent(new Event('scroll'));});
  await fetch(`http://127.0.0.1:${fixture.port}/__load/append?count=50`);await page.waitForTimeout(200);await rendered(page);
  report.logs.pausedScrollTop=await viewport.locator('.xterm-viewport').evaluate(el=>el.scrollTop);
  if(report.logs.pausedScrollTop!==0)throw new Error('Follow off scrolled');
  await page.getByRole('button',{name:'Follow paused',exact:true}).click();await fetch(`http://127.0.0.1:${fixture.port}/__load/append?count=50`);await viewport.getByText(/synthetic-log-100100/).waitFor();await rendered(page);
  report.logs.followBottomGap=await viewport.locator('.xterm-viewport').evaluate(el=>el.scrollHeight-el.scrollTop-el.clientHeight);
  report.afterLogs={rssBytes:rss(),heap:await cdp.send('Runtime.getHeapUsage')};
  // This synthetic transport implements skills, not provider configuration.
  await page.evaluate(()=>window.dispatchEvent(new CustomEvent('redjohn:navigate',{detail:{page:'settings',section:'skills'}})));
  report.skills=await skillsLoad(page);report.afterSkills={rssBytes:rss(),heap:await cdp.send('Runtime.getHeapUsage')};
  report.api=await fetch(`http://127.0.0.1:${fixture.port}/__load/metrics`).then(r=>r.json());report.network=requests();report.passed=true;
}catch(error){report.passed=false;report.error=String(error);throw error;}
finally{report.errors=errors;await writeFile(process.argv[2]??'/tmp/redjohn-desktop-ui-load.json',JSON.stringify(report,null,2));await electron?.close();await fixture.close();await rm(scratch,{recursive:true,force:true});console.log(JSON.stringify(report));}
