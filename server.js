import express from 'express';
import axios from 'axios';
import cors from 'cors';
import https from 'https';
import dns from 'dns';
import { URL } from 'url';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// === UTILITY FUNCTIONS ===

function normalizeDomain(input) {
  let d = input.trim().toLowerCase();
  d = d.replace(/^(https?:\/\/)/, '').replace(/\/.*$/, '').replace(/^www\./, '');
  return d;
}

function buildUrl(domain, protocol = 'https') {
  return `${protocol}://${domain}`;
}

function extractRootDomain(url) {
  try {
    let h = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    const p = h.split('.');
    if (p.length >= 2) return p.slice(-2).join('.');
    return h;
  } catch { return ''; }
}

// === DNS ANALYSIS ===

async function analyzeDNS(domain) {
  const r = { hasARecord:false, hasMXRecord:false, hasNSRecord:false, aRecords:[], mxRecords:[], nsRecords:[], cnameRecords:[], txtRecords:[], error:null };
  try {
    try { const a = await dns.promises.resolve4(domain); r.aRecords = a; r.hasARecord = a.length > 0; } catch {}
    try { const mx = await dns.promises.resolveMx(domain); r.mxRecords = mx.map(x => ({ priority:x.priority, exchange:x.exchange })); r.hasMXRecord = mx.length > 0; } catch {}
    try { const ns = await dns.promises.resolveNs(domain); r.nsRecords = ns; r.hasNSRecord = ns.length > 0; } catch {}
    try { const cn = await dns.promises.resolveCname(domain); r.cnameRecords = cn; } catch {}
    try { const tx = await dns.promises.resolveTxt(domain); r.txtRecords = tx.map(x => x.join('')); } catch {}
  } catch (e) { r.error = e.message; }
  return r;
}

// === SSL ANALYSIS ===

function analyzeSSL(domain) {
  return new Promise((resolve) => {
    const r = { valid:false, issuer:null, subject:null, validFrom:null, validTo:null, daysRemaining:null, protocol:null, error:null };
    try {
      const req = https.request({ hostname:domain, port:443, method:'HEAD', timeout:10000, rejectUnauthorized:false }, (res) => {
        const c = res.socket.getPeerCertificate();
        if (c && Object.keys(c).length > 0) {
          r.valid = res.socket.authorized;
          r.issuer = c.issuer ? (c.issuer.O || c.issuer.CN || 'Unknown') : 'Unknown';
          r.subject = c.subject ? (c.subject.CN || 'Unknown') : 'Unknown';
          r.validFrom = c.valid_from || null; r.validTo = c.valid_to || null;
          if (c.valid_to) r.daysRemaining = Math.floor((new Date(c.valid_to) - new Date()) / 86400000);
          r.protocol = res.socket.getProtocol ? res.socket.getProtocol() : null;
        }
        resolve(r);
      });
      req.on('error', (e) => { r.error = e.message; resolve(r); });
      req.on('timeout', () => { r.error = 'Timed out'; req.destroy(); resolve(r); });
      req.end();
    } catch (e) { r.error = e.message; resolve(r); }
  });
}

// === HTTP STATUS ANALYSIS ===

async function analyzeHTTPStatus(domain) {
  const r = { isUp:false, statusCode:null, statusText:null, responseTime:null, finalUrl:null, redirectChain:[], headers:{}, error:null };
  const start = Date.now();
  const hdrs = { 'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', 'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language':'en-US,en;q=0.5' };

  try {
    const res = await axios.get(buildUrl(domain), { timeout:15000, maxRedirects:10, validateStatus:()=>true, headers:hdrs });
    r.isUp = true; r.statusCode = res.status; r.statusText = res.statusText;
    r.responseTime = Date.now() - start;
    r.finalUrl = res.request?.res?.responseUrl || res.config?.url || null;
    r.headers = { server:res.headers['server']||null, poweredBy:res.headers['x-powered-by']||null, contentType:res.headers['content-type']||null };
    return { result:r, html:typeof res.data === 'string' ? res.data : '' };
  } catch (err) {
    r.responseTime = Date.now() - start;
    try {
      const fb = await axios.get(buildUrl(domain,'http'), { timeout:15000, maxRedirects:10, validateStatus:()=>true, headers:{'User-Agent':'Mozilla/5.0'} });
      r.isUp = true; r.statusCode = fb.status; r.statusText = fb.statusText;
      r.finalUrl = fb.request?.res?.responseUrl || fb.config?.url || null;
      return { result:r, html:typeof fb.data === 'string' ? fb.data : '' };
    } catch (e2) { r.error = err.code || err.message; return { result:r, html:'' }; }
  }
}

// ═══════════════════════════════════════════════════════════════
// CONTENT INTELLIGENCE ENGINE v2.1 (Bug fixes)
// ═══════════════════════════════════════════════════════════════

function analyzeContent(html, domain, finalUrl) {
  const analysis = {
    verdict:'VALID', confidence:0, reasons:[], flags:[], redirectInfo:null,
    details:{ title:null, metaDescription:null, hasBody:false, bodyTextLength:0, wordCount:0, uniqueWordCount:0, headings:[], links:{internal:0,external:0}, images:0, forms:0, scripts:0, iframes:0 }
  };

  // ════════════════════════════════════════════════════════════
  // PRE-CHECK: Cross-Domain Redirect via HTTP (before HTML parsing)
  // Catches: outlook.live.com → microsoft.com, etc.
  // ════════════════════════════════════════════════════════════
  if (finalUrl) {
    const origRoot = extractRootDomain(domain);
    const finalRoot = extractRootDomain(finalUrl);
    if (origRoot && finalRoot && origRoot !== finalRoot) {
      // HTTP-level cross-domain redirect detected
      analysis.verdict = 'CROSS_DOMAIN_REDIRECT'; analysis.confidence = 92;
      analysis.reasons.push('Website redirects to a different domain: ' + finalUrl);
      analysis.flags.push('CROSS_DOMAIN_REDIRECT');
      analysis.redirectInfo = { source:domain, target:finalUrl, targetDomain:finalRoot, method:'HTTP 3xx' };

      const spamPatterns = [/\/articles\/?$/i, /\/blog\/?$/i, /\/news\/?$/i, /dot-[a-z]+\.org/i, /searchhounds/i, /dot-guide/i, /dot-mom/i, /dot-consulting/i];
      if (spamPatterns.some(p => p.test(finalUrl))) {
        analysis.confidence = 97; analysis.flags.push('SUSPICIOUS_REDIRECT_TARGET');
        analysis.reasons.push('Redirect target matches known SEO spam / link farm patterns');
      }
      return analysis;
    }
  }

  if (!html || html.trim().length === 0) {
    // Empty HTML but we already checked HTTP redirect above
    analysis.verdict = 'NO_CONTENT'; analysis.confidence = 95;
    analysis.reasons.push('Empty or no HTML response received');
    return analysis;
  }

  // -- Extract basic details --
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  analysis.details.title = titleMatch ? titleMatch[1].trim().replace(/\s+/g, ' ') : null;

  const metaDescMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([\s\S]*?)["']/i);
  analysis.details.metaDescription = metaDescMatch ? metaDescMatch[1].trim() : null;

  let bodyMatch = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  let bodyText = bodyMatch ? bodyMatch[1] : html;
  bodyText = bodyText.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<noscript[\s\S]*?<\/noscript>/gi, '').replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/gi, ' ').replace(/&#\d+;/gi, ' ').replace(/\s+/g, ' ').trim();

  analysis.details.hasBody = bodyText.length > 0;
  analysis.details.bodyTextLength = bodyText.length;
  const words = bodyText.split(/\s+/).filter(w => w.length > 1);
  analysis.details.wordCount = words.length;
  const uniqueWords = new Set(words.map(w => w.toLowerCase()));
  analysis.details.uniqueWordCount = uniqueWords.size;

  // Repetition ratio: how repetitive is the text?
  const repetitionRatio = analysis.details.wordCount > 0 ? analysis.details.uniqueWordCount / analysis.details.wordCount : 0;

  const headingMatches = html.match(/<h[1-6][^>]*>([\s\S]*?)<\/h[1-6]>/gi) || [];
  analysis.details.headings = headingMatches.map(h => h.replace(/<[^>]+>/g, '').trim()).filter(h => h.length > 0);
  analysis.details.images = (html.match(/<img[\s ]/gi) || []).length;
  analysis.details.forms = (html.match(/<form[\s ]/gi) || []).length;
  analysis.details.scripts = (html.match(/<script[\s>]/gi) || []).length;
  analysis.details.iframes = (html.match(/<iframe[\s ]/gi) || []).length;

  const linkMatches = html.match(/<a[^>]+href=["']([^"']+)["']/gi) || [];
  linkMatches.forEach(link => {
    const hm = link.match(/href=["']([^"']+)["']/i);
    if (hm) {
      const href = hm[1];
      if (href.includes(domain) || href.startsWith('/') || href.startsWith('#') || href.startsWith('.')) analysis.details.links.internal++;
      else if (href.startsWith('http')) analysis.details.links.external++;
    }
  });

  // ════════════════════════════════════════════════════════════
  // DETECTION 1: Cross-Domain Redirect (JS / Meta Refresh)
  // Catches: timanjel.co, mikasprachkurs.store, etc.
  // ════════════════════════════════════════════════════════════

  let jsRedirectTarget = null;
  const jsRedirectPatterns = [
    /window\.location\s*(?:\.href)?\s*=\s*["']([^"']+)["']/i,
    /window\.location\.replace\s*\(\s*["']([^"']+)["']\s*\)/i,
    /window\.location\.assign\s*\(\s*["']([^"']+)["']\s*\)/i,
    /document\.location\s*(?:\.href)?\s*=\s*["']([^"']+)["']/i,
    /location\.href\s*=\s*["']([^"']+)["']/i,
    /location\.replace\s*\(\s*["']([^"']+)["']\s*\)/i,
    /top\.location\s*(?:\.href)?\s*=\s*["']([^"']+)["']/i,
    /self\.location\s*(?:\.href)?\s*=\s*["']([^"']+)["']/i,
    // Additional patterns: setTimeout/setInterval redirects
    /setTimeout\s*\(\s*(?:function\s*\(\)\s*\{)?\s*(?:window\.)?location\s*(?:\.href)?\s*=\s*["']([^"']+)["']/i,
    // Meta http-equiv in JS
    /url=["']?(https?:\/\/[^"'\s>]+)/i
  ];

  for (const p of jsRedirectPatterns) {
    const m = html.match(p);
    if (m && m[1] && (m[1].startsWith('http') || m[1].startsWith('//'))) { jsRedirectTarget = m[1]; break; }
  }

  const metaRefreshMatch = html.match(/<meta[^>]*http-equiv=["']refresh["'][^>]*content=["']\d+;\s*url=([^"']+)["']/i);
  if (!jsRedirectTarget && metaRefreshMatch) jsRedirectTarget = metaRefreshMatch[1];

  if (jsRedirectTarget) {
    const targetRoot = extractRootDomain(jsRedirectTarget);
    const sourceRoot = extractRootDomain(domain);
    if (targetRoot && sourceRoot && targetRoot !== sourceRoot) {
      analysis.verdict = 'CROSS_DOMAIN_REDIRECT'; analysis.confidence = 92;
      analysis.reasons.push('Website redirects to an unrelated domain: ' + jsRedirectTarget);
      analysis.flags.push('CROSS_DOMAIN_REDIRECT');
      analysis.redirectInfo = { source:domain, target:jsRedirectTarget, targetDomain:targetRoot, method: metaRefreshMatch ? 'Meta Refresh' : 'JavaScript' };

      const spamPatterns = [/\/articles\/?$/i, /\/blog\/?$/i, /\/news\/?$/i, /dot-[a-z]+\.org/i, /searchhounds/i, /dot-guide/i, /dot-mom/i, /dot-consulting/i];
      if (spamPatterns.some(p => p.test(jsRedirectTarget))) {
        analysis.confidence = 97; analysis.flags.push('SUSPICIOUS_REDIRECT_TARGET');
        analysis.reasons.push('Redirect target matches known SEO spam / link farm patterns');
      }
      return analysis;
    }
  }

  // ════════════════════════════════════════════════════════════
  // DETECTION 2: Website Builder Shell Sites (IMPROVED)
  // Catches: GoDaddy one-page templates with just brand + contact form
  // monarchpartyrentals.com, maranathageneration.com, etc.
  // ════════════════════════════════════════════════════════════

  // --- Direct GoDaddy shell template detection ---
  // Pattern: brand name repeated 3+ times in headings + "Drop us a line" + reCAPTCHA + cookies
  const gdShellSignals = [
    /drop us a line/i,
    /sign up for our email list/i,
    /this site is protected by recaptcha/i,
    /this website uses cookies[\s\S]{0,300}accept/i,
    /powered by/i
  ];
  const gdShellHits = gdShellSignals.filter(p => p.test(html)).length;

  // Check if brand/title is repeated excessively in headings
  const titleText = (analysis.details.title || '').toLowerCase().trim();
  let titleRepeatInHeadings = 0;
  if (titleText.length > 2) {
    analysis.details.headings.forEach(h => {
      if (h.toLowerCase().includes(titleText) || titleText.includes(h.toLowerCase())) titleRepeatInHeadings++;
    });
  }

  // GoDaddy builder indicators
  const gdIndicators = [/wsimg\.com/i, /godaddy/i, /websites\.godaddy\.com/i, /secureserver\.net/i, /cdn-website\.com/i];
  const hasGDIndicator = gdIndicators.some(p => p.test(html));

  // SHELL SITE detection: multiple ways to trigger
  const isShellSite = (
    // Path A: GoDaddy shell signals (3+ signals) + low content
    (gdShellHits >= 3 && analysis.details.wordCount < 200) ||
    // Path B: Brand repeated in headings + contact form signals + low content
    (titleRepeatInHeadings >= 2 && gdShellHits >= 2 && analysis.details.wordCount < 200) ||
    // Path C: Builder indicator + shell signals + very repetitive content
    (hasGDIndicator && gdShellHits >= 2 && repetitionRatio < 0.35 && analysis.details.wordCount < 250) ||
    // Path D: Very repetitive + contact form + low unique words
    (repetitionRatio < 0.3 && analysis.details.uniqueWordCount < 50 && gdShellHits >= 2 && analysis.details.wordCount < 200)
  );

  if (isShellSite) {
    analysis.verdict = 'SHELL_SITE';
    analysis.confidence = Math.min(60 + gdShellHits * 8 + (titleRepeatInHeadings >= 2 ? 10 : 0) + (hasGDIndicator ? 10 : 0), 95);
    analysis.reasons.push('Website is a template shell — only brand name, tagline, and contact form. No meaningful business content.');
    analysis.flags.push('SHELL_SITE');
    if (hasGDIndicator) analysis.flags.push('BUILDER_GODADDY');
    return analysis;
  }

  // Also check other builders (Wix, Squarespace, etc.)
  const otherBuilderShells = [
    { name:'Wix', indicators:[/wix\.com/i, /wixsite\.com/i, /parastorage\.com/i], signals:[/this is a blank site/i, /welcome to your site/i, /start editing/i] },
    { name:'Squarespace', indicators:[/squarespace\.com/i, /sqsp\.net/i], signals:[/it all begins with an idea/i] },
    { name:'WordPress', indicators:[/wordpress\.com/i], signals:[/just another wordpress site/i, /hello world/i, /sample page/i] }
  ];

  for (const b of otherBuilderShells) {
    const hasIndicator = b.indicators.some(p => p.test(html));
    const signalHits = b.signals.filter(p => p.test(html)).length;
    if (hasIndicator && signalHits >= 1 && analysis.details.uniqueWordCount < 60 && analysis.details.wordCount < 150) {
      analysis.verdict = 'SHELL_SITE';
      analysis.confidence = 85;
      analysis.reasons.push(b.name + ' template shell with no meaningful content.');
      analysis.flags.push('SHELL_SITE', 'BUILDER_' + b.name.toUpperCase());
      return analysis;
    }
  }

  // ════════════════════════════════════════════════════════════
  // DETECTION 3: Parked Domain / For Sale
  // ════════════════════════════════════════════════════════════

  const parkedPatterns = [
    /this domain is (for sale|parked|available)/i, /buy this domain/i, /domain (is )?parked/i,
    /parked (by|at|with|domain)/i, /this (webpage|page|site|website) is parked/i,
    /domain (name )?for sale/i, /purchase this domain/i, /make (an )?offer (on|for) this domain/i,
    /hugedomains|sedo|dan\.com|afternic|godaddy\s*auctions/i, /sedoparking/i, /above\.com/i,
    /parkingcrew/i, /domainmarket/i, /is for sale[\s!.]/i, /inquire about (this|purchasing)/i,
    /domain.*premium/i, /get this domain/i, /sponsored\s+listings/i, /related\s+searches/i
  ];

  let parkedScore = 0;
  parkedPatterns.forEach(p => { if (p.test(html)) parkedScore += 20; });
  if (parkedScore > 0) {
    analysis.verdict = 'PARKED'; analysis.confidence = Math.min(parkedScore, 95);
    analysis.reasons.push('Domain appears to be parked or for sale'); analysis.flags.push('PARKED'); return analysis;
  }

  // ════════════════════════════════════════════════════════════
  // DETECTION 4: Coming Soon / Under Construction
  // ════════════════════════════════════════════════════════════

  const comingSoonPatterns = [
    /coming\s+soon/i, /launching\s+soon/i, /under\s+construction/i,
    /we['\u2019]?re\s+(building|launching|coming)/i, /site\s+(is\s+)?(under\s+construction|being\s+built|coming\s+soon)/i,
    /stay\s+tuned/i, /something\s+(big|great|new|exciting|amazing)\s+is\s+(coming|on\s+the\s+way|brewing)/i,
    /we['\u2019]?ll\s+be\s+(back|live|launching|ready)\s+soon/i, /watch\s+this\s+space/i,
    /new\s+website\s+(is\s+)?(coming|under)/i, /opening\s+soon/i, /check\s+back\s+(soon|later)/i,
    /almost\s+(here|ready|there|done)/i, /notify\s+me\s+when/i, /get\s+notified/i,
    /work\s+in\s+progress/i, /pardon\s+our\s+(dust|mess)/i, /exciting\s+things\s+(are\s+)?coming/i
  ];

  let csScore = 0;
  comingSoonPatterns.forEach(p => { if (p.test(html)) csScore += 15; });
  if (csScore > 0 && analysis.details.wordCount < 100) csScore += 20;
  if (csScore > 0 && /countdown|timer|days.*hours.*min/i.test(html)) csScore += 15;

  if (csScore > 15) {
    analysis.verdict = 'COMING_SOON'; analysis.confidence = Math.min(csScore, 95);
    analysis.reasons.push('Website appears to be a coming soon / under construction page'); analysis.flags.push('COMING_SOON'); return analysis;
  }

  // ════════════════════════════════════════════════════════════
  // DETECTION 5: Default Server Page
  // ════════════════════════════════════════════════════════════

  const defaultPagePatterns = [
    /default\s+(web\s+)?page/i, /this\s+is\s+(the|a)\s+default/i, /web\s+server\s+(is\s+)?working/i,
    /it\s+works/i, /apache.*default\s+page/i, /welcome\s+to\s+nginx/i, /iis\s+windows\s+server/i,
    /test\s+page.*apache/i, /congratulations.*successfully\s+installed/i, /placeholder\s+page/i,
    /website\s+is\s+(almost|not\s+yet)\s+ready/i
  ];

  if (defaultPagePatterns.some(p => p.test(html))) {
    analysis.verdict = 'DEFAULT_PAGE'; analysis.confidence = 85;
    analysis.reasons.push('Website shows a default server/hosting page'); analysis.flags.push('DEFAULT_PAGE'); return analysis;
  }

  // ════════════════════════════════════════════════════════════
  // DETECTION 6: Suspended
  // ════════════════════════════════════════════════════════════

  const suspendedPatterns = [
    /account\s+(has\s+been\s+)?suspended/i, /this\s+(site|account|website)\s+(has\s+been|is)\s+suspended/i,
    /website\s+suspended/i, /hosting\s+account\s+suspended/i, /bandwidth\s+(limit\s+)?exceeded/i,
    /account\s+deactivated/i, /access\s+to\s+this\s+site\s+has\s+been\s+disabled/i
  ];

  if (suspendedPatterns.some(p => p.test(html))) {
    analysis.verdict = 'SUSPENDED'; analysis.confidence = 90;
    analysis.reasons.push('Website account appears to be suspended'); analysis.flags.push('SUSPENDED'); return analysis;
  }

  // ════════════════════════════════════════════════════════════
  // DETECTION 7: No Meaningful Content
  // ════════════════════════════════════════════════════════════

  if (analysis.details.wordCount < 10) {
    analysis.verdict = 'NO_CONTENT'; analysis.confidence = 92;
    analysis.reasons.push('Page has virtually no text content (fewer than 10 words)'); return analysis;
  }
  if (analysis.details.wordCount < 30 && analysis.details.headings.length === 0 && analysis.details.images === 0) {
    analysis.verdict = 'NO_CONTENT'; analysis.confidence = 80;
    analysis.reasons.push('Page has minimal content with no headings or images'); return analysis;
  }
  // Highly repetitive content = likely template/placeholder
  if (analysis.details.wordCount > 20 && repetitionRatio < 0.25) {
    analysis.verdict = 'NO_CONTENT'; analysis.confidence = 82;
    analysis.reasons.push('Page content is extremely repetitive — likely a template placeholder'); analysis.flags.push('REPETITIVE_CONTENT'); return analysis;
  }
  if (analysis.details.wordCount > 30 && analysis.details.uniqueWordCount < 25) {
    analysis.verdict = 'NO_CONTENT'; analysis.confidence = 78;
    analysis.reasons.push('Page has very few unique words — likely placeholder content'); analysis.flags.push('REPETITIVE_CONTENT'); return analysis;
  }

  // ════════════════════════════════════════════════════════════
  // DETECTION 8: Political Campaign Site (STRICTER - v2.1 fix)
  // Must have STRONG political signals, not just generic words
  // ════════════════════════════════════════════════════════════

  // Strong signals (high confidence - things ONLY political sites have)
  const strongPoliticalPatterns = [
    /paid\s+for\s+by/i,                              // FEC disclosure (very strong)
    /authorized\s+by\s+[\w\s]+committee/i,           // Authorization disclosure
    /donate\s+to\s+(our|the|my)\s+campaign/i,        // Campaign donation
    /find\s+a\s+(voting|polling)\s+location/i,       // Voter info
    /registered\s+to\s+vote/i,                       // Voter registration
    /vote\s+(for|on)\s+(may|november|tuesday|monday|march|april|june|july|august|september|october|december|\d)/i,  // Specific vote dates
    /political\s+committee/i,                        // Political committee
    /political\s+action\s+committee/i,               // PAC
  ];

  // Medium signals (need 2+ to count)
  const mediumPoliticalPatterns = [
    /running\s+for\s+(office|mayor|governor|council|commissioner|congress|senate|board|judge|sheriff|attorney)/i,
    /county\s+commissioner/i,
    /campaign\s+(team|headquarters|office|donation|contribution)/i,
    /join\s+(my|our|the)\s+campaign/i,
    /your\s+vote\s+(matters|counts)/i,
    /on\s+the\s+ballot/i,
    /election\s+day/i,
    /primary\s+election/i,
    /general\s+election/i
  ];

  // Domain patterns
  const politicalDomainPatterns = [/^vote\d*[a-z]/i, /^elect[a-z]/i];

  let strongHits = strongPoliticalPatterns.filter(p => p.test(html)).length;
  let mediumHits = mediumPoliticalPatterns.filter(p => p.test(html)).length;
  let domainHits = politicalDomainPatterns.filter(p => p.test(domain)).length;

  // Require at least 1 strong signal, OR 2+ medium signals + domain match
  const isPolitical = (strongHits >= 1 && (mediumHits >= 1 || domainHits >= 1)) ||
                      (mediumHits >= 2 && domainHits >= 1) ||
                      (strongHits >= 2);

  if (isPolitical) {
    analysis.verdict = 'POLITICAL_CAMPAIGN';
    analysis.confidence = Math.min(20 + (analysis.details.wordCount > 100 ? 20 : 0) + (analysis.details.wordCount > 500 ? 15 : 0) + (analysis.details.headings.length > 2 ? 10 : 0) + (analysis.details.images > 0 ? 10 : 0) + (analysis.details.links.internal > 3 ? 10 : 0) + (analysis.details.metaDescription ? 10 : 0), 98);
    analysis.reasons.push('Website is a political campaign site with election-related content');
    analysis.flags.push('POLITICAL_CAMPAIGN');
    if (strongHits > 0) analysis.flags.push('HAS_FEC_DISCLOSURE');
    return analysis;
  }

  // ════════════════════════════════════════════════════════════
  // FINAL: VALID
  // ════════════════════════════════════════════════════════════

  analysis.verdict = 'VALID';
  analysis.confidence = Math.min(20 + (analysis.details.wordCount > 100 ? 20 : 0) + (analysis.details.wordCount > 500 ? 15 : 0) + (analysis.details.headings.length > 2 ? 10 : 0) + (analysis.details.images > 0 ? 10 : 0) + (analysis.details.links.internal > 3 ? 10 : 0) + (analysis.details.forms > 0 ? 5 : 0) + (analysis.details.metaDescription ? 10 : 0), 98);
  analysis.reasons.push('Website has substantive content and appears to be a legitimate, active site');
  return analysis;
}

// === MAIN ANALYSIS ENDPOINT ===

app.post('/api/analyze', async (req, res) => {
  const { domain: rawDomain } = req.body;
  if (!rawDomain || rawDomain.trim().length === 0) return res.status(400).json({ error:'Domain is required' });

  const domain = normalizeDomain(rawDomain);
  const timestamp = new Date().toISOString();
  console.log(`\n[SCAN] ${domain} at ${timestamp}`);

  try {
    const [dnsResults, sslResults, httpResults] = await Promise.all([analyzeDNS(domain), analyzeSSL(domain), analyzeHTTPStatus(domain)]);
    const { result: httpStatus, html } = httpResults;
    const contentAnalysis = analyzeContent(html, domain, httpStatus.finalUrl);

    let overallStatus = 'UNKNOWN', statusColor = 'gray';
    if (!dnsResults.hasARecord && !httpStatus.isUp) { overallStatus = 'DEAD'; statusColor = 'red'; }
    else if (!httpStatus.isUp) { overallStatus = 'DOWN'; statusColor = 'red'; }
    else if (contentAnalysis.verdict === 'CROSS_DOMAIN_REDIRECT') { overallStatus = 'CROSS_DOMAIN_REDIRECT'; statusColor = 'red'; }
    else if (contentAnalysis.verdict === 'PARKED') { overallStatus = 'PARKED'; statusColor = 'orange'; }
    else if (contentAnalysis.verdict === 'COMING_SOON') { overallStatus = 'COMING_SOON'; statusColor = 'yellow'; }
    else if (contentAnalysis.verdict === 'SHELL_SITE') { overallStatus = 'SHELL_SITE'; statusColor = 'orange'; }
    else if (contentAnalysis.verdict === 'NO_CONTENT') { overallStatus = 'NO_CONTENT'; statusColor = 'orange'; }
    else if (contentAnalysis.verdict === 'DEFAULT_PAGE') { overallStatus = 'DEFAULT_PAGE'; statusColor = 'orange'; }
    else if (contentAnalysis.verdict === 'SUSPENDED') { overallStatus = 'SUSPENDED'; statusColor = 'red'; }
    else if (contentAnalysis.verdict === 'POLITICAL_CAMPAIGN') { overallStatus = 'POLITICAL_CAMPAIGN'; statusColor = 'blue'; }
    else if (httpStatus.statusCode >= 200 && httpStatus.statusCode < 400 && contentAnalysis.verdict === 'VALID') { overallStatus = 'ACTIVE'; statusColor = 'green'; }
    else { overallStatus = 'ISSUES'; statusColor = 'yellow'; }

    const genuinelyValid = ['ACTIVE','POLITICAL_CAMPAIGN'].includes(overallStatus);
    console.log(`  -> ${overallStatus} | ${contentAnalysis.verdict} | Valid: ${genuinelyValid} | Words: ${contentAnalysis.details.wordCount} | Unique: ${contentAnalysis.details.uniqueWordCount}`);
    res.json({ domain, timestamp, overallStatus, statusColor, isGenuinelyValid:genuinelyValid, dns:dnsResults, ssl:sslResults, http:httpStatus, content:contentAnalysis });
  } catch (err) {
    console.error(`  -> ERROR: ${err.message}`);
    res.status(500).json({ domain, error:'Analysis failed', message:err.message });
  }
});

// === BULK ANALYSIS ENDPOINT ===

app.post('/api/analyze/bulk', async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains) || domains.length === 0) return res.status(400).json({ error:'Provide an array of domains' });
  if (domains.length > 20) return res.status(400).json({ error:'Maximum 20 domains per request' });

  console.log(`\n[BULK] Analyzing ${domains.length} domains...`);
  const results = [];

  for (const rawDomain of domains) {
    try {
      const domain = normalizeDomain(rawDomain);
      const [dnsResults, sslResults, httpResults] = await Promise.all([analyzeDNS(domain), analyzeSSL(domain), analyzeHTTPStatus(domain)]);
      const { result: httpStatus, html } = httpResults;
      const contentAnalysis = analyzeContent(html, domain, httpStatus.finalUrl);

      let overallStatus = 'UNKNOWN';
      if (!dnsResults.hasARecord && !httpStatus.isUp) overallStatus = 'DEAD';
      else if (!httpStatus.isUp) overallStatus = 'DOWN';
      else if (contentAnalysis.verdict === 'CROSS_DOMAIN_REDIRECT') overallStatus = 'CROSS_DOMAIN_REDIRECT';
      else if (contentAnalysis.verdict === 'PARKED') overallStatus = 'PARKED';
      else if (contentAnalysis.verdict === 'COMING_SOON') overallStatus = 'COMING_SOON';
      else if (contentAnalysis.verdict === 'SHELL_SITE') overallStatus = 'SHELL_SITE';
      else if (contentAnalysis.verdict === 'NO_CONTENT') overallStatus = 'NO_CONTENT';
      else if (contentAnalysis.verdict === 'DEFAULT_PAGE') overallStatus = 'DEFAULT_PAGE';
      else if (contentAnalysis.verdict === 'SUSPENDED') overallStatus = 'SUSPENDED';
      else if (contentAnalysis.verdict === 'POLITICAL_CAMPAIGN') overallStatus = 'POLITICAL_CAMPAIGN';
      else if (httpStatus.statusCode >= 200 && httpStatus.statusCode < 400 && contentAnalysis.verdict === 'VALID') overallStatus = 'ACTIVE';
      else overallStatus = 'ISSUES';

      results.push({ domain, overallStatus, isGenuinelyValid:['ACTIVE','POLITICAL_CAMPAIGN'].includes(overallStatus), statusCode:httpStatus.statusCode, verdict:contentAnalysis.verdict, confidence:contentAnalysis.confidence, reasons:contentAnalysis.reasons, flags:contentAnalysis.flags, redirectInfo:contentAnalysis.redirectInfo, title:contentAnalysis.details.title, wordCount:contentAnalysis.details.wordCount, uniqueWordCount:contentAnalysis.details.uniqueWordCount });
      console.log(`  [OK] ${domain} -> ${overallStatus}`);
    } catch (err) {
      results.push({ domain:normalizeDomain(rawDomain), overallStatus:'ERROR', isGenuinelyValid:false, error:err.message });
      console.log(`  [ERR] ${normalizeDomain(rawDomain)} -> ${err.message}`);
    }
  }
  res.json({ total:results.length, results });
});

app.get('/api/health', (req, res) => res.json({ status:'ok', uptime:process.uptime() }));

app.listen(PORT, () => {
  console.log(`\n=== Website Intelligence v2.1 ===`);
  console.log(`Dashboard: http://localhost:${PORT}`);
  console.log(`API:       http://localhost:${PORT}/api/analyze\n`);
});
