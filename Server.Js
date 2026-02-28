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
  let domain = input.trim().toLowerCase();
  domain = domain.replace(/^(https?:\/\/)/, '');
  domain = domain.replace(/\/.*$/, '');
  domain = domain.replace(/^www\./, '');
  return domain;
}

function buildUrl(domain, protocol = 'https') {
  return `${protocol}://${domain}`;
}

function extractRootDomain(url) {
  try {
    let hostname = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    const parts = hostname.split('.');
    if (parts.length >= 2) return parts.slice(-2).join('.');
    return hostname;
  } catch { return ''; }
}

// === DNS ANALYSIS ===

async function analyzeDNS(domain) {
  const results = { hasARecord: false, hasMXRecord: false, hasNSRecord: false, aRecords: [], mxRecords: [], nsRecords: [], cnameRecords: [], txtRecords: [], error: null };
  try {
    try { const a = await dns.promises.resolve4(domain); results.aRecords = a; results.hasARecord = a.length > 0; } catch {}
    try { const mx = await dns.promises.resolveMx(domain); results.mxRecords = mx.map(r => ({ priority: r.priority, exchange: r.exchange })); results.hasMXRecord = mx.length > 0; } catch {}
    try { const ns = await dns.promises.resolveNs(domain); results.nsRecords = ns; results.hasNSRecord = ns.length > 0; } catch {}
    try { const cn = await dns.promises.resolveCname(domain); results.cnameRecords = cn; } catch {}
    try { const tx = await dns.promises.resolveTxt(domain); results.txtRecords = tx.map(r => r.join('')); } catch {}
  } catch (err) { results.error = err.message; }
  return results;
}

// === SSL ANALYSIS ===

function analyzeSSL(domain) {
  return new Promise((resolve) => {
    const result = { valid: false, issuer: null, subject: null, validFrom: null, validTo: null, daysRemaining: null, protocol: null, error: null };
    try {
      const req = https.request({ hostname: domain, port: 443, method: 'HEAD', timeout: 10000, rejectUnauthorized: false }, (res) => {
        const cert = res.socket.getPeerCertificate();
        if (cert && Object.keys(cert).length > 0) {
          result.valid = res.socket.authorized;
          result.issuer = cert.issuer ? (cert.issuer.O || cert.issuer.CN || 'Unknown') : 'Unknown';
          result.subject = cert.subject ? (cert.subject.CN || 'Unknown') : 'Unknown';
          result.validFrom = cert.valid_from || null;
          result.validTo = cert.valid_to || null;
          if (cert.valid_to) { const exp = new Date(cert.valid_to); result.daysRemaining = Math.floor((exp - new Date()) / 86400000); }
          result.protocol = res.socket.getProtocol ? res.socket.getProtocol() : null;
        }
        resolve(result);
      });
      req.on('error', (e) => { result.error = e.message; resolve(result); });
      req.on('timeout', () => { result.error = 'Timed out'; req.destroy(); resolve(result); });
      req.end();
    } catch (e) { result.error = e.message; resolve(result); }
  });
}

// === HTTP STATUS ANALYSIS ===

async function analyzeHTTPStatus(domain) {
  const result = { isUp: false, statusCode: null, statusText: null, responseTime: null, finalUrl: null, redirectChain: [], headers: {}, error: null };
  const start = Date.now();
  const hdrs = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5' };

  try {
    const res = await axios.get(buildUrl(domain), { timeout: 15000, maxRedirects: 10, validateStatus: () => true, headers: hdrs });
    result.isUp = true; result.statusCode = res.status; result.statusText = res.statusText;
    result.responseTime = Date.now() - start;
    result.finalUrl = res.request?.res?.responseUrl || res.config?.url || null;
    result.headers = { server: res.headers['server'] || null, poweredBy: res.headers['x-powered-by'] || null, contentType: res.headers['content-type'] || null };
    return { result, html: typeof res.data === 'string' ? res.data : '' };
  } catch (err) {
    result.responseTime = Date.now() - start;
    try {
      const fb = await axios.get(buildUrl(domain, 'http'), { timeout: 15000, maxRedirects: 10, validateStatus: () => true, headers: { 'User-Agent': 'Mozilla/5.0' } });
      result.isUp = true; result.statusCode = fb.status; result.statusText = fb.statusText;
      result.finalUrl = fb.request?.res?.responseUrl || fb.config?.url || null;
      return { result, html: typeof fb.data === 'string' ? fb.data : '' };
    } catch (e2) { result.error = err.code || err.message; return { result, html: '' }; }
  }
}

// ═══════════════════════════════════════════════════════════════
// CONTENT INTELLIGENCE ENGINE v2.0
// ═══════════════════════════════════════════════════════════════

function analyzeContent(html, domain, finalUrl) {
  const analysis = {
    verdict: 'VALID', confidence: 0, reasons: [], flags: [], redirectInfo: null,
    details: { title: null, metaDescription: null, hasBody: false, bodyTextLength: 0, wordCount: 0, uniqueWordCount: 0, headings: [], links: { internal: 0, external: 0 }, images: 0, forms: 0, scripts: 0, iframes: 0 }
  };

  if (!html || html.trim().length === 0) {
    analysis.verdict = 'NO_CONTENT'; analysis.confidence = 95; analysis.reasons.push('Empty or no HTML response received'); return analysis;
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
  // e.g. timanjel.co -> dot-mom.org, palmsbreezeinsurance.com -> searchhounds.com
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
    /self\.location\s*(?:\.href)?\s*=\s*["']([^"']+)["']/i
  ];

  for (const p of jsRedirectPatterns) {
    const m = html.match(p);
    if (m && m[1] && (m[1].startsWith('http') || m[1].startsWith('//'))) { jsRedirectTarget = m[1]; break; }
  }

  const metaRefreshMatch = html.match(/<meta[^>]*http-equiv=["']refresh["'][^>]*content=["']\d+;\s*url=([^"']+)["']/i);
  if (!jsRedirectTarget && metaRefreshMatch) jsRedirectTarget = metaRefreshMatch[1];

  let httpRedirectCrossDomain = false;
  if (finalUrl) {
    const origRoot = extractRootDomain(domain);
    const finalRoot = extractRootDomain(finalUrl);
    if (origRoot && finalRoot && origRoot !== finalRoot) {
      httpRedirectCrossDomain = true;
      if (!jsRedirectTarget) jsRedirectTarget = finalUrl;
    }
  }

  if (jsRedirectTarget) {
    const targetRoot = extractRootDomain(jsRedirectTarget);
    const sourceRoot = extractRootDomain(domain);
    if (targetRoot && sourceRoot && targetRoot !== sourceRoot) {
      analysis.verdict = 'CROSS_DOMAIN_REDIRECT'; analysis.confidence = 92;
      analysis.reasons.push('Website redirects to an unrelated domain: ' + jsRedirectTarget);
      analysis.flags.push('CROSS_DOMAIN_REDIRECT');
      analysis.redirectInfo = { source: domain, target: jsRedirectTarget, targetDomain: targetRoot, method: httpRedirectCrossDomain ? 'HTTP 3xx' : (metaRefreshMatch ? 'Meta Refresh' : 'JavaScript') };

      const spamPatterns = [/\/articles\/?$/i, /\/blog\/?$/i, /\/news\/?$/i, /dot-[a-z]+\.org/i, /searchhounds/i, /dot-guide/i, /dot-mom/i];
      if (spamPatterns.some(p => p.test(jsRedirectTarget))) {
        analysis.confidence = 97; analysis.flags.push('SUSPICIOUS_REDIRECT_TARGET');
        analysis.reasons.push('Redirect target matches known SEO spam / link farm patterns');
      }
      return analysis;
    }
  }

  // ════════════════════════════════════════════════════════════
  // DETECTION 2: Website Builder Shell Sites
  // e.g. allincarehomes.com, ardaventures.us, athletesonboard.com
  // Template sites with just a brand name + tagline + contact form
  // ════════════════════════════════════════════════════════════

  const builderConfigs = {
    godaddy: {
      indicators: [/wsimg\.com/i, /godaddy/i, /websites\.godaddy\.com/i, /secureserver\.net/i],
      shellSignals: [/drop us a line/i, /sign up for our email list/i, /this site is protected by recaptcha/i, /this website uses cookies[\s\S]{0,200}accept/i]
    },
    wix: {
      indicators: [/wix\.com/i, /wixsite\.com/i, /parastorage\.com/i],
      shellSignals: [/this is a blank site/i, /welcome to your site/i, /start editing/i]
    },
    squarespace: {
      indicators: [/squarespace\.com/i, /sqsp\.net/i],
      shellSignals: [/it all begins with an idea/i]
    },
    weebly: { indicators: [/weebly\.com/i], shellSignals: [] },
    wordpress: {
      indicators: [/wordpress\.com/i, /wp-content/i],
      shellSignals: [/just another wordpress site/i, /hello world/i, /sample page/i]
    }
  };

  let detectedBuilder = null, bIndicators = 0, bShellHits = 0;
  for (const [name, cfg] of Object.entries(builderConfigs)) {
    let iHits = 0, sHits = 0;
    cfg.indicators.forEach(p => { if (p.test(html)) iHits++; });
    cfg.shellSignals.forEach(p => { if (p.test(html)) sHits++; });
    if (iHits > 0 && (iHits + sHits) > (bIndicators + bShellHits)) { detectedBuilder = name; bIndicators = iHits; bShellHits = sHits; }
  }

  const hasOnlyContactForm = analysis.details.forms > 0 && analysis.details.wordCount < 120 && /contact\s+us|drop\s+us\s+a\s+line|get\s+in\s+touch|send\s+us\s+a\s+message/i.test(html);

  const hasRepetitiveContent = (() => {
    if (!analysis.details.title || analysis.details.headings.length === 0) return false;
    const tw = new Set(analysis.details.title.toLowerCase().split(/\s+/));
    const hw = analysis.details.headings.map(h => h.toLowerCase()).join(' ').split(/\s+/);
    const overlap = hw.filter(w => tw.has(w)).length;
    return overlap > 2 && (overlap / hw.length) > 0.4;
  })();

  const isShellSite = detectedBuilder && bShellHits >= 1 && analysis.details.uniqueWordCount < 60 && analysis.details.wordCount < 150;

  if (isShellSite || (hasOnlyContactForm && hasRepetitiveContent && analysis.details.uniqueWordCount < 60)) {
    const bName = detectedBuilder ? detectedBuilder.charAt(0).toUpperCase() + detectedBuilder.slice(1) : 'Website builder';
    analysis.verdict = 'SHELL_SITE';
    analysis.confidence = Math.min(70 + bShellHits * 10 + (hasRepetitiveContent ? 10 : 0), 95);
    analysis.reasons.push(bName + ' template shell — only brand name, tagline, and contact form. No meaningful content.');
    analysis.flags.push('SHELL_SITE');
    if (detectedBuilder) analysis.flags.push('BUILDER_' + detectedBuilder.toUpperCase());
    return analysis;
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
    /we[''\u2019]?re\s+(building|launching|coming)/i, /site\s+(is\s+)?(under\s+construction|being\s+built|coming\s+soon)/i,
    /stay\s+tuned/i, /something\s+(big|great|new|exciting|amazing)\s+is\s+(coming|on\s+the\s+way|brewing)/i,
    /we[''\u2019]?ll\s+be\s+(back|live|launching|ready)\s+soon/i, /watch\s+this\s+space/i,
    /new\s+website\s+(is\s+)?(coming|under)/i, /opening\s+soon/i, /check\s+back\s+(soon|later)/i,
    /almost\s+(here|ready|there|done)/i, /notify\s+me\s+when/i, /get\s+notified/i,
    /sign\s+up\s+(for|to)\s+(be\s+)?notif/i, /work\s+in\s+progress/i, /pardon\s+our\s+(dust|mess)/i,
    /exciting\s+things\s+(are\s+)?coming/i
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
  // DETECTION 5: Hosting Provider Default Page
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
  if (analysis.details.wordCount > 30 && analysis.details.uniqueWordCount < 25) {
    analysis.verdict = 'NO_CONTENT'; analysis.confidence = 78;
    analysis.reasons.push('Page content is extremely repetitive — likely a template placeholder'); analysis.flags.push('REPETITIVE_CONTENT'); return analysis;
  }

  // ════════════════════════════════════════════════════════════
  // DETECTION 8: Political Campaign Site
  // ════════════════════════════════════════════════════════════

  const politicalPatterns = [
    /vote\s+(for|on|may|november|tuesday)/i, /campaign/i, /commissioner/i,
    /county\s+(commissioner|council|board|supervisor)/i, /running\s+for/i, /elect\s/i, /election/i,
    /paid\s+for\s+by/i, /authorized\s+by/i, /political\s+committee/i,
    /donate\s+to\s+(our|the|my)\s+campaign/i, /join\s+(my|our|the)\s+(team|campaign|movement)/i,
    /your\s+vote/i, /(congress|senate|mayor|governor|council|school\s+board)/i, /ballot/i,
    /find\s+a\s+voting\s+location/i, /polling\s+(place|location|station)/i,
    /registered\s+to\s+vote/i, /primary\s+election/i, /general\s+election/i,
    /constituent/i, /precinct/i, /vote4|votefor|elect[a-z]/i
  ];

  let polScore = 0;
  politicalPatterns.forEach(p => { if (p.test(html)) polScore += 8; });
  // Domain name check
  [/vote\d*[a-z]/i, /elect[a-z]/i, /[a-z]+for[a-z]+/i, /[a-z]+2\d{3}/i].forEach(p => { if (p.test(domain)) polScore += 5; });

  if (polScore >= 20) {
    analysis.verdict = 'POLITICAL_CAMPAIGN';
    analysis.confidence = Math.min(20 + (analysis.details.wordCount > 100 ? 20 : 0) + (analysis.details.wordCount > 500 ? 15 : 0) + (analysis.details.headings.length > 2 ? 10 : 0) + (analysis.details.images > 0 ? 10 : 0) + (analysis.details.links.internal > 3 ? 10 : 0) + (analysis.details.metaDescription ? 10 : 0), 98);
    analysis.reasons.push('Website is a political campaign site with election-related content');
    analysis.flags.push('POLITICAL_CAMPAIGN');
    if (/paid\s+for\s+by/i.test(html)) analysis.flags.push('HAS_FEC_DISCLOSURE');
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
  if (!rawDomain || rawDomain.trim().length === 0) return res.status(400).json({ error: 'Domain is required' });

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
    else if (contentAnalysis.verdict === 'REDIRECT_HOST') { overallStatus = 'REDIRECT_HOST'; statusColor = 'orange'; }
    else if (contentAnalysis.verdict === 'DEFAULT_PAGE') { overallStatus = 'DEFAULT_PAGE'; statusColor = 'orange'; }
    else if (contentAnalysis.verdict === 'SUSPENDED') { overallStatus = 'SUSPENDED'; statusColor = 'red'; }
    else if (contentAnalysis.verdict === 'POLITICAL_CAMPAIGN') { overallStatus = 'POLITICAL_CAMPAIGN'; statusColor = 'blue'; }
    else if (httpStatus.statusCode >= 200 && httpStatus.statusCode < 400 && contentAnalysis.verdict === 'VALID') { overallStatus = 'ACTIVE'; statusColor = 'green'; }
    else { overallStatus = 'ISSUES'; statusColor = 'yellow'; }

    const genuinelyValid = ['ACTIVE', 'POLITICAL_CAMPAIGN'].includes(overallStatus);

    console.log(`  -> ${overallStatus} | ${contentAnalysis.verdict} | Valid: ${genuinelyValid}`);
    res.json({ domain, timestamp, overallStatus, statusColor, isGenuinelyValid: genuinelyValid, dns: dnsResults, ssl: sslResults, http: httpStatus, content: contentAnalysis });
  } catch (err) {
    console.error(`  -> ERROR: ${err.message}`);
    res.status(500).json({ domain, error: 'Analysis failed', message: err.message });
  }
});

// === BULK ANALYSIS ENDPOINT ===

app.post('/api/analyze/bulk', async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains) || domains.length === 0) return res.status(400).json({ error: 'Provide an array of domains' });
  if (domains.length > 20) return res.status(400).json({ error: 'Maximum 20 domains per request' });

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
      else if (contentAnalysis.verdict === 'REDIRECT_HOST') overallStatus = 'REDIRECT_HOST';
      else if (contentAnalysis.verdict === 'DEFAULT_PAGE') overallStatus = 'DEFAULT_PAGE';
      else if (contentAnalysis.verdict === 'SUSPENDED') overallStatus = 'SUSPENDED';
      else if (contentAnalysis.verdict === 'POLITICAL_CAMPAIGN') overallStatus = 'POLITICAL_CAMPAIGN';
      else if (httpStatus.statusCode >= 200 && httpStatus.statusCode < 400 && contentAnalysis.verdict === 'VALID') overallStatus = 'ACTIVE';
      else overallStatus = 'ISSUES';

      results.push({ domain, overallStatus, isGenuinelyValid: ['ACTIVE', 'POLITICAL_CAMPAIGN'].includes(overallStatus), statusCode: httpStatus.statusCode, verdict: contentAnalysis.verdict, confidence: contentAnalysis.confidence, reasons: contentAnalysis.reasons, flags: contentAnalysis.flags, redirectInfo: contentAnalysis.redirectInfo, title: contentAnalysis.details.title, wordCount: contentAnalysis.details.wordCount, uniqueWordCount: contentAnalysis.details.uniqueWordCount });
      console.log(`  [OK] ${domain} -> ${overallStatus}`);
    } catch (err) {
      results.push({ domain: normalizeDomain(rawDomain), overallStatus: 'ERROR', isGenuinelyValid: false, error: err.message });
      console.log(`  [ERR] ${normalizeDomain(rawDomain)} -> ${err.message}`);
    }
  }
  res.json({ total: results.length, results });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

app.listen(PORT, () => {
  console.log(`\n=== Website Intelligence v2.0 ===`);
  console.log(`Dashboard: http://localhost:${PORT}`);
  console.log(`API:       http://localhost:${PORT}/api/analyze\n`);
});
