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

// === CDN / PLATFORM DOMAIN WHITELIST ===
// These are CDN, hosting, and platform domains where finalUrl may land
// but the site is NOT actually redirecting to a different website.
const CDN_HOSTING_DOMAINS = [
  'cdn-website.com',     // Duda / Thryv
  'cloudfront.net',      // AWS CloudFront
  'cloudflare.com',      // Cloudflare
  'workers.dev',         // Cloudflare Workers
  'pages.dev',           // Cloudflare Pages
  'netlify.app',         // Netlify
  'vercel.app',          // Vercel
  'herokuapp.com',       // Heroku
  'azurewebsites.net',   // Azure
  'azureedge.net',       // Azure CDN
  'amazonaws.com',       // AWS
  'googleapis.com',      // Google
  'firebaseapp.com',     // Firebase
  'web.app',             // Firebase
  'onrender.com',        // Render
  'railway.app',         // Railway
  'fly.dev',             // Fly.io
  'deno.dev',            // Deno
  'github.io',           // GitHub Pages
  'gitlab.io',           // GitLab Pages
  'bitbucket.io',        // Bitbucket
  'shopify.com',         // Shopify
  'myshopify.com',       // Shopify
  'squarespace.com',     // Squarespace
  'wixsite.com',         // Wix
  'weebly.com',          // Weebly
  'godaddysites.com',    // GoDaddy
  'wsimg.com',           // GoDaddy CDN
  'secureserver.net',    // GoDaddy
  'edgekey.net',         // Akamai
  'akamaihd.net',        // Akamai
  'akamaized.net',       // Akamai
  'fastly.net',          // Fastly
  'lirp.cdn-website.com',// Duda
  'dudaone.com',         // Duda
  'b-cdn.net',           // BunnyCDN
  'cdninstagram.com',    // Instagram CDN
  'fbcdn.net',           // Facebook CDN
  'twimg.com',           // Twitter CDN
  'gstatic.com'          // Google Static
];

function isCDNDomain(url) {
  const root = extractRootDomain(url);
  const hostname = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
  return CDN_HOSTING_DOMAINS.some(cdn => root === cdn || hostname.endsWith('.' + cdn) || hostname === cdn);
}

// === KNOWN WEB APP / LOGIN PAGE PATTERNS ===
// Major web applications that show login pages or SPAs with no real content
const KNOWN_WEB_APP_PATTERNS = [
  { match: /outlook\.live\.com|outlook\.office/i, redirectsTo: 'microsoft.com', name: 'Microsoft Outlook' },
  { match: /login\.live\.com/i, redirectsTo: 'microsoft.com', name: 'Microsoft Login' },
  { match: /login\.microsoftonline\.com/i, redirectsTo: 'microsoft.com', name: 'Microsoft Online' },
  { match: /accounts\.google\.com/i, redirectsTo: 'google.com', name: 'Google Accounts' },
  { match: /mail\.google\.com/i, redirectsTo: 'google.com', name: 'Gmail' },
  { match: /login\.yahoo\.com/i, redirectsTo: 'yahoo.com', name: 'Yahoo Login' }
];

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
// CONTENT INTELLIGENCE ENGINE v2.2
// ═══════════════════════════════════════════════════════════════

function analyzeContent(html, domain, finalUrl) {
  const analysis = {
    verdict:'VALID', confidence:0, reasons:[], flags:[], redirectInfo:null,
    details:{ title:null, metaDescription:null, hasBody:false, bodyTextLength:0, wordCount:0, uniqueWordCount:0, headings:[], links:{internal:0,external:0}, images:0, forms:0, scripts:0, iframes:0 }
  };

  // ════════════════════════════════════════════════════════════
  // PRE-CHECK 1: Known Web App / Login Page Detection
  // Catches: outlook.live.com → Microsoft, mail.google.com → Google
  // These domains are web apps that show login/SPA pages, not real websites
  // ════════════════════════════════════════════════════════════
  const fullDomainStr = domain + (finalUrl ? ' ' + finalUrl : '');
  for (const app of KNOWN_WEB_APP_PATTERNS) {
    if (app.match.test(fullDomainStr)) {
      analysis.verdict = 'CROSS_DOMAIN_REDIRECT';
      analysis.confidence = 90;
      analysis.reasons.push('Domain is a web application login portal that redirects to ' + app.redirectsTo);
      analysis.flags.push('CROSS_DOMAIN_REDIRECT', 'WEB_APP_LOGIN');
      analysis.redirectInfo = { source:domain, target:app.redirectsTo, targetDomain:app.redirectsTo, method:'Web Application Redirect' };
      return analysis;
    }
  }

  // ════════════════════════════════════════════════════════════
  // PRE-CHECK 2: Cross-Domain Redirect via HTTP
  // Catches real cross-domain redirects BUT skips CDN/hosting domains
  // ════════════════════════════════════════════════════════════
  if (finalUrl) {
    const origRoot = extractRootDomain(domain);
    const finalRoot = extractRootDomain(finalUrl);
    if (origRoot && finalRoot && origRoot !== finalRoot && !isCDNDomain(finalUrl)) {
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
  const repetitionRatio = analysis.details.wordCount > 0 ? analysis.details.uniqueWordCount / analysis.details.wordCount : 0;

  const headingMatches = html.match(/<h[1-6][^>]*>([\s\S]*?)<\/h[1-6]>/gi) || [];
  analysis.details.headings = headingMatches.map(h => h.replace(/<[^>]+>/g, '').trim()).filter(h => h.length > 0);
  analysis.details.images = (html.match(/<img[\s ]/gi) || []).length;
  analysis.details.forms = (html.match(/<form[\s ]/gi) || []).length;
  analysis.details.scripts = (html.match(/<script[\s>]/gi) || []).length;
  analysis.details.iframes = (html.match(/<iframe[\s ]/gi) || []).length;

  const linkMatches = html.match(/<a[^>]+href=["']([^"']+)["']/gi) || [];
  let internalLinks = 0, externalLinks = 0;
  linkMatches.forEach(link => {
    const hm = link.match(/href=["']([^"']+)["']/i);
    if (hm) {
      const href = hm[1];
      if (href.includes(domain) || href.startsWith('/') || href.startsWith('#') || href.startsWith('.')) internalLinks++;
      else if (href.startsWith('http')) externalLinks++;
    }
  });
  analysis.details.links.internal = internalLinks;
  analysis.details.links.external = externalLinks;

  // How many REAL internal navigation links (not just / or #)?
  const realNavLinks = linkMatches.filter(link => {
    const hm = link.match(/href=["']([^"']+)["']/i);
    if (!hm) return false;
    const href = hm[1];
    return (href.startsWith('/') && href.length > 1 && href !== '/#') || href.includes(domain);
  }).length;

  // ════════════════════════════════════════════════════════════
  // DETECTION 1: Cross-Domain Redirect (JS / Meta Refresh)
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
    /setTimeout\s*\(\s*(?:function\s*\(\)\s*\{)?\s*(?:window\.)?location\s*(?:\.href)?\s*=\s*["']([^"']+)["']/i
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
    if (targetRoot && sourceRoot && targetRoot !== sourceRoot && !isCDNDomain(jsRedirectTarget)) {
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
  // DETECTION 2: Website Builder Shell Sites (WIDENED in v2.2)
  // GoDaddy one-page templates: brand + tagline + contact form
  // ════════════════════════════════════════════════════════════

  // Shell page signals (common across GoDaddy templates)
  const shellSignals = {
    dropUsLine: /drop us a line/i.test(html),
    emailList: /sign up for our email list/i.test(html),
    recaptcha: /this site is protected by recaptcha/i.test(html),
    cookieBanner: /this website uses cookies[\s\S]{0,300}accept/i.test(html),
    poweredBy: /powered by/i.test(html),
    contactUs: /contact\s+us\s*---/i.test(html),  // GoDaddy "Contact Us ---" section divider
    googlePolicies: /google\s+privacy\s+policy[\s\S]{0,50}terms\s+of\s+service/i.test(html),
    allRightsReserved: /all\s+rights\s+reserved/i.test(html)
  };

  const shellSignalCount = Object.values(shellSignals).filter(Boolean).length;

  // Builder platform CDN indicators
  const builderIndicators = [/wsimg\.com/i, /godaddy/i, /websites\.godaddy\.com/i, /secureserver\.net/i, /cdn-website\.com/i, /wix\.com/i, /squarespace\.com/i, /weebly\.com/i];
  const hasBuilderIndicator = builderIndicators.some(p => p.test(html));

  // Check title repetition in headings
  const titleText = (analysis.details.title || '').toLowerCase().trim();
  let titleRepeatCount = 0;
  if (titleText.length > 2) {
    analysis.details.headings.forEach(h => {
      const ht = h.toLowerCase().trim();
      if (ht.includes(titleText) || titleText.includes(ht)) titleRepeatCount++;
    });
  }

  // SHELL SITE detection — multiple paths to catch all variants
  const isShellSite = (
    // Path A: 3+ shell signals + word count under 250
    (shellSignalCount >= 3 && analysis.details.wordCount < 250) ||
    // Path B: 2+ shell signals + title repeated + word count under 300
    (shellSignalCount >= 2 && titleRepeatCount >= 2 && analysis.details.wordCount < 300) ||
    // Path C: Builder CDN + 2+ shell signals + low unique content
    (hasBuilderIndicator && shellSignalCount >= 2 && analysis.details.uniqueWordCount < 80) ||
    // Path D: Very repetitive + shell signals + low words
    (repetitionRatio < 0.30 && shellSignalCount >= 2 && analysis.details.wordCount < 250) ||
    // Path E: "Drop us a line" + reCAPTCHA + under 250 words (very specific GoDaddy pattern)
    (shellSignals.dropUsLine && shellSignals.recaptcha && analysis.details.wordCount < 250) ||
    // Path F: Cookie banner + powered by + contact section + very few nav links + under 300 words
    (shellSignals.cookieBanner && shellSignals.poweredBy && shellSignalCount >= 3 && realNavLinks <= 2 && analysis.details.wordCount < 300)
  );

  if (isShellSite) {
    analysis.verdict = 'SHELL_SITE';
    analysis.confidence = Math.min(55 + shellSignalCount * 7 + (titleRepeatCount >= 2 ? 10 : 0) + (hasBuilderIndicator ? 10 : 0) + (shellSignals.dropUsLine ? 5 : 0), 95);
    analysis.reasons.push('Website is a template shell — only brand name, tagline, and contact form. No meaningful business content.');
    analysis.flags.push('SHELL_SITE');
    if (hasBuilderIndicator) analysis.flags.push('BUILDER_DETECTED');
    return analysis;
  }

  // Other builders (Wix blank, Squarespace default, WordPress default)
  const otherBuilderShells = [
    { name:'Wix', indicators:[/wix\.com/i, /wixsite\.com/i, /parastorage\.com/i], signals:[/this is a blank site/i, /welcome to your site/i, /start editing/i] },
    { name:'Squarespace', indicators:[/squarespace\.com/i, /sqsp\.net/i], signals:[/it all begins with an idea/i] },
    { name:'WordPress', indicators:[/wordpress\.com/i], signals:[/just another wordpress site/i, /hello world/i, /sample page/i] }
  ];

  for (const b of otherBuilderShells) {
    const hasInd = b.indicators.some(p => p.test(html));
    const sigHits = b.signals.filter(p => p.test(html)).length;
    if (hasInd && sigHits >= 1 && analysis.details.uniqueWordCount < 60) {
      analysis.verdict = 'SHELL_SITE'; analysis.confidence = 85;
      analysis.reasons.push(b.name + ' template shell with no meaningful content.');
      analysis.flags.push('SHELL_SITE', 'BUILDER_' + b.name.toUpperCase()); return analysis;
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
    /apache.*default\s+page/i, /welcome\s+to\s+nginx/i, /iis\s+windows\s+server/i,
    /test\s+page.*apache/i, /congratulations.*successfully\s+installed/i, /placeholder\s+page/i,
    /website\s+is\s+(almost|not\s+yet)\s+ready/i
  ];

  // "It works!" is the classic Apache default page — but ONLY match when page has very few words
  // Real business sites say "how it works" all the time, so we need the word count guard
  const hasItWorks = /it\s+works/i.test(html) && analysis.details.wordCount < 50;

  if ((defaultPagePatterns.some(p => p.test(html)) && analysis.details.wordCount < 100) || hasItWorks) {
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
  if (analysis.details.wordCount > 20 && repetitionRatio < 0.25) {
    analysis.verdict = 'NO_CONTENT'; analysis.confidence = 82;
    analysis.reasons.push('Page content is extremely repetitive — likely a template placeholder'); analysis.flags.push('REPETITIVE_CONTENT'); return analysis;
  }
  if (analysis.details.wordCount > 30 && analysis.details.uniqueWordCount < 25) {
    analysis.verdict = 'NO_CONTENT'; analysis.confidence = 78;
    analysis.reasons.push('Page has very few unique words — likely placeholder content'); analysis.flags.push('REPETITIVE_CONTENT'); return analysis;
  }

  // ════════════════════════════════════════════════════════════
  // DETECTION 8: Political Campaign Site (strict)
  // ════════════════════════════════════════════════════════════

  const strongPoliticalPatterns = [
    /paid\s+for\s+by/i, /authorized\s+by\s+[\w\s]+committee/i,
    /donate\s+to\s+(our|the|my)\s+campaign/i, /find\s+a\s+(voting|polling)\s+location/i,
    /registered\s+to\s+vote/i, /political\s+committee/i, /political\s+action\s+committee/i,
    /vote\s+(for|on)\s+(may|november|tuesday|monday|march|april|june|july|august|september|october|december|\d)/i
  ];

  const mediumPoliticalPatterns = [
    /running\s+for\s+(office|mayor|governor|council|commissioner|congress|senate|board|judge|sheriff|attorney)/i,
    /county\s+commissioner/i, /campaign\s+(team|headquarters|office|donation|contribution)/i,
    /join\s+(my|our|the)\s+campaign/i, /your\s+vote\s+(matters|counts)/i,
    /on\s+the\s+ballot/i, /election\s+day/i, /primary\s+election/i, /general\s+election/i
  ];

  const politicalDomainPatterns = [/^vote\d*[a-z]/i, /^elect[a-z]/i];

  let strongHits = strongPoliticalPatterns.filter(p => p.test(html)).length;
  let mediumHits = mediumPoliticalPatterns.filter(p => p.test(html)).length;
  let domainHits = politicalDomainPatterns.filter(p => p.test(domain)).length;

  const isPolitical = (strongHits >= 1 && (mediumHits >= 1 || domainHits >= 1)) || (mediumHits >= 2 && domainHits >= 1) || (strongHits >= 2);

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

// === ENDPOINTS ===

app.post('/api/analyze', async (req, res) => {
  const { domain: rawDomain } = req.body;
  if (!rawDomain || rawDomain.trim().length === 0) return res.status(400).json({ error:'Domain is required' });

  const domain = normalizeDomain(rawDomain);
  const timestamp = new Date().toISOString();
  console.log(`\n[SCAN] ${domain}`);

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
    console.log(`  -> ${overallStatus} | Words:${contentAnalysis.details.wordCount} Unique:${contentAnalysis.details.uniqueWordCount} | Valid:${genuinelyValid}`);
    res.json({ domain, timestamp, overallStatus, statusColor, isGenuinelyValid:genuinelyValid, dns:dnsResults, ssl:sslResults, http:httpStatus, content:contentAnalysis });
  } catch (err) {
    console.error(`  -> ERROR: ${err.message}`);
    res.status(500).json({ domain, error:'Analysis failed', message:err.message });
  }
});

app.post('/api/analyze/bulk', async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains) || domains.length === 0) return res.status(400).json({ error:'Provide an array of domains' });
  if (domains.length > 100) return res.status(400).json({ error:'Maximum 100 domains per request' });

  console.log(`\n[BULK] ${domains.length} domains`);
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
    }
  }
  res.json({ total:results.length, results });
});

// ═══════════════════════════════════════════════════════════════
// BUSINESS INFO EXTRACTION ENGINE v1.0
// ═══════════════════════════════════════════════════════════════

// --- US States lookup ---
const US_STATES = {AL:'Alabama',AK:'Alaska',AZ:'Arizona',AR:'Arkansas',CA:'California',CO:'Colorado',CT:'Connecticut',DE:'Delaware',FL:'Florida',GA:'Georgia',HI:'Hawaii',ID:'Idaho',IL:'Illinois',IN:'Indiana',IA:'Iowa',KS:'Kansas',KY:'Kentucky',LA:'Louisiana',ME:'Maine',MD:'Maryland',MA:'Massachusetts',MI:'Michigan',MN:'Minnesota',MS:'Mississippi',MO:'Missouri',MT:'Montana',NE:'Nebraska',NV:'Nevada',NH:'New Hampshire',NJ:'New Jersey',NM:'New Mexico',NY:'New York',NC:'North Carolina',ND:'North Dakota',OH:'Ohio',OK:'Oklahoma',OR:'Oregon',PA:'Pennsylvania',RI:'Rhode Island',SC:'South Carolina',SD:'South Dakota',TN:'Tennessee',TX:'Texas',UT:'Utah',VT:'Vermont',VA:'Virginia',WA:'Washington',WV:'West Virginia',WI:'Wisconsin',WY:'Wyoming',DC:'District of Columbia'};
const US_STATE_NAMES = Object.values(US_STATES).map(s => s.toLowerCase());
const US_STATE_CODES = Object.keys(US_STATES);

// --- Country TLD mapping ---
const COUNTRY_TLDS = {'.ca':'Canada','.co.uk':'United Kingdom','.uk':'United Kingdom','.com.au':'Australia','.au':'Australia','.de':'Germany','.fr':'France','.es':'Spain','.it':'Italy','.nl':'Netherlands','.be':'Belgium','.ch':'Switzerland','.at':'Austria','.in':'India','.jp':'Japan','.cn':'China','.kr':'South Korea','.br':'Brazil','.mx':'Mexico','.nz':'New Zealand','.ie':'Ireland','.za':'South Africa','.se':'Sweden','.no':'Norway','.dk':'Denmark','.fi':'Finland','.pl':'Poland','.pt':'Portugal','.ru':'Russia','.sg':'Singapore','.ph':'Philippines','.my':'Malaysia','.th':'Thailand','.ng':'Nigeria','.ke':'Kenya','.gh':'Ghana'};

// --- Country phone prefixes ---
const PHONE_COUNTRY = [[/\+1[\s\-\(]/,'USA/Canada'],[/\+44\s?/,'United Kingdom'],[/\+61\s?/,'Australia'],[/\+49\s?/,'Germany'],[/\+33\s?/,'France'],[/\+91\s?/,'India'],[/\+81\s?/,'Japan'],[/\+86\s?/,'China'],[/\+52\s?/,'Mexico'],[/\+55\s?/,'Brazil'],[/\+64\s?/,'New Zealand'],[/\+353\s?/,'Ireland'],[/\+27\s?/,'South Africa']];

// --- Canadian provinces (only match in address context, not as standalone words) ---
const CA_PROVINCES = ['AB','BC','MB','NB','NL','NS','NT','NU','ON','PE','QC','SK','YT'];
const CA_POSTAL = /[A-Z]\d[A-Z]\s?\d[A-Z]\d/i;
// Strict: province must appear after a comma or with postal code nearby
function hasCanadianAddress(text) {
  if (CA_POSTAL.test(text)) return true;
  // Look for "City, XX" pattern where XX is a province code
  for (const prov of CA_PROVINCES) {
    const re = new RegExp(',\\s*' + prov + '\\b(?:\\s+[A-Z]\\d[A-Z])?', 'i');
    if (re.test(text)) return true;
  }
  return false;
}

// --- UK postcode ---
const UK_POSTAL = /[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}/i;

// --- AU states ---
const AU_STATES = ['NSW','VIC','QLD','SA','WA','TAS','ACT','NT'];
const AU_POSTAL = /\b\d{4}\b/;

function cleanBusinessName(rawTitle, ogSiteName, schemaName, domain) {
  // Helper: check if string is mostly ASCII/English
  const isEnglish = (s) => { if (!s) return false; const nonAscii = s.replace(/[\x00-\x7F]/g, '').length; return nonAscii / s.length < 0.3; };

  // Helper: is this an error page title?
  const isErrorTitle = (s) => /^(403|404|500|502|503|forbidden|not found|error|access denied|unavailable|page not found)/i.test(s?.trim());

  // Priority: Schema > OG site_name > cleaned title > domain
  // But ONLY if the value is English and not an error
  if (schemaName && schemaName.length > 2 && schemaName.length < 80 && isEnglish(schemaName) && !isErrorTitle(schemaName)) return schemaName.trim();
  if (ogSiteName && ogSiteName.length > 2 && ogSiteName.length < 80 && isEnglish(ogSiteName) && !isErrorTitle(ogSiteName)) return ogSiteName.trim();

  if (rawTitle && isEnglish(rawTitle) && !isErrorTitle(rawTitle)) {
    let name = rawTitle;
    // Remove common prefixes
    name = name.replace(/^(home|welcome to|welcome|about us?)\s*[-–—|:]\s*/i, '');
    name = name.replace(/^(welcome to|welcome)\s+/i, '');

    // Split on separators (|, –, —, :, and " - " with spaces)
    const separators = /\s*[|–—:]\s*|\s+-\s+/;
    if (separators.test(name)) {
      const parts = name.split(separators).map(p => p.trim()).filter(p => p.length > 1);
      if (parts.length >= 2) {
        const domBase = domain.replace(/\.(com|net|org|info|biz|co|us|io|store|art|inc|godaddysites\.com)$/i, '').replace(/\d+/g, '');
        const domWords = domBase.split(/[-_.]/).filter(w => w.length > 2);

        let best = parts[0], bestScore = -1;
        for (let pi = 0; pi < parts.length; pi++) {
          const p = parts[pi];
          let score = 0;
          const pLower = p.toLowerCase();

          // First position bonus — title almost always starts with the business name
          if (pi === 0) score += 4;

          // Domain word matches (strongest signal)
          let domMatches = 0;
          for (const dw of domWords) {
            if (pLower.includes(dw.toLowerCase())) domMatches++;
            // Partial match: domain abbreviation matches start of a word in the part
            else if (dw.length >= 4) {
              const partWords = pLower.split(/\s+/);
              for (const pw of partWords) {
                if (pw.startsWith(dw.toLowerCase().substring(0, 4)) || dw.toLowerCase().startsWith(pw.substring(0, 4))) { domMatches += 0.5; break; }
              }
            }
          }
          score += domMatches * 10;

          // Business suffix — only boost if part also has a proper name before it
          if (/\b(LLC|Inc|Corp|Co|Ltd|Group|Associates|Partners|Agency|Management|Enterprises|Company)\b/i.test(p)) {
            const hasPropName = /^[A-Z][a-z]/.test(p) || /['']s\b/.test(p);
            score += hasPropName ? 6 : 2;
          }

          // Penalize generic service-only descriptions (no proper nouns)
          if (/^(hvac|plumbing|heating|cooling|electrical|roofing|cleaning|dental|legal|auto|real estate)\s+(service|solution|repair|company|specialist)/i.test(p)) score -= 4;

          // Penalize generic SEO keywords
          if (/^(best|top|#?\d|trusted|affordable|professional|premier|quality|expert|local|official|leading|certified|licensed)\b/i.test(p)) score -= 5;
          // Penalize "Location + Service" patterns
          if (/\b(dentist|plumber|lawyer|doctor|attorney|contractor|electrician|realtor|cleaning|repair|roofing|hvac|landscap)\w*\s*(in|near|for|of)?\s*$/i.test(p)) score -= 3;
          if (/^\w+(\s+\w+)?\s+(dentist|plumber|lawyer|doctor|attorney|contractor|electrician|realtor|cleaning|company)\s*$/i.test(p)) score -= 4;
          if (/\d[-\s]star/i.test(p)) score -= 5;

          // Boost parts with possessive names (Big Mike's, Joe's, etc.)
          if (/[A-Z][a-z]+['']s\b/.test(p)) score += 3;

          if (p.length >= 5 && p.length <= 50) score += 2;
          if (p.length > 60) score -= 2;
          const caps = (p.match(/[A-Z][a-z]/g) || []).length;
          if (caps >= 2) score += 1;

          if (score > bestScore) { bestScore = score; best = p; }
        }
        name = best;
      }
    }
    name = name.replace(/\s+/g, ' ').trim();
    if (name.length > 2 && name.length < 100) return name;
  }

  // Fallback: humanize domain name (works for non-English sites too)
  const base = domain.replace(/\.(com|net|org|info|biz|co|us|io|store|art|inc|godaddysites\.com)$/i, '');
  return base.split(/[-_.]/).filter(w => w.length > 0).map(w => {
    // Skip pure numbers
    if (/^\d+$/.test(w)) return '';
    return w.charAt(0).toUpperCase() + w.slice(1);
  }).filter(Boolean).join(' ') || domain;
}

function extractSocialLinks(html) {
  const socials = { facebook:null, twitter:null, instagram:null, linkedin:null, youtube:null, tiktok:null, pinterest:null, yelp:null };
  const patterns = [
    [/https?:\/\/(?:www\.)?facebook\.com\/[a-zA-Z0-9._%-]+/gi, 'facebook'],
    [/https?:\/\/(?:www\.)?twitter\.com\/[a-zA-Z0-9_]+/gi, 'twitter'],
    [/https?:\/\/(?:www\.)?x\.com\/[a-zA-Z0-9_]+/gi, 'twitter'],
    [/https?:\/\/(?:www\.)?instagram\.com\/[a-zA-Z0-9._]+/gi, 'instagram'],
    [/https?:\/\/(?:www\.)?linkedin\.com\/(?:company|in)\/[a-zA-Z0-9_%-]+/gi, 'linkedin'],
    [/https?:\/\/(?:www\.)?youtube\.com\/(?:channel|c|user|@)[a-zA-Z0-9_%-\/]+/gi, 'youtube'],
    [/https?:\/\/(?:www\.)?tiktok\.com\/@[a-zA-Z0-9._]+/gi, 'tiktok'],
    [/https?:\/\/(?:www\.)?pinterest\.com\/[a-zA-Z0-9._]+/gi, 'pinterest'],
    [/https?:\/\/(?:www\.)?yelp\.com\/biz\/[a-zA-Z0-9._%-]+/gi, 'yelp']
  ];
  patterns.forEach(([regex, key]) => {
    const m = html.match(regex);
    if (m) socials[key] = [...new Set(m)][0]; // first unique match
  });
  return socials;
}

function extractContactInfo(html, bodyText) {
  const result = { phones:[], emails:[], rawAddress:null };

  // Emails from mailto: links (most reliable)
  const mailtoMatches = html.match(/mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/gi) || [];
  mailtoMatches.forEach(m => {
    const email = m.replace(/^mailto:/i, '').toLowerCase();
    if (!result.emails.includes(email) && !/example\.com|test\.com|email\.com|yourdomain/.test(email)) result.emails.push(email);
  });

  // Emails from text (less reliable, filter common false positives)
  const textEmails = bodyText.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || [];
  textEmails.forEach(e => {
    const email = e.toLowerCase();
    if (!result.emails.includes(email) && !/example\.com|test\.com|email\.com|yourdomain|sentry\.io|wixpress|google\.com|facebook\.com|w3\.org|schema\.org|jquery|wordpress|gravatar/.test(email)) result.emails.push(email);
  });

  // Phone numbers from tel: links (most reliable)
  const telMatches = html.match(/tel:([+\d\s\-().]+)/gi) || [];
  telMatches.forEach(m => {
    let phone = m.replace(/^tel:/i, '').replace(/\s+/g, ' ').trim();
    if (phone.replace(/\D/g, '').length >= 7 && !result.phones.includes(phone)) result.phones.push(phone);
  });

  // Phone numbers from text
  const phonePatterns = [
    /\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}/g,           // (xxx) xxx-xxxx
    /\+1[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}/g, // +1 xxx xxx xxxx
    /\+\d{1,3}[\s.\-]?\d{2,4}[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}/g // international
  ];
  phonePatterns.forEach(p => {
    const matches = bodyText.match(p) || [];
    matches.forEach(phone => {
      const digits = phone.replace(/\D/g, '');
      if (digits.length >= 7 && digits.length <= 15 && !result.phones.some(ep => ep.replace(/\D/g, '') === digits)) {
        result.phones.push(phone.trim());
      }
    });
  });

  return result;
}

function extractSchemaOrg(html) {
  const result = { name:null, phone:null, email:null, address:null, description:null, type:null, url:null, priceRange:null, rating:null, hours:[] };
  const ldMatches = html.match(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi) || [];

  for (const block of ldMatches) {
    try {
      const jsonText = block.replace(/<script[^>]*>/i, '').replace(/<\/script>/i, '').trim();
      const data = JSON.parse(jsonText);
      const items = Array.isArray(data) ? data : data['@graph'] ? data['@graph'] : [data];

      for (const item of items) {
        if (item.name && !result.name) result.name = item.name;
        if (item.telephone && !result.phone) result.phone = item.telephone;
        if (item.email && !result.email) result.email = item.email;
        if (item.description && !result.description) result.description = item.description;
        if (item['@type'] && !result.type) result.type = Array.isArray(item['@type']) ? item['@type'][0] : item['@type'];
        if (item.url && !result.url) result.url = item.url;
        if (item.priceRange && !result.priceRange) result.priceRange = item.priceRange;
        if (item.aggregateRating) result.rating = { value: item.aggregateRating.ratingValue, count: item.aggregateRating.reviewCount || item.aggregateRating.ratingCount };

        if (item.address && !result.address) {
          const a = item.address;
          if (typeof a === 'string') result.address = { raw: a };
          else result.address = {
            raw: [a.streetAddress, a.addressLocality, a.addressRegion, a.postalCode, a.addressCountry].filter(Boolean).join(', '),
            street: a.streetAddress || null,
            city: a.addressLocality || null,
            state: a.addressRegion || null,
            zip: a.postalCode || null,
            country: a.addressCountry || null
          };
        }

        if (item.openingHoursSpecification) {
          const specs = Array.isArray(item.openingHoursSpecification) ? item.openingHoursSpecification : [item.openingHoursSpecification];
          result.hours = specs.map(s => ({ days: s.dayOfWeek, opens: s.opens, closes: s.closes }));
        }
      }
    } catch (e) { /* ignore bad JSON-LD */ }
  }
  return result;
}

function parseUSAddress(rawAddress) {
  const result = { street: '', city: '', state: '', zip: '' };
  if (!rawAddress) return result;

  const addr = rawAddress.replace(/\s+/g, ' ').trim();

  // Extract ZIP code (US 5-digit or 5+4)
  const zipMatch = addr.match(/\b(\d{5}(?:-\d{4})?)\b/);
  if (zipMatch) result.zip = zipMatch[1];

  // Extract state code (must appear before ZIP or after comma)
  for (const code of US_STATE_CODES) {
    // Match ", ST" or ", ST 12345" or "ST 12345"
    const re = new RegExp('(?:,\\s*|\\s+)(' + code + ')\\b(?:\\s+\\d{5})?', 'i');
    const m = addr.match(re);
    if (m) { result.state = code; break; }
  }
  // Try full state names
  if (!result.state) {
    for (const [code, name] of Object.entries(US_STATES)) {
      if (addr.toLowerCase().includes(name.toLowerCase())) { result.state = code; break; }
    }
  }

  // Parse by comma-separated parts
  const parts = addr.split(',').map(p => p.trim()).filter(p => p.length > 0);

  if (parts.length >= 3) {
    // "123 Main St, City, ST 12345" or "123 Main St, Suite 100, City, ST 12345"
    result.street = parts[0];
    // Walk backwards: last part has state+zip, second-to-last is city
    const lastPart = parts[parts.length - 1];
    // Remove state and zip from last part to check if city is there
    let cityPart = parts[parts.length - 2];
    // If last part only has state/zip, city is second-to-last
    if (/^\s*[A-Z]{2}\s*\d{5}/.test(lastPart) || /^\s*[A-Z]{2}\s*$/.test(lastPart)) {
      result.city = cityPart;
    } else {
      // City might be in the last part before state
      const cityMatch = lastPart.match(/^([A-Za-z\s.'-]+?)(?:\s+[A-Z]{2}\s*\d{5}|\s+[A-Z]{2}\s*$)/);
      if (cityMatch) result.city = cityMatch[1].trim();
      else result.city = cityPart; // fallback
    }
    // If we have 4+ parts, combine first parts as street
    if (parts.length >= 4) {
      result.street = parts.slice(0, parts.length - 2).join(', ');
    }
  } else if (parts.length === 2) {
    // Could be "City, ST 12345" OR "123 Main St, City"
    const part2 = parts[1].trim();
    const hasStateZip = /[A-Z]{2}\s*\d{5}/.test(part2) || /^\s*[A-Z]{2}\s*$/.test(part2);
    const hasStreetWords = /\b(street|st|avenue|ave|boulevard|blvd|drive|dr|road|rd|lane|ln|way|court|ct|place|pl|suite|ste|unit|#)\b/i.test(parts[0]);

    if (hasStreetWords) {
      // "123 Main St, City ST 12345"
      result.street = parts[0];
      const cityMatch = part2.match(/^([A-Za-z\s.'-]+?)(?:\s+[A-Z]{2}|\s*$)/);
      if (cityMatch) result.city = cityMatch[1].trim();
    } else if (hasStateZip) {
      // "City, ST 12345" — no street
      result.city = parts[0];
    } else {
      // Ambiguous — assume "Street, City"
      result.street = parts[0];
      result.city = parts[1];
    }
  } else {
    // Single string — try "City ST ZIP" pattern
    const csMatch = addr.match(/^(.+?),?\s+([A-Z]{2})\s*(\d{5}(?:-\d{4})?)?$/i);
    if (csMatch) {
      const hasStreet = /\b(street|st|avenue|ave|boulevard|blvd|drive|dr|road|rd|lane|ln|way|court|ct|place|pl|suite|ste|unit|#|\d+)\b/i.test(csMatch[1]);
      if (hasStreet) result.street = csMatch[1].trim();
      else result.city = csMatch[1].trim();
      result.state = csMatch[2].toUpperCase();
      if (csMatch[3]) result.zip = csMatch[3];
    }
  }

  // Clean up city - remove any trailing state/zip
  result.city = result.city.replace(/\s+[A-Z]{2}\s*\d{5}.*$/, '').replace(/\s+[A-Z]{2}\s*$/, '').trim();

  return result;
}

function detectCountry(html, domain, schemaAddress, phones) {
  // Priority 1: Schema.org country
  if (schemaAddress?.country) {
    const c = schemaAddress.country;
    if (c === 'US' || c === 'USA' || c === 'United States') return { code: 'US', name: 'United States', confidence: 'high' };
    if (c === 'CA' || c === 'Canada') return { code: 'CA', name: 'Canada', confidence: 'high' };
    if (c === 'AU' || c === 'Australia') return { code: 'AU', name: 'Australia', confidence: 'high' };
    if (c === 'GB' || c === 'UK' || c === 'United Kingdom') return { code: 'GB', name: 'United Kingdom', confidence: 'high' };
    return { code: c, name: c, confidence: 'high' };
  }

  // Priority 2: Country TLD
  for (const [tld, country] of Object.entries(COUNTRY_TLDS)) {
    if (domain.endsWith(tld)) {
      const code = tld.replace(/^\.(?:com?\.)?/, '').toUpperCase();
      return { code, name: country, confidence: 'high' };
    }
  }

  const bodyText = html.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ');

  // Priority 3: US ZIP + state pattern (strongest US signal)
  for (const code of US_STATE_CODES) {
    if (new RegExp(',\\s*' + code + '\\s+\\d{5}').test(bodyText)) return { code: 'US', name: 'United States', confidence: 'high' };
  }

  // Priority 4: Canadian postal code or province in address context
  if (hasCanadianAddress(bodyText)) return { code: 'CA', name: 'Canada', confidence: 'medium' };

  // Priority 5: UK postcode pattern (strict — must not also have US ZIP)
  const hasUSzip = /\b\d{5}(?:-\d{4})?\b/.test(bodyText);
  if (UK_POSTAL.test(bodyText) && !hasUSzip) return { code: 'GB', name: 'United Kingdom', confidence: 'medium' };

  // Priority 6: Phone prefix
  if (phones && phones.length > 0) {
    for (const [regex, country] of PHONE_COUNTRY) {
      if (phones.some(p => regex.test(p))) {
        if (country === 'USA/Canada') {
          // Already checked for Canadian address above, so default to US
          return { code: 'US', name: 'United States', confidence: 'medium' };
        }
        return { code: country.substring(0, 2).toUpperCase(), name: country, confidence: 'medium' };
      }
    }
  }

  // Priority 7: US phone pattern in text (10-digit)
  const usPhoneCount = (bodyText.match(/\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}/g) || []).length;
  if (usPhoneCount > 0) return { code: 'US', name: 'United States', confidence: 'low' };

  // Priority 8: Currency
  if (/\$CAD|\bCAD\b.*\$/i.test(html)) return { code: 'CA', name: 'Canada', confidence: 'low' };
  if (/£\d/.test(html)) return { code: 'GB', name: 'United Kingdom', confidence: 'low' };
  if (/A\$\d|AUD/.test(html)) return { code: 'AU', name: 'Australia', confidence: 'low' };
  if (/€\d|EUR/.test(html)) return { code: 'EU', name: 'Europe', confidence: 'low' };

  // Default for .com/.net/.org — assume US (most common)
  if (/\.(com|net|org|us|info|biz)$/i.test(domain)) {
    return { code: 'US', name: 'United States', confidence: 'low' };
  }

  return { code: 'UNKNOWN', name: 'Unknown', confidence: 'none' };
}

async function getDomainAge(domain) {
  try {
    const rdapUrl = `https://rdap.org/domain/${domain}`;
    const res = await axios.get(rdapUrl, { timeout: 8000, validateStatus: () => true });
    if (res.status === 200 && res.data) {
      const events = res.data.events || [];
      const regEvent = events.find(e => e.eventAction === 'registration');
      const expEvent = events.find(e => e.eventAction === 'expiration');
      const regDate = regEvent?.eventDate || null;
      const expDate = expEvent?.eventDate || null;
      let ageFormatted = null;
      if (regDate) {
        const diffMs = Date.now() - new Date(regDate).getTime();
        const totalMonths = Math.floor(diffMs / (30.44 * 86400000));
        const years = Math.floor(totalMonths / 12);
        const months = totalMonths % 12;
        if (years > 0 && months > 0) ageFormatted = years + 'Y, ' + months + 'M';
        else if (years > 0) ageFormatted = years + 'Y';
        else ageFormatted = months + 'M';
      }
      return { registrationDate: regDate ? regDate.split('T')[0] : null, expirationDate: expDate ? expDate.split('T')[0] : null, ageFormatted, registrar: res.data.entities?.[0]?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || null };
    }
  } catch (e) { /* RDAP failed */ }
  return { registrationDate: null, expirationDate: null, ageFormatted: null, registrar: null };
}

function extractOGMeta(html) {
  const get = (prop) => { const m = html.match(new RegExp('<meta[^>]*property=["\']og:' + prop + '["\'][^>]*content=["\']([^"\']*)["\']', 'i')) || html.match(new RegExp('<meta[^>]*content=["\']([^"\']*)["\'][^>]*property=["\']og:' + prop + '["\']', 'i')); return m ? m[1].trim() : null; };
  return { siteName: get('site_name'), title: get('title'), description: get('description'), image: get('image'), url: get('url'), type: get('type') };
}

async function extractBusinessInfo(html, domain) {
  const bodyText = html.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/gi, ' ').replace(/\s+/g, ' ').trim();

  // 1. Schema.org JSON-LD (most structured)
  const schema = extractSchemaOrg(html);

  // 2. Open Graph meta tags
  const og = extractOGMeta(html);

  // 3. Title tag
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const rawTitle = titleMatch ? titleMatch[1].trim().replace(/\s+/g, ' ') : null;

  // 4. Business name (cleaned)
  const businessName = cleanBusinessName(rawTitle, og.siteName, schema.name, domain);

  // 5. Contact info
  const contact = extractContactInfo(html, bodyText);
  // Merge schema contacts
  if (schema.phone && !contact.phones.includes(schema.phone)) contact.phones.unshift(schema.phone);
  if (schema.email && !contact.emails.includes(schema.email.toLowerCase())) contact.emails.unshift(schema.email.toLowerCase());

  // 6. Social links
  const socials = extractSocialLinks(html);

  // 7. Address parsing
  let address = { street:'', city:'', state:'', zip:'' };
  if (schema.address) {
    if (schema.address.street || schema.address.city) {
      address = { street: schema.address.street || '', city: schema.address.city || '', state: schema.address.state || '', zip: schema.address.zip || '' };
    } else if (schema.address.raw) {
      address = parseUSAddress(schema.address.raw);
    }
  }
  // Try to find address in text if schema didn't have it
  if (!address.street && !address.city) {
    const addrMatch = bodyText.match(/\d+\s+[A-Z][a-zA-Z\s]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Road|Rd|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir|Trail|Trl|Parkway|Pkwy|Highway|Hwy|Suite|Ste|Unit|#)\b[^.]*?,\s*[A-Za-z\s]+,?\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?/i);
    if (addrMatch) address = parseUSAddress(addrMatch[0]);
  }

  // 8. Country detection
  const country = detectCountry(html, domain, schema.address, contact.phones);

  // 9. Domain age (RDAP)
  const domainAge = await getDomainAge(domain);

  // 10. Meta description
  const metaDescMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([\s\S]*?)["']/i);
  const metaDescription = metaDescMatch ? metaDescMatch[1].trim() : og.description || schema.description || null;

  // 11. Business type/industry from schema
  const businessType = schema.type || null;

  return {
    businessName,
    rawTitle,
    metaDescription,
    businessType,
    phones: contact.phones.slice(0, 3),
    emails: contact.emails.slice(0, 3),
    address,
    country,
    socials,
    domainAge,
    schema: { hasSchema: !!schema.name, rating: schema.rating, priceRange: schema.priceRange, hours: schema.hours.length > 0 ? schema.hours : null },
    og: { siteName: og.siteName, image: og.image }
  };
}

// === BUSINESS EXTRACTION ENDPOINT ===

app.post('/api/extract-business', async (req, res) => {
  const { domain: rawDomain } = req.body;
  if (!rawDomain || rawDomain.trim().length === 0) return res.status(400).json({ error: 'Domain is required' });

  const domain = normalizeDomain(rawDomain);
  console.log(`\n[BIZ] ${domain}`);

  try {
    const [dnsResults, httpResults] = await Promise.all([analyzeDNS(domain), analyzeHTTPStatus(domain)]);
    const { result: httpStatus, html } = httpResults;

    // Determine website status using same logic as analyze
    const contentAnalysis = analyzeContent(html, domain, httpStatus.finalUrl);
    let websiteStatus = 'UNKNOWN';
    if (!dnsResults.hasARecord && !httpStatus.isUp) websiteStatus = 'DEAD';
    else if (!httpStatus.isUp) websiteStatus = 'DOWN';
    else if (contentAnalysis.verdict === 'CROSS_DOMAIN_REDIRECT') websiteStatus = 'CROSS_DOMAIN_REDIRECT';
    else if (contentAnalysis.verdict === 'PARKED') websiteStatus = 'PARKED';
    else if (contentAnalysis.verdict === 'COMING_SOON') websiteStatus = 'COMING_SOON';
    else if (contentAnalysis.verdict === 'SHELL_SITE') websiteStatus = 'SHELL_SITE';
    else if (contentAnalysis.verdict === 'NO_CONTENT') websiteStatus = 'NO_CONTENT';
    else if (contentAnalysis.verdict === 'DEFAULT_PAGE') websiteStatus = 'DEFAULT_PAGE';
    else if (contentAnalysis.verdict === 'SUSPENDED') websiteStatus = 'SUSPENDED';
    else if (contentAnalysis.verdict === 'POLITICAL_CAMPAIGN') websiteStatus = 'POLITICAL_CAMPAIGN';
    else if (httpStatus.statusCode >= 200 && httpStatus.statusCode < 400 && contentAnalysis.verdict === 'VALID') websiteStatus = 'ACTIVE';
    else websiteStatus = 'ISSUES';

    // If site is dead/down/suspended, skip business extraction
    if (['DEAD', 'DOWN', 'SUSPENDED'].includes(websiteStatus)) {
      const domainAge = await getDomainAge(domain);
      return res.json({ domain, websiteStatus, reasons: contentAnalysis.reasons, business: { businessName: '', phones: [], emails: [], address: { street:'', city:'', state:'', zip:'' }, country: { code:'UNKNOWN', name:'Unknown', confidence:'none' }, socials: {}, domainAge, metaDescription: null, businessType: null } });
    }

    const business = await extractBusinessInfo(html, domain);
    console.log(`  -> ${websiteStatus} | ${business.businessName} | Phones:${business.phones.length} Emails:${business.emails.length} | ${business.country.name}`);
    res.json({ domain, websiteStatus, reasons: contentAnalysis.reasons, business });
  } catch (err) {
    console.error(`  -> BIZ ERROR: ${err.message}`);
    res.status(500).json({ domain, error: 'Extraction failed', message: err.message });
  }
});

app.get('/api/health', (req, res) => res.json({ status:'ok', uptime:process.uptime(), version:'3.0' }));

app.listen(PORT, () => {
  console.log(`\n=== Website Intelligence v3.0 ===`);
  console.log(`Dashboard: http://localhost:${PORT}`);
  console.log(`API:       http://localhost:${PORT}/api/analyze`);
  console.log(`Business:  http://localhost:${PORT}/api/extract-business\n`);
});
