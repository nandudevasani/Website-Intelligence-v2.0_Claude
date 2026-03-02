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

// HTML Entity Decoder
function decodeHTML(str) {
  if (!str) return str;
  return str
    .replace(/&bull;|&#8226;/gi, '')  // strip bullet entities BEFORE numeric decode
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(n))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
    .replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
    .replace(/&nbsp;/gi, ' ').replace(/&ndash;/gi, '–').replace(/&mdash;/gi, '—')
    .replace(/&copy;/gi, '©').replace(/&reg;/gi, '®')
    .replace(/&trade;/gi, '™').replace(/&laquo;/gi, '«').replace(/&raquo;/gi, '»')
    .replace(/[•·]/g, '')  // also strip literal bullet/middle dot chars
    .replace(/\s+/g, ' ').trim();
}

// In-Memory Cache (1-hour TTL)
const CACHE = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes — short TTL so fixes apply quickly
function cacheGet(key) { const e = CACHE.get(key); if (!e) return null; if (Date.now() > e.expires) { CACHE.delete(key); return null; } return e.data; }
function cacheSet(key, data) { CACHE.set(key, { data, expires: Date.now() + CACHE_TTL }); if (CACHE.size > 500) { const oldest = CACHE.keys().next().value; CACHE.delete(oldest); } }

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

function isBoilerplateName(s) {
  if (!s) return false;
  const t = s.trim().toLowerCase();
  return (
    /my wordpress blog/i.test(t) ||
    /just another wordpress site/i.test(t) ||
    /another wordpress site/i.test(t) ||
    /^wordpress$/i.test(t) ||
    /wordpress starter/i.test(t) ||
    /^(my site|my website|my blog|my home page|website)$/i.test(t) ||
    /google\s+privacy\s+policy/i.test(t) ||
    /privacy\s+policy\s+and\s+terms\s+of\s+service/i.test(t) ||
    /terms\s+of\s+service/i.test(t) ||
    /protected\s+by\s+recaptcha/i.test(t) ||
    /this\s+site\s+is\s+protected/i.test(t) ||
    /coming\s+soon/i.test(t) ||
    /under\s+construction/i.test(t) ||
    /\b(for sale|park model|for sale by owner|fsbo|listing)\b/i.test(t) ||
    /^(home|index|untitled|default|new page|page \d+)$/i.test(t) ||
    /^(hello world|sample page|test page)$/i.test(t)
  );
}

function normalizeExtractedBusinessName(name) {
  if (!name) return name;
  let cleaned = name.replace(/\s+/g, ' ').trim();
  // Collapse exact repeated halves: "Name Name" -> "Name"
  const words = cleaned.split(' ');
  if (words.length >= 4 && words.length % 2 === 0) {
    const half = words.length / 2;
    if (words.slice(0, half).join(' ').toLowerCase() === words.slice(half).join(' ').toLowerCase()) {
      cleaned = words.slice(0, half).join(' ');
    }
  }
  cleaned = cleaned.replace(/\((repeat(?:ed)?\s+\w+)\)$/i, '').trim();
  return cleaned;
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

// === HTTP STATUS ANALYSIS (with retry) ===

async function analyzeHTTPStatus(domain, retries = 2) {
  const r = { isUp:false, statusCode:null, statusText:null, responseTime:null, finalUrl:null, redirectChain:[], headers:{}, error:null };
  const start = Date.now();
  const hdrs = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language':'en-US,en;q=0.9',
    'Accept-Encoding':'gzip, deflate, br',
    'Cache-Control':'no-cache',
    'Connection':'keep-alive',
    'Upgrade-Insecure-Requests':'1'
  };

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      if (attempt > 0) await new Promise(ok => setTimeout(ok, 1000 * attempt)); // backoff
      const res = await axios.get(buildUrl(domain), { timeout:12000, maxRedirects:10, validateStatus:()=>true, headers:hdrs });
      r.isUp = true; r.statusCode = res.status; r.statusText = res.statusText;
      r.responseTime = Date.now() - start;
      r.finalUrl = res.request?.res?.responseUrl || res.config?.url || null;
      r.headers = { server:res.headers['server']||null, poweredBy:res.headers['x-powered-by']||null, contentType:res.headers['content-type']||null };
      return { result:r, html:typeof res.data === 'string' ? res.data : '' };
    } catch (err) {
      r.responseTime = Date.now() - start;
      if (attempt < retries) continue; // retry
      // Final attempt: try HTTP fallback
      try {
        const fb = await axios.get(buildUrl(domain,'http'), { timeout:10000, maxRedirects:10, validateStatus:()=>true, headers:{'User-Agent':hdrs['User-Agent'],'Accept':hdrs['Accept']} });
        r.isUp = true; r.statusCode = fb.status; r.statusText = fb.statusText;
        r.finalUrl = fb.request?.res?.responseUrl || fb.config?.url || null;
        return { result:r, html:typeof fb.data === 'string' ? fb.data : '' };
      } catch (e2) { r.error = err.code || err.message; return { result:r, html:'' }; }
    }
  }
  return { result:r, html:'' };
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
    // ── Real business override ──
    // Even a minimal real business leaves traces: phone, email, WhatsApp, or social.
    // If ANY of these exist, the site belongs to a real business — not a true shell.
    const hasPhone   = /(?:tel:|href=["']tel:|(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4})/i.test(html);
    const hasEmail   = /mailto:[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/i.test(html);
    const hasWhatsApp = /wa\.me\/|whatsapp\.com\/send|api\.whatsapp\.com|whatsapp:/i.test(html);
    const hasSocial  = /facebook\.com\/(?!sharer|share\.php|login|dialog|groups|hashtag|intent|plugins|php\?)[^"'\s<>]{3,}/i.test(html)
                    || /instagram\.com\/[^"'\s<>]{3,}/i.test(html)
                    || /linkedin\.com\/(company|in)\/[^"'\s<>]{2,}/i.test(html)
                    || /tiktok\.com\/@[^"'\s<>]{2,}/i.test(html)
                    || /twitter\.com\/[^"'\s<>]{2,}/i.test(html)
                    || /x\.com\/[^"'\s<>]{2,}/i.test(html)
                    || /youtube\.com\/(channel|c|user|@)[^"'\s<>]{2,}/i.test(html)
                    || /yelp\.com\/biz\/[^"'\s<>]{2,}/i.test(html);

    const realBusinessSignals = [hasPhone, hasEmail, hasWhatsApp, hasSocial].filter(Boolean);

    // Filter out template-default signals (GoDaddy filler emails, placeholder phones)
    const hasFillerEmail = /mailto:(?:filler|noreply|no-reply)@/i.test(html);
    const cleanSignalCount = realBusinessSignals.length - (hasFillerEmail && hasEmail ? 1 : 0);

    if (cleanSignalCount >= 2) {
      // Has 2+ genuine business signals — real business on a template, mark VALID
      analysis.verdict = 'VALID';
      analysis.confidence = Math.min(40 + realBusinessSignals.length * 15, 80);
      analysis.reasons.push('Template-style site but has real business contact signals (' +
        [hasPhone && 'phone', hasEmail && 'email', hasWhatsApp && 'WhatsApp', hasSocial && 'social'].filter(Boolean).join(', ') + ')');
      analysis.flags.push('MINIMAL_SITE', 'BUILDER_DETECTED');
      if (hasWhatsApp) analysis.flags.push('HAS_WHATSAPP');
      if (hasPhone)    analysis.flags.push('HAS_PHONE');
      if (hasEmail)    analysis.flags.push('HAS_EMAIL');
      if (hasSocial)   analysis.flags.push('HAS_SOCIAL');
      return analysis;
    }

    // No real business signals — confirmed shell
    analysis.verdict = 'SHELL_SITE';
    analysis.confidence = Math.min(55 + shellSignalCount * 7 + (titleRepeatCount >= 2 ? 10 : 0) + (hasBuilderIndicator ? 10 : 0) + (shellSignals.dropUsLine ? 5 : 0), 95);
    analysis.reasons.push('Website is a template shell — no phone, email, WhatsApp, or social links found.');
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
    // High-confidence — unambiguous parked/for-sale language
    /this domain is (for sale|parked|available)/i,
    /buy this domain/i,
    /domain (is )?parked/i,
    /parked (by|at|with|domain)/i,
    /this (webpage|page|site|website) is parked/i,
    /domain (name )?for sale/i,
    /purchase this domain/i,
    /make (an )?offer (on|for) this domain/i,
    /hugedomains|sedo\.com|dan\.com|afternic|godaddy\s*auctions/i,
    /sedoparking/i,
    /parkingcrew/i,
    /domainmarket\.com/i,
    // Tightened: must say "this domain is for sale" not "this plan is for sale"
    /this\s+domain\s+is\s+for\s+sale/i,
    /inquire about (this|purchasing)\s+this\s+domain/i,
    // Tightened: "premium domain" only when preceded by parked-page context words
    /(?:buy|purchase|acquire|own)\s+(?:this\s+)?(?:premium\s+)?domain/i,
    // Tightened: "get this domain" only as a standalone CTA, not mid-sentence
    /^get this domain[\s!.]|[^a-z]get this domain[\s!.]/i,
    // Lower-confidence — need a partner signal
    /sponsored\s+listings/i,
    /related\s+searches/i,
  ];

  let parkedScore = 0;
  parkedPatterns.forEach(p => { if (p.test(html)) parkedScore += 20; });
  // Require 2+ signals (score >= 40) to avoid false positives on legit sites
  // that happen to mention "related" or "sponsored" in their own content
  if (parkedScore >= 40) {
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

  // Before flagging NO_CONTENT, check if this is a JS SPA (React/Vue/Angular)
  // SPAs return shell HTML with an empty root div — all content loads via JS
  const isSPA = (
    /<div[^>]+id=["'](?:root|app|main|__next|__nuxt|vue-app)["']/i.test(html) ||
    /data-reactroot|ng-version|data-server-rendered|__NEXT_DATA__|__NUXT__/i.test(html) ||
    /<noscript[^>]*>[\s\S]{20,}<\/noscript>/i.test(html)  // noscript fallback = SPA
  );

  if (analysis.details.wordCount < 10) {
    if (isSPA) {
      // SPA detected — site is active but JS-rendered, we can't read the content
      analysis.verdict = 'VALID'; analysis.confidence = 55;
      analysis.reasons.push('JavaScript single-page application — content loads dynamically (React/Vue/Angular)');
      analysis.flags.push('SPA_DETECTED');
      return analysis;
    }
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

  // Check cache first
  const cached = cacheGet('analyze:' + domain);
  if (cached) { console.log(`  [CACHE HIT] ${domain}`); return res.json(cached); }

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
    const result = { domain, timestamp, overallStatus, statusColor, isGenuinelyValid:genuinelyValid, dns:dnsResults, ssl:sslResults, http:httpStatus, content:contentAnalysis };
    cacheSet('analyze:' + domain, result);
    res.json(result);
  } catch (err) {
    console.error(`  -> ERROR: ${err.message}`);
    res.status(500).json({ domain, error:'Analysis failed', message:err.message });
  }
});

app.post('/api/analyze/bulk', async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains) || domains.length === 0) return res.status(400).json({ error:'Provide an array of domains' });
  if (domains.length > 50) return res.status(400).json({ error:'Maximum 50 domains per request' });

  console.log(`\n[BULK] ${domains.length} domains — batched concurrency (10 at a time)`);

  // Helper: analyze a single domain, never throws
  async function analyzeSingleDomain(rawDomain) {
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

      console.log(`  [OK] ${domain} -> ${overallStatus}`);
      return { domain, overallStatus, isGenuinelyValid:['ACTIVE','POLITICAL_CAMPAIGN'].includes(overallStatus), statusCode:httpStatus.statusCode, verdict:contentAnalysis.verdict, confidence:contentAnalysis.confidence, reasons:contentAnalysis.reasons, flags:contentAnalysis.flags, redirectInfo:contentAnalysis.redirectInfo, title:contentAnalysis.details.title, wordCount:contentAnalysis.details.wordCount, uniqueWordCount:contentAnalysis.details.uniqueWordCount };
    } catch (err) {
      const domain = normalizeDomain(rawDomain);
      console.log(`  [ERR] ${domain} -> ${err.message}`);
      return { domain, overallStatus:'ERROR', isGenuinelyValid:false, error:err.message };
    }
  }

  // Process in batches of 10 — parallel within each batch, sequential across batches
  // 50 domains = 5 batches × ~4s each ≈ 20s total (vs 50 × 6s = 300s sequential)
  const BATCH_SIZE = 10;
  const results = [];
  for (let i = 0; i < domains.length; i += BATCH_SIZE) {
    const batch = domains.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(batch.map(d => analyzeSingleDomain(d)));
    results.push(...batchResults);
    console.log(`  [BATCH] ${Math.min(i + BATCH_SIZE, domains.length)}/${domains.length} done`);
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
  // Must have actual CA postal code (e.g. M5V 3A8) to confirm Canada
  if (CA_POSTAL.test(text)) return true;
  // Province code alone is NOT enough — "CA" appears in US addresses too
  // Require province + postal code nearby (within 30 chars)
  for (const prov of CA_PROVINCES) {
    const re = new RegExp(',\\s*' + prov + '\\b[\\s\\S]{0,20}[A-Z]\\d[A-Z]', 'i');
    if (re.test(text)) return true;
  }
  return false;
}

// --- UK postcode ---
const UK_POSTAL = /[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}/i;

// --- AU states ---
const AU_STATES = ['NSW','VIC','QLD','SA','WA','TAS','ACT','NT'];
const AU_POSTAL = /\b\d{4}\b/;

function cleanBusinessName(rawTitle, ogSiteName, schemaName, domain, footerName) {
  // Helper: check if string is mostly ASCII/English
  const isEnglish = (s) => { if (!s) return false; const nonAscii = s.replace(/[\x00-\x7F]/g, '').length; return nonAscii / s.length < 0.3; };

  // Helper: is this an error page title?
  const isErrorTitle = (s) => /^(403|404|500|502|503|forbidden|not found|error|access denied|unavailable|page not found)/i.test(s?.trim());

  
  // Helper: clean trailing/leading junk from a name
  const cleanName = (s) => s ? normalizeExtractedBusinessName(s.replace(/[•·|:–—\-]+$/, '').replace(/^[•·|:–—\-]+/, '').replace(/\s+/g, ' ').trim()) : s;

  // Helper: strip subtitle like "Name - A Fidelity Company"
  const stripSubtitle = (s) => {
    if (!s) return s;
    // "Name - A/An Subtitle" or "Name - Subtitle Here"
    return s.replace(/\s*[-–—]\s*[Aa]n?\s+\w+\s+\w+.*$/, '').trim();
  };

  // Helper: is this just a domain name as the title?
  const isDomainAsName = (s, dom) => {
    if (!s) return false;
    // Never reject pure ALL-CAPS acronyms (NAUW, IBM, etc.)
    if (/^[A-Z]{2,8}$/.test(s.trim())) return false;
    const cleaned = s.toLowerCase().replace(/[.\s]/g, '');
    const domBase = dom.replace(/\.[a-z]+$/i, '').replace(/[.\-_]/g, '');
    return cleaned === domBase || cleaned === dom.replace(/\./g, '') || /\.com$|\.net$|\.org$/i.test(s);
  };

  // Priority: Schema > Footer > OG site_name > cleaned title > domain
  if (schemaName && schemaName.length > 2 && schemaName.length < 80 && isEnglish(schemaName) && !isErrorTitle(schemaName) && !isBoilerplateName(schemaName) && !isDomainAsName(schemaName, domain)) {
    // If schema name contains a dash separator, score each part and pick the best business name
    const dashParts = schemaName.split(/\s*[-–—]\s*/).map(p => p.trim()).filter(p => p.length > 1);
    if (dashParts.length >= 2) {
      const domBase = domain.replace(/\.[a-z]+$/i, '').replace(/[-_.]/g, '').toLowerCase();
      let best = dashParts[0], bestScore = -99;
      for (const p of dashParts) {
        let s = 0;
        // Strong domain match
        if (p.toLowerCase().replace(/\s+/g, '').includes(domBase.substring(0, 5))) s += 20;
        // Subtitle red flags — never pick these as the primary name
        if (/^[Aa]n?\s+/i.test(p)) s -= 30;                        // "A Fidelity Company"
        if (/\b(fidelity|division|subsidiary|affiliate|member)\b/i.test(p)) s -= 25;
        if (/\b(real estate|brokerage)\b/i.test(p) && dashParts.length > 1) s -= 10;
        // Proper business name signals
        if (/^[A-Z][a-z]/.test(p)) s += 5;                          // Title-cased
        if (/\b(LLC|Inc|Corp|Co|Ltd|Management|Systems|Mechanical|Plumbing|Service)\b/i.test(p)) s += 8;
        if (p.length >= 4 && p.length <= 50) s += 3;
        if (s > bestScore) { bestScore = s; best = p; }
      }
      return cleanName(best);
    }
    return cleanName(stripSubtitle(schemaName));
  }
  if (footerName && footerName.length > 2 && footerName.length < 80 && isEnglish(footerName) && !isBoilerplateName(footerName) && !isDomainAsName(footerName, domain)) return cleanName(footerName);
  if (ogSiteName && ogSiteName.length > 2 && ogSiteName.length < 80 && isEnglish(ogSiteName) && !isErrorTitle(ogSiteName) && !isBoilerplateName(ogSiteName) && !isDomainAsName(ogSiteName, domain)) return cleanName(stripSubtitle(ogSiteName));

  if (rawTitle && isEnglish(rawTitle) && !isErrorTitle(rawTitle) && !isBoilerplateName(rawTitle)) {
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
        const domWordsRaw = domBase.split(/[-_.]/).filter(w => w.length > 2);
        // Also extract inner words: "bjunk" → also include "junk"
        const domWords = [...domWordsRaw];
        domWordsRaw.forEach(w => { if (w.length > 3) domWords.push(w.substring(1)); });

        let best = parts[0], bestScore = -1;
        for (let pi = 0; pi < parts.length; pi++) {
          const p = parts[pi];
          let score = 0;
          const pLower = p.toLowerCase();

          // First position bonus
          if (pi === 0) score += 4;

          // Domain word matches (strongest signal)
          let domMatches = 0;
          for (const dw of domWords) {
            if (pLower.includes(dw.toLowerCase())) domMatches++;
            else if (dw.length >= 4) {
              const partWords = pLower.split(/\s+/);
              for (const pw of partWords) {
                if (pw.startsWith(dw.toLowerCase().substring(0, 4)) || dw.toLowerCase().startsWith(pw.substring(0, 4))) { domMatches += 0.5; break; }
              }
            }
          }
          score += domMatches * 10;

          // Business suffix — boost more if preceded by proper name
          if (/\b(LLC|Inc|Corp|Co|Ltd|Group|Associates|Partners|Agency|Management|Enterprises|Company)\b/i.test(p)) {
            const hasPropName = /^[A-Z][a-z]/.test(p) || /['']s\b/.test(p);
            score += hasPropName ? 6 : 2;
          }

          // Penalize generic service-only descriptions
          if (/^(hvac|plumbing|heating|cooling|electrical|roofing|cleaning|dental|legal|auto|real estate)\s+(service|solution|repair|company|specialist)/i.test(p)) score -= 4;
          if (/^(best|top|#?\d|trusted|affordable|professional|premier|quality|expert|local|official|leading|certified|licensed)\b/i.test(p)) score -= 5;
          if (/^(our|my)\s+(service|product|team|work|project|portfolio|blog|story|mission)/i.test(p)) score -= 8;
          if (/^(service|about|contact|home|faq|blog|testimonial|review|portfolio|gallery|pricing|team)/i.test(p) && p.split(/\s+/).length <= 2) score -= 8;
          if (/\b(dentist|plumber|lawyer|doctor|attorney|contractor|electrician|realtor|cleaning|repair|roofing|hvac|landscap)\w*\s*(in|near|for|of)?\s*$/i.test(p)) score -= 3;
          if (/^\w+(\s+\w+)?\s+(dentist|plumber|lawyer|doctor|attorney|contractor|electrician|realtor|cleaning|company)\s*$/i.test(p)) score -= 4;
          if (/\d[-\s]star/i.test(p)) score -= 5;

          // Boost possessive names
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
    name = cleanName(stripSubtitle(name));
    if (name.length > 2 && name.length < 100 && !isDomainAsName(name, domain)) return name;
  }

  // Fallback: humanize domain name — split camelCase, hyphenated slugs, and number prefixes
  const base = domain.replace(/\.(com|net|org|info|biz|co|us|io|store|art|inc|godaddysites\.com)$/i, '');
  const words = base.split(/[-_.]/).filter(w => w.length > 0);
  const expanded = words.flatMap(w => {
    if (/^\d+$/.test(w)) return [w]; // Keep pure numbers as-is (e.g. "307")
    // Handle leading number + letters: "14k" → "14K", "1foryou" → "1 For You"
    const leadNumMatch = w.match(/^(\d+)([a-zA-Z].*)$/);
    if (leadNumMatch) {
      const num = leadNumMatch[1];
      const rest = leadNumMatch[2];

      // Special case: single letter after number = unit/abbreviation, keep together
      // "14k" → "14K", "4b" → "4B", "1st" → "1st"
      if (rest.length <= 2) {
        return [num + rest.toUpperCase()];
      }

      // Check if it starts with a short prefix (1-2 chars) + longer word
      // "4bjunk" → "4B" + "Junk", "14kshowcase" → "14K" + "Showcase"
      // Try 1-char prefix first (more common: k=karat, b=brothers)
      const prefix1 = rest.match(/^([a-z])([a-z]{3,})$/i);
      const prefix2 = rest.match(/^([a-z]{2})([a-z]{3,})$/i);
      // Prefer 1-char if it looks like an abbreviation (single letter)
      const prefixMatch = prefix1 || prefix2;
      if (prefixMatch) {
        const prefix = prefixMatch[1];
        const mainWord = prefixMatch[2];
        // Split mainWord on any camelCase or just capitalize
        const mainSplit = mainWord.replace(/([a-z])([A-Z])/g, '$1 $2').split(' ');
        const mainWords = mainSplit.map(s => s.charAt(0).toUpperCase() + s.slice(1));
        return [num + prefix.toUpperCase(), ...mainWords];
      }

      // Split the alphabetic rest on camelCase and capitalize
      const restSplit = rest.replace(/([a-z])([A-Z])/g, '$1 $2').split(' ');
      const restWords = restSplit.map(s => s.charAt(0).toUpperCase() + s.slice(1));
      return [num, ...restWords];
    }
    // Split camelCase: "NasonMechanical" → ["Nason", "Mechanical"]
    const split = w.replace(/([a-z])([A-Z])/g, '$1 $2').split(' ');
    return split.map(s => s.charAt(0).toUpperCase() + s.slice(1));
  });
  return expanded.filter(Boolean).join(' ') || domain;
}

function extractOGMeta(html) {
  const get = (prop) => {
    const m = html.match(new RegExp('<meta[^>]*property=["\']og:' + prop + '["\'][^>]*content=["\']([^"\']*)["\']', 'i'))
           || html.match(new RegExp('<meta[^>]*content=["\']([^"\']*)["\'][^>]*property=["\']og:' + prop + '["\']', 'i'));
    return m ? m[1].trim() : null;
  };
  return { siteName: get('site_name'), title: get('title'), description: get('description'), image: get('image'), url: get('url'), type: get('type') };
}

function extractSocialLinks(html) {
  const socials = { facebook:null, twitter:null, instagram:null, linkedin:null, youtube:null, tiktok:null, pinterest:null, yelp:null, whatsapp:null };

  const allLinks = html.match(/https?:\/\/[^\s"'<>]+/gi) || [];

  const badFacebookPatterns = [
    'sharer',
    'share.php',
    'login',
    'dialog',
    'groups',
    'events',
    'hashtag',
    'intent',
    'plugins',
    'php?'
  ];

  for (let url of allLinks) {
    const cleanUrl = url.split('?')[0].replace(/\/$/, '');

    if (!socials.facebook && /facebook\.com\//i.test(cleanUrl)) {
      const lower = cleanUrl.toLowerCase();
      if (!badFacebookPatterns.some(p => lower.includes(p))) {
        socials.facebook = cleanUrl;
      }
    }

    if (!socials.twitter && /(twitter\.com|x\.com)\//i.test(cleanUrl)) {
      socials.twitter = cleanUrl;
    }

    if (!socials.instagram && /instagram\.com\//i.test(cleanUrl)) {
      socials.instagram = cleanUrl;
    }

    if (!socials.linkedin && /linkedin\.com\/(company|in)\//i.test(cleanUrl)) {
      socials.linkedin = cleanUrl;
    }

    if (!socials.youtube && /youtube\.com\/(channel|c|user|@)/i.test(cleanUrl)) {
      socials.youtube = cleanUrl;
    }

    if (!socials.tiktok && /tiktok\.com\/@/i.test(cleanUrl)) {
      socials.tiktok = cleanUrl;
    }

    if (!socials.pinterest && /pinterest\.com\//i.test(cleanUrl)) {
      socials.pinterest = cleanUrl;
    }

    if (!socials.yelp && /yelp\.com\/biz\//i.test(cleanUrl)) {
      socials.yelp = cleanUrl;
    }

    if (!socials.whatsapp && /wa\.me\/|whatsapp\.com\/send|api\.whatsapp\.com/i.test(url)) {
      // Preserve full WhatsApp link including number
      socials.whatsapp = url.split('"')[0].split("'")[0].replace(/[>\s].*/, '');
    }
  }

  // Also check for whatsapp: protocol links
  if (!socials.whatsapp) {
    const waMatch = html.match(/href=["']((?:https?:\/\/)?(?:wa\.me|api\.whatsapp\.com|whatsapp\.com\/send)[^"'\s<>]+)["']/i);
    if (waMatch) socials.whatsapp = waMatch[1];
  }

  // Strip null values — only return platforms that actually have links
  return Object.fromEntries(Object.entries(socials).filter(([, v]) => v !== null));
}

function extractContactInfo(html, bodyText) {
  const result = { phones:[], emails:[], rawAddress:null };

  // Emails from mailto: links (most reliable)
  const mailtoMatches = html.match(/mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/gi) || [];
  mailtoMatches.forEach(m => {
    const email = m.replace(/^mailto:/i, '').toLowerCase();
    if (!result.emails.includes(email) && !/example\.com|test\.com|email\.com|yourdomain/.test(email)) result.emails.push(email);
  });

  // Emails from text (less reliable, filter false positives)
  const textEmails = bodyText.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || [];
  textEmails.forEach(e => {
    const email = e.toLowerCase();
    if (!result.emails.includes(email) && !/example\.com|test\.com|email\.com|yourdomain|sentry\.io|wixpress|google\.com|facebook\.com|w3\.org|schema\.org|jquery|wordpress|gravatar|godaddy/.test(email)) result.emails.push(email);
  });

  // Helper: format raw digits to US phone
  function formatPhone(digits) {
    if (digits.length === 11 && digits.startsWith('1')) digits = digits.substring(1);
    if (digits.length === 10) return '(' + digits.substring(0,3) + ') ' + digits.substring(3,6) + '-' + digits.substring(6);
    return digits; // international or unusual
  }

  // Phone numbers from BODY TEXT first (already formatted by the website)
  const phonePatterns = [
    /\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}/g,           // (xxx) xxx-xxxx
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

  // Phone numbers from tel: links (fallback — format the raw digits)
  const telMatches = html.match(/tel:([+\d\s\-().]+)/gi) || [];
  telMatches.forEach(m => {
    let raw = m.replace(/^tel:/i, '').trim();
    let digits = raw.replace(/\D/g, '');
    if (digits.length >= 7 && !result.phones.some(ep => ep.replace(/\D/g, '') === digits)) {
      // Format it since tel: links are usually just raw digits
      result.phones.push(formatPhone(digits));
    }
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

  const addr = decodeHTML(String(rawAddress))
    .replace(/[\[\]{}<>]/g, ' ')
    .replace(/[|]/g, ', ')
    .replace(/\s+/g, ' ')
    .replace(/,+/g, ',')
    .replace(/^\s*,|,\s*$/g, ''
    .trim();
  
 const cleanToken = (v = '') => String(v).replace(/^\s*,|,\s*$/g, '').replace(/\s+/g, ' ').trim();
  const stripTrailingCityFromStreet = (street, city) => {
    const s = cleanToken(street);
    const c = cleanToken(city);
    if (!s || !c) return s;
    const escapedCity = c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return s.replace(new RegExp(`(?:,?\\s+)${escapedCity}$`, 'i'), '').replace(/,\s*$/, '').trim();
  };

  // Strict full-address format: STREET, CITY, STATE ZIP
  const strictComma = addr.match(/^\s*([^,]+?)\s*,\s*([^,]+?)\s*,\s*([A-Z]{2})\s*(\d{5})(?:-\d{4})?\s*$/);
  if (strictComma) {
    result.street = cleanToken(strictComma[1]);
    result.city = cleanToken(strictComma[2]);
    result.state = strictComma[3].toUpperCase();
    result.zip = strictComma[4];

    // City must never be numeric ZIP data
    if (/^\d{5}$/.test(result.city)) {
      result.zip = result.zip || result.city;
      result.city = '';
    }

    result.street = stripTrailingCityFromStreet(result.street, result.city);
    return result;
  }
  
  // Extract ZIP code (US 5-digit or 5+4)
  const zipMatch = addr.match(/\b(\d{5}(?:-\d{4})?)\b/);
  if (zipMatch) result.zip = zipMatch[1];

  // Prefer explicit ", City, ST ZIP" / ", City ST ZIP" tail patterns
  let tail = addr.match(/,\s*([A-Za-z][A-Za-z\s.'-]{1,40}),\s*([A-Z]{2})\s*(\d{5}(?:-\d{4})?)?\b/);
  if (!tail) {
    tail = addr.match(/,\s*([A-Za-z][A-Za-z\s.'-]{1,40})\s+([A-Z]{2})\s*(\d{5}(?:-\d{4})?)?\b/);
  }
  if (tail) {
    result.city = tail[1].trim();
    result.state = tail[2].toUpperCase();
    if (tail[3]) result.zip = tail[3];
  }
 // Also support non-comma format like: "267 DEDHAM St NORFOLK MA 02056"
  if (!result.city || !result.state || !result.street) {
    const noCommaFull = addr.match(/^(\d{1,6}\s+[A-Za-z0-9\s.#'&/,-]{2,90}?\s+(?:Street|St\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Drive|Dr\.?|Road|Rd\.?|Lane|Ln\.?|Way|Court|Ct\.?|Place|Pl\.?|Circle|Cir\.?|Trail|Trl\.?|Parkway|Pkwy\.?|Highway|Hwy\.?))\s+([A-Za-z][A-Za-z\s.'-]{1,40})\s+([A-Z]{2})\s*(\d{5}(?:-\d{4})?)\b/i);
    if (noCommaFull) {
      if (!result.street) result.street = noCommaFull[1].trim();
      if (!result.city) result.city = noCommaFull[2].trim();
      if (!result.state) result.state = noCommaFull[3].toUpperCase();
      if (!result.zip) result.zip = noCommaFull[4];
    }
  }
  // Fallback: extract state code only from end-ish context (avoid street suffixes like Ct/Ct.)
  if (!result.state) {
    for (const code of US_STATE_CODES) {
      const re = new RegExp('(?:,\\s*|\\s)(' + code + ')(?:\\s+\\d{5}(?:-\\d{4})?)?(?:\\s*$|[,])');
      const m = addr.match(re);
      if (m) { result.state = code; break; }
    }
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
  // Fallback no-comma format: "Street City ST ZIP"
     const noCommaCityStateZip = addr.match(/(.*)\s([A-Za-z\s]+)\s([A-Z]{2})\s(\d{5})$/);
     if (noCommaCityStateZip) {
       const fallbackStreet = cleanToken(noCommaCityStateZip[1]);
       const fallbackCity = cleanToken(noCommaCityStateZip[2]);
       const fallbackState = noCommaCityStateZip[3].toUpperCase();
       const fallbackZip = noCommaCityStateZip[4];
       if (fallbackCity && /^[A-Za-z][A-Za-z\s.'-]*$/.test(fallbackCity) && fallbackCity !== fallbackState) {
         if (!result.street) result.street = fallbackStreet;
         if (!result.city) result.city = fallbackCity;
         if (!result.state) result.state = fallbackState;
         if (!result.zip) result.zip = fallbackZip;
       }
     } 
  }
 
  // If street accidentally captured only city/state text, demote it
  if (result.street) {
    const cityStateOnly = result.street.match(/^([A-Za-z][A-Za-z\s.'-]{1,40}),?\s+([A-Z]{2})(?:\s+(\d{5}(?:-\d{4})?))?$/i);
    if (cityStateOnly && !/\d+\s+\w+/.test(result.street)) {
      if (!result.city) result.city = cityStateOnly[1].trim();
      if (!result.state) result.state = cityStateOnly[2].toUpperCase();
      if (!result.zip && cityStateOnly[3]) result.zip = cityStateOnly[3];
      result.street = '';
    }
  }

  // Strip dangling punctuation / special suffix artifacts
  if (result.street) {
    result.street = result.street
      .replace(/[\]\[{}<>]+/g, ' ')
      .replace(/[•·]+/g, ' ')
      .replace(/\s+/g, ' ')
      .replace(/[,;:\-]+$/, '')
      .trim();
  }
  
   // Clean up city - remove any trailing state/zip and block ZIP in city
   result.city = cleanToken(result.city).replace(/\s+[A-Z]{2}\s*\d{5}.*$/, '').replace(/\s+[A-Z]{2}\s*$/, '').trim();
   if (/^\d{5}$/.test(result.city)) {
     if (!result.zip) result.zip = result.city;
     result.city = '';
   }

   // Keep ZIP as 5 digits only and avoid ZIP duplication into city
   if (result.zip) {
     const zip5 = String(result.zip).match(/\b(\d{5})\b/);
     result.zip = zip5 ? zip5[1] : '';
     if (result.zip && result.city === result.zip) result.city = '';
   }

   result.street = stripTrailingCityFromStreet(result.street, result.city);
   result.street = cleanToken(result.street);
   result.city = cleanToken(result.city);
 
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

   // Clean body text: strip scripts, styles, AND tags — prevents CSS/HTML artifact matches
   const bodyText = html
     .replace(/<script[\s\S]*?<\/script>/gi, '')
     .replace(/<style[\s\S]*?<\/style>/gi, '')
     .replace(/<[^>]+>/g, ' ')
     .replace(/&[a-z]+;/gi, ' ')
     .replace(/\s+/g, ' ');

   // Valid US state codes for address matching
   const US_STATE_SET = new Set([
     'AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA','HI','ID','IL','IN','IA','KS','KY','LA',
     'ME','MD','MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ','NM','NY','NC','ND','OH','OK',
     'OR','PA','RI','SC','SD','TN','TX','UT','VT','VA','WA','WV','WI','WY','DC'
   ]);

   // Priority 3: US ZIP code + state in body text (strongest US signal)
   // Matches: ", FL 33404", "Naples FL 33404", "Naples, Florida 33404"
   const usZipWithComma = /,\s*([A-Z]{2})\s+(\d{5})\b/.exec(bodyText);
   const usZipNoComma = /\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+([A-Z]{2})\s+(\d{5})\b/.exec(bodyText);
   const usFullState = /\b(Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New\s+Hampshire|New\s+Jersey|New\s+Mexico|New\s+York|North\s+Carolina|North\s+Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode\s+Island|South\s+Carolina|South\s+Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West\s+Virginia|Wisconsin|Wyoming)\b/i.test(bodyText);

   const hasUSZip = (usZipWithComma && US_STATE_SET.has(usZipWithComma[1])) ||
                    (usZipNoComma && US_STATE_SET.has(usZipNoComma[2]));

   if (hasUSZip) {
     // Double-check Canadian: if STRICT Canadian postal + province found, it's Canada
     if (hasCanadianAddress(bodyText)) return { code: 'CA', name: 'Canada', confidence: 'medium' };
     return { code: 'US', name: 'United States', confidence: 'high' };
   }

   // Priority 4: Full US state name in text (e.g. "Florida", "North Carolina")
   if (usFullState && /\.(com|net|org|us|info|biz)$/i.test(domain)) {
     return { code: 'US', name: 'United States', confidence: 'medium' };
   }

   // Priority 5: US toll-free numbers (800, 833, 844, 855, 866, 877, 888)
   const allPhoneText = (phones || []).join(' ') + ' ' + bodyText;
   const US_TOLL_FREE = /\b(800|833|844|855|866|877|888)[\s.\-]\d{3}[\s.\-]\d{4}\b/;
   if (US_TOLL_FREE.test(allPhoneText)) {
     if (hasCanadianAddress(bodyText)) return { code: 'CA', name: 'Canada', confidence: 'medium' };
     return { code: 'US', name: 'United States', confidence: 'high' };
   }

   // Priority 6: 10-digit US/CA phone pattern (with or without +1 prefix)
   const hasUSPhone = /\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}/.test(allPhoneText);

   // Priority 7: Phone with explicit international prefix
   if (phones && phones.length > 0) {
     for (const [regex, country] of PHONE_COUNTRY) {
       if (phones.some(p => regex.test(p))) {
         if (country === 'USA/Canada') {
           if (hasCanadianAddress(bodyText)) return { code: 'CA', name: 'Canada', confidence: 'medium' };
           return { code: 'US', name: 'United States', confidence: 'medium' };
         }
         return { code: country.substring(0, 2).toUpperCase(), name: country, confidence: 'medium' };
       }
     }
   }

   // Priority 8: If US 10-digit phone on a generic TLD → US
   if (hasUSPhone && /\.(com|net|org|us|info|biz)$/i.test(domain)) {
     if (hasCanadianAddress(bodyText)) return { code: 'CA', name: 'Canada', confidence: 'low' };
     return { code: 'US', name: 'United States', confidence: 'medium' };
   }

   // Priority 9: Canadian postal code — STRICT context required
   // Must appear after a comma or city-like word, not random strings like product codes
   // Real: "Toronto, ON M5V 3A8" or "M5V 3A8" at end of address block
   // False: "model T4E 5K3", "ref B2C 3D4"
   const strictCApat = /(?:,\s*[A-Z]{2}\s+|[Cc]anada\s+|[A-Z][a-z]+,?\s+(?:AB|BC|MB|NB|NL|NS|NT|NU|ON|PE|QC|SK|YT)\s+)[A-Z]\d[A-Z]\s?\d[A-Z]\d/;
   if (strictCApat.test(bodyText)) return { code: 'CA', name: 'Canada', confidence: 'medium' };

   // Priority 10: UK postcode — STRICT context required
   // Must follow a comma or known UK city/county name, not random text
   // Real: "London, SW1A 1AA" or ", EC2R 8AH"
   // False: "model P2 0BX", "item B1 2CD"
   const strictUKpat = /(?:,\s*|[Ll]ondon\s+|[Mm]anchester\s+|[Bb]irmingham\s+|[Ll]iverpool\s+|[Ll]eeds\s+|[Bb]ristol\s+|[Ss]heffield\s+|[Ee]dinburgh\s+|[Gg]lasgow\s+|[Cc]ardiff\s+|[Bb]elfast\s+|[Ee]ngland\s+|[Ss]cotland\s+|[Ww]ales\s+|United Kingdom\s+|UK\s+)[A-Z]{1,2}\d[A-Z\d]?\s\d[A-Z]{2}\b/;
   if (strictUKpat.test(bodyText) && !hasUSPhone) return { code: 'GB', name: 'United Kingdom', confidence: 'medium' };

   // Priority 11: Currency symbols (only on clean body text)
   if (/\bCAD\b|\$\s*CAD/i.test(bodyText)) return { code: 'CA', name: 'Canada', confidence: 'low' };
   if (/£\s*\d/.test(bodyText) && !hasUSPhone) return { code: 'GB', name: 'United Kingdom', confidence: 'low' };
   if (/A\$\s*\d|\bAUD\b/.test(bodyText)) return { code: 'AU', name: 'Australia', confidence: 'low' };
   if (/€\s*\d|\bEUR\b/.test(bodyText)) return { code: 'EU', name: 'Europe', confidence: 'low' };

   // Priority 12: If any US phone pattern exists at all, weak US signal
   if (hasUSPhone) return { code: 'US', name: 'United States', confidence: 'low' };

   // Priority 13: Generic TLDs (.com/.net/.org) with US full state names → likely US
   if (/\.(com|net|org)$/i.test(domain) && /\b(Florida|Texas|California|New York|Ohio|Georgia|Michigan|Illinois|Pennsylvania|North Carolina|Virginia|Arizona|Tennessee|Colorado|Washington)\b/i.test(bodyText)) {
     return { code: 'US', name: 'United States', confidence: 'low' };
   }

   return { code: 'UNKNOWN', name: 'Unknown', confidence: 'none' };
}

 // === DOMAIN AGE VIA RDAP / WHOIS ===
 
 // Shared age calculator
 function calcDomainAge(result, createdDate) {
   const created = new Date(createdDate);
   if (isNaN(created.getTime())) return false;
   result.createdDate = createdDate;
   result.ageInDays = Math.floor((Date.now() - created) / 86400000);
   const years  = Math.floor(result.ageInDays / 365);
   const months = Math.floor((result.ageInDays % 365) / 30);
   if (years > 0 && months > 0) result.ageText = `${years}Y ${months}M`;
   else if (years > 0)          result.ageText = `${years}Y`;
   else if (months > 0)         result.ageText = `${months}M`;
   else                         result.ageText = '0M';
   return true;
 }
 
 // Parse RDAP response object into our result shape
 function parseRdapData(data, result) {
   for (const ev of (data.events || [])) {
     if (!ev.eventAction || !ev.eventDate) continue;
     const action = ev.eventAction.toLowerCase().trim();
     if (/^registr|^creat/.test(action)) calcDomainAge(result, ev.eventDate);
     else if (action.includes('expir'))   result.expiresDate  = ev.eventDate;
     else if (action.includes('last') || action.includes('updat') || action.includes('chang')) result.updatedDate = ev.eventDate;
   }

  // Some RDAP providers return creation date as top-level fields instead of events
  if (!result.createdDate) {
    const directCreated = data?.creationDate || data?.createdDate || data?.registrationDate;
    if (directCreated) calcDomainAge(result, directCreated);
  }

   for (const entity of (data.entities || [])) {
     if (!result.registrar && entity.roles?.includes('registrar') && entity.vcardArray) {
       for (const field of (entity.vcardArray[1] || [])) {
         if (field[0] === 'fn' && field[3]) { result.registrar = field[3]; break; }
       }
     }
   }
 }
 
 async function getDomainAge(domain) {
  const result = {
    createdDate: null,
    updatedDate: null,
    expiresDate: null,
    ageInDays: null,
    ageText: null,
    registrar: null,
    error: null,
    attempts: []
  };

  const tld = domain.split('.').pop().toLowerCase();

  // ── TLD → RDAP endpoint map (direct registry, no intermediary) ──
  const RDAP_ENDPOINTS = {
    com:  'https://rdap.verisign.com/com/v1/domain/',
    net:  'https://rdap.verisign.com/net/v1/domain/',
    org:  'https://rdap.publicinterestregistry.org/rdap/domain/',
    info: 'https://rdap.afilias.net/rdap/info/domain/',
    biz:  'https://rdap.nic.biz/domain/',
    io:   'https://rdap.nic.io/domain/',
    co:   'https://rdap.nic.co/domain/',
    ai:   'https://rdap.nic.ai/domain/',
    app:  'https://rdap.nic.google/domain/'
  };

  // ── Helper: try RDAP endpoint ──
  async function tryRdap(name, url) {
    try {
      const r = await axios.get(url, {
        timeout: 8000,
        validateStatus: s => s === 200,
        headers: {
          Accept: 'application/rdap+json, application/json',
          'User-Agent': 'Mozilla/5.0 DomainChecker/1.0'
        }
      });

      if (r.data?.events?.length) {
        result.attempts.push({ source: name, status: 'ok' });
        return r.data;
      }

      result.attempts.push({
        source: name,
        status: 'no-events',
        keys: Object.keys(r.data || {}).slice(0, 5).join(',')
      });

    } catch (e) {
      result.attempts.push({
        source: name,
        status: 'fail',
        error: (e.code || e.message || 'unknown').substring(0, 80)
      });
    }

    return null;
  }
 
   // Helper: try a WHOIS JSON API
   async function tryWhois(name, url, extract) {
     try {
       const r = await axios.get(url, {
         timeout: 8000,
         validateStatus: s => s === 200,
         headers: { Accept: 'application/json', 'User-Agent': 'Mozilla/5.0 DomainChecker/1.0' }
       });
       const raw = extract(r.data);
      const firstDate = (value) => {
        if (!value) return null;
        if (Array.isArray(value)) {
          for (const v of value) {
            const d = firstDate(v);
            if (d) return d;
          }
          return null;
        }
        if (typeof value === 'string') return value;
        if (typeof value === 'object') return value.date || value.value || value.timestamp || value.created || null;
        return null;
      };
      const dateStr = firstDate(raw);
       if (dateStr && calcDomainAge(result, dateStr)) {
         result.registrar = result.registrar || extractRegistrar(r.data) || null;
         result.attempts.push({ source: name, status: 'ok' });
         return true;
       }
       result.attempts.push({ source: name, status: 'no-date', sample: JSON.stringify(r.data).substring(0,120) });
     } catch(e) {
       result.attempts.push({ source: name, status: 'fail', error: (e.code || e.message || 'unknown').substring(0,80) });
     }
     return false;
   }
 
   function extractRegistrar(d) {
     if (!d) return null;
     if (typeof d?.registrar === 'string') return d.registrar;
     if (d?.registrar?.name) return d.registrar.name;
     if (d?.WhoisRecord?.registrarName) return d.WhoisRecord.registrarName;
     if (d?.registrar_name) return d.registrar_name;
     return null;
   }
 
   // ── ATTEMPT 1: Direct TLD registry RDAP (most reliable, authoritative) ──
   const directEndpoint = RDAP_ENDPOINTS[tld];
   if (directEndpoint) {
     const data = await tryRdap(`rdap-${tld}`, `${directEndpoint}${domain}`);
     if (data) parseRdapData(data, result);
     if (result.createdDate) return result;
   }
 
   // ── ATTEMPT 2: RDAP.cloud — community proxy, works from datacenter IPs ──
   const rdapCloud = await tryRdap('rdap.cloud', `https://rdap.cloud/domain/${domain}`);
   if (rdapCloud) parseRdapData(rdapCloud, result);
   if (result.createdDate) return result;
 
   // ── ATTEMPT 3: rdap.net — open community RDAP proxy ──
   const rdapNet = await tryRdap('rdap.net', `https://rdap.net/domain/${domain}`);
   if (rdapNet) parseRdapData(rdapNet, result);
   if (result.createdDate) return result;
 
   // ── ATTEMPT 4: shreshtait.com — truly unlimited, no auth, no daily cap ──
   // Community WHOIS API: https://domaininfo.shreshtait.com/api/search/{domain}
   // Returns: { creation_date, domain_name, registrar } — clean and simple
   const shreshtait = await tryWhois('shreshtait', `https://domaininfo.shreshtait.com/api/search/${domain}`, d =>
     d?.creation_date
   );
   if (shreshtait) return result;
 
   // ── ATTEMPT 5: who-dat.as93.net — open source, no auth, no stated limit ──
   const whoDat = await tryWhois('who-dat', `https://who-dat.as93.net/${domain}`, d => {
     const inner = d?.domain || d;
    return inner?.created_date || inner?.creation_date || inner?.createdDate || inner?.creationDate || inner?.registered;
   });
   if (whoDat) return result;
 
   // ── ATTEMPT 6: domainsdb.info — last resort ──
   try {
     const r = await axios.get(`https://api.domainsdb.info/v1/domains/search?domain=${domain}&zone=${tld}`, {
       timeout: 8000, validateStatus: s => s === 200, headers: { 'User-Agent': 'Mozilla/5.0 DomainChecker/1.0' }
     });
     const match = (r.data?.domains||[]).find(d => d.domain?.toLowerCase() === domain.toLowerCase());
     if (match?.create_date && calcDomainAge(result, match.create_date)) {
       result.attempts.push({ source: 'domainsdb', status: 'ok' });
       return result;
     }
     result.attempts.push({ source: 'domainsdb', status: 'no-match', total: r.data?.domains?.length || 0 });
   } catch(e) {
     result.attempts.push({ source: 'domainsdb', status: 'fail', error: (e.code||e.message||'').substring(0,80) });
   }
 
   result.error = `All ${result.attempts.length} domain age lookups failed — diagnose at /api/debug-domain-age?domain=${domain}`;
   return result;
 }
 
 async function extractBusinessInfo(html, domain) {
   const bodyText = html
     .replace(/<script[\s\S]*?<\/script>/gi, '')
     .replace(/<style[\s\S]*?<\/style>/gi, '')
     .replace(/<[^>]+>/g, ' ')
     .replace(/&[a-z]+;/gi, ' ')
     .replace(/\s+/g, ' ')
     .trim();

   // 1. Schema.org JSON-LD (most structured data source)
   const schema = extractSchemaOrg(html);

   // 2. Open Graph meta tags
   const og = extractOGMeta(html);

   // 3. Title tag
   const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
   const rawTitle = titleMatch ? decodeHTML(titleMatch[1].trim().replace(/\s+/g, ' ')) : null;

   // 4. Decode schema/OG values
   const cleanSchemaName = schema.name ? decodeHTML(schema.name) : null;
   const cleanOGSiteName = og.siteName ? decodeHTML(og.siteName) : null;

   // 4b. Social links
   const socials = extractSocialLinks(html);

   // 4c. Address init + schema address parsing
   let address = { street:'', city:'', state:'', zip:'' };
   if (schema.address) {
     if (schema.address.street || schema.address.city) {
       address = {
         street: schema.address.street || '',
         city: schema.address.city || '',
         state: schema.address.state || '',
         zip: schema.address.zip ? String(schema.address.zip) : ''
       };
     } else if (schema.address.raw) {
       address = parseUSAddress(schema.address.raw);
     }
   }
 
   // 5. Footer/Copyright extraction for business name
   let footerName = null;
   const footerMatch = html.match(/<footer[\s\S]*?<\/footer>/i);
   if (footerMatch) {
     const footerText = footerMatch[0]
       .replace(/<[^>]+>/g, ' ')
       .replace(/&[a-z]+;/gi, ' ')
       .replace(/\s+/g, ' ');
     const copyMatch = footerText.match(
       /(?:©|copyright)\s*(?:\d{4}\s*[-–]?\s*\d{0,4}\s*)?([A-Z][A-Za-z\s&'.,-]+?)(?:\s*[.|]|\s*All\s+Rights|\s*$)/i
     );
     if (copyMatch && copyMatch[1]) {
       let fn = copyMatch[1].trim().replace(/[.,]+$/, '').trim();
       if (
         fn.length > 3 &&
         fn.length < 80 &&
         !/all rights|privacy|terms|powered by|built with|designed by/i.test(fn)
       ) {
         footerName = fn;
       }
     }
   }
 
  // Extra signal: first H1 often contains the actual business name
  const h1Match = html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);
  const cleanH1 = h1Match ? decodeHTML(h1Match[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()) : null;

   // 6. Business name (cleaned) — now includes footer as a source
   let businessName = cleanBusinessName(rawTitle, cleanOGSiteName, cleanSchemaName, domain, footerName);

  // Helper: count how many domain keywords appear in a string
  const domRaw = domain.replace(/\.(com|net|org|info|biz|co|us|io|store|art|inc|godaddysites\.com)$/i, '');
  // Extract domain words: split on hyphens, dots, digit-letter boundaries, and camelCase
  const domWords = [];
  domRaw.split(/[-_.]/).forEach(part => {
    // Split at digit-to-letter and letter-to-digit boundaries: "4bjunk" → "4b", "junk"
    // Also split camelCase: "bigMike" → "big", "Mike"
    const subparts = part
      .replace(/(\d)([a-zA-Z])/g, '$1 $2')   // "4bjunk" → "4b junk"
      .replace(/([a-z])([A-Z])/g, '$1 $2')   // "bigMike" → "big Mike"
      .split(/\s+/);
    subparts.forEach(sp => {
      const clean = sp.replace(/\d+/g, '');   // strip digits: "4b" → "b" (too short, filtered below)
      if (clean.length > 2) domWords.push(clean.toLowerCase());
      if (sp.length > 2) domWords.push(sp.toLowerCase());  // also keep with digits: "14k"
      // Extra: if word starts with a single letter prefix + 3+ letter word, extract the inner word
      // "bjunk" → "junk", "bservices" → "services"
      if (clean.length > 3) {
        const innerWord = clean.substring(1);  // strip single leading letter
        if (innerWord.length > 2) domWords.push(innerWord.toLowerCase());
      }
    });
  });
  // Deduplicate
  const uniqueDomWords = [...new Set(domWords)];

  const countDomainOverlap = (str) => {
    if (!str || uniqueDomWords.length === 0) return 0;
    const sl = str.toLowerCase();
    return uniqueDomWords.filter(dw => dw.length > 2 && sl.includes(dw)).length;
  };

  const looksLikeWeakName = (n) => {
    if (!n) return true;
    const t = n.trim();
    return (
      t.length < 4 ||
      /^home$/i.test(t) ||
      /^(welcome|contact|about|services?|our services|our team|our work|my blog|blog|portfolio|gallery)$/i.test(t) ||
      /^(my|our)\s+(wordpress|blog|site|website|page)/i.test(t) ||
      /\.(com|net|org|info|biz)$/i.test(t) ||
      t.toLowerCase() === domain.toLowerCase()
    );
  };

  // If cleanBusinessName returned a name with ZERO domain overlap, check if H1 is better
  const nameOverlap = countDomainOverlap(businessName);
  const h1Overlap = countDomainOverlap(cleanH1);
  if (nameOverlap === 0 && h1Overlap > 0 && cleanH1 && cleanH1.length > 2 && cleanH1.length < 90 && !isBoilerplateName(cleanH1)) {
    businessName = cleanH1;
  }

  // Also fall back to H1 if name looks weak
  if (looksLikeWeakName(businessName) && cleanH1 && cleanH1.length > 2 && cleanH1.length < 90 && !isBoilerplateName(cleanH1)) {
    businessName = cleanH1;
  }

   // Fallback: if cleanBusinessName returned nothing, use the domain
   if (!businessName || businessName.trim().length === 0) {
     businessName = domain;
   }
 
   // 7. Contact info
   const contact = extractContactInfo(html, bodyText);

   // Merge schema phone/email (JSON-LD is highly structured — trust it)
   if (schema.phone) {
     const schemaDigits = schema.phone.replace(/\D/g, '');
     if (!contact.phones.some(p => p.replace(/\D/g, '') === schemaDigits)) contact.phones.unshift(schema.phone);
   }
   if (schema.email) {
     const se = schema.email.toLowerCase();
     if (!contact.emails.includes(se)) contact.emails.unshift(se);
   }
   // Filter filler/placeholder emails
   contact.emails = contact.emails.filter(e => !/filler@|noreply@|no-reply@|donotreply@|placeholder/i.test(e));
 
   // Strong fallback: detect business name from contact block or body
// Also trigger when name looks like a domain slug (no spaces = camelCase/concatenated)
// Also trigger when current name has ZERO overlap with domain keywords
const nameIsSlug = businessName && !businessName.includes(' ') && businessName.length > 6;
const currentNameOverlap = countDomainOverlap(businessName);

if (!businessName || businessName.length < 5 || businessName.toLowerCase() === domain.toLowerCase() || nameIsSlug || currentNameOverlap === 0) {

  // Scan all matches, pick the shortest clean one (avoids grabbing repeated carousel text)
  const nameRegex = /([A-Z][A-Za-z0-9&'.]{0,40}(?:[ \t]+[A-Za-z0-9&'.]+){0,6}[ \t]+(?:LLC|Inc\.?|Corp\.?|Corporation|Company|Services?|Solutions?|Repair|Removal|Junk\s+Removal|Plumbing|Mechanical|Management|Systems|Associates|Group|Partners|Enterprises?|Construction|Restoration|Properties|Realty|Holdings|Builders?|Hauling|Disposal|Electric(?:al)?|Roofing|Heating|Cooling|Landscaping|Painting|Contracting|Agency|Consulting|Studio|Design|Media|Logistics|Moving|Storage|Cleaning|Flooring|Paving|Fencing|Welding|Towing|Auto|Dental|Legal|Financial|Insurance|Advisors?|Interiors?|Exteriors?|Renovations?|Inspections?|Demolition|Excavat(?:ing|ion))(?:[ \t]+LLC|\.?)?)/g;

  let nameCandidate = null;
  let bestCandidateScore = -1;
  let nm;

  while ((nm = nameRegex.exec(bodyText)) !== null) {
    const candidate = normalizeExtractedBusinessName(nm[0].trim().replace(/\s+/g, ' '));

    // Skip if it contains obvious repetition (same word appears 3+ times)
    const words = candidate.toLowerCase().split(/\s+/);
    const wordCounts = {};
    words.forEach(w => { wordCounts[w] = (wordCounts[w] || 0) + 1; });
    const maxRepeat = Math.max(...Object.values(wordCounts));

    if (maxRepeat >= 3) continue;

    if (candidate.length > 5 && candidate.length < 80 && !isBoilerplateName(candidate)) {
      // Score: domain overlap is most important, then prefer LONGER names (full business name)
      // Then prefer names with more capitalized words (proper noun signal)
      const overlap = countDomainOverlap(candidate);
      const hasLegalEntity = typeof candidate === 'string' && /\b(?:LLC|Inc\.?|Corp\.?|Corporation|Ltd|Company)\b/i.test(candidate);
      if (overlap === 0 && !hasLegalEntity) continue;
      const capWords = (candidate.match(/\b[A-Z][a-z]/g) || []).length;
      const score = overlap * 100 + capWords * 5 + Math.min(candidate.length, 50);
      if (score > bestCandidateScore) {
        nameCandidate = candidate;
        bestCandidateScore = score;
      }
    }
  }

  if (nameCandidate) {
    businessName = nameCandidate;
  } else if (schema.address?.raw) {
    address = parseUSAddress(schema.address.raw);
  }
}
 
   // If still no street found, scan body for "City, ST ZIP" pattern
   if (!address.street) {
     // Match 1-3 word city names immediately before state code + ZIP
     // Anchored to word start to avoid "Repair LLC Sanford, NC" matching
       const cityStateZipMatch = bodyText.match(/(?:^|[\n\r,.|]\s*)([A-Za-z][A-Za-z.'-]+(?:\s+[A-Za-z][A-Za-z.'-]+){0,2}),?\s*([A-Z]{2})\s*(\d{5})\b/m);
     if (cityStateZipMatch) {
       const candidateCity = cityStateZipMatch[1].trim();
       const candidateState = cityStateZipMatch[2];
       const candidateZip = cityStateZipMatch[3];
       // Must not contain business-name words
       const notACity = /LLC|Inc|Corp|Repair|Service|Plumbing|Mechanical|Management|Company|the|and|for|your|this|terms|privacy|rights|contact|email|phone/i;
       if (!notACity.test(candidateCity) && candidateCity.length >= 3 && candidateCity.length <= 40) {
         if (!address.city) address.city = candidateCity;
         if (!address.state) address.state = candidateState;
         if (!address.zip) address.zip = candidateZip;
       }
     }
     // Also handle full state name: "Auburn, Maine 04210"
     if (!address.city) {
         const fullStateMatch = bodyText.match(/(?:^|[\n\r,.|]\s*)([A-Za-z][A-Za-z.'-]+(?:\s+[A-Za-z][A-Za-z.'-]+){0,2}),?\s*([A-Za-z][A-Za-z.'-]+(?:\s+[A-Za-z][A-Za-z.'-]+)?)\s+(\d{5})\b/m);
       if (fullStateMatch) {
         const stateNameRaw = fullStateMatch[2].trim();
         const stateCode = Object.entries(US_STATES).find(([,name]) => name.toLowerCase() === stateNameRaw.toLowerCase())?.[0];
         if (stateCode) {
           address.city  = fullStateMatch[1].trim();
           address.state = stateCode;
           address.zip   = fullStateMatch[3];
         }
       }
     }

    // Handle city/state without ZIP: "Austin, TX"
    if (!address.city) {
        const cityStateOnlyMatch = bodyText.match(/(?:^|[\n\r,.|]\s*)([A-Za-z][A-Za-z.'-]+(?:\s+[A-Za-z][A-Za-z.'-]+){0,2}),?\s*([A-Z]{2})\b/m);
      if (cityStateOnlyMatch) {
        const candidateCity = cityStateOnlyMatch[1].trim();
        const candidateState = cityStateOnlyMatch[2];
        const notACity = /LLC|Inc|Corp|Repair|Service|Plumbing|Mechanical|Management|Company|the|and|for|your|this|terms|privacy|rights|contact|email|phone/i;
        if (!notACity.test(candidateCity) && candidateCity.length >= 3 && candidateCity.length <= 40) {
          address.city = candidateCity;
          address.state = candidateState;
        }
      }
    }
   }
 
   // --- Street address extraction: strict regex to prevent bleed into business name ---
     const addrMatch = bodyText.match(
    /(?:^|[\n\r\s])(\d{1,6}\s+[A-Za-z][A-Za-z0-9\s.#'&/,-]{1,85}?\s+(?:Street|St\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Drive|Dr\.?|Road|Rd\.?|Lane|Ln\.?|Way|Court|Ct\.?|Place|Pl\.?|Circle|Cir\.?|Trail|Trl\.?|Parkway|Pkwy\.?|Highway|Hwy\.?)\.?(?:,?\s+(?:Suite|Ste\.?|Bldg\.?|Building|Unit|Apt\.?|Floor|Fl\.?)\s*[#]?[A-Za-z0-9-]+)?)(?:,?\s*[A-Za-z][A-Za-z\s.'-]{1,40},?\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?)?/im
  );
  if (addrMatch) {
    const rawMatch = (addrMatch[0] || '').substring(0, 200).trim();
    const parsed = parseUSAddress(rawMatch);
 
     // Sanitize street: strip business name suffixes that bleed AFTER the street address
     if (parsed.street) {
       parsed.street = parsed.street
         .replace(/\s{2,}/g, ' ')
         .replace(/^((?:\S+\s+){4,})(?:LLC|Inc\.?|Corp\.?|Co\.?|Ltd\.?|Company|Services?|Repair|Plumbing|Mechanical)\b.*/i, '$1')
         .trim();
     }
 
     // Reject street if it looks like body text, not an address:
     // Real streets: "1010 S Park Loop Road", "194 Merrow Road", "1801 N. Opdyke Rd."
     // Body text: "21 years of service with the United", "10 reasons why our..."
     // Guard: after the number, if 3rd+ token is a common English article/preposition → reject
     if (parsed.street) {
       const streetWords = parsed.street.split(/\s+/);
       const nonAddrWords = /^(of|with|the|for|and|or|but|why|how|when|what|that|this|to|in|on|at|by|from|years|days|months|reasons|ways|steps|things|tips|over|under|more|less|than|our|your|we|us|my|their|its|has|have|was|were|is|are|been|will|can|not|no|new|old|about|after|before|since|until|while|where|which)$/i;

          if (streetWords.length >= 3 && nonAddrWords.test(streetWords[2])) {
        parsed.street = '';
      }
    }

    const validStates = new Set([
      'AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA','HI','ID','IL','IN','IA','KS','KY','LA',
      'ME','MD','MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ','NM','NY','NC','ND','OH','OK',
      'OR','PA','RI','SC','SD','TN','TX','UT','VT','VA','WA','WV','WI','WY'
    ]);

    if (parsed.state && validStates.has(parsed.state)) {
      address = parsed;
    } else if (parsed.street && !address.street) {
      address.street = parsed.street;
    }
  }

  // Ensure ZIP preserves leading zeros
  if (address.zip && /^\d{4}$/.test(address.zip)) address.zip = '0' + address.zip;

  // 10. Country detection
  const country = detectCountry(html, domain, schema.address, contact.phones);

  // 11. Domain age — computed at endpoint level and injected, not here
  // (placeholder filled in by endpoint after extractBusinessInfo returns)
  const domainAge = { createdDate:null, updatedDate:null, expiresDate:null, ageInDays:null, ageText:null, registrar:null };

  // 12. Meta description
  const metaDescMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([\s\S]*?)["']/i);
  const metaDescription = metaDescMatch
    ? decodeHTML(metaDescMatch[1].trim())
    : og.description
    ? decodeHTML(og.description)
    : schema.description
    ? decodeHTML(schema.description)
    : null;

  // 13. Business type/industry from schema
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
    // Flat convenience fields for CSV/table consumers
    domainAgeText: domainAge.ageText || null,
    domainCreated: domainAge.createdDate ? domainAge.createdDate.substring(0, 10) : null,
    registrar: domainAge.registrar || null,
    schema: {
      hasSchema: !!schema.name,
      rating: schema.rating,
      priceRange: schema.priceRange,
      hours: schema.hours.length > 0 ? schema.hours : null,
    },
    og: { siteName: og.siteName, image: og.image },
  };
}

// === CONTACT PAGE FETCHER ===
// Looks for a contact/about link in the homepage HTML and fetches it
async function fetchContactPage(domain, homepageHtml) {
  try {
    // Known contact page slug patterns, in priority order
    const contactSlugs = [
      '/contact-us', '/contact', '/about-us', '/about',
      '/find-us', '/find-me', '/location', '/locations',
      '/get-in-touch', '/reach-us', '/our-location',
      '/contact-real-estate', '/contact-information',
    ];

    // First: try to find a contact link directly in the homepage HTML
    const linkMatches = homepageHtml.match(/href=["']([^"']*(?:contact|about|find|location|reach)[^"']{0,30})["']/gi) || [];
    const foundSlugs = linkMatches
      .map(m => { const hm = m.match(/href=["']([^"']+)["']/i); return hm ? hm[1] : null; })
      .filter(h => h && h.startsWith('/') && h.length > 1 && h.length < 60)
      .map(h => h.split('?')[0].split('#')[0]);  // strip query/hash

    // Deduplicate and combine: found links first, then known slugs
    const toTry = [...new Set([...foundSlugs, ...contactSlugs])].slice(0, 6);

    const hdrs = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
    };

    for (const slug of toTry) {
      try {
        const url = `https://${domain}${slug}`;
        const resp = await axios.get(url, { timeout: 8000, maxRedirects: 5, validateStatus: s => s === 200, headers: hdrs });
        if (resp.data && typeof resp.data === 'string' && resp.data.length > 500) {
          console.log(`  [CONTACT PAGE] fetched: ${slug}`);
          return resp.data;
        }
      } catch {}
    }
  } catch {}
  return null;
}

// === BUSINESS EXTRACTION ENDPOINT ===

app.post('/api/extract-business', async (req, res) => {
  const { domain: rawDomain } = req.body;
  if (!rawDomain || rawDomain.trim().length === 0) return res.status(400).json({ error: 'Domain is required' });

  const domain = normalizeDomain(rawDomain);
  console.log(`\n[BIZ] ${domain}`);

  // No cache — always return live results

  try {
    // Run DNS, HTTP fetch, AND domain age all in parallel — no sequential waiting
    const [dnsResults, httpResults, domainAgeResult] = await Promise.all([
      analyzeDNS(domain),
      analyzeHTTPStatus(domain),
      getDomainAge(domain)
    ]);
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

    // If site is dead/down/suspended, skip business extraction (reuse domainAgeResult from above)
    if (['DEAD', 'DOWN', 'SUSPENDED'].includes(websiteStatus)) {
      return res.json({ domain, websiteStatus, reasons: contentAnalysis.reasons, business: { businessName: '', phones: [], emails: [], address: { street:'', city:'', state:'', zip:'' }, country: { code:'UNKNOWN', name:'Unknown', confidence:'none' }, socials: {}, domainAge: { ...domainAgeResult, ageFormatted: domainAgeResult.ageText || null }, domainAgeText: domainAgeResult.ageText || null, domainCreated: domainAgeResult.createdDate ? domainAgeResult.createdDate.substring(0,10) : null, registrar: domainAgeResult.registrar || null, metaDescription: null, businessType: null } });
    }

    let business = await extractBusinessInfo(html, domain);

    // Inject domain age (computed in parallel above)
    business.domainAge     = { ...domainAgeResult, ageFormatted: domainAgeResult.ageText || null };
    business.domainAgeText = domainAgeResult.ageText || null;
    business.domainCreated = domainAgeResult.createdDate ? domainAgeResult.createdDate.substring(0, 10) : null;
    business.registrar     = domainAgeResult.registrar || null;

    // Fetch contact page if street is missing (we need full address, city alone isn't enough)
    const needsContactPage = !business.address.street;
    if (needsContactPage) {
      const contactHtml = await fetchContactPage(domain, html);
      if (contactHtml) {
        const contactBusiness = await extractBusinessInfo(contactHtml, domain);
        // Merge: fill in any blanks from the contact page
        if (!business.address.street && contactBusiness.address.street) business.address.street = contactBusiness.address.street;
        if (!business.address.city   && contactBusiness.address.city)   business.address.city   = contactBusiness.address.city;
        if (!business.address.state  && contactBusiness.address.state)  business.address.state  = contactBusiness.address.state;
        if (!business.address.zip    && contactBusiness.address.zip)    business.address.zip    = contactBusiness.address.zip;
        if (business.phones.length === 0 && contactBusiness.phones.length > 0) business.phones = contactBusiness.phones;
        if (business.emails.length === 0 && contactBusiness.emails.length > 0) business.emails = contactBusiness.emails;
        console.log(`  [CONTACT PAGE] merged address/phone from contact subpage`);
      }
    }

    console.log(`  -> ${websiteStatus} | ${business.businessName} | Phones:${business.phones.length} Emails:${business.emails.length} | ${business.country.name}`);
    const bizResult = { domain, websiteStatus, reasons: contentAnalysis.reasons, business };
    res.json(bizResult);
  } catch (err) {
    console.error(`  -> BIZ ERROR: ${err.message}`);
    res.status(500).json({ domain, error: 'Extraction failed', message: err.message });
  }
});

app.get('/api/health', (req, res) => res.json({ status:'ok', uptime:process.uptime(), version:'3.7', cache:CACHE.size }));

// Clear all cached results — call this after deploying fixes so stale data is gone immediately
app.post('/api/cache-clear', (req, res) => {
  const size = CACHE.size;
  CACHE.clear();
  console.log(`[CACHE] Cleared ${size} entries`);
  res.json({ cleared: size, message: 'Cache cleared. Next requests will re-fetch fresh data.' });
});

// === DOMAIN AGE DEBUG ENDPOINT ===
// Hit: GET /api/debug-domain-age?domain=ccplumbingservice.com
// Shows every attempt, what worked, what failed, and why
app.get('/api/debug-domain-age', async (req, res) => {
  const domain = normalizeDomain(req.query.domain || 'ccplumbingservice.com');
  console.log(`[DEBUG-AGE] ${domain}`);
  const result = await getDomainAge(domain);

  const passed  = result.attempts.filter(a => a.status === 'ok');
  const failed  = result.attempts.filter(a => a.status === 'fail');
  const noData  = result.attempts.filter(a => a.status !== 'ok' && a.status !== 'fail');

  res.json({
    domain,
    success: !!result.createdDate,
    createdDate:  result.createdDate,
    ageText:      result.ageText,
    registrar:    result.registrar,
    expiresDate:  result.expiresDate,
    summary: {
      totalAttempts: result.attempts.length,
      passed:  passed.map(a => a.source),
      failed:  failed.map(a => `${a.source} (${a.error})`),
      noData:  noData.map(a => `${a.source} (${a.status}: ${a.sample||a.keys||''})`),
    },
    attempts: result.attempts,
    error: result.error || null,
    tip: result.createdDate
      ? 'Domain age successfully retrieved ✅'
      : 'All services failed. If errors are EAI_AGAIN or ECONNREFUSED, Render is blocking outbound DNS/HTTPS to these hosts. All 6 services in the chain are unlimited and require no API key.',
  });
});

app.listen(PORT, () => {
  console.log(`\n=== Website Intelligence v3.0 ===`);
  console.log(`Dashboard: http://localhost:${PORT}`);
  console.log(`API:       http://localhost:${PORT}/api/analyze`);
  console.log(`Business:  http://localhost:${PORT}/api/extract-business\n`);
});
