import express from "express";
import cors from "cors";
import axios from "axios";
import * as cheerio from "cheerio";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import whois from "whois-json";
import dns from "dns/promises";
import net from "net";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());

// Serve frontend assets from /public
app.use(express.static(path.join(__dirname, "public")));

// Root route for direct browser visits
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ============================================================
// CONFIGURATION
// ============================================================
const FETCH_TIMEOUT = 8000; // 8 seconds per page
const DOMAIN_SCAN_TIMEOUT = 25000; // 25 seconds per domain scan
const WHOIS_TIMEOUT = 8000; // 8 seconds for whois
const MAX_HTML_SIZE = 2 * 1024 * 1024; // 2MB
const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const MAX_BATCH_SIZE = 60;
const BATCH_CONCURRENCY = 5;

const scanRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

const DOMAIN_REGEX = /^(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

// Sub-pages to always crawl (in addition to homepage)
const SUB_PAGES = [
  "/contact",
  "/contact-us",
  "/about",
  "/about-us",
  "/privacy-policy",
  "/privacy",
];
const INTERNAL_LINK_KEYWORDS = ["contact", "about", "location", "team", "company"];

// Known parking/registrar domains
const PARKING_DOMAINS = [
  "sedoparking.com", "parkingcrew.net", "bodis.com", "afternic.com",
  "hugedomains.com", "dan.com", "godaddy.com/parking", "namecheap.com",
  "above.com", "domainmarket.com", "sav.com",
];

// Known registrar/hosting default page patterns
const PARKING_KEYWORDS = [
  "this domain is for sale", "buy this domain", "domain is parked",
  "parked by", "parked domain", "parked free", "this webpage is parked",
  "domain parking", "this site is under construction and coming soon",
  "future home of something", "website coming soon", "is registered at",
  "this domain has been registered", "domain has expired",
  "renew your domain", "this site can't be reached",
];

const COMING_SOON_KEYWORDS = [
  "coming soon", "launching soon", "stay tuned", "we're almost ready",
  "we are almost ready", "we'll be back", "we will be back",
  "almost there", "opening soon", "site is launching",
  "exciting things are coming", "something awesome is coming",
  "under development", "getting ready",
];

const UNDER_CONSTRUCTION_KEYWORDS = [
  "under construction", "work in progress", "currently being updated",
  "undergoing maintenance", "site maintenance", "being redesigned",
  "rebuilding", "under renovation",
];

const SUSPENDED_KEYWORDS = [
  "account suspended", "account has been suspended", "hosting expired",
  "billing issue", "suspended for", "this account has been suspended",
  "website is suspended", "site suspended",
];

const DEFAULT_PAGE_KEYWORDS = [
  "apache2 ubuntu default page",
  "welcome to nginx",
  "test page for the nginx",
  "if you see this page",
  "c panel default",
  "plesk",
  "web server is running but no content",
];

const COMING_SOON_TEMPLATE_KEYWORDS = [
  "godaddy",
  "wix",
  "squarespace",
  "template",
  "choose a design",
  "edit this site",
  "coming soon",
  "under construction",
];

const COUNTRY_BY_TLD = {
  us: "US", ca: "CA", uk: "GB", gb: "GB", in: "IN", au: "AU", nz: "NZ", ie: "IE",
  de: "DE", fr: "FR", it: "IT", es: "ES", nl: "NL", be: "BE", ch: "CH", at: "AT",
  se: "SE", no: "NO", dk: "DK", fi: "FI", pl: "PL", pt: "PT", cz: "CZ", hu: "HU",
  ro: "RO", bg: "BG", gr: "GR", tr: "TR", il: "IL", ae: "AE", sa: "SA", za: "ZA",
  jp: "JP", kr: "KR", sg: "SG", hk: "HK", cn: "CN", tw: "TW", br: "BR", mx: "MX",
  ar: "AR", cl: "CL", co: "CO", pe: "PE",
};

// Words to strip from title tag when extracting business name
const TITLE_STRIP_PATTERNS = [
  /\s*[\|\-–—]\s*home\s*/gi,
  /\s*home\s*[\|\-–—]\s*/gi,
  /\s*[\|\-–—]\s*welcome\s*/gi,
  /\s*welcome\s*to\s*/gi,
  /\s*[\|\-–—]\s*official\s*(site|website)\s*/gi,
  /\s*[\|\-–—]\s*(website|site|page|blog)\s*/gi,
  /\s*(website|site|page|blog)\s*[\|\-–—]\s*/gi,
  /\s*[\|\-–—]\s*$/,
  /^\s*[\|\-–—]\s*/,
];
function logEvent(event, payload = {}) {
  console.log(JSON.stringify({ event, ts: new Date().toISOString(), ...payload }));
}

function normalizeDomain(input) {
  if (typeof input !== "string") return "";
  let domain = input.trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//i, "");
  domain = domain.split(/[/?#]/)[0];
  domain = domain.replace(/\/+$/, "");
  return domain;
}

function isPrivateOrInternalIp(ip) {
  if (!ip) return true;
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    const [a, b] = parts;
    if (ip === "127.0.0.1" || ip === "0.0.0.0") return true;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }

  if (net.isIPv6(ip)) {
    const lowered = ip.toLowerCase();
    if (lowered === "::1" || lowered === "0:0:0:0:0:0:0:1") return true;
    if (lowered.startsWith("fc") || lowered.startsWith("fd")) return true; // unique local
    if (lowered.startsWith("fe80:")) return true; // link-local
    return false;
  }

  return true;
}

async function validateAndResolveDomain(rawDomain) {
  const domain = normalizeDomain(rawDomain);

  if (!domain) {
    return { ok: false, domain: "", error: "Invalid domain format" };
  }
  if (domain === "localhost" || domain.endsWith(".localhost")) {
    return { ok: false, domain, error: "Blocked domain" };
  }
  if (domain.includes(":")) {
    return { ok: false, domain, error: "Ports are not allowed" };
  }
  if (net.isIP(domain)) {
    return { ok: false, domain, error: "IP addresses are not allowed" };
  }
  if (!DOMAIN_REGEX.test(domain)) {
    return { ok: false, domain, error: "Invalid domain format" };
  }

  try {
    const records = await dns.lookup(domain, { all: true, verbatim: true });
    if (!records || records.length === 0) {
      return { ok: false, domain, error: "DNS Not Found" };
    }

    const blocked = records.some((record) => isPrivateOrInternalIp(record.address));
    if (blocked) {
      return { ok: false, domain, error: "Blocked private/internal IP" };
    }

    return { ok: true, domain, resolvedIps: records.map((r) => r.address) };
  } catch (_err) {
    return { ok: false, domain, error: "DNS Not Found" };
  }
}

function countKeywordMatches(text, keywords) {
  return keywords.reduce((count, kw) => (text.includes(kw) ? count + 1 : count), 0);
}

function formatDomainAgeFromDate(createdDateInput) {
  if (!createdDateInput) return "Unknown";

  const createdDate = new Date(createdDateInput);
  if (Number.isNaN(createdDate.getTime())) return "Unknown";

  const now = new Date();
  if (createdDate > now) return "0M";

  let months = (now.getFullYear() - createdDate.getFullYear()) * 12;
  months += now.getMonth() - createdDate.getMonth();

  if (now.getDate() < createdDate.getDate()) {
    months -= 1;
  }

  if (months < 0) months = 0;

  const years = Math.floor(months / 12);
  const remMonths = months % 12;

  if (years > 0) return `${years}Y ${remMonths}M`;
  return `${remMonths}M`;
}

async function resolveDomainAge(domain) {
  try {
    const result = await Promise.race([
      whois(domain),
      new Promise((_, reject) => setTimeout(() => reject(new Error("WHOIS timeout")), WHOIS_TIMEOUT)),
    ]);

    const created = result?.creationDate || result?.created || result?.registered;
    if (Array.isArray(created)) {
      const firstValid = created.find(Boolean);
      return formatDomainAgeFromDate(firstValid);
    }

    return formatDomainAgeFromDate(created);
  } catch (_e) {
    return "Unknown";
  }
}

// ============================================================
// UTILITY: Fetch a single page
// ============================================================
async function fetchPage(url, signal) {
  try {
    const response = await axios.get(url, {
      timeout: FETCH_TIMEOUT,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: { "User-Agent": USER_AGENT },
      responseType: "text",
      maxContentLength: MAX_HTML_SIZE,
      maxBodyLength: MAX_HTML_SIZE,
      signal,
    });

    const finalUrl = response.request?.res?.responseUrl || response.config?.url || url;

    return {
      ok: true,
      html: typeof response.data === "string" ? response.data : "",
      statusCode: response.status,
      finalUrl: finalUrl,
      headers: response.headers,
      error: null,
      tooLarge: false,
      timedOut: false,
      aborted: false,
    };
  } catch (err) {
    let errorType = "Unknown Error";
    let tooLarge = false;
    let timedOut = false;
    let aborted = false;

    if (err.code === "ENOTFOUND") errorType = "DNS Not Found";
    else if (err.code === "ECONNREFUSED") errorType = "Connection Refused";
    else if (err.code === "ETIMEDOUT" || err.code === "ECONNABORTED") {
      errorType = "Timeout";
      timedOut = true;
    } else if (err.code === "ERR_CANCELED") {
      errorType = "Aborted";
      aborted = true;
    } else if (err.code === "ERR_TLS_CERT_ALTNAME_INVALID") errorType = "SSL Certificate Invalid";
    else if (err.code === "ETIMEDOUT" || err.code === "ECONNABORTED") errorType = "Timeout";
    else if (err.code === "ERR_TLS_CERT_ALTNAME_INVALID") errorType = "SSL Certificate Invalid";
    else if (err.code === "CERT_HAS_EXPIRED") errorType = "SSL Certificate Expired";
    else if (err.code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE") errorType = "SSL Verification Failed";
    else if (err.code === "ERR_FR_TOO_MANY_REDIRECTS") errorType = "Too Many Redirects";
    else if (String(err.message || "").toLowerCase().includes("maxcontentlength") || String(err.message || "").toLowerCase().includes("maxbodylength")) {
      errorType = "Page Too Large";
      tooLarge = true;
    } else if (err.message) errorType = err.message.substring(0, 80);

    logEvent("fetch_error", { url, error: errorType });
    
    return {
      ok: false,
      html: "",
      statusCode: 0,
      finalUrl: url,
      headers: {},
      error: errorType,
      tooLarge,
      timedOut,
      aborted,
    };
  }
}
async function fetchRobotsDisallowRules(baseUrl, signal) {
  try {
    const robots = await fetchPage(`${baseUrl}/robots.txt`, signal);
    if (!robots.ok || !robots.html) return [];

    const lines = robots.html.split(/\r?\n/);
    const disallowed = [];
    let userAgentApplies = false;

    for (const line of lines) {
      const clean = line.split("#")[0].trim();
      if (!clean) continue;
      const parts = clean.split(":");
      if (parts.length < 2) continue;
      const key = parts[0].trim().toLowerCase();
      const value = parts.slice(1).join(":").trim();

      if (key === "user-agent") {
        userAgentApplies = value === "*";
      } else if (key === "disallow" && userAgentApplies && value) {
        disallowed.push(value);
      }
    }

    return disallowed;
  } catch (_e) {
    return [];
  }
}

function isPathDisallowed(pathname, disallowedRules) {
  if (!pathname || !disallowedRules.length) return false;
  return disallowedRules.some((rule) => {
    if (!rule || rule === "/") return rule === "/";
    return pathname.startsWith(rule);
  });
}

function discoverInternalLinks(html, baseUrl, domain) {
  const $ = cheerio.load(html || "");
  const discovered = [];

  $("a[href]").each((_, el) => {
    if (discovered.length >= 5) return;

    const href = ($(el).attr("href") || "").trim();
    if (!href || href.startsWith("mailto:") || href.startsWith("tel:") || href.startsWith("javascript:")) return;

    try {
      const url = new URL(href, `${baseUrl}/`);
      const normalizedHost = url.hostname.replace(/^www\./, "").toLowerCase();
      if (normalizedHost !== domain && normalizedHost !== `www.${domain}`) return;

      const pathLower = url.pathname.toLowerCase();
      const matched = INTERNAL_LINK_KEYWORDS.some((kw) => pathLower.includes(kw));
      if (!matched) return;

      const normalizedPath = url.pathname.endsWith("/") && url.pathname !== "/"
        ? url.pathname.slice(0, -1)
        : url.pathname;

      discovered.push(normalizedPath || "/");
    } catch (_e) {
      // skip invalid URLs
    }
  });

  return [...new Set(discovered)].slice(0, 5);
}

// ============================================================
// EXTRACTION: JSON-LD Structured Data
// ============================================================
function extractJsonLd(html) {
  const results = [];
  try {
    const $ = cheerio.load(html);
    $('script[type="application/ld+json"]').each((_, el) => {
      try {
        const raw = $(el).html();
        if (raw) {
          const data = JSON.parse(raw);
          // Handle arrays
          const items = Array.isArray(data) ? data : [data];
          // Also handle @graph
          for (const item of items) {
            if (item["@graph"] && Array.isArray(item["@graph"])) {
              results.push(...item["@graph"]);
            } else {
              results.push(item);
            }
          }
        }
      } catch (e) { /* skip invalid JSON-LD */ }
    });
  } catch (e) { /* skip */ }
  return results;
}

// ============================================================
// EXTRACTION: Business Name (Hybrid Waterfall + Domain Fallback)
// ============================================================
function extractBusinessName(html, domain) {
  const $ = cheerio.load(html);
  let name = "";

  // Priority 1: JSON-LD Organization / LocalBusiness name
  const jsonLd = extractJsonLd(html);
  for (const item of jsonLd) {
    const type = (item["@type"] || "").toLowerCase();
    if (
      type.includes("organization") ||
      type.includes("localbusiness") ||
      type.includes("store") ||
      type.includes("restaurant") ||
      type.includes("professional") ||
      type.includes("medical") ||
      type.includes("business") ||
      type.includes("company")
    ) {
      if (item.name && typeof item.name === "string" && item.name.trim().length > 1) {
        name = item.name.trim();
        break;
      }
    }
  }
  // Also check top-level name in any JSON-LD
  if (!name) {
    for (const item of jsonLd) {
      if (item.name && typeof item.name === "string" && item.name.trim().length > 1) {
        name = item.name.trim();
        break;
      }
    }
  }

  // Priority 2: Open Graph og:site_name
  if (!name) {
    const ogName = $('meta[property="og:site_name"]').attr("content");
    if (ogName && ogName.trim().length > 1) {
      name = ogName.trim();
    }
  }

  // Priority 3: Meta application-name or author
  if (!name) {
    const appName = $('meta[name="application-name"]').attr("content");
    if (appName && appName.trim().length > 1) {
      name = appName.trim();
    }
  }

  // Priority 4: Copyright text in footer
  if (!name) {
    const footerHtml = $("footer").text() || "";
    const bodyText = $.text() || "";
    const textToSearch = footerHtml || bodyText;
    // Match: © 2024 Company Name or Copyright 2024 Company Name
    const copyrightMatch = textToSearch.match(
      /(?:©|copyright)\s*(?:\d{4}\s*[-–]?\s*\d{0,4})?\s*([A-Z][A-Za-z0-9\s&',.\-]+?)(?:\.|All rights|LLC|Inc|Corp|Ltd|\||\n|$)/i
    );
    if (copyrightMatch && copyrightMatch[1] && copyrightMatch[1].trim().length > 2) {
      name = copyrightMatch[1].trim();
    }
  }

  // Priority 5: Header logo alt text
  if (!name) {
    const logoAlt = $("header img").first().attr("alt") ||
                    $(".logo img").first().attr("alt") ||
                    $('[class*="logo"] img').first().attr("alt") ||
                    $("a[href='/'] img").first().attr("alt");
    if (logoAlt && logoAlt.trim().length > 2 && logoAlt.toLowerCase() !== "logo") {
      name = logoAlt.trim();
    }
  }

  // Priority 6: Title tag (cleaned)
  if (!name) {
    let title = $("title").first().text() || "";
    title = title.trim();
    if (title.length > 1) {
      // Take first part before | or - or –
      const parts = title.split(/\s*[\|\-–—]\s*/);
      title = parts[0].trim();
      // Apply strip patterns
      for (const pattern of TITLE_STRIP_PATTERNS) {
        title = title.replace(pattern, "").trim();
      }
      if (title.length > 1 && title.toLowerCase() !== "home" && title.toLowerCase() !== "index") {
        name = title;
      }
    }
  }

  // Priority 7: Humanize domain name as fallback
  if (!name) {
    name = humanizeDomain(domain);
  }

  // Clean up
  name = name.replace(/\s+/g, " ").trim();
  // Remove trailing punctuation
  name = name.replace(/[.,;:]+$/, "").trim();

  return name;
}

// ============================================================
// EXTRACTION: Humanize domain name as business name fallback
// ============================================================
function humanizeDomain(domain) {
  let name = domain
    .replace(/^www\./, "")
    .replace(/\.(com|net|org|co|us|io|biz|info|godaddysites\.com|wixsite\.com|squarespace\.com|wordpress\.com)$/i, "")
    .replace(/[-_]/g, " ")
    .replace(/\./g, " ");

  // Capitalize each word
  name = name.replace(/\b\w/g, c => c.toUpperCase());
  return name.trim();
}

// ============================================================
// EXTRACTION: Phone Number
// ============================================================
function extractPhone(html) {
  const $ = cheerio.load(html);

  // Priority 1: tel: links
  let phone = "";
  $('a[href^="tel:"]').each((_, el) => {
    if (!phone) {
      const href = $(el).attr("href") || "";
      const num = href.replace("tel:", "").replace(/\s+/g, "").trim();
      if (num.length >= 10) {
        phone = formatPhone(num);
      }
    }
  });

  // Priority 2: JSON-LD telephone
  if (!phone) {
    const jsonLd = extractJsonLd(html);
    for (const item of jsonLd) {
      if (item.telephone) {
        phone = formatPhone(String(item.telephone));
        break;
      }
    }
  }

  // Priority 3: Regex on page text
  if (!phone) {
    const text = $.text();
    const phoneRegex = /(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})/g;
    const match = phoneRegex.exec(text);
    if (match) {
      phone = formatPhone(match[0]);
    }
  }

  return phone;
}

function formatPhone(raw) {
  const digits = raw.replace(/\D/g, "");
  if (digits.length === 11 && digits.startsWith("1")) {
    return `(${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7)}`;
  }
  if (digits.length === 10) {
    return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}`;
  }
  return raw.trim();
}

// ============================================================
// EXTRACTION: Email
// ============================================================
function extractEmail(html) {
  const $ = cheerio.load(html);
  let email = "";

  // Priority 1: mailto: links
  $('a[href^="mailto:"]').each((_, el) => {
    if (!email) {
      const href = $(el).attr("href") || "";
      const addr = href.replace("mailto:", "").split("?")[0].trim().toLowerCase();
      if (addr.includes("@") && !addr.includes("example.com") && !addr.includes("email.com")) {
        email = addr;
      }
    }
  });

  // Priority 2: JSON-LD email
  if (!email) {
    const jsonLd = extractJsonLd(html);
    for (const item of jsonLd) {
      if (item.email) {
        email = String(item.email).replace("mailto:", "").trim().toLowerCase();
        break;
      }
    }
  }

  // Priority 3: Regex on page text
  if (!email) {
    const text = $.text() + " " + $.html();
    const emailRegex = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
    const matches = text.match(emailRegex) || [];
    for (const m of matches) {
      const lower = m.toLowerCase();
      // Skip common non-business emails
      if (
        !lower.includes("example.com") &&
        !lower.includes("email.com") &&
        !lower.includes("sentry.io") &&
        !lower.includes("wixpress.com") &&
        !lower.includes("wordpress.") &&
        !lower.endsWith(".png") &&
        !lower.endsWith(".jpg")
      ) {
        email = lower;
        break;
      }
    }
  }

  return email;
}

// ============================================================
// EXTRACTION: Social Media Links
// ============================================================
function extractSocial(html) {
  const $ = cheerio.load(html);
  const social = { facebook: "", instagram: "", linkedin: "", gmb: "" };
  
  $("a[href]").each((_, el) => {
    const href = ($(el).attr("href") || "").trim();
    const hrefLower = href.toLowerCase();

    // Facebook
    if (!social.facebook && (hrefLower.includes("facebook.com/") || hrefLower.includes("fb.com/"))) {
      // Skip share/sharer links
      if (!hrefLower.includes("sharer") && !hrefLower.includes("share.php") && !hrefLower.includes("dialog/")) {
        social.facebook = href;
      }
    }

    // Instagram
    if (!social.instagram && hrefLower.includes("instagram.com/")) {
      if (!hrefLower.includes("/p/") && !hrefLower.includes("share")) {
        social.instagram = href;
      }
    }

    // LinkedIn
    if (!social.linkedin && hrefLower.includes("linkedin.com/")) {
      if (!hrefLower.includes("share") && !hrefLower.includes("shareArticle")) {
        social.linkedin = href;
      }
    }

    // Google My Business / Maps
    if (!social.gmb) {
      if (
        hrefLower.includes("google.com/maps") ||
        hrefLower.includes("goo.gl/maps") ||
        hrefLower.includes("maps.google.com") ||
        hrefLower.includes("maps.app.goo.gl") ||
        hrefLower.includes("business.google.com")
      ) {
        social.gmb = href;
      }
    }
  });

  return social;
}

// ============================================================
// EXTRACTION: Address (from single page HTML)
// ============================================================
function extractAddressFromPage(html) {
  const $ = cheerio.load(html);
  const address = { street: "", city: "", state: "", zip: "", country: "" };

  // Priority 1: JSON-LD PostalAddress
  const jsonLd = extractJsonLd(html);
  for (const item of jsonLd) {
    const addr = item.address || item.location?.address;
    if (addr) {
      const addrObj = typeof addr === "string" ? null : addr;
      if (addrObj) {
        if (addrObj.streetAddress) address.street = String(addrObj.streetAddress).trim();
        if (addrObj.addressLocality) address.city = String(addrObj.addressLocality).trim();
        if (addrObj.addressRegion) address.state = String(addrObj.addressRegion).trim().substring(0, 2).toUpperCase();
        if (addrObj.postalCode) address.zip = String(addrObj.postalCode).trim();
        if (addrObj.addressCountry) address.country = String(addrObj.addressCountry).trim().toUpperCase().substring(0, 2);
        if (address.street || address.city) return address;
      }
    }
  }

  // Priority 2: Microdata itemprop
  const street = $('[itemprop="streetAddress"]').first().text().trim();
  const city = $('[itemprop="addressLocality"]').first().text().trim();
  const state = $('[itemprop="addressRegion"]').first().text().trim();
  const zip = $('[itemprop="postalCode"]').first().text().trim();
  const country = $('[itemprop="addressCountry"]').first().text().trim();
  if (street || city) {
    address.street = street;
    address.city = city;
    address.state = state.substring(0, 2).toUpperCase();
    address.zip = zip;
    address.country = country ? country.toUpperCase().substring(0, 2) : "";
    return address;
  }

  // Priority 3: semantic address node
  const addressNodeText = $("address").first().text().trim();
  if (addressNodeText) {
    const semanticAddress = parseAddressFromText(addressNodeText);
    if (semanticAddress.street || semanticAddress.city) return semanticAddress;
  }

  // Priority 4: Footer-focused regex
  const footerText = $("footer").text() || "";
  const footerAddr = parseAddressFromText(footerText);
  if (footerAddr.street || footerAddr.city) return footerAddr;

  // Priority 5: Full page regex (last resort)
  const bodyText = $.text() || "";
  const fullAddr = parseAddressFromText(bodyText);
  if (fullAddr.street || fullAddr.city) return fullAddr;

  return address;
}
// ============================================================
// UTILITY: Parse US address from raw text using regex
// ============================================================
function parseAddressFromText(text) {
  const address = { street: "", city: "", state: "", zip: "", country: "" };

  // US state abbreviations
  const states = "AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC";
  const streetTypes = "St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Rd|Road|Ln|Lane|Way|Ct|Court|Pl|Place|Cir|Circle|Pkwy|Parkway|Ter|Terrace|Hwy|Highway|Loop|Trail|Trl";

  // Pattern: 123 Main St, City, ST 12345
  const fullPattern = new RegExp(
    `(\\d{1,5}\\s[\\w\\s.]+(?:${streetTypes})(?:\\s*(?:Ste|Suite|Unit|Apt|#)\\s*[\\w\\d-]*)?)\\s*[,\\n]\\s*([A-Za-z\\s.]+?)\\s*[,\\n]\\s*(${states})\\s*[,\\s]*(\\d{5}(?:-\\d{4})?)`,
    "i"
  );

  const match = text.match(fullPattern);
  if (match) {
    address.street = match[1].trim();
    address.city = match[2].trim().replace(/,\s*$/, "");
    address.state = match[3].trim().toUpperCase();
    address.zip = match[4].trim();
    return address;
  }

  // Simpler pattern: just City, ST ZIP
  const cityStateZip = new RegExp(
    `([A-Za-z\\s.]+?)\\s*[,]\\s*(${states})\\s*[,\\s]*(\\d{5}(?:-\\d{4})?)`,
    "i"
  );

  const match2 = text.match(cityStateZip);
  if (match2) {
    address.city = match2[1].trim().replace(/,\s*$/, "");
    address.state = match2[2].trim().toUpperCase();
    address.zip = match2[3].trim();

    // Try to find street before city
    const beforeCity = text.substring(0, text.indexOf(match2[0]));
    const streetMatch = beforeCity.match(
      new RegExp(`(\\d{1,5}\\s[\\w\\s.]+(?:${streetTypes})(?:\\s*(?:Ste|Suite|Unit|Apt|#)\\s*[\\w\\d-]*)?)\\s*$`, "i")
    );
    if (streetMatch) {
      address.street = streetMatch[1].trim();
    }
  }

  return address;
}

function extractCountryFromPage(html, domain, address, phone) {
  const $ = cheerio.load(html || "");
  const jsonLd = extractJsonLd(html || "");

  for (const item of jsonLd) {
    const addr = item.address || item.location?.address;
    if (addr && typeof addr === "object" && addr.addressCountry) {
      return String(addr.addressCountry).trim().toUpperCase().substring(0, 2);
    }
  }

  const metaCountry =
    $('meta[name="geo.country"]').attr("content") ||
    $('meta[name="country"]').attr("content") ||
    $('meta[property="og:locale"]').attr("content");

  if (metaCountry) {
    const normalized = String(metaCountry).trim().toUpperCase();
    if (normalized.includes("_")) return normalized.split("_")[1].substring(0, 2);
    return normalized.substring(0, 2);
  }

  if (address?.country) return address.country;
  if (address?.state && /^[A-Z]{2}$/.test(address.state)) return "US";

  if (phone && phone.trim().startsWith("+44")) return "GB";
  if (phone && phone.trim().startsWith("+91")) return "IN";

  const parts = String(domain || "").toLowerCase().split(".");
  const tld = parts[parts.length - 1];
  return COUNTRY_BY_TLD[tld] || "Unknown";
}

// ============================================================
// STATUS CLASSIFICATION: Layer 1 — HTTP/Network Level
// ============================================================
function classifyLayer1(fetchResult, domain) {
  if (fetchResult.tooLarge) {
    return { status: "ISSUES", reason: "Page Too Large" };
  }
  if (!fetchResult.ok) {
    if (fetchResult.error === "DNS Not Found") return { status: "DEAD", reason: "DNS Not Found" };
    if (["Connection Refused", "Timeout", "Aborted"].includes(fetchResult.error)) {
      return { status: "DOWN", reason: "Website Not Working" };
    }
    return { status: "ERROR", reason: "Website Not Working" };
  }

  const code = fetchResult.statusCode;

  if (code === 404) return { status: "ISSUES", reason: "404 Not Found" };
  if (code === 403) return { status: "ISSUES", reason: "403 Forbidden" };
  if (code === 410) return { status: "ISSUES", reason: "410 Gone" };
  if (code >= 500) return { status: "ISSUES", reason: `Server Error (${code})` };

  const finalUrl = (fetchResult.finalUrl || "").toLowerCase();
  for (const parking of PARKING_DOMAINS) {
    if (finalUrl.includes(parking)) {
      return { status: "REDIRECT_HOST", reason: "Redirects to Registrar" };
    }
  }

  try {
    const finalHost = new URL(fetchResult.finalUrl).hostname.replace(/^www\./, "").toLowerCase();
    const originalHost = domain.replace(/^www\./, "").toLowerCase();
    if (finalHost && originalHost && !finalHost.endsWith(originalHost) && !originalHost.endsWith(finalHost)) {
      return { status: "CROSS_DOMAIN_REDIRECT", reason: "Redirects to unrelated domain" };
    }
  } catch (_e) {
    // ignore URL parse failures
  }

  return null; // No Layer 1 issue — proceed to Layer 2
}

// ============================================================
// STATUS CLASSIFICATION: Layer 2 — Content Analysis
// ============================================================
function classifyLayer2(html) {
  if (!html || typeof html !== "string") {
    return { status: "NO_CONTENT", reason: "Empty Response" };
  }

  const $ = cheerio.load(html);
  $("script, style, noscript, iframe").remove();
  const bodyText = $.text().replace(/\s+/g, " ").trim();
  const bodyLength = bodyText.length;
  const htmlLower = html.toLowerCase();

  for (const kw of SUSPENDED_KEYWORDS) {
    if (htmlLower.includes(kw)) {
      return { status: "SUSPENDED", reason: "Hosting Suspended" };
    }
  }

  const ignoreKeywordClassification = bodyLength > 8000;
  const parkingCount = countKeywordMatches(htmlLower, PARKING_KEYWORDS);
  const comingSoonCount = countKeywordMatches(htmlLower, COMING_SOON_KEYWORDS);
  const constructionCount = countKeywordMatches(htmlLower, UNDER_CONSTRUCTION_KEYWORDS);

  if (!ignoreKeywordClassification && parkingCount >= 2 && bodyLength < 4000) {
    return { status: "PARKED", reason: "Parked Domain" };
  }

  if (htmlLower.includes("domain is for sale") || htmlLower.includes("buy this domain") || htmlLower.includes("domain for sale")) {
    return { status: "PARKED", reason: "Domain For Sale" };
  }

  if (DEFAULT_PAGE_KEYWORDS.some((kw) => htmlLower.includes(kw))) {
    return { status: "DEFAULT_PAGE", reason: "Default server page" };
  }

  if (!ignoreKeywordClassification && constructionCount >= 2 && bodyLength < 4000) {
    return { status: "COMING_SOON", reason: "Under Construction" };
  }

  if (!ignoreKeywordClassification && comingSoonCount >= 2 && bodyLength < 4000) {
    return { status: "COMING_SOON", reason: "Coming Soon" };
  }

  const templateHits = countKeywordMatches(htmlLower, COMING_SOON_TEMPLATE_KEYWORDS);
  if (templateHits >= 3 && bodyLength < 5000) {
    return { status: "SHELL_SITE", reason: "Template/Shell Website" };
  }

  if (bodyLength < 100) {
    return { status: "NO_CONTENT", reason: "Empty Page" };
  }
  if (bodyLength < 300) {
    return { status: "NO_CONTENT", reason: "Minimal Content" };
  }

  const hasLoginForm = htmlLower.includes('type="password"') || htmlLower.includes("login") || htmlLower.includes("sign in");
  const hasOnlyLogin = hasLoginForm && bodyLength < 2000;
  if (hasOnlyLogin) {
    return { status: "NO_CONTENT", reason: "Login Portal Only" };
  }

  return null; // No Layer 2 issue — proceed to Layer 3
}

// ============================================================
// STATUS CLASSIFICATION: Layer 3 — Business Signal Detection
// ============================================================
function classifyLayer3(signals) {
 const {
    hasPhone,
    hasEmail,
    hasSocial,
    hasAddress,
    hasGoogleMaps,
  } = signals;

  const confidenceScore =
    (hasPhone ? 3 : 0) +
    (hasEmail ? 3 : 0) +
    (hasAddress ? 3 : 0) +
    (hasSocial ? 2 : 0) +
    (hasGoogleMaps ? 3 : 0);

  if (confidenceScore >= 7) {
    return { status: "ACTIVE", reason: "Active (Strong)", confidenceScore };
  }
  if (confidenceScore >= 4) {
    return { status: "ACTIVE", reason: "Active", confidenceScore };
  }

  return { status: "SHELL_SITE", reason: "Weak Business Signal", confidenceScore };
}

// ============================================================
// BUILD SIGNALS SUMMARY STRING
// ============================================================
function buildSignalsSummary(phone, email, social, address) {
  const parts = [];
  parts.push(phone ? "Phone ✓" : "Phone ✗");
  parts.push(email ? "Email ✓" : "Email ✗");

  const hasSocial = social.facebook || social.instagram || social.linkedin;
  parts.push(hasSocial ? "Social ✓" : "Social ✗");

  const hasAddr = address.street || address.city;
  parts.push(hasAddr ? "Address ✓" : "Address ✗");

  return parts.join(" | ");
}
async function processWithConcurrency(items, concurrency, worker) {
  const results = [];
  let index = 0;

  async function runNext() {
    while (index < items.length) {
      const currentIndex = index++;
      const value = await worker(items[currentIndex], currentIndex);
      if (value) results.push(value);
    }
  }

  const runners = Array.from({ length: Math.min(concurrency, items.length) }, () => runNext());
  await Promise.all(runners);
  return results;
}

// ============================================================
// MAIN: Scan a single domain (multi-page crawl)
// ============================================================
async function scanDomain(inputDomain) {
  const validated = await validateAndResolveDomain(inputDomain);
  if (!validated.ok) {
    return {
      domain: validated.domain || normalizeDomain(inputDomain),
      status: "ERROR",
      statusCode: 0,
      reason: validated.error,
      name: "",
      country: "Unknown",
      phone: "",
      email: "",
      street: "",
      city: "",
      state: "",
      zip: "",
      social: { facebook: "", instagram: "", linkedin: "", gmb: "" },
      signals: "Phone ✗ | Email ✗ | Social ✗ | Address ✗",
      pagesCrawled: "",
      confidenceScore: 0,
      domainAge: "Unknown",
    };
  }

  const domain = validated.domain;
  logEvent("scan_start", { domain });
 const scanController = new AbortController();
  let scanTimedOut = false;
  const timeoutId = setTimeout(() => {
    scanTimedOut = true;
    scanController.abort();
  }, DOMAIN_SCAN_TIMEOUT);

  try {
    const baseUrl = `https://${domain}`;
    
  // ---- Step 1: Fetch homepage + whois in parallel ----
    const whoisPromise = resolveDomainAge(domain);
    const homepage = await fetchPage(baseUrl, scanController.signal);

  // If HTTPS fails with SSL error, try HTTP
    let homepageResult = homepage;
    if (!homepage.ok && (homepage.error.includes("SSL") || homepage.error.includes("certificate"))) {
      homepageResult = await fetchPage(`http://${domain}`, scanController.signal);
    }
    const domainAge = await whoisPromise;
    
   // ---- Step 2: Layer 1 classification (HTTP level) ----
    const layer1 = classifyLayer1(homepageResult, domain);

    // ---- Step 3: Always crawl sub-pages (user chose thorough mode) ----
    const crawledPages = [{ url: baseUrl, html: homepageResult.html, code: homepageResult.statusCode }];
    const pagesCrawled = ["homepage"];;

  if (!scanTimedOut) {
      const robotsDisallow = await fetchRobotsDisallowRules(baseUrl, scanController.signal);
      const discoveredPaths = discoverInternalLinks(homepageResult.html, baseUrl, domain);
      const allPaths = [...new Set([...SUB_PAGES, ...discoveredPaths])];
      const allowedPaths = allPaths.filter((pathPart) => !isPathDisallowed(pathPart, robotsDisallow));

        // Crawl sub-pages in parallel
      const subPagePromises = allowedPaths.map(async (pathPart) => {
        if (scanTimedOut) return null;

 const subUrl = `${baseUrl}${pathPart}`;
        const result = await fetchPage(subUrl, scanController.signal);
        if (result.ok && result.statusCode >= 200 && result.statusCode < 400 && result.html.length > 200) {
          return { url: subUrl, html: result.html, code: result.statusCode, path: pathPart };
        }
        return null;
      });

      const subResults = await Promise.all(subPagePromises);
      for (const sub of subResults) {
        if (sub) {
          crawledPages.push(sub);
          pagesCrawled.push(sub.path);
        }
      }
    }

    // ---- Step 4: Extract data from ALL crawled pages ----
    let bestName = "";
    let bestPhone = "";
    let bestEmail = "";
   let bestAddress = { street: "", city: "", state: "", zip: "", country: "" };
    let bestSocial = { facebook: "", instagram: "", linkedin: "", gmb: "" };

    for (const page of crawledPages) {
      if (!page.html) continue;

      if (!bestName) {
        bestName = extractBusinessName(page.html, domain);
      }

      if (!bestPhone) {
        bestPhone = extractPhone(page.html);
      }

      if (!bestEmail) {
        bestEmail = extractEmail(page.html);
      }

      if (!bestAddress.street && !bestAddress.city) {
        const addr = extractAddressFromPage(page.html);
        if (addr.street || addr.city) {
          bestAddress = addr;
        }
      }

      const pageSocial = extractSocial(page.html);
      if (!bestSocial.facebook && pageSocial.facebook) bestSocial.facebook = pageSocial.facebook;
      if (!bestSocial.instagram && pageSocial.instagram) bestSocial.instagram = pageSocial.instagram;
      if (!bestSocial.linkedin && pageSocial.linkedin) bestSocial.linkedin = pageSocial.linkedin;
      if (!bestSocial.gmb && pageSocial.gmb) bestSocial.gmb = pageSocial.gmb;
    }

    const detectedCountry = extractCountryFromPage(homepageResult.html, domain, bestAddress, bestPhone);
    
    // ---- Step 5: Final status classification ----
    let finalStatus;
    let finalReason;

    const layer3Signals = {
      hasPhone: !!bestPhone,
      hasEmail: !!bestEmail,
      hasSocial: !!(bestSocial.facebook || bestSocial.instagram || bestSocial.linkedin),
      hasAddress: !!(bestAddress.street || bestAddress.city),
      hasGoogleMaps: !!bestSocial.gmb,
    };
    const layer3 = classifyLayer3(layer3Signals);

    if (layer1) {
      const hasSomething = layer3.confidenceScore > 0;
      if (hasSomething && layer1.status === "ERROR") {
        finalStatus = "ACTIVE";
        finalReason = `Homepage ${layer1.reason}, but business info found on sub-pages`;
      } else {
        finalStatus = layer1.status;
        finalReason = layer1.reason;
      }
    } else {
      const layer2 = classifyLayer2(homepageResult.html);

      if (layer2) {
        const hasSomething = layer3.confidenceScore > 0;

        if (hasSomething && layer2.status === "NO_CONTENT") {
          finalStatus = "ACTIVE";
          finalReason = "Business signals found despite thin content";
        } else {
          finalStatus = layer2.status;
          finalReason = layer2.reason;
        }
      } else {
        finalStatus = layer3.status;
        finalReason = layer3.reason;
      }
    }

    if (scanTimedOut) {
      finalReason = finalReason ? `${finalReason} | Scan Timeout` : "Scan Timeout";
    }

    const signalsSummary = buildSignalsSummary(bestPhone, bestEmail, bestSocial, bestAddress);

    const result = {
      domain,
      status: finalStatus,
      country: detectedCountry,
      statusCode: homepageResult.statusCode,
      reason: finalReason,
      name: bestName,
      phone: bestPhone,
      email: bestEmail,
      street: bestAddress.street,
      city: bestAddress.city,
      state: bestAddress.state,
      zip: bestAddress.zip,
      social: bestSocial,
      signals: signalsSummary,
      pagesCrawled: pagesCrawled.join(", "),
      confidenceScore: layer3.confidenceScore,
      domainAge,
    };

    logEvent("scan_complete", {
      domain,
      status: finalStatus,
      reason: finalReason,
      confidenceScore: layer3.confidenceScore,
      pages: pagesCrawled.length,
    });

    return result;
    
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================
// ENDPOINTS
// ============================================================

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", message: "Website Intelligence Scanner v2.0" });
});

// Batch scan: 5 domains in parallel, up to 60 domains total
app.post("/batch-scan", scanRateLimiter, async (req, res) => {
  try {
    const { domains } = req.body;

    if (!domains || !Array.isArray(domains) || domains.length === 0) {
      return res.status(400).json({ error: "Domains array required" });
    }

    const batch = domains.slice(0, MAX_BATCH_SIZE);

    const validations = await Promise.all(batch.map((d) => validateAndResolveDomain(d)));
    const invalid = validations.filter((v) => !v.ok);
    if (invalid.length > 0) {
      return res.status(400).json({
        error: "Invalid or blocked domains",
        details: invalid.map((v) => ({ domain: v.domain, reason: v.error })),
      });
    }

    const results = await processWithConcurrency(batch, BATCH_CONCURRENCY, async (d) => scanDomain(d));

    res.json(results);
  } catch (err) {
    logEvent("fetch_error", { scope: "batch-scan", error: err.message || "Unknown" });
    res.status(500).json({ error: "Server error: " + (err.message || "Unknown") });
  }
});

// Backward-compatible full bulk endpoint
app.post("/bulk-analyze", scanRateLimiter, async (req, res) => {
  try {
    const { domains } = req.body;

    if (!domains || !Array.isArray(domains) || domains.length === 0) {
      return res.status(400).json({ error: "Domains array required" });
    }

    const limited = domains.slice(0, MAX_BATCH_SIZE);

    const validations = await Promise.all(limited.map((d) => validateAndResolveDomain(d)));
    const invalid = validations.filter((v) => !v.ok);
    if (invalid.length > 0) {
      return res.status(400).json({
        error: "Invalid or blocked domains",
        details: invalid.map((v) => ({ domain: v.domain, reason: v.error })),
      });
    }

    const results = await processWithConcurrency(limited, BATCH_CONCURRENCY, async (d) => scanDomain(d));
    res.json(results);
  } catch (err) {
    logEvent("fetch_error", { scope: "bulk-analyze", error: err.message || "Unknown" });
    res.status(500).json({ error: "Server error: " + (err.message || "Unknown") });
  }
});

// ============================================================
// START SERVER
// ============================================================
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "0.0.0.0";

app.listen(PORT, HOST, () => {
  console.log(`Website Intelligence Scanner v2.0 running on http://${HOST}:${PORT}`);
});
