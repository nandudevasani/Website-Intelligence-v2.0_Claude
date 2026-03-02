import express from "express";
import cors from "cors";
import axios from "axios";
import * as cheerio from "cheerio";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// Serve index.html at root
app.use(express.static(__dirname));

// ============================================================
// CONFIGURATION
// ============================================================
const FETCH_TIMEOUT = 8000; // 8 seconds per page
const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

// Sub-pages to always crawl (in addition to homepage)
const SUB_PAGES = [
  "/contact",
  "/contact-us",
  "/about",
  "/about-us",
  "/privacy-policy",
  "/privacy",
];

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

// ============================================================
// UTILITY: Fetch a single page
// ============================================================
async function fetchPage(url) {
  try {
    const response = await axios.get(url, {
      timeout: FETCH_TIMEOUT,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: { "User-Agent": USER_AGENT },
      responseType: "text",
    });

    const finalUrl = response.request?.res?.responseUrl || response.config?.url || url;

    return {
      ok: true,
      html: typeof response.data === "string" ? response.data : "",
      statusCode: response.status,
      finalUrl: finalUrl,
      headers: response.headers,
      error: null,
    };
  } catch (err) {
    let errorType = "Unknown Error";
    if (err.code === "ENOTFOUND") errorType = "DNS Not Found";
    else if (err.code === "ECONNREFUSED") errorType = "Connection Refused";
    else if (err.code === "ETIMEDOUT" || err.code === "ECONNABORTED") errorType = "Timeout";
    else if (err.code === "ERR_TLS_CERT_ALTNAME_INVALID") errorType = "SSL Certificate Invalid";
    else if (err.code === "CERT_HAS_EXPIRED") errorType = "SSL Certificate Expired";
    else if (err.code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE") errorType = "SSL Verification Failed";
    else if (err.code === "ERR_FR_TOO_MANY_REDIRECTS") errorType = "Too Many Redirects";
    else if (err.message) errorType = err.message.substring(0, 80);

    return {
      ok: false,
      html: "",
      statusCode: 0,
      finalUrl: url,
      headers: {},
      error: errorType,
    };
  }
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
function extractEmail(html, domain) {
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
  const allHtml = $.html().toLowerCase();

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
  const address = { street: "", city: "", state: "", zip: "" };

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
        if (address.street || address.city) return address;
      }
    }
  }

  // Priority 2: Microdata itemprop
  const street = $('[itemprop="streetAddress"]').first().text().trim();
  const city = $('[itemprop="addressLocality"]').first().text().trim();
  const state = $('[itemprop="addressRegion"]').first().text().trim();
  const zip = $('[itemprop="postalCode"]').first().text().trim();
  if (street || city) {
    address.street = street;
    address.city = city;
    address.state = state.substring(0, 2).toUpperCase();
    address.zip = zip;
    return address;
  }

  // Priority 3: Footer-focused regex
  const footerText = $("footer").text() || "";
  const footerAddr = parseAddressFromText(footerText);
  if (footerAddr.street || footerAddr.city) return footerAddr;

  // Priority 4: Full page regex (last resort)
  const bodyText = $.text() || "";
  const fullAddr = parseAddressFromText(bodyText);
  if (fullAddr.street || fullAddr.city) return fullAddr;

  return address;
}

// ============================================================
// UTILITY: Parse US address from raw text using regex
// ============================================================
function parseAddressFromText(text) {
  const address = { street: "", city: "", state: "", zip: "" };

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

// ============================================================
// STATUS CLASSIFICATION: Layer 1 — HTTP/Network Level
// ============================================================
function classifyLayer1(fetchResult) {
  if (!fetchResult.ok) {
    return { status: "Error", reason: fetchResult.error };
  }

  const code = fetchResult.statusCode;

  if (code === 404) return { status: "Error", reason: "404 Not Found" };
  if (code === 403) return { status: "Error", reason: "403 Forbidden" };
  if (code === 410) return { status: "Error", reason: "410 Gone" };
  if (code >= 500) return { status: "Error", reason: `Server Error (${code})` };

  // Check if redirected to a parking/registrar domain
  const finalUrl = (fetchResult.finalUrl || "").toLowerCase();
  for (const parking of PARKING_DOMAINS) {
    if (finalUrl.includes(parking)) {
      return { status: "Parked", reason: "Redirects to Registrar" };
    }
  }

  return null; // No Layer 1 issue — proceed to Layer 2
}

// ============================================================
// STATUS CLASSIFICATION: Layer 2 — Content Analysis
// ============================================================
function classifyLayer2(html) {
  if (!html || typeof html !== "string") {
    return { status: "No Content", reason: "Empty Response" };
  }

  const $ = cheerio.load(html);

  // Get meaningful text content (strip scripts, styles, tags)
  $("script, style, noscript, iframe").remove();
  const bodyText = $.text().replace(/\s+/g, " ").trim();
  const bodyLength = bodyText.length;
  const htmlLower = html.toLowerCase();

  // Check for suspended hosting
  for (const kw of SUSPENDED_KEYWORDS) {
    if (htmlLower.includes(kw)) {
      return { status: "Suspended", reason: "Hosting Suspended" };
    }
  }

  // Check for parking pages
  for (const kw of PARKING_KEYWORDS) {
    if (htmlLower.includes(kw)) {
      return { status: "Parked", reason: "Parked Domain" };
    }
  }

  // Check for "domain for sale" specifically
  if (htmlLower.includes("domain is for sale") || htmlLower.includes("buy this domain") || htmlLower.includes("domain for sale")) {
    return { status: "Parked", reason: "Domain For Sale" };
  }

  // Check for under construction
  for (const kw of UNDER_CONSTRUCTION_KEYWORDS) {
    if (htmlLower.includes(kw)) {
      // Only classify if page is relatively thin (real sites might mention "under construction" in a blog post)
      if (bodyLength < 5000) {
        return { status: "Under Construction", reason: "Under Construction" };
      }
    }
  }

  // Check for coming soon
  for (const kw of COMING_SOON_KEYWORDS) {
    if (htmlLower.includes(kw)) {
      if (bodyLength < 5000) {
        return { status: "Coming Soon", reason: "Coming Soon" };
      }
    }
  }

  // Check for empty/minimal content
  if (bodyLength < 100) {
    return { status: "No Content", reason: "Empty Page" };
  }
  if (bodyLength < 300) {
    return { status: "No Content", reason: "Minimal Content" };
  }

  // Check for login-only pages
  const hasLoginForm = htmlLower.includes('type="password"') || htmlLower.includes("login") || htmlLower.includes("sign in");
  const hasOnlyLogin = hasLoginForm && bodyLength < 2000;
  if (hasOnlyLogin) {
    return { status: "No Content", reason: "Login Portal Only" };
  }

  return null; // No Layer 2 issue — proceed to Layer 3
}

// ============================================================
// STATUS CLASSIFICATION: Layer 3 — Business Signal Detection
// ============================================================
function classifyLayer3(signals) {
  const { hasPhone, hasEmail, hasSocial, hasAddress } = signals;
  const signalCount = [hasPhone, hasEmail, hasSocial, hasAddress].filter(Boolean).length;

  if (signalCount >= 2) {
    return { status: "Active", reason: "Verified Business (Strong)" };
  }
  if (signalCount === 1) {
    return { status: "Active", reason: "Verified Business" };
  }

  // No contact signals at all
  return { status: "Shell", reason: "No Contact Information Found" };
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

// ============================================================
// MAIN: Scan a single domain (multi-page crawl)
// ============================================================
async function scanDomain(domain) {
  console.log(`\n[SCAN] Starting: ${domain}`);

  // Clean up domain
  domain = domain.trim().replace(/^https?:\/\//, "").replace(/\/+$/, "").toLowerCase();
  if (!domain) return null;

  const baseUrl = `https://${domain}`;

  // ---- Step 1: Fetch homepage ----
  console.log(`  [FETCH] Homepage: ${baseUrl}`);
  const homepage = await fetchPage(baseUrl);

  // If HTTPS fails with SSL error, try HTTP
  let homepageResult = homepage;
  if (!homepage.ok && (homepage.error.includes("SSL") || homepage.error.includes("certificate"))) {
    console.log(`  [RETRY] Trying HTTP for ${domain}`);
    homepageResult = await fetchPage(`http://${domain}`);
  }

  // ---- Step 2: Layer 1 classification (HTTP level) ----
  const layer1 = classifyLayer1(homepageResult);

  // ---- Step 3: Always crawl sub-pages (user chose thorough mode) ----
  const crawledPages = [{ url: baseUrl, html: homepageResult.html, code: homepageResult.statusCode }];
  const pagesCrawled = ["homepage"];

  // Crawl sub-pages in parallel
  const subPagePromises = SUB_PAGES.map(async (path) => {
    const subUrl = `${baseUrl}${path}`;
    try {
      const result = await fetchPage(subUrl);
      if (result.ok && result.statusCode >= 200 && result.statusCode < 400 && result.html.length > 200) {
        return { url: subUrl, html: result.html, code: result.statusCode, path: path };
      }
    } catch (e) { /* skip */ }
    return null;
  });

  const subResults = await Promise.all(subPagePromises);
  for (const sub of subResults) {
    if (sub) {
      crawledPages.push(sub);
      pagesCrawled.push(sub.path);
    }
  }

  console.log(`  [CRAWL] Pages found: ${pagesCrawled.join(", ")}`);

  // ---- Step 4: Extract data from ALL crawled pages ----
  let bestName = "";
  let bestPhone = "";
  let bestEmail = "";
  let bestAddress = { street: "", city: "", state: "", zip: "" };
  let bestSocial = { facebook: "", instagram: "", linkedin: "", gmb: "" };

  for (const page of crawledPages) {
    if (!page.html) continue;

    // Name: prefer homepage extraction
    if (!bestName) {
      bestName = extractBusinessName(page.html, domain);
    }

    // Phone: take first found
    if (!bestPhone) {
      bestPhone = extractPhone(page.html);
    }

    // Email: take first found
    if (!bestEmail) {
      bestEmail = extractEmail(page.html, domain);
    }

    // Address: take first complete one
    if (!bestAddress.street && !bestAddress.city) {
      const addr = extractAddressFromPage(page.html);
      if (addr.street || addr.city) {
        bestAddress = addr;
      }
    }

    // Social: merge from all pages
    const pageSocial = extractSocial(page.html);
    if (!bestSocial.facebook && pageSocial.facebook) bestSocial.facebook = pageSocial.facebook;
    if (!bestSocial.instagram && pageSocial.instagram) bestSocial.instagram = pageSocial.instagram;
    if (!bestSocial.linkedin && pageSocial.linkedin) bestSocial.linkedin = pageSocial.linkedin;
    if (!bestSocial.gmb && pageSocial.gmb) bestSocial.gmb = pageSocial.gmb;
  }

  // ---- Step 5: Final status classification ----
  let finalStatus, finalReason;

  if (layer1) {
    // Layer 1 caught an error — but if we found business signals on sub-pages, override!
    const hasSomething = bestPhone || bestEmail || bestSocial.facebook || bestSocial.instagram || bestSocial.linkedin;
    if (hasSomething && layer1.status === "Error" && layer1.reason !== "DNS Not Found" && layer1.reason !== "Connection Refused" && layer1.reason !== "Timeout") {
      // Site has errors but sub-pages returned data — mark as Active with note
      finalStatus = "Active";
      finalReason = `Homepage ${layer1.reason}, but business info found on sub-pages`;
    } else {
      finalStatus = layer1.status;
      finalReason = layer1.reason;
    }
  } else {
    // Layer 1 passed — check Layer 2 (content analysis on homepage)
    const layer2 = classifyLayer2(homepageResult.html);

    if (layer2) {
      // Layer 2 found an issue — but check if business signals override it
      const hasSomething = bestPhone || bestEmail || bestSocial.facebook || bestSocial.instagram || bestSocial.linkedin;

      if (hasSomething && (layer2.status === "Shell" || layer2.status === "No Content")) {
        finalStatus = "Active";
        finalReason = "Business signals found despite thin content";
      } else if (hasSomething && layer2.status === "Coming Soon") {
        finalStatus = "Coming Soon";
        finalReason = "Coming Soon (has contact info)";
      } else {
        finalStatus = layer2.status;
        finalReason = layer2.reason;
      }
    } else {
      // Layer 2 passed — use Layer 3 (business signal check)
      const signals = {
        hasPhone: !!bestPhone,
        hasEmail: !!bestEmail,
        hasSocial: !!(bestSocial.facebook || bestSocial.instagram || bestSocial.linkedin),
        hasAddress: !!(bestAddress.street || bestAddress.city),
      };
      const layer3 = classifyLayer3(signals);
      finalStatus = layer3.status;
      finalReason = layer3.reason;
    }
  }

  // ---- Step 6: Build signals summary ----
  const signalsSummary = buildSignalsSummary(bestPhone, bestEmail, bestSocial, bestAddress);

  const result = {
    domain,
    status: finalStatus,
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
  };

  console.log(`  [DONE] ${domain} → ${finalStatus} (${finalReason}) | Name: ${bestName.substring(0, 30)} | ${signalsSummary}`);
  return result;
}

// ============================================================
// ENDPOINTS
// ============================================================

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", message: "Website Intelligence Scanner v2.0" });
});

// Batch scan: 2 domains at a time (safe for Render 30s timeout with multi-page crawl)
app.post("/batch-scan", async (req, res) => {
  try {
    const { domains } = req.body;

    if (!domains || !Array.isArray(domains) || domains.length === 0) {
      return res.status(400).json({ error: "Domains array required" });
    }

    const batch = domains.slice(0, 2); // Max 2 per batch
    const results = [];

    // Scan domains in parallel (2 at a time)
    const promises = batch.map(d => scanDomain(d));
    const outcomes = await Promise.all(promises);

    for (const r of outcomes) {
      if (r) results.push(r);
    }

    res.json(results);
  } catch (err) {
    console.error("Batch scan error:", err);
    res.status(500).json({ error: "Server error: " + (err.message || "Unknown") });
  }
});

// Backward-compatible full bulk endpoint
app.post("/bulk-analyze", async (req, res) => {
  try {
    const { domains } = req.body;

    if (!domains || !Array.isArray(domains) || domains.length === 0) {
      return res.status(400).json({ error: "Domains array required" });
    }

    const limited = domains.slice(0, 10);
    const results = [];

    for (const d of limited) {
      const r = await scanDomain(d);
      if (r) results.push(r);
    }

    res.json(results);
  } catch (err) {
    console.error("Bulk analyze error:", err);
    res.status(500).json({ error: "Server error: " + (err.message || "Unknown") });
  }
});

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Website Intelligence Scanner v2.0 running on port ${PORT}`);
});
