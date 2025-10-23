const whois = require('whois-json');
const psl = require('psl');

const CATEGORY_KEY = 'whois';
const CATEGORY_LABEL = 'Domain WHOIS';
const MAX_SCORE = 25;
const PASSING_THRESHOLD = 18;
const DEFAULT_TIMEOUT = 10000;
const DAY_IN_MS = 1000 * 60 * 60 * 24;

const normalizeRecord = (record = {}) =>
  Object.entries(record).reduce((acc, [key, value]) => {
    const normalizedKey = key.toLowerCase().replace(/[\s_-]/g, '');
    acc[normalizedKey] = value;
    return acc;
  }, {});

const pickValue = (record, keys) => {
  for (const key of keys) {
    const normalizedKey = key.toLowerCase().replace(/[\s_-]/g, '');
    if (record[normalizedKey] !== undefined) {
      return record[normalizedKey];
    }
  }
  return undefined;
};

const parseDate = (value) => {
  if (!value) return undefined;
  const candidate = Array.isArray(value) ? value[0] : value;
  if (typeof candidate !== 'string') {
    return undefined;
  }
  const cleaned = candidate.trim();
  const parsed = new Date(cleaned);
  if (Number.isNaN(parsed.getTime())) {
    return undefined;
  }
  return parsed;
};

const toArray = (value) => {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') {
    return value
      .split(/\s+/)
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  return [];
};

const finalizeResult = ({ score, warnings, details }) => {
  const boundedScore = Math.max(0, Math.min(MAX_SCORE, Math.round(score)));
  return {
    key: CATEGORY_KEY,
    label: CATEGORY_LABEL,
    score: boundedScore,
    maxScore: MAX_SCORE,
    passed: boundedScore >= PASSING_THRESHOLD,
    warnings,
    details,
  };
};

const checkWhois = async (targetUrl) => {
  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    return finalizeResult({
      score: 0,
      warnings: ['The URL is not valid, so WHOIS information could not be checked.'],
      details: {},
    });
  }

  const domainInfo = psl.parse(parsedUrl.hostname);
  if (!domainInfo.domain) {
    return finalizeResult({
      score: 0,
      warnings: ['Unable to determine a registrable domain for WHOIS lookup.'],
      details: { hostname: parsedUrl.hostname },
    });
  }

  let record;
  try {
    record = await whois(domainInfo.domain, { timeout: DEFAULT_TIMEOUT });
  } catch (error) {
    return finalizeResult({
      score: 0,
      warnings: ['WHOIS lookup failed.', error.message].filter(Boolean),
      details: { hostname: parsedUrl.hostname },
    });
  }

  if (!record || Object.keys(record).length === 0) {
    return finalizeResult({
      score: 0,
      warnings: ['WHOIS lookup did not return any data.'],
      details: { hostname: parsedUrl.hostname },
    });
  }

  const normalized = normalizeRecord(record);

  const creationDate =
    parseDate(
      pickValue(normalized, [
        'creationdate',
        'createddate',
        'creationtime',
        'domaincreatedate',
        'registrationtime',
        'domainregistrationdate',
        'registered',
      ]),
    ) || undefined;

  const expiryDate =
    parseDate(
      pickValue(normalized, [
        'registryexpirydate',
        'expirationdate',
        'expirydate',
        'registrarexpirationdate',
        'domainexpirydate',
      ]),
    ) || undefined;

  const registrar =
    pickValue(normalized, [
      'registrar',
      'registrarname',
      'registrarorganization',
      'sponsoringregistrar',
    ]) || undefined;

  const nameServers = toArray(
    pickValue(normalized, ['nameserver', 'nameservers', 'nameserverserver']),
  );

  const warnings = [];
  let score = MAX_SCORE;
  const details = {
    domain: domainInfo.domain,
    registrar,
    nameServers,
  };

  if (creationDate) {
    const domainAgeDays = Math.floor((Date.now() - creationDate.getTime()) / DAY_IN_MS);
    details.creationDate = creationDate.toISOString();
    details.domainAgeDays = domainAgeDays;
    if (domainAgeDays < 30) {
      warnings.push('Domain was registered within the last 30 days.');
      score -= 12;
    } else if (domainAgeDays < 180) {
      warnings.push('Domain is relatively new (less than six months old).');
      score -= 6;
    }
  } else {
    warnings.push('Unable to determine domain creation date.');
    score -= 6;
  }

  if (expiryDate) {
    const daysUntilExpiry = Math.floor((expiryDate.getTime() - Date.now()) / DAY_IN_MS);
    details.expiryDate = expiryDate.toISOString();
    details.daysUntilExpiry = daysUntilExpiry;
    if (daysUntilExpiry <= 0) {
      warnings.push('Domain appears to be expired.');
      score -= 10;
    } else if (daysUntilExpiry <= 30) {
      warnings.push('Domain expires within the next 30 days.');
      score -= 6;
    }
  } else {
    warnings.push('Unable to determine domain expiry date.');
    score -= 5;
  }

  if (!registrar) {
    warnings.push('Registrar information is missing.');
    score -= 3;
  }

  return finalizeResult({
    score,
    warnings,
    details,
  });
};

module.exports = {
  checkWhois,
  CATEGORY_KEY,
  CATEGORY_LABEL,
  MAX_SCORE,
};
