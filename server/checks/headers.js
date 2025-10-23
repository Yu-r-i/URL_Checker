const axios = require('axios');

const CATEGORY_KEY = 'headers';
const CATEGORY_LABEL = 'Security Headers';
const MAX_SCORE = 25;
const PASSING_THRESHOLD = 18;
const DEFAULT_TIMEOUT = 8000;

const normalizeValue = (value) => {
  if (Array.isArray(value)) {
    return value.map((entry) => `${entry}`.trim()).join(', ');
  }
  if (typeof value === 'number') {
    return String(value);
  }
  if (value === undefined || value === null) {
    return undefined;
  }
  return value.trim();
};

const createHeaderChecks = (headers) => {
  const csp = headers['content-security-policy'];
  const cspValue = normalizeValue(csp);
  const hasFrameAncestors = cspValue && /frame-ancestors\s+/i.test(cspValue);

  return [
    {
      key: 'strict-transport-security',
      label: 'HSTS (Strict-Transport-Security)',
      weight: 5,
      present: Boolean(headers['strict-transport-security']),
      valid: () => {
        const value = normalizeValue(headers['strict-transport-security']);
        return Boolean(value && /max-age=\d+/i.test(value));
      },
      warning: 'Missing Strict-Transport-Security header (HSTS).',
    },
    {
      key: 'content-security-policy',
      label: 'Content-Security-Policy',
      weight: 5,
      present: Boolean(headers['content-security-policy']),
      valid: () => Boolean(cspValue && cspValue.length > 0),
      warning: 'Missing Content-Security-Policy header.',
    },
    {
      key: 'x-frame-options',
      label: 'Clickjacking protection',
      weight: 4,
      present: Boolean(headers['x-frame-options']) || hasFrameAncestors,
      valid: () => {
        const value = normalizeValue(headers['x-frame-options']);
        if (value) {
          return /sameorigin|deny/i.test(value);
        }
        return hasFrameAncestors;
      },
      warning: 'Missing X-Frame-Options header or frame-ancestors directive.',
    },
    {
      key: 'referrer-policy',
      label: 'Referrer-Policy',
      weight: 4,
      present: Boolean(headers['referrer-policy']),
      valid: () => {
        const value = normalizeValue(headers['referrer-policy']);
        return Boolean(
          value &&
            /(no-referrer|strict-origin|strict-origin-when-cross-origin)/i.test(value),
        );
      },
      warning: 'Missing Referrer-Policy header.',
    },
    {
      key: 'permissions-policy',
      label: 'Permissions-Policy',
      weight: 3,
      present: Boolean(headers['permissions-policy']),
      valid: () => {
        const value = normalizeValue(headers['permissions-policy']);
        return Boolean(value && value.length > 0);
      },
      warning: 'Missing Permissions-Policy header.',
    },
    {
      key: 'x-content-type-options',
      label: 'X-Content-Type-Options',
      weight: 4,
      present: Boolean(headers['x-content-type-options']),
      valid: () => {
        const value = normalizeValue(headers['x-content-type-options']);
        return Boolean(value && value.toLowerCase() === 'nosniff');
      },
      warning: 'Missing X-Content-Type-Options header (nosniff).',
    },
  ];
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

const extractHeaders = (response) => {
  if (!response || !response.headers) {
    return {};
  }
  return Object.entries(response.headers).reduce((acc, [rawKey, value]) => {
    acc[rawKey.toLowerCase()] = value;
    return acc;
  }, {});
};

const checkHeaders = async (targetUrl, context = {}) => {
  const { response: prefetchedResponse, fetchError } = context;
  let response = prefetchedResponse;
  let capturedError = fetchError;

  if (!response) {
    try {
      response = await axios.get(targetUrl, {
        timeout: DEFAULT_TIMEOUT,
        maxRedirects: 5,
        validateStatus: () => true,
        headers: {
          'User-Agent': 'SafeURLChecker/1.0',
          Accept: 'text/html,application/xhtml+xml',
        },
      });
    } catch (error) {
      capturedError = error;
      response = error.response;
    }
  }

  if (!response) {
    return finalizeResult({
      score: 0,
      warnings: [
        'Unable to retrieve the site response headers.',
        capturedError?.message,
      ].filter(Boolean),
      details: {},
    });
  }

  const headers = extractHeaders(response);
  const checks = createHeaderChecks(headers);
  const warnings = [];
  let score = MAX_SCORE;

  const presentHeaders = {};
  Object.entries(headers).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      presentHeaders[key] = normalizeValue(value);
    }
  });

  checks.forEach((check) => {
    if (!check.present || !check.valid()) {
      warnings.push(check.warning);
      score -= check.weight;
    }
  });

  return finalizeResult({
    score,
    warnings,
    details: {
      statusCode: response.status,
      finalUrl: response.request?.res?.responseUrl || response.config?.url || targetUrl,
      presentHeaders,
      missing: checks
        .filter((check) => !check.present || !check.valid())
        .map((check) => check.label),
    },
  });
};

module.exports = {
  checkHeaders,
  CATEGORY_KEY,
  CATEGORY_LABEL,
  MAX_SCORE,
};
