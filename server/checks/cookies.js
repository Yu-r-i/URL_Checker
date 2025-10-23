const axios = require('axios');
const setCookieParser = require('set-cookie-parser');

const CATEGORY_KEY = 'cookies';
const CATEGORY_LABEL = 'Cookie Security';
const MAX_SCORE = 25;
const PASSING_THRESHOLD = 18;
const DEFAULT_TIMEOUT = 8000;

const sanitizeSameSite = (value) => {
  if (!value) return undefined;
  return `${value}`.toLowerCase();
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

const analyzeCookieIssues = (cookie) => {
  const issues = [];
  const sameSite = sanitizeSameSite(cookie.sameSite);

  if (!cookie.secure) {
    issues.push('Missing Secure attribute.');
  }
  if (!cookie.httpOnly) {
    issues.push('Missing HttpOnly attribute.');
  }
  if (!sameSite) {
    issues.push('Missing SameSite attribute.');
  } else if (sameSite === 'none' && !cookie.secure) {
    issues.push('SameSite=None cookies must also be Secure.');
  }
  if (cookie.name?.startsWith('__Secure-') && !cookie.secure) {
    issues.push('__Secure- cookies must set the Secure flag.');
  }
  if (cookie.name?.startsWith('__Host-')) {
    if (!cookie.secure) {
      issues.push('__Host- cookies must set the Secure flag.');
    }
    if (cookie.path !== '/') {
      issues.push('__Host- cookies must have Path=/');
    }
    if (cookie.domain) {
      issues.push('__Host- cookies must not specify a Domain attribute.');
    }
  }

  return issues;
};

const checkCookies = async (targetUrl, context = {}) => {
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
      warnings: ['Unable to retrieve response cookies.', capturedError?.message].filter(Boolean),
      details: {},
    });
  }

  const setCookieHeader = response.headers?.['set-cookie'];
  if (!setCookieHeader || setCookieHeader.length === 0) {
    return finalizeResult({
      score: MAX_SCORE,
      warnings: [],
      details: {
        totalCookies: 0,
        note: 'No cookies were set during the initial request.',
      },
    });
  }

  const parsedCookies = setCookieParser.parse(setCookieHeader, { map: false });

  let penalty = 0;
  const cookiesWithDetails = parsedCookies.map((cookie) => {
    const issues = analyzeCookieIssues(cookie);
    if (issues.length > 0) {
      penalty += issues.length * 5;
    }
    return {
      name: cookie.name,
      domain: cookie.domain,
      path: cookie.path,
      expires: cookie.expires ? new Date(cookie.expires).toISOString() : undefined,
      secure: Boolean(cookie.secure),
      httpOnly: Boolean(cookie.httpOnly),
      sameSite: sanitizeSameSite(cookie.sameSite),
      issues,
    };
  });

  const score = Math.max(0, MAX_SCORE - Math.min(MAX_SCORE, penalty));
  const insecureCookies = cookiesWithDetails.filter((cookie) => cookie.issues.length > 0);
  const warnings = insecureCookies.map(
    (cookie) => `${cookie.name}: ${cookie.issues.join(' ')}`,
  );

  return finalizeResult({
    score,
    warnings,
    details: {
      totalCookies: parsedCookies.length,
      insecureCookies: insecureCookies.length,
      cookies: cookiesWithDetails,
    },
  });
};

module.exports = {
  checkCookies,
  CATEGORY_KEY,
  CATEGORY_LABEL,
  MAX_SCORE,
};
