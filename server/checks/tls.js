const tls = require('tls');

const CATEGORY_KEY = 'tls';
const CATEGORY_LABEL = 'HTTPS & TLS';
const MAX_SCORE = 25;
const PASSING_THRESHOLD = 18;
const DEFAULT_TIMEOUT = 5000;

const formatName = (entity = {}) => {
  if (typeof entity !== 'object' || entity === null) {
    return null;
  }
  const preferredOrder = ['CN', 'O', 'OU'];
  const parts = preferredOrder
    .map((key) => entity[key])
    .filter(Boolean);
  if (parts.length === 0) {
    const fallback = Object.values(entity).filter(Boolean);
    return fallback.length > 0 ? fallback.join(', ') : null;
  }
  return parts.join(', ');
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

const checkTLS = async (targetUrl, options = {}) => {
  const { timeout = DEFAULT_TIMEOUT } = options;
  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    return finalizeResult({
      score: 0,
      warnings: ['The URL is not valid, so the TLS certificate could not be checked.'],
      details: {},
    });
  }

  if (parsedUrl.protocol !== 'https:') {
    return finalizeResult({
      score: 0,
      warnings: ['Site does not use HTTPS; TLS certificate was not evaluated.'],
      details: {
        protocol: parsedUrl.protocol.replace(':', ''),
      },
    });
  }

  const port = parsedUrl.port ? Number(parsedUrl.port) : 443;

  return new Promise((resolve) => {
    let settled = false;
    const resolveSafe = (payload) => {
      if (settled) return;
      settled = true;
      resolve(payload);
    };

    const socket = tls.connect(
      {
        host: parsedUrl.hostname,
        port,
        servername: parsedUrl.hostname,
        rejectUnauthorized: false,
        timeout,
      },
      () => {
        let score = MAX_SCORE;
        const warnings = [];
        const details = {
          host: parsedUrl.hostname,
          port,
        };

        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol();
          if (protocol) {
            details.protocol = protocol;
            if (!protocol.toUpperCase().startsWith('TLS')) {
              warnings.push(`Insecure protocol negotiated: ${protocol}`);
              score -= 10;
            }
          }

          if (!cert || Object.keys(cert).length === 0) {
            warnings.push('Unable to read TLS certificate details.');
            score = Math.min(score, 5);
          } else {
            const issuer = formatName(cert.issuer);
            if (issuer) {
              details.issuer = issuer;
            } else {
              warnings.push('Certificate issuer information is incomplete.');
              score -= 3;
            }

            const subject = formatName(cert.subject);
            if (subject) {
              details.subject = subject;
            }

            if (cert.serialNumber) {
              details.serialNumber = cert.serialNumber;
            }

            if (cert.valid_from) {
              const validFrom = new Date(cert.valid_from);
              if (!Number.isNaN(validFrom.getTime())) {
                details.validFrom = validFrom.toISOString();
              }
            }

            if (cert.valid_to) {
              const validTo = new Date(cert.valid_to);
              if (!Number.isNaN(validTo.getTime())) {
                details.validTo = validTo.toISOString();
                const diffMs = validTo.getTime() - Date.now();
                const daysUntilExpiry = Math.floor(diffMs / (1000 * 60 * 60 * 24));
                details.daysUntilExpiry = daysUntilExpiry;

                if (daysUntilExpiry < 0) {
                  warnings.push('Certificate is expired.');
                  score = 0;
                } else if (daysUntilExpiry <= 7) {
                  warnings.push('Certificate expires within 7 days.');
                  score -= 12;
                } else if (daysUntilExpiry <= 30) {
                  warnings.push('Certificate expires within 30 days.');
                  score -= 8;
                } else if (daysUntilExpiry <= 90) {
                  warnings.push('Certificate expires within 90 days.');
                  score -= 3;
                }
              } else {
                warnings.push('Unable to parse certificate expiration date.');
                score -= 4;
              }
            } else {
              warnings.push('Certificate expiration date is missing.');
              score -= 6;
            }

            if (cert.subjectaltname) {
              const entries = cert.subjectaltname
                .split(',')
                .map((entry) => entry.trim().replace(/^DNS:\s*/i, ''))
                .filter(Boolean);
              if (entries.length > 0) {
                details.subjectAltNames = entries;
                if (!entries.includes(parsedUrl.hostname)) {
                  warnings.push('Hostname is not explicitly listed in the certificate SAN entries.');
                  score -= 5;
                }
              }
            }
          }
        } catch (error) {
          warnings.push('TLS inspection failed.');
          details.error = error.message;
          score = Math.min(score, 10);
        } finally {
          socket.end();
          resolveSafe(finalizeResult({ score, warnings, details }));
        }
      },
    );

    socket.on('error', (error) => {
      resolveSafe(
        finalizeResult({
          score: 0,
          warnings: ['Could not establish a TLS connection.', error.message].filter(Boolean),
          details: { error: error.message },
        }),
      );
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolveSafe(
        finalizeResult({
          score: 0,
          warnings: ['TLS handshake timed out.'],
          details: {},
        }),
      );
    });
  });
};

module.exports = {
  checkTLS,
  CATEGORY_KEY,
  CATEGORY_LABEL,
  MAX_SCORE,
};
