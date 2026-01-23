const express = require('express');
const cors = require('cors');
const axios = require('axios');

const { checkTLS, MAX_SCORE: TLS_MAX } = require('./checks/tls');
const { checkHeaders, MAX_SCORE: HEADERS_MAX } = require('./checks/headers');
const { checkCookies, MAX_SCORE: COOKIES_MAX } = require('./checks/cookies');
const { checkWhois, MAX_SCORE: WHOIS_MAX } = require('./checks/whois');

// NOTE:
// macOS では 5000 番ポートが OS 側プロセスに使われていることがあり、
// その場合フロントの proxy が別プロセスに向いて 403 になることがあります。
// 環境変数を設定しなくても確実に動くよう、デフォルトを 5050 にします。
const PORT = Number(process.env.PORT) || 5050;

// 環境変数が無くても動作するデフォルト。
const FETCH_TIMEOUT = Number(process.env.FETCH_TIMEOUT) || 8000;

const app = express();

app.use(cors());
app.use(express.json());

const fetchSiteResponse = async (targetUrl) => {
  try {
    const response = await axios.get(targetUrl, {
      timeout: FETCH_TIMEOUT,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'SafeURLChecker/1.0 (student project)',
        Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
      },
    });
    return { response };
  } catch (error) {
    if (error.response) {
      return { response: error.response, error };
    }
    return { response: null, error };
  }
};

const summarizeOverall = (categories) => {
  const totalScore = categories.reduce((sum, category) => sum + (category.score || 0), 0);
  const totalMaxScore = categories.reduce(
    (sum, category) => sum + (category.maxScore || 0),
    0,
  );
  const normalizedScore =
    totalMaxScore > 0 ? Math.round((totalScore / totalMaxScore) * 100) : 0;

  let rating = 'Safe';
  if (normalizedScore < 50) {
    rating = 'Dangerous';
  } else if (normalizedScore < 60) {
    rating = 'Warning';
  }

  return {
    total: normalizedScore,
    max: 100,
    rating,
  };
};

app.get('/health', (_req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
});

app.post('/api/check', async (req, res) => {
  const { url } = req.body || {};
  if (!url) {
    return res.status(400).json({ error: 'Please provide a url in the request body.' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    return res.status(400).json({ error: 'The provided URL is not valid.' });
  }

  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return res
      .status(400)
      .json({ error: 'Only HTTP and HTTPS URLs can be checked by this service.' });
  }

  const sanitizedUrl = parsedUrl.toString();
  const { response: siteResponse, error: fetchError } = await fetchSiteResponse(sanitizedUrl);
  const sharedContext = {
    response: siteResponse,
    fetchError,
  };

  const tasks = [
    {
      fn: () => checkTLS(sanitizedUrl),
      key: 'tls',
      label: 'HTTPS & TLS',
      maxScore: TLS_MAX,
    },
    {
      fn: () => checkHeaders(sanitizedUrl, sharedContext),
      key: 'headers',
      label: 'Security Headers',
      maxScore: HEADERS_MAX,
    },
    {
      fn: () => checkCookies(sanitizedUrl, sharedContext),
      key: 'cookies',
      label: 'Cookie Security',
      maxScore: COOKIES_MAX,
    },
    {
      fn: () => checkWhois(sanitizedUrl),
      key: 'whois',
      label: 'Domain WHOIS',
      maxScore: WHOIS_MAX,
    },
  ];

  const results = await Promise.allSettled(tasks.map((task) => task.fn()));

  const categories = results.map((result, index) => {
    if (result.status === 'fulfilled') {
      return result.value;
    }
    const fallback = tasks[index];
    return {
      key: fallback.key || `check-${index}`,
      label: fallback.label || 'Unknown Check',
      score: 0,
      maxScore: fallback.maxScore ?? 25,
      passed: false,
      warnings: ['Check failed to complete.', result.reason?.message].filter(Boolean),
      details: { error: result.reason?.message },
    };
  });

  const overall = summarizeOverall(categories);

  return res.json({
    url: sanitizedUrl,
    fetchedAt: new Date().toISOString(),
    score: overall,
    categories,
    http: {
      status: siteResponse?.status,
      finalUrl:
        siteResponse?.request?.res?.responseUrl ||
        siteResponse?.config?.url ||
        sanitizedUrl,
      error: fetchError && !siteResponse ? fetchError.message : undefined,
    },
  });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`SafeURL Checker server running on port ${PORT}`);
  });
}

module.exports = app;
