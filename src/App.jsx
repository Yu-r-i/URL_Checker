import { useState } from 'react';
import UrlForm from './components/UrlForm';
import './App.css';

const ratingTone = (rating) => {
  if (!rating) return 'score-badge--neutral';
  const normalized = rating.toLowerCase();
  if (normalized === 'safe') return 'score-badge--good';
  if (normalized === 'warning') return 'score-badge--warn';
  if (normalized === 'dangerous') return 'score-badge--bad';
  return 'score-badge--neutral';
};

const formatDays = (days) => {
  if (days === undefined || days === null) return undefined;
  if (days < 0) return 'Expired';
  if (days === 0) return 'Today';
  if (days === 1) return '1 day';
  return `${days} days`;
};

const formatDate = (value) => {
  if (!value) return undefined;
  try {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return undefined;
    return date.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return undefined;
  }
};

const renderCategoryDetails = (category) => {
  const { key, details = {} } = category;
  const rows = [];

  const addRow = (label, value) => {
    if (value === undefined || value === null || value === '') return;
    rows.push(
      <li key={`${key}-${label}`} className="detail-list__item">
        <span className="detail-list__label">{label}</span>
        <span className="detail-list__value">{value}</span>
      </li>,
    );
  };

  switch (key) {
    case 'tls':
      addRow('Issuer', details.issuer);
      addRow('Protocol', details.protocol);
      addRow('Valid From', formatDate(details.validFrom));
      addRow('Valid To', formatDate(details.validTo));
      addRow('Days Until Expiry', formatDays(details.daysUntilExpiry));
      break;
    case 'headers':
      if (details.missing && details.missing.length > 0) {
        addRow('Missing Headers', details.missing.join(', '));
      }
      if (details.presentHeaders) {
        const highlighted = [
          'strict-transport-security',
          'content-security-policy',
          'x-frame-options',
          'referrer-policy',
          'x-content-type-options',
        ];
        highlighted.forEach((header) => {
          if (details.presentHeaders[header]) {
            addRow(header, details.presentHeaders[header]);
          }
        });
      }
      addRow('HTTP Status', details.statusCode);
      break;
    case 'cookies':
      addRow('Cookies Set', details.totalCookies);
      addRow('Cookies with Issues', details.insecureCookies);
      if (details.cookies && details.cookies.length > 0) {
        const insecure = details.cookies
          .filter((cookie) => cookie.issues?.length)
          .slice(0, 3)
          .map((cookie) => `${cookie.name} (${cookie.issues.join(' ')})`)
          .join(' | ');
        if (insecure) {
          addRow('Notable Issues', insecure);
        }
      }
      break;
    case 'whois':
      addRow('Registrar', details.registrar);
      addRow(
        'Domain Age',
        details.domainAgeDays !== undefined ? formatDays(details.domainAgeDays) : undefined,
      );
      addRow('Expires In', formatDays(details.daysUntilExpiry));
      if (details.nameServers && details.nameServers.length > 0) {
        addRow('Name Servers', details.nameServers.slice(0, 3).join(', '));
      }
      break;
    default:
      break;
  }

  if (rows.length === 0) {
    return <p className="detail-list__empty">No additional details for this check.</p>;
  }

  return <ul className="detail-list">{rows}</ul>;
};

const renderWarnings = (warnings) => {
  if (!warnings || warnings.length === 0) {
    return <span className="badge badge--ok">No warnings</span>;
  }
  return warnings.map((warning, index) => (
    <span key={`${warning}-${index}`} className="badge badge--warn">
      {warning}
    </span>
  ));
};

function App() {
  const [results, setResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [lastCheckedUrl, setLastCheckedUrl] = useState('');

  const handleCheckUrl = async (candidateUrl) => {
    setIsLoading(true);
    setError('');
    setLastCheckedUrl(candidateUrl);

    try {
      const response = await fetch('/api/check', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: candidateUrl }),
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        const message =
          payload?.error ||
          `Unable to check the URL. The server responded with status ${response.status}.`;
        throw new Error(message);
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err.message || 'Something went wrong while checking that URL.');
      setResults(null);
    } finally {
      setIsLoading(false);
    }
  };

  const renderResults = () => {
    if (!results) {
      return (
        <section className="results-placeholder">
          <h2>Ready When You Are</h2>
          <p>
            Enter a full website URL to run passive checks. We will inspect TLS, security
            headers, cookie flags, and WHOIS data to produce a safety score.
          </p>
        </section>
      );
    }

    const { score, categories, url } = results;
    return (
      <section className="results-card">
        <div className="overall-score">
          <div className="overall-score__info">
            <h2>Overall Score</h2>
            <p className="overall-score__url">{url}</p>
            <p className="overall-score__meta">
              Last checked{' '}
              {results.fetchedAt
                ? new Date(results.fetchedAt).toLocaleString()
                : 'just now'}
            </p>
          </div>
          <div className={`score-badge ${ratingTone(score?.rating)}`}>
            <span className="score-badge__value">{score?.total ?? 0}</span>
            <span className="score-badge__label">{score?.rating ?? 'Unknown'}</span>
          </div>
        </div>

        <div className="category-grid">
          {categories?.map((category) => (
            <article key={category.key} className="category-card">
              <header className="category-card__header">
                <h3>{category.label}</h3>
                <span className="category-card__score">
                  {category.score}/{category.maxScore}
                </span>
              </header>
              <div className="category-card__warnings">{renderWarnings(category.warnings)}</div>
              <div className="category-card__details">{renderCategoryDetails(category)}</div>
            </article>
          ))}
        </div>
      </section>
    );
  };

  return (
    <div className="app">
      <main className="layout">
        <header className="hero">
          <h1>SafeURL Checker</h1>
          <p>
            Evaluate a website in seconds. We gather public information only&mdash;no invasive
            scans or brute-force tests.
          </p>
        </header>

        <UrlForm onSubmit={handleCheckUrl} isLoading={isLoading} initialValue={lastCheckedUrl} />

        {error && <div className="alert alert--error">{error}</div>}
        {renderResults()}
      </main>
    </div>
  );
}

export default App;
