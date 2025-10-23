import { useState } from 'react';
import PropTypes from 'prop-types';

const UrlForm = ({ onSubmit, isLoading, initialValue }) => {
  const [value, setValue] = useState(initialValue ?? '');

  const handleSubmit = (event) => {
    event.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) return;
    onSubmit(trimmed);
  };

  return (
    <form className="url-form" onSubmit={handleSubmit}>
      <label className="url-form__label" htmlFor="url-input">
        Website URL
      </label>
      <div className="url-form__controls">
        <input
          id="url-input"
          type="url"
          className="url-form__input"
          placeholder="https://example.com"
          value={value}
          required
          onChange={(event) => setValue(event.target.value)}
          spellCheck={false}
          autoComplete="off"
        />
        <button
          type="submit"
          className="url-form__button"
          disabled={isLoading || !value.trim()}
        >
          {isLoading ? 'Checking...' : 'Check URL'}
        </button>
      </div>
    </form>
  );
};

UrlForm.propTypes = {
  onSubmit: PropTypes.func.isRequired,
  isLoading: PropTypes.bool,
  initialValue: PropTypes.string,
};

UrlForm.defaultProps = {
  isLoading: false,
  initialValue: '',
};

export default UrlForm;
