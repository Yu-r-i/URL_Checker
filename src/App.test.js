import { render, screen } from '@testing-library/react';
import App from './App';

describe('App', () => {
  it('renders the application title', () => {
    render(<App />);
    expect(screen.getByText(/SafeURL Checker/i)).toBeInTheDocument();
  });

  it('shows the URL form label', () => {
    render(<App />);
    expect(screen.getByLabelText(/Website URL/i)).toBeInTheDocument();
  });
});
