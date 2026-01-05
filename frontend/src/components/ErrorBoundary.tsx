import { Component, type ReactNode, type ErrorInfo } from 'react';
import { ShieldAlert, RotateCw, Home } from 'lucide-react';
import { Link } from 'react-router-dom';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    this.setState({
      error,
      errorInfo,
    });
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100 p-4">
          <div className="max-w-2xl w-full bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded-2xl shadow-2xl p-8">
            <div className="flex items-center justify-center mb-6">
              <div className="bg-danger-100 p-4 rounded-full">
                <ShieldAlert className="w-12 h-12 text-danger-600" />
              </div>
            </div>

            <h1 className="text-3xl font-bold text-gray-900 text-center mb-4">
              Oops! Something went wrong
            </h1>

            <p className="text-gray-600 text-center mb-6">
              We encountered an unexpected error. Don't worry, our team has been notified.
            </p>

            {this.state.error && (
              <div className="bg-gray-50/50 dark:bg-neutral-800/50 backdrop-blur-sm rounded-lg p-4 mb-6 border border-gray-200">
                <p className="text-sm font-semibold text-gray-700 mb-2">Error Details:</p>
                <p className="text-sm text-danger-600 font-mono mb-2">
                  {this.state.error.message}
                </p>
                {this.state.errorInfo && (
                  <details className="mt-4">
                    <summary className="text-sm text-gray-600 cursor-pointer hover:text-gray-900">
                      View Stack Trace
                    </summary>
                    <pre className="mt-2 text-xs text-gray-700 overflow-auto max-h-64 bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm p-4 rounded border border-gray-200">
                      {this.state.errorInfo.componentStack}
                    </pre>
                  </details>
                )}
              </div>
            )}

            <div className="flex gap-4 justify-center">
              <button
                onClick={this.handleReset}
                className="flex items-center gap-2 px-6 py-3 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
              >
                <RotateCw className="w-5 h-5" />
                <span>Try Again</span>
              </button>

              <Link
                to="/"
                className="flex items-center gap-2 px-6 py-3 bg-gray-200 text-gray-900 rounded-lg hover:bg-gray-300 transition-colors"
              >
                <Home className="w-5 h-5" />
                <span>Go Home</span>
              </Link>
            </div>

            <div className="mt-8 text-center">
              <p className="text-sm text-gray-700">
                If the problem persists, please contact support at{' '}
                <a
                  href="mailto:support@ntro.gov"
                  className="text-primary-600 hover:underline"
                >
                  support@ntro.gov
                </a>
              </p>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
