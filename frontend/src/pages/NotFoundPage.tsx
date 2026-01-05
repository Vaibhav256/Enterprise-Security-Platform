import { Link } from 'react-router-dom';
import { Home, Search, ArrowLeft } from 'lucide-react';
import { motion } from 'framer-motion';

const NotFoundPage = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="max-w-2xl w-full mx-4"
      >
        <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded-2xl shadow-2xl p-12 text-center">
          {/* 404 Illustration */}
          <div className="mb-8">
            <motion.div
              animate={{ y: [0, -10, 0] }}
              transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
              className="text-9xl font-bold text-primary-600 mb-4"
            >
              404
            </motion.div>
            <div className="flex items-center justify-center gap-4 text-gray-900 dark:text-gray-300">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: '6rem' }}
                transition={{ delay: 0.5, duration: 0.8 }}
                className="h-1 bg-primary-200 dark:bg-primary-800 rounded-full"
              />
              <motion.div
                animate={{ rotate: [0, 360] }}
                transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
              >
                <Search className="w-8 h-8" />
              </motion.div>
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: '6rem' }}
                transition={{ delay: 0.5, duration: 0.8 }}
                className="h-1 bg-primary-200 dark:bg-primary-800 rounded-full"
              />
            </div>
          </div>

          {/* Message */}
          <motion.h1
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.8 }}
            className="text-4xl font-bold text-gray-900 dark:text-white mb-4"
          >
            Page Not Found
          </motion.h1>
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1 }}
            className="text-lg text-gray-800 dark:text-gray-400 mb-8"
          >
            The page you're looking for doesn't exist or has been moved.
            <br />
            Let's get you back on track!
          </motion.p>

          {/* Actions */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 1.2 }}
            className="flex flex-col sm:flex-row gap-4 justify-center"
          >
            <Link
              to="/"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-all transform hover:scale-105 shadow-lg hover:shadow-xl"
            >
              <Home className="w-5 h-5" />
              <span className="font-semibold">Go to Dashboard</span>
            </Link>

            <button
              onClick={() => window.history.back()}
              className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-gray-200 dark:bg-neutral-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-300 dark:hover:bg-neutral-600 transition-all transform hover:scale-105"
            >
              <ArrowLeft className="w-5 h-5" />
              <span className="font-semibold">Go Back</span>
            </button>
          </motion.div>

          {/* Helpful Links */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.4 }}
            className="mt-12 pt-8 border-t border-gray-200 dark:border-neutral-700"
          >
            <p className="text-sm text-gray-700 dark:text-gray-400 mb-4">Quick Links:</p>
            <div className="flex flex-wrap gap-4 justify-center text-sm">
              <Link to="/scans" className="text-primary-600 hover:underline">
                View All Scans
              </Link>
              <Link to="/scan/new" className="text-primary-600 hover:underline">
                Create New Scan
              </Link>
              <Link to="/intelligence" className="text-primary-600 hover:underline">
                AI Assistant
              </Link>
              <Link to="/settings" className="text-primary-600 hover:underline">
                Settings
              </Link>
            </div>
          </motion.div>
        </div>
      </motion.div>
    </div>
  );
};

export default NotFoundPage;
