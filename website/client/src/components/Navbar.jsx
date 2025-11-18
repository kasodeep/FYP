import { useState, useContext } from 'react';
import { NavLink } from 'react-router-dom';
import { ThemeContext } from '../contexts/ThemeContextValue';

export default function Navbar() {
  const { isDark, toggleTheme } = useContext(ThemeContext);
  const [isOpen, setIsOpen] = useState(false);

  return (
    <nav className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm shadow-lg fixed w-full top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex h-16">
          <div className="flex items-center w-48">
            <img src="/logo.png" alt="NetSentinel Logo" className="h-12 w-12" />
            <span className="text-xl font-bold text-gray-900 dark:text-white hidden md:block">NetSentinel</span>
            <span className="text-xl font-bold text-gray-900 dark:text-white md:hidden">NSD</span>
          </div>
          
          {/* Desktop Navigation */}
          <div className="hidden md:flex flex-1 items-center justify-center space-x-4">
            <NavLink
              to="/"
              className={({ isActive }) =>
                `px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-900 dark:text-white hover:bg-blue-500 hover:text-white dark:hover:bg-blue-600'
                }`
              }
            >
              Dashboard
            </NavLink>
            <NavLink
              to="/alerts"
              className={({ isActive }) =>
                `px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-900 dark:text-white hover:bg-blue-500 hover:text-white dark:hover:bg-blue-600'
                }`
              }
            >
              Alerts
            </NavLink>
            <NavLink
              to="/logs"
              className={({ isActive }) =>
                `px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-900 dark:text-white hover:bg-blue-500 hover:text-white dark:hover:bg-blue-600'
                }`
              }
            >
              Logs
            </NavLink>
          </div>
          
          <div className="flex items-center w-48 justify-end space-x-4">
            <button
              onClick={toggleTheme}
              className="p-2 rounded-md text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              aria-label="Toggle theme"
            >
              {isDark ? (
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              ) : (
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
              )}
            </button>
            
            {/* Mobile menu button */}
            <button
              onClick={() => setIsOpen(!isOpen)}
              className="md:hidden inline-flex items-center justify-center p-2 rounded-md text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              aria-label="Main menu"
            >
              <svg
                className={`${isOpen ? 'hidden' : 'block'} h-6 w-6`}
                stroke="currentColor"
                fill="none"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
              <svg
                className={`${isOpen ? 'block' : 'hidden'} h-6 w-6`}
                stroke="currentColor"
                fill="none"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
      </div>
      
      {/* Mobile Navigation */}
      <div className={`${isOpen ? 'block' : 'hidden'} md:hidden bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm shadow-lg`}>
        <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3">
          <NavLink
            to="/"
            className={({ isActive }) =>
              `block px-3 py-2 rounded-md text-base font-medium transition-all duration-200 ${
                isActive
                  ? 'bg-blue-600 text-white shadow-md'
                  : 'text-gray-900 dark:text-white hover:bg-blue-50 hover:text-blue-600 dark:hover:bg-gray-700'
              }`
            }
            onClick={() => setIsOpen(false)}
          >
            Dashboard
          </NavLink>
          <NavLink
            to="/alerts"
            className={({ isActive }) =>
              `block px-3 py-2 rounded-md text-base font-medium transition-colors ${
                isActive
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-900 dark:text-white hover:bg-blue-500 hover:text-white dark:hover:bg-blue-600'
              }`
            }
            onClick={() => setIsOpen(false)}
          >
            Alerts
          </NavLink>
          <NavLink
            to="/logs"
            className={({ isActive }) =>
              `block px-3 py-2 rounded-md text-base font-medium transition-colors ${
                isActive
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-900 dark:text-white hover:bg-blue-500 hover:text-white dark:hover:bg-blue-600'
              }`
            }
            onClick={() => setIsOpen(false)}
          >
            Logs
          </NavLink>
        </div>
      </div>
    </nav>
  )
}