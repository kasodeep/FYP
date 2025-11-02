/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#3B82F6', // Cyan Blue
        },
        success: {
          DEFAULT: '#10B981', // Emerald Green
        },
        warning: {
          DEFAULT: '#FACC15', // Gold
        },
        danger: {
          DEFAULT: '#DC2626', // Scarlet Red
        },
        info: {
          DEFAULT: '#38BDF8', // Sky Blue
        },
        dark: {
          DEFAULT: '#121212', // Midnight Black
          secondary: '#1E293B', // Space Gray
        },
        light: {
          DEFAULT: '#E5E7EB', // Neutral Light
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
    },
  },
  plugins: [],
}