/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#0F1419',
        surface: '#161C24',
        raised: '#1D2530',
        line: '#2A3441',
        text: '#E4E8EC',
        muted: '#8B97A6',
        signal: '#4FB3A5',
        caution: '#D9884F',
        fault: '#D9615A',
      },
      fontFamily: {
        sans: ['"Inter"', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      maxWidth: {
        reading: '68ch',
      },
    },
  },
  plugins: [],
};
