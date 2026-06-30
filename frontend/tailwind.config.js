/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Cool near-black surface scale (page → elevated card). Replaces the
        // flat zinc backgrounds; gives cards real depth against the page.
        ink: {
          950: '#0d0f15',
          900: '#12151d',
          850: '#171b24',
          800: '#1d2330',
          700: '#252c3a',
        },
        // Hairline borders tuned to the ink scale.
        hair: {
          DEFAULT: '#252c3a',
          soft: '#1c212d',
          strong: '#323b4d',
        },
        // Indigo primary accent (brand action color).
        accent: {
          DEFAULT: '#6366f1',
          fg: '#c7caff',
          50: '#eef2ff',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
        },
      },
      boxShadow: {
        card: '0 1px 2px rgba(0,0,0,0.30), 0 4px 12px -4px rgba(0,0,0,0.40)',
        pop: '0 8px 28px -6px rgba(0,0,0,0.55)',
      },
    },
  },
  plugins: [],
}
