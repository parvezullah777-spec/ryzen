/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/**/*.{js,jsx,ts,tsx}", "./index.html"],
  theme: {
    extend: {
      colors: {
        'ryzen-ink': '#14212E',
        'ryzen-paper': '#F7F5F0',
        'ryzen-teal': '#0E6E63',
        'ryzen-orange': '#E8823C',
        'ryzen-danger': '#C4432B',
      }
    },
  },
  plugins: [],
}
