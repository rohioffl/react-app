import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const BACKEND = 'http://localhost:8000'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/scan': BACKEND,
      '/AWSfinding': BACKEND,
      '/GCPfinding': BACKEND,
      '/AWS_Scan': BACKEND,
      '/GCP_Scan': BACKEND,
      '/scanlist': BACKEND,
      '/GCPscanlist': BACKEND,
      '/xls': BACKEND,
      '/gcp-xls': BACKEND,
    }
  }
})
