import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://34.202.36.87:8000';

const api = axios.create({
  baseURL: BASE_URL,
});

export default api;
