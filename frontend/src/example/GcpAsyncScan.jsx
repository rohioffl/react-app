import { useState, useEffect, useRef } from 'react';
import api from '../api';

/**
 * Minimal component demonstrating the async GCP scan workflow.
 */
export default function GcpAsyncScan() {
  const [keyId, setKeyId] = useState('');
  const [projects, setProjects] = useState([]);
  const [project, setProject] = useState('');
  const [scanId, setScanId] = useState(localStorage.getItem('scanId'));
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const pollRef = useRef();

  useEffect(() => {
    if (scanId) pollStatus(scanId);
    return () => clearInterval(pollRef.current);
  }, [scanId]);

  async function uploadKey(e) {
    const file = e.target.files[0];
    if (!file) return;
    const data = new FormData();
    data.append('keyFile', file);
    try {
      const res = await api.post('gcp/projects', data, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setProjects(res.data.projects);
      setKeyId(res.data.keyId);
    } catch (err) {
      alert(err.response?.data?.error || err.message);
    }
  }

  async function startScan() {
    const data = new FormData();
    data.append('keyId', keyId);
    data.append('projectId', project);
    const res = await api.post('scan/async/gcp/', data);
    setScanId(res.data.scan_id);
    localStorage.setItem('scanId', res.data.scan_id);
    pollStatus(res.data.scan_id);
  }

  const pollStatus = (id) => {
    clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const res = await api.get(`scan/status/${id}/`);
        setProgress(res.data.progress);
        if (res.data.result) {
          clearInterval(pollRef.current);
          localStorage.removeItem('scanId');
          setResult(res.data.result);
        }
      } catch (err) {
        console.error(err);
      }
    }, 2000);
  };

  return (
    <div>
      <input type="file" accept=".json" onChange={uploadKey} />
      {projects.length > 0 && (
        <select value={project} onChange={e => setProject(e.target.value)}>
          <option value="">Select project</option>
          {projects.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
      )}
      <button disabled={!project} onClick={startScan}>Start Scan</button>
      {scanId && <p>Progress: {progress}%</p>}
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
    </div>
  );
}
