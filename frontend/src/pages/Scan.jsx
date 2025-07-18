import React, { useState, useEffect, useRef } from 'react';
import { Cloud, ShieldCheck, UploadCloud } from 'lucide-react';
import api from '../api';
const Scan = () => {
  const [provider, setProvider] = useState('');
  const [awsCreds, setAwsCreds] = useState({ accessKey: '', secretKey: '', region: 'all' });
  const [gcpKeyFile, setGcpKeyFile] = useState(null);
  const [gcpProjects, setGcpProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState('');
  const [keyId, setKeyId] = useState('');
  const [fetchingProjects, setFetchingProjects] = useState(false);
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState('');
  const [progress, setProgress] = useState(0);
  const [scanId, setScanId] = useState(null);
  const pollRef = useRef();

  useEffect(() => {
    const saved = localStorage.getItem('scanId');
    if (saved) {
      setScanId(saved);
      setLoading(true);
    }
  }, []);

  useEffect(() => {
    if (scanId) {
      pollStatus(scanId);
    }
    return () => clearInterval(pollRef.current);
  }, [scanId]);

  const handleAwsChange = (e) => {
    setAwsCreds({ ...awsCreds, [e.target.name]: e.target.value });
  };

const handleGcpFileChange = async (e) => {
  const file = e.target.files[0];
  setGcpKeyFile(file);
  if (!file) return;
  setFetchingProjects(true);
  const formData = new FormData();
  formData.append('keyFile', file);
  try {
    const res = await api.post('gcp/projects', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    setGcpProjects(res.data.projects);
    setKeyId(res.data.keyId);
  } catch (err) {
    setResponse(`❌ Error: ${err.response?.data?.error || err.message}`);
  } finally {
    setFetchingProjects(false);
  }
};

  const pollStatus = (id) => {
    clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const res = await api.get(`scan/status/${id}`);
        setProgress(res.data.progress);
        if (res.data.progress >= 100) {
          clearInterval(pollRef.current);
          setLoading(false);
          if (res.data.result) {
            setResponse(JSON.stringify(res.data.result, null, 2));
          }
          localStorage.removeItem('scanId');
          setScanId(null);
        }
      } catch (err) {
        console.error('Status check failed', err);
      }
    }, 2000);
  };

const handleScan = async () => {
    setLoading(true);
    setResponse('');
    setProgress(0);

  try {
    let res;
    if (provider === 'AWS') {
      res = await api.post('scan/aws', awsCreds);
    } else if (provider === 'GCP') {
        const formData = new FormData();
        formData.append('keyId', keyId);
        formData.append('projectId', selectedProject);
        res = await api.post('scan/async/gcp/', formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
    }
      if (res) {
        setScanId(res.data.scan_id);
        localStorage.setItem('scanId', res.data.scan_id);
        pollStatus(res.data.scan_id);
      }
    } catch (err) {
      setLoading(false);
      setResponse(`❌ Error: ${err.response?.data?.error || err.message}`);
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-6 bg-white shadow-xl rounded-2xl mt-10 border border-gray-200">
      <h2 className="text-3xl font-bold text-center text-blue-700 flex items-center justify-center gap-2 mb-6">
        <ShieldCheck className="w-7 h-7 text-green-500" /> Cloud Security Scan
      </h2>

      <div className="flex justify-center gap-6 mb-8">
        <button
          onClick={() => setProvider('AWS')}
          className={`flex items-center gap-2 px-5 py-2 rounded-full font-medium transition ${
            provider === 'AWS' ? 'bg-blue-600 text-white shadow-md' : 'bg-gray-100 hover:bg-blue-100 text-blue-800'
          }`}
        >
          <Cloud className="w-5 h-5" /> AWS
        </button>
        <button
          onClick={() => setProvider('GCP')}
          className={`flex items-center gap-2 px-5 py-2 rounded-full font-medium transition ${
            provider === 'GCP' ? 'bg-green-600 text-white shadow-md' : 'bg-gray-100 hover:bg-green-100 text-green-800'
          }`}
        >
          <Cloud className="w-5 h-5" /> GCP
        </button>
      </div>

      {/* AWS Fields */}
      {provider === 'AWS' && (
        <div className="space-y-4">
          <input
            name="accessKey"
            type="text"
            placeholder="AWS Access Key"
            className="w-full border border-gray-300 px-4 py-2 rounded-lg"
            onChange={handleAwsChange}
          />
          <input
            name="secretKey"
            type="password"
            placeholder="AWS Secret Key"
            className="w-full border border-gray-300 px-4 py-2 rounded-lg"
            onChange={handleAwsChange}
          />
          <div className="flex gap-4 items-center">
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="regionOption"
                value="all"
                checked={awsCreds.region === 'all'}
                onChange={() => setAwsCreds({ ...awsCreds, region: 'all' })}
              />
              All Regions
            </label>
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="regionOption"
                value="specific"
                checked={awsCreds.region !== 'all'}
                onChange={() => setAwsCreds({ ...awsCreds, region: '' })}
              />
              Specific Region
            </label>
          </div>
          {awsCreds.region !== 'all' && (
            <input
              name="region"
              type="text"
              placeholder="e.g. us-east-1"
              className="w-full border border-gray-300 px-4 py-2 rounded-lg"
              onChange={handleAwsChange}
              value={awsCreds.region}
            />
          )}
        </div>
      )}

      {/* GCP Fields */}
      {provider === 'GCP' && (
        <div className="space-y-4 text-center">
          <label className="flex flex-col items-center justify-center p-4 border-2 border-dashed border-green-400 rounded-lg cursor-pointer hover:bg-green-50 transition">
            <UploadCloud className="w-8 h-8 text-green-500 mb-2" />
            <span className="text-sm text-gray-600 mb-1">Upload GCP Service Account Key (.json)</span>
            <input type="file" className="hidden" accept=".json" onChange={handleGcpFileChange} />
          </label>
          {fetchingProjects && <p className="text-sm text-blue-600">Loading projects...</p>}
          {gcpProjects.length > 0 && !fetchingProjects && (
            <select
              className="w-full border border-gray-300 px-4 py-2 rounded-lg"
              value={selectedProject}
              onChange={(e) => setSelectedProject(e.target.value)}
            >
              <option value="">Select Project</option>
              {gcpProjects.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          )}
        </div>
      )}

      {/* Submit */}
      <div className="mt-6 text-center">
        <button
          onClick={handleScan}
          disabled={
            loading ||
            (provider === 'GCP' && (!keyId || !selectedProject))
          }
          className="bg-indigo-600 text-white px-6 py-2 rounded-lg hover:bg-indigo-700 disabled:opacity-50"
        >
          {loading ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>

      {loading && (
        <div className="mt-4">
          <div className="flex items-center gap-2 mb-2">
            <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div>
            <span className="text-sm text-blue-600">Fetching... {progress}%</span>
          </div>
          <div className="w-full bg-gray-200 h-2 rounded">
            <div className="bg-blue-600 h-2 rounded" style={{ width: `${progress}%` }}></div>
          </div>
        </div>
      )}

      {/* Output */}
      {response && (
        <div className="mt-6 p-4 bg-gray-900 text-green-400 text-sm rounded-lg overflow-auto max-h-80 whitespace-pre-wrap">
          {response}
        </div>
      )}
    </div>
  );
};

export default Scan;
