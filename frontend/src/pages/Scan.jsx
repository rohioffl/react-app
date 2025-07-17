import React, { useState } from 'react';
import axios from 'axios';
import { Cloud, ShieldCheck, UploadCloud } from 'lucide-react';
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;
const Scan = () => {
  const [provider, setProvider] = useState('');
  const [awsCreds, setAwsCreds] = useState({ accessKey: '', secretKey: '', region: 'all' });
  const [gcpKeyFile, setGcpKeyFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState('');
  console.log(API_BASE_URL)

  const handleAwsChange = (e) => {
    setAwsCreds({ ...awsCreds, [e.target.name]: e.target.value });
  };

  const handleGcpFileChange = (e) => {
    setGcpKeyFile(e.target.files[0]);
  };

  const handleScan = async () => {
    setLoading(true);
    setResponse('');

    try {
      if (provider === 'AWS') {
        const res = await axios.post(`${API_BASE_URL}/scan/aws`, awsCreds);
        setResponse(JSON.stringify(res.data, null, 2));
      } else if (provider === 'GCP') {
        const formData = new FormData();
        formData.append('keyFile', gcpKeyFile);
        const res = await axios.post(`${API_BASE_URL}/scan/gcp`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
        setResponse(JSON.stringify(res.data, null, 2));
      }
    } catch (err) {
      setResponse(`❌ Error: ${err.message}`);
    } finally {
      setLoading(false);
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
          {gcpKeyFile && <p className="text-green-700 text-sm">✅ {gcpKeyFile.name}</p>}
        </div>
      )}

      {/* Submit */}
      <div className="mt-6 text-center">
        <button
          onClick={handleScan}
          disabled={loading || (provider === 'GCP' && !gcpKeyFile)}
          className="bg-indigo-600 text-white px-6 py-2 rounded-lg hover:bg-indigo-700 disabled:opacity-50"
        >
          {loading ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>

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
