# Frontend Integration Guide

This guide explains how to integrate your frontend application with **FastAPIOAuthRBAC**. It covers both standard email/password authentication and Google OAuth using **Vanilla JavaScript** and **React**.

## 1. Standard Login (Email & Password)

The library uses standard `OAuth2` form data (username/password) for login. The endpoint is `/auth/login`.

### 🔐 Vanilla JavaScript

Here is a simple example using the native `fetch` API.

```javascript
async function login(email, password) {
  const formData = new FormData();
  formData.append('username', email); // Note: OAuth2 expects 'username', not 'email'
  formData.append('password', password);

  try {
    const response = await fetch('http://localhost:8000/auth/login', {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Login failed');
    }

    const data = await response.json();

    // Store the tokens securely
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);

    console.log('Login successful!', data);
    return data;
  } catch (error) {
    console.error('Error logging in:', error);
  }
}
```

### ⚛️ React

In React, you typically manage the form state and handle the submission.

```jsx
import React, { useState } from 'react';

export const LoginForm = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    const formData = new FormData();
    formData.append('username', email);
    formData.append('password', password);

    try {
      const response = await fetch('http://localhost:8000/auth/login', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || 'Login failed');
      }

      const data = await response.json();
      localStorage.setItem('access_token', data.access_token);

      // Redirect or update app state
      alert('Login Successful');
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && <div style={{ color: 'red' }}>{error}</div>}
      <input 
        type="email" 
        value={email} 
        onChange={(e) => setEmail(e.target.value)} 
        placeholder="Email" 
        required 
      />
      <input 
        type="password" 
        value={password} 
        onChange={(e) => setPassword(e.target.value)} 
        placeholder="Password" 
        required 
      />
      <button type="submit">Log In</button>
    </form>
  );
};
```

---

---

## 2. Google Cloud Configuration

Before implementing Google OAuth, you need to obtain credentials from the Google Cloud Console.

### 1. Create Credentials
1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project or select an existing one.
3. Navigate to **APIs & Services > Credentials**.
4. Click **Create Credentials > OAuth client ID**.
5. Select **Web application** as the application type.

### 2. Configure URIs
The configuration depends on your integration method:

| Setting | Backend Flow (Standard) | SPA Flow (React/Vue/etc) |
| :--- | :--- | :--- |
| **Authorized JavaScript Origins** | Not strictly required, but recommended (e.g., `http://localhost:8000`) | **REQUIRED**: Your Frontend URL (e.g., `http://localhost:3000`) |
| **Authorized Redirect URIs** | Your Backend Callback URL (e.g., `http://localhost:8000/auth/google/callback`) | Your Frontend Callback URL (e.g., `http://localhost:3000/oauth/callback`) |

> [!IMPORTANT]
> For **SPA Mode**, you must add your frontend URL (e.g., `http://localhost:3000`) to **Authorized JavaScript Origins**. If you don't, Google will block the popup/redirect.

### 3. Environment Variables
Add the credentials to your backend `.env` file:

```bash
GOOGLE_OAUTH_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret
# Only for Backend Flow
GOOGLE_OAUTH_REDIRECT_URI=http://localhost:8000/auth/google/callback
```

For SPAs, you also need the `CLIENT_ID` in your frontend code.

---

## 3. Google OAuth Integration (SPA Mode)

The library provides a dedicated endpoint for Single Page Applications (SPAs) at `POST /auth/google/exchange`. This allows you to handle the OAuth redirect on the client-side and simply exchange the authorization code for a session token.

### ⚙️ How it works
1. **Frontend**: Redirects user to Google's OAuth consent screen.
2. **Google**: Redirects user back to your SPA (e.g., `http://localhost:3000/callback`).
3. **Frontend**: Extracts the `code` from the URL.
4. **Frontend**: Sends the `code` to the backend (`POST /auth/google/exchange`);
5. **Backend**: Validates code, logs in user, and returns tokens.

### 🔐 Vanilla JavaScript

```javascript
const GOOGLE_CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID';
// Ensure this URI is registered in Google Cloud Console
const REDIRECT_URI = 'http://localhost:3000/callback'; 

// 1. Initiate Login
function loginWithGoogle() {
  const rootUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  const options = {
    redirect_uri: REDIRECT_URI,
    client_id: GOOGLE_CLIENT_ID,
    access_type: 'offline',
    response_type: 'code',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email',
    ].join(' '),
  };

  const qs = new URLSearchParams(options);
  window.location.href = `${rootUrl}?${qs.toString()}`;
}

// 2. Handle Callback (on /callback page)
async function handleCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');

  if (code) {
    try {
      const response = await fetch('http://localhost:8000/auth/google/exchange', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ code: code, redirect_uri: REDIRECT_URI }),
      });

      const data = await response.json();
      if (response.ok) {
          localStorage.setItem('access_token', data.access_token);
          console.log('Google Login Successful', data);
      } else {
          console.error('Google Login FAILED', data);
      }
    } catch (err) {
      console.error(err);
    }
  }
}
```

### ⚛️ React

A clean React implementation using `react-router-dom`.

```jsx
import React, { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';

// Configuration
const GOOGLE_CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID';
const REDIRECT_URI = 'http://localhost:3000/oauth/callback';
const BACKEND_URL = 'http://localhost:8000';

export const GoogleLoginButton = () => {
  const handleLogin = () => {
    const rootUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
    const options = {
      redirect_uri: REDIRECT_URI,
      client_id: GOOGLE_CLIENT_ID,
      access_type: 'offline',
      response_type: 'code',
      prompt: 'consent',
      scope: [
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/userinfo.email',
      ].join(' '),
    };

    const qs = new URLSearchParams(options);
    window.location.assign(`${rootUrl}?${qs.toString()}`);
  };

  return (
    <button onClick={handleLogin} className="google-btn">
      Sign in with Google
    </button>
  );
};

export const GoogleCallbackPage = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const code = searchParams.get('code');

  useEffect(() => {
    if (!code) return;

    const exchangeCode = async () => {
      try {
        const response = await fetch(`${BACKEND_URL}/auth/google/exchange`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ 
            code, 
            redirect_uri: REDIRECT_URI 
          }),
        });

        if (!response.ok) throw new Error('Failed to exchange code');

        const data = await response.json();

        // Save tokens
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('refresh_token', data.refresh_token);

        // Redirect to home/dashboard
        navigate('/dashboard');

      } catch (error) {
        console.error('Login failed', error);
        navigate('/login?error=google_failed');
      }
    };

    exchangeCode();
  }, [code, navigate]);

  return <div>Verifying Google Login...</div>;
};
```
