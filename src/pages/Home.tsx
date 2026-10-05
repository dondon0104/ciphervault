import { useState } from 'react';
import { IonContent, IonIcon, IonPage } from '@ionic/react';
import {
  checkmarkCircleOutline,
  clipboardOutline,
  eyeOffOutline,
  eyeOutline,
  keyOutline,
  lockClosedOutline,
  refreshOutline,
  shieldCheckmarkOutline,
  lockOpenOutline,
} from 'ionicons/icons';
import './Home.css';

type Mode = 'encrypt' | 'decrypt';

const FORMAT_VERSION = 'SMV1';
const PBKDF2_ITERATIONS = 310_000;
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 1_000_000;

const toBase64 = (bytes: Uint8Array) => {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const fromBase64 = (value: string) => {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

const toArrayBuffer = (bytes: Uint8Array) => {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
};

const deriveKey = async (password: string, salt: Uint8Array, iterations: number) => {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: toArrayBuffer(salt), iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
};

const getPasswordStrength = (password: string) => {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password) || /[^a-zA-Z0-9]/.test(password)) score += 1;
  return score;
};

const Home: React.FC = () => {
  const [mode, setMode] = useState<Mode>('encrypt');
  const [message, setMessage] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [result, setResult] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [isBusy, setIsBusy] = useState(false);

  const strength = getPasswordStrength(password);
  const messageLabel = mode === 'encrypt' ? 'Your message' : 'Encrypted message';

  const handleModeChange = (nextMode: Mode) => {
    setMode(nextMode);
    setMessage('');
    setPassword('');
    setResult('');
    setError('');
    setNotice('');
  };

  const handleSubmit = async () => {
    setError('');
    setNotice('');
    setResult('');

    if (!message.trim()) {
      setError('Add a message before continuing.');
      return;
    }
    if (!password) {
      setError('Enter your password to continue.');
      return;
    }
    if (mode === 'encrypt' && password.length < 8) {
      setError('Use a password with at least 8 characters.');
      return;
    }

    setIsBusy(true);
    try {
      if (mode === 'encrypt') {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);
        const ciphertext = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: toArrayBuffer(iv) },
          key,
          new TextEncoder().encode(message),
        );
        setResult([
          FORMAT_VERSION,
          String(PBKDF2_ITERATIONS),
          toBase64(salt),
          toBase64(iv),
          toBase64(new Uint8Array(ciphertext)),
        ].join('.'));
        setNotice('Message encrypted. Keep your password separate from this text.');
      } else {
        const [version, iterationText, saltText, ivText, ciphertextText, ...extra] = message.trim().split('.');
        const iterations = Number(iterationText);
        if (
          version !== FORMAT_VERSION || extra.length > 0 ||
          !Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS ||
          !saltText || !ivText || !ciphertextText
        ) {
          throw new Error('That text is not a valid Secure Message Vault package.');
        }
        const salt = fromBase64(saltText);
        const iv = fromBase64(ivText);
        const ciphertext = fromBase64(ciphertextText);
        if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16) {
          throw new Error('That encrypted package is incomplete or malformed.');
        }
        const key = await deriveKey(password, salt, iterations);
        const plaintext = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: toArrayBuffer(iv) },
          key,
          toArrayBuffer(ciphertext),
        );
        setResult(new TextDecoder().decode(plaintext));
        setNotice('Message decrypted successfully.');
      }
    } catch (caught) {
      setError(caught instanceof Error && caught.message.startsWith('That ')
        ? caught.message
        : 'Could not decrypt this message. Check the password and make sure the encrypted text is unchanged.');
    } finally {
      setIsBusy(false);
    }
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(result);
      setNotice('Copied to clipboard.');
    } catch {
      setError('Clipboard access is unavailable. Select and copy the result instead.');
    }
  };

  const handleClear = () => {
    setMessage('');
    setPassword('');
    setResult('');
    setError('');
    setNotice('');
  };

  return (
    <IonPage className="vault-page">
      <IonContent className="vault-content" fullscreen>
        <div className="vault-shell">
          <header className="topbar">
            <div className="window-controls" aria-hidden="true">
              <span className="window-dot window-dot-close" />
              <span className="window-dot window-dot-minimize" />
              <span className="window-dot window-dot-maximize" />
            </div>
            <a className="brand" href="/home" aria-label="Cipher Vault home">
              <span className="brand-mark"><IonIcon icon={lockClosedOutline} /></span>
              <span>CIPHER<span className="brand-light">VAULT</span><span className="window-version"> v1.0</span></span>
            </a>
            <div className="local-indicator"><span className="status-dot" /> PRIVATE BY DESIGN</div>
          </header>

          <main>
            <section className="intro" aria-labelledby="page-title">
              <div className="intro-copy">
                <div className="eyebrow"><span>01</span> PERSONAL MESSAGE ENCRYPTION</div>
                <h1 id="page-title">Keep your words<br /><em>between you.</em></h1>
                <p>Lock a message with a password. Only someone with the same password can open it.</p>
              </div>
              <div className="intro-seal" aria-hidden="true">
                <span className="seal-ring"><IonIcon icon={shieldCheckmarkOutline} /></span>
                <span className="seal-caption">AES-256<br />GCM ENCRYPTION</span>
              </div>
            </section>

            <section className="workspace" aria-label="Message encryption tool">
              <div className="composer">
                <div className="mode-row">
                  <div className="mode-switch" role="tablist" aria-label="Choose an operation">
                    <button
                      className={mode === 'encrypt' ? 'mode-button active' : 'mode-button'}
                      type="button"
                      role="tab"
                      aria-selected={mode === 'encrypt'}
                      onClick={() => handleModeChange('encrypt')}
                    >
                      <IonIcon icon={lockClosedOutline} /> Encrypt
                    </button>
                    <button
                      className={mode === 'decrypt' ? 'mode-button active' : 'mode-button'}
                      type="button"
                      role="tab"
                      aria-selected={mode === 'decrypt'}
                      onClick={() => handleModeChange('decrypt')}
                    >
                      <IonIcon icon={lockOpenOutline} /> Decrypt
                    </button>
                  </div>
                  <span className="mode-caption">{mode === 'encrypt' ? 'CREATE A SECURE MESSAGE' : 'OPEN A SECURE MESSAGE'}</span>
                </div>

                <label className="field-label" htmlFor="message-input">{messageLabel}</label>
                <div className="message-wrap">
                  <textarea
                    id="message-input"
                    className="message-input"
                    value={message}
                    onChange={(event) => setMessage(event.target.value)}
                    placeholder={mode === 'encrypt' ? 'Type the message you want to protect...' : 'Paste an SMV1 encrypted message...'}
                    rows={6}
                    maxLength={100_000}
                    spellCheck={mode === 'encrypt'}
                    autoCapitalize="off"
                  />
                  <span className="char-count">{message.length.toLocaleString()} / 100,000</span>
                </div>

                <div className="password-heading">
                  <label className="field-label" htmlFor="vault-password">Password</label>
                  {mode === 'encrypt' && password && (
                    <span className={`strength-label strength-${strength}`}>
                      {['WEAK', 'FAIR', 'GOOD', 'STRONG', 'STRONG'][strength]}
                    </span>
                  )}
                </div>
                <div className="password-wrap">
                  <IonIcon className="password-icon" icon={keyOutline} />
                  <input
                    id="vault-password"
                    className="password-input"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="Enter a strong password"
                    autoComplete="new-password"
                  />
                  <button
                    className="visibility-button"
                    type="button"
                    onClick={() => setShowPassword((visible) => !visible)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    <IonIcon icon={showPassword ? eyeOffOutline : eyeOutline} />
                  </button>
                </div>
                {mode === 'encrypt' && (
                  <div className="strength-meter" aria-label={`Password strength: ${strength} of 4`}>
                    {[0, 1, 2, 3].map((segment) => (
                      <span key={segment} className={segment < strength ? `filled strength-${strength}` : ''} />
                    ))}
                    <span className="password-hint">Use 8+ characters, mixed case, and numbers or symbols.</span>
                  </div>
                )}

                <div className="action-row">
                  <button className="primary-button" type="button" onClick={handleSubmit} disabled={isBusy}>
                    <IonIcon icon={mode === 'encrypt' ? lockClosedOutline : lockOpenOutline} />
                    {isBusy ? 'Working...' : mode === 'encrypt' ? 'Encrypt message' : 'Decrypt message'}
                  </button>
                  <button className="clear-button" type="button" onClick={handleClear} aria-label="Clear form">
                    <IonIcon icon={refreshOutline} /> Clear
                  </button>
                </div>

                {error && <p className="feedback error-feedback" role="alert">{error}</p>}
                {notice && !error && <p className="feedback success-feedback" role="status"><IonIcon icon={checkmarkCircleOutline} />{notice}</p>}

                {result && (
                  <div className="result-panel">
                    <div className="result-heading">
                      <div>
                        <span className="result-kicker">{mode === 'encrypt' ? 'ENCRYPTED OUTPUT' : 'DECRYPTED MESSAGE'}</span>
                        <h2>{mode === 'encrypt' ? 'Ready to share' : 'Message unlocked'}</h2>
                      </div>
                      <button className="copy-button" type="button" onClick={handleCopy} aria-label="Copy result">
                        <IonIcon icon={clipboardOutline} /> Copy
                      </button>
                    </div>
                    <textarea className="result-output" value={result} readOnly aria-label="Result" rows={4} />
                    {mode === 'encrypt' && <p className="result-note">Share this text, but send the password through a different channel.</p>}
                  </div>
                )}
              </div>

              <aside className="security-rail" aria-label="Encryption details">
                <div className="rail-heading"><span>HOW IT WORKS</span><span className="rail-index">02 / 03</span></div>
                <ol className="steps-list">
                  <li><span className="step-number">01</span><div><strong>Password becomes a key</strong><p>PBKDF2 derives a unique 256-bit key from your password.</p></div></li>
                  <li><span className="step-number">02</span><div><strong>Message is sealed</strong><p>AES-GCM encrypts and authenticates your message.</p></div></li>
                  <li><span className="step-number">03</span><div><strong>You stay in control</strong><p>Copy the encrypted text. Keep the password private.</p></div></li>
                </ol>
                <div className="privacy-note">
                  <IonIcon icon={shieldCheckmarkOutline} />
                  <div><strong>Processed on this device</strong><p>Your message and password are not uploaded or saved.</p></div>
                </div>
                <div className="rail-footer"><span>WEB CRYPTO API</span><span>SHA-256 KDF</span><span>RANDOM SALT + IV</span></div>
              </aside>
            </section>
          </main>

          <footer className="page-footer">
            <span>BUILT FOR PRIVATE CONVERSATIONS</span>
            <span>Encryption is only as strong as the password you choose.</span>
          </footer>
        </div>
      </IonContent>
    </IonPage>
  );
};

export default Home;
