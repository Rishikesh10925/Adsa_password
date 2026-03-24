import { useMemo, useState } from "react";

const SPECIAL_REGEX = /[^A-Za-z0-9]/;
const LOWER_REGEX = /[a-z]/;
const UPPER_REGEX = /[A-Z]/;
const DIGIT_REGEX = /\d/;
const REPEATING_REGEX = /(.)\1{2,}/;
const SEQUENTIAL_REGEX = /(012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210)/;

const COMMON_PASSWORD_LIST = ["password", "123456", "admin", "qwerty", "abc123"];

// Hash map usage: O(1)-style lookup for known weak passwords.
const COMMON_PASSWORD_MAP = COMMON_PASSWORD_LIST.reduce((accumulator, password) => {
  accumulator[password] = true;
  return accumulator;
}, {});

const replacementMap = {
  a: "@",
  e: "3",
  i: "1",
  o: "0",
  s: "$",
  t: "7",
};

const uppercaseChars = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const lowercaseChars = "abcdefghijkmnopqrstuvwxyz";
const numberChars = "23456789";
const symbolChars = "!@#$%^&*-_=+?";

const getSecureRandomInt = (max) => {
  if (window.crypto?.getRandomValues) {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    return array[0] % max;
  }
  return Math.floor(Math.random() * max);
};

const pickRandom = (pool) => pool[getSecureRandomInt(pool.length)];

const shuffleString = (value) => {
  const chars = value.split("");
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = getSecureRandomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
};

const generateStrongPassword = (length = 14) => {
  const safeLength = Math.max(12, length);
  const pool = `${uppercaseChars}${lowercaseChars}${numberChars}${symbolChars}`;

  const output = [
    pickRandom(uppercaseChars),
    pickRandom(lowercaseChars),
    pickRandom(numberChars),
    pickRandom(symbolChars),
  ];

  while (output.length < safeLength) {
    output.push(pickRandom(pool));
  }

  return shuffleString(output.join(""));
};

const getPattern = (password) => {
  // Pattern logic: normalize each character into structural tokens.
  return password
    .split("")
    .map((character) => {
      if (UPPER_REGEX.test(character)) return "A";
      if (LOWER_REGEX.test(character)) return "a";
      if (DIGIT_REGEX.test(character)) return "#";
      return "@";
    })
    .join("");
};

const getCharsetSize = (password) => {
  let size = 0;
  if (LOWER_REGEX.test(password)) size += 26;
  if (UPPER_REGEX.test(password)) size += 26;
  if (DIGIT_REGEX.test(password)) size += 10;
  if (SPECIAL_REGEX.test(password)) size += 32;
  return size || 1;
};

const getEntropyBits = (password) => {
  const charsetSize = getCharsetSize(password);
  return password.length * Math.log2(charsetSize);
};

const getEntropyLabel = (entropyBits) => {
  if (entropyBits < 28) return "Low entropy";
  if (entropyBits < 45) return "Moderate entropy";
  if (entropyBits < 60) return "Good entropy";
  return "High entropy";
};

const getCrackTimeEstimate = ({ entropyBits, isCommonPassword, hasRepeating, hasSequential }) => {
  if (isCommonPassword) return "Instantly";
  if (entropyBits < 28 || hasRepeating || hasSequential) return "Seconds";
  if (entropyBits < 50) return "Hours";
  return "Years";
};

const getPasswordScore = (password) => {
  // Strength scoring logic: weighted additions + penalties on common weak patterns.
  let score = 0;
  const weaknesses = [];
  const lower = password.toLowerCase();

  const isCommonPassword = Boolean(COMMON_PASSWORD_MAP[lower]);
  const hasUppercase = UPPER_REGEX.test(password);
  const hasLowercase = LOWER_REGEX.test(password);
  const hasNumbers = DIGIT_REGEX.test(password);
  const hasSymbols = SPECIAL_REGEX.test(password);
  const hasRepeating = REPEATING_REGEX.test(lower);
  const hasSequential = SEQUENTIAL_REGEX.test(lower);

  if (password.length >= 12) {
    score += 30;
  } else if (password.length >= 8) {
    score += 20;
  } else {
    weaknesses.push("Too short (minimum 8 characters recommended)");
  }

  if (hasUppercase) score += 15;
  else weaknesses.push("No uppercase letter");

  if (hasLowercase) score += 15;
  else weaknesses.push("No lowercase letter");

  if (hasNumbers) score += 15;
  else weaknesses.push("No numbers");

  if (hasSymbols) score += 15;
  else weaknesses.push("No symbols");

  if (hasRepeating) {
    score -= 15;
    weaknesses.push("Repeating characters detected");
  }

  if (hasSequential) {
    score -= 10;
    weaknesses.push("Sequential pattern detected");
  }

  if (isCommonPassword) {
    score -= 35;
    weaknesses.push("Common password found in breach dictionaries");
  }

  const normalizedScore = Math.max(0, Math.min(100, Math.round(score)));
  const entropyBits = getEntropyBits(password);

  return {
    score: normalizedScore,
    entropyBits,
    entropyLabel: getEntropyLabel(entropyBits),
    weaknesses,
    isCommonPassword,
    hasRepeating,
    hasSequential,
  };
};

const getStrengthLabel = (score) => {
  if (score < 25) return "Very weak";
  if (score < 50) return "Weak";
  if (score < 75) return "Medium";
  return "Strong";
};

const suggestStrongerPassword = (password) => {
  const base = password
    .split("")
    .map((character) => {
      const lower = character.toLowerCase();
      return replacementMap[lower] ?? character;
    })
    .join("");

  let upgraded = base.length > 0 ? `${base[0].toUpperCase()}${base.slice(1)}` : "Secure";

  if (!DIGIT_REGEX.test(upgraded)) upgraded += pickRandom(numberChars);
  if (!SPECIAL_REGEX.test(upgraded)) upgraded += pickRandom(symbolChars);
  if (!UPPER_REGEX.test(upgraded)) upgraded = `R${upgraded}`;

  while (upgraded.length < 10) {
    upgraded += pickRandom(`${lowercaseChars}${numberChars}${symbolChars}`);
  }

  return shuffleString(upgraded);
};

const analyzePasswords = (inputText) => {
  const passwords = inputText
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  // Hash map usage: stores pattern occurrence counts { pattern: frequency }.
  const patternFrequencyMap = {};

  const rows = passwords.map((password) => {
    const pattern = getPattern(password);
    const analysis = getPasswordScore(password);
    const strengthLabel = getStrengthLabel(analysis.score);
    const crackTime = getCrackTimeEstimate(analysis);

    patternFrequencyMap[pattern] = (patternFrequencyMap[pattern] || 0) + 1;

    return {
      password,
      pattern,
      score: analysis.score,
      strengthLabel,
      crackTime,
      entropyBits: analysis.entropyBits,
      entropyLabel: analysis.entropyLabel,
      weaknesses: analysis.weaknesses,
      isCommonPassword: analysis.isCommonPassword,
      isRisky: analysis.weaknesses.length > 0,
      suggestion: suggestStrongerPassword(password),
    };
  });

  let mostCommonPattern = "N/A";
  let highestFrequency = 0;

  Object.entries(patternFrequencyMap).forEach(([pattern, count]) => {
    if (count > highestFrequency) {
      mostCommonPattern = pattern;
      highestFrequency = count;
    }
  });

  return {
    totalPasswords: passwords.length,
    patternFrequencyMap,
    mostCommonPattern,
    highestFrequency,
    rows,
  };
};

const parseCsvLine = (line) => {
  const values = [];
  let current = "";
  let inQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];

    if (char === '"') {
      const nextChar = line[index + 1];
      if (inQuotes && nextChar === '"') {
        current += '"';
        index += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === "," && !inQuotes) {
      values.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  values.push(current);
  return values.map((value) => value.trim());
};

const extractPasswordsFromCsv = (csvText) => {
  const lines = csvText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length === 0) return [];

  const header = parseCsvLine(lines[0]).map((column) => column.toLowerCase());
  const passwordIndex = header.findIndex((column) =>
    ["password", "pass", "pwd"].includes(column)
  );

  const dataLines = lines.slice(1);
  const sourceLines = dataLines.length > 0 ? dataLines : lines;

  return sourceLines
    .map((line) => parseCsvLine(line))
    .map((columns) => {
      if (passwordIndex >= 0) {
        return columns[passwordIndex] || "";
      }
      return columns[0] || "";
    })
    .map((password) => password.trim())
    .filter(Boolean);
};

const extractPasswordsFromText = (rawText) =>
  rawText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

const readAsText = (file) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(new Error("Failed to read file."));
    reader.readAsText(file);
  });

const readDocxText = async (file) => {
  const mammoth = await import("mammoth/mammoth.browser");
  const arrayBuffer = await file.arrayBuffer();
  const result = await mammoth.extractRawText({ arrayBuffer });
  return result.value || "";
};

function App() {
  const [inputText, setInputText] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [importStatus, setImportStatus] = useState("");
  const [generatedPassword, setGeneratedPassword] = useState(generateStrongPassword());
  const [activeView, setActiveView] = useState("analyzer");

  const appendPasswordsToInput = (passwords) => {
    if (passwords.length === 0) {
      setImportStatus("No passwords found in the selected file.");
      return;
    }

    setInputText((previous) => {
      const prefix = previous.trim() ? `${previous.trim()}\n` : "";
      return `${prefix}${passwords.join("\n")}`;
    });
    setImportStatus(`Imported ${passwords.length} password(s).`);
    setError("");
  };

  const handleDocumentUpload = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;

    try {
      const lowerName = file.name.toLowerCase();
      let parsedPasswords = [];

      if (lowerName.endsWith(".csv")) {
        const csvText = await readAsText(file);
        parsedPasswords = extractPasswordsFromCsv(csvText);
      } else if (lowerName.endsWith(".json")) {
        const jsonText = await readAsText(file);
        const parsed = JSON.parse(jsonText);
        if (Array.isArray(parsed)) {
          parsedPasswords = parsed.map((item) => String(item).trim()).filter(Boolean);
        } else if (Array.isArray(parsed.passwords)) {
          parsedPasswords = parsed.passwords
            .map((item) => String(item).trim())
            .filter(Boolean);
        }
      } else if (lowerName.endsWith(".docx")) {
        const docxText = await readDocxText(file);
        parsedPasswords = extractPasswordsFromText(docxText);
      } else if (lowerName.endsWith(".doc")) {
        setImportStatus(".doc is not supported in browser parsing. Please use .docx, .txt, or .csv.");
        return;
      } else {
        const text = await readAsText(file);
        parsedPasswords = extractPasswordsFromText(text);
      }

      appendPasswordsToInput(parsedPasswords);
    } catch {
      setImportStatus("Could not import that file. Please verify format and try again.");
    }
  };

  const handleGoogleCsvUpload = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;

    try {
      const csvText = await readAsText(file);
      const lines = csvText
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);

      if (lines.length < 2) {
        setImportStatus("Google Password CSV is empty or invalid.");
        return;
      }

      const header = parseCsvLine(lines[0]).map((value) => value.toLowerCase());
      const passwordIndex = header.findIndex((value) => value === "password");

      if (passwordIndex < 0) {
        setImportStatus("No 'password' column found. Export directly from Google Password Manager.");
        return;
      }

      const passwords = lines
        .slice(1)
        .map((line) => parseCsvLine(line)[passwordIndex] || "")
        .map((value) => value.trim())
        .filter(Boolean);

      appendPasswordsToInput(passwords);
    } catch {
      setImportStatus("Unable to read Google Password CSV file.");
    }
  };

  const handleAnalyze = () => {
    if (!inputText.trim()) {
      setError("Please enter at least one password.");
      setResult(null);
      return;
    }

    setError("");
    const analysis = analyzePasswords(inputText);
    setResult(analysis);
  };

  const handleClear = () => {
    setInputText("");
    setError("");
    setImportStatus("");
    setResult(null);
  };

  const handleGeneratePassword = () => {
    setGeneratedPassword(generateStrongPassword());
  };

  const handleUseGeneratedPassword = () => {
    setInputText((previous) => {
      const prefix = previous.trim() ? `${previous.trim()}\n` : "";
      return `${prefix}${generatedPassword}`;
    });
    setImportStatus("Generated strong password added to input.");
  };

  const patternEntries = useMemo(
    () => (result ? Object.entries(result.patternFrequencyMap) : []),
    [result]
  );

  const overview = useMemo(() => {
    if (!result) {
      return {
        averageScore: 0,
        riskyCount: 0,
        strongCount: 0,
        weakCount: 0,
      };
    }

    const totalScore = result.rows.reduce((sum, row) => sum + row.score, 0);
    const averageScore = result.rows.length
      ? Math.round(totalScore / result.rows.length)
      : 0;

    return {
      averageScore,
      riskyCount: result.rows.filter((row) => row.isRisky).length,
      strongCount: result.rows.filter((row) => row.strengthLabel === "Strong").length,
      weakCount: result.rows.filter(
        (row) => row.strengthLabel === "Weak" || row.strengthLabel === "Very weak"
      ).length,
      averageEntropy: result.rows.length
        ? Math.round(result.rows.reduce((sum, row) => sum + row.entropyBits, 0) / result.rows.length)
        : 0,
    };
  }, [result]);

  const strengthClassMap = {
    "Very weak": "strengthWeak",
    Weak: "strengthWeak",
    Medium: "strengthMedium",
    Strong: "strengthStrong",
  };

  return (
    <main className="page">
      <section className="appShell">
        <header className="hero">
          <p className="eyebrow">Security Intelligence Suite</p>
          <h1>Password Security Auditor</h1>
          <p className="subtitle">
            Enterprise-style password auditing with weighted scoring, pattern-risk
            discovery, crack-time estimation, and stronger replacement guidance.
          </p>
        </header>

        <nav className="navTabs" aria-label="Main navigation">
          <button
            type="button"
            className={`navTabBtn ${activeView === "analyzer" ? "active" : ""}`}
            onClick={() => setActiveView("analyzer")}
          >
            Analyzer
          </button>
          <button
            type="button"
            className={`navTabBtn ${activeView === "concept" ? "active" : ""}`}
            onClick={() => setActiveView("concept")}
          >
            ADSA Concept Page
          </button>
        </nav>

        {activeView === "analyzer" ? (
          <>
            <section className="inputPanel">
              <label htmlFor="passwordInput" className="label">
                Password List (one per line)
              </label>
              <textarea
                id="passwordInput"
                className="textarea"
                rows={10}
                placeholder="Example:\nrihsii\npassword\nRishi@123"
                value={inputText}
                onChange={(event) => setInputText(event.target.value)}
              />

              <div className="uploadGrid">
                <label className="uploadCard" htmlFor="docUpload">
                  <span className="uploadTitle">Upload Document</span>
                  <span className="uploadHint">Supports .txt, .csv, .json, .docx</span>
                  <input
                    id="docUpload"
                    type="file"
                    className="fileInput"
                    accept=".txt,.csv,.json,.doc,.docx"
                    onChange={handleDocumentUpload}
                  />
                </label>

                <label className="uploadCard" htmlFor="googleUpload">
                  <span className="uploadTitle">Import Google Password CSV</span>
                  <span className="uploadHint">Use CSV export from Google Password Manager</span>
                  <input
                    id="googleUpload"
                    type="file"
                    className="fileInput"
                    accept=".csv"
                    onChange={handleGoogleCsvUpload}
                  />
                </label>
              </div>

              <p className="privacyNote">
                Direct access to saved Google/Chrome passwords is blocked by browser security.
                Import works via exported CSV file only.
              </p>

              <div className="generatorCard">
                <p className="generatorTitle">Strong Password Generator</p>
                <p className="generatorValue">{generatedPassword}</p>
                <div className="generatorActions">
                  <button type="button" className="btn secondary" onClick={handleGeneratePassword}>
                    Generate New
                  </button>
                  <button type="button" className="btn ghost" onClick={handleUseGeneratedPassword}>
                    Use in Input
                  </button>
                </div>
              </div>

              {importStatus && <p className="importStatus">{importStatus}</p>}

              {error && <p className="error">{error}</p>}

              <div className="actions">
                <button type="button" className="btn primary" onClick={handleAnalyze}>
                  Analyze Security
                </button>
                <button type="button" className="btn ghost" onClick={handleClear}>
                  Clear Input
                </button>
              </div>
            </section>

            {result && (
              <section className="results">
                <div className="sectionHeader">
                  <h2>Audit Summary</h2>
                  <span className="statusChip">Live Assessment</span>
                </div>

                <div className="dashboardBand">
                  <div className="statsGrid">
                    <article className="statCard">
                      <p className="statLabel">Total Passwords</p>
                      <p className="statValue">{result.totalPasswords}</p>
                    </article>
                    <article className="statCard">
                      <p className="statLabel">Most Common Pattern</p>
                      <p className="statValue compact">{result.mostCommonPattern}</p>
                      {result.highestFrequency > 0 && (
                        <p className="statMeta">Appears {result.highestFrequency} times</p>
                      )}
                    </article>
                    <article className="statCard">
                      <p className="statLabel">Risky Passwords</p>
                      <p className="statValue">{overview.riskyCount}</p>
                      <p className="statMeta">Need urgent fixes</p>
                    </article>
                    <article className="statCard">
                      <p className="statLabel">Strong Passwords</p>
                      <p className="statValue">{overview.strongCount}</p>
                      <p className="statMeta">Healthy credentials</p>
                    </article>
                    <article className="statCard">
                      <p className="statLabel">Average Entropy</p>
                      <p className="statValue">{overview.averageEntropy} bits</p>
                      <p className="statMeta">Higher is harder to crack</p>
                    </article>
                  </div>

                  <aside className="postureCard">
                    <p className="statLabel">Security Posture</p>
                    <div
                      className="scoreDial"
                      style={{
                        background: `conic-gradient(#0f6fff ${overview.averageScore * 3.6}deg, #dce7fa 0deg)`,
                      }}
                    >
                      <div className="scoreDialInner">
                        <strong>{overview.averageScore}</strong>
                        <span>/100</span>
                      </div>
                    </div>
                    <p className="statMeta">Weak or very weak: {overview.weakCount}</p>
                  </aside>
                </div>

                <section className="panelCard">
                  <h3 className="sectionTitle">Pattern Frequency (Hash Map Output)</h3>
                  <div className="tableWrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Pattern</th>
                          <th>Frequency</th>
                        </tr>
                      </thead>
                      <tbody>
                        {patternEntries.map(([pattern, count]) => (
                          <tr
                            key={pattern}
                            className={
                              pattern === result.mostCommonPattern ? "highlightRow" : ""
                            }
                          >
                            <td>{pattern}</td>
                            <td>{count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>

                <section className="panelCard">
                  <h3 className="sectionTitle">Detailed Password Review</h3>
                  <div className="tableWrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Input Password</th>
                          <th>Pattern</th>
                          <th>Score</th>
                          <th>Strength</th>
                          <th>Crack Time</th>
                          <th>Entropy</th>
                          <th>Weaknesses</th>
                          <th>Suggested Strong Password</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.rows.map((row) => (
                          <tr
                            key={`${row.password}-${row.suggestion}`}
                            className={row.isRisky ? "riskyRow" : ""}
                          >
                            <td className={row.isRisky ? "weakPassword" : ""}>{row.password}</td>
                            <td>{row.pattern}</td>
                            <td>
                              <div className="scoreBlock">
                                <span className="scoreValue">{row.score}/100</span>
                                <div className="strengthBarTrack">
                                  <div
                                    className={`strengthBarFill ${strengthClassMap[row.strengthLabel]}`}
                                    style={{ width: `${row.score}%` }}
                                  />
                                </div>
                              </div>
                            </td>
                            <td>
                              <span className={`strengthBadge ${strengthClassMap[row.strengthLabel]}`}>
                                {row.strengthLabel}
                              </span>
                            </td>
                            <td>{row.crackTime}</td>
                            <td>
                              <div className="entropyBlock">
                                <strong>{Math.round(row.entropyBits)} bits</strong>
                                <span>{row.entropyLabel}</span>
                              </div>
                            </td>
                            <td>
                              {row.weaknesses.length > 0 ? (
                                <ul className="inlineList">
                                  {row.weaknesses.map((reason) => (
                                    <li key={reason}>{reason}</li>
                                  ))}
                                </ul>
                              ) : (
                                <span className="positiveText">Looks good</span>
                              )}
                            </td>
                            <td className="suggestionText">{row.suggestion}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              </section>
            )}
          </>
        ) : (
          <section className="conceptPage">
            <div className="conceptIntro">
              <h2>ADSA Concept Behind This Project</h2>
              <p>
                This project is a practical ADSA case-study where strings are transformed,
                grouped, and analyzed using data structures and algorithms to evaluate
                password security quality.
              </p>
            </div>

            <div className="conceptGrid">
              <article className="conceptCard">
                <h3>1. Hash Map Usage</h3>
                <p>
                  We use JavaScript objects as hash maps to track pattern frequencies and to
                  perform fast lookup for common passwords.
                </p>
                <p className="monoText">patternFrequencyMap[pattern] = (count || 0) + 1</p>
              </article>

              <article className="conceptCard">
                <h3>2. String Processing Pipeline</h3>
                <p>
                  Each password is scanned character-by-character and mapped into a structural
                  token format: uppercase to A, lowercase to a, digit to #, symbol to @.
                </p>
                <p className="monoText">Rishi@123 -&gt; Aaaaa@###</p>
              </article>

              <article className="conceptCard">
                <h3>3. Rule-Based Scoring Algorithm</h3>
                <p>
                  Weighted scoring uses additive rewards (length/diversity) and penalties
                  (repetition/sequences/common passwords) to compute a 0 to 100 score.
                </p>
              </article>

              <article className="conceptCard">
                <h3>4. Entropy Estimation</h3>
                <p>
                  Entropy approximates unpredictability using charset size and password length:
                </p>
                <p className="monoText">Entropy = length * log2(charsetSize)</p>
              </article>
            </div>

            <section className="conceptCard wide">
              <h3>Time Complexity Discussion (ADSA)</h3>
              <div className="conceptTableWrap">
                <table>
                  <thead>
                    <tr>
                      <th>Operation</th>
                      <th>Complexity</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Pattern Generation</td>
                      <td>O(L)</td>
                      <td>Single pass over password characters</td>
                    </tr>
                    <tr>
                      <td>Frequency Counting</td>
                      <td>O(N)</td>
                      <td>One hash-map update per password</td>
                    </tr>
                    <tr>
                      <td>Common Password Check</td>
                      <td>O(1)</td>
                      <td>Hash map lookup by password string key</td>
                    </tr>
                    <tr>
                      <td>Total Analysis</td>
                      <td>O(N * L)</td>
                      <td>N passwords, each scanned for multiple string rules</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>

            <section className="conceptCard wide">
              <h3>Why This Fits ADSA Coursework</h3>
              <ul className="inlineList">
                <li>Demonstrates hash maps for frequency counting and fast dictionary lookup.</li>
                <li>Applies string algorithms for tokenization, sequence detection, and repetition checks.</li>
                <li>Transforms theoretical complexity analysis into a real security auditing tool.</li>
                <li>Combines data structures with practical UI to communicate algorithmic insights clearly.</li>
              </ul>
            </section>
          </section>
        )}
      </section>
    </main>
  );
}

export default App;