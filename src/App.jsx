import { useMemo, useState } from "react";

const SPECIAL_REGEX = /[^A-Za-z0-9]/;
const LOWER_REGEX = /[a-z]/;
const UPPER_REGEX = /[A-Z]/;
const DIGIT_REGEX = /\d/;
const REPEATING_REGEX = /(.)\1{2,}/;
const ONLY_LOWERCASE_REGEX = /^[a-z]+$/;
const SEQUENTIAL_NUMBERS_REGEX = /012|123|234|345|456|567|678|789/;

const COMMON_PASSWORDS = ["password", "123456", "admin", "qwerty", "abc123"];

const replacementMap = {
  a: "@",
  e: "3",
  i: "1",
  o: "0",
  s: "$",
  t: "7",
};

const randomPool = "!@#$%&*X9Z7Q";

const getRandomChars = (length) => {
  let output = "";
  for (let index = 0; index < length; index += 1) {
    const pick = Math.floor(Math.random() * randomPool.length);
    output += randomPool[pick];
  }
  return output;
};

const getPattern = (password) => {
  // Pattern logic: normalize each character into its structural token.
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

const getRiskSignals = (password) => {
  // Pattern detection: identify common weak structures and predictable sequences.
  const normalized = password.toLowerCase();
  const signals = [];

  if (ONLY_LOWERCASE_REGEX.test(password)) {
    signals.push("Only lowercase letters (low complexity)");
  }

  if (SEQUENTIAL_NUMBERS_REGEX.test(normalized)) {
    signals.push("Sequential numbers found (e.g., 123)");
  }

  if (REPEATING_REGEX.test(normalized)) {
    signals.push("Repeating characters detected");
  }

  return signals;
};

const getPasswordScore = (password) => {
  // Strength scoring logic: weighted signals produce a normalized 0-100 score.
  let rawScore = 0;
  const reasons = [];

  const normalized = password.toLowerCase();
  const isCommonPassword = COMMON_PASSWORDS.includes(normalized);
  const hasNumbers = DIGIT_REGEX.test(password);
  const hasUppercase = UPPER_REGEX.test(password);
  const hasLowercase = LOWER_REGEX.test(password);
  const hasSpecial = SPECIAL_REGEX.test(password);
  const hasRepeatingCharacters = REPEATING_REGEX.test(normalized);

  if (password.length >= 8) {
    rawScore += 20;
  } else {
    reasons.push("Length is below 8 characters.");
  }

  if (hasUppercase) {
    rawScore += 10;
  } else {
    reasons.push("No uppercase letter found.");
  }

  if (hasLowercase) {
    rawScore += 10;
  } else {
    reasons.push("No lowercase letter found.");
  }

  if (hasNumbers) {
    rawScore += 10;
  } else {
    reasons.push("No number found.");
  }

  if (hasSpecial) {
    rawScore += 15;
  } else {
    reasons.push("No special character found.");
  }

  if (hasRepeatingCharacters) {
    rawScore -= 15;
    reasons.push("Repeated characters reduce unpredictability.");
  }

  if (isCommonPassword) {
    rawScore -= 30;
    reasons.push("This is a known common password.");
  }

  const normalizedScore = Math.max(0, Math.min(100, Math.round((rawScore / 65) * 100)));

  return {
    score: normalizedScore,
    rawScore,
    reasons,
    isCommonPassword,
  };
};

const getStrengthLabel = (score) => {
  if (score < 25) return "Very weak";
  if (score < 50) return "Weak";
  if (score < 75) return "Medium";
  return "Strong";
};

const getCrackTimeEstimate = (strengthLabel) => {
  if (strengthLabel === "Very weak") return "Instantly";
  if (strengthLabel === "Weak") return "Few seconds";
  if (strengthLabel === "Medium") return "Hours";
  return "Years";
};

const suggestStrongerPassword = (password) => {
  let transformed = password
    .split("")
    .map((character) => {
      const lower = character.toLowerCase();
      if (replacementMap[lower]) {
        return Math.random() > 0.5 ? replacementMap[lower] : character;
      }
      return character;
    })
    .join("");

  if (transformed.length > 0) {
    transformed = `${transformed[0].toUpperCase()}${transformed.slice(1)}`;
  } else {
    transformed = "Secure";
  }

  if (!SPECIAL_REGEX.test(transformed)) {
    transformed += "@";
  }

  if (!DIGIT_REGEX.test(transformed)) {
    transformed += String(Math.floor(Math.random() * 90) + 10);
  }

  if (!UPPER_REGEX.test(transformed)) {
    transformed = `R${transformed}`;
  }

  if (transformed.length < 8) {
    transformed += getRandomChars(8 - transformed.length);
  }

  return transformed;
};

const analyzePasswords = (inputText) => {
  const passwords = inputText
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  // Hash map usage: object stores pattern counts as { pattern: frequency }.
  const patternFrequencyMap = {};

  const rows = passwords.map((password) => {
    const pattern = getPattern(password);
    const riskSignals = getRiskSignals(password);
    const { score, reasons, isCommonPassword } = getPasswordScore(password);
    const strengthLabel = getStrengthLabel(score);
    const crackTime = getCrackTimeEstimate(strengthLabel);

    patternFrequencyMap[pattern] = (patternFrequencyMap[pattern] || 0) + 1;

    return {
      password,
      pattern,
      score,
      strengthLabel,
      crackTime,
      riskSignals,
      reasons,
      isCommonPassword,
      isRisky: riskSignals.length > 0 || isCommonPassword,
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
                      <th>Weak Reasons</th>
                      <th>Risk Patterns</th>
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
                          {row.reasons.length > 0 ? (
                            <ul className="inlineList">
                              {row.reasons.map((reason) => (
                                <li key={reason}>{reason}</li>
                              ))}
                            </ul>
                          ) : (
                            <span className="positiveText">Looks good</span>
                          )}
                        </td>
                        <td>
                          {row.isCommonPassword && <div className="riskTag">Common password</div>}
                          {row.riskSignals.length > 0 ? (
                            <ul className="inlineList">
                              {row.riskSignals.map((signal) => (
                                <li key={signal}>{signal}</li>
                              ))}
                            </ul>
                          ) : (
                            <span className="positiveText">None</span>
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
      </section>
    </main>
  );
}

export default App;