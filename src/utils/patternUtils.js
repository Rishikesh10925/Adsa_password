export const getPasswordPattern = (password) => {
  // Pattern generation: map each character to a category token.
  return password
    .split("")
    .map((char) => {
      if (/[A-Z]/.test(char)) return "A";
      if (/[a-z]/.test(char)) return "a";
      if (/[0-9]/.test(char)) return "#";
      return "@";
    })
    .join("");
};

export const analyzePasswordPatterns = (rawInput) => {
  const passwords = rawInput
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  // Hash map usage: object keys are patterns and values are occurrence counts.
  const frequencyMap = {};

  passwords.forEach((password) => {
    const pattern = getPasswordPattern(password);
    frequencyMap[pattern] = (frequencyMap[pattern] || 0) + 1;
  });

  let mostCommonPattern = "";
  let highestFrequency = 0;

  Object.entries(frequencyMap).forEach(([pattern, count]) => {
    if (count > highestFrequency) {
      highestFrequency = count;
      mostCommonPattern = pattern;
    }
  });

  return {
    totalPasswords: passwords.length,
    frequencyMap,
    mostCommonPattern,
    highestFrequency,
  };
};