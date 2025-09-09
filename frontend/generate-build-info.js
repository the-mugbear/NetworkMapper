const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Read version from package.json
let packageVersion = '1.0.0';
try {
  const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  packageVersion = packageJson.version;
} catch (error) {
  console.warn('Could not read package.json version:', error.message);
}

// Generate build information
const buildInfo = {
  BUILD_TIME: new Date().toISOString(),
  VERSION: packageVersion,
  GIT_COMMIT: 'unknown'
};

// Try to get git commit hash
try {
  buildInfo.GIT_COMMIT = execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
} catch (error) {
  console.warn('Could not get git commit hash:', error.message);
}

// Create .env file for build
const envContent = Object.entries(buildInfo)
  .map(([key, value]) => `REACT_APP_${key}=${value}`)
  .join('\n');

fs.writeFileSync(path.join(__dirname, '.env.local'), envContent);

console.log('Build info generated:');
console.log(envContent);