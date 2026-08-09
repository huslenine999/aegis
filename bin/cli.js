#!/usr/bin/env node

const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const aegisHome = path.join(os.homedir(), '.aegis');
const venvDir = path.join(aegisHome, 'venv');
const pipBin = path.join(venvDir, os.platform() === 'win32' ? 'Scripts/pip' : 'bin/pip');
const pythonBin = path.join(venvDir, os.platform() === 'win32' ? 'Scripts/python' : 'bin/python');
const installStamp = path.join(venvDir, '.aegis-install-stamp');

// Package directories
const packageRoot = path.join(__dirname, '..');
const requirementsPath = path.join(packageRoot, 'requirements.txt');
function checkPython() {
    try {
        execSync('python3 --version', { stdio: 'ignore' });
        return 'python3';
    } catch (e) {
        try {
            execSync('python --version', { stdio: 'ignore' });
            return 'python';
        } catch (e2) {
            console.error('Error: Python is required to run Aegis. Please install Python 3 and try again.');
            process.exit(1);
        }
    }
}

async function setupEnv() {
    if (!fs.existsSync(aegisHome)) {
        fs.mkdirSync(aegisHome, { recursive: true });
    }

    const pythonCmd = checkPython();

    let created = false;
    if (!fs.existsSync(pythonBin)) {
        console.log('🛡️ Creating Python virtual environment in ' + venvDir + '...');
        try {
            execSync(`${pythonCmd} -m venv "${venvDir}"`, { stdio: 'inherit' });
            created = true;
        } catch (e) {
            console.error('Failed to create virtual environment:', e);
            process.exit(1);
        }
    }

    const requirementsHash = crypto
        .createHash('sha256')
        .update(fs.readFileSync(requirementsPath))
        .digest('hex');
    const currentStamp = fs.existsSync(installStamp)
        ? fs.readFileSync(installStamp, 'utf8').trim()
        : '';
    if (!created && currentStamp === requirementsHash) {
        return;
    }

    console.log('🛡️ Installing Python dependencies...');
    try {
        execSync(`"${pipBin}" install --upgrade pip`, { stdio: 'inherit' });
        execSync(`"${pipBin}" install -r "${requirementsPath}"`, { stdio: 'inherit' });
        fs.writeFileSync(installStamp, requirementsHash + '\n', { mode: 0o600 });
    } catch (e) {
        console.error('Failed to install Python dependencies:', e);
        process.exit(1);
    }
}

async function run() {
    await setupEnv();
    const args = process.argv.slice(2);
    
    let runArgs = ['-m', 'app.main'];
    
    if (args.length > 0) {
        runArgs = ['-m', 'app.cli', ...args];
    } else {
        console.log('🛡️ Starting Aegis Security Console...');
        console.log('Access the dashboard at http://127.0.0.1:5001');
    }
    
    const appProcess = spawn(pythonBin, runArgs, {
        stdio: 'inherit',
        env: {
            ...process.env,
            AEGIS_DATA_DIR: aegisHome,
            AEGIS_HOST: '127.0.0.1',
            PYTHONPATH: [packageRoot, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter),
        }
    });

    appProcess.on('close', (code) => {
        process.exit(code);
    });
}

run();
