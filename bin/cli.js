#!/usr/bin/env node

const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const aegisHome = path.join(os.homedir(), '.aegis');
const venvDir = path.join(aegisHome, 'venv');
const pipBin = path.join(venvDir, os.platform() === 'win32' ? 'Scripts/pip' : 'bin/pip');
const pythonBin = path.join(venvDir, os.platform() === 'win32' ? 'Scripts/python' : 'bin/python');

// Package directories
const packageRoot = path.join(__dirname, '..');
const requirementsPath = path.join(packageRoot, 'requirements.txt');
const mainPyPath = path.join(packageRoot, 'app', 'main.py');

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

    if (!fs.existsSync(pythonBin)) {
        console.log('🛡️ Creating Python virtual environment in ' + venvDir + '...');
        try {
            execSync(`${pythonCmd} -m venv "${venvDir}"`, { stdio: 'inherit' });
        } catch (e) {
            console.error('Failed to create virtual environment:', e);
            process.exit(1);
        }
    }

    // Install/update requirements
    console.log('🛡️ Ensuring Python dependencies are installed...');
    try {
        execSync(`"${pipBin}" install --upgrade pip`, { stdio: 'inherit' });
        execSync(`"${pipBin}" install -r "${requirementsPath}"`, { stdio: 'inherit' });
    } catch (e) {
        console.error('Failed to install Python dependencies:', e);
        process.exit(1);
    }
}

async function run() {
    await setupEnv();
    const args = process.argv.slice(2);
    const cliPyPath = path.join(packageRoot, 'app', 'cli.py');
    
    let targetScript = mainPyPath;
    let runArgs = [mainPyPath];
    
    if (args.length > 0) {
        targetScript = cliPyPath;
        runArgs = [cliPyPath, ...args];
    } else {
        console.log('🛡️ Starting Aegis Security Console...');
        console.log('Access the dashboard at http://127.0.0.1:5001');
    }
    
    const appProcess = spawn(pythonBin, runArgs, {
        stdio: 'inherit',
        env: { ...process.env, AEGIS_DATA_DIR: aegisHome }
    });

    appProcess.on('close', (code) => {
        process.exit(code);
    });
}

run();

