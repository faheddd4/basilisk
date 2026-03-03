const { app, BrowserWindow, ipcMain, dialog, shell, Menu } = require('electron');
const path = require('path');
const { spawn, execSync } = require('child_process');
const fs = require('fs');

// Fix GPU crashes on Wayland/Intel (prevents 30s startup delay)
app.commandLine.appendSwitch('disable-gpu-sandbox');
app.commandLine.appendSwitch('ozone-platform-hint', 'auto');
app.commandLine.appendSwitch('disable-software-rasterizer');

let mainWindow;
let pythonProcess;

function createWindow() {
    // Remove the native menu bar completely
    Menu.setApplicationMenu(null);

    // Resolve icon path: build/icon.png > src/assets/logo.jpg
    const iconPng = path.join(__dirname, 'build', 'icon.png');
    const iconJpg = path.join(__dirname, 'src', 'assets', 'logo.jpg');
    const iconPath = fs.existsSync(iconPng) ? iconPng : iconJpg;

    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1024,
        minHeight: 700,
        icon: iconPath,
        frame: false,
        autoHideMenuBar: true,
        backgroundColor: '#09090b',
        show: false, // Don't show until ready
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
        },
    });

    mainWindow.loadFile('src/index.html');

    // Show window as soon as the page is ready (don't wait for backend)
    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });
}

// Start FastAPI backend sidecar
function startBackend() {
    console.log('[*] Starting Basilisk Python backend...');

    let executablePath;
    let args = [];
    let options = {};
    const bridgePort = process.env.BASILISK_PORT || '8741';

    if (app.isPackaged) {
        if (process.platform === 'win32') {
            executablePath = path.join(process.resourcesPath, 'bin', 'basilisk-backend.exe');
        } else {
            const bundled = path.join(process.resourcesPath, 'bin', 'basilisk-backend');
            const system = path.join(__dirname, 'bin', 'basilisk-backend');
            executablePath = fs.existsSync(system) ? system : bundled;
        }

        if (!fs.existsSync(executablePath)) {
            console.error(`[FATAL] Backend binary not found: ${executablePath}`);
            dialog.showErrorBox('Basilisk Backend Missing', `Could not find backend at:\n${executablePath}\n\nPlease reinstall Basilisk.`);
            return;
        }

        if (process.platform !== 'win32') {
            try {
                fs.accessSync(executablePath, fs.constants.W_OK);
                fs.chmodSync(executablePath, 0o755);
            } catch (e) { /* system install, already +x */ }
        }

        options = { stdio: 'pipe', env: { ...process.env, BASILISK_PORT: bridgePort } };
    } else {
        // Dev mode — use venv python if available
        const projectRoot = path.join(__dirname, '..');
        const venvPython = path.join(projectRoot, 'venv', 'bin', 'python');
        const venvPythonWin = path.join(projectRoot, 'venv', 'Scripts', 'python.exe');

        if (process.platform === 'win32' && fs.existsSync(venvPythonWin)) {
            executablePath = venvPythonWin;
        } else if (fs.existsSync(venvPython)) {
            executablePath = venvPython;
        } else {
            executablePath = process.platform === 'win32' ? 'python' : 'python3';
        }

        options = {
            cwd: projectRoot,
            stdio: 'pipe',
            env: { ...process.env, BASILISK_PORT: bridgePort },
        };
        args = ['-m', 'basilisk.desktop_backend'];
    }

    console.log(`[Main] Spawning: ${executablePath} ${args.join(' ')}`);

    try {
        pythonProcess = spawn(executablePath, args, options);
    } catch (e) {
        console.error(`[FATAL] Failed to spawn backend: ${e.message}`);
        dialog.showErrorBox('Basilisk Backend Error', `Failed to start backend:\n${e.message}`);
        return;
    }

    pythonProcess.stdout.on('data', (data) => {
        const msg = data.toString();
        console.log(`[Python] ${msg}`);
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('backend-log', msg);
        }
    });

    pythonProcess.stderr.on('data', (data) => {
        const msg = data.toString();
        console.error(`[Python] ${msg}`);
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('backend-log', msg);
        }
    });

    pythonProcess.on('exit', (code, signal) => {
        console.error(`[Main] Backend exited code=${code} signal=${signal}`);
        if (code !== 0 && code !== null && mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('backend-error', `Backend crashed (exit code ${code})`);
        }
    });

    pythonProcess.on('error', (err) => {
        console.error(`[FATAL] Backend error: ${err.message}`);
        dialog.showErrorBox('Basilisk Backend Error', `Backend failed:\n${err.message}`);
    });
}

app.whenReady().then(() => {
    startBackend();
    createWindow();

    // IPC Handlers
    ipcMain.handle('dialog:exportReport', async (event, htmlContent) => {
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Export Report',
            filters: [
                { name: 'HTML Report', extensions: ['html'] },
                { name: 'JSON Report', extensions: ['json'] },
                { name: 'SARIF Report', extensions: ['sarif'] },
                { name: 'Markdown', extensions: ['md'] },
            ],
            defaultPath: `basilisk_report_${Date.now()}.html`,
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, htmlContent, 'utf-8');
                return { success: true, path: result.filePath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:saveFile', async (event, { content, defaultName, filters }) => {
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Save File',
            filters: filters || [{ name: 'All Files', extensions: ['*'] }],
            defaultPath: defaultName,
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, content, 'utf-8');
                return { success: true, path: result.filePath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    // Window controls
    ipcMain.on('window:minimize', () => { if (mainWindow) mainWindow.minimize(); });
    ipcMain.on('window:maximize', () => {
        if (mainWindow) {
            mainWindow.isMaximized() ? mainWindow.restore() : mainWindow.maximize();
        }
    });
    ipcMain.on('window:close', () => { if (mainWindow) mainWindow.close(); });

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (pythonProcess) pythonProcess.kill();
    if (process.platform !== 'darwin') app.quit();
});
