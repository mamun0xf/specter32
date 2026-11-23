document.addEventListener('DOMContentLoaded', () => {
    const el = {
        scanBtn: document.getElementById('scanBtn'),
        networkList: document.getElementById('networkList'),
        targetSSID: document.getElementById('targetSSID'),
        targetBSSID: document.getElementById('targetBSSID'),
        targetChannel: document.getElementById('targetChannel'),
        scanClientsBtn: document.getElementById('scanClientsBtn'),
        clientList: document.getElementById('clientList'),

        channelSelect: document.getElementById('channelSelect'),
        applyChannelBtn: document.getElementById('applyChannelBtn'),

        // Deauth controls
        deauthDurationSeconds: document.getElementById('deauthDurationSeconds'),
        startDeauthBtn: document.getElementById('startDeauthBtn'),
        stopDeauthBtn: document.getElementById('stopDeauthBtn'),

        // Capture controls
        startCaptureBtn: document.getElementById('startCaptureBtn'),
        stopCaptureBtn: document.getElementById('stopCaptureBtn'),

        // Evil Twin controls
        startEvilTwinBtn: document.getElementById('startEvilTwinBtn'),
        stopEvilTwinBtn: document.getElementById('stopEvilTwinBtn'),

        // Beacon Flood controls
        beaconMode: document.getElementById('beaconMode'),
        beaconSsid: document.getElementById('beaconSsid'),
        beaconAmount: document.getElementById('beaconAmount'),
        beaconDuration: document.getElementById('beaconDuration'),
        startBeaconBtn: document.getElementById('startBeaconBtn'),
        stopBeaconBtn: document.getElementById('stopBeaconBtn'),

        refreshFilesBtn: document.getElementById('refreshFilesBtn'),
        resetDeviceBtn: document.getElementById('resetDeviceBtn'),
        fileList: document.getElementById('fileList'),
        statusBar: document.getElementById('statusBar'),
        apName: document.getElementById('apName'),
        apMac: document.getElementById('apMac'),
        apChannel: document.getElementById('apChannel'),

        // PMKID controls
        startPmkidBtn: document.getElementById('startPmkidBtn'),
        stopPmkidBtn: document.getElementById('stopPmkidBtn'),

        // Router Controls
        routerPassword: document.getElementById('routerPassword'),
        routerConnectBtn: document.getElementById('routerConnectBtn'),
        routerStatusText: document.getElementById('routerStatusText'),
    };

    const elAuto = {
        pmkid: document.getElementById('autoPmkidTime'),
        handshake: document.getElementById('autoHandshakeTime'),
        btn: document.getElementById('startAutoHuntBtn')
    };

    const targetDependentControls = [
        el.deauthDurationSeconds, el.startDeauthBtn,
        el.startCaptureBtn,
        el.startPmkidBtn,
        el.startEvilTwinBtn,
        el.scanClientsBtn
    ];

    const attackInProgressControls = [
        el.scanBtn, el.applyChannelBtn, el.startDeauthBtn,
        el.startCaptureBtn, el.startEvilTwinBtn, el.startPmkidBtn,
        el.startBeaconBtn, el.beaconMode, el.beaconSsid, el.beaconAmount, el.beaconDuration,
        el.resetDeviceBtn, elAuto.btn // Disable reset and Auto Hunt during attack
    ];

    let statusInterval = null;
    let wasClientScanning = false;
    let isClientScanTimerActive = false;
    let isRouterActive = false;

    // --- Router Functions ---
    let routerConnectTimeout = null;

    async function handleRouterConnect() {
        const currentStatus = el.routerStatusText.textContent.toLowerCase();

        if (currentStatus === 'connected' || currentStatus === 'connecting') {
             // Disconnect action
             el.routerConnectBtn.disabled = true;
             el.routerConnectBtn.innerHTML = '<span class="spinner"></span>Disconnecting...';
             await apiRequest('/api/router/disconnect', 'POST');
             if (routerConnectTimeout) clearTimeout(routerConnectTimeout);
        } else {
             // Connect action
             const ssid = el.targetSSID.textContent;
             if (!ssid || ssid === 'No target selected') {
                 alert('Please select a target network first.');
                 return;
             }

             // Check if password is required (if visible)
             let pass = "";
             if (el.routerPassword.style.display !== 'none') {
                 pass = el.routerPassword.value;
                 if (!pass) {
                     alert('Please enter a password.');
                     return;
                 }
                 // Save password for this SSID
                 savePasswordForSSID(ssid, pass);
             }

             el.routerConnectBtn.disabled = true;
             el.routerConnectBtn.innerHTML = '<span class="spinner"></span>Connecting...';

             // Set a safety timeout (30s) in case status never updates
             if (routerConnectTimeout) clearTimeout(routerConnectTimeout);
             routerConnectTimeout = setTimeout(() => {
                 if (el.routerStatusText.textContent === 'connecting') {
                     el.routerStatusText.textContent = 'timeout';
                     el.routerConnectBtn.disabled = false;
                     el.routerConnectBtn.textContent = 'Connect';
                     if (el.routerPassword.style.display !== 'none') {
                        el.routerPassword.disabled = false;
                     }
                 }
             }, 30000);

             await apiRequest('/api/router/connect', 'POST', { ssid: ssid, password: pass });
        }
    }

    async function pollRouterStatus() {
        const data = await apiRequest('/api/router/status');
        if (data && data.status) {
            const status = data.status; // 'idle', 'connecting', 'connected', 'failed'

            // If we got a real status update, clear the timeout
            if (status !== 'connecting' && routerConnectTimeout) {
                clearTimeout(routerConnectTimeout);
                routerConnectTimeout = null;
            }

            // Don't overwrite the 'timeout' local state unless backend is no longer 'connecting'
            if (el.routerStatusText.textContent === 'timeout' && status === 'connecting') {
                return;
            }

            el.routerStatusText.textContent = status;

            isRouterActive = (status === 'connected' || status === 'connecting');

            // Update Button State
            if (status === 'connected') {
                el.routerConnectBtn.textContent = 'Disconnect';
                el.routerConnectBtn.disabled = false;
                el.routerPassword.disabled = true;
            } else if (status === 'connecting') {
                el.routerConnectBtn.innerHTML = '<span class="spinner"></span>Connecting';
                el.routerConnectBtn.disabled = true;
                el.routerPassword.disabled = true;
            } else {
                // idle or failed
                el.routerConnectBtn.textContent = 'Connect';
                const hasTarget = (el.targetSSID.textContent !== 'No target selected');
                el.routerConnectBtn.disabled = !hasTarget;
                // Only enable password field if it is supposed to be visible
                if (el.routerPassword.style.display !== 'none') {
                    el.routerPassword.disabled = !hasTarget;
                }
            }
        }
    }

    // --- Auto Hunt Logic ---

    elAuto.btn.addEventListener('click', async () => {
        const pmkidTime = parseInt(elAuto.pmkid.value) || 5;
        const handshakeTime = parseInt(elAuto.handshake.value) || 10;

        // 1. Scan first to get network count
        elAuto.btn.innerHTML = '<span class="spinner"></span>Scanning...';
        elAuto.btn.disabled = true;

        const scanData = await apiRequest('/api/scan');

        if (!scanData || !scanData.success) {
            alert('Scan failed. Cannot calculate duration.');
            elAuto.btn.textContent = 'Start';
            elAuto.btn.disabled = false;
            return;
        }

        const netCount = scanData.networks.length;
        if (netCount === 0) {
            alert('No networks found to attack.');
            elAuto.btn.textContent = 'Start';
            elAuto.btn.disabled = false;
            return;
        }

        // 2. Calculate Estimate
        const totalSeconds = netCount * (pmkidTime + handshakeTime);
        const mins = Math.floor(totalSeconds / 60);
        const secs = totalSeconds % 60;

        // 3. Confirm
        if (confirm(`Found ${netCount} networks.\n\nEstimated Max Duration: ~${mins}m ${secs}s\n\nAuto-Hunt will stop the AP and you will be DISCONNECTED.\n\nContinue?`)) {
            await apiRequest('/api/attack/auto/start', 'POST', {
                pmkid_time: pmkidTime,
                handshake_time: handshakeTime
            });
            el.statusBar.textContent = 'Status: Auto-Hunt started. You have been disconnected.';
            // Do NOT clear interval, keep polling so we recover when AP returns
            // if (statusInterval) clearInterval(statusInterval);
        } else {
            elAuto.btn.textContent = 'Start';
            elAuto.btn.disabled = false;
        }
    });

    // Local Timer State
    let lastKnownState = 'IDLE';

    async function apiRequest(endpoint, method = 'GET', body = null) {
        const options = { method };
        if (body) {
            options.headers = { 'Content-Type': 'application/json' };
            options.body = JSON.stringify(body);
        }
        try {
            const response = await fetch(endpoint, options);
            if (!response.ok) {
                console.error(`API request failed: ${response.status} ${response.statusText}`);
                return null;
            }
            const contentType = response.headers.get("content-type");
            if (contentType && contentType.includes("application/json")) {
                return response.json();
            }
            return response.text();
        } catch (error) {
            console.error('Fetch error:', error);
            return null;
        }
    }

    function renderNetworkList(networks) {
        if (!networks) return;
        networks.sort((a, b) => b.rssi - a.rssi);

        // Simple change detection to prevent flickering
        const currentData = JSON.stringify(networks);
        if (el.networkList.dataset.lastData === currentData) return;
        el.networkList.dataset.lastData = currentData;

        el.networkList.innerHTML = '';
        if (networks.length === 0) {
            el.networkList.innerHTML = '<div>No networks found.</div>';
            return;
        }
        networks.forEach(net => {
            const netDiv = document.createElement('div');
            netDiv.className = 'network-item';
            // Determine security icon/text
            let sec = "Open";
            if (net.auth > 0) sec = "Secured";

            netDiv.innerHTML = `<span>${net.ssid || '(Hidden)'} (${net.rssi} dBm) [Ch: ${net.channel}]</span><span>${sec}</span>`;
            // Pass authmode to handler
            netDiv.onclick = (event) => handleSelectNetwork(net, event.currentTarget);
            el.networkList.appendChild(netDiv);
        });
    }

    function renderClientList(clients) {
        const currentData = JSON.stringify(clients);
        if (el.clientList.dataset.lastData === currentData) return;
        el.clientList.dataset.lastData = currentData;

        el.clientList.innerHTML = '';
        if (!clients || clients.length === 0) {
            el.clientList.innerHTML = '<div class="client-item" style="justify-content: center;">No clients found.</div>';
            return;
        }
        clients.forEach(mac => {
            const clientDiv = document.createElement('div');
            clientDiv.className = 'client-item';
            clientDiv.textContent = mac;
            el.clientList.appendChild(clientDiv);
        });
    }

    function renderFileList(files) {
        if (!files) return;
        const currentData = JSON.stringify(files);
        if (el.fileList.dataset.lastData === currentData) return;
        el.fileList.dataset.lastData = currentData;

        el.fileList.innerHTML = '';
        if (files.length === 0) {
            el.fileList.innerHTML = '<div>No captured files.</div>';
            return;
        }
        files.forEach(file => {
            const fileDiv = document.createElement('div');
            fileDiv.className = 'file-item';

            // Generate convert button only for .pcap files
            let convertBtn = '';
            if (file.filename.endsWith('.pcap')) {
                convertBtn = `<button class="btn btn-sm convert-btn" data-filename="${file.filename}">to hccapx</button>`;
            }

            fileDiv.innerHTML = `
                <a class="file-name" href="/api/download?file=${encodeURIComponent(file.filename)}" download>${file.filename}</a>
                <span style="display:flex; align-items:center;">
                    ${convertBtn}
                    <span style="margin: 0 10px;">(${(file.size / 1024).toFixed(2)} KB)</span>
                    <button class="delete-btn" data-filename="${file.filename}">✖</button>
                </span>
            `;
            el.fileList.appendChild(fileDiv);
        });
    }

    function updateUIState(state) {
        if (!state) return;
        const isIdle = state.state === 'IDLE';
        const isDeauthing = state.state === 'DEAUTH_CONTINUOUS';
        const isCapturing = state.state === 'CAPTURE_CREDENTIALS';
        const isBeaconing = state.state === 'BEACON_FLOOD';
        const isPmkid = state.state === 'PMKID_CAPTURE';
        const isEvilTwin = state.state === 'EVIL_TWIN';
        const isClientScan = state.state === 'CLIENT_SCAN';

        lastKnownState = state.state;

        // Sync Client Scan UI if page refreshed during scan
        if (isClientScan && !isClientScanTimerActive) {
            isClientScanTimerActive = true;
            wasClientScanning = true;
            el.scanClientsBtn.innerHTML = '<span class="spinner"></span>Scanning...';
            el.scanClientsBtn.disabled = true;
        }

        if (!isClientScanTimerActive) {
            el.scanClientsBtn.disabled = !state.has_target || !isIdle || isRouterActive;
            // Restore button text if not scanning
            if (!isClientScan) el.scanClientsBtn.textContent = 'Scan Clients';
        }

        attackInProgressControls.forEach(elem => elem.disabled = !isIdle || isRouterActive);
        targetDependentControls.forEach(elem => elem.disabled = !state.has_target || !isIdle || isRouterActive);

        if (state.has_target) {
            el.targetSSID.textContent = state.target_ssid || '(Hidden)';
            el.targetBSSID.textContent = `(${state.target_bssid})`;
            el.targetChannel.textContent = state.target_channel || 'N/A';
        } else {
            el.targetSSID.textContent = 'No target selected';
            el.targetBSSID.textContent = '';
            el.targetChannel.textContent = 'N/A';
        }

        el.stopDeauthBtn.classList.toggle('hidden', !isDeauthing);
        el.stopCaptureBtn.classList.toggle('hidden', !isCapturing);
        el.stopPmkidBtn.classList.toggle('hidden', !isPmkid);
        el.stopBeaconBtn.classList.toggle('hidden', !isBeaconing);

        el.startDeauthBtn.classList.toggle('hidden', isDeauthing);
        el.startCaptureBtn.classList.toggle('hidden', isCapturing);
        el.startPmkidBtn.classList.toggle('hidden', isPmkid);
        el.startBeaconBtn.classList.toggle('hidden', isBeaconing);
        el.startEvilTwinBtn.classList.toggle('hidden', isEvilTwin);
        el.stopEvilTwinBtn.classList.toggle('hidden', !isEvilTwin);

        let statusText = `Status: ${state.state.replace(/_/g, ' ')}`;
        el.statusBar.textContent = statusText;
    }

    function updateCaptureInputs() {
        // Placeholder
    }

    // --- LocalStorage Helpers ---
    function getSavedPassword(ssid) {
        return localStorage.getItem('wifi_pass_' + ssid);
    }

    function savePasswordForSSID(ssid, pass) {
        localStorage.setItem('wifi_pass_' + ssid, pass);
    }

    async function handleScan() {
        el.scanBtn.innerHTML = '<span class="spinner"></span>Scanning...';
        el.scanBtn.disabled = true;
        const data = await apiRequest('/api/scan');
        el.scanBtn.innerHTML = 'Scan Networks';
        if (data && data.success) renderNetworkList(data.networks);
        el.scanBtn.disabled = false;
    }

    async function handleSelectNetwork(net, targetElement) {
        const response = await apiRequest('/api/target', 'POST', { ssid: net.ssid, bssid: net.bssid });
        if (response && response.success) {
            el.channelSelect.value = net.channel;
            document.querySelectorAll('.network-item').forEach(item => item.classList.remove('selected'));
            targetElement.classList.add('selected');
            el.clientList.innerHTML = '';

            // Handle Password Field Visibility
            if (net.auth === 0) { // OPEN
                el.routerPassword.style.display = 'none';
                el.routerPassword.value = '';
                el.routerPassword.disabled = true;
            } else {
                el.routerPassword.style.display = 'block';
                el.routerPassword.disabled = false;
                // Pre-fill password if saved
                const saved = getSavedPassword(net.ssid);
                if (saved) {
                    el.routerPassword.value = saved;
                } else {
                    el.routerPassword.value = '';
                }
            }

            pollStatus();
        }
    }

    async function handleApplyChannel() {
        const channel = parseInt(el.channelSelect.value, 10);
        await apiRequest('/api/wifi/set-channel', 'POST', { channel });
        pollApInfo();
    }

    async function handleReset() {
        if (confirm("DANGER: This will delete all captured files, saved credentials, and reset configuration (NVS).\n\nThe device will need to be reconfigured.\n\nAre you sure?")) {
            el.resetDeviceBtn.disabled = true;
            el.resetDeviceBtn.textContent = "Resetting...";
            await apiRequest('/api/reset', 'POST');

            // Clear browser saved passwords to prevent conflicts
            localStorage.clear();

            alert("Reset complete. Please refresh the page or power cycle the device if needed.");
            el.resetDeviceBtn.textContent = "Reset Data";
            el.resetDeviceBtn.disabled = false;
            handleRefreshFiles();
        }
    }

    async function syncBrowserTime() {
        const timestamp = Math.floor(Date.now() / 1000);
        await apiRequest('/api/set-time', 'POST', { timestamp: timestamp });
    }

    async function handleFileActions(event) {
        const filename = event.target.dataset.filename;
        if (event.target.classList.contains('delete-btn')) {
            if (confirm(`Are you sure you want to delete ${filename}?`)) {
                await apiRequest('/api/delete', 'POST', { name: filename });
                handleRefreshFiles();
            }
        }
        // Handle Conversion
        else if (event.target.classList.contains('convert-btn')) {
            const originalText = event.target.textContent;
            event.target.innerHTML = '⏳'; // Loading icon
            event.target.disabled = true;
            const data = await apiRequest('/api/convert', 'POST', { name: filename });
            if (data && data.success) {
                alert(`Success! Created file: ${data.new_file}`);
                handleRefreshFiles(); // Refresh list to show new file
            } else {
                alert('Conversion failed. No valid handshake found in PCAP?');
            }
            event.target.innerHTML = originalText;
            event.target.disabled = false;
        }
    }

    async function handleScanClients() {
        if (isClientScanTimerActive) return;

        el.clientList.innerHTML = '<div class="client-item" style="justify-content: center;"><span class="spinner"></span>Scanning...</div>';

        // 15s Total
        startCountdown(el.scanClientsBtn, "Scanning", 15, (val) => {
            isClientScanTimerActive = val;
            // When timer finishes (val becomes false), fetch results
            if (val === false) {
                handleGetClientScanResults();
            }
        });
        await apiRequest('/api/scan-clients/start');
    }

    async function handleGetClientScanResults() {
        const data = await apiRequest('/api/scan-clients/results');
        if (data && data.success) {
            renderClientList(data.clients);
        } else {
            renderClientList([]);
        }
    }

    async function pollStatus() {
        const data = await apiRequest('/api/status');
        if (data) {
            if (data.state === 'CLIENT_SCAN') {
                wasClientScanning = true;
            }
            if (wasClientScanning && data.state === 'IDLE') {
                wasClientScanning = false;
                // Double check to ensure we got results if backend finished early
                if(!isClientScanTimerActive) handleGetClientScanResults();
            }
            updateUIState(data);
        }
    }

    async function pollApInfo() {
        const data = await apiRequest('/api/ap-info');
        if (data) {
            el.apName.textContent = data.ssid;
            el.apMac.textContent = data.mac;
            el.apChannel.textContent = data.channel;
        }
    }

    // --- WebSocket Logic ---
    let ws = null;

    function connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

        ws.onopen = function() {
            console.log("WebSocket Connected");
            el.statusBar.textContent = "Status: Connected (WebSocket)";
        };

        ws.onmessage = function(event) {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'status') {
                    updateUIState(msg.data);
                } else if (msg.type === 'log') {
                    // Optional: Add a log area if UI supports it
                    console.log("Server Log:", msg.data);
                } else if (msg.type === 'scan_result') {
                     // Reload scan results if open
                     handleRefreshFiles();
                }
            } catch (e) {
                console.error("WS Parse Error", e);
            }
        };

        ws.onclose = function() {
            console.log("WebSocket Closed, retrying in 2s...");
            setTimeout(connectWebSocket, 2000);
        };

        ws.onerror = function(err) {
            console.error("WebSocket Error", err);
        };
    }

    function startPolling() {
        if (statusInterval) clearInterval(statusInterval);

        // Connect WebSocket
        connectWebSocket();

        pollApInfo();
        pollStatus();
        pollRouterStatus(); // Initial check

        // Keep polling as backup/heartbeat (every 5s instead of 2s)
        statusInterval = setInterval(() => {
            pollStatus();
            pollRouterStatus();
            pollApInfo();
        }, 5000);
    }

    async function handleRefreshFiles() {
        const data = await apiRequest('/api/files');
        if (data && data.success) renderFileList(data.files);
    }

    // --- Event Listeners ---
    el.routerConnectBtn.addEventListener('click', handleRouterConnect);
    el.scanBtn.addEventListener('click', handleScan);
    el.applyChannelBtn.addEventListener('click', handleApplyChannel);
    el.refreshFilesBtn.addEventListener('click', handleRefreshFiles);
    el.resetDeviceBtn.addEventListener('click', handleReset);
    el.fileList.addEventListener('click', handleFileActions);
    el.scanClientsBtn.addEventListener('click', handleScanClients);

    el.startEvilTwinBtn.addEventListener('click', async () => {
        if (confirm('Start Evil Twin attack?\n\nThe root page will now serve the captive portal. You can always access this panel at /admin')) {
            await apiRequest('/api/attack/eviltwin/start', 'POST');
            el.statusBar.textContent = 'Status: EVIL TWIN started.';
        }
    });

    el.stopEvilTwinBtn.addEventListener('click', async () => {
        el.stopEvilTwinBtn.innerHTML = '<span class="spinner"></span>Stopping...';
        await apiRequest('/api/attack/eviltwin/stop', 'POST');
        el.statusBar.textContent = 'Status: Stopping Evil Twin...';
    });

    // --- Beacon Flood Listeners ---
    el.beaconMode.addEventListener('change', () => {
        if (el.beaconMode.value == "0") { // Custom
            el.beaconSsid.style.display = 'inline-block';
        } else {
            el.beaconSsid.style.display = 'none';
        }
    });

    el.startBeaconBtn.addEventListener('click', async () => {
        const params = {
            mode: parseInt(el.beaconMode.value, 10),
            ssid: el.beaconSsid.value,
            amount: parseInt(el.beaconAmount.value, 10),
            duration: 0
        };
        await apiRequest('/api/attack/beacon/start', 'POST', params);
        pollStatus();
    });

    el.stopBeaconBtn.addEventListener('click', async () => {
        await apiRequest('/api/attack/beacon/stop', 'POST');
        pollStatus();
    });

    el.startDeauthBtn.addEventListener('click', async () => {
        await apiRequest('/api/deauth/start', 'POST', { duration: 0 });
        pollStatus();
    });

    el.stopDeauthBtn.addEventListener('click', async () => {
        await apiRequest('/api/deauth/stop', 'POST');
        pollStatus();
    });

    el.startCaptureBtn.addEventListener('click', async () => {
        await apiRequest('/api/capture/start', 'POST', {});
        pollStatus();
     });

    el.stopCaptureBtn.addEventListener('click', async () => {
        await apiRequest('/api/capture/stop', 'POST');
        pollStatus();
    });

    el.startPmkidBtn.addEventListener('click', async () => {
        el.statusBar.textContent = 'Status: PMKID Capture started...';
        await apiRequest('/api/pmkid/start', 'POST');
        pollStatus();
    });

    el.stopPmkidBtn.addEventListener('click', async () => {
        await apiRequest('/api/pmkid/stop', 'POST');
        pollStatus();
    });

    // --- Initial Load ---
    syncBrowserTime();
    handleRefreshFiles();
    startPolling();
    el.beaconMode.dispatchEvent(new Event('change'));
});
