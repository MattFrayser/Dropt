//==============
// Browser
//==============
const BROWSER_PROFILES = [
    {
        id: 'chromium',
        label: 'Modern Chromium',
        check: () => 'showSaveFilePicker' in window,
        config: {
            strategy: 'FILESYSTEM',
            maxSize: Infinity
        }
    },
    {
        id: 'ios',
        label: 'iOS Safari',
        check: (ua) => /iPad|iPhone|iPod/.test(ua) || (ua.includes("Mac") && navigator.maxTouchPoints > 1),
        config: {
            strategy: 'BLOB',
            maxSize: 500 * 1024 * 1024 // 500 MB - safe limit for blob memory
        }
    },
    {
        id: 'safari_desktop',
        label: 'Safari Desktop',
        check: (ua) => /^((?!chrome|android).)*safari/i.test(ua),
        config: {
            strategy: 'BLOB',
            maxSize: 500 * 1024 * 1024 // 500 MB - safe limit for blob memory
        }
    },
    {
        id: 'firefox',
        label: 'Firefox',
        check: (ua) => /Firefox/i.test(ua),
        config: {
            strategy: 'BLOB',
            maxSize: 500 * 1024 * 1024 // 500 MB - safe limit for blob memory
        }
    },
    {
        id: 'generic',
        label: 'Unknown Browser',
        check: () => true, // Always matches
        config: {
            strategy: 'BLOB',
            maxSize: 500 * 1024 * 1024 // 500 MB - safe limit for blob memory
        }
    }
]

function getBrowserConfig() {
    const ua = navigator.userAgent

    const profile = BROWSER_PROFILES.find(p => p.check(ua))

    return {
        ...profile.config,
        profileId: profile.id
    }
}

function validateFileSize(fileSize, browserConfig) {
    return {
        isValid: fileSize <= browserConfig.maxSize,
        maxSize: browserConfig.maxSize,
        exceedsBy: Math.max(0, fileSize - browserConfig.maxSize)
    }
}

//==============
// KEY STORAGE
//==============
class KeyStore {
    constructor() {
        this.name = 'ad-keys'
        this.storeName = 'keys'
        this.db = null
    }

    async open() {
        if (this.db) return this.db

        return new Promise((resolve, reject) => {
            const req = indexedDB.open(this.name, 1)

            req.onerror = () => reject(request.error)

            req.onsuccess = () => {
                this.db = req.result
                resolve(this.db)
            }

            req.onupgradeneeded = (event) => {
                const db = event.target.result 
                if (!db.objectStoreNames.contains(this.storeName)) {
                    const store = db.createObjectStore(this.storeName, { keyPath: 'id' })
                    store.createIndex('timestamp', 'timestamp', { unique: false })
                }
            }
        })
    }

    async put(token, fileIndex, key, nonceBase64) {
        // purge old storage if memory usage is high 
        if (navigator.storage && navigator.storage.estimate) {
            const { usage, quota } = await navigator.storage.estimate()
            const percentageUsed = (usage / quota) * 100

            if (percentageUsed > 80) {
                await this.cleanup(25 * 60 * 1000)
            }

            if (percentageUsed > 95) {
                throw new Error('Storage quota exceeded. Please clear browser data.');

            }
        }

        const db = await this.open()
        return new Promise((resolve, reject) => {
            const tx = db.transaction([this.storeName], 'readwrite')
            const store = tx.objectStore(this.storeName)
            const req = store.put({
                id: `${token}_${fileIndex}`,
                token,
                fileIndex,
                key,  
                nonceBase64,
                timestamp: Date.now()
            })
            req.onsuccess = () => resolve()
            req.onerror = () => reject(req.error)
        })
    }

    async get(token, fileIndex) {
        const db = await this.open()
        return new Promise((resolve, reject) => {
            const tx = db.transaction([this.storeName], 'readwrite')
            const store = tx.objectStore(this.storeName)
            const req = store.get(`${token}_${fileIndex}`) 
            req.onsuccess = () => resolve(req.result || null)
            req.onerror = () => reject(req.error)
        })
    }

    async clear(token) {
        const db = await this.open()
        return new Promise((resolve, reject) => {
            const tx = db.transaction([this.storeName], 'readwrite')
            const store = tx.objectStore(this.storeName)
            const req = store.openCursor()
            req.onsuccess = (event) => {
                const cursor = event.target.result
                if (cursor) {
                    if (cursor.value.token === token) {
                        cursor.delete()
                    }
                    cursor.continue()
                } else {
                    resolve()
                }
            }
            req.onerror = () => reject(req.error)
        })
    }

    async cleanup(maxAge) {
        const db = await this.open()
        const cutoff = Date.now() - maxAge
        return new Promise((resolve, reject) => {
            const tx = db.transaction([this.storeName], 'readwrite')
            const store = tx.objectStore(this.storeName)
            const req = store.openCursor()
            req.onsuccess = (event) => {
                const cursor = event.target.result
                if (cursor) {
                    if (cursor.value.timestamp < cutoff) {
                        cursor.delete()
                    }
                    cursor.continue()
                } else {
                    resolve()
                }
            }
            req.onerror = () => reject(req.error)
        })
    }
}

const keyStore = new KeyStore();

//==============
// Global Cache
//=============
let cachedManifest = null
let cachedToken = null

// Download button
document.addEventListener('DOMContentLoaded', async () => {
    const downloadBtn = document.getElementById('downloadBtn');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', handleDownloadAction);
    }

    // Load manifest and display files
    try {
        cachedToken = getTokenFromUrl()

        const manifestResponse = await fetch('/send/manifest', {
            headers: authHeaders()
        })
        if (!manifestResponse.ok) {
            throw new Error(`Failed to fetch manifest: HTTP ${manifestResponse.status}`);

        }

        cachedManifest = await manifestResponse.json()
        setLockToken(cachedManifest.lockToken)

        // Extract and store keys
        const { key } = await getEncryptionKeyFromUrl(['decrypt'])

        for (const file of cachedManifest.files) {
            await keyStore.put(
                cachedToken,
                file.index,
                key,  //  (non-extractable)
                file.nonce  // Only store nonce, not raw key
            );
        }

        await keyStore.cleanup();
        displayFileList(cachedManifest.files)

    } catch (error) {
        console.error('Failed to load file list:', error)
    }
})

// List of files to download
function displayFileList(files) {
    const fileList = document.getElementById('fileList')
    if (!fileList || files.length === 0) return

    fileList.classList.add('show')
    const browserConfig = getBrowserConfig()

    files.forEach((file, index) => {
        const validation = validateFileSize(file.size, browserConfig)

        const item = createFileItem(file, index, {
            initialProgressText: !validation.isValid
                ? `Exceeds Browsers limit - will be skipped`
                : 'Ready to download',
            useSummaryWrapper: true
        })

        if (!validation.isValid) {
            item.classList.add('size-warning')
        }

        const progress = item.querySelector('.file-progress')
        if (progress) progress.classList.add('show')

        fileList.appendChild(item)
    })
}

//===========
// Download
//===========
let isTransferComplete = false;

async function handleDownloadAction() {
    const downloadBtn = document.getElementById('downloadBtn');
    
    if (isTransferComplete) {
        // ACTION: Finish and Close
        try {
            await fetch('/send/complete', { method: 'POST', headers: transferHeaders() });
            downloadBtn.textContent = 'Connection Closed';
            window.close(); // Try to close tab
        } catch (e) {
            console.error("Error closing session:", e);
        }
        return;
    }

    await startDownload();
}

async function downloadFile(token, fileEntry, fileItem, transferConfig) {
    const downloadManager = new DownloadManager(token, transferConfig);
    await downloadManager.download(fileEntry, fileItem);
}

async function startDownload() {
    if (!cachedManifest || !cachedToken) {
        alert('File list not loaded. Please refresh the page.');
        return;
    }

    const downloadBtn = document.getElementById('downloadBtn')
    const browserConfig = getBrowserConfig()

    // Show progress bars
    const fileList = document.getElementById('fileList')
    const fileItems = fileList.querySelectorAll('.file-item')
    fileItems.forEach(item => {
        const progress = item.querySelector('.file-progress')
        if (progress) progress.classList.add('show')
    })

    // Filter files into downloadable vs skipped
    const downloadableFiles = []
    const skippedFiles = []

    cachedManifest.files.forEach((file, index) => {
        const validation = validateFileSize(file.size, browserConfig)
        const fileItem = fileItems[index]

        if (validation.isValid) {
            downloadableFiles.push({ file, index, fileItem })
        } else {
            skippedFiles.push({ file, index, fileItem })
            // Mark as skipped immediately
            fileItem.classList.add('skipped')
            const progressText = fileItem.querySelector('.progress-text')
            if (progressText) {
                progressText.textContent = `Skipped - exceeds browsers limit`
            }
        }
    })

    downloadBtn.disabled = true
    let downloadedCount = 0
    let errorCount = 0

    const transferConfig = cachedManifest.config

    try {
        // ONLY download files that fit
        await runWithConcurrency(
            downloadableFiles,
            async ({ file, fileItem }) => {
                fileItem.classList.add('downloading')
                try {
                    await downloadFile(cachedToken, file, fileItem, transferConfig)
                    fileItem.classList.remove('downloading')
                    fileItem.classList.add('completed')
                    downloadedCount++
                } catch (error) {
                    fileItem.classList.remove('downloading')
                    fileItem.classList.add('error')
                    errorCount++
                    throw error
                }
            },
            transferConfig.concurrency
        )

        // Completion
        await retryWithExponentialBackoff(async () => {
            const skippedFilesPayload = skippedFiles.map(({ file }) => ({
                fileIndex: file.index,
                reason: 'browser_limit'
            }));

            const response = await fetch('/send/complete', {
                method: 'POST',
                headers: {
                    ...transferHeaders(),
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    skippedFiles: skippedFilesPayload
                })
            });
            if (!response.ok) {
                throw new Error(`Completion handshake failed: ${response.status}`);
            }
        }, 5, 'Finalizing Transfer');

        isTransferComplete = true;

        downloadBtn.textContent = 'Download Complete'

        await keyStore.clear(cachedToken);

    } catch(error) {
        console.error(error)
        alert(`Download failed: ${error.message}`)
        downloadBtn.textContent = 'Download Files'
        downloadBtn.disabled = false
    }
}
class DownloadManager {
    constructor(token, config) {
        this.token = token
        this.config = getBrowserConfig()
        this.transferConfig = config
    }

    async download(fileEntry, fileItem) {
        const keyData = await keyStore.get(this.token, fileEntry.index)
        if (!keyData) {
            throw new Error("Encryption key missing. Reload Page")
        }

        if (this.config.strategy === 'FILESYSTEM') {
            await this.downloadToFileSystem(fileEntry, keyData, fileItem)
        } else {
            await this.downloadToBlob(fileEntry, keyData, fileItem)
        }
    }

    async downloadToFileSystem(fileEntry, keyData, fileItem) {
        const fileHandle = await window.showSaveFilePicker({
            suggestedName: fileEntry.name
        })

        const writable = await fileHandle.createWritable()

        try {
            await this.streamDownload(
                fileEntry,
                keyData,
                fileItem,
                this.transferConfig.concurrency,
                async (data, _) => {
                    // enforcing order, so cannot stream direct
                    await writable.write(data)
                }
            )
        } finally {
            await writable.close()
        }
    }
    async downloadToBlob(fileEntry, keyData, fileItem) {
        const totalChunks = Math.ceil(fileEntry.size / this.transferConfig.chunk_size);
        const chunks = new Array(totalChunks)

        await this.streamDownload(
            fileEntry,
            keyData,
            fileItem,
            this.transferConfig.concurrency,
            async (data, index) => {
                chunks[index] = data
            }
        )

        this.saveBlob(new Blob(chunks), fileEntry.name)
    }

    async streamDownload(fileEntry, keyData, fileItem, concurrency, writeCallback) {
        const totalChunks = Math.ceil(fileEntry.size / this.transferConfig.chunk_size);

        // Buffer for out of order
        // Buffer will never have more than allowed max chunks
        const activeFetches = new Map()
        let nextFetch = 0
        let nextChunkNeeded = 0

        // Files arrive in correct order, but we still use concurrecy
        // nextFetch sends out up to max limit of chunks or room in buffer
        // activeFetches is hold results of those fetches.
        // Chunks are taken out of activeFetches in order.
        while (nextChunkNeeded < totalChunks) {

            // push data if available
            while (
                activeFetches.size < concurrency &&
                nextFetch < totalChunks
            ) {
                const chunkIndex = nextFetch++

                // send out fetches
                const fetchPromise = this.fetchAndDecrypt(
                    fileEntry,
                    chunkIndex,
                    keyData
                )

                activeFetches.set(chunkIndex, fetchPromise)
            }

            // wait for inorder to arrive
            try {
                // wait for needed chunk to arrive in map
                const chunkData = await activeFetches.get(nextChunkNeeded)

                await writeCallback(chunkData, nextChunkNeeded);

                activeFetches.delete(nextChunkNeeded)
                nextChunkNeeded++

                this.updateProgress(fileItem, nextChunkNeeded, totalChunks);

            } catch (err) {
                throw err
            }
        }
    }

    async fetchAndDecrypt(fileEntry, chunkIndex, keyData) {
        const response = await retryWithExponentialBackoff(async () => {
            const controller = new AbortController()
            const timeout = setTimeout(() => controller.abort(), 30000)

            try {
                const res = await fetch(
                    `/send/${fileEntry.index}/chunk/${chunkIndex}`,
                    { signal: controller.signal, headers: transferHeaders() }
                )

                clearTimeout(timeout)

                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`)
                }

                return res
            } catch (error) {
                clearTimeout(timeout)
                if (error.name === 'AbortError') {
                    throw new Error(`Request timeout after 30s`)
                }
                throw error
            }
        }, 3, `download chunk ${chunkIndex}`)

        const encrypted = await response.arrayBuffer()
        const nonceBase = urlSafeBase64ToUint8Array(keyData.nonceBase64)
        const nonce = generateNonce(nonceBase, chunkIndex)
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            keyData.key,
            encrypted
        )

        return new Uint8Array(decrypted)
    }

    saveBlob(blob, filename) {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        a.style.display = 'none'
        document.body.appendChild(a)
        a.click()

        setTimeout(() => {
            document.body.removeChild(a)
            URL.revokeObjectURL(url)
        }, 1000)
    }

    updateProgress(fileItem, completed, total) {
        updateFileProgress(fileItem, completed, total)
    }
}
