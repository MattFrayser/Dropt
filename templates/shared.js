//==============
// Constants
//==============
const SERVER_CHUNK_SIZE = __CHUNK_SIZE__ // Run time injected from server

// All clients use the same chunk size (8MB) to match server expectations
const CHUNK_SIZE = SERVER_CHUNK_SIZE

const MAX_MEMORY = 100 * 1024 * 1024 // 100MB

const MAX_CONCURRENT_FILES = 4
const isHTTP2 = performance.getEntriesByType('navigation')[0]?.nextHopProtocol === 'h2';
const MAX_CONCURRENT_CHUNKS = isHTTP2 ? 8 : 4;
const FILE_SYSTEM_API_THRESHOLD = 100 * 1024 * 1024 // 100MB - use FileSystem API for files larger than this

//============
// URL Helpers
//============
function urlSafeBase64ToUint8Array(str) {
    // Convert URL-safe base64 to standard base64
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
    
    // Add padding if needed (Rust uses URL_SAFE_NO_PAD, so padding may be missing)
    // Base64 padding: length mod 4 determines padding
    const padLength = (4 - (base64.length % 4)) % 4
    base64 += '='.repeat(padLength)

    const binaryString = atob(base64)
    const bytes = new Uint8Array(binaryString.length)

    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i)
    }

    return bytes
}

async function getEncryptionKeyFromUrl(usages = ['encrypt', 'decrypt']) {
    const fragment = window.location.hash.substring(1) // remove #
    const params = new URLSearchParams(fragment)
    const keyBase64 = params.get('key')

    if (!keyBase64) {
        throw new Error('Missing encryption key')
    }

    // Clear URL fragment immediately after extraction to prevent it from persisting in browser history
    history.replaceState(null, document.title, location.pathname + location.search)

    // base64 -> string -> byte array
    const keyData = urlSafeBase64ToUint8Array(keyBase64);

    const key = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'AES-GCM' },
        false,
        usages
    )

    return { key }
}

function getTokenFromUrl() {
    return window.location.pathname.split('/').pop()
}

function arrayBufferToBase64(buffer) {
    // Convert Uint8Array to base64 string
    const bytes = new Uint8Array(buffer)
    let binary = ''
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i])
    }
    // Convert to URL-safe base64 (no padding) to match Rust's URL_SAFE_NO_PAD
    const base64 = btoa(binary)
        .replace(/\+/g, '-')  // Replace + with -
        .replace(/\//g, '_')  // Replace / with _
        .replace(/=+$/, '');  // Remove padding
    return base64
}

//===============
// CLIENT_ID
//==============
const CLIENT_ID_KEY = 'archdrop_client_id';

function getClientId() {
    let clientId = localStorage.getItem(CLIENT_ID_KEY);

    if (!clientId) {
        clientId = generateUuid();
        localStorage.setItem(CLIENT_ID_KEY, clientId);
    }
    return clientId;
}

//==============
// Crypto
//==============
// Construct nonce to match Rusts EncryptorBE32
// [8 byte base][4 byte counter]
function generateNonce(nonceBase64, counter) {
    const nonce = new Uint8Array(12)
    nonce.set(nonceBase64,  0) // first 8 bytes


    // last 5 bytes (4 + last flag)
    const view = new DataView(nonce.buffer)
    view.setUint32(8, counter, false) // false = BE32

    return nonce
}

function generateUuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0,
            v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

//=============
// UI
//=============

// Create file item element with optional remove button
function createFileItem(file, index, options = {}) {
    const {
        showRemoveButton = false,
        onRemove = null,
        initialProgressText = 'Waiting...',
        useSummaryWrapper = false
    } = options

    const item = document.createElement('div')
    item.className = 'file-item'
    if (index !== undefined) {
        item.dataset.fileIndex = index
    }

    // File icon
    const icon = document.createElement('div')
    icon.className = 'file-icon'
    icon.innerHTML = `
        <svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
            <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
            <polyline points="13 2 13 9 20 9"></polyline>
        </svg>
    `

    // File details container
    const details = document.createElement('div')
    details.className = 'file-details'

    // File name
    const name = document.createElement('div')
    name.className = 'file-name'
    name.textContent = file.name

    // File size
    const size = document.createElement('div')
    size.className = 'file-size'
    size.textContent = formatFileSize(file.size)

    // Progress bar
    const progress = document.createElement('div')
    progress.className = 'file-progress'
    progress.innerHTML = `
        <div class="progress-bar-container">
            <div class="progress-bar"></div>
        </div>
        <div class="progress-text">${initialProgressText}</div>
    `

    // Assemble details based on layout preference
    if (useSummaryWrapper) {
        const summary = document.createElement('div')
        summary.className = 'file-summary'
        summary.appendChild(name)
        summary.appendChild(size)
        details.appendChild(summary)
        details.appendChild(progress)
    } else {
        details.appendChild(name)
        details.appendChild(size)
        details.appendChild(progress)
    }

    // Assemble item
    item.appendChild(icon)
    item.appendChild(details)

    // Add remove button if requested
    if (showRemoveButton && onRemove) {
        const removeBtn = document.createElement('button')
        removeBtn.className = 'remove-file-btn'
        removeBtn.type = 'button'
        removeBtn.innerHTML = `
            <svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
        `
        removeBtn.addEventListener('click', () => onRemove(index))
        item.appendChild(removeBtn)
    }

    return item
}

// Update file progress UI
function updateFileProgress(fileItem, completedChunks, totalChunks) {
    const percent = Math.round((completedChunks / totalChunks) * 100)
    const progressBar = fileItem.querySelector('.progress-bar')
    const progressText = fileItem.querySelector('.progress-text')
    if (progressBar) progressBar.style.width = `${percent}%`
    if (progressText) progressText.textContent = `${completedChunks}/${totalChunks} chunks (${percent}%)`
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

//================
// Retry Helper
//================

// Retry an async function with exponential backoff
async function retryWithExponentialBackoff(asyncFn, maxRetries = 3, context = '') {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            return await asyncFn()
        } catch (e) {
            if (attempt === maxRetries - 1) {
                throw e
            }
            // Exponential backoff: 1s, 2s, 4s
            const delay = 1000 * Math.pow(2, attempt)
            await new Promise(r => setTimeout(r, delay))
            console.log(`Retrying ${context} (attempt ${attempt + 2}/${maxRetries})...`)
        }
    }
}

// Helper: Run async tasks with concurrency limit
async function runWithConcurrency(items, asyncFn, concurrency) {
    const results = new Array(items.length)
    let index = 0

    async function runner() {
        while (index < items.length) {
            const currentIndex = index++
            results[currentIndex] = await asyncFn(items[currentIndex])
        }
    }

    // Start 'concurrency' number of runners
    const runners = Array(Math.min(concurrency, items.length))
        .fill()
        .map(() => runner())

    await Promise.all(runners)
    return results
}
