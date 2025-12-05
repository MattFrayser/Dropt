// Detect browser capabilities once on page load
// Chrome bases allows for File System Access
// which vastly increases max download size
const browserCaps = detectBrowserCapabilities()
function detectBrowserCapabilities() {
    return {
        // File System Access API (Chrome, Edge, Opera, Brave)
        hasFileSystemAccess: 'showSaveFilePicker' in window,
        
        // Device memory in GB (Chrome-only, returns 2, 4, 8, etc.)
        deviceMemoryGB: navigator.deviceMemory || null,
        
        // Estimated available memory in bytes
        estimatedMemory: navigator.deviceMemory 
            ? navigator.deviceMemory * 1024 * 1024 * 1024 
            : 4 * 1024 * 1024 * 1024, // Default 4GB
    }
}

//==============
// Global Cache
//=============
let cachedManifest = null
let cachedToken = null
let cachedClientId = null

// Download button
document.addEventListener('DOMContentLoaded', async () => {
    const downloadBtn = document.getElementById('downloadBtn');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', startDownload);
    }

    // Load manifest and display files
    try {
        cachedToken = window.location.pathname.split('/').pop()
        cachedClientId = getClientId()
        const manifestResponse = await fetch(`/send/${token}/manifest?clientId=${clientId}`)
        if (!manifestResponse.ok) {
            throw new Error(`Failed to fetch manifest: HTTP ${manifestResponse.status}`);
        }

        cachedManifest = await manifestResponse.json()
        displayFileList(manifest.files)

    } catch (error) {
        console.error('Failed to load file list:', error)
    }
})

// List of files to download
function displayFileList(files) {
    const fileList = document.getElementById('fileList')
    if (!fileList || files.length === 0) return

    fileList.classList.add('show')

    files.forEach((file, index) => {
        const item = createFileItem(file, index, {
            initialProgressText: 'Ready to download',
            useSummaryWrapper: true
        })

        const progress = item.querySelector('.file-progress')
        if (progress) progress.classList.add('show')

        fileList.appendChild(item)
    })
}

//===========
// Logic
//===========
async function startDownload() {
    if (!cachedManifest || !cachedToken) {
        alert('File list not loaded. Please refresh the page.');
        return;
    }

    // Show progress bars
    const fileList = document.getElementById('fileList')
    const fileItems = fileList.querySelectorAll('.file-item')
    fileItems.forEach(item => {
        const progress = item.querySelector('.file-progress')
        if (progress) progress.classList.add('show')
    })

    try {
        // Get session key form url
        const { key } = await getCredentialsFromUrl()
        const token = window.location.pathname.split('/').pop()

        // download files concurrently
        await runWithConcurrency(
            cachedManifest.files.map((file, index) => ({ file, index, fileItem: fileItems[index] })),
            async ({ file, fileItem }) => {
                fileItem.classList.add('downloading')
                try {
                    await downloadFile(token, file, key, fileItem)
                    fileItem.classList.remove('downloading')
                    fileItem.classList.add('completed')
                } catch (error) {
                    fileItem.classList.remove('downloading')
                    fileItem.classList.add('error')
                    throw error
                }
            },
            MAX_CONCURRENT_FILES
        )

        await fetch(`/send/${token}/complete`, { method: 'POST' })

        const downloadBtn = document.getElementById('downloadBtn')
        downloadBtn.textContent = 'Download Complete!'

    } catch(error) {
        console.error(error)
        alert(`Download failed: ${error.message}`)
    }
}

async function downloadFile(token, fileEntry, key, fileItem) {
    const nonceBase = urlSafeBase64ToUint8Array(fileEntry.nonce)
    const totalChunks = Math.ceil(fileEntry.size / CHUNK_SIZE)

    // Decrypt chunks into Transform stram for total file verification
    const decryptedStream = getDecryptedChunkStream(token, fileEntry, key, totalChunks, fileItem)
    const hashStream = new HashingTransformStream()
    
    if (browserCaps.hasFileSystemAccess && fileEntry.size > FILE_SYSTEM_API_THRESHOLD) {
        console.log(`Using File System API for ${fileEntry.name} (${formatFileSize(fileEntry.size)})`)
        await downloadViaFileSystemAPI(token, fileEntry, key, nonceBase, totalChunks, fileItem)
    } else {
        // Check if file might be too large for available memory
        if (fileEntry.size > browserCaps.estimatedMemory * 0.5) {
            await showMemoryWarning(fileEntry)
        }
        
        console.log(`Using in-memory download for ${fileEntry.name}`)
        await downloadViaBlob(token, fileEntry, key, nonceBase, totalChunks, fileItem)
    }

    // Verify the hash after all chunks arrive
    const computedHash = await hashStream.getComputedHash()
    await verifyHash(computedHash, fileEntry, token)
}

// Create the stream of decrypted chunks
function getDecryptedChunkStream(token, fileEntry, key, totalChunks, fileItem) {
    const nonceBase = urlSafeBase64ToUint8Array(fileEntry.nonce)
    let completedChunks = 0

    return new ReadableStream({
        async start(controller) {
            // Use concurrency helper to download chunks in parallel
            await runWithConcurrency(
                Array.from({ length: totalChunks }, (_, i) => i),
                async (chunkIndex) => {
                    try {
                        const encrypted = await downloadChunk(token, fileEntry.index, chunkIndex)
                        const nonce = generateNonce(nonceBase, chunkIndex)
                        
                        const decrypted = await window.crypto.subtle.decrypt(
                            { name: 'AES-GCM', iv: nonce },
                            key,
                            encrypted
                        )
                        
                        // Enqueue the decrypted chunk directly
                        controller.enqueue(new Uint8Array(decrypted))

                        completedChunks++
                        updateFileProgress(fileItem, completedChunks, totalChunks)
                    } catch (e) {
                        console.error(`Error processing chunk ${chunkIndex}:`, e)
                        // Error handling: Abort the stream on chunk failure
                        controller.error(e) 
                        throw e 
                    }
                },
                MAX_CONCURRENT_DOWNLOADS
            )
            controller.close()
        },
    })
}


// Transform Stream for memory-efficient hash calculation
class HashingTransformStream {
    constructor() {
        this.collectedChunks = []
        this.hashPromise = new Promise(resolve => this.resolveHash = resolve)
        
        // This is the standard TransformStream API implementation
        this.transformStream = new TransformStream({
            transform: (chunk, controller) => {
                // Collect chunks into a buffer for final hashing
                this.collectedChunks.push(chunk)
                // Pass the chunk down the pipe immediately for writing
                controller.enqueue(chunk) 
            },
            flush: () => {
                // The stream is done; now, compute the hash
                this._computeHash() 
            }
        })
    }

    get writable() {
        return this.transformStream.writable
    }

    get readable() {
        return this.transformStream.readable
    }
    
    // Method to be called by downloadFile to get the final hash
    async getComputedHash() {
        return this.hashPromise
    }
    
    async _computeHash() {
        // Create one Blob from all collected chunks (only Copy 2 is made)
        const fullFileBlob = new Blob(this.collectedChunks)
        
        // Read the Blob into an ArrayBuffer for crypto.subtle.digest()
        const arrayBuffer = await fullFileBlob.arrayBuffer()
        
        // Compute local hash
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', arrayBuffer)
        const hashArray = Array.from(new Uint8Array(hashBuffer))
        const computedHash = hashArray
            .map(b => b.toString(16).padStart(2,'0'))
            .join('')
            
        this.resolveHash(computedHash)
        // Free up memory from collected chunks after hashing
        this.collectedChunks = [] 
    }
}

async function downloadViaFileSystemAPI(token, fileEntry, key, nonceBase, totalChunks, fileItem) {
    // Prompt user to save file
    const fileHandle = await window.showSaveFilePicker({
        suggestedName: fileEntry.name,
    })
    
    const writable = await fileHandle.createWritable()
    
    try {
        // Pipe the verifiable stream directly to the disk writable
        await stream.pipeTo(writable)
        
        // Update UI
        const progressText = fileEntry.fileItem.querySelector('.progress-text')
        if (progressText) progressText.textContent = 'Download complete!'
        
    } catch (error) {
        await writable.abort()
        throw error
    }
}

// In-memory blob path (Firefox/Safari/small files)
async function downloadViaBlob(token, fileEntry, key, nonceBase, totalChunks, fileItem) {
// Collect the stream into a Response
    const response = new Response(stream)
    
    // Create a Blob from the Response stream
    const blob = await response.blob()

    // Trigger download (standard browser action)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = fileEntry.name
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
}

async function showMemoryWarning(fileEntry) {
    const fileSize = formatFileSize(fileEntry.size)
    const availableMem = formatFileSize(browserCaps.estimatedMemory)
    
    const message = `
        Warning: This file (${fileSize}) is very large and may use significant memory.

        Available memory: ~${availableMem}
        Your browser: ${browserCaps.hasFileSystemAccess ? 'Chrome/Edge' : 'Firefox/Safari'}

        ${browserCaps.hasFileSystemAccess ? '' : 'Recommendation: Use Chrome or Edge for files over 200MB for better memory efficiency.\n\n'}
        Continue download?
    `
    
    if (!confirm(message)) {
        throw new Error('Download cancelled by user')
    }
}


async function verifyHash(blob, fileEntry, token) {
    // Compute local hash
    const arrayBuffer = await blob.arrayBuffer()
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const computedHash = hashArray
        .map(b => b.toString(16).padStart(2,'0'))
        .join('')

    // Request hash from server
    const clientId = getClientId()
    const response = await fetch(`/send/${token}/${fileEntry.index}/hash?clientId=${clientId}`)
    if (!response.ok) {
        console.warn(`Could not verify ${fileEntry.name}: ${response.status}`)
        return // Skip if hash unavailable
    }

    const { sha256 } = await response.json()

    if (computedHash !== sha256) {
        throw new Error(`File integrity check failed! Expected ${sha256}, got ${computedHash}`)
    }

    console.log(`✓ Verified ${fileEntry.name}`)
}

async function downloadChunk(token, fileIndex, chunkIndex, maxRetries = 3) {
    const clientId = getClientId()

    return await retryWithExponentialBackoff(async () => {
        const response = await fetch(`/send/${token}/${fileIndex}/chunk/${chunkIndex}?clientId=${clientId}`)
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`)
        }
        return await response.arrayBuffer()
    }, maxRetries, `chunk ${chunkIndex}`)
}


