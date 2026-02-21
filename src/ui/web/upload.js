//=====
// UI
//=====
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const fileList = document.getElementById('fileList');
const uploadBtn = document.getElementById('uploadBtn');
let selectedFiles = [];
let transferInProgress = false;

window.addEventListener('beforeunload', (event) => {
    if (transferInProgress) {
        event.preventDefault()
        event.returnValue = ''
    }
})

// Click upload
uploadArea.addEventListener('click', () => fileInput.click())

// File selected
fileInput.addEventListener('change', (e) => {
    handleFiles(Array.from(e.target.files))
});

// Drag and drop
uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault()
    uploadArea.classList.add('dragover')
});

uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('dragover')
});

uploadArea.addEventListener('drop', (e) => {
    e.preventDefault()
    uploadArea.classList.remove('dragover')
    handleFiles(Array.from(e.dataTransfer.files))
});

// Handle multiple files
function handleFiles(files) {
    if (!files || files.length === 0) return

    // Add new files to existing selection
    selectedFiles = [...selectedFiles, ...files]

    updateFileList()
}

// Create summary element
function createSummary(fileCount, totalSize) {
    const summary = document.createElement('div')
    summary.className = 'file-list-summary'
    summary.textContent = `${fileCount} files selected • Total: ${formatFileSize(totalSize)}`
    return summary
}

// Update the file list UI
function updateFileList() {
    // Clear existing content
    fileList.innerHTML = ''

    if (selectedFiles.length === 0) {
        fileList.classList.remove('show')
        uploadBtn.classList.remove('show')
        return
    }

    fileList.classList.add('show')
    uploadBtn.classList.add('show')

    // Add each file
    selectedFiles.forEach((file, index) => {
        const fileItem = createFileItem(file, index, {
            showRemoveButton: true,
            onRemove: removeFile,
            initialProgressText: 'Waiting...'
        })
        fileList.appendChild(fileItem)
    })

    // Add summary if multiple files
    if (selectedFiles.length > 1) {
        const totalSize = selectedFiles.reduce((sum, file) => sum + file.size, 0)
        const summary = createSummary(selectedFiles.length, totalSize)
        fileList.appendChild(summary)
    }

    // Update button text
    uploadBtn.textContent = selectedFiles.length === 1 
        ? 'Upload File' 
        : `Upload ${selectedFiles.length} Files`
}

// Remove individual file
function removeFile(index) {
    selectedFiles.splice(index, 1)
    
    if (selectedFiles.length === 0) {
        fileInput.value = ''
    }
    
    updateFileList()
}

//===========
// LOGIC
//==========
async function sendManifest(files) {
    const manifest = {
        files: files.map(file => ({
            relative_path: file.webkitRelativePath || file.name,
            size: file.size
        }))
    };

    const response = await fetch('/receive/manifest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify(manifest)
    });

    if (!response.ok) {
        let errorMsg = 'Failed to send manifest';
        try {
            const errorData = await response.json();
            if (errorData.error && errorData.error.message) {
                errorMsg = errorData.error.message;
            }
        } catch (e) {
            // If parsing fails, use status text
            errorMsg = `Failed to send manifest: ${response.status} ${response.statusText}`;
        }
        throw new Error(errorMsg);
    }

    return await response.json();
}

function showError(msg) {
    const el = document.getElementById('errorMsg')
    if (el) el.textContent = msg
}

async function uploadFiles(selectedFiles) {
    if (selectedFiles.length === 0) return

    const uploadBtn = document.getElementById('uploadBtn')
    showError('')
    uploadBtn.disabled = true
    transferInProgress = true

    // Show progress bars for all files
    const fileItems = fileList.querySelectorAll('.file-item')
    fileItems.forEach(item => {
        const progress = item.querySelector('.file-progress')
        if (progress) progress.classList.add('show')
    })

    try {
        const { key } = await getEncryptionKeyFromUrl(['encrypt'])

        // Send manifest first so server knows total chunks
        const manifestResponse = await sendManifest(selectedFiles);
        setLockToken(manifestResponse.lockToken)
        const transferConfig = manifestResponse.config

        const skippedFiles = new Set(manifestResponse.skipped_files ?? []);

        // Mark skipped file items in the UI before uploading
        selectedFiles.forEach((file, index) => {
            if (skippedFiles.has(file.webkitRelativePath || file.name)) {
                const fileItem = fileItems[index];
                fileItem.classList.add('skipped');
                const progressText = fileItem.querySelector('.progress-text');
                if (progressText) progressText.textContent = 'Skipped (already exists)';
                const progress = fileItem.querySelector('.file-progress');
                if (progress) progress.classList.remove('show');
            }
        });

        // Build upload tasks preserving original selectedFiles indices so fileItem mapping stays correct
        const uploadTasks = selectedFiles
            .map((file, index) => ({ file, index, fileItem: fileItems[index] }))
            .filter(({ file }) => !skippedFiles.has(file.webkitRelativePath || file.name));

        await runWithConcurrency(
            uploadTasks,
            async ({ file, fileItem }) => {
                const relativePath = file.webkitRelativePath || file.name

                fileItem.classList.add('uploading')
                try {
                    await uploadFile(file, relativePath, key, fileItem, transferConfig)
                    fileItem.classList.remove('uploading')
                    fileItem.classList.add('completed')
                } catch (error) {
                    fileItem.classList.remove('uploading')
                    fileItem.classList.add('error')
                    throw error
                }
            },
            transferConfig.concurrency
        )

        await fetch('/receive/complete', { method: 'POST', headers: transferHeaders() })

        uploadBtn.textContent = 'Upload Complete!'

    } catch(error) {
        showError(error.message)
        uploadBtn.disabled = false
        uploadBtn.textContent = selectedFiles.length === 1 ? 'Retry Upload' : 'Retry Uploads'
    } finally {
        transferInProgress = false
    }
}

async function uploadFile(file, relativePath, key, fileItem, config) {
    // each file gets its own nonce
    const chunkSize = config.chunk_size
    const totalChunks = Math.ceil(file.size / chunkSize)

    const fileNonce = crypto.getRandomValues(new Uint8Array(8));

    // Track completed chunks for progress
    let completedChunks = 0

    // Helper function to prepare and upload a single chunk
    const prepareAndUploadChunk = async (chunkIndex) => {
        const start = chunkIndex * chunkSize
        const end = Math.min(start + chunkSize, file.size)
        const chunkBlob = file.slice(start, end)
        const chunkData = await chunkBlob.arrayBuffer()

        // Encrypt chunk
        const nonce = generateNonce(fileNonce, chunkIndex)
        const nonceBase64 = arrayBufferToBase64(fileNonce)
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            chunkData
        )

        // Create FormData with chunk and metadata
        const formData = new FormData()
        formData.append('chunk', new Blob([encrypted]))
        formData.append('relativePath', relativePath)
        formData.append('fileName', file.name)
        formData.append('chunkIndex', chunkIndex.toString())
        formData.append('nonce', nonceBase64)

        // Upload chunk
        await uploadChunk(formData, chunkIndex, relativePath)
        completedChunks++
        updateFileProgress(fileItem, completedChunks, totalChunks)
    }

    if (totalChunks > 0) {
        const chunkIndices = Array.from({ length: totalChunks }, (_, i) => i);
        await runWithConcurrency(
            chunkIndices,
            prepareAndUploadChunk,
            config.concurrency
        )
    }

    await finalizeFile(relativePath);

    const progressText = fileItem.querySelector('.progress-text')
    if (progressText) progressText.textContent = 'Upload complete!'
}

async function uploadChunk(formData, chunkIndex, relativePath) {
    await retryWithExponentialBackoff(async () => {
        await fetchWithTimeout('/receive/chunk', {
            method: 'POST',
            body: formData,
            headers: transferHeaders()
        })
    }, 3, `chunk ${chunkIndex}`)
}

async function finalizeFile(relativePath) {
    const formData = new FormData();
    formData.append('relativePath', relativePath);

    const response = await fetch('/receive/finalize', {
        method: 'POST',
        body: formData,
        headers: transferHeaders()
    });
    
    if (!response.ok) {
        throw new Error(`Failed to finalize ${relativePath}`);
    }
}

