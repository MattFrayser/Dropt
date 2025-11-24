async function startDownload() {
    try { 
        const fragment = window.location.hash.substring(1) // remove #
        const params = new URLSearchParams(fragment)
        const keyBase64 = params.get('key')
        const nonceBase64 = params.get('nonce')

        if (!keyBase64 || !nonceBase64) {
            throw new Error('Missing encryption key')
        }

        // Clear url fragment immediatly after getti 
        // window.location.replace(window.location.href.split('#')[0])

        // base64 -> string -> byte array
        const keyData = urlSafeBase64ToUint8Array(keyBase64);
        const nonceData = urlSafeBase64ToUint8Array(nonceBase64);

        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        )

        console.log("key imported")

        // Fetch encrypted stream from server 
        const token = window.location.pathname.split('/').pop()
        const response = await fetch(`/download/${token}/data`)
        console.log('Response status:', response.status);
        console.log('Response headers:', Object.fromEntries(response.headers.entries()));

        // Parse filename from headers
        let filename = 'download';
        const contentDisposition = response.headers.get('Content-Disposition');
        console.log('Content-Disposition:', contentDisposition); 

        if (contentDisposition) {
            filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/);
            if (filenameMatch) {
                filename = filenameMatch[1];
            }
        }

        console.log('Using filename:', filename); 

        const reader = response.body.getReader()
        let buffer = new Uint8Array(0)
        let counter = 0
        const chunks = []

        while (true) {
            const { done, value } = await reader.read() // chunk from network
            if (done) break

            buffer = concatArrays(buffer, value)

            // parse chunks
            // recieving [4 byte length prefix][encrpted data]
            while (buffer.length >= 4) {
                // read prefix
                const lengthView = new DataView(buffer.buffer, buffer.byteOffset,  4)
                const chunkLength = lengthView.getUint32(0) // # encrpted bytes

                if (buffer.length < 4 + chunkLength) {
                    break // dont have full chunk yet
                }

                const encryptedChunk = buffer.slice(4, 4 + chunkLength)
                buffer = buffer.slice(4 + chunkLength) // remove chunk

                // decrypt chunk -> [7 bytes from QR][4 byte counter][1 byte flag]
                // GCM throws if tampered with
                const nonce = generateNonce(nonceData, counter++)
                const decrypted = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: nonce },
                    key,
                    encryptedChunk
                )

                chunks.push(new Uint8Array(decrypted)) // store in plain text
            }

        }
    
        // reassemble complete file
        const fileData = concatArrays(...chunks) 

        console.log('Final file size:', fileData.length, 'bytes')

        console.log('File contents (as text):', new TextDecoder().decode(fileData))

        // calc hash for verificaiton
        const hashBuffer = await crypto.subtle.digest('SHA-256', fileData)
        const hashArray = Array.from(new Uint8Array(hashBuffer))
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

        document.getElementById('file-hash').textContent = hashHex

        // Download
        const blob = new Blob([fileData])
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        a.click()

    } catch(error) {
        console.error(error)
    }
}

function urlSafeBase64ToUint8Array(str) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    str = str.replace(/=/g, '')

    const bytes = []
    let buffer = 0
    let bitsInBuffer = 0

    for (let i = 0; i < str.length; i++) {
        const value = chars.indexOf(str[i])
        if (value === -1) {
            throw new Error (`Invalid base64 character: ${str[i]}`)
        }

        buffer = (buffer << 6) | value
        bitsInBuffer += 6

        if (bitsInBuffer >= 8) {
            bytes.push((buffer >> (bitsInBuffer - 8)) & 0xFF)
            bitsInBuffer -= 8
        }
    }
    return new Uint8Array(bytes)
}

// Construct nonce to match Rusts EncryptorBE32
function generateNonce(nonceBase64, counter) {
    const nonce = new Uint8Array(12)
    nonce.set(nonceBase64,  0) // first 7 bytes


    // last 5 bytes
    const view = new DataView(nonce.buffer)
    view.setUint32(7, counter, false) // false = BE32

    return nonce
}

function concatArrays(...arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}
