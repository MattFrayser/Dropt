async function startDownload() {
    try { 
        const { key, nonceBase } = await getCredentialsFromUrl();
        console.log("key imported")

        // get token from url 
        const token = window.location.pathname.split('/').pop()

        // Fetch encrypted stream from server 
        const response = await fetch(`/download/${token}/data`)
        if (!response.ok) {
            throw new Error(`Download failed: ${response.status}`)
        }
        console.log('Response status:', response.status);

        // Parse filename from headers
        let filename = 'download';
        const contentDisposition = response.headers.get('Content-Disposition');
        if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/);
            if (filenameMatch) {
                filename = filenameMatch[1];
            }
        }
        console.log('Using filename:', filename); 

        // Stream and Decrypt
        const reader = response.body.getReader()
        let buffer = new Uint8Array(0)
        let counter = 0
        const chunks = []

        while (true) {
            const { done, value } = await reader.read() // chunk from network
            if (done) break

            buffer = concatArrays(buffer, value)

            // parse and decrypt frames
            for (const { frame, remaining } of parseFrames(buffer)) {
                // GCM throws if tampered with
                const nonce = generateNonce(nonceBase, counter++)
                const decrypted = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: nonce },
                    key,
                    frame
                )

                chunks.push(new Uint8Array(decrypted)) // store in plain text
                buffer = remaining 
            }
        }
    
        // reassemble complete file
        const fileData = concatArrays(...chunks) 
        console.log('Download complete:', fileData.length, 'bytes')


        // Download
        const blob = new Blob([fileData])
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        a.click()
        URL.revokeObjectURL(url)

    } catch(error) {
        console.error(error)
        alert(`Download failed: ${error.message}`)
    }
}

