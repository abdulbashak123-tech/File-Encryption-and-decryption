// DOM Elements
const encryptTab = document.getElementById('encryptTab');
const decryptTab = document.getElementById('decryptTab');
const encryptSection = document.getElementById('encryptSection');
const decryptSection = document.getElementById('decryptSection');
const fileToEncrypt = document.getElementById('fileToEncrypt');
const fileToDecrypt = document.getElementById('fileToDecrypt');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const encryptPassword = document.getElementById('encryptPassword');
const decryptPassword = document.getElementById('decryptPassword');
const toggleEncryptPassword = document.getElementById('toggleEncryptPassword');
const toggleDecryptPassword = document.getElementById('toggleDecryptPassword');
const selectedFile = document.getElementById('selectedFile');
const selectedEncryptedFile = document.getElementById('selectedEncryptedFile');

// Tab switching
encryptTab.addEventListener('click', () => {
    encryptTab.classList.add('active');
    decryptTab.classList.remove('active');
    encryptSection.classList.remove('hidden');
    decryptSection.classList.add('hidden');
});

decryptTab.addEventListener('click', () => {
    decryptTab.classList.add('active');
    encryptTab.classList.remove('active');
    decryptSection.classList.remove('hidden');
    encryptSection.classList.add('hidden');
});

// File selection handlers
fileToEncrypt.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        selectedFile.textContent = e.target.files[0].name;
    } else {
        selectedFile.textContent = 'No file selected';
    }
});

fileToDecrypt.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        selectedEncryptedFile.textContent = e.target.files[0].name;
    } else {
        selectedEncryptedFile.textContent = 'No file selected';
    }
});

// Toggle password visibility
toggleEncryptPassword.addEventListener('click', () => {
    const type = encryptPassword.type === 'password' ? 'text' : 'password';
    encryptPassword.type = type;
    toggleEncryptPassword.innerHTML = type === 'password' ? '<i class="far fa-eye"></i>' : '<i class="far fa-eye-slash"></i>';
});

toggleDecryptPassword.addEventListener('click', () => {
    const type = decryptPassword.type === 'password' ? 'text' : 'password';
    decryptPassword.type = type;
    toggleDecryptPassword.innerHTML = type === 'password' ? '<i class="far fa-eye"></i>' : '<i class="far fa-eye-slash"></i>';
});

// Encryption/Decryption functions
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );

    return await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptFile(file, password) {
    // Generate a random salt
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    
    // Derive key from password
    const key = await deriveKey(password, salt);
    
    // Generate a random IV
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    // Read the file as ArrayBuffer
    const fileBuffer = await file.arrayBuffer();
    
    // Encrypt the file
    const encryptedData = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        fileBuffer
    );
    
    // Combine salt + iv + encrypted data
    const result = new Uint8Array(salt.length + iv.length + encryptedData.byteLength);
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(new Uint8Array(encryptedData), salt.length + iv.length);
    
    return result;
}

async function decryptFile(encryptedFile, password) {
    // Read the encrypted file as ArrayBuffer
    const encryptedBuffer = await encryptedFile.arrayBuffer();
    const encryptedData = new Uint8Array(encryptedBuffer);
    
    // Extract salt (first 16 bytes), IV (next 12 bytes), and actual encrypted data
    const salt = encryptedData.slice(0, 16);
    const iv = encryptedData.slice(16, 28);
    const data = encryptedData.slice(28);
    
    try {
        // Derive key from password
        const key = await deriveKey(password, salt);
        
        // Decrypt the data
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            data
        );
        
        return new Uint8Array(decryptedData);
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error('Incorrect password or corrupted file');
    }
}

// Download helper function
function downloadFile(data, filename) {
    const blob = new Blob([data], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Event listeners for encrypt/decrypt buttons
encryptBtn.addEventListener('click', async () => {
    if (!fileToEncrypt.files.length) {
        alert('Please select a file to encrypt');
        return;
    }
    
    const password = encryptPassword.value;
    if (!password) {
        alert('Please enter an encryption password');
        return;
    }
    
    try {
        const file = fileToEncrypt.files[0];
        const originalBtnText = encryptBtn.innerHTML;
        encryptBtn.disabled = true;
        encryptBtn.innerHTML = '<span class="spinner"></span> Encrypting...';
        
        const encryptedData = await encryptFile(file, password);
        downloadFile(encryptedData, `${file.name}.enc`);
        
        // Reset form
        fileToEncrypt.value = '';
        selectedFile.textContent = 'No file selected';
        encryptPassword.value = '';
    } catch (error) {
        console.error('Encryption failed:', error);
        alert('Encryption failed: ' + error.message);
    } finally {
        encryptBtn.disabled = false;
        encryptBtn.innerHTML = originalBtnText;
    }
});

decryptBtn.addEventListener('click', async () => {
    if (!fileToDecrypt.files.length) {
        alert('Please select a file to decrypt');
        return;
    }
    
    const password = decryptPassword.value;
    if (!password) {
        alert('Please enter the decryption password');
        return;
    }
    
    try {
        const file = fileToDecrypt.files[0];
        const originalBtnText = decryptBtn.innerHTML;
        decryptBtn.disabled = true;
        decryptBtn.innerHTML = '<span class="spinner"></span> Decrypting...';
        
        const decryptedData = await decryptFile(file, password);
        
        // Get original filename (remove .enc extension if present)
        let originalFilename = file.name;
        if (originalFilename.endsWith('.enc')) {
            originalFilename = originalFilename.slice(0, -4);
        }
        
        downloadFile(decryptedData, `decrypted_${originalFilename}`);
        
        // Reset form
        fileToDecrypt.value = '';
        selectedEncryptedFile.textContent = 'No file selected';
        decryptPassword.value = '';
    } catch (error) {
        console.error('Decryption failed:', error);
        alert('Decryption failed: ' + (error.message || 'Incorrect password or corrupted file'));
    } finally {
        decryptBtn.disabled = false;
        decryptBtn.innerHTML = originalBtnText;
    }
});

// Add drag and drop functionality
const dropArea = document.querySelectorAll('.border-dashed');

dropArea.forEach(area => {
    area.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.stopPropagation();
        area.classList.add('drag-active');
    });
    
    area.addEventListener('dragleave', (e) => {
        e.preventDefault();
        e.stopPropagation();
        area.classList.remove('drag-active');
    });
    
    area.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        area.classList.remove('drag-active');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            const input = area.querySelector('input[type="file"]');
            input.files = files;
            
            // Trigger change event
            const event = new Event('change');
            input.dispatchEvent(event);
        }
    });
});

// Show initial tab
encryptTab.click();
