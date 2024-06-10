
const localVideo = document.getElementById('localVideo');
const remoteVideo = document.getElementById('remoteVideo');
const chat = document.getElementById('chat');
const chatInput = document.getElementById('chatInput');
const loginDiv = document.getElementById('login');
const registerDiv = document.getElementById('register');
const videoChatDiv = document.getElementById('videoChat');
const loginUsername = document.getElementById('loginUsername');
const loginPassword = document.getElementById('loginPassword');
const registerUsername = document.getElementById('registerUsername');
const registerPassword = document.getElementById('registerPassword');
const loginButton = document.getElementById('loginButton');
const registerButton = document.getElementById('registerButton');
const showRegister = document.getElementById('showRegister');
const showLogin = document.getElementById('showLogin');
const startVideoButton = document.getElementById('startVideoButton');
const endVideoButton = document.getElementById('endVideoButton');

let accessToken;
let localStream;
let peerConnection;
let socket;
let username;

const config = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' }
    ]
};

showRegister.addEventListener('click', () => {
    loginDiv.style.display = 'none';
    registerDiv.style.display = 'block';
});

showLogin.addEventListener('click', () => {
    registerDiv.style.display = 'none';
    loginDiv.style.display = 'block';
});

registerButton.addEventListener('click', async () => {
    const username = registerUsername.value;
    const password = registerPassword.value;

    const response = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });

    if (response.ok) {
        alert('Registration successful');
        registerDiv.style.display = 'none';
        loginDiv.style.display = 'block';
    } else {
        alert('Registration failed');
    }
});

loginButton.addEventListener('click', async () => {
    username = loginUsername.value;
    const password = loginPassword.value;

    const response = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });

    if (response.ok) {
        const data = await response.json();
        accessToken = data.accessToken;
        videoChatDiv.style.display = 'block';
        loginDiv.style.display = 'none';
        initializeSocket();
    } else {
        alert('Login failed');
    }
});

async function refreshAccessToken() {
    const response = await fetch('/token', {
        method: 'POST',
        credentials: 'include'
    });

    if (response.ok) {
        const data = await response.json();
        accessToken = data.accessToken;
    } else {
        alert('Session expired. Please log in again.');
        loginDiv.style.display = 'block';
        videoChatDiv.style.display = 'none';
    }
}

function initializeSocket() {
    socket = io({
        query: { token: accessToken }
    });

    socket.on('connect_error', async (err) => {
        if (err.message === 'Authentication error') {
            await refreshAccessToken();
            socket.io.opts.query.token = accessToken;
            socket.connect();
        }
    });

    socket.on('joined', () => {
        createPeerConnection();
        if (localStream) {
            localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
        }
    });

    socket.on('offer', async (offer) => {
        if (!peerConnection) createPeerConnection();
        await peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
        const answer = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(answer);
        socket.emit('answer', answer);
    });

    socket.on('answer', async (answer) => {
        await peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
    });

    socket.on('ice-candidate', async (candidate) => {
        try {
            await peerConnection.addIceCandidate(candidate);
        } catch (e) {
            console.error('Error adding received ice candidate', e);
        }
    });

    socket.on('chat-message', ({ username, message, timestamp }) => {
        displayMessage({ username, message, timestamp });
    });

    socket.on('start-video', () => {
        if (!localStream) startVideoButton.click();
    });

    socket.on('end-video', () => {
        if (localStream) endVideoButton.click();
    });

    startVideoButton.addEventListener('click', () => {
        startVideoButton.classList.add('hidden');
        endVideoButton.classList.remove('hidden');

        navigator.mediaDevices.getUserMedia({ video: true, audio: true })
            .then(stream => {
                localVideo.srcObject = stream;
                localStream = stream;
                socket.emit('join', 'room1');
            })
            .catch(error => console.error('Error accessing media devices.', error));
    });

    endVideoButton.addEventListener('click', () => {
        startVideoButton.classList.remove('hidden');
        endVideoButton.classList.add('hidden');

        if (localStream) {
            localStream.getTracks().forEach(track => track.stop());
            localStream = null;
        }

        localVideo.srcObject = null;
        remoteVideo.srcObject = null;

        socket.emit('end-video');
    });

    chatInput.addEventListener('keypress', event => {
        if (event.key === 'Enter') {
            const message = chatInput.value;
            const timestamp = new Date().toLocaleTimeString();
            socket.emit('chat-message', { username, message, timestamp });
            chatInput.value = '';
            displayMessage({ username: 'You', message, timestamp });
        }
    });
}

function displayMessage({ username, message, timestamp }) {
    const messageElement = document.createElement('div');
    messageElement.textContent = `${timestamp} ${username}: ${message}`;
    chat.appendChild(messageElement);
    chat.scrollTop = chat.scrollHeight;
}

function createPeerConnection() {
    peerConnection = new RTCPeerConnection(config);

    peerConnection.onicecandidate = ({ candidate }) => {
        if (candidate) {
            socket.emit('ice-candidate', candidate);
        }
    };

    peerConnection.ontrack = (event) => {
        remoteVideo.srcObject = event.streams[0];
    };

    peerConnection.onnegotiationneeded = async () => {
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);
        socket.emit('offer', offer);
    };
}

