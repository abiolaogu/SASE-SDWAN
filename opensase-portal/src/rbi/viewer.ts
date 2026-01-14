/**
 * OpenSASE RBI Client Viewer
 * 
 * Displays isolated browser content via WebRTC pixel streaming.
 */

export interface RbiConfig {
    apiBaseUrl: string;
    iceServers?: RTCIceServer[];
}

export interface RbiSession {
    id: string;
    targetUrl: string;
    isolationLevel: IsolationLevel;
    createdAt: string;
}

export type IsolationLevel = 'pixel_streaming' | 'dom_reconstruction' | 'read_only';

export interface InputEvent {
    type: 'mouseMove' | 'mouseDown' | 'mouseUp' | 'keyDown' | 'keyUp' | 'scroll';
    x?: number;
    y?: number;
    button?: number;
    key?: string;
    code?: string;
    deltaX?: number;
    deltaY?: number;
    modifiers?: {
        ctrl: boolean;
        shift: boolean;
        alt: boolean;
        meta: boolean;
    };
}

/**
 * RBI Viewer - Main client for Remote Browser Isolation
 */
export class RbiViewer {
    private sessionId: string | null = null;
    private peerConnection: RTCPeerConnection | null = null;
    private websocket: WebSocket | null = null;
    private videoElement: HTMLVideoElement;
    private inputHandler: InputHandler;
    private config: RbiConfig;
    private onStatusChange?: (status: string) => void;

    constructor(container: HTMLElement, config: RbiConfig) {
        this.config = config;

        // Create video element
        this.videoElement = document.createElement('video');
        this.videoElement.autoplay = true;
        this.videoElement.playsInline = true;
        this.videoElement.muted = false;
        this.videoElement.style.width = '100%';
        this.videoElement.style.height = '100%';
        this.videoElement.style.objectFit = 'contain';
        this.videoElement.style.backgroundColor = '#1a1a1a';
        container.appendChild(this.videoElement);

        // Initialize input handler
        this.inputHandler = new InputHandler(this.videoElement);
        this.inputHandler.onInput = (event) => this.sendInput(event);
    }

    /**
     * Connect to an isolated browsing session
     */
    async connect(targetUrl: string, isolationLevel: IsolationLevel = 'pixel_streaming'): Promise<RbiSession> {
        this.updateStatus('Creating session...');

        // Request session from gateway
        const response = await fetch(`${this.config.apiBaseUrl}/api/rbi/sessions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ targetUrl, isolationLevel }),
        });

        if (!response.ok) {
            throw new Error(`Failed to create session: ${response.statusText}`);
        }

        const session: RbiSession = await response.json();
        this.sessionId = session.id;

        this.updateStatus('Establishing connection...');

        // Establish WebRTC connection
        await this.setupWebRTC();

        // Connect WebSocket for input events
        this.setupWebSocket();

        this.updateStatus('Connected');

        return session;
    }

    /**
     * Setup WebRTC peer connection
     */
    private async setupWebRTC(): Promise<void> {
        this.peerConnection = new RTCPeerConnection({
            iceServers: this.config.iceServers || [
                { urls: 'stun:stun.l.google.com:19302' },
            ],
        });

        // Handle incoming video track
        this.peerConnection.ontrack = (event) => {
            console.log('Received video track');
            this.videoElement.srcObject = event.streams[0];
        };

        // Handle ICE candidates
        this.peerConnection.onicecandidate = async (event) => {
            if (event.candidate) {
                await fetch(`${this.config.apiBaseUrl}/api/rbi/sessions/${this.sessionId}/ice`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ candidate: event.candidate }),
                });
            }
        };

        // Connection state changes
        this.peerConnection.onconnectionstatechange = () => {
            console.log('Connection state:', this.peerConnection?.connectionState);
            this.updateStatus(this.peerConnection?.connectionState || 'unknown');
        };

        // Create offer
        const offer = await this.peerConnection.createOffer({
            offerToReceiveVideo: true,
            offerToReceiveAudio: true,
        });
        await this.peerConnection.setLocalDescription(offer);

        // Exchange SDP with server
        const answerResponse = await fetch(
            `${this.config.apiBaseUrl}/api/rbi/sessions/${this.sessionId}/connect`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ offer: offer.sdp }),
            }
        );

        const answer = await answerResponse.json();
        await this.peerConnection.setRemoteDescription({
            type: 'answer',
            sdp: answer.sdp,
        });
    }

    /**
     * Setup WebSocket for input events
     */
    private setupWebSocket(): void {
        const wsUrl = this.config.apiBaseUrl
            .replace('http://', 'ws://')
            .replace('https://', 'wss://');

        this.websocket = new WebSocket(
            `${wsUrl}/api/rbi/sessions/${this.sessionId}/input`
        );

        this.websocket.onopen = () => {
            console.log('Input WebSocket connected');
        };

        this.websocket.onclose = () => {
            console.log('Input WebSocket disconnected');
        };

        this.websocket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    /**
     * Send input event to server
     */
    private sendInput(event: InputEvent): void {
        if (this.websocket?.readyState === WebSocket.OPEN) {
            this.websocket.send(JSON.stringify(event));
        }
    }

    /**
     * Navigate to a new URL in the isolated browser
     */
    async navigateTo(url: string): Promise<void> {
        if (!this.sessionId) {
            throw new Error('Not connected');
        }

        await fetch(`${this.config.apiBaseUrl}/api/rbi/sessions/${this.sessionId}/navigate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        });
    }

    /**
     * Download a file (sanitized by server)
     */
    async downloadFile(fileId: string): Promise<Blob> {
        if (!this.sessionId) {
            throw new Error('Not connected');
        }

        const response = await fetch(
            `${this.config.apiBaseUrl}/api/rbi/sessions/${this.sessionId}/downloads/${fileId}`
        );

        if (!response.ok) {
            throw new Error(`Download failed: ${response.statusText}`);
        }

        return response.blob();
    }

    /**
     * Copy text from isolated browser clipboard
     */
    async copyFromBrowser(): Promise<string> {
        if (!this.sessionId) {
            throw new Error('Not connected');
        }

        const response = await fetch(
            `${this.config.apiBaseUrl}/api/rbi/sessions/${this.sessionId}/clipboard`,
            { method: 'GET' }
        );

        const result = await response.json();
        return result.content;
    }

    /**
     * Paste text to isolated browser clipboard
     */
    async pasteToBrowser(text: string): Promise<void> {
        if (!this.sessionId) {
            throw new Error('Not connected');
        }

        await fetch(
            `${this.config.apiBaseUrl}/api/rbi/sessions/${this.sessionId}/clipboard`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: text }),
            }
        );
    }

    /**
     * Set status change callback
     */
    onStatus(callback: (status: string) => void): void {
        this.onStatusChange = callback;
    }

    private updateStatus(status: string): void {
        this.onStatusChange?.(status);
    }

    /**
     * Disconnect from session
     */
    disconnect(): void {
        this.websocket?.close();
        this.peerConnection?.close();
        this.videoElement.srcObject = null;
        this.sessionId = null;
        this.updateStatus('Disconnected');
    }

    /**
     * Get current session ID
     */
    getSessionId(): string | null {
        return this.sessionId;
    }
}

/**
 * Input Handler - Captures and normalizes user input
 */
class InputHandler {
    onInput: ((event: InputEvent) => void) | null = null;
    private lastMousePos = { x: 0, y: 0 };
    private element: HTMLElement;

    constructor(element: HTMLElement) {
        this.element = element;
        element.tabIndex = 0; // Make focusable

        // Mouse events
        element.addEventListener('mousemove', (e) => this.handleMouseMove(e));
        element.addEventListener('mousedown', (e) => this.handleMouseDown(e));
        element.addEventListener('mouseup', (e) => this.handleMouseUp(e));
        element.addEventListener('wheel', (e) => this.handleWheel(e), { passive: false });
        element.addEventListener('click', () => element.focus());

        // Keyboard events (must focus element first)
        element.addEventListener('keydown', (e) => this.handleKeyDown(e));
        element.addEventListener('keyup', (e) => this.handleKeyUp(e));

        // Prevent context menu
        element.addEventListener('contextmenu', (e) => e.preventDefault());

        // Prevent default drag behavior
        element.addEventListener('dragstart', (e) => e.preventDefault());
    }

    private getRelativePosition(e: MouseEvent): { x: number; y: number } {
        const rect = this.element.getBoundingClientRect();
        return {
            x: (e.clientX - rect.left) / rect.width,
            y: (e.clientY - rect.top) / rect.height,
        };
    }

    private handleMouseMove(e: MouseEvent): void {
        const pos = this.getRelativePosition(e);
        this.lastMousePos = pos;
        this.onInput?.({ type: 'mouseMove', ...pos });
    }

    private handleMouseDown(e: MouseEvent): void {
        e.preventDefault();
        this.onInput?.({
            type: 'mouseDown',
            button: e.button,
            ...this.lastMousePos,
        });
    }

    private handleMouseUp(e: MouseEvent): void {
        this.onInput?.({
            type: 'mouseUp',
            button: e.button,
            ...this.lastMousePos,
        });
    }

    private handleWheel(e: WheelEvent): void {
        e.preventDefault();
        this.onInput?.({
            type: 'scroll',
            ...this.lastMousePos,
            deltaX: e.deltaX,
            deltaY: e.deltaY,
        });
    }

    private handleKeyDown(e: KeyboardEvent): void {
        // Prevent browser shortcuts from interfering
        if (e.ctrlKey || e.metaKey) {
            // Allow Ctrl+C, Ctrl+V to be handled locally then forwarded
            if (e.key !== 'c' && e.key !== 'v') {
                e.preventDefault();
            }
        }

        this.onInput?.({
            type: 'keyDown',
            key: e.key,
            code: e.code,
            modifiers: {
                ctrl: e.ctrlKey,
                shift: e.shiftKey,
                alt: e.altKey,
                meta: e.metaKey,
            },
        });
    }

    private handleKeyUp(e: KeyboardEvent): void {
        this.onInput?.({
            type: 'keyUp',
            key: e.key,
            code: e.code,
            modifiers: {
                ctrl: e.ctrlKey,
                shift: e.shiftKey,
                alt: e.altKey,
                meta: e.metaKey,
            },
        });
    }
}

export { InputHandler };
