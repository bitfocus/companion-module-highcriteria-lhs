import { EventEmitter } from 'events'
import { TCPHelper, TCPStatuses } from '@companion-module/base'
import PQueue from 'p-queue'

// ─── Framing constants ────────────────────────────────────────────────────────

const MAGIC_START = Buffer.from('4c4953762362676e', 'hex') // "LISv#bgn"
const MAGIC_END = Buffer.from('4c49537623656e64', 'hex') // "LISv#end"

// ─── Protocol constants ───────────────────────────────────────────────────────

const LHS_DEFAULT_PORT = 5002

/**
 * Message type codes (header offset 8).
 * Type 2 = handshake, Type 3 = bookmark, Type 5 = command.
 */
const enum MsgType {
	Handshake = 0x02,
	Bookmark = 0x03,
	Command = 0x05,
}

/**
 * Command codes used in Type-5 payloads (payload offset 1).
 */
const enum Cmd {
	HeartbeatA = 0x03,
	StartRecording = 0x04,
	HeartbeatB = 0x05,
	NewFile = 0x06,
	StopRecording = 0x07,
	PauseResume = 0x08,
}

// Device IDs observed in capture. The LHS does not appear to validate these.
const DEVICE_ID_HANDSHAKE = 0x00aec2bc
const DEVICE_ID_HEARTBEAT = 0x884adf83
const DEVICE_ID_DEFAULT = 0x00000000

// Exact 20-byte bookmark payload from the protocol capture.
const BOOKMARK_PAYLOAD = Buffer.from('00ffffffff020000010000010000010000010000', 'hex')

// ─── Event interface ──────────────────────────────────────────────────────────

export interface LHSClientEvents {
	/** Forwarded status_change events from the TCP connection. */
	status_change: [status: TCPStatuses, message: string | undefined]

	/** Emitted once the TCP connection is established and the handshake has been sent. */
	connected: []

	/** Emitted when the TCP connection is lost or closed. */
	disconnected: []

	/** Emitted when a complete framed message body is received from the LHS. */
	message: [body: Buffer]

	/** Emitted on any TCP or protocol error. */
	error: [err: Error]
}

// ─── Options ──────────────────────────────────────────────────────────────────

export interface LHSClientOptions {
	/** Hostname or IP address of the LHS device. */
	host: string
	/** TCP port (default: 5002). */
	port?: number
	/** Name reported to the LHS during the handshake (max 47 ASCII chars). */
	clientName?: string
	/** Room / court name sent in the handshake (max 47 ASCII chars). */
	roomName?: string
	/** Heartbeat interval in ms (default: 3000). */
	heartbeatIntervalMs?: number
	/** Whether TCPHelper should auto-reconnect on drops (default: true). */
	reconnect?: boolean
	/** Auto-reconnect interval in ms (default: 2000). */
	reconnectIntervalMs?: number
}

// ─── LHSClient ────────────────────────────────────────────────────────────────

/**
 * LHSClient — controls Liberty Helper Service (LHS) over TCP.
 *
 * Protocol overview
 * -----------------
 * Transport : TCP, port 5002 (LHS is the server).
 * Framing   : Every message is wrapped in magic bytes:
 *               "LISv#bgn" (0x4c4953762362676e) … body … "LISv#end" (0x4c49537623656e64)
 *
 * Body layout (all integers big-endian):
 *   Offset  Size  Field
 *      0      4   Device / session ID
 *      4      4   Reserved (always 0)
 *      8      4   Message type  (2=handshake, 3=bookmark, 5=command)
 *     12      4   Payload length N
 *     16      4   Reserved (always 0)
 *     20      4   Reserved (always 0)
 *     24      N   Payload
 *
 * Type-5 command payload (11 bytes):
 *   [0x00][cmdCode][0x00 0x00 0x00][param][0x00 0x00 0x00 0x00 0x00]
 *
 * Known command codes:
 *   0x03  Heartbeat ping A    param 0x00
 *   0x04  Start Recording     param 0x01
 *   0x05  Heartbeat ping B    param 0x00
 *   0x06  New File            param 0x00
 *   0x07  Stop Recording      param 0x00
 *   0x08  Pause / Resume      param 0x04  (same bytes; LHS toggles state)
 *
 * Notes
 * -----
 * • Pause and Resume send identical bytes — the LHS is stateful and toggles.
 * • A heartbeat pair (0x03 + 0x05) is sent every ~3 s; this is handled
 *   automatically while connected and stopped on disconnect.
 * • closeFile() destroys the TCP connection (no distinct protocol command
 *   was observed in the capture for this action).
 */
export class LHSClient extends EventEmitter<LHSClientEvents> {
	private readonly host: string
	private readonly port: number
	private readonly clientName: string
	private readonly roomName: string
	private readonly heartbeatIntervalMs: number
	private readonly reconnect: boolean
	private readonly reconnectIntervalMs: number
	private queue: PQueue = new PQueue({ concurrency: 1, interval: 20, intervalCap: 1 })
	private tcp: TCPHelper | null = null
	private receiveBuffer: Buffer = Buffer.alloc(0)
	private heartbeatTimer: ReturnType<typeof setInterval> | null = null

	constructor(options: LHSClientOptions) {
		super()
		this.host = options.host
		this.port = options.port ?? LHS_DEFAULT_PORT
		this.clientName = options.clientName ?? 'LHSClient'
		this.roomName = options.roomName ?? 'Room'
		this.heartbeatIntervalMs = options.heartbeatIntervalMs ?? 3000
		this.reconnect = options.reconnect ?? true
		this.reconnectIntervalMs = options.reconnectIntervalMs ?? 2000
	}

	// ─── Connection lifecycle ─────────────────────────────────────────────────

	/**
	 * Open the TCP connection to the LHS.
	 * TCPHelper will attempt to connect immediately and auto-reconnect on drops
	 * (controlled by the `reconnect` option).
	 */
	connect(): void {
		if (this.tcp) return

		this.tcp = new TCPHelper(this.host, this.port, {
			reconnect: this.reconnect,
			reconnect_interval: this.reconnectIntervalMs,
		})

		this.tcp.on('error', (err) => {
			this.emit('error', err)
		})

		this.tcp.on('status_change', (status, message) => {
			this.emit('status_change', status, message)
		})

		this.tcp.on('connect', () => {
			this.receiveBuffer = Buffer.alloc(0)
			this._sendHandshake().catch(() => {})
			this._startHeartbeat().catch(() => {})
			this.emit('connected')
		})

		this.tcp.on('end', () => {
			this._stopHeartbeat()
			this.emit('disconnected')
		})

		this.tcp.on('data', (chunk) => {
			this._onData(chunk)
		})
	}

	/**
	 * Close File — destroys the TCP connection and cleans up all resources.
	 * No distinct "close file" command was observed in the protocol capture;
	 * the session is terminated at the transport layer.
	 */
	closeFile(): void {
		this.queue.clear()
		this._stopHeartbeat()
		if (this.tcp) {
			this.tcp.destroy()
			this.tcp = null
		}
		this.receiveBuffer = Buffer.alloc(0)
	}

	/** Alias for closeFile() — tears down the connection entirely. */
	destroy(): void {
		this.closeFile()
	}

	// ─── Recording commands ───────────────────────────────────────────────────

	/**
	 * New File — instructs the LHS to prepare a new recording file.
	 * (Command 0x06, param 0x00)
	 */
	async newFile(): Promise<void> {
		await this._sendCommand(Cmd.NewFile, 0x00)
	}

	/**
	 * Start Recording — begins audio capture to the current file.
	 * (Command 0x04, param 0x01)
	 */
	async startRecording(): Promise<void> {
		await this._sendCommand(Cmd.StartRecording, 0x01)
	}

	/**
	 * Pause Recording — pauses the active recording.
	 * (Command 0x08, param 0x04)
	 *
	 * ⚠️  Pause and Resume send **identical bytes**. The LHS is stateful and
	 * toggles between paused/resumed on each receipt of this message.
	 */
	async pauseRecording(): Promise<void> {
		await this._sendCommand(Cmd.PauseResume, 0x04)
	}

	/**
	 * Resume Recording — resumes a paused recording.
	 * (Command 0x08, param 0x04 — same bytes as Pause; LHS is stateful)
	 */
	async resumeRecording(): Promise<void> {
		await this._sendCommand(Cmd.PauseResume, 0x04)
	}

	/**
	 * Insert Bookmark — places a timestamp marker into the active recording.
	 * Uses message type 0x03 with a fixed 20-byte payload (as captured).
	 */
	async insertBookmark(): Promise<void> {
		await this._send(this._buildMessage(MsgType.Bookmark, BOOKMARK_PAYLOAD, DEVICE_ID_DEFAULT))
	}

	/**
	 * Stop Recording — ends the active recording session.
	 * (Command 0x07, param 0x00)
	 */
	async stopRecording(): Promise<void> {
		await this._sendCommand(Cmd.StopRecording, 0x00)
	}

	// ─── Private — heartbeat ──────────────────────────────────────────────────

	private async _startHeartbeat(): Promise<void> {
		if (this.heartbeatTimer) return
		this.heartbeatTimer = setInterval(() => {
			if (!this.tcp?.isConnected) return
			this._sendCommand(Cmd.HeartbeatA, 0x00, DEVICE_ID_HEARTBEAT).catch(() => {})
			this._sendCommand(Cmd.HeartbeatB, 0x00, DEVICE_ID_HEARTBEAT).catch(() => {})
		}, this.heartbeatIntervalMs)
	}

	private _stopHeartbeat(): void {
		if (this.heartbeatTimer) {
			clearInterval(this.heartbeatTimer)
			this.heartbeatTimer = null
		}
	}

	// ─── Private — message building ───────────────────────────────────────────

	/**
	 * Build a fully framed message:
	 *   [MAGIC_START][deviceId:4][0:4][msgType:4][payloadLen:4][0:4][0:4][payload][MAGIC_END]
	 */
	private _buildMessage(msgType: MsgType, payload: Buffer, deviceId: number = DEVICE_ID_DEFAULT): Buffer {
		const header = Buffer.alloc(24)
		header.writeUInt32BE(deviceId, 0)
		header.writeUInt32BE(0, 4)
		header.writeUInt32BE(msgType, 8)
		header.writeUInt32BE(payload.length, 12)
		header.writeUInt32BE(0, 16)
		header.writeUInt32BE(0, 20)
		return Buffer.concat([MAGIC_START, header, payload, MAGIC_END])
	}

	/**
	 * Build a Type-5 command payload (11 bytes):
	 *   [0x00][cmd][0x00 0x00 0x00][param][0x00 0x00 0x00 0x00 0x00]
	 */
	private _buildCommandPayload(cmd: Cmd, param: number): Buffer {
		const payload = Buffer.alloc(11)
		payload[1] = cmd
		payload[5] = param
		return payload
	}

	/** Build and send a Type-5 command message. */
	private async _sendCommand(cmd: Cmd, param: number, deviceId: number = DEVICE_ID_DEFAULT): Promise<void> {
		const payload = this._buildCommandPayload(cmd, param)
		await this._send(this._buildMessage(MsgType.Command, payload, deviceId))
	}

	/**
	 * Send the initial handshake (message type 0x02).
	 *
	 * Handshake payload (120 bytes):
	 *   [0x00000002][0x00000001][0x00000001][0x00000274][0x00000004][0x00000000]
	 *   [clientName: 48 bytes, null-padded]
	 *   [roomName:   48 bytes, null-padded]
	 */
	private async _sendHandshake(): Promise<void> {
		const payload = Buffer.alloc(120)
		payload.writeUInt32BE(0x00000002, 0)
		payload.writeUInt32BE(0x00000001, 4)
		payload.writeUInt32BE(0x00000001, 8)
		payload.writeUInt32BE(0x00000274, 12)
		payload.writeUInt32BE(0x00000004, 16)
		payload.writeUInt32BE(0x00000000, 20)

		const nameBytes = Buffer.from(this.clientName, 'ascii')
		nameBytes.copy(payload, 24, 0, Math.min(nameBytes.length, 47))

		const roomBytes = Buffer.from(this.roomName, 'ascii')
		roomBytes.copy(payload, 72, 0, Math.min(roomBytes.length, 47))

		await this._send(this._buildMessage(MsgType.Handshake, payload, DEVICE_ID_HANDSHAKE))
	}

	/** Write a buffer to the TCP socket. Emits 'error' if not connected. */
	private async _send(data: Buffer): Promise<boolean> {
		return await this.queue.add(async () => {
			if (!this.tcp) {
				this.emit('error', new Error('LHSClient: not connected'))
				return false
			}
			return await this.tcp.send(data)
		})
	}

	// ─── Private — receive framing ────────────────────────────────────────────

	/** Accumulate incoming bytes and extract complete LISv-framed messages. */
	private _onData(chunk: Buffer): void {
		this.receiveBuffer = Buffer.concat([this.receiveBuffer, chunk])

		while (true) {
			const start = this.receiveBuffer.indexOf(MAGIC_START)
			if (start === -1) {
				this.receiveBuffer = Buffer.alloc(0)
				break
			}

			const end = this.receiveBuffer.indexOf(MAGIC_END, start + MAGIC_START.length)
			if (end === -1) {
				// Discard any garbage before the start marker, then wait for more data.
				if (start > 0) this.receiveBuffer = this.receiveBuffer.slice(start)
				break
			}

			const body = this.receiveBuffer.slice(start + MAGIC_START.length, end)
			this.emit('message', body)

			this.receiveBuffer = this.receiveBuffer.slice(end + MAGIC_END.length)
		}
	}
}
