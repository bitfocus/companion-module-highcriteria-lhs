import { EventEmitter } from 'events'
import { TCPHelper, TCPStatuses } from '@companion-module/base'
import PQueue from 'p-queue'

// ─── Framing constants ────────────────────────────────────────────────────────

/** "LISv#bgn" — marks the start of every framed message. */
const MAGIC_START = Buffer.from('4c4953762362676e', 'hex')
/** "LISv#end" — marks the end of every framed message. */
const MAGIC_END = Buffer.from('4c49537623656e64', 'hex')

const LIRSRV_SIG_SIZE = 8 // bytes per magic marker
const LIRSRV_HEAD_SIZE = 24 // bytes in LIRSRV_EXCHG_HEAD (incl. 2 reserved DWORDs)
const MAX_ROOM_NAME_LEN = 32
const PROG_NAME_LEN = 64

// ─── Protocol version ─────────────────────────────────────────────────────────

const LIRSRV_PROTOCOL_VERS_MAJOR = 4
const LIRSRV_PROTOCOL_VERS_MINOR = 1

// Client version constants (matching observed PCAP values)
const LIR_CTRL_VERS_MAJOR = 0x00
const LIR_CTRL_VERS_MINOR = 0x00
const LIR_CTRL_VERS_BUILD = 0x00

// ─── Block type enum (LIRSRV_BLOCK_TYPE) ─────────────────────────────────────

/**
 * Block type IDs as they appear in the ulDataType field of the exchange header.
 * Values match the C++ enum LIRSRV_BLOCK_TYPE starting at 1.
 */
const enum BlockType {
	SrvInitInfo = 1, // LIRSRV_SERVICE_INIT_INFO   — server → client on connect
	ClientInitInfo = 2, // LIRSRV_CLIENT_INIT_INFO    — client → server on connect
	BmInfo = 3, // BOOKMARK_EXCHDESCR         — bookmark add/modify/delete
	FileInfo = 4, // DCR_FILE_DESCR             — current file descriptor
	Cmd = 5, // LIRSRV_CMD_INFO            — generic command envelope
	Msg = 6, // LIRSRV_MSG_INFO_OLD        — legacy message
	KeepAlive = 7, // (no payload)               — server keepalive ping
	RecorderInfo = 8, // LIRSRV_RECSTATE_INFO       — recorder state (v1)
	RoomsList = 9, // LIRSRV_ROOM_LIST
	CurrBroad = 10, // LIRSRV_BROAD_INFO
	BmStruct = 11, // LIRSRV_BM_STRUCT
	Msg2 = 12, // LIRSRV_MSG_INFO
	RoomsList2 = 13, // LIRSRV_ROOM_LIST2
	BmInfo2 = 14, // BOOKMARK_EXCHDESCR2
	FileInfo2 = 15, // DCR_FILE_DESCR2            — file info (protocol ≥ 4.1)
	RecorderInfo2 = 16, // LIRSRV_RECSTATE_INFO2      — recorder state (v2, protocol ≥ 4.1)
}

// ─── Command codes (LIRSRV_CMD_TYPE / btCmd in command payload) ───────────────

/**
 * Command byte codes as observed in the PCAP and cross-referenced with the C++ API.
 * These appear in the btCmd byte of a LIRSRV_CMD_INFO payload.
 */
const enum Cmd {
	// Incoming commands (server → client)
	NotifyRecorderRunning = 0x01, // param1: 1=running, 0=not

	// Outgoing commands (client → server), confirmed from PCAP
	HeartbeatA = 0x03, // Q-Sys polling heartbeat A (param 0)
	RecAction = 0x04, // LIRSRV_CMD_REC_ACTION  — param = RecActionFlags
	HeartbeatB = 0x05, // Q-Sys polling heartbeat B (param 0)
	NewFile = 0x06, // LIRSRV_CMD_NEW_FILE
	StopRec = 0x07, // Stop recording          — param 0
	PauseAction = 0x08, // LIRSRV_CMD_PAUSE_ACTION — param = PauseActionFlags
}

// ─── Command parameter flags ──────────────────────────────────────────────────

/** Flags for Cmd.RecAction (dwCmdParam1). */
const enum RecActionFlags {
	StartRec = 0x01, // RECACTION_STARTREC
	StopRec = 0x02, // RECACTION_STOPREC
	CloseFile = 0x04, // RECACTION_CLOSEFILE — can be OR'd with StopRec
}

/**
 * Flags for Cmd.PauseAction (dwCmdParam1).
 * Both Pause and Resume were observed as 0x04 in the PCAP — the LHS toggles
 * state internally on each receipt.
 */
const enum PauseActionFlags {
	Pause = 0x04, // PAUSEACTION_PAUSE
}

// ─── Recorder state flags (dwStateF in LIRSRV_RECSTATE_INFO) ─────────────────

/**
 * Bit flags for the dwStateF field in a recorder state message.
 * Values verified by cross-referencing PCAP state transitions with the C++ API
 * (RECORDER_STATEF_REC family of constants).
 *
 *   dwStateF = 0 → stopped / idle
 *   dwStateF = 1 → recording active
 *   dwStateF = 3 → recording + paused  (bit 0 + bit 1)
 */
export const RecorderStateFlags = {
	/** Recording is active. */
	RECORDING: 0x01,
	/** Recording is currently paused (always set alongside RECORDING). */
	PAUSED: 0x02,
} as const

// ─── Default port ─────────────────────────────────────────────────────────────

const LHS_DEFAULT_PORT = 5002

// ─── Public types ─────────────────────────────────────────────────────────────

/** Parsed recorder state from LIRSRV_BLOCK_RECORDERINFO / RECORDERINFO2. */
export interface RecorderState {
	/** Room ID reported by the recorder (usually empty for single-room setups). */
	roomId: string
	/** Court / room ID from v2 packets (protocol ≥ 4.1); empty string for v1. */
	courtId: string
	/** Raw state flags — use RecorderStateFlags to test individual bits. */
	stateFlags: number
	/** Raw enabled-feature flags. */
	enabledFlags: number
	/** Raw alert flags. */
	alertFlags: number
	/** True when the recorder is actively recording (stateFlags & RECORDING). */
	isRecording: boolean
	/** True when recording is paused (stateFlags & PAUSED). */
	isPaused: boolean
}

// ─── Event interface ──────────────────────────────────────────────────────────

export interface LHSClientEvents {
	/** Forwarded status_change events from the TCP connection. */
	status_change: [status: TCPStatuses, message: string | undefined]

	/**
	 * Emitted once the TCP connection is established, the client handshake has
	 * been sent, and the server has acknowledged it with SRV_INITINFO.
	 */
	connected: []

	/** Emitted when the TCP connection is lost or closed. */
	disconnected: []

	/**
	 * Emitted whenever the LHS sends a recorder state update
	 * (LIRSRV_BLOCK_RECORDERINFO or RECORDERINFO2).  This is the primary way
	 * to know whether the recorder is running, paused, or stopped.
	 */
	recorder_state: [state: RecorderState]

	/** Emitted on any TCP or protocol error. */
	error: [err: Error]
}

// ─── Options ──────────────────────────────────────────────────────────────────

export interface LHSClientOptions {
	/** Hostname or IP address of the LHS device. */
	host: string
	/** TCP port (default: 5002). */
	port?: number
	/**
	 * Name reported to the LHS during the handshake (max 63 ASCII chars).
	 * Appears in LHS logs.
	 */
	clientName?: string
	/**
	 * Room name / court ID to filter messages for (max 31 ASCII chars).
	 * Pass an empty string to receive messages for all rooms.
	 */
	roomName?: string
	/** Heartbeat poll interval in ms (default: 3000). */
	heartbeatIntervalMs?: number
	/** Whether TCPHelper should auto-reconnect on drops (default: true). */
	reconnect?: boolean
	/** Auto-reconnect interval in ms (default: 2000). */
	reconnectIntervalMs?: number
}

// ─── LHSClient ────────────────────────────────────────────────────────────────

/**
 * LHSClient — controls a Liberty Hardware System (LHS) recorder over TCP.
 *
 * ## Protocol overview
 *
 * Transport : TCP, port 5002 (LHS is the server).
 *
 * Every message is wrapped in magic bytes:
 *   `"LISv#bgn"` (0x4c4953762362676e) … frame … `"LISv#end"` (0x4c49537623656e64)
 *
 * Inside each frame there is a 24-byte **LIRSRV_EXCHG_HEAD** (all fields big-endian):
 * ```
 *   Offset  Size  Field
 *      0      4   ulSender   — client/server socket ID
 *      4      4   ulTarget   — target ID (0 = broadcast)
 *      8      4   ulDataType — BlockType enum
 *     12      4   ulDataSize — byte length of the payload that follows
 *     16      4   (reserved, always 0)
 *     20      4   (reserved, always 0)
 *     24      N   payload
 * ```
 *
 * ## Command payload (BlockType.Cmd)
 * ```
 *   Offset  Size  Field
 *      0      1   roomIDCmd  (null-terminated, empty → just 0x00)
 *      1      1   btCmd      — Cmd enum
 *      2      4   dwCmdParam1 (big-endian)
 *      6      4   dwCmdParam2 (big-endian)
 *     10      1   sCmdInfo   (null-terminated, empty → just 0x00)
 * ```
 *
 * ## Determining recorder state
 *
 * Listen for the `recorder_state` event.  The `isRecording` and `isPaused`
 * boolean helpers are derived directly from the `stateFlags` field using
 * `RecorderStateFlags`.  The LHS pushes state updates automatically whenever
 * the recorder changes state, and also responds to the periodic heartbeat polls
 * sent by this client every ~3 s.
 *
 * ## Session lifecycle
 * 1. Call `connect()` — TCPHelper establishes TCP and auto-reconnects on drops.
 * 2. On TCP connect: client sends handshake (CLIENT_INITINFO).
 * 3. Server replies with SRV_INITINFO → `connected` event is emitted.
 * 4. Heartbeat pairs (cmd 0x03 + 0x05) are sent every 3 s.
 * 5. Server pushes `RECORDERINFO` packets in response and on state change.
 * 6. Call recording commands as needed.
 * 7. Call `destroy()` to tear everything down.
 */
export class LHSClient extends EventEmitter<LHSClientEvents> {
	private readonly host: string
	private readonly port: number
	private readonly clientName: string
	private readonly roomName: string
	private readonly heartbeatIntervalMs: number
	private readonly reconnect: boolean
	private readonly reconnectIntervalMs: number

	/** Serialises all outgoing writes — one frame in flight at a time, max one per 20 ms. */
	private readonly queue: PQueue = new PQueue({ concurrency: 1, interval: 20, intervalCap: 1 })

	private tcp: TCPHelper | null = null
	private receiveBuffer: Buffer = Buffer.alloc(0)
	private heartbeatTimer: ReturnType<typeof setInterval> | null = null

	/** True once the server has acknowledged our handshake with SRV_INITINFO. */
	private handshakeAcknowledged = false

	/**
	 * Random 32-bit socket ID used as the sender in all outgoing messages,
	 * matching the `m_dwSocketID = myrand32()` pattern from SSClientMobile.
	 * A consistent ID allows the server to route responses back correctly.
	 */
	private readonly socketId: number = (Math.random() * 0xffffffff) >>> 0

	/** Incrementing counter for bookmark IDs — must be unique per session. */
	private nextBmId = 1

	constructor(options: LHSClientOptions) {
		super()
		this.host = options.host
		this.port = options.port ?? LHS_DEFAULT_PORT
		this.clientName = options.clientName?.substring(0, 63) ?? 'Companion LHS Client'
		this.roomName = options.roomName?.substring(0, 31) ?? ''
		this.heartbeatIntervalMs = options.heartbeatIntervalMs ?? 3000
		this.reconnect = options.reconnect ?? true
		this.reconnectIntervalMs = options.reconnectIntervalMs ?? 2000
	}

	// ─── Connection lifecycle ─────────────────────────────────────────────────

	/**
	 * Open the TCP connection to the LHS.
	 * TCPHelper will attempt to connect immediately and auto-reconnect on drops.
	 * The `connected` event fires once the server has acknowledged the handshake.
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
			this.handshakeAcknowledged = false
			this.queue.clear()
			this._sendHandshake().catch(() => {})
			this._startHeartbeat()
		})

		this.tcp.on('end', () => {
			this.handshakeAcknowledged = false
			this._stopHeartbeat()
			this.emit('disconnected')
		})

		this.tcp.on('data', (chunk) => {
			this._onData(chunk)
		})
	}

	/** Destroy the TCP connection and clean up all resources. */
	destroy(): void {
		this._stopHeartbeat()
		this.queue.clear()
		if (this.tcp) {
			this.tcp.destroy()
			this.tcp = null
		}
		this.receiveBuffer = Buffer.alloc(0)
		this.handshakeAcknowledged = false
	}

	// ─── Recording commands ───────────────────────────────────────────────────

	/**
	 * New File — instructs the LHS to create a new recording file.
	 * (Cmd 0x06, param 0)
	 */
	async newFile(): Promise<void> {
		await this._sendCmd(Cmd.NewFile, 0)
	}

	/**
	 * Start Recording — begins audio capture to the current file.
	 * (Cmd 0x04, param RECACTION_STARTREC = 0x01)
	 */
	async startRecording(): Promise<void> {
		await this._sendCmd(Cmd.RecAction, RecActionFlags.StartRec)
	}

	/**
	 * Pause Recording — pauses the active recording.
	 * (Cmd 0x08, param PAUSEACTION_PAUSE = 0x04)
	 */
	async pauseRecording(): Promise<void> {
		await this._sendCmd(Cmd.PauseAction, PauseActionFlags.Pause)
	}

	/**
	 * Insert Bookmark — places a timestamp marker into the active recording.
	 *
	 * Serialises a BOOKMARK_EXCHDESCR (BOOKMARK_TYPE_OTHER) per the C++ API
	 * (CopyBMExchDescrToBuff / CopyBMDescrToBuff):
	 *   roomIDBM\0          null-terminated string  — matches this.roomName
	 *   dwBMId              4 B BE                  — unique incrementing ID
	 *   btBmType            1 B                     — 0x02 (BOOKMARK_TYPE_OTHER)
	 *   btReadOnlyBM        1 B                     — 0x00
	 *   btUsedCaseFields    1 B                     — 0x00
	 *   [4 × field record]  using(1) + name\0 + val\0
	 *
	 * @param note  Optional text label attached to the bookmark's note field.
	 */
	async insertBookmark(note = ''): Promise<void> {
		const bmId = this.nextBmId++
		const room = Buffer.from(this.roomName, 'ascii')
		const noteB = Buffer.from(note, 'ascii')

		// 4 field records: using(1B) + name\0(1B) + val\0(variable).
		// Field 0 is the note field — it receives the note value.
		// The remaining 3 fields are empty.
		const NUM_FIELDS = 4
		const NOTE_FIELD = 0

		const fieldBufs: Buffer[] = []
		for (let i = 0; i < NUM_FIELDS; i++) {
			const val = i === NOTE_FIELD ? noteB : Buffer.alloc(0)
			fieldBufs.push(
				Buffer.from([0x01]), // abtFieldUsing = 1
				Buffer.from([0x00]), // asFieldNames[i] = "" (null terminator)
				val,
				Buffer.from([0x00]), // asFieldVals[i] null terminator
			)
		}

		const header = Buffer.alloc(7)
		header.writeUInt32BE(bmId, 0) // dwBMId
		header[4] = 0x02 // btBmType = BOOKMARK_TYPE_OTHER
		header[5] = 0x00 // btReadOnlyBM
		header[6] = 0x00 // btUsedCaseFields

		const payload = Buffer.concat([
			room,
			Buffer.from([0x00]), // roomIDBM null terminator
			header,
			...fieldBufs,
		])

		await this._sendBlock(BlockType.BmInfo, payload)
	}

	/**
	 * Stop Recording — ends the active recording session.
	 * The LHS automatically closes the file on stop.
	 * (Cmd 0x07, param 0 — as observed in PCAP)
	 */
	async stopRecording(): Promise<void> {
		await this._sendCmd(Cmd.StopRec, 0)
	}

	/**
	 * Close File — alias for stopRecording().
	 * The LHS closes the file as part of the stop command.
	 */
	async closeFile(): Promise<void> {
		await this.stopRecording()
	}

	// ─── Private — heartbeat ──────────────────────────────────────────────────

	/**
	 * Send a heartbeat pair (cmd 0x03 + cmd 0x05) every `heartbeatIntervalMs`.
	 * This also acts as a state-poll: the LHS responds with a RECORDERINFO
	 * packet after receiving these, keeping `recorder_state` events flowing.
	 */
	private _startHeartbeat(): void {
		if (this.heartbeatTimer) return
		this.heartbeatTimer = setInterval(() => {
			if (!this.tcp?.isConnected) return
			this._sendCmd(Cmd.HeartbeatA, 0).catch(() => {})
			this._sendCmd(Cmd.HeartbeatB, 0).catch(() => {})
		}, this.heartbeatIntervalMs)
	}

	private _stopHeartbeat(): void {
		if (this.heartbeatTimer) {
			clearInterval(this.heartbeatTimer)
			this.heartbeatTimer = null
		}
	}

	// ─── Private — frame building ─────────────────────────────────────────────

	/**
	 * Build a complete framed message:
	 *   [MAGIC_START][sender:4][target:4][dataType:4][dataSize:4][0:4][0:4][payload][MAGIC_END]
	 */
	private _buildFrame(dataType: BlockType, payload: Buffer, target = 0): Buffer {
		const head = Buffer.alloc(LIRSRV_HEAD_SIZE)
		head.writeUInt32BE(this.socketId, 0)
		head.writeUInt32BE(target, 4)
		head.writeUInt32BE(dataType, 8)
		head.writeUInt32BE(payload.length, 12)
		head.writeUInt32BE(0, 16) // reserved
		head.writeUInt32BE(0, 20) // reserved
		return Buffer.concat([MAGIC_START, head, payload, MAGIC_END])
	}

	/**
	 * Build a BlockType.Cmd payload:
	 *   [roomIDCmd\0][btCmd][dwCmdParam1:4 BE][dwCmdParam2:4 BE][sCmdInfo\0]
	 */
	private _buildCmdPayload(cmd: Cmd, param1: number, param2 = 0): Buffer {
		const buf = Buffer.alloc(11)
		buf[0] = 0x00 // empty roomIDCmd string terminator
		buf[1] = cmd // btCmd
		buf.writeUInt32BE(param1, 2) // dwCmdParam1
		buf.writeUInt32BE(param2, 6) // dwCmdParam2
		buf[10] = 0x00 // empty sCmdInfo string terminator
		return buf
	}

	/** Build and send a BlockType.Cmd message. */
	private async _sendCmd(cmd: Cmd, param1: number, param2 = 0): Promise<void> {
		await this._sendBlock(BlockType.Cmd, this._buildCmdPayload(cmd, param1, param2))
	}

	/** Build and send a raw block of any type. */
	private async _sendBlock(dataType: BlockType, payload: Buffer): Promise<void> {
		await this._sendRaw(this._buildFrame(dataType, payload))
	}

	/**
	 * Send the initial CLIENT_INITINFO handshake (BlockType.ClientInitInfo).
	 *
	 * LIRSRV_CLIENT_INIT_INFO payload (120 bytes):
	 *   dwClientType        4 B  — LIRSRV_CLIENT_MOBILE = 0x00000002
	 *   dwClientVersMajor   4 B
	 *   dwClientVersMinor   4 B
	 *   dwClientVersBuild   4 B
	 *   dwProtocolVersMajor 4 B  — 4
	 *   dwProtocolVersMinor 4 B  — 1
	 *   szProgName[64]     64 B  — null-padded ASCII
	 *   roomID[32]         32 B  — null-padded ASCII
	 */
	private async _sendHandshake(): Promise<void> {
		const LIRSRV_CLIENT_MOBILE = 0x00000002

		const payload = Buffer.alloc(120)
		payload.writeUInt32BE(LIRSRV_CLIENT_MOBILE, 0)
		payload.writeUInt32BE(LIR_CTRL_VERS_MAJOR, 4)
		payload.writeUInt32BE(LIR_CTRL_VERS_MINOR, 8)
		payload.writeUInt32BE(LIR_CTRL_VERS_BUILD, 12)
		payload.writeUInt32BE(LIRSRV_PROTOCOL_VERS_MAJOR, 16)
		payload.writeUInt32BE(LIRSRV_PROTOCOL_VERS_MINOR, 20)

		Buffer.from(this.clientName, 'ascii').copy(payload, 24, 0, PROG_NAME_LEN - 1)
		Buffer.from(this.roomName, 'ascii').copy(payload, 88, 0, MAX_ROOM_NAME_LEN - 1)

		await this._sendBlock(BlockType.ClientInitInfo, payload)
	}

	/**
	 * Enqueue a raw frame for sending.
	 * PQueue ensures frames are sent one at a time with a minimum 20 ms gap,
	 * preventing the LHS from being overwhelmed by bursts.
	 */
	private async _sendRaw(data: Buffer): Promise<boolean> {
		return (
			(await this.queue.add(async () => {
				if (!this.tcp?.isConnected) {
					this.emit('error', new Error('LHSClient: not connected'))
					return false
				}
				return this.tcp.send(data)
			})) ?? false
		)
	}

	// ─── Private — receive framing & dispatch ─────────────────────────────────

	/** Accumulate bytes and extract complete LISv-framed messages. */
	private _onData(chunk: Buffer): void {
		this.receiveBuffer = Buffer.concat([this.receiveBuffer, chunk])

		while (true) {
			const start = this.receiveBuffer.indexOf(MAGIC_START)
			if (start === -1) {
				this.receiveBuffer = Buffer.alloc(0)
				break
			}

			// Discard garbage before start marker.
			if (start > 0) {
				this.receiveBuffer = this.receiveBuffer.slice(start)
			}

			// Need at least magic + header to know total size.
			if (this.receiveBuffer.length < LIRSRV_SIG_SIZE + LIRSRV_HEAD_SIZE) break

			// Read payload size from header without consuming the buffer yet.
			const dataSize = this.receiveBuffer.readUInt32BE(LIRSRV_SIG_SIZE + 12)
			const frameLen = LIRSRV_SIG_SIZE + LIRSRV_HEAD_SIZE + dataSize + LIRSRV_SIG_SIZE

			if (this.receiveBuffer.length < frameLen) break // wait for more data

			// Validate end marker.
			const endOffset = frameLen - LIRSRV_SIG_SIZE
			if (!this.receiveBuffer.slice(endOffset, endOffset + LIRSRV_SIG_SIZE).equals(MAGIC_END)) {
				this.emit('error', new Error('LHSClient: invalid end signature'))
				this.receiveBuffer = Buffer.alloc(0)
				break
			}

			// Extract header fields and payload.
			const head = this.receiveBuffer.slice(LIRSRV_SIG_SIZE, LIRSRV_SIG_SIZE + LIRSRV_HEAD_SIZE)
			const payload = this.receiveBuffer.slice(LIRSRV_SIG_SIZE + LIRSRV_HEAD_SIZE, endOffset)
			const dataType = head.readUInt32BE(8) as BlockType

			this._dispatchBlock(dataType, payload)

			this.receiveBuffer = this.receiveBuffer.slice(frameLen)
		}
	}

	/** Route a fully-parsed incoming block to the appropriate handler. */
	private _dispatchBlock(dataType: BlockType, payload: Buffer): void {
		switch (dataType) {
			case BlockType.SrvInitInfo:
				this._handleSrvInitInfo(payload)
				break
			case BlockType.RecorderInfo:
				this._handleRecorderInfo(payload, false)
				break
			case BlockType.RecorderInfo2:
				this._handleRecorderInfo(payload, true)
				break
			case BlockType.KeepAlive:
				// No action required — server just confirming it's alive.
				break
			case BlockType.Cmd:
				this._handleIncomingCmd(payload)
				break
			// FileInfo, BmInfo, RoomsList etc. are not needed for recording control.
			// Add cases here if you need to react to file or bookmark events.
			default:
				break
		}
	}

	// ─── Private — incoming message handlers ──────────────────────────────────

	/**
	 * Handle LIRSRV_BLOCK_SRV_INITINFO (server's response to our handshake).
	 *
	 * LIRSRV_SERVICE_INIT_INFO layout (fixed struct):
	 *   dwServVersMajor     4 B  → offset  0
	 *   dwServVersMinor     4 B  → offset  4
	 *   dwServVersBuild     4 B  → offset  8
	 *   btProtocolVersMajor 1 B  → offset 12
	 *   btProtocolVersMinor 1 B  → offset 13
	 *   szProgName[64]     64 B  → offset 14
	 *   Total: 78 bytes
	 */
	private _handleSrvInitInfo(payload: Buffer): void {
		if (payload.length < 78) {
			this.emit('error', new Error(`LHSClient: SRV_INITINFO payload too short (${payload.length} bytes, expected ≥78)`))
			return
		}

		const serverMajor = payload.readUInt32BE(0)
		const serverMinor = payload.readUInt32BE(4)
		const serverBuild = payload.readUInt32BE(8)
		const protocolMajor = payload[12]
		const protocolMinor = payload[13]
		const progName = payload.slice(14, 78).toString('ascii').replace(/\0+$/, '')

		console.log(
			`LHSClient SRV_INITINFO: server=${serverMajor}.${serverMinor}.${serverBuild}` +
				` protocol=${protocolMajor}.${protocolMinor} prog="${progName}"`,
		)

		if (protocolMajor !== LIRSRV_PROTOCOL_VERS_MAJOR) {
			this.emit(
				'error',
				new Error(
					`LHSClient: unsupported protocol version ${protocolMajor}.${protocolMinor}` +
						` (expected ${LIRSRV_PROTOCOL_VERS_MAJOR}.x)`,
				),
			)
			return
		}

		if (!this.handshakeAcknowledged) {
			this.handshakeAcknowledged = true
			this.emit('connected')
		}
	}

	/**
	 * Parse a LIRSRV_BLOCK_RECORDERINFO (v1) or RECORDERINFO2 (v2) payload
	 * and emit a `recorder_state` event.
	 *
	 * Wire format (CopyRecStateToBuff[2]):
	 *   roomIDRS       null-terminated string  (≤ MAX_ROOM_NAME_LEN = 32 chars)
	 *   dwStateF       4 B BE  — recorder state bit flags
	 *   dwEnabledF     4 B BE  — enabled feature flags
	 *   dwAlertF       4 B BE  — alert flags
	 *   dwReserved1    4 B BE
	 *   dwReserved2    4 B BE
	 *   sCourtId       null-terminated string  (v2 only)
	 */
	private _handleRecorderInfo(payload: Buffer, isV2: boolean): void {
		let offset = 0

		// Read roomIDRS (null-terminated).
		const roomIdEnd = payload.indexOf(0x00, offset)
		if (roomIdEnd === -1) {
			this.emit('error', new Error('LHSClient: RECORDERINFO missing roomIDRS terminator'))
			return
		}
		const roomId = payload.slice(offset, roomIdEnd).toString('ascii')
		offset = roomIdEnd + 1

		// Need 5 DWORDs (20 bytes) after the room ID string.
		if (payload.length < offset + 20) {
			this.emit('error', new Error('LHSClient: RECORDERINFO payload too short'))
			return
		}

		const stateFlags = payload.readUInt32BE(offset)
		offset += 4
		const enabledFlags = payload.readUInt32BE(offset)
		offset += 4
		const alertFlags = payload.readUInt32BE(offset)
		offset += 4
		offset += 4 // dwReserved1
		offset += 4 // dwReserved2

		// v2 appends a null-terminated court ID string.
		let courtId = ''
		if (isV2 && offset < payload.length) {
			const courtIdEnd = payload.indexOf(0x00, offset)
			if (courtIdEnd !== -1) {
				courtId = payload.slice(offset, courtIdEnd).toString('ascii')
			}
		}

		this.emit('recorder_state', {
			roomId,
			courtId,
			stateFlags,
			enabledFlags,
			alertFlags,
			isRecording: (stateFlags & RecorderStateFlags.RECORDING) !== 0,
			isPaused: (stateFlags & RecorderStateFlags.PAUSED) !== 0,
		})
	}

	/**
	 * Handle LIRSRV_BLOCK_CMD packets sent from the server to this client.
	 *
	 * ParseCmdBuffer wire format:
	 *   roomIDCmd      null-terminated string  (≤ MAX_ROOM_NAME_LEN)
	 *   btCmd          1 B
	 *   dwCmdParam1    4 B BE
	 *   dwCmdParam2    4 B BE
	 *   sCmdInfo       null-terminated string
	 */
	private _handleIncomingCmd(payload: Buffer): void {
		// Skip roomIDCmd.
		const roomEnd = payload.indexOf(0x00)
		if (roomEnd === -1) return
		let offset = roomEnd + 1

		if (payload.length < offset + 9) return // btCmd + 2×DWORD

		const btCmd = payload[offset] as Cmd
		offset += 1
		const param1 = payload.readUInt32BE(offset)

		switch (btCmd) {
			case Cmd.NotifyRecorderRunning:
				// Server notifying us whether the recorder application is running.
				// param1 = 1 running, 0 not running. Not the same as actively recording.
				// Actual recording state comes from the recorder_state event (RECORDERINFO).
				void param1
				break

			default:
				break
		}
	}
}
