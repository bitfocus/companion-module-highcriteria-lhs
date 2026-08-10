/**
 * Unit tests for LHSClient.
 *
 * Tests cover:
 *  - Constructor defaults / option truncation
 *  - connect()/destroy() lifecycle and idempotency
 *  - CLIENT_INITINFO handshake framing
 *  - SRV_INITINFO handling and the "connected" event
 *  - RECORDERINFO (v1) / RECORDERINFO2 (v2) parsing and the "recorder_state" event
 *  - Incoming BlockType.Cmd handling
 *  - Frame buffering edge cases (split frames, garbage bytes, bad markers)
 *  - Outgoing recording commands and insertBookmark() payload framing
 *  - Heartbeat scheduling
 *  - Send guard when not connected
 *  - Event forwarding (status_change, error, disconnected)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { LHSClient, RecorderStateFlags } from './lhs.js'

// ── Mocks ─────────────────────────────────────────────────────────────────────

/** Captured TCP event handlers, reset per test. */
// eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
let tcpHandlers: Record<string, Function> = {}
let tcpIsConnected = false
let tcpConstructorCalls: Array<{ host: string; port: number; options?: Record<string, unknown> }> = []

const mockTCP = {
	send: vi.fn().mockReturnValue(true),
	destroy: vi.fn(),
}

vi.mock('@companion-module/base', () => ({
	TCPHelper: class {
		constructor(host: string, port: number, options?: Record<string, unknown>) {
			tcpConstructorCalls.push({ host, port, options })
		}
		// eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
		on(event: string, fn: Function) {
			tcpHandlers[event] = fn
		}
		get isConnected() {
			return tcpIsConnected
		}
		send(data: Buffer) {
			return mockTCP.send(data)
		}
		destroy() {
			mockTCP.destroy()
		}
	},
}))

// PQueue mock — concurrency 1, immediately executes the queued function.
vi.mock('p-queue', () => ({
	default: class {
		async add(fn: () => Promise<unknown>) {
			return fn()
		}
		clear() {}
	},
}))

// ── Wire-format constants (mirrors the private constants in lhs.ts) ────────────

const MAGIC_START = Buffer.from('4c4953762362676e', 'hex') // "LISv#bgn"
const MAGIC_END = Buffer.from('4c49537623656e64', 'hex') // "LISv#end"

const BLOCK = {
	SrvInitInfo: 1,
	ClientInitInfo: 2,
	FileInfo: 4,
	Cmd: 5,
	KeepAlive: 7,
	RecorderInfo: 8,
	BmInfo2: 14,
	RecorderInfo2: 16,
} as const

const CMD = {
	NotifyRecorderRunning: 0x01,
	HeartbeatA: 0x03,
	RecAction: 0x04,
	HeartbeatB: 0x05,
	NewFile: 0x06,
	StopRec: 0x07,
	PauseAction: 0x08,
} as const

const REC_ACTION = { StartRec: 0x01, StopRec: 0x02 } as const
const PAUSE_ACTION = { Pause: 0x01, Continue: 0x02, Toggle: 0x04 } as const

// ── Frame helpers ────────────────────────────────────────────────────────────

/** Build a complete framed message, mirroring `_buildFrame`. */
function buildFrame(dataType: number, payload: Buffer, sender = 1, target = 0): Buffer {
	const head = Buffer.alloc(24)
	head.writeUInt32BE(sender, 0)
	head.writeUInt32BE(target, 4)
	head.writeUInt32BE(dataType, 8)
	head.writeUInt32BE(payload.length, 12)
	head.writeUInt32BE(0, 16)
	head.writeUInt32BE(0, 20)
	return Buffer.concat([MAGIC_START, head, payload, MAGIC_END])
}

/** Build a SRV_INITINFO payload (78 bytes). */
function buildSrvInitInfo(
	opts: {
		major?: number
		minor?: number
		build?: number
		protocolMajor?: number
		protocolMinor?: number
		progName?: string
	} = {},
): Buffer {
	const { major = 1, minor = 0, build = 0, protocolMajor = 4, protocolMinor = 1, progName = 'LHS Server' } = opts
	const buf = Buffer.alloc(78)
	buf.writeUInt32BE(major, 0)
	buf.writeUInt32BE(minor, 4)
	buf.writeUInt32BE(build, 8)
	buf[12] = protocolMajor
	buf[13] = protocolMinor
	Buffer.from(progName, 'ascii').copy(buf, 14, 0, 64)
	return buf
}

/** Build a RECORDERINFO / RECORDERINFO2 payload. */
function buildRecorderInfo(opts: {
	roomId?: string
	stateFlags?: number
	enabledFlags?: number
	alertFlags?: number
	isV2?: boolean
	courtId?: string
}): Buffer {
	const { roomId = '', stateFlags = 0, enabledFlags = 0, alertFlags = 0, isV2 = false, courtId } = opts
	const body = Buffer.alloc(20)
	body.writeUInt32BE(stateFlags, 0)
	body.writeUInt32BE(enabledFlags, 4)
	body.writeUInt32BE(alertFlags, 8)
	const parts = [Buffer.from(roomId, 'ascii'), Buffer.from([0x00]), body]
	if (isV2) {
		parts.push(Buffer.from(courtId ?? '', 'ascii'), Buffer.from([0x00]))
	}
	return Buffer.concat(parts)
}

/** Build a BlockType.Cmd payload (roomIDCmd\0, btCmd, param1 BE, param2 BE, sCmdInfo\0). */
function buildCmdPayload(cmd: number, param1: number, param2 = 0): Buffer {
	const buf = Buffer.alloc(11)
	buf[0] = 0x00
	buf[1] = cmd
	buf.writeUInt32BE(param1, 2)
	buf.writeUInt32BE(param2, 6)
	buf[10] = 0x00
	return buf
}

/** Decode a Cmd frame captured from mockTCP.send back into its fields. */
function decodeCmdFrame(buf: Buffer): { dataType: number; cmd: number; param1: number; param2: number } {
	const dataType = buf.readUInt32BE(8 + 8)
	const payload = buf.slice(8 + 24, buf.length - 8)
	return { dataType, cmd: payload[1], param1: payload.readUInt32BE(2), param2: payload.readUInt32BE(6) }
}

/** Extract the 120-byte CLIENT_INITINFO payload from a captured handshake frame. */
function extractHandshakePayload(buf: Buffer): Buffer {
	return buf.slice(8 + 24, 8 + 24 + 120)
}

/** Yield control to allow pending microtasks (promise chains) to settle. */
const flush = async (ticks = 5): Promise<void> => {
	for (let i = 0; i < ticks; i++) await Promise.resolve()
}

/** Create a client, open the TCP connection, and let the handshake send settle. */
async function connectClient(options: Partial<ConstructorParameters<typeof LHSClient>[0]> = {}): Promise<LHSClient> {
	const client = new LHSClient({ host: '127.0.0.1', ...options })
	client.connect()
	tcpIsConnected = true
	tcpHandlers['connect']()
	await flush()
	return client
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('LHSClient', () => {
	beforeEach(() => {
		vi.useFakeTimers()
		tcpHandlers = {}
		tcpIsConnected = false
		tcpConstructorCalls = []
		mockTCP.send.mockClear()
		mockTCP.send.mockReturnValue(true)
		mockTCP.destroy.mockClear()
	})

	afterEach(() => {
		vi.clearAllTimers()
		vi.useRealTimers()
		vi.clearAllMocks()
	})

	// ── Constructor / connect() ────────────────────────────────────────────

	describe('constructor and connect()', () => {
		it('uses the default port when none is given', () => {
			const client = new LHSClient({ host: '10.0.0.1' })
			client.connect()
			expect(tcpConstructorCalls[0]).toMatchObject({ host: '10.0.0.1', port: 5002 })
		})

		it('passes a custom port through to TCPHelper', () => {
			const client = new LHSClient({ host: '10.0.0.1', port: 6000 })
			client.connect()
			expect(tcpConstructorCalls[0].port).toBe(6000)
		})

		it('defaults reconnect to true and reconnectIntervalMs to 2000', () => {
			const client = new LHSClient({ host: '10.0.0.1' })
			client.connect()
			expect(tcpConstructorCalls[0].options).toMatchObject({ reconnect: true, reconnect_interval: 2000 })
		})

		it('passes custom reconnect options through to TCPHelper', () => {
			const client = new LHSClient({ host: '10.0.0.1', reconnect: false, reconnectIntervalMs: 500 })
			client.connect()
			expect(tcpConstructorCalls[0].options).toMatchObject({ reconnect: false, reconnect_interval: 500 })
		})

		it('does not recreate the TCP connection on a second connect() call', () => {
			const client = new LHSClient({ host: '10.0.0.1' })
			client.connect()
			client.connect()
			expect(tcpConstructorCalls).toHaveLength(1)
		})
	})

	describe('destroy()', () => {
		it('destroys the TCP connection and resets state', () => {
			const client = new LHSClient({ host: '10.0.0.1' })
			client.connect()
			client.destroy()
			expect(mockTCP.destroy).toHaveBeenCalledOnce()
		})

		it('does nothing harmful when called before connect()', () => {
			const client = new LHSClient({ host: '10.0.0.1' })
			expect(() => client.destroy()).not.toThrow()
			expect(mockTCP.destroy).not.toHaveBeenCalled()
		})

		it('allows connect() again after destroy()', () => {
			const client = new LHSClient({ host: '10.0.0.1' })
			client.connect()
			client.destroy()
			client.connect()
			expect(tcpConstructorCalls).toHaveLength(2)
		})

		it('stops the heartbeat timer', () => {
			const client = new LHSClient({ host: '10.0.0.1', heartbeatIntervalMs: 100 })
			client.connect()
			tcpIsConnected = true
			tcpHandlers['connect']()
			client.destroy()
			mockTCP.send.mockClear()
			vi.advanceTimersByTime(1000)
			expect(mockTCP.send).not.toHaveBeenCalled()
		})
	})

	// ── Handshake (CLIENT_INITINFO) ─────────────────────────────────────────

	describe('CLIENT_INITINFO handshake', () => {
		it('sends a correctly framed handshake on TCP connect', async () => {
			await connectClient()
			expect(mockTCP.send).toHaveBeenCalledOnce()
			const buf = mockTCP.send.mock.calls[0][0] as Buffer
			expect(buf.slice(0, 8)).toEqual(MAGIC_START)
			expect(buf.slice(buf.length - 8)).toEqual(MAGIC_END)
			expect(buf.readUInt32BE(8 + 8)).toBe(BLOCK.ClientInitInfo)
			expect(buf.readUInt32BE(8 + 12)).toBe(120) // payload length
		})

		it('encodes client type, versions, and protocol version', async () => {
			await connectClient()
			const payload = extractHandshakePayload(mockTCP.send.mock.calls[0][0] as Buffer)
			expect(payload.readUInt32BE(0)).toBe(0x00000002) // LIRSRV_CLIENT_MOBILE
			expect(payload.readUInt32BE(4)).toBe(0) // client vers major
			expect(payload.readUInt32BE(8)).toBe(0) // client vers minor
			expect(payload.readUInt32BE(12)).toBe(0) // client vers build
			expect(payload.readUInt32BE(16)).toBe(4) // protocol major
			expect(payload.readUInt32BE(20)).toBe(1) // protocol minor
		})

		it('uses the default client name when none is given', async () => {
			await connectClient()
			const payload = extractHandshakePayload(mockTCP.send.mock.calls[0][0] as Buffer)
			const progName = payload.slice(24, 88).toString('ascii').replace(/\0+$/, '')
			expect(progName).toBe('Companion LHS Client')
		})

		it('truncates a long client name to 63 characters', async () => {
			const longName = 'X'.repeat(100)
			await connectClient({ clientName: longName })
			const payload = extractHandshakePayload(mockTCP.send.mock.calls[0][0] as Buffer)
			const progName = payload.slice(24, 88).toString('ascii').replace(/\0+$/, '')
			expect(progName).toBe('X'.repeat(63))
		})

		it('defaults room name to empty and truncates a long room name to 31 characters', async () => {
			const longRoom = 'R'.repeat(50)
			await connectClient({ roomName: longRoom })
			const payload = extractHandshakePayload(mockTCP.send.mock.calls[0][0] as Buffer)
			const roomId = payload.slice(88, 120).toString('ascii').replace(/\0+$/, '')
			expect(roomId).toBe('R'.repeat(31))
		})
	})

	// ── SRV_INITINFO / "connected" event ────────────────────────────────────

	describe('SRV_INITINFO handling', () => {
		it('emits "connected" once a valid SRV_INITINFO is received', async () => {
			const client = await connectClient()
			const onConnected = vi.fn()
			client.on('connected', onConnected)

			tcpHandlers['data'](buildFrame(BLOCK.SrvInitInfo, buildSrvInitInfo()))

			expect(onConnected).toHaveBeenCalledOnce()
		})

		it('emits "connected" only once even if SRV_INITINFO is received again', async () => {
			const client = await connectClient()
			const onConnected = vi.fn()
			client.on('connected', onConnected)

			tcpHandlers['data'](buildFrame(BLOCK.SrvInitInfo, buildSrvInitInfo()))
			tcpHandlers['data'](buildFrame(BLOCK.SrvInitInfo, buildSrvInitInfo()))

			expect(onConnected).toHaveBeenCalledOnce()
		})

		it('emits "error" and does not emit "connected" when payload is too short', async () => {
			const client = await connectClient()
			const onConnected = vi.fn()
			const onError = vi.fn()
			client.on('connected', onConnected)
			client.on('error', onError)

			tcpHandlers['data'](buildFrame(BLOCK.SrvInitInfo, Buffer.alloc(50)))

			expect(onConnected).not.toHaveBeenCalled()
			expect(onError).toHaveBeenCalledOnce()
			expect((onError.mock.calls[0][0] as Error).message).toMatch(/too short/)
		})

		it('emits "error" and does not emit "connected" on unsupported protocol major version', async () => {
			const client = await connectClient()
			const onConnected = vi.fn()
			const onError = vi.fn()
			client.on('connected', onConnected)
			client.on('error', onError)

			tcpHandlers['data'](buildFrame(BLOCK.SrvInitInfo, buildSrvInitInfo({ protocolMajor: 3 })))

			expect(onConnected).not.toHaveBeenCalled()
			expect(onError).toHaveBeenCalledOnce()
			expect((onError.mock.calls[0][0] as Error).message).toMatch(/unsupported protocol version/)
		})
	})

	// ── RECORDERINFO / RECORDERINFO2 parsing ────────────────────────────────

	describe('recorder_state parsing', () => {
		it('parses a v1 RECORDERINFO with stateFlags = 0 (idle)', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			client.on('recorder_state', onState)

			tcpHandlers['data'](buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({ roomId: 'MainRoom', stateFlags: 0 })))

			expect(onState).toHaveBeenCalledOnce()
			const state = onState.mock.calls[0][0]
			expect(state.roomId).toBe('MainRoom')
			expect(state.courtId).toBe('')
			expect(state.isRecording).toBe(false)
			expect(state.isPaused).toBe(false)
		})

		it('parses stateFlags = RECORDING as isRecording=true, isPaused=false', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			client.on('recorder_state', onState)

			tcpHandlers['data'](
				buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({ stateFlags: RecorderStateFlags.RECORDING })),
			)

			const state = onState.mock.calls[0][0]
			expect(state.isRecording).toBe(true)
			expect(state.isPaused).toBe(false)
		})

		it('parses stateFlags = RECORDING|PAUSED as both true', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			client.on('recorder_state', onState)

			tcpHandlers['data'](
				buildFrame(
					BLOCK.RecorderInfo,
					buildRecorderInfo({ stateFlags: RecorderStateFlags.RECORDING | RecorderStateFlags.PAUSED }),
				),
			)

			const state = onState.mock.calls[0][0]
			expect(state.isRecording).toBe(true)
			expect(state.isPaused).toBe(true)
		})

		it('parses enabledFlags and alertFlags', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			client.on('recorder_state', onState)

			tcpHandlers['data'](buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({ enabledFlags: 0x0a, alertFlags: 0x05 })))

			const state = onState.mock.calls[0][0]
			expect(state.enabledFlags).toBe(0x0a)
			expect(state.alertFlags).toBe(0x05)
		})

		it('parses a v2 RECORDERINFO2 with a court ID', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			client.on('recorder_state', onState)

			tcpHandlers['data'](
				buildFrame(
					BLOCK.RecorderInfo2,
					buildRecorderInfo({
						roomId: 'Room1',
						isV2: true,
						courtId: 'Court9',
						stateFlags: RecorderStateFlags.RECORDING,
					}),
				),
			)

			const state = onState.mock.calls[0][0]
			expect(state.roomId).toBe('Room1')
			expect(state.courtId).toBe('Court9')
			expect(state.isRecording).toBe(true)
		})

		it('leaves courtId empty for a v1 RECORDERINFO', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			client.on('recorder_state', onState)

			tcpHandlers['data'](buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({})))

			expect(onState.mock.calls[0][0].courtId).toBe('')
		})

		it('emits "error" when roomIDRS terminator is missing', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			const onError = vi.fn()
			client.on('recorder_state', onState)
			client.on('error', onError)

			// No null byte anywhere in the payload.
			tcpHandlers['data'](buildFrame(BLOCK.RecorderInfo, Buffer.from([1, 2, 3, 4])))

			expect(onState).not.toHaveBeenCalled()
			expect(onError).toHaveBeenCalledOnce()
			expect((onError.mock.calls[0][0] as Error).message).toMatch(/missing roomIDRS terminator/)
		})

		it('emits "error" when payload is too short after the room ID', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			const onError = vi.fn()
			client.on('recorder_state', onState)
			client.on('error', onError)

			// Room terminator followed by only 3 bytes (need 20).
			tcpHandlers['data'](buildFrame(BLOCK.RecorderInfo, Buffer.from([0x00, 0x01, 0x02, 0x03])))

			expect(onState).not.toHaveBeenCalled()
			expect(onError).toHaveBeenCalledOnce()
			expect((onError.mock.calls[0][0] as Error).message).toMatch(/too short/)
		})
	})

	// ── Incoming Cmd handling ────────────────────────────────────────────────

	describe('incoming BlockType.Cmd handling', () => {
		it('does not throw for a known incoming command (NotifyRecorderRunning)', async () => {
			await connectClient()
			expect(() =>
				tcpHandlers['data'](buildFrame(BLOCK.Cmd, buildCmdPayload(CMD.NotifyRecorderRunning, 1))),
			).not.toThrow()
		})

		it('ignores a payload with no roomIDCmd terminator', async () => {
			const client = await connectClient()
			const onError = vi.fn()
			client.on('error', onError)
			expect(() => tcpHandlers['data'](buildFrame(BLOCK.Cmd, Buffer.from([1, 2, 3])))).not.toThrow()
			expect(onError).not.toHaveBeenCalled()
		})

		it('ignores a payload too short to contain btCmd + params', async () => {
			await connectClient()
			expect(() => tcpHandlers['data'](buildFrame(BLOCK.Cmd, Buffer.from([0x00, 0x01])))).not.toThrow()
		})

		it('emits "error" (without throwing) for an unrecognised command byte, and keeps parsing subsequent frames', async () => {
			const client = await connectClient()
			const onError = vi.fn()
			const onState = vi.fn()
			client.on('error', onError)
			client.on('recorder_state', onState)

			expect(() => tcpHandlers['data'](buildFrame(BLOCK.Cmd, buildCmdPayload(0xff, 0)))).not.toThrow()
			expect(onError).toHaveBeenCalledOnce()
			expect((onError.mock.calls[0][0] as Error).message).toMatch(/Invalid value/)

			// The receive buffer must still have advanced past the bad frame.
			tcpHandlers['data'](buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({ stateFlags: 1 })))
			expect(onState).toHaveBeenCalledOnce()
		})
	})

	// ── Unhandled / passthrough block types ─────────────────────────────────

	describe('unhandled block types', () => {
		it('does nothing for KeepAlive blocks', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			const onConnected = vi.fn()
			const onError = vi.fn()
			client.on('recorder_state', onState)
			client.on('connected', onConnected)
			client.on('error', onError)

			expect(() => tcpHandlers['data'](buildFrame(BLOCK.KeepAlive, Buffer.alloc(0)))).not.toThrow()
			expect(onState).not.toHaveBeenCalled()
			expect(onConnected).not.toHaveBeenCalled()
			expect(onError).not.toHaveBeenCalled()
		})

		it('does nothing for block types with no registered handler (e.g. FileInfo)', async () => {
			const client = await connectClient()
			const onError = vi.fn()
			client.on('error', onError)
			expect(() => tcpHandlers['data'](buildFrame(BLOCK.FileInfo, Buffer.from([1, 2, 3])))).not.toThrow()
			expect(onError).not.toHaveBeenCalled()
		})

		it('emits "error" (without throwing) for a completely unknown dataType, and keeps parsing subsequent frames', async () => {
			const client = await connectClient()
			const onError = vi.fn()
			const onState = vi.fn()
			client.on('error', onError)
			client.on('recorder_state', onState)

			expect(() => tcpHandlers['data'](buildFrame(99, Buffer.alloc(0)))).not.toThrow()
			expect(onError).toHaveBeenCalledOnce()
			expect((onError.mock.calls[0][0] as Error).message).toMatch(/Invalid value/)

			// The receive buffer must still have advanced past the bad frame.
			tcpHandlers['data'](buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({ stateFlags: 1 })))
			expect(onState).toHaveBeenCalledOnce()
		})
	})

	// ── Frame buffering edge cases ───────────────────────────────────────────

	describe('receive buffering', () => {
		it('dispatches multiple frames delivered in a single chunk', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			client.on('recorder_state', onState)

			const frame1 = buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({ stateFlags: 0 }))
			const frame2 = buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({ stateFlags: 1 }))
			tcpHandlers['data'](Buffer.concat([frame1, frame2]))

			expect(onState).toHaveBeenCalledTimes(2)
		})

		it('dispatches a frame split across two chunks', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			client.on('recorder_state', onState)

			const frame = buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({ stateFlags: 1 }))
			tcpHandlers['data'](frame.slice(0, 10))
			expect(onState).not.toHaveBeenCalled()
			tcpHandlers['data'](frame.slice(10))

			expect(onState).toHaveBeenCalledOnce()
		})

		it('discards garbage bytes preceding the start marker', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			client.on('recorder_state', onState)

			const frame = buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({ stateFlags: 1 }))
			tcpHandlers['data'](Buffer.concat([Buffer.from([0xaa, 0xbb, 0xcc]), frame]))

			expect(onState).toHaveBeenCalledOnce()
		})

		it('clears the receive buffer when no start marker is present', async () => {
			const client = await connectClient()
			const onState = vi.fn()
			client.on('recorder_state', onState)

			tcpHandlers['data'](Buffer.from([0x01, 0x02, 0x03, 0x04]))
			// A subsequent valid frame should still parse cleanly from an empty buffer.
			tcpHandlers['data'](buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({ stateFlags: 1 })))

			expect(onState).toHaveBeenCalledOnce()
		})

		it('emits "error" and resets the buffer on an invalid end marker', async () => {
			const client = await connectClient()
			const onError = vi.fn()
			client.on('error', onError)

			const frame = buildFrame(BLOCK.RecorderInfo, buildRecorderInfo({ stateFlags: 1 }))
			// Corrupt the last byte of the end marker.
			frame[frame.length - 1] = 0x00
			tcpHandlers['data'](frame)

			expect(onError).toHaveBeenCalledOnce()
			expect((onError.mock.calls[0][0] as Error).message).toMatch(/invalid end signature/)
		})
	})

	// ── Outgoing recording commands ──────────────────────────────────────────

	describe('recording commands', () => {
		async function connectedAndReady(): Promise<LHSClient> {
			const client = new LHSClient({ host: '10.0.0.1' })
			client.connect()
			tcpIsConnected = true
			mockTCP.send.mockClear()
			return client
		}

		it('newFile() sends Cmd.NewFile with param 0', async () => {
			const client = await connectedAndReady()
			await client.newFile()
			const { dataType, cmd, param1 } = decodeCmdFrame(mockTCP.send.mock.calls[0][0] as Buffer)
			expect(dataType).toBe(BLOCK.Cmd)
			expect(cmd).toBe(CMD.NewFile)
			expect(param1).toBe(0)
		})

		it('startRecording() sends Cmd.RecAction with StartRec', async () => {
			const client = await connectedAndReady()
			await client.startRecording()
			const { cmd, param1 } = decodeCmdFrame(mockTCP.send.mock.calls[0][0] as Buffer)
			expect(cmd).toBe(CMD.RecAction)
			expect(param1).toBe(REC_ACTION.StartRec)
		})

		it('stopRecording() sends Cmd.RecAction with StopRec', async () => {
			const client = await connectedAndReady()
			await client.stopRecording()
			const { cmd, param1 } = decodeCmdFrame(mockTCP.send.mock.calls[0][0] as Buffer)
			expect(cmd).toBe(CMD.RecAction)
			expect(param1).toBe(REC_ACTION.StopRec)
		})

		it('pauseRecording() sends Cmd.PauseAction with Pause', async () => {
			const client = await connectedAndReady()
			await client.pauseRecording()
			const { cmd, param1 } = decodeCmdFrame(mockTCP.send.mock.calls[0][0] as Buffer)
			expect(cmd).toBe(CMD.PauseAction)
			expect(param1).toBe(PAUSE_ACTION.Pause)
		})

		it('continueRecording() sends Cmd.PauseAction with Continue', async () => {
			const client = await connectedAndReady()
			await client.continueRecording()
			const { cmd, param1 } = decodeCmdFrame(mockTCP.send.mock.calls[0][0] as Buffer)
			expect(cmd).toBe(CMD.PauseAction)
			expect(param1).toBe(PAUSE_ACTION.Continue)
		})

		it('pauseContRecording() sends Cmd.PauseAction with Toggle', async () => {
			const client = await connectedAndReady()
			await client.pauseContRecording()
			const { cmd, param1 } = decodeCmdFrame(mockTCP.send.mock.calls[0][0] as Buffer)
			expect(cmd).toBe(CMD.PauseAction)
			expect(param1).toBe(PAUSE_ACTION.Toggle)
		})

		it('closeFile() sends Cmd.StopRec with param 0', async () => {
			const client = await connectedAndReady()
			await client.closeFile()
			const { cmd, param1 } = decodeCmdFrame(mockTCP.send.mock.calls[0][0] as Buffer)
			expect(cmd).toBe(CMD.StopRec)
			expect(param1).toBe(0)
		})
	})

	// ── insertBookmark() ──────────────────────────────────────────────────────

	describe('insertBookmark()', () => {
		async function connectedAndReady(
			options: Partial<ConstructorParameters<typeof LHSClient>[0]> = {},
		): Promise<LHSClient> {
			const client = new LHSClient({ host: '10.0.0.1', ...options })
			client.connect()
			tcpIsConnected = true
			mockTCP.send.mockClear()
			return client
		}

		it('sends a BmInfo2 block with the room name and note', async () => {
			const client = await connectedAndReady({ roomName: 'RoomA' })
			await client.insertBookmark('hi')

			const buf = mockTCP.send.mock.calls[0][0] as Buffer
			const dataType = buf.readUInt32BE(8 + 8)
			expect(dataType).toBe(BLOCK.BmInfo2)

			const payload = buf.slice(8 + 24, buf.length - 8)
			const roomEnd = payload.indexOf(0x00)
			expect(payload.slice(0, roomEnd).toString('ascii')).toBe('RoomA')

			// header: bmId(4 BE) + btBmType + btReadOnlyBM + btUsedCaseFields
			const header = payload.slice(roomEnd + 1, roomEnd + 1 + 7)
			expect(header[4]).toBe(0x02) // BOOKMARK_TYPE_OTHER
			expect(header[5]).toBe(0x00)
			expect(header[6]).toBe(0x00)

			// The note text should appear somewhere in the field records.
			expect(payload.includes(Buffer.from('hi', 'ascii'))).toBe(true)
		})

		it('increments the bookmark ID on each call', async () => {
			const client = await connectedAndReady()
			await client.insertBookmark('a')
			const firstId = (mockTCP.send.mock.calls[0][0] as Buffer).readUInt32BE(8 + 24 + 1)

			mockTCP.send.mockClear()
			await client.insertBookmark('b')
			const secondId = (mockTCP.send.mock.calls[0][0] as Buffer).readUInt32BE(8 + 24 + 1)

			expect(secondId).toBe(firstId + 1)
		})

		it('defaults to an empty note', async () => {
			const client = await connectedAndReady()
			await expect(client.insertBookmark()).resolves.not.toThrow()
		})
	})

	// ── Heartbeat ─────────────────────────────────────────────────────────────

	describe('heartbeat', () => {
		it('starts sending heartbeats on TCP connect, before the handshake is acknowledged', async () => {
			const client = new LHSClient({ host: '10.0.0.1', heartbeatIntervalMs: 100 })
			client.connect()
			tcpIsConnected = true
			tcpHandlers['connect']()
			await flush()
			mockTCP.send.mockClear()

			vi.advanceTimersByTime(100)
			await flush()

			expect(mockTCP.send).toHaveBeenCalledTimes(2)
			const first = decodeCmdFrame(mockTCP.send.mock.calls[0][0] as Buffer)
			const second = decodeCmdFrame(mockTCP.send.mock.calls[1][0] as Buffer)
			expect(first.cmd).toBe(CMD.HeartbeatA)
			expect(first.param1).toBe(0)
			expect(second.cmd).toBe(CMD.HeartbeatB)
			expect(second.param1).toBe(0)
		})

		it('uses the default 3000ms interval when none is given', async () => {
			const client = new LHSClient({ host: '10.0.0.1' })
			client.connect()
			tcpIsConnected = true
			tcpHandlers['connect']()
			await flush()
			mockTCP.send.mockClear()

			vi.advanceTimersByTime(2999)
			await flush()
			expect(mockTCP.send).not.toHaveBeenCalled()

			vi.advanceTimersByTime(1)
			await flush()
			expect(mockTCP.send).toHaveBeenCalledTimes(2)
		})

		it('skips sending heartbeats while the socket is not connected', async () => {
			const client = new LHSClient({ host: '10.0.0.1', heartbeatIntervalMs: 100 })
			client.connect()
			tcpIsConnected = true
			tcpHandlers['connect']()
			await flush()

			tcpIsConnected = false
			mockTCP.send.mockClear()
			vi.advanceTimersByTime(300)
			await flush()

			expect(mockTCP.send).not.toHaveBeenCalled()
		})

		it('resets the receive buffer, handshakeAcknowledged flag, and queue on reconnect', async () => {
			const client = await connectClient({ heartbeatIntervalMs: 100 })
			tcpHandlers['data'](buildFrame(BLOCK.SrvInitInfo, buildSrvInitInfo()))

			const onConnected = vi.fn()
			client.on('connected', onConnected)

			// Simulate TCPHelper reconnecting: 'connect' fires again.
			tcpHandlers['connect']()
			await flush()
			tcpHandlers['data'](buildFrame(BLOCK.SrvInitInfo, buildSrvInitInfo()))

			// handshakeAcknowledged was reset, so "connected" fires again.
			expect(onConnected).toHaveBeenCalledOnce()
		})
	})

	// ── Send guard ────────────────────────────────────────────────────────────

	describe('send guard when not connected', () => {
		it('emits "error" and does not call tcp.send() when never connected', async () => {
			const client = new LHSClient({ host: '10.0.0.1' })
			const onError = vi.fn()
			client.on('error', onError)

			await client.newFile()

			expect(onError).toHaveBeenCalledOnce()
			expect((onError.mock.calls[0][0] as Error).message).toMatch(/not connected/)
			expect(mockTCP.send).not.toHaveBeenCalled()
		})

		it('emits "error" when the TCP socket drops before sending', async () => {
			const client = new LHSClient({ host: '10.0.0.1' })
			client.connect()
			tcpIsConnected = false // constructed but never actually connected

			const onError = vi.fn()
			client.on('error', onError)

			await client.startRecording()

			expect(onError).toHaveBeenCalledOnce()
			expect(mockTCP.send).not.toHaveBeenCalled()
		})
	})

	// ── Event forwarding ──────────────────────────────────────────────────────

	describe('event forwarding', () => {
		it('forwards status_change events from the TCP connection', () => {
			const client = new LHSClient({ host: '10.0.0.1' })
			client.connect()
			const onStatus = vi.fn()
			client.on('status_change', onStatus)

			tcpHandlers['status_change']('Ok', 'all good')

			expect(onStatus).toHaveBeenCalledWith('Ok', 'all good')
		})

		it('forwards error events from the TCP connection', () => {
			const client = new LHSClient({ host: '10.0.0.1' })
			client.connect()
			const onError = vi.fn()
			client.on('error', onError)

			const err = new Error('socket boom')
			tcpHandlers['error'](err)

			expect(onError).toHaveBeenCalledWith(err)
		})

		it('emits "disconnected" and stops the heartbeat when TCP ends', async () => {
			const client = new LHSClient({ host: '10.0.0.1', heartbeatIntervalMs: 100 })
			client.connect()
			tcpIsConnected = true
			tcpHandlers['connect']()
			await flush()

			const onDisconnected = vi.fn()
			client.on('disconnected', onDisconnected)

			tcpIsConnected = false
			tcpHandlers['end']()

			expect(onDisconnected).toHaveBeenCalledOnce()

			mockTCP.send.mockClear()
			vi.advanceTimersByTime(1000)
			await flush()
			expect(mockTCP.send).not.toHaveBeenCalled()
		})
	})

	// ── RecorderStateFlags ────────────────────────────────────────────────────

	describe('RecorderStateFlags', () => {
		it('exposes the RECORDING and PAUSED bit values', () => {
			expect(RecorderStateFlags.RECORDING).toBe(0x01)
			expect(RecorderStateFlags.PAUSED).toBe(0x02)
		})
	})
})
