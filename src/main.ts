import { InstanceBase, runEntrypoint, InstanceStatus, SomeCompanionConfigField } from '@companion-module/base'
import { GetConfigFields, type ModuleConfig } from './config.js'
import { UpdateVariableDefinitions } from './variables.js'
import { UpgradeScripts } from './upgrades.js'
import { UpdateActions } from './actions.js'
import { UpdateFeedbacks, FeedbackId } from './feedbacks.js'
import { UpdatePresets } from './presets.js'
import { LHSClient, type RecorderState } from './lhs.js'

export class ModuleInstance extends InstanceBase<ModuleConfig> {
	private config!: ModuleConfig // Setup in init()
	public client!: LHSClient
	public recorders: Map<string, RecorderState> = new Map()

	constructor(internal: unknown) {
		super(internal)
	}

	public async init(config: ModuleConfig): Promise<void> {
		this.config = config

		this.updateStatus(InstanceStatus.Connecting)

		this.updateActions() // export actions
		this.updateFeedbacks() // export feedbacks
		this.updatePresets() // export Presets
		this.updateVariableDefinitions() // export variable definitions
		this.setupClient(config)
	}
	// When module gets deleted
	public async destroy(): Promise<void> {
		this.log('debug', `destroy ${this.id}: ${this.label}\n Process: ${process.pid}`)
		this.client.destroy()
	}

	public async configUpdated(config: ModuleConfig): Promise<void> {
		this.config = config
		this.setupClient(this.config)
	}

	// Return config fields for web config
	public getConfigFields(): SomeCompanionConfigField[] {
		return GetConfigFields()
	}

	private setupClient(config: ModuleConfig): void {
		if (this.client) {
			this.client.destroy()
			this.client.removeAllListeners()
		}
		this.client = new LHSClient({
			host: config.host,
			port: config.port,
			clientName: config.client,
			roomName: config.room,
		})

		this.client.on('status_change', (status, message) => {
			this.updateStatus(status, message)
		})
		this.client.on('error', (err) => {
			this.log('error', err.message)
		})
		this.client.on('recorder_state', (state) => {
			this.log('info', `Recorder State Changed: ${JSON.stringify(state)}`)
			const oldState = this.recorders.get(state.roomId || this.config.room)
			this.recorders.set(state.roomId || this.config.room, state)
			if (state.roomId == this.config.room || state.roomId == '') {
				const feedbacksToCheck: FeedbackId[] = []
				if (oldState?.isPaused != state.isPaused) feedbacksToCheck.push(FeedbackId.isPaused)
				if (oldState?.isRecording != state.isRecording) feedbacksToCheck.push(FeedbackId.isRecording)
				if (feedbacksToCheck.length > 0) this.checkFeedbacks(...feedbacksToCheck)
			}
		})
		this.client.on('connected', () => {
			this.log('info', `Connected to ${config.host}:${config.port}`)
		})
		this.client.on('disconnected', () => {
			this.log('warn', `Disconnected from ${config.host}:${config.port}`)
		})
		this.client.connect()
	}

	public get room(): Readonly<string> {
		return this.config?.room ?? ''
	}

	private updateActions(): void {
		UpdateActions(this)
	}

	private updateFeedbacks(): void {
		UpdateFeedbacks(this)
	}

	private updatePresets(): void {
		UpdatePresets(this)
	}

	private updateVariableDefinitions(): void {
		UpdateVariableDefinitions(this)
	}
}

runEntrypoint(ModuleInstance, UpgradeScripts)
