import type ModuleInstance from './main.js'
import type { CompanionActionDefinitions } from '@companion-module/base'

export enum ActionId {
	NewFile = 'new_file',
	CloseFile = 'close_file',
	StartRecording = 'start_recording',
	StopRecording = 'stop_recording',
	PauseRecording = 'pause_recording',
	//InsertBookmark = 'insert_bookmark',
}

export type ActionSchema = {
	[ActionId.NewFile]: {
		// eslint-disable-next-line @typescript-eslint/no-empty-object-type
		options: {}
	}
	[ActionId.CloseFile]: {
		// eslint-disable-next-line @typescript-eslint/no-empty-object-type
		options: {}
	}
	[ActionId.StartRecording]: {
		// eslint-disable-next-line @typescript-eslint/no-empty-object-type
		options: {}
	}
	[ActionId.StopRecording]: {
		// eslint-disable-next-line @typescript-eslint/no-empty-object-type
		options: {}
	}
	[ActionId.PauseRecording]: {
		options: {
			method: 'pause' | 'resume' | 'toggle'
		}
	}
}

export function UpdateActions(self: ModuleInstance): void {
	const actions: CompanionActionDefinitions<ActionSchema> = {
		[ActionId.NewFile]: {
			name: 'File: New',
			options: [],
			callback: async (event) => {
				self.log('info', `${event.actionId}:${event.id}`)
				await self.client.newFile()
			},
		},
		[ActionId.CloseFile]: {
			name: 'File: Stop & Close File',
			options: [],
			callback: async (event) => {
				self.log('info', `${event.actionId}:${event.id}`)
				await self.client.closeFile()
			},
		},
		[ActionId.StartRecording]: {
			name: 'Recording: Start',
			options: [],
			callback: async (event) => {
				self.log('info', `${event.actionId}:${event.id}`)
				await self.client.startRecording()
			},
		},
		[ActionId.StopRecording]: {
			name: 'Recording: Stop',
			options: [],
			callback: async (_event) => {
				self.log('info', 'Record: Stop')
				await self.client.stopRecording()
			},
		},
		[ActionId.PauseRecording]: {
			name: 'Recording: Pause',
			options: [
				{
					type: 'dropdown',
					id: 'method',
					label: 'Method',
					default: 'pause',
					choices: [
						{ id: 'pause', label: 'Pause' },
						{ id: 'resume', label: 'Resume' },
						{ id: 'toggle', label: 'Toggle' },
					],
					allowCustom: false,
					expressionDescription: `Return: pause | resume | toggle`,
				},
			],
			callback: async (event) => {
				self.log('info', `${event.actionId}:${event.id}- ${event.options.method}`)
				const method = event.options.method?.toString()
				switch (method) {
					case 'pause':
						await self.client.pauseRecording()
						break
					case 'resume':
						await self.client.continueRecording()
						break
					case 'toggle':
						await self.client.pauseContRecording()
						break
					default:
						throw new Error(`Invalid selection: ${method} aborting action...`)
				}
			},
		},
		/* [ActionId.InsertBookmark]: {
			name: 'Bookmark: Insert',
			options: [
				{
					type: 'textinput',
					id: 'note',
					label: 'Note',
					useVariables: { local: true },
					multiline: true,
					default: '',
				},
			],
			callback: async (event) => {
				self.log('info', `${event.actionId}:${event.id} - ${event.options.note}`)
				await self.client.insertBookmark(event.options.note?.toString())
			},
		}, */
	}
	self.setActionDefinitions(actions)
}
