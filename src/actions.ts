import type { ModuleInstance } from './main.js'
import type { CompanionActionDefinition } from '@companion-module/base'

export enum ActionId {
	NewFile = 'new_file',
	//  CloseFile = 'close_file',
	StartRecording = 'start_recording',
	StopRecording = 'stop_recording',
	PauseRecording = 'pause_recording',
	InsertBookmark = 'insert_bookmark',
}

export function UpdateActions(self: ModuleInstance): void {
	const actions: Record<ActionId, CompanionActionDefinition> = {
		[ActionId.NewFile]: {
			name: 'File: New',
			options: [],
			callback: async (event) => {
				self.log('info', `${event.actionId}:${event.id}`)
				await self.client.newFile()
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
			name: 'Recording: Stop & Close File',
			options: [],
			callback: async (_event) => {
				self.log('info', 'Record: Stop & Close File')
				await self.client.stopRecording()
			},
		},
		[ActionId.PauseRecording]: {
			name: 'Recording: Pause',
			options: [],
			callback: async (event) => {
				self.log('info', `${event.actionId}:${event.id}`)
				await self.client.pauseRecording()
			},
		},
		[ActionId.InsertBookmark]: {
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
		},
	}
	self.setActionDefinitions(actions)
}
