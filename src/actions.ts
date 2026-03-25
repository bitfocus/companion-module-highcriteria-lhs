import type { ModuleInstance } from './main.js'
import type { CompanionActionDefinition } from '@companion-module/base'

export enum ActionId {
	NewFile = 'new_file',
	StartRecording = 'start_recording',
	StopRecording = 'stop_recording',
	PauseRecording = 'pause_recording',
	InsertBookmark = 'insert_bookmark',
}

export function UpdateActions(self: ModuleInstance): void {
	const actions: Record<ActionId, CompanionActionDefinition> = {
		[ActionId.NewFile]: {
			name: 'New File',
			options: [],
			callback: async (_event) => {
				self.log('info', 'Preparing new file')
				await self.client.newFile()
			},
		},
		[ActionId.StartRecording]: {
			name: 'Start Recording',
			options: [],
			callback: async (_event) => {
				self.log('info', 'Starting Recording')
				await self.client.startRecording()
			},
		},
		[ActionId.StopRecording]: {
			name: 'Stop Recording',
			options: [],
			callback: async (_event) => {
				self.log('info', 'Stopping Recording')
				await self.client.stopRecording()
			},
		},
		[ActionId.PauseRecording]: {
			name: 'Pause Recording',
			options: [],
			callback: async (_event) => {
				self.log('info', 'Pauseing Recording')
				await self.client.pauseRecording()
			},
		},
		[ActionId.InsertBookmark]: {
			name: 'Insert Bookmark',
			options: [],
			callback: async (_event) => {
				self.log('info', 'Inserting Bookmark')
				await self.client.insertBookmark()
			},
		},
	}
	self.setActionDefinitions(actions)
}
