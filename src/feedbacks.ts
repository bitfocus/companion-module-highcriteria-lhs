import { type CompanionFeedbackDefinitions, combineRgb } from '@companion-module/base'
import type ModuleInstance from './main.js'

export enum FeedbackId {
	isRecording = 'recording',
	isPaused = 'paused',
}

export type FeedbackSchema = {
	[FeedbackId.isRecording]: {
		type: 'boolean'
		// eslint-disable-next-line @typescript-eslint/no-empty-object-type
		options: {}
	}
	[FeedbackId.isPaused]: {
		type: 'boolean'
		// eslint-disable-next-line @typescript-eslint/no-empty-object-type
		options: {}
	}
}

const defaultStyle = {
	bgcolor: combineRgb(255, 0, 0),
	color: combineRgb(0, 0, 0),
}

export function UpdateFeedbacks(self: ModuleInstance): void {
	const feedbacks: CompanionFeedbackDefinitions<FeedbackSchema> = {
		[FeedbackId.isPaused]: {
			name: 'Paused',
			type: 'boolean',
			defaultStyle: defaultStyle,
			options: [],
			callback: (_event): boolean => {
				return self.recorders.get(self.room)?.isPaused ?? false
			},
		},
		[FeedbackId.isRecording]: {
			name: 'Recording',
			type: 'boolean',
			defaultStyle: defaultStyle,
			options: [],
			callback: (_event): boolean => {
				return self.recorders.get(self.room)?.isRecording ?? false
			},
		},
	}
	self.setFeedbackDefinitions(feedbacks)
}
