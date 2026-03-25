import { type CompanionFeedbackDefinition } from '@companion-module/base'
import type { ModuleInstance } from './main.js'

export function UpdateFeedbacks(self: ModuleInstance): void {
	const feedbacks: Record<string, CompanionFeedbackDefinition> = {}
	self.setFeedbackDefinitions(feedbacks)
}
