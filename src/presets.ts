import type { ModuleInstance } from './main.js'
import { CompanionPresetDefinitions } from '@companion-module/base'

export function UpdatePresets(self: ModuleInstance): void {
	const presets: CompanionPresetDefinitions = {}

	self.setPresetDefinitions(presets)
}
