import type { ModuleInstance } from './main.js'
import type { CompanionVariableDefinition } from '@companion-module/base'

export function UpdateVariableDefinitions(self: ModuleInstance): void {
	const variables: CompanionVariableDefinition[] = []
	self.setVariableDefinitions(variables)
}
