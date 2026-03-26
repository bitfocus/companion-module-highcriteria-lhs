import { Regex, type SomeCompanionConfigField } from '@companion-module/base'

export interface ModuleConfig {
	host: string
	port: number
	client: string
	room: string
}

export function GetConfigFields(): SomeCompanionConfigField[] {
	return [
		{
			type: 'textinput',
			id: 'host',
			label: 'LHS Host',
			width: 8,
			regex: Regex.HOSTNAME,
		},
		{
			type: 'number',
			id: 'port',
			label: 'Target Port',
			width: 4,
			min: 1,
			max: 65535,
			default: 5002,
		},
		{
			type: 'textinput',
			id: 'client',
			label: 'Client Name',
			width: 8,
			regex: '/^[ -~]{0,63}$/',
			default: 'Companion',
		},
		{
			type: 'textinput',
			id: 'room',
			label: 'Room',
			width: 8,
			regex: '/^[ -~]{0,31}$/',
		},
	]
}
