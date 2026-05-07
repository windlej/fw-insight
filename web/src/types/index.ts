export interface Session {
  id: string
  vendor: string
  vendor_version: string | null
  hostname: string | null
  parsed_at: string
  source_filename: string | null
  source_checksum: string | null
  labels: Record<string, string>
  metadata: Record<string, unknown>
  security_policies: SecurityPolicy[]
  nat_rules: NATRule[]
  interfaces: Interface[]
  zones: Zone[]
  address_objects: AddressObject[]
  service_objects: ServiceObject[]
  health_score: number
  finding_counts: Record<string, number>
  created_at: string
}

export interface SessionSummary {
  id: string
  vendor: string
  vendor_version: string | null
  hostname: string | null
  parsed_at: string
  source_filename: string | null
  source_checksum: string | null
  labels: Record<string, string>
  health_score: number
  finding_counts: Record<string, number>
  rule_count: number
  created_at: string
}

export interface SecurityPolicy {
  id: string
  name: string | null
  position: number
  source: RuleEndpoint
  destination: RuleEndpoint
  services: ServiceRef[]
  action: string
  enabled: boolean
  logging: Record<string, boolean>
  schedule: string | null
  description: string | null
  vendor_raw: Record<string, unknown>
}

export interface RuleEndpoint {
  addresses: string[]
  zones: string[]
  users: string[] | null
}

export interface ServiceRef {
  protocol: string
  ports: string[]
}

export interface NATRule {
  id: string
  name: string | null
  position: number
  type: string
  original_source: string | null
  translated_source: string | null
  original_destination: string | null
  translated_destination: string | null
  original_service: ServiceRef | null
  translated_service: ServiceRef | null
  enabled: boolean
  vendor_raw: Record<string, unknown>
}

export interface Interface {
  name: string
  type: string
  enabled: boolean
  ip_addresses: string[]
  zone: string | null
  description: string | null
  vendor_raw: Record<string, unknown>
}

export interface Zone {
  name: string
  type: string | null
  interfaces: string[]
  vendor_raw: Record<string, unknown>
}

export interface AddressObject {
  name: string
  type: string
  value: string
  members: string[] | null
  description: string | null
  vendor_raw: Record<string, unknown>
}

export interface ServiceObject {
  name: string
  protocol: string
  ports: string[]
  description: string | null
  vendor_raw: Record<string, unknown>
}

export interface Finding {
  id: string
  check_id: string
  severity: string
  category: string
  title: string
  description: string
  entity_id: string
  entity_type: string
  references: string[]
  related_entity_ids: string[]
}

export interface AnalysisResult {
  session_id: string
  health_score: number
  finding_counts: Record<string, number>
  findings: Finding[]
}

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#2563eb',
  info: '#6b7280',
}
