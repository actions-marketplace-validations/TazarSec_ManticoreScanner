package api

import "time"

type Ecosystem string

const (
	EcosystemNPM      Ecosystem = "npm"
	EcosystemPyPI     Ecosystem = "pypi"
	EcosystemRubyGems Ecosystem = "rubygems"
	EcosystemCrates   Ecosystem = "crates"
	EcosystemMaven    Ecosystem = "maven"
	EcosystemGo       Ecosystem = "go"
)

type ScanStatus string

const (
	StatusCompleted  ScanStatus = "completed"
	StatusInProgress ScanStatus = "in_progress"
	StatusQueued     ScanStatus = "queued"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Phase string

const (
	PhaseInstall Phase = "install"
	PhaseRequire Phase = "require"
)

type ScanRequestItem struct {
	Package   string    `json:"package,omitempty"`
	Version   string    `json:"version,omitempty"`
	Ecosystem Ecosystem `json:"ecosystem,omitempty"`
	Hash      string    `json:"hash,omitempty"`
}

type ScanRequest struct {
	Packages []ScanRequestItem `json:"packages"`
}

type ReasonType string

const (
	ReasonScanIntegrity                     ReasonType = "scan_integrity"
	ReasonIndicatorMatch                    ReasonType = "indicator_match"
	ReasonUnknownNetwork                    ReasonType = "unknown_network"
	ReasonUnknownDNS                        ReasonType = "unknown_dns"
	ReasonSensitiveFileAccess               ReasonType = "sensitive_file_access"
	ReasonSuspiciousProcess                 ReasonType = "suspicious_process"
	ReasonUnknownProcess                    ReasonType = "unknown_process"
	ReasonSensitiveEnvAccess                ReasonType = "sensitive_env_access"
	ReasonInstallScriptsWithNetwork         ReasonType = "install_scripts_with_network"
	ReasonInstallScriptsWithSensitiveAccess ReasonType = "install_scripts_with_sensitive_access"
	ReasonCredentialExfiltration            ReasonType = "credential_exfiltration"
	ReasonDropperPattern                    ReasonType = "dropper_pattern"
	ReasonNewNetwork                        ReasonType = "new_network"
	ReasonNewDNS                            ReasonType = "new_dns"
	ReasonNewProcess                        ReasonType = "new_process"
)

type ItemErrorCode string

const (
	ErrQueueFull           ItemErrorCode = "queue_full"
	ErrPackageNotFound     ItemErrorCode = "package_not_found"
	ErrRegistryUnavailable ItemErrorCode = "registry_unavailable"
	ErrHashMismatch        ItemErrorCode = "hash_mismatch"
	ErrHashUnverifiable    ItemErrorCode = "hash_unverifiable"
	ErrNoProfileForHash    ItemErrorCode = "no profile found for hash"
	ErrInternal            ItemErrorCode = "internal error"
)

type Classification string

const (
	ClassExpected       Classification = "expected"
	ClassInfrastructure Classification = "infrastructure"
	ClassRegistry       Classification = "registry"
	ClassSensitive      Classification = "sensitive"
	ClassSuspicious     Classification = "suspicious"
	ClassBenign         Classification = "benign"
	ClassUnknown        Classification = "unknown"
	ClassMalicious      Classification = "malicious"
)

type SuspicionReason struct {
	Type     ReasonType `json:"type"`
	Detail   string     `json:"detail"`
	Severity Severity   `json:"severity"`
	Phase    Phase      `json:"phase"`
}

type NetworkSummaryEntry struct {
	DstIP          string         `json:"dst_ip,omitempty"`
	DstPort        int            `json:"dst_port,omitempty"`
	Protocol       string         `json:"protocol,omitempty"`
	Direction      string         `json:"direction,omitempty"`
	Count          int            `json:"count,omitempty"`
	PIDs           []int          `json:"pids,omitempty"`
	Classification Classification `json:"classification,omitempty"`
}

type DnsSummaryEntry struct {
	Query          string         `json:"query,omitempty"`
	Type           string         `json:"type,omitempty"`
	ResolvedIPs    []string       `json:"resolved_ips,omitempty"`
	Outcome        string         `json:"outcome,omitempty"`
	PIDs           []int          `json:"pids,omitempty"`
	Classification Classification `json:"classification,omitempty"`
}

type FileSummaryEntry struct {
	Path           string         `json:"path,omitempty"`
	Operation      string         `json:"operation,omitempty"`
	Count          int            `json:"count,omitempty"`
	PIDs           []int          `json:"pids,omitempty"`
	Classification Classification `json:"classification,omitempty"`
}

type ProcessInstance struct {
	PID  int `json:"pid,omitempty"`
	PPID int `json:"ppid,omitempty"`
}

type ProcessSummaryEntry struct {
	Binary         string            `json:"binary,omitempty"`
	BinarySHA256   string            `json:"binary_sha256,omitempty"`
	Args           []string          `json:"args,omitempty"`
	ScriptPath     string            `json:"script_path,omitempty"`
	ScriptSHA256   string            `json:"script_sha256,omitempty"`
	Parent         *string           `json:"parent,omitempty"`
	Instances      []ProcessInstance `json:"instances,omitempty"`
	Count          int               `json:"count,omitempty"`
	Classification Classification    `json:"classification,omitempty"`
}

type EnvVarEntry struct {
	Name      string `json:"name,omitempty"`
	Count     int    `json:"count,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
	PIDs      []int  `json:"pids,omitempty"`
}

type EnvAccessSummary struct {
	Vars []EnvVarEntry `json:"vars,omitempty"`
}

type PhaseSummary struct {
	ExitCode  int                   `json:"exit_code"`
	Network   []NetworkSummaryEntry `json:"network,omitempty"`
	DNS       []DnsSummaryEntry     `json:"dns,omitempty"`
	Files     []FileSummaryEntry    `json:"files,omitempty"`
	Processes []ProcessSummaryEntry `json:"processes,omitempty"`
	EnvAccess *EnvAccessSummary     `json:"env_access,omitempty"`
}

type Profile struct {
	Ecosystem              string            `json:"ecosystem"`
	PackageName            string            `json:"package_name"`
	Version                string            `json:"version"`
	SuspicionScore         float64           `json:"suspicion_score"`
	SuspicionReasons       []SuspicionReason `json:"suspicion_reasons"`
	HasUnknownNetwork      bool              `json:"has_unknown_network"`
	HasSensitiveFileAccess bool              `json:"has_sensitive_file_access"`
	HasUnexpectedProcess   bool              `json:"has_unexpected_processes"`
	ScannedAt              time.Time         `json:"scanned_at"`
	InstallPhase           *PhaseSummary     `json:"install_phase,omitempty"`
	RequirePhase           *PhaseSummary     `json:"require_phase,omitempty"`
}

type BatchResultItem struct {
	Package   string        `json:"package,omitempty"`
	Version   string        `json:"version,omitempty"`
	Ecosystem string        `json:"ecosystem,omitempty"`
	Hash      string        `json:"hash,omitempty"`
	Status    ScanStatus    `json:"status"`
	Profile   *Profile      `json:"profile,omitempty"`
	Error     ItemErrorCode `json:"error,omitempty"`
}

type BatchResponse struct {
	Results []BatchResultItem `json:"results"`
}

type APIError struct {
	Error string `json:"error"`
}
