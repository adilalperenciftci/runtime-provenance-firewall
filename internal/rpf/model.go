package rpf

const (
	EventSchema      = "0.2"
	ManifestSchema   = "0.1"
	StatementType    = "https://in-toto.io/Statement/v1"
	RuntimePredicate = "https://in-toto.io/attestation/runtime-trace/v0.1"
	SLSAPredicate    = "https://slsa.dev/provenance/v1"
	CorrelationKey   = "https://github.com/adilalperenciftci/runtime-provenance-firewall/runtime-provenance/v0.1"
	BuildIdentityKey = "https://github.com/adilalperenciftci/runtime-provenance-firewall/build-identity/v0.1"
	zeroHash         = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

type BuildScope struct {
	BuildID        string         `json:"build_id"`
	RunID          string         `json:"run_id"`
	Source         SourceIdentity `json:"source"`
	BootID         string         `json:"boot_id"`
	CgroupID       uint64         `json:"cgroup_id"`
	CgroupPathHash string         `json:"cgroup_path_hash"`
}

type Executable struct {
	Path         string `json:"path"`
	Identity     string `json:"identity"`
	IdentityKind string `json:"identity_kind"`
}

type Process struct {
	ProcessKey     string     `json:"process_key"`
	ParentKey      string     `json:"parent_key,omitempty"`
	PID            uint32     `json:"pid"`
	TGID           uint32     `json:"tgid"`
	PPID           uint32     `json:"ppid"`
	StartTimeNS    uint64     `json:"start_time_ns"`
	PIDNamespace   uint64     `json:"pid_namespace"`
	MountNamespace uint64     `json:"mount_namespace"`
	UID            uint32     `json:"uid"`
	GID            uint32     `json:"gid"`
	Executable     Executable `json:"executable"`
}

type Outcome struct {
	Status string `json:"status"`
	Errno  int32  `json:"errno"`
}

type Sensor struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	ConfigDigest string `json:"config_digest"`
}

type Integrity struct {
	PreviousEventHash string `json:"previous_event_hash"`
	EventHash         string `json:"event_hash"`
}

type Event struct {
	SchemaVersion string         `json:"schema_version"`
	EventID       string         `json:"event_id"`
	Sequence      uint64         `json:"sequence"`
	ObservedAt    string         `json:"observed_at"`
	MonotonicNS   uint64         `json:"monotonic_ns"`
	Build         BuildScope     `json:"build"`
	Process       *Process       `json:"process"`
	Operation     string         `json:"operation"`
	Resource      map[string]any `json:"resource"`
	Outcome       Outcome        `json:"outcome"`
	Sensor        Sensor         `json:"sensor"`
	Integrity     Integrity      `json:"integrity"`
}

type GraphNode struct {
	ProcessKey        string `json:"process_key"`
	ParentKey         string `json:"parent_key,omitempty"`
	ParentObservation string `json:"parent_observation"`
	Executable        string `json:"executable"`
}

type GraphEdge struct {
	Sequence uint64         `json:"sequence"`
	From     string         `json:"from"`
	To       string         `json:"to"`
	Kind     string         `json:"kind"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

type ExecutionGraph struct {
	SchemaVersion string      `json:"schema_version"`
	BuildID       string      `json:"build_id"`
	Nodes         []GraphNode `json:"nodes"`
	Edges         []GraphEdge `json:"edges"`
}

type Loss struct {
	KernelReserve     uint64 `json:"kernel_reserve"`
	KernelCorrelation uint64 `json:"kernel_correlation"`
	Decode            uint64 `json:"decode"`
	Queue             uint64 `json:"queue"`
	Persistence       uint64 `json:"persistence"`
	CounterReadError  bool   `json:"counter_read_error"`
}

type Lifecycle struct {
	Started   bool `json:"started"`
	Finalized bool `json:"finalized"`
}

type RunIdentity struct {
	Provider string `json:"provider"`
	RunID    string `json:"run_id"`
	Attempt  uint32 `json:"attempt"`
}

type SourceIdentity struct {
	Repository string `json:"repository"`
	Revision   string `json:"revision"`
}

type StreamCommitment struct {
	SHA256        string `json:"sha256"`
	FirstSequence uint64 `json:"first_sequence"`
	LastSequence  uint64 `json:"last_sequence"`
	EventCount    uint64 `json:"event_count"`
}

type Artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion        string           `json:"schema_version"`
	BuildID              string           `json:"build_id"`
	RunIdentity          RunIdentity      `json:"run_identity"`
	Source               SourceIdentity   `json:"source"`
	EventStream          StreamCommitment `json:"event_stream"`
	Loss                 Loss             `json:"loss"`
	Lifecycle            Lifecycle        `json:"lifecycle"`
	ExecutionGraphSHA256 string           `json:"execution_graph_sha256"`
	Artifact             Artifact         `json:"artifact"`
	PolicySHA256         string           `json:"policy_sha256"`
	SensorConfigSHA256   string           `json:"sensor_config_sha256"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Statement struct {
	Type          string         `json:"_type"`
	Subject       []Subject      `json:"subject"`
	PredicateType string         `json:"predicateType"`
	Predicate     map[string]any `json:"predicate"`
}

type Correlation struct {
	BuildID              string         `json:"buildId"`
	BuilderID            string         `json:"builderId"`
	RunIdentity          RunIdentity    `json:"runIdentity"`
	Source               SourceIdentity `json:"sourceRevision"`
	EvidenceManifestHash string         `json:"evidenceManifestDigest"`
	ExecutionGraphHash   string         `json:"executionGraphDigest"`
	SLSAProvenanceHash   string         `json:"slsaProvenanceDigest"`
	PolicyHash           string         `json:"policyDigest"`
	Completeness         string         `json:"completeness"`
}

type Policy struct {
	SchemaVersion                string   `json:"schema_version"`
	AllowedBuilderIDs            []string `json:"allowed_builder_ids"`
	AllowedArtifactProducers     []string `json:"allowed_artifact_producers"`
	AllowedRepositories          []string `json:"allowed_repositories"`
	AllowedExecutables           []string `json:"allowed_executables"`
	AllowedNetworkDestinations   []string `json:"allowed_network_destinations"`
	ForbiddenSensitiveCategories []string `json:"forbidden_sensitive_categories"`
	ExpectedProvider             string   `json:"expected_provider"`
	IncompleteDecision           string   `json:"incomplete_decision"`
}

type Reason struct {
	Code     string `json:"code"`
	Effect   string `json:"effect"`
	Message  string `json:"message"`
	Sequence uint64 `json:"sequence,omitempty"`
}

type Decision struct {
	Decision     string   `json:"decision"`
	Completeness string   `json:"completeness"`
	Reasons      []Reason `json:"reasons"`
}
