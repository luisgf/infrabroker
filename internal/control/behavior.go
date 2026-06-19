package control

import (
	"strings"
	"sync"
	"time"
)

// Behaviour guardrail modes.
const (
	BehaviorOff     = "off"     // disabled (also the empty value)
	BehaviorObserve = "observe" // audits anomalies only; does not block
	BehaviorEnforce = "enforce" // anomalies escalate to approval; rate exceeded is denied
)

// Default bounds for the tracker's in-memory state. They cap memory so a flood
// of distinct subjects (e.g. a trusted forwarder rotating end_user values) or a
// subject touching many distinct hosts/commands cannot grow the maps without
// limit. Overridable per deployment via BehaviorConfig; 0 means "use default".
const (
	defaultMaxSubjects      = 4096           // max tracked subjects before eviction
	defaultSubjectTTL       = 24 * time.Hour // idle subjects past this are evictable
	defaultMaxDistinctHosts = 1024           // max distinct hosts retained per subject
	defaultMaxDistinctCmds  = 1024           // max distinct command fingerprints per subject
)

// BehaviorConfig configures per-agent behaviour guardrails.
type BehaviorConfig struct {
	// Mode: "off"|"observe"|"enforce".
	Mode string `json:"mode,omitempty"`
	// RateLimitPerMin: maximum requests per subject per minute (0 = no limit).
	RateLimitPerMin int `json:"rate_limit_per_min,omitempty"`
	// MaxSubjects caps how many subjects are tracked before the least-recently
	// -seen one is evicted (0 = defaultMaxSubjects).
	MaxSubjects int `json:"max_subjects,omitempty"`
	// SubjectTTLMinutes evicts subjects idle for longer than this (0 =
	// defaultSubjectTTL).
	SubjectTTLMinutes int `json:"subject_ttl_minutes,omitempty"`
	// MaxDistinctPerSubject caps the distinct hosts and command fingerprints
	// retained per subject (0 = defaults). Once full, novelty detection for that
	// dimension degrades to "seen" rather than growing without bound.
	MaxDistinctPerSubject int `json:"max_distinct_per_subject,omitempty"`
}

// BehaviorTracker detects deviations from each agent's normal behaviour: rate
// spikes, previously unseen hosts, and commands outside its history. It is
// rule/statistics-based (no ML). State lives in memory (warmed at runtime);
// restarting the control plane resets the baseline.
//
// Memory is bounded: the subject table is capped (least-recently-seen eviction
// plus idle-TTL pruning) and each subject's host/command sets have a cardinality
// cap, so neither the number of subjects nor the per-subject history can grow
// without limit. See the bounds resolved in NewBehaviorTracker.
type BehaviorTracker struct {
	mu       sync.Mutex
	cfg      BehaviorConfig
	subjects map[string]*subjectState

	// Resolved bounds (config override or default).
	maxSubjects int
	subjectTTL  time.Duration
	maxDistinct int
}

type subjectState struct {
	events   []time.Time         // sliding window of request timestamps (for rate)
	hosts    map[string]struct{} // seen hosts
	cmds     map[string]struct{} // seen command fingerprints (first token)
	lastSeen time.Time           // for idle-TTL and LRU eviction
}

// NewBehaviorTracker creates a tracker with the given configuration, resolving
// any unset bounds to their defaults.
func NewBehaviorTracker(cfg BehaviorConfig) *BehaviorTracker {
	t := &BehaviorTracker{
		cfg:         cfg,
		subjects:    make(map[string]*subjectState),
		maxSubjects: cfg.MaxSubjects,
		subjectTTL:  time.Duration(cfg.SubjectTTLMinutes) * time.Minute,
		maxDistinct: cfg.MaxDistinctPerSubject,
	}
	if t.maxSubjects <= 0 {
		t.maxSubjects = defaultMaxSubjects
	}
	if t.subjectTTL <= 0 {
		t.subjectTTL = defaultSubjectTTL
	}
	if t.maxDistinct <= 0 {
		t.maxDistinct = defaultMaxDistinctHosts // hosts and cmds share the cap
	}
	return t
}

// Enabled reports whether guardrails are active (observe or enforce).
func (t *BehaviorTracker) Enabled() bool {
	return t.cfg.Mode == BehaviorObserve || t.cfg.Mode == BehaviorEnforce
}

// Enforcing reports whether the mode is enforce (blocks/escalates instead of
// only auditing).
func (t *BehaviorTracker) Enforcing() bool { return t.cfg.Mode == BehaviorEnforce }

// Check records a request from the subject (the authenticated broker CN,
// optionally qualified with a trusted end user — see the control plane's
// guardrailSubject) and returns detected anomalies and whether the rate limit
// has been exceeded. The first
// request from a subject establishes the baseline: new-host/new-command are
// not flagged (only on subsequent requests with novel host/command).
func (t *BehaviorTracker) Check(subject, host, command string) (anomalies []string, exceeded bool) {
	if !t.Enabled() {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	st, seen := t.subjects[subject]
	if !seen {
		// New subject: enforce the table cap before inserting so the map cannot
		// grow without bound (e.g. a trusted forwarder rotating end_user values).
		t.evictLocked(now)
		st = &subjectState{hosts: map[string]struct{}{}, cmds: map[string]struct{}{}}
		t.subjects[subject] = st
	}
	st.lastSeen = now

	// Rate limit (1-minute sliding window). Blocked attempts are also counted
	// to prevent rate-limit evasion.
	if t.cfg.RateLimitPerMin > 0 {
		cutoff := now.Add(-time.Minute)
		kept := st.events[:0]
		for _, e := range st.events {
			if e.After(cutoff) {
				kept = append(kept, e)
			}
		}
		st.events = append(kept, now)
		if len(st.events) > t.cfg.RateLimitPerMin {
			exceeded = true
			anomalies = append(anomalies, "rate-exceeded")
		}
	}

	// Novel host/command: only after the baseline is established (subject already
	// seen). Once a set is at its cardinality cap, novelty detection for that
	// dimension degrades to "seen" (no flag, no insert): a subject that has
	// already exhibited that much diversity makes novelty meaningless, and
	// continuing would either grow the map without bound or emit unbounded
	// escalations.
	fp := firstToken(command)
	hostsFull := len(st.hosts) >= t.maxDistinct
	cmdsFull := len(st.cmds) >= t.maxDistinct
	if seen {
		if _, ok := st.hosts[host]; !ok && !hostsFull {
			anomalies = append(anomalies, "new-host:"+host)
		}
		if fp != "" {
			if _, ok := st.cmds[fp]; !ok && !cmdsFull {
				anomalies = append(anomalies, "new-command:"+fp)
			}
		}
	}
	if !hostsFull {
		st.hosts[host] = struct{}{}
	}
	if fp != "" && !cmdsFull {
		st.cmds[fp] = struct{}{}
	}
	return anomalies, exceeded
}

// evictLocked bounds the subject table before a new subject is inserted. It
// first prunes subjects idle past the TTL; if the table is still at capacity it
// removes the single least-recently-seen entry. Caller must hold t.mu. Cost is
// O(len(subjects)) but runs only when a brand-new subject arrives at capacity —
// exactly the flood it is meant to bound.
func (t *BehaviorTracker) evictLocked(now time.Time) {
	if len(t.subjects) < t.maxSubjects {
		return
	}
	cutoff := now.Add(-t.subjectTTL)
	var oldestKey string
	var oldestSeen time.Time
	for k, st := range t.subjects {
		if st.lastSeen.Before(cutoff) {
			delete(t.subjects, k)
			continue
		}
		if oldestKey == "" || st.lastSeen.Before(oldestSeen) {
			oldestKey, oldestSeen = k, st.lastSeen
		}
	}
	if len(t.subjects) >= t.maxSubjects && oldestKey != "" {
		delete(t.subjects, oldestKey)
	}
}

// firstToken returns the first token (the program name) of a command, used as
// a fingerprint. E.g. "systemctl restart nginx" → "systemctl".
func firstToken(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
