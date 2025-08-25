// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"time"
	"os"
	"encoding/json"
	"strings"
	"strconv"
	"os/exec"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover

	ctx          context.Context
	mu           sync.Mutex
	rnd          *rand.Rand
	target       *prog.Target
	hintsLimiter prog.HintsLimiter
	runningJobs  map[jobIntrospector]struct{}

	ct           *prog.ChoiceTable
	ctProgs      int
	ctMu         sync.Mutex // TODO: use RWLock.
	ctRegenerate chan struct{}

	SourceLineToConfig SourceLineToConfig
	SrcLineMu          sync.RWMutex
	Vmlinux string

	execQueues
}

type LineRangeConfig struct {
    StartLine int
    EndLine   int
    Configs   []string
}
type SourceLineToConfig map[string][]LineRangeConfig

// LoadConfigTree loads configtree.json -> map[string][]string
func LoadConfigTree(jsonPath string) (map[string][]string, error) {
    if jsonPath == "" {
        return nil, nil
    }
    data, err := os.ReadFile(jsonPath)
    if err != nil {
        return nil, fmt.Errorf("read configtree.json: %w", err)
    }
    var tree map[string][]string
    if err := json.Unmarshal(data, &tree); err != nil {
        return nil, fmt.Errorf("parse configtree.json: %w", err)
    }
    return tree, nil
}

// LoadSourceLineToConfig loads sourceline2config.json, expands related CONFIGs using configTree.
func LoadSourceLineToConfig(jsonPath string, configTree map[string][]string) (SourceLineToConfig, error) {
    res := make(SourceLineToConfig)
    if jsonPath == "" {
        return res, nil
    }
    data, err := os.ReadFile(jsonPath)
    if err != nil {
        return nil, fmt.Errorf("read sourceline2config: %w", err)
    }
    var raw map[string]map[string][]string
    if err := json.Unmarshal(data, &raw); err != nil {
        return nil, fmt.Errorf("parse sourceline2config: %w", err)
    }
    for file, ranges := range raw {
        for rstr, cfgs := range ranges {
            parts := strings.Split(rstr, "-")
            if len(parts) != 2 {
                continue
            }
            start, err1 := strconv.Atoi(parts[0])
            end, err2 := strconv.Atoi(parts[1])
            if err1 != nil || err2 != nil {
                continue
            }
            // expand related configs using configTree
            ext := make(map[string]bool)
            for _, c := range cfgs {
                ext[c] = true
                if rel, ok := configTree[c]; ok {
                    for _, r := range rel {
                        ext[r] = true
                    }
                }
            }
            final := make([]string, 0, len(ext))
            for c := range ext {
                final = append(final, c)
            }
            res[file] = append(res[file], LineRangeConfig{
                StartLine: start,
                EndLine:   end,
                Configs:   final,
            })
        }
    }
    return res, nil
}

// InjectSeedsFromSyscallPairJSON parses JSON and generates seeds using current choice table.
// It then converts them to Candidate and calls AddCandidates.
func (f *Fuzzer) InjectSeedsFromSyscallPairJSON(jsonPath string) error {
    if jsonPath == "" {
        return nil
    }
    data, err := os.ReadFile(jsonPath)
    if err != nil {
        return fmt.Errorf("read syscall pair json: %w", err)
    }
    var deps []struct {
        Targets []string `json:"Target"`
        Relate  []string `json:"Relate"`
        Addr    uint32   `json:"Addr"`
    }
    if err := json.Unmarshal(data, &deps); err != nil {
        return fmt.Errorf("parse syscall pair json: %w", err)
    }

    ct := f.ChoiceTable()
    if ct == nil {
        return fmt.Errorf("choice table not ready")
    }
    rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
    generated := make(map[string]bool)
    var seeds []*prog.Prog
    for _, dep := range deps {
        for _, tname := range dep.Targets {
            tgt := f.target.SyscallMap[tname]
            if tgt == nil || !ct.Enabled(tgt.ID) {
                continue
            }
            for _, rname := range dep.Relate {
                rel := f.target.SyscallMap[rname]
                if rel == nil || !ct.Enabled(rel.ID) {
                    continue
                }
                key := tname + ":" + rname
                if generated[key] {
                    continue
                }
                generated[key] = true

                p, err := prog.GenerateSeedFromSyscallPair(f.target, ct, tgt, rel, rnd)
                if err != nil {
                    f.Logf(0, "failed to generate seed for %v->%v: %v", tname, rname, err)
                    continue
                }
                seeds = append(seeds, p)
            }
        }
    }

    if len(seeds) == 0 {
        return nil
    }
    // Convert to Candidate type and add
    cands := make([]Candidate, 0, len(seeds))
    for _, p := range seeds {
        cands = append(cands, Candidate{
            Prog:  p,
            Flags: 0, // set flags as needed
        })
    }
    f.AddCandidates(cands)
    f.Logf(0, "injected %d seeds from %s", len(seeds), jsonPath)
    return nil
}

// UpdateSyscallPairFromProg: given prog p and a mapping allCover (per-syscall list of addresses),
// map addresses to source:line using addr2line on f.vmlinux, consult sourceLineToConfig,
// and update choice table's SyscallPair accordingly.
//
// allCover: map[*prog.Syscall][]uint64 - addresses (as uint64 or uint32 depending on your raw cover)
func (f *Fuzzer) UpdateSyscallPairFromProg(p *prog.Prog, allCover map[*prog.Syscall][]uint64) {
    if len(allCover) == 0 {
        return
    }
    f.SrcLineMu.RLock()
    s2c := f.SourceLineToConfig
    vmlinux := f.Vmlinux
    f.SrcLineMu.RUnlock()

    if vmlinux == "" || s2c == nil {
        f.Logf(1, "no vmlinux or sourceLineToConfig configured, skipping update")
        return
    }

    // Build address list (strings) for addr2line.
    var addrs []string
    addrToPair := make(map[string]struct{ s string; off uint64 }) // optional map for tracking
    for syscall, cov := range allCover {
        for _, a := range cov {
            // convert to hex 0x... string; your addr width may vary
            addrStr := fmt.Sprintf("0x%x", a)
            addrs = append(addrs, addrStr)
            addrToPair[addrStr] = struct{ s string; off uint64 }{ s: syscall.Name, off: a }
        }
    }
    if len(addrs) == 0 {
        return
    }
    // call addr2line: -e vmlinux addr1 addr2 ...
    args := append([]string{"-e", vmlinux, "-f", "-i"}, addrs...)
    cmd := exec.Command("addr2line", args...)
    out, err := cmd.Output()
    if err != nil {
        f.Logf(0, "addr2line failed: %v", err)
        return
    }
    lines := strings.Split(strings.TrimSpace(string(out)), "\n")
    // addr2line produces function/source:line pairs; we need source:line lines positions.
    // Parse results and build map config -> syscall -> []addr
    configToSyscallAddrs := make(map[string]map[*prog.Syscall][]uint64)
    // We'll iterate in same order as addrs.
    idx := 0
    for i := 0; i+1 < len(lines) && idx < len(addrs); i += 2 {
        // lines[i] = function name, lines[i+1] = file:line or "??:0"
        srcLine := lines[i+1]
        // parse file:line
        colon := strings.LastIndex(srcLine, ":")
        if colon == -1 {
            idx++
            continue
        }
        file := srcLine[:colon]
        lineStr := srcLine[colon+1:]
        lineNum, err := strconv.Atoi(lineStr)
        if err != nil {
            idx++
            continue
        }
        // normalize file path if needed (strip prefix)
        // now find configs for this file/line:
        if ranges, ok := s2c[file]; ok {
            for _, r := range ranges {
                if lineNum >= r.StartLine && lineNum <= r.EndLine {
                    for _, cfg := range r.Configs {
                        // find syscall for this addr: we need to map addrs[idx] -> which syscall.
                        // This simple code loops allCover to find which syscall has this addr.
                        addrVal, _ := strconv.ParseUint(strings.TrimPrefix(addrs[idx], "0x"), 16, 64)
                        for sc, cov := range allCover {
                            for _, a := range cov {
                                if a == addrVal {
                                    if _, ok := configToSyscallAddrs[cfg]; !ok {
                                        configToSyscallAddrs[cfg] = make(map[*prog.Syscall][]uint64)
                                    }
                                    // append address
                                    configToSyscallAddrs[cfg][sc] = append(configToSyscallAddrs[cfg][sc], uint64(a))
                                }
                            }
                        }
                    }
                }
            }
        }
        idx++
    }

    // Now update choice table: for each config that ties together multiple syscalls add pair infos.
    f.ctMu.Lock()
    defer f.ctMu.Unlock()
    ct := f.ct
    if ct == nil {
        return
    }
    for _, scMap := range configToSyscallAddrs {
        // make slice of syscalls in this config
        syscalls := make([]*prog.Syscall, 0, len(scMap))
        for s := range scMap {
            syscalls = append(syscalls, s)
        }
        for i := 0; i < len(syscalls); i++ {
            sa := syscalls[i]
            addrsA := scMap[sa]
            for j := i + 1; j < len(syscalls); j++ {
                sb := syscalls[j]
                addrsB := scMap[sb]
                // for each address pair insert both directions
                for _, a := range addrsA {
                    // ensure ct.SyscallPair map exists
                    if ct.SyscallPair == nil {
                        ct.SyscallPair = make(map[*prog.Syscall][]*prog.SyscallPairInfo)
                    }
                    // insert sa -> sb with addr a (uint32 if your struct expects)
                    ct.SyscallPair[sa] = append(ct.SyscallPair[sa], &prog.SyscallPairInfo{
                        Relate:   sb,
                        Verified: true,
                        Freq:     1,
                        Addr:     a,
                    })
                }
                for _, b := range addrsB {
                    if ct.SyscallPair == nil {
                        ct.SyscallPair = make(map[*prog.Syscall][]*prog.SyscallPairInfo)
                    }
                    ct.SyscallPair[sb] = append(ct.SyscallPair[sb], &prog.SyscallPairInfo{
                        Relate:   sa,
                        Verified: true,
                        Freq:     1,
                        Addr:     b,
                    })
                }
            }
        }
    }
    f.Logf(0, "updated choice table syscall pairs from program %v", p)
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	if cfg.NewInputFilter == nil {
		cfg.NewInputFilter = func(call string) bool {
			return true
		}
	}
	f := &Fuzzer{
		Stats:  newStats(target),
		Config: cfg,
		Cover:  newCover(),

		ctx:         ctx,
		rnd:         rnd,
		target:      target,
		runningJobs: map[jobIntrospector]struct{}{},

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),
	}
	f.execQueues = newExecQueues(f)
	f.updateChoiceTable(nil)
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}
	return f
}

type execQueues struct {
	triageCandidateQueue *queue.DynamicOrderer
	candidateQueue       *queue.PlainQueue
	triageQueue          *queue.DynamicOrderer
	smashQueue           *queue.PlainQueue
	source               queue.Source
}

func newExecQueues(fuzzer *Fuzzer) execQueues {
	ret := execQueues{
		triageCandidateQueue: queue.DynamicOrder(),
		candidateQueue:       queue.Plain(),
		triageQueue:          queue.DynamicOrder(),
		smashQueue:           queue.Plain(),
	}
	// Alternate smash jobs with exec/fuzz to spread attention to the wider area.
	skipQueue := 3
	if fuzzer.Config.PatchTest {
		// When we do patch fuzzing, we do not focus on finding and persisting
		// new coverage that much, so it's reasonable to spend more time just
		// mutating various corpus programs.
		skipQueue = 2
	}
	// Sources are listed in the order, in which they will be polled.
	ret.source = queue.Order(
		ret.triageCandidateQueue,
		ret.candidateQueue,
		ret.triageQueue,
		queue.Alternate(ret.smashQueue, skipQueue),
		queue.Callback(fuzzer.genFuzz),
	)
	return ret
}

func (fuzzer *Fuzzer) CandidatesToTriage() int {
	return fuzzer.statCandidates.Val() + fuzzer.statJobsTriageCandidate.Val()
}

func (fuzzer *Fuzzer) CandidateTriageFinished() bool {
	return fuzzer.CandidatesToTriage() == 0
}

func (fuzzer *Fuzzer) execute(executor queue.Executor, req *queue.Request) *queue.Result {
	return fuzzer.executeWithFlags(executor, req, 0)
}

func (fuzzer *Fuzzer) executeWithFlags(executor queue.Executor, req *queue.Request, flags ProgFlags) *queue.Result {
	fuzzer.enqueue(executor, req, flags, 0)
	return req.Wait(fuzzer.ctx)
}

func (fuzzer *Fuzzer) prepare(req *queue.Request, flags ProgFlags, attempt int) {
	req.OnDone(func(req *queue.Request, res *queue.Result) bool {
		return fuzzer.processResult(req, res, flags, attempt)
	})
}

func (fuzzer *Fuzzer) enqueue(executor queue.Executor, req *queue.Request, flags ProgFlags, attempt int) {
	fuzzer.prepare(req, flags, attempt)
	executor.Submit(req)
}

func (fuzzer *Fuzzer) processResult(req *queue.Request, res *queue.Result, flags ProgFlags, attempt int) bool {
	// If we are already triaging this exact prog, this is flaky coverage.
	// Hanged programs are harmful as they consume executor procs.
	dontTriage := flags&progInTriage > 0 || res.Status == queue.Hanged
	// Triage the program.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	var triage map[int]*triageCall
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0 && res.Info != nil && !dontTriage {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, info, call, &triage)
		}
		fuzzer.triageProgCall(req.Prog, res.Info.Extra, -1, &triage)

		if len(triage) != 0 {
			queue, stat := fuzzer.triageQueue, fuzzer.statJobsTriage
			if flags&progCandidate > 0 {
				queue, stat = fuzzer.triageCandidateQueue, fuzzer.statJobsTriageCandidate
			}
			job := &triageJob{
				p:        req.Prog.Clone(),
				executor: res.Executor,
				flags:    flags,
				queue:    queue.Append(),
				calls:    triage,
				info: &JobInfo{
					Name: req.Prog.String(),
					Type: "triage",
				},
			}
			for id := range triage {
				job.info.Calls = append(job.info.Calls, job.p.CallName(id))
			}
			sort.Strings(job.info.Calls)
			fuzzer.startJob(stat, job)
		}
	}

	if res.Info != nil {
		fuzzer.statExecTime.Add(int(res.Info.Elapsed / 1e6))
		for call, info := range res.Info.Calls {
			fuzzer.handleCallInfo(req, info, call)
		}
		fuzzer.handleCallInfo(req, res.Info.Extra, -1)
	}

	// Corpus candidates may have flaky coverage, so we give them a second chance.
	maxCandidateAttempts := 3
	if req.Risky() {
		// In non-snapshot mode usually we are not sure which exactly input caused the crash,
		// so give it one more chance. In snapshot mode we know for sure, so don't retry.
		maxCandidateAttempts = 2
		if fuzzer.Config.Snapshot || res.Status == queue.Hanged {
			maxCandidateAttempts = 0
		}
	}
	if len(triage) == 0 && flags&ProgFromCorpus != 0 && attempt < maxCandidateAttempts {
		fuzzer.enqueue(fuzzer.candidateQueue, req, flags, attempt+1)
		return false
	}
	if flags&progCandidate != 0 {
		fuzzer.statCandidates.Add(-1)
	}
	return true
}

type Config struct {
	Debug          bool
	Corpus         *corpus.Corpus
	Logf           func(level int, msg string, args ...interface{})
	Snapshot       bool
	Coverage       bool
	FaultInjection bool
	Comparisons    bool
	Collide        bool
	EnabledCalls   map[*prog.Syscall]bool
	NoMutateCalls  map[int]bool
	FetchRawCover  bool
	NewInputFilter func(call string) bool
	PatchTest      bool
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *flatrpc.CallInfo, call int, triage *map[int]*triageCall) {
	if info == nil {
		return
	}
	prio := signalPrio(p, info, call)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)
	if *triage == nil {
		*triage = make(map[int]*triageCall)
	}
	(*triage)[call] = &triageCall{
		errno:     info.Error,
		newSignal: newMaxSignal,
		signals:   [deflakeNeedRuns]signal.Signal{signal.FromRaw(info.Signal, prio)},
	}
}

func (fuzzer *Fuzzer) handleCallInfo(req *queue.Request, info *flatrpc.CallInfo, call int) {
	if info == nil || info.Flags&flatrpc.CallFlagCoverageOverflow == 0 {
		return
	}
	syscallIdx := len(fuzzer.Syscalls) - 1
	if call != -1 {
		syscallIdx = req.Prog.Calls[call].Meta.ID
	}
	stat := &fuzzer.Syscalls[syscallIdx]
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps != 0 {
		stat.CompsOverflows.Add(1)
		fuzzer.statCompsOverflows.Add(1)
	} else {
		stat.CoverOverflows.Add(1)
		fuzzer.statCoverOverflows.Add(1)
	}
}

func signalPrio(p *prog.Prog, info *flatrpc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Error == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func (fuzzer *Fuzzer) genFuzz() *queue.Request {
	// Either generate a new input or mutate an existing one.
	mutateRate := 0.95
	if !fuzzer.Config.Coverage {
		// If we don't have real coverage signal, generate programs
		// more frequently because fallback signal is weak.
		mutateRate = 0.5
	}
	var req *queue.Request
	rnd := fuzzer.rand()
	if rnd.Float64() < mutateRate {
		req = mutateProgRequest(fuzzer, rnd)
	}
	if req == nil {
		req = genProgRequest(fuzzer, rnd)
	}
	if fuzzer.Config.Collide && rnd.Intn(3) == 0 {
		req = &queue.Request{
			Prog: randomCollide(req.Prog, rnd),
			Stat: fuzzer.statExecCollide,
		}
	}
	fuzzer.prepare(req, 0, 0)
	return req
}

func (fuzzer *Fuzzer) startJob(stat *stat.Val, newJob job) {
	fuzzer.Logf(2, "started %T", newJob)
	go func() {
		stat.Add(1)
		defer stat.Add(-1)

		fuzzer.statJobs.Add(1)
		defer fuzzer.statJobs.Add(-1)

		if obj, ok := newJob.(jobIntrospector); ok {
			fuzzer.mu.Lock()
			fuzzer.runningJobs[obj] = struct{}{}
			fuzzer.mu.Unlock()

			defer func() {
				fuzzer.mu.Lock()
				delete(fuzzer.runningJobs, obj)
				fuzzer.mu.Unlock()
			}()
		}

		newJob.run(fuzzer)
	}()
}

func (fuzzer *Fuzzer) Next() *queue.Request {
	req := fuzzer.source.Next()
	if req == nil {
		// The fuzzer is not supposed to issue nil requests.
		panic("nil request from the fuzzer")
	}
	return req
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

type ProgFlags int

const (
	// The candidate was loaded from our local corpus rather than come from hub.
	ProgFromCorpus ProgFlags = 1 << iota
	ProgMinimized
	ProgSmashed

	progCandidate
	progInTriage
)

type Candidate struct {
	Prog  *prog.Prog
	Flags ProgFlags
}

func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	fuzzer.statCandidates.Add(len(candidates))
	for _, candidate := range candidates {
		req := &queue.Request{
			Prog:      candidate.Prog,
			ExecOpts:  setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:      fuzzer.statExecCandidate,
			Important: true,
		}
		fuzzer.enqueue(fuzzer.candidateQueue, req, candidate.Flags|progCandidate, 0)
	}
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(fuzzer.rnd.Int63()))
}

func (fuzzer *Fuzzer) updateChoiceTable(programs []*prog.Prog) {
	newCt := fuzzer.target.BuildChoiceTable(programs, fuzzer.Config.EnabledCalls)

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if len(programs) >= fuzzer.ctProgs {
		fuzzer.ctProgs = len(programs)
		fuzzer.ct = newCt
	}
}

func (fuzzer *Fuzzer) choiceTableUpdater() {
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-fuzzer.ctRegenerate:
		}
		fuzzer.updateChoiceTable(fuzzer.Config.Corpus.Programs())
	}
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	progs := fuzzer.Config.Corpus.Programs()

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()

	// There were no deep ideas nor any calculations behind these numbers.
	regenerateEveryProgs := 333
	if len(progs) < 100 {
		regenerateEveryProgs = 33
	}
	if fuzzer.ctProgs+regenerateEveryProgs < len(progs) {
		select {
		case fuzzer.ctRegenerate <- struct{}{}:
		default:
			// We're okay to lose the message.
			// It means that we're already regenerating the table.
		}
	}
	return fuzzer.ct
}

func (fuzzer *Fuzzer) RunningJobs() []*JobInfo {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()

	var ret []*JobInfo
	for item := range fuzzer.runningJobs {
		ret = append(ret, item.getInfo())
	}
	return ret
}

func (fuzzer *Fuzzer) logCurrentStats() {
	for {
		select {
		case <-time.After(time.Minute):
		case <-fuzzer.ctx.Done():
			return
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		str := fmt.Sprintf("running jobs: %d, heap (MB): %d",
			fuzzer.statJobs.Val(), m.Alloc/1000/1000)
		fuzzer.Logf(0, "%s", str)
	}
}

func setFlags(execFlags flatrpc.ExecFlag) flatrpc.ExecOpts {
	return flatrpc.ExecOpts{
		ExecFlags: execFlags,
	}
}

// TODO: This method belongs better to pkg/flatrpc, but we currently end up
// having a cyclic dependency error.
func DefaultExecOpts(cfg *mgrconfig.Config, features flatrpc.Feature, debug bool) flatrpc.ExecOpts {
	env := csource.FeaturesToFlags(features, nil)
	if debug {
		env |= flatrpc.ExecEnvDebug
	}
	if cfg.Experimental.ResetAccState {
		env |= flatrpc.ExecEnvResetState
	}
	if cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := flatrpc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: cfg.SandboxArg,
	}
}
