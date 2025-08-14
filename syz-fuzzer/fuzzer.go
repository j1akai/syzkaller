// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"encoding/json"
	stdlog "log"
	"path/filepath"
	"os/exec"
    "strconv"
    "strings"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type Fuzzer struct {
	name              string
	outputType        OutputType
	config            *ipc.Config
	execOpts          *ipc.ExecOpts
	procs             []*Proc
	gate              *ipc.Gate
	workQueue         *WorkQueue
	needPoll          chan struct{}
	choiceTable       *prog.ChoiceTable
	stats             [StatCount]uint64
	manager           *rpctype.RPCClient
	target            *prog.Target
	triagedCandidates uint32
	timeouts          targets.Timeouts

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool
	fetchRawCover            bool

	corpusMu     sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[hash.Sig]struct{}
	corpusPrios  []int64
	sumPrios     int64

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus
	maxSignal    signal.Signal // max signal ever observed including flakes
	newSignal    signal.Signal // diff of maxSignal since last sync with master

	checkResult *rpctype.CheckArgs
	logMu       sync.Mutex
}

type FuzzerSnapshot struct {
	corpus      []*prog.Prog
	corpusPrios []int64
	sumPrios    int64
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCollide
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:  "exec gen",
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
	StatCollide:   "exec collide",
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func createIPCConfig(features *host.Features, config *ipc.Config) {
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureDelayKcovMmap].Enabled {
		config.Flags |= ipc.FlagDelayKcovMmap
	}
	if features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	config.Flags |= ipc.FlagEnableNetReset
	config.Flags |= ipc.FlagEnableCgroups
	config.Flags |= ipc.FlagEnableCloseFds
	if features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	if features[host.FeatureWifiEmulation].Enabled {
		config.Flags |= ipc.FlagEnableWifi
	}
}

// 输入:包含具有依赖信息的系统调用对的json文件
// 输出:根据每个具有依赖关系的系统调用对生成一个种子
func generateSeedsFromJSON_debug(jsonPath string, choiceTable *prog.ChoiceTable, target *prog.Target) ([]*prog.Prog, error) {
	// log.Logf(0, "%s", choiceTable.PrintChoiceTable_debug())

	if jsonPath == "" {
        log.Logf(0, "FlagSyscallPair is empty")
        return nil, nil
    }
    log.Logf(0, "FlagSyscallPair: %s", jsonPath)

	data, err := os.ReadFile(jsonPath)
    if err != nil {
        return nil, fmt.Errorf("Failed to read JSON file: %v", err)
    }

    var dependencies []struct {
        Target string   `json:"Target"`
        Relate []string `json:"Relate"`
		Source string   `json:"Source"`
        Line   int      `json:"Line"`
    }
	// 读取json文件,转换到内存中,存储在dependencies
    if err := json.Unmarshal(data, &dependencies); err != nil {
        return nil, fmt.Errorf("Failed to parse JSON file: %v", err)
    }

	// maxPairs := 10
	// if len(dependencies) > maxPairs {
	//     dependencies = dependencies[:maxPairs]
	//     log.Logf(0, "Limiting to first %d syscall pairs", maxPairs)
	// }

	// 初始化ChoiceTable的SyscallPair字段(我们自定义的)
	choiceTable.SyscallPair = make(map[*prog.Syscall][]*prog.SyscallPairInfo_debug)
    for _, dep := range dependencies {
        targetCall := target.SyscallMap[dep.Target]
        if targetCall == nil || !choiceTable.Enabled(targetCall.ID) {
            log.Logf(0, "Unknown target syscall: %v", dep.Target)
            continue
        }
        var relateInfos []*prog.SyscallPairInfo_debug
        for _, relate := range dep.Relate {
            relateCall := target.SyscallMap[relate]
            if relateCall == nil || !choiceTable.Enabled(relateCall.ID) {
                log.Logf(0, "Unknown relate syscall: %v", relate)
                continue
            }
            relateInfos = append(relateInfos, &prog.SyscallPairInfo_debug{
                Relate:   relateCall,
                Verified: false,
                Freq:     0,
				Source:   dep.Source,
                Line:     dep.Line,
            })
        }
        if len(relateInfos) > 0 {
            choiceTable.SyscallPair[targetCall] = relateInfos
        }
    }

	log.Logf(0, "==== SyscallPair ====")
	for target, relates := range choiceTable.SyscallPair {
	    log.Logf(0, "Target: %s", target.Name)
	    for _, info := range relates {
	        log.Logf(0, "    Relate: %s, Verified: %v, Freq: %d", info.Relate.Name, info.Verified, info.Freq)
	    }
	}
	log.Logf(0, "==== SyscallPair ====")

    log.Logf(0, "Dependencies:")
    for _, dep := range dependencies {
        log.Logf(0, "Target: %s, Relate: %v", dep.Target, dep.Relate)
    }

    var seeds []*prog.Prog
    rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
    for _, dep := range dependencies {
		// 遍历dependencies,对每一对target_syscall和relate_syscall都调用GenerateSeedFromSyscallPair_debug来生成种子
        targetCall := target.SyscallMap[dep.Target]
        if targetCall == nil {
            log.Logf(0, "Unknown target syscall: %v", dep.Target)
            continue
        }
		if !choiceTable.Enabled(targetCall.ID) {
    	    log.Logf(0, "Target syscall not enabled: %v [%v], skipping", dep.Target, targetCall.ID)
    	    continue
    	}
        for _, relate := range dep.Relate {
            relateCall := target.SyscallMap[relate]
            if relateCall == nil {
                log.Logf(0, "Unknown relate syscall: %v", relate)
                continue
            }
        	if !choiceTable.Enabled(relateCall.ID) {
        	    log.Logf(0, "Relate syscall not enabled: %v [%v], skipping", relate, relateCall.ID)
        	    continue
        	}
            log.Logf(0, "Generating seed for \nTarget: %s, Relate: %s", dep.Target, relate)
            p, err := prog.GenerateSeedFromSyscallPair_debug(target, choiceTable, targetCall, relateCall, rnd)
            if err != nil {
                log.Logf(0, "Failed to generate seed program for %v and %v: %v", dep.Target, relate, err)
                continue
            }

			log.Logf(0, "Generated seed with %d calls", len(p.Calls))

            seeds = append(seeds, p)
        }
    }

	log.Logf(0, "Total seeds generated: %d", len(seeds))

    return seeds, nil
}

// 在fuzzer端初始化ChoiceTable之后,利用静态分析得到的结果json文件
// 生成初始种子,并加入到候选队列中,等待被执行
func (fuzzer *Fuzzer) injectInitialSeeds_debug(syscallPairPath string) {
    seeds, err := generateSeedsFromJSON_debug(syscallPairPath, fuzzer.choiceTable, fuzzer.target)
    if err != nil {
        log.Logf(0, "Failed to generate seeds from JSON: %v", err)
        return
    }
	fuzzer.workQueue.PrintAll_debug()
    for _, seed := range seeds {
        fuzzer.workQueue.enqueue(&WorkCandidate{
            p:     seed,
            flags: ProgCandidate,
        })
    }
	fuzzer.workQueue.PrintAll_debug()
    log.Logf(0, "Generated %d seeds from JSON file", len(seeds))
}

// nolint: funlen
func main() {
	debug.SetGCPercent(50)

	var (
		flagName     = flag.String("name", "test", "unique name for manager")
		flagOS       = flag.String("os", runtime.GOOS, "target OS")
		flagArch     = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager  = flag.String("manager", "", "manager rpc address")
		flagProcs    = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput   = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagTest     = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest  = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
		flagRawCover = flag.Bool("raw_cover", false, "fetch raw coverage")
		// 通过命令行参数接收json文件路径,和pkg/instance/instance.go中的更改相对应
		flagSyscallPair = flag.String("syscallPair","","file with dependencies between syscalls")
	)
	defer tool.Init()()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("failed to create default ipc config: %v", err)
	}
	if *flagRawCover {
		execOpts.Flags &^= ipc.FlagDedupCover
	}
	timeouts := config.Timeouts
	sandbox := ipc.FlagsToSandbox(config.Flags)
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	checkArgs := &checkArgs{
		target:         target,
		sandbox:        sandbox,
		ipcConfig:      config,
		ipcExecOpts:    execOpts,
		gitRevision:    prog.GitRevision,
		targetRevision: target.Revision,
	}
	if *flagTest {
		testImage(*flagManager, checkArgs)
		return
	}

	machineInfo, modules := collectMachineInfos(target)

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale)
	if err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}

	log.Logf(1, "connecting to manager...")
	a := &rpctype.ConnectArgs{
		Name:        *flagName,
		MachineInfo: machineInfo,
		Modules:     modules,
	}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.Fatal(err)
	}
	if r.CoverFilterBitmap != nil {
		if err := osutil.WriteFile("syz-cover-bitmap", r.CoverFilterBitmap); err != nil {
			log.Fatalf("failed to write syz-cover-bitmap: %v", err)
		}
	}
	if r.CheckResult == nil {
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			if r.CheckResult == nil {
				r.CheckResult = new(rpctype.CheckArgs)
			}
			r.CheckResult.Error = err.Error()
		}
		r.CheckResult.Name = *flagName
		if err := manager.Call("Manager.Check", r.CheckResult, nil); err != nil {
			log.Fatalf("Manager.Check call failed: %v", err)
		}
		if r.CheckResult.Error != "" {
			log.Fatalf("%v", r.CheckResult.Error)
		}
	} else {
		target.UpdateGlobs(r.CheckResult.GlobFiles)
		if err = host.Setup(target, r.CheckResult.Features, featureFlags, config.Executor); err != nil {
			log.Fatal(err)
		}
	}
	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls[sandbox]))
	for _, feat := range r.CheckResult.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	createIPCConfig(r.CheckResult.Features, config)

	if *flagRunTest {
		runTest(target, manager, *flagName, config.Executor)
		return
	}

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	fuzzer := &Fuzzer{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		manager:                  manager,
		target:                   target,
		timeouts:                 timeouts,
		faultInjectionEnabled:    r.CheckResult.Features[host.FeatureFault].Enabled,
		comparisonTracingEnabled: r.CheckResult.Features[host.FeatureComparisons].Enabled,
		corpusHashes:             make(map[hash.Sig]struct{}),
		checkResult:              r.CheckResult,
		fetchRawCover:            *flagRawCover,
	}
	gateCallback := fuzzer.useBugFrames(r, *flagProcs)
	fuzzer.gate = ipc.NewGate(2**flagProcs, gateCallback)

	for needCandidates, more := true, true; more; needCandidates = false {
		more = fuzzer.poll(needCandidates, nil)
		// This loop lead to "no output" in qemu emulation, tell manager we are not dead.
		log.Logf(0, "fetching corpus: %v, signal %v/%v (executing program)",
			len(fuzzer.corpus), len(fuzzer.corpusSignal), len(fuzzer.maxSignal))
	}
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}
	fuzzer.choiceTable = target.BuildChoiceTable(fuzzer.corpus, calls)

	if r.CoverFilterBitmap != nil {
		fuzzer.execOpts.Flags |= ipc.FlagEnableCoverageFilter
	}

	// *****************************
	// 将打印信息持久化到文件中
	logDir := "/home/debug"
	logFile := filepath.Join(logDir, "log")

	// 检查并处理debug目录
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
	    // 目录不存在则创建
	    if err := os.MkdirAll(logDir, 0755); err != nil {
	        log.Fatalf("Failed to create debug directory: %v", err)
	    }
	} else {
	    // 目录存在则删除旧的日志文件（如果存在）
	    if _, err := os.Stat(logFile); err == nil {
	        if err := os.Remove(logFile); err != nil {
	            log.Fatalf("Failed to remove old log file: %v", err)
	        }
	    }
	}

	// 创建新的日志文件
	file, err := os.Create(logFile)
	if err != nil {
	    log.Fatalf("Failed to create log file: %v", err)
	}
	defer file.Close()
	stdlog.SetOutput(file)
	
	// 利用依赖信息生成候选种子
	fuzzer.injectInitialSeeds_debug(*flagSyscallPair)
	// *****************************


	log.Logf(0, "starting %v fuzzer processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.Fatalf("failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
	}

	fuzzer.pollLoop()
}

func collectMachineInfos(target *prog.Target) ([]byte, []host.KernelModule) {
	machineInfo, err := host.CollectMachineInfo()
	if err != nil {
		log.Fatalf("failed to collect machine information: %v", err)
	}
	modules, err := host.CollectModulesInfo()
	if err != nil {
		log.Fatalf("failed to collect modules info: %v", err)
	}
	return machineInfo, modules
}

// Returns gateCallback for leak checking if enabled.
func (fuzzer *Fuzzer) useBugFrames(r *rpctype.ConnectRes, flagProcs int) func() {
	var gateCallback func()

	if r.CheckResult.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { fuzzer.gateCallback(r.MemoryLeakFrames) }
	}

	if r.CheckResult.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
		fuzzer.filterDataRaceFrames(r.DataRaceFrames)
	}

	return gateCallback
}

func (fuzzer *Fuzzer) gateCallback(leakFrames []string) {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&fuzzer.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, leakFrames...)
	timeout := fuzzer.timeouts.NoOutput * 9 / 10
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed\n")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 2)
	}
}

func (fuzzer *Fuzzer) filterDataRaceFrames(frames []string) {
	args := append([]string{"setup_kcsan_filterlist"}, frames...)
	timeout := time.Minute * fuzzer.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil {
		log.Fatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (fuzzer *Fuzzer) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second * fuzzer.timeouts.Scale).C
	for {
		poll := false
		select {
		case <-ticker:
		case <-fuzzer.needPoll:
			poll = true
		}
		if fuzzer.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second*fuzzer.timeouts.Scale {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second*fuzzer.timeouts.Scale {
			needCandidates := fuzzer.workQueue.wantCandidates()
			if poll && !needCandidates {
				continue
			}
			stats := make(map[string]uint64)
			for _, proc := range fuzzer.procs {
				stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
				stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}
			for stat := Stat(0); stat < StatCount; stat++ {
				v := atomic.SwapUint64(&fuzzer.stats[stat], 0)
				stats[statNames[stat]] = v
				execTotal += v
			}
			if !fuzzer.poll(needCandidates, stats) {
				lastPoll = time.Now()
			}
		}
	}
}

func (fuzzer *Fuzzer) poll(needCandidates bool, stats map[string]uint64) bool {
	a := &rpctype.PollArgs{
		Name:           fuzzer.name,
		NeedCandidates: needCandidates,
		MaxSignal:      fuzzer.grabNewSignal().Serialize(),
		Stats:          stats,
	}
	r := &rpctype.PollRes{}
	if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
		log.Fatalf("Manager.Poll call failed: %v", err)
	}
	maxSignal := r.MaxSignal.Deserialize()
	log.Logf(1, "poll: candidates=%v inputs=%v signal=%v",
		len(r.Candidates), len(r.NewInputs), maxSignal.Len())
	fuzzer.addMaxSignal(maxSignal)
	for _, inp := range r.NewInputs {
		fuzzer.addInputFromAnotherFuzzer(inp)
	}
	for _, candidate := range r.Candidates {
		fuzzer.addCandidateInput(candidate)
	}
	if needCandidates && len(r.Candidates) == 0 && atomic.LoadUint32(&fuzzer.triagedCandidates) == 0 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 1)
	}
	return len(r.NewInputs) != 0 || len(r.Candidates) != 0 || maxSignal.Len() != 0
}

func (fuzzer *Fuzzer) sendInputToManager(inp rpctype.Input) {
	a := &rpctype.NewInputArgs{
		Name:  fuzzer.name,
		Input: inp,
	}
	if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
		log.Fatalf("Manager.NewInput call failed: %v", err)
	}
}

func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp rpctype.Input) {
	p := fuzzer.deserializeInput(inp.Prog)
	if p == nil {
		return
	}
	sig := hash.Hash(inp.Prog)
	sign := inp.Signal.Deserialize()
	fuzzer.addInputToCorpus(p, sign, sig, []uint32{}, map[*prog.Syscall][][]uint32{})
}

func (fuzzer *Fuzzer) addCandidateInput(candidate rpctype.Candidate) {
	p := fuzzer.deserializeInput(candidate.Prog)
	if p == nil {
		return
	}
	flags := ProgCandidate
	if candidate.Minimized {
		flags |= ProgMinimized
	}
	if candidate.Smashed {
		flags |= ProgSmashed
	}
	fuzzer.workQueue.enqueue(&WorkCandidate{
		p:     p,
		flags: flags,
	})
}

func (fuzzer *Fuzzer) deserializeInput(inp []byte) *prog.Prog {
	p, err := fuzzer.target.Deserialize(inp, prog.NonStrict)
	if err != nil {
		log.Fatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	// We build choice table only after we received the initial corpus,
	// so we don't check the initial corpus here, we check it later in BuildChoiceTable.
	if fuzzer.choiceTable != nil {
		fuzzer.checkDisabledCalls(p)
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil
	}
	return p
}

func (fuzzer *Fuzzer) checkDisabledCalls(p *prog.Prog) {
	for _, call := range p.Calls {
		if !fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v [%v]\n", call.Meta.Name, call.Meta.ID)
			sandbox := ipc.FlagsToSandbox(fuzzer.config.Flags)
			fmt.Printf("check result for sandbox=%v:\n", sandbox)
			for _, id := range fuzzer.checkResult.EnabledCalls[sandbox] {
				meta := fuzzer.target.Syscalls[id]
				fmt.Printf("  %v [%v]\n", meta.Name, meta.ID)
			}
			fmt.Printf("choice table:\n")
			for i, meta := range fuzzer.target.Syscalls {
				fmt.Printf("  #%v: %v [%v]: enabled=%v\n", i, meta.Name, meta.ID, fuzzer.choiceTable.Enabled(meta.ID))
			}
			panic("disabled syscall")
		}
	}
}

func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand) *prog.Prog {
	randVal := r.Int63n(fuzzer.sumPrios + 1)
	idx := sort.Search(len(fuzzer.corpusPrios), func(i int) bool {
		return fuzzer.corpusPrios[i] >= randVal
	})
	return fuzzer.corpus[idx]
}

var updateLogMu sync.Mutex

func (fuzzer *Fuzzer) updateSyscallPair_debug(p *prog.Prog, addrs []uint32, allCover map[*prog.Syscall][][]uint32) {
    logFile := fmt.Sprintf("/home/debug/updateVerifiedAndFreq_debug_%x.log", hash.Hash(p.Serialize()))
    updateLogMu.Lock()
    defer updateLogMu.Unlock()
    file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Logf(0, "Failed to open log file: %v", err)
        return
    }
    defer file.Close()
    stdlog.SetOutput(file)

	// 0. 打印种子
	fmt.Fprintf(file, "[debug] seed program:\n%s", p.Serialize())

	// 1. 打印原始addrs内容
    fmt.Fprintf(file, "[debug] raw addrs: %v\n", addrs)

    // 2. 转换为64位地址并打印
    var addrList []string
    for _, addr32 := range addrs {
        addr := uint64(addr32)
        // 高位补1直到64位
        if addr < 0xffffffff80000000 {
            addr |= 0xffffffff00000000
        }
        addrStr := fmt.Sprintf("0x%016x", addr)
        addrList = append(addrList, addrStr)
    }
    fmt.Fprintf(file, "[debug] 64bit addrs(hex): %v\n", addrList)

    // 3. addr2line转换为<source,line>并打印
    vmlinux := "/home/vmlinux"
    lines := make(map[string]struct{})
    if len(addrList) > 0 {
    	args := append([]string{"-e", vmlinux}, addrList...)
    	cmd := exec.Command("addr2line", args...)
    	out, err := cmd.Output()
    	if err != nil {
    	    fmt.Fprintf(file, "[debug] addr2line failed: %v\n", err)
    	    log.Logf(0, "addr2line failed: %v", err)
    	} else {
    	    results := strings.Split(strings.TrimSpace(string(out)), "\n")
    	    for i, res := range results {
    	        // 只保留linux下的相对路径
    	        idx := strings.Index(res, "/home/jiakai/linux/")
    	        if idx != -1 {
    	            res = res[idx+len("/home/jiakai/linux/"):]
    	        }
				idx = strings.Index(res, "./")
    	        if idx != -1 {
    	            res = res[idx+len("./"):]
    	        }
				if idx := strings.Index(res, " (discriminator"); idx != -1 {
    				res = res[:idx]
				}
    	        if idx := strings.LastIndex(res, ":"); idx != -1 {
    	            source := res[:idx]
    	            line := res[idx+1:]
    	            key := source + ":" + line
    	            lines[key] = struct{}{}
					fmt.Fprintf(file, "[debug] addr2line(%s) = source=%s line=%s\n",addrList[i], source, line)
    	        } else {
					fmt.Fprintf(file, "[debug] addr2line error\n")
				}
    	    }
    	}
	}
    fmt.Fprintf(file, "[debug] lines: %v\n", lines)

    // 4. 检查p中是否包含<target,relate>，并比对source,line, 进而更新verified
    if fuzzer.choiceTable == nil || fuzzer.choiceTable.SyscallPair == nil {
        return
    }
	foundDependency := false
    for i, call := range p.Calls {
        infos, ok := fuzzer.choiceTable.SyscallPair[call.Meta]
        if !ok {
    	    // 没有找到任何以当前 syscall 为 target 的依赖关系
    	    fmt.Fprintf(file, "[updateVerifiedAndFreq_debug] Program call #%d (%s) is not a target syscall\n", i, call.Meta.Name)
    	    continue
    	}
    	if len(infos) == 0 {
    	    fmt.Fprintf(file, "[updateVerifiedAndFreq_debug] Target syscall %s found but has no relate syscalls\n", call.Meta.Name)
    	    continue
    	}
    	foundAnyRelate := false
        for _, info := range infos {
			foundRelateInProgram := false
            for j := i + 1; j < len(p.Calls); j++ {
                if p.Calls[j].Meta == info.Relate {
					foundDependency = true
					foundRelateInProgram = true
                	foundAnyRelate = true
                    key := info.Source + ":" + strconv.Itoa(info.Line)
                    if _, ok := lines[key]; ok {
                        wasVerified := info.Verified
                        info.Verified = true
                        info.Freq++
                        if !wasVerified {
							fmt.Fprintf(file, "[updateVerifiedAndFreq_debug] <Target: %s, Relate: %s> Verified=true by source match\n", call.Meta.Name, info.Relate.Name)
                        }
						fmt.Fprintf(file, "[updateVerifiedAndFreq_debug] <Target: %s, Relate: %s> Freq=%d (source match)\n", call.Meta.Name, info.Relate.Name, info.Freq)
                    } else {
						fmt.Fprintf(file, "[updateVerifiedAndFreq_debug] <Target: %s, Relate: %s> not matched in lines\n", call.Meta.Name, info.Relate.Name)
                    }
                    break
                }
            }
			if !foundRelateInProgram {
        	    fmt.Fprintf(file, "[updateVerifiedAndFreq_debug] Target %s has relate %s but it is not present in this program\n", call.Meta.Name, info.Relate.Name)
        	}
        }
		if !foundAnyRelate {
    	    fmt.Fprintf(file, "[updateVerifiedAndFreq_debug] Target %s has %d relates but none were found in this program\n", call.Meta.Name, len(infos))
    	}
    }

	// 5. 若种子中不包含<target,relate>，则分析种子，判断是否存在两个系统调用所执行的source-line被同一配置项管辖，若是，则添加SyscallPairInfo_debug
	// 假设 configMap 已经初始化好
	var configMap map[string]string // key: source-line, value: config name
	if !foundDependency {
		// 5-1. 将 allCover 中的 cover 转为 source-line
		callSourceLines := make(map[*prog.Syscall]map[string]struct{})
		for meta, covers := range allCover {
		    callSourceLines[meta] = make(map[string]struct{})
		    for _, cover := range covers {
		        for _, addr := range cover {
		            // 转换 addr 为 source-line
		            addrStr := fmt.Sprintf("0x%016x", uint64(addr))
		            // 调用 addr2line，可以考虑缓存结果以提升效率
		            cmd := exec.Command("addr2line", "-e", "/home/vmlinux", addrStr)
		            out, err := cmd.Output()
		            if err != nil {
		                continue
		            }
		            res := strings.TrimSpace(string(out))
		            idx := strings.Index(res, "linux/")
		            if idx != -1 {
		                res = res[idx+len("linux/"):]
		            }
		            if idx := strings.Index(res, " (discriminator"); idx != -1 {
		                res = res[:idx]
		            }
		            if idx := strings.LastIndex(res, ":"); idx != -1 {
		                sourceLine := res
		                callSourceLines[meta][sourceLine] = struct{}{}
		            }
		        }
		    }
		}

		// 5-2. 双重循环判断是否有两个 syscall 的 cover 被同一配置项管辖
		for meta1, lines1 := range callSourceLines {
		    for meta2, lines2 := range callSourceLines {
		        if meta1 == meta2 {
		            continue
		        }
		        for l1 := range lines1 {
		            for l2 := range lines2 {
		                config1, ok1 := configMap[l1]
		                config2, ok2 := configMap[l2]
		                if ok1 && ok2 && config1 == config2 && config1 != "" {
		                    // 被同一配置项管辖
		                    // 插入到SyscallPair
		                    info := &prog.SyscallPairInfo_debug{
		                        Relate:   meta2,
		                        Verified: false,
		                        Freq:     0,
		                        Source:   l1 + "|" + l2,// 疑点
		                        Line:     0,
		                    }
		                    fuzzer.choiceTable.SyscallPair[meta1] = append(fuzzer.choiceTable.SyscallPair[meta1], info)
		                }
		            }
		        }
		    }
		}
	}
}

// 在种子加入到种子库之后,更新ChoiceTable的SyscallPair字段
func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, sig hash.Sig, addrs []uint32, allCover map[*prog.Syscall][][]uint32) {
	fuzzer.corpusMu.Lock()
	added := false
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = struct{}{}
		prio := int64(len(sign))
		if sign.Empty() {
			prio = 1
		}
		fuzzer.sumPrios += prio
		fuzzer.corpusPrios = append(fuzzer.corpusPrios, fuzzer.sumPrios)
		added = true
	}
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}

	if added {
		go fuzzer.updateSyscallPair_debug(p, addrs, allCover)
	}
}

func (fuzzer *Fuzzer) snapshot() FuzzerSnapshot {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	return FuzzerSnapshot{fuzzer.corpus, fuzzer.corpusPrios, fuzzer.sumPrios}
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}

func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	for i, inf := range info.Calls {
		if fuzzer.checkNewCallSignal(p, &inf, i) {
			calls = append(calls, i)
		}
	}
	extra = fuzzer.checkNewCallSignal(p, &info.Extra, -1)
	return
}

func (fuzzer *Fuzzer) checkNewCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	if diff.Empty() {
		return false
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	fuzzer.maxSignal.Merge(diff)
	fuzzer.newSignal.Merge(diff)
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()
	return true
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.Fatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}
