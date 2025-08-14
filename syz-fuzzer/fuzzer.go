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
    "strings"
	"strconv"
	"bytes"

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

// 存储每一行区间和对应 CONFIG 的映射
type LineRangeConfig struct {
    StartLine int
    EndLine   int
    Configs   []string
}

// 保存每个源文件对应的行范围与 CONFIG 的映射
type SourceLineToConfig map[string][]LineRangeConfig

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

	sourceLineToConfig SourceLineToConfig
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

// 输入: 包含具有依赖信息的系统调用对的 json 文件
// 输出: 根据每个具有依赖关系的系统调用对生成一个种子
func generateSeedsFromJSON_debug(jsonPath string, choiceTable *prog.ChoiceTable, target *prog.Target) ([]*prog.Prog, error) {
    // 存储已生成种子的 target + relate 组合（防止重复）
	generatedPairs := make(map[string]bool)
	if jsonPath == "" {
        log.Logf(0, "FlagSyscallPair is empty")
        return nil, nil
    }
    // log.Logf(0, "FlagSyscallPair: %s", jsonPath)

    data, err := os.ReadFile(jsonPath)
    if err != nil {
        return nil, fmt.Errorf("Failed to read JSON file: %v", err)
    }

    var dependencies []struct {
        Targets []string `json:"Target"`
        Relate  []string `json:"Relate"`
        Addr    uint32   `json:"Addr"`
    }

    // 解析 JSON 数据，适配新结构
    if err := json.Unmarshal(data, &dependencies); err != nil {
        return nil, fmt.Errorf("Failed to parse JSON file: %v", err)
    }

	maxPairs := 200000
	if len(dependencies) > maxPairs {
	    dependencies = dependencies[:maxPairs]
	    log.Logf(0, "Limiting to first %d syscall pairs", maxPairs)
	}

    var seeds []*prog.Prog
    rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
    choiceTable.SyscallPair = make(map[*prog.Syscall][]*prog.SyscallPairInfo_debug)

    for _, dep := range dependencies {
        // 遍历每一个 Target
        for _, targetName := range dep.Targets {
            targetCall := target.SyscallMap[targetName]
            if targetCall == nil || !choiceTable.Enabled(targetCall.ID) {
                // log.Logf(0, "Unknown target syscall: %v", targetName)
                continue
            }

            var relateInfos []*prog.SyscallPairInfo_debug
            for _, relate := range dep.Relate {
                relateCall := target.SyscallMap[relate]
                if relateCall == nil || !choiceTable.Enabled(relateCall.ID) {
                    // log.Logf(0, "Unknown relate syscall: %v", relate)
                    continue
                }
				pairKey := fmt.Sprintf("%s:%s", targetName, relate)
            	if generatedPairs[pairKey] {
            	    log.Logf(1, "Skipping duplicate seed generation for %v -> %v", targetName, relate)
            	    continue // 已经有 seed 被生成过了，跳过
            	}
			
            	// 把这个 pair 标记为已生成过 seed
            	generatedPairs[pairKey] = true
                relateInfos = append(relateInfos, &prog.SyscallPairInfo_debug{
                    Relate:   relateCall,
                    Verified: false,
                    Freq:     0,
                    Addr:     dep.Addr,
                })
                // log.Logf(0, "Generating seed for \nTarget: %s, Relate: %s", targetName, relate)
                p, err := prog.GenerateSeedFromSyscallPair_debug(target, choiceTable, targetCall, relateCall, rnd)
                if err != nil {
                    log.Logf(0, "Failed to generate seed program for %v and %v: %v", targetName, relate, err)
                    continue
                }
                // log.Logf(0, "Generated seed with %d calls", len(p.Calls))
                seeds = append(seeds, p)
            }
            if len(relateInfos) > 0 {
                choiceTable.SyscallPair[targetCall] = relateInfos
            }
        }
    }

    // 打印 SyscallPair 信息供调试
    // log.Logf(0, "==== SyscallPair ====")
    // for targetCall, relates := range choiceTable.SyscallPair {
    //     log.Logf(0, "Target: %s", targetCall.Name)
    //     for _, info := range relates {
    //         log.Logf(0, "    Relate: %s, Verified: %v, Freq: %d, Addr: %d", info.Relate.Name, info.Verified, info.Freq, info.Addr)
    //     }
    // }
    // log.Logf(0, "==== SyscallPair ====")

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
	// fuzzer.workQueue.PrintAll_debug()
    for _, seed := range seeds {
        fuzzer.workQueue.enqueue(&WorkCandidate{
            p:     seed,
            flags: ProgCandidate,
        })
    }
	// fuzzer.workQueue.PrintAll_debug()
    log.Logf(0, "Generated %d seeds from JSON file", len(seeds))
}

func loadSourceLineToConfig(jsonPath string) (SourceLineToConfig, error) {
    data, err := os.ReadFile(jsonPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read file: %v", err)
    }

    var raw map[string]map[string][]string
    if err := json.Unmarshal(data, &raw); err != nil {
        return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
    }

    result := make(SourceLineToConfig)

    for file, lineRanges := range raw {
        for lineRangeStr, configs := range lineRanges {
            parts := strings.Split(lineRangeStr, "-")
            if len(parts) != 2 {
                log.Logf(0, "Invalid line range format: %s", lineRangeStr)
                continue
            }
            start, err1 := strconv.Atoi(parts[0])
            end, err2 := strconv.Atoi(parts[1])
            if err1 != nil || err2 != nil {
                log.Logf(0, "Invalid line numbers in range: %s", lineRangeStr)
                continue
            }
            result[file] = append(result[file], LineRangeConfig{
                StartLine: start,
                EndLine:   end,
                Configs:   configs,
            })
        }
    }

    return result, nil
}


// PrintSourceLineToConfig_debug 打印 sourceLineToConfig 的内容，用于调试
func (f *Fuzzer) PrintSourceLineToConfig_debug() string {
    var buf bytes.Buffer
    buf.WriteString("SourceLineToConfig Debug Info:\n")
    
    // 按文件名排序以保证输出顺序一致
    fileNames := make([]string, 0, len(f.sourceLineToConfig))
    for file := range f.sourceLineToConfig {
        fileNames = append(fileNames, file)
    }
    sort.Strings(fileNames)

    for _, file := range fileNames {
        ranges := f.sourceLineToConfig[file]
        buf.WriteString(fmt.Sprintf("File: %s\n", file))
        for _, lr := range ranges {
            buf.WriteString(fmt.Sprintf("  Lines %d-%d: %v\n", lr.StartLine, lr.EndLine, lr.Configs))
        }
    }

    return buf.String()
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

	
	// 读取sourceline2config
	sourceLineToConfig, err := loadSourceLineToConfig("/home/sourceline2config.json")
	if err != nil {
	    log.Fatalf("Failed to load sourceline2config.json: %v", err)
	}
	fuzzer.sourceLineToConfig = sourceLineToConfig

	// log.Logf(0, "%s", fuzzer.PrintSourceLineToConfig_debug())
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
	fuzzer.addInputToCorpus(p, sign, sig, []uint32{}, map[*prog.Syscall][]uint32{})
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

// 将32位内核PC地址转为64位地址字符串
func addr32To64Hex_debug(addr32 uint32) string {
    addr := uint64(addr32)
    // 高位补1直到64位
    if addr < 0xffffffff80000000 {
        addr |= 0xffffffff00000000
    }
    return fmt.Sprintf("0x%016x", addr)
}

// 调试用的Line2Config_debug函数
func (f *Fuzzer) line2Config(sourceFile string, lineNumber int) []string {
    ranges, ok := f.sourceLineToConfig[sourceFile]
    if !ok {
        return nil
    }
    for _, r := range ranges {
        if lineNumber >= r.StartLine && lineNumber <= r.EndLine {
            return r.Configs
        }
    }
    return nil
}

var updateLogMu sync.Mutex
func (fuzzer *Fuzzer) updateSyscallPair_debug(p *prog.Prog, addrs []uint32, allCover map[*prog.Syscall][]uint32) {
    logFile := fmt.Sprintf("/home/debug/updateSyscallPair_debug_%x.log", hash.Hash(p.Serialize()))
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

    // 2. 检查p中是否包含<target,relate>，并比对addr, 进而更新verified
    if fuzzer.choiceTable == nil || fuzzer.choiceTable.SyscallPair == nil {
        return
    }
	foundDependency := false
    for i, call := range p.Calls {
        infos, ok := fuzzer.choiceTable.SyscallPair[call.Meta]
        if !ok {
    	    // 没有找到任何以当前 syscall 为 target 的依赖关系
    	    fmt.Fprintf(file, "[updateSyscallPair_debug] Program call #%d (%s) is not a target syscall\n", i, call.Meta.Name)
    	    continue
    	}
    	if len(infos) == 0 {
    	    fmt.Fprintf(file, "[updateSyscallPair_debug] Target syscall %s found but has no relate syscalls\n", call.Meta.Name)
    	    continue
    	}
    	foundAnyRelate := false
        for _, info := range infos {
			foundRelateInProgram := false
            for j := i - 1; j >= 0; j-- {
                if p.Calls[j].Meta == info.Relate {
					foundDependency = true
					foundRelateInProgram = true
                	foundAnyRelate = true
					// 直接判断 addr 是否在 addrs 中
                    addrMatched := false
                    for _, a := range addrs {
                        if a == info.Addr {
                            addrMatched = true
                            break
                        }
                    }
                    if addrMatched {
                        wasVerified := info.Verified
                        info.Verified = true
                        info.Freq++
                        if !wasVerified {
							fmt.Fprintf(file, "[updateSyscallPair_debug] <Target: %s, Relate: %s> Verified=true by source match\n", call.Meta.Name, info.Relate.Name)
                        }
						fmt.Fprintf(file, "[updateSyscallPair_debug] <Target: %s, Relate: %s> Freq=%d (source match)\n", call.Meta.Name, info.Relate.Name, info.Freq)
                    } else {
						fmt.Fprintf(file, "[updateSyscallPair_debug] <Target: %s, Relate: %s> not matched in lines\n", call.Meta.Name, info.Relate.Name)
                    }
                    break
                }
            }
			if !foundRelateInProgram {
        	    fmt.Fprintf(file, "[updateSyscallPair_debug] Target %s has relate %s but it is not present in this program\n", call.Meta.Name, info.Relate.Name)
        	}
        }
		if !foundAnyRelate {
    	    fmt.Fprintf(file, "[updateSyscallPair_debug] Target %s has %d relates but none were found in this program\n", call.Meta.Name, len(infos))
    	}
    }

	// 3. 如果p中不包含<target, relate>,那么分析种子，判断是否存在两个系统调用所执行的代码被同一配置项管辖
	if !foundDependency {
		fmt.Fprintf(file, "[updateSyscallPair_debug] Program has no <target, relate>\n")
		fmt.Fprintf(file, "[updateSyscallPair_debug] allCover dump:\n")
    	for syscall, cover := range allCover {
    	    fmt.Fprintf(file, "  Syscall: %s\n    Cover: %v\n", syscall.Name, cover)
    	}

		// 3-1 将allCover中的每个syscall的每个cover都转换成对应的source-line,并把source-line对应到Config
		fmt.Fprintf(file, "[updateSyscallPair_debug] 3-1: uint32 cover -> source:line cover -> config cover\n")
		vmlinux := "/home/vmlinux"
		allConfig := make(map[*prog.Syscall]map[string]struct{})
        for syscall, coverAddrs := range allCover {
            fmt.Fprintf(file, "  Syscall: %s\n", syscall.Name)
            // 转成64位地址字符串
            var addrList []string
            for _, addr32 := range coverAddrs {
                addrList = append(addrList, addr32To64Hex_debug(addr32))
            }
            fmt.Fprintf(file, "    raw cover: %v\n", coverAddrs)
            fmt.Fprintf(file, "    64bit addrs(hex): %v\n", addrList)

            if len(addrList) > 0 {
                args := append([]string{"-e", vmlinux}, addrList...)
                cmd := exec.Command("addr2line", args...)
                out, err := cmd.Output()
                if err != nil {
                    fmt.Fprintf(file, "    [updateSyscallPair_debug] addr2line failed: %v\n", err)
                    continue
                }
                results := strings.Split(strings.TrimSpace(string(out)), "\n")
                for i, res := range results {
                    // 只保留相对路径
                    if idx := strings.Index(res, "/home/jiakai/linux/"); idx != -1 {
                        res = res[idx+len("/home/jiakai/linux/"):]
                    }
                    if idx := strings.Index(res, "./"); idx != -1 {
                        res = res[idx+len("./"):]
                    }
                    if idx := strings.Index(res, " (discriminator"); idx != -1 {
                        res = res[:idx]
                    }
                    if idx := strings.LastIndex(res, ":"); idx != -1 {
                        source := res[:idx]
                        line := res[idx+1:]
                        fmt.Fprintf(file, "    addr2line(%s) = %s:%s\n", addrList[i], source, line)
						lineNum, _ := strconv.Atoi(line)
						configs := fuzzer.line2Config(source, lineNum)
						if len(configs) > 0 {
						    for _, config := range configs {
						        if allConfig[syscall] == nil {
						            allConfig[syscall] = make(map[string]struct{})
						        }
						        if _, exists := allConfig[syscall][config]; !exists {
						            allConfig[syscall][config] = struct{}{}
						            fmt.Fprintf(file, "      [Line2Config_debug] config: %s\n", config)
						        }
						    }
						}
                    } else {
                        fmt.Fprintf(file, "    addr2line(%s) parse error\n", addrList[i])
                    }
                }
            }
        }

		// 3-2 检查 allConfig，若两个 syscall 的 configs 有交集，则插入到 ChoiceTable 的 SyscallPair 字段
		fmt.Fprintf(file, "[updateSyscallPair_debug] 3-2: check config intersection\n")
		for sysA, configsA := range allConfig {
		    for sysB, configsB := range allConfig {
		        if sysA == sysB {
		            continue
		        }
		        // 检查交集
		        for config := range configsA {
		            if _, ok := configsB[config]; ok {
		                // 有交集，插入到 ChoiceTable 的 SyscallPair
		                // 检查是否已存在
               			exists := false
               			for _, info := range fuzzer.choiceTable.SyscallPair[sysA] {
               			    if info.Relate == sysB {
               			        exists = true
               			        break
               			    }
               			}
               			if !exists {
               			    fuzzer.choiceTable.SyscallPair[sysA] = append(fuzzer.choiceTable.SyscallPair[sysA], &prog.SyscallPairInfo_debug{
               			        Relate:   sysB,
               			        Verified: false,
               			        Freq:     0,
               			        Addr:     0,
               			    })
               			    fmt.Fprintf(file, "    [config-intersect] %s <-> %s via config %s\n", sysA.Name, sysB.Name, config)
               			}
		            }
		        }
		    }
		}
	}
}

// 在种子加入到种子库之后,更新ChoiceTable的SyscallPair字段
func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, sig hash.Sig, addrs []uint32, allCover map[*prog.Syscall][]uint32) {
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
