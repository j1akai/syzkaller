// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"
	// stdlog "log"
	// "os/exec"
	// "strings"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer          *Fuzzer
	pid             int
	env             *ipc.Env
	rnd             *rand.Rand
	execOpts        *ipc.ExecOpts
	execOptsCollide *ipc.ExecOpts
	execOptsCover   *ipc.ExecOpts
	execOptsComps   *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsCollide := *fuzzer.execOpts
	execOptsCollide.Flags &= ^ipc.FlagCollectSignal
	execOptsCover := *fuzzer.execOpts
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := *fuzzer.execOpts
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:          fuzzer,
		pid:             pid,
		env:             env,
		rnd:             rnd,
		execOpts:        fuzzer.execOpts,
		execOptsCollide: &execOptsCollide,
		execOptsCover:   &execOptsCover,
		execOptsComps:   &execOptsComps,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	generatePeriod := 100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}
	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			case *WorkCandidate:
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				proc.smashInput(item)
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			continue
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			// Generate a new prog.
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatGenerate)
		} else {
			// Mutate an existing prog.
			p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated", proc.pid)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatFuzz)
		}
	}
}

func (proc *Proc) triageInput(item *WorkTriage) {
	// 这块日志打印目前还有问题，会存在多个triage任务日志写在同一个文件内
	// logFile := fmt.Sprintf("/home/debug/triageInput_%d.log", proc.pid)
	// logFile := fmt.Sprintf("/home/debug/triageInput_%d_%d.log", proc.pid, time.Now().UnixNano())
	logFile := fmt.Sprintf("/home/debug/triageInput_%d_%x.log", 
        proc.pid, hash.Hash(item.p.Serialize()))
	prog.InitLogFile_debug(logFile)

	// 开始时打印种子所有系统调用
    log.Logf(0, "[triage] Initial program syscalls:")
    for i, call := range item.p.Calls {
        log.Logf(0, "  #%d: %s", i, call.Meta.Name)
    }

	// 打印触发新路径的系统调用
    if item.call == -1 {
        log.Logf(0, "[triage] Extra triggered new signal")
    } else {
        log.Logf(0, "[triage] Call #%d %s triggered new signal", item.call, item.p.Calls[item.call].Meta.Name)
		log.Logf(0, "    signal: %v", item.info.Signal)
    }

	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	rawCover := []uint32{}
	for i := 0; i < signalRuns; i++ {
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
        	log.Logf(0, "  #%03d: execution failed | call:%s | failures:%d/%d", 
        	    i, item.p.Calls[item.call].Meta.Name, notexecuted, signalRuns)
			if notexecuted > signalRuns/2+1 {
				log.Logf(0, "  #%03d: ABORTING | too many failures (%d > %d)", 
                	i, notexecuted, signalRuns/2+1)
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
		log.Logf(0, "[triage] Run #%d - Per-call coverage:", i)
    	for callIdx, call := range item.p.Calls {
    	    callCover := info.Calls[callIdx].Cover
    	    log.Logf(0, "  Call #%d %s: coverage=%d PCs: %v", 
    	        callIdx, call.Meta.Name, len(callCover), callCover)
    	}
		if len(rawCover) == 0 && proc.fuzzer.fetchRawCover {
			rawCover = append([]uint32{}, thisCover...)
		}
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			log.Logf(0, "  #%03d: EARLY EXIT | empty signal & non-minimized prog | call:%s", 
            	i, item.p.Calls[item.call].Meta.Name)
			return
		}
		inputCover.Merge(thisCover)
		log.Logf(0, "  #%03d: success | call:%s | signal:%d | coverage:%d", 
        	i, item.p.Calls[item.call].Meta.Name, thisSignal.Len(), len(thisCover))
	}
	// 稳定性测试后打印
    log.Logf(0, "[triage] After stable_test, program syscalls:")
    for i, call := range item.p.Calls {
        log.Logf(0, "  #%d: %s", i, call.Meta.Name)
    }

	if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOpts, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			})
	}

	// 最小化后打印
    log.Logf(0, "[triage] After minimization, program syscalls:")
    for i, call := range item.p.Calls {
        log.Logf(0, "  #%d: %s", i, call.Meta.Name)
    }

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)

	log.Logf(0, "InputCover (%d unique PCs): %v", 
    len(inputCover), inputCover.Serialize())
	log.Logf(0, "inputSignal (%d unique Signals): %v", 
    len(inputSignal), inputSignal.Serialize())

	proc.fuzzer.sendInputToManager(rpctype.Input{
		Call:     callName,
		CallID:   item.call,
		Prog:     data,
		Signal:   inputSignal.Serialize(),
		Cover:    inputCover.Serialize(),
		RawCover: rawCover,
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)

	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 1; nth <= 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		newProg := p.Clone()
		newProg.Calls[call].Props.FailNth = nth
		info := proc.executeRaw(proc.execOpts, newProg, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {
	logFile := fmt.Sprintf("/home/debug/execute_%d_%x.log", 
        proc.pid, hash.Hash(p.Serialize()))
	prog.InitLogFile_debug(logFile)

	execOpts.Flags |= ipc.FlagCollectCover  // 启用覆盖率收集
	info := proc.executeRaw(execOpts, p, stat)
	if info == nil {
		return nil
	}
	calls, extra := proc.fuzzer.checkNewSignal(p, info)

	if execOpts != nil {
        log.Logf(0, "[execute] ExecOpts.Flags: %b (binary)", execOpts.Flags)
        // 或者打印十六进制
        log.Logf(0, "[execute] ExecOpts.Flags: 0x%x (hex)", execOpts.Flags)
        
        // 详细打印每个标志位是否设置
        log.Logf(0, "[execute] ExecOpts flags details:")
        log.Logf(0, "  FlagCollectSignal: %v", execOpts.Flags&ipc.FlagCollectSignal != 0)
        log.Logf(0, "  FlagCollectCover: %v", execOpts.Flags&ipc.FlagCollectCover != 0)
        log.Logf(0, "  FlagDedupCover: %v", execOpts.Flags&ipc.FlagDedupCover != 0)
        log.Logf(0, "  FlagCollectComps: %v", execOpts.Flags&ipc.FlagCollectComps != 0)
        log.Logf(0, "  FlagThreaded: %v", execOpts.Flags&ipc.FlagThreaded != 0)
        log.Logf(0, "  FlagEnableCoverageFilter: %v", execOpts.Flags&ipc.FlagEnableCoverageFilter != 0)
    } else {
        log.Logf(0, "[execute] ExecOpts is nil")
    }

	// 打印当前种子包含哪些系统调用
    log.Logf(0, "[execute] Program syscalls:")
    for i, call := range p.Calls {
        log.Logf(0, "  #%d: %s", i, call.Meta.Name)
    }

	// 打印每个系统调用触发了哪些路径（signal）
    for i, inf := range info.Calls {
        log.Logf(0, "  Call #%d %s triggered signal: %v", i, p.Calls[i].Meta.Name, inf.Signal)
		log.Logf(0, "  Call #%d %s triggered cover: %v", i, p.Calls[i].Meta.Name, inf.Cover)
    }
    log.Logf(0, "  Extra triggered signal: %v", info.Extra.Signal)
	log.Logf(0, "  Extra triggered cover: %v", info.Extra.Cover)

    log.Logf(0, "[execute] Calls triggered new signal: %v", calls)
    if extra {
        log.Logf(0, "[execute] Extra triggered new signal")
    }
    for _, callIndex := range calls {
        log.Logf(0, "  Call #%d %s triggered new signal: %v", callIndex, p.Calls[callIndex].Meta.Name, info.Calls[callIndex].Signal)
    }
    if extra {
        log.Logf(0, "  Extra triggered new signal: %v", info.Extra.Signal)
    }

	for _, callIndex := range calls {
		proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
	}
	if extra {
		proc.enqueueCallTriage(p, flags, -1, info.Extra)
	}
	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

func (proc *Proc) executeAndCollide(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) {
	proc.execute(execOpts, p, flags, stat)

	if proc.execOptsCollide.Flags&ipc.FlagThreaded == 0 {
		// We cannot collide syscalls without being in the threaded mode.
		return
	}
	const collideIterations = 2
	for i := 0; i < collideIterations; i++ {
		proc.executeRaw(proc.execOptsCollide, proc.randomCollide(p), StatCollide)
	}
}

func (proc *Proc) randomCollide(origP *prog.Prog) *prog.Prog {
	// Old-styl collide with a 33% probability.
	if proc.rnd.Intn(3) == 0 {
		p, err := prog.DoubleExecCollide(origP, proc.rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, proc.rnd)
	if proc.rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, proc.rnd)
	}
	return p
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	proc.fuzzer.checkDisabledCalls(p)

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		output, info, hanged, err := proc.env.Exec(opts, p)

		log.Logf(0, "[executeRaw] Exec returned values:")
		log.Logf(0, "  output: %s", output)
		log.Logf(0, "  hanged: %v", hanged)
		log.Logf(0, "  err: %v", err)
		if info != nil {
			log.Logf(0, "  info.Calls: %d calls", len(info.Calls))
			for i, callInfo := range info.Calls {
				log.Logf(0, "    Call #%d: Signal=%v, Cover=%v", i, callInfo.Signal, callInfo.Cover)
			}
			log.Logf(0, "  info.Extra: Signal=%v, Cover=%v", info.Extra.Signal, info.Extra.Cover)
		} else {
			log.Logf(0, "  info: nil")
		}
		if err != nil {
			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than ignoring this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				return nil
			}
			if try > 10 {
				log.Fatalf("executor %v failed %v times: %v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v:\n%s\n",
				proc.pid, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			f.Write(data)
			f.Close()
		}
	default:
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}
