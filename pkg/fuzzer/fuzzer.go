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
	"path/filepath"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	// "github.com/google/syzkaller/pkg/log"
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
	Vmlinux string

	execQueues

	// lastLogTime  time.Time
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
		relFile := normalizeSourcePath(file)
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
            res[relFile] = append(res[relFile], LineRangeConfig{
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
        Source  string   `json:"Source"`
        Line    int      `json:"Line"`
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
		relSource := normalizeSourcePath(dep.Source) // 转为相对路径
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

                // 插入到ChoiceTable.SyscallPair
                if ct.SyscallPair == nil {
                    ct.SyscallPair = make(map[*prog.Syscall][]*prog.SyscallPairInfo)
                }
                ct.SyscallPair[tgt] = append(ct.SyscallPair[tgt], &prog.SyscallPairInfo{
                    Relate:   rel,
                    Verified: false,
                    Freq:     0,
                    Source:   relSource,
                    Line:     dep.Line,
                })
				// f.Logf(0, "Transforming address for pair %v->%v: origin=0x%x, now=0x%x", tname, rname, dep.Addr, finalAddr)

                // 对每个系统调用对生成2个不同的种子程序
                baseRnd := rnd.Int63() // 为这对系统调用生成一个基础随机数
                for i := 0; i < 2; i++ {
                    // 每次使用不同的种子初始化新的随机数生成器
                    iterRnd := rand.New(rand.NewSource(baseRnd + int64(i)))
                    p, err := prog.GenerateSeedFromSyscallPair(f.target, ct, tgt, rel, iterRnd)
                    if err != nil {
                        f.Logf(0, "failed to generate seed %d for %v->%v: %v", i+1, tname, rname, err)
                        continue
                    }
                    seeds = append(seeds, p)
                }
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

// normalizeSourcePath converts an absolute source path from addr2line to a relative path
// that can be used as a key in the SourceLineToConfig map.
// It assumes the kernel source code is in a directory named "linux" and strips
// the prefix up to and including the first occurrence of "/linux/".
func normalizeSourcePath(absPath string) string {
    // First, clean the path to resolve any "." or ".." components and use forward slashes.
    cleanedPath := filepath.ToSlash(filepath.Clean(absPath))

    // The heuristic is to find the first occurrence of "/linux/" which is assumed to be
    // the kernel source root directory. This is more robust than LastIndex due to
    // subdirectories like "include/linux".
    const marker = "/linux/"
    if idx := strings.Index(cleanedPath, marker); idx != -1 {
        // The relative path starts after the marker.
        return cleanedPath[idx+len(marker):]
    }

    // Fallback for paths that don't contain "/linux/". This might happen with
    // out-of-tree modules or unusual build setups. We return the original
    // cleaned path and let the map lookup handle it.
    return cleanedPath
}

// TempSyscallPairUpdate 用于存储需要更新的系统调用对信息
type TempSyscallPairUpdate struct {
    Target   *prog.Syscall
    Relate   *prog.Syscall
    Source   string
    Line     int
    Verified bool
    Freq     int
}

var (
    tempPairUpdates []TempSyscallPairUpdate
    tempPairMu      sync.RWMutex
    updaterStarted  sync.Once
)

// startPairUpdater 启动一个后台线程定期检查和更新临时存储的系统调用对
func (f *Fuzzer) startPairUpdater() {
    updaterStarted.Do(func() {
        go func() {
            for {
                time.Sleep(10 * time.Minute)
                
                tempPairMu.Lock()
                if len(tempPairUpdates) >= 50 {
                    f.Logf(0, "------------[ Batch Update SyscallPair Start ]------------")
                    f.Logf(0, "Found %d updates to process", len(tempPairUpdates))
                    
                    // 获取当前所有更新
                    updates := tempPairUpdates
                    tempPairUpdates = nil // 清空临时存储
                    
                    // 统计信息
                    verifiedCount := 0
                    newPairCount := 0
                    
                    // 批量更新到 SyscallPair
                    for _, update := range updates {
                        found := false
                        pairs := f.ct.SyscallPair[update.Target]
                        for _, pair := range pairs {
                            if pair.Relate == update.Relate &&
                               pair.Source == update.Source &&
                               pair.Line == update.Line {
                                // 更新已存在的记录
                                f.ct.Mu.Lock()
                                pair.Verified = update.Verified
                                pair.Freq += update.Freq
                                f.ct.Mu.Unlock()
                                found = true
                                verifiedCount++
                                f.Logf(0, "  -> [VERIFIED] %v -> %v (%s:%d), new freq: %d", 
                                    update.Target.Name, update.Relate.Name, 
                                    update.Source, update.Line, pair.Freq)
                                break
                            }
                        }
                        if !found {
                            // 添加新记录
                            f.ct.Mu.Lock()
                            if f.ct.SyscallPair == nil {
                                f.ct.SyscallPair = make(map[*prog.Syscall][]*prog.SyscallPairInfo)
                            }
                            f.ct.SyscallPair[update.Target] = append(f.ct.SyscallPair[update.Target], 
                                &prog.SyscallPairInfo{
                                    Relate:   update.Relate,
                                    Verified: update.Verified,
                                    Freq:     update.Freq,
                                    Source:   update.Source,
                                    Line:     update.Line,
                                })
                            f.ct.Mu.Unlock()
                            newPairCount++
                            f.Logf(0, "  -> [NEW] Added pair: %v -> %v (%s:%d)", 
                                update.Target.Name, update.Relate.Name,
                                update.Source, update.Line)
                        }
                    }
                    
                    f.Logf(0, "Update Summary:")
                    f.Logf(0, "  - Verified existing pairs: %d", verifiedCount)
                    f.Logf(0, "  - Added new pairs: %d", newPairCount)
                    f.Logf(0, "------------[ Batch Update SyscallPair End ]------------")
                }
                tempPairMu.Unlock()
            }
        }()
    })
}

func (f *Fuzzer) UpdateSyscallPairFromProg(p *prog.Prog, allCover map[*prog.Syscall][]uint64) {
    // 确保更新线程已启动
    f.startPairUpdater()
    // if len(p.Calls) != 7 {
    //     return
    // }
    // f.mu.Lock()
    // if time.Since(f.lastLogTime) < 50*time.Minute {
    //     f.mu.Unlock()
    //     return
    // }
    // f.lastLogTime = time.Now()
    // f.mu.Unlock()

    // // 日志 1: 打印正在处理的程序和其产生的覆盖信息。
    // f.Logf(0, "------------[ UpdateSyscallPairFromProg Start ]------------")
    // f.Logf(0, "-> Processing Program:\n%s", p.Serialize())
    // f.Logf(0, "-> Coverage Information:")
    // for syscall, covers := range allCover {
    //     if len(covers) > 0 {
    //         var paths []string
    //         for _, addr := range covers {
    //             paths = append(paths, fmt.Sprintf("0x%x", addr))
    //         }
    //         f.Logf(0, "  -> Syscall[%s] triggered %d addresses: %s", syscall.Name, len(covers), strings.Join(paths, ", "))
    //     }
    // }
	ct := f.ct
	f.ct.Mu.RLock()
	if ct == nil || ct.SyscallPair == nil {
		// 如果在检查时发现 ct 或 SyscallPair 为 nil，必须先释放读锁再返回，
		// 否则会导致后续尝试获取写锁的协程死锁。
		f.ct.Mu.RUnlock()
		// f.Logf(0, "-> Choice table or SyscallPair map is nil, skipping update.")
		// f.Logf(0, "------------[ UpdateSyscallPairFromProg End ]------------")
		return
	}
	f.ct.Mu.RUnlock()
    calls := p.Calls
    vmlinux := f.Vmlinux

    addrToConfigs := func(addr uint64) (string, int, []string) {
        hexAddr := fmt.Sprintf("0x%x", addr)
        out, err := exec.Command("addr2line", "-e", vmlinux, hexAddr).Output()
        if err != nil {
            // f.Logf(0, "  -> addr2line failed for %s: %v", hexAddr, err)
            return "", 0, nil
        }
        line := string(out)
        idx := strings.LastIndex(line, ":")
        if idx < 0 {
            return "", 0, nil
        }
        src := line[:idx]
        lineno, _ := strconv.Atoi(strings.TrimSpace(line[idx+1:]))
        rel := normalizeSourcePath(src)
		var configs []string
		if ranges, ok := f.SourceLineToConfig[rel]; ok {
			for _, r := range ranges {
				// If StartLine and EndLine are both 0, treat the range as
				// applying to the whole file (match any lineno).
				if (r.StartLine == 0 && r.EndLine == 0) || (lineno >= r.StartLine && lineno <= r.EndLine) {
					configs = append(configs, r.Configs...)
				}
			}
		}
        // 日志 4: 打印 addr2line 的结果
        if len(configs) > 0 {
            // f.Logf(0, "  -> Addr 0x%x -> %s:%d -> CONFIGs: [%s]", addr, rel, lineno, strings.Join(configs, ", "))
        }
        return rel, lineno, configs
    }

	// 新增：收集corpus已覆盖的所有addr
	var corpusAddrs map[uint64]struct{}
	if f.Config != nil && f.Config.Corpus != nil {
		corpusAddrs = make(map[uint64]struct{})
		for _, addr := range f.Config.Corpus.PCs() {
			corpusAddrs[addr] = struct{}{}
		}
	}

    // 1. 先做已有pair的验证
    // f.Logf(0, "\n-> Phase 1: Verifying existing syscall pairs...")
    for i := 0; i < len(calls); i++ {
        sa := calls[i].Meta
        targetCovers, hasTargetCover := allCover[sa]
        if !hasTargetCover {
            continue
        }
        for j := 0; j < len(calls); j++ {
            if i == j {
                continue
            }
            sb := calls[j].Meta
            pairList := ct.SyscallPair[sa]
            for _, pair := range pairList {
                if pair.Relate == sb {
                    // 日志 2: 发现一个需要验证的 pair。
                    // f.Logf(0, "  -> Checking existing pair %s -> %s for address 0x%x", sa.Name, sb.Name, pair.Addr)
                    found := false
                	// 检查 target syscall 的覆盖
					for _, addr := range targetCovers {
						src, line, _ := addrToConfigs(addr)
						if src == pair.Source && line == pair.Line {
							tempPairMu.Lock()
							tempPairUpdates = append(tempPairUpdates, TempSyscallPairUpdate{
							    Target:   sa,
							    Relate:   sb,
							    Source:   pair.Source,
							    Line:     pair.Line,
							    Verified: true,
							    Freq:     1,
							})
							tempPairMu.Unlock()
                	    	// f.Logf(0, "  -> [SUCCESS] Verified pair: %s -> %s (%s:%d found). New Freq: %d", sa.Name, sb.Name, pair.Source, pair.Line, pair.Freq)
							break
						} else {
							// 新逻辑：src/line不匹配时，判断是否为corpus新覆盖且未被SyscallPair记录
							if f.Config != nil && f.Config.Corpus != nil {
								isNew := true
								for _, caddr := range f.Config.Corpus.PCs() {
									if caddr == addr {
										isNew = false
										break
									}
								}
								if isNew {
									already := false
									for _, p := range ct.SyscallPair[sa] {
										if p.Relate == sb && p.Source == src && p.Line == line {
											already = true
											break
										}
									}
									if !already && src != "" && line != 0 {
										tempPairMu.Lock()
										tempPairUpdates = append(tempPairUpdates, TempSyscallPairUpdate{
										    Target:   sa,
										    Relate:   sb,
										    Source:   src,
										    Line:     line,
										    Verified: true,
										    Freq:     1,
										})
										tempPairMu.Unlock()
										// f.Logf(0, "  -> [NEW SOURCELINE] Added by new addr: %s -> %s (%s:%d)", sa.Name, sb.Name, src, line)
									}
								}
							}
						}
					}
					// 如果在 target 中没找到，则检查 relate syscall 的覆盖
					if !found {
						if relateCovers, ok := allCover[sb]; ok {
							for _, addr := range relateCovers {
								src, line, _ := addrToConfigs(addr)
								if src == pair.Source && line == pair.Line {
									tempPairMu.Lock()
									tempPairUpdates = append(tempPairUpdates, TempSyscallPairUpdate{
									    Target:   sa,
									    Relate:   sb,
									    Source:   pair.Source,
									    Line:     pair.Line,
									    Verified: true,
									    Freq:     1,
									})
									tempPairMu.Unlock()
                	    			// f.Logf(0, "  -> [SUCCESS] Verified pair: %s -> %s (%s:%d found). New Freq: %d", sa.Name, sb.Name, pair.Source, pair.Line, pair.Freq)
									break
								} else {
									if f.Config != nil && f.Config.Corpus != nil {
										isNew := true
										for _, caddr := range f.Config.Corpus.PCs() {
											if caddr == addr {
												isNew = false
												break
											}
										}
										if isNew {
											already := false
											for _, p := range ct.SyscallPair[sa] {
												if p.Relate == sb && p.Source == src && p.Line == line {
													already = true
													break
												}
											}
											if !already && src != "" && line != 0 {
												tempPairMu.Lock()
												tempPairUpdates = append(tempPairUpdates, TempSyscallPairUpdate{
												    Target:   sa,
												    Relate:   sb,
												    Source:   src,
												    Line:     line,
												    Verified: true,
												    Freq:     1,
												})
												tempPairMu.Unlock()
												// f.Logf(0, "  -> [NEW SOURCELINE] Added by new addr: %s -> %s (%s:%d)", sa.Name, sb.Name, src, line)
											}
										}
									}
								}
							}
						}
					}
                }
            }
        }
    }

    // 2. 自动发现新pair
    // f.Logf(0, "\n-> Phase 2: Discovering new pairs from shared CONFIGs...")
    
    // 收集每个call的source:line->config映射
	callConfigSet := make(map[*prog.Syscall]map[string][]struct{Source string; Line int})
	for _, call := range calls {
	    sa := call.Meta
	    addrs, ok := allCover[sa]
	    if !ok {
	        continue
	    }
	    for _, addr := range addrs {
	        src, line, configs := addrToConfigs(addr)
	        if src == "" || line == 0 {
	            continue
	        }
	        for _, cfg := range configs {
	            if callConfigSet[sa] == nil {
	                callConfigSet[sa] = make(map[string][]struct{Source string; Line int})
	            }
	            callConfigSet[sa][cfg] = append(callConfigSet[sa][cfg], struct{Source string; Line int}{src, line})
	        }
	    }
	}

    // 任意两个call，若有config交集且不在SyscallPair里，则插入
    for i := 0; i < len(calls); i++ {
        sa := calls[i].Meta
        for j := 0; j < len(calls); j++ {
            if i == j {
                continue
            }
            sb := calls[j].Meta
            // 跳过已在SyscallPair的
            already := false
            for _, pair := range ct.SyscallPair[sa] {
                if pair.Relate == sb {
                    already = true
                    break
                }
            }
            if already {
                continue
            }
            
            configsA := callConfigSet[sa]
            configsB := callConfigSet[sb]
            if configsA == nil || configsB == nil {
                continue
            }
        	for cfg, srcLinesA := range configsA {
        	    if srcLinesB, ok := configsB[cfg]; ok {
        	        // f.Logf(0, "  -> [NEW DISCOVERY] Found shared CONFIG '%s' between %s and %s", cfg, sa.Name, sb.Name)
					tempPairMu.Lock()
        	        // 为 sa -> sb 添加所有相关 source:line
        	        for _, sl := range srcLinesA {
						tempPairUpdates = append(tempPairUpdates, TempSyscallPairUpdate{
						    Target:   sa,
						    Relate:   sb,
						    Source:   sl.Source,
						    Line:     sl.Line,
						    Verified: false,
						    Freq:     0,
						})
        	        }
        	        // 为 sb -> sa 添加所有相关 source:line
        	        for _, sl := range srcLinesB {
						tempPairUpdates = append(tempPairUpdates, TempSyscallPairUpdate{
						    Target:   sb,
						    Relate:   sa,
						    Source:   sl.Source,
						    Line:     sl.Line,
						    Verified: false,
						    Freq:     0,
						})
        	        }
					tempPairMu.Unlock()
        	    }
        	}
        }
    }
    // f.Logf(0, "------------[ UpdateSyscallPairFromProg End ]--------------")
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
		if fuzzer.ct != nil && fuzzer.ct.SyscallPair != nil {
			// 深拷贝 SyscallPair map 和切片，避免与正在被更新的旧表共享底层数据结构，
			// 并在读取时使用 ct.Mu 的读锁以防止并发写入。
			f := fuzzer.ct
			f.Mu.RLock()
			newMap := make(map[*prog.Syscall][]*prog.SyscallPairInfo, len(f.SyscallPair))
			for k, v := range f.SyscallPair {
				if v == nil {
					newMap[k] = nil
					continue
				}
				copied := make([]*prog.SyscallPairInfo, len(v))
				copy(copied, v)
				newMap[k] = copied
			}
			f.Mu.RUnlock()
			newCt.SyscallPair = newMap
		}
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
