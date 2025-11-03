// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
    "sync"
)

// 新增：riscv 系统调用全局注册（供 fuzzer 收集、prog.Generate 与 mutation 使用）
var (
    riscvMu       sync.RWMutex
    riscvSyscalls []*Syscall
)

// AddRiscvSyscall 注册一个触发了 arch/riscv 路径的 syscall（可重复注册，内部分配时去重）
func AddRiscvSyscall(sc *Syscall) {
    if sc == nil {
        return
    }
    for _, s := range riscvSyscalls {
        if s == sc {
            return
        }
    }
    riscvMu.Lock()
    defer riscvMu.Unlock()
    riscvSyscalls = append(riscvSyscalls, sc)
}

// GetRiscvSyscalls 返回当前注册的 riscv syscall 列表（返回副本）
func GetRiscvSyscalls() []*Syscall {
    riscvMu.RLock()
    defer riscvMu.RUnlock()
    out := make([]*Syscall, len(riscvSyscalls))
    copy(out, riscvSyscalls)
    return out
}

func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
    p := &Prog{
        Target: target,
    }
    r := newRand(target, rs)
    s := newState(target, ct, nil)
    riscvList := GetRiscvSyscalls()
    // Prepare filtered candidates excluding disabled or NoGenerate pseudo-calls.
    var riscvCandidates []*Syscall
    for _, sc := range riscvList {
        if sc == nil || sc.Attrs.Disabled || sc.Attrs.NoGenerate {
            continue
        }
        riscvCandidates = append(riscvCandidates, sc)
    }

    for len(p.Calls) < ncalls {
        // 30% 概率进入这个分支
        // Use filtered riscvCandidates; if empty, fall back to normal generation.
        if len(riscvCandidates) > 0 && r.Intn(10) < 3 {
            // 随机插入 1..3 个 riscv syscall（不超过 ncalls）
            cnt := 1 + r.Intn(3)
            for k := 0; k < cnt && len(p.Calls) < ncalls; k++ {
                sc := riscvCandidates[r.Intn(len(riscvCandidates))]
                calls := r.generateParticularCall(s, sc)
                for _, c := range calls {
                    s.analyze(c)
                    p.Calls = append(p.Calls, c)
                }
            }
            continue
        }
    
        // 新增：在 1/3 ~ 2/3 区间内，优先插入pair(只有40%的机会进入这个特殊逻辑)
        if ct != nil && len(p.Calls) > ncalls/2 && len(p.Calls) <= ncalls*2/3 && r.Intn(10) < 6 {
            // 随机选一个target（在读取 SyscallPair 时使用 RLock 以避免并发写入）
            targets := make([]*Syscall, 0)
            var chosenRelates []*SyscallPairInfo
            ct.Mu.RLock()
            hasPairs := ct != nil && len(ct.SyscallPair) > 0
            if hasPairs {
                for t, relates := range ct.SyscallPair {
                    if len(relates) > 0 {
                        targets = append(targets, t)
                    }
                }
            }
            ct.Mu.RUnlock()
            if len(targets) > 0 {
                targetIdx := r.Intn(len(targets))
                targetCall := targets[targetIdx]
                ct.Mu.RLock()
                relates := ct.SyscallPair[targetCall]
                // make a local copy of relates slice to avoid holding lock while using it
                if len(relates) > 0 {
                    chosenRelates = make([]*SyscallPairInfo, len(relates))
                    copy(chosenRelates, relates)
                }
                ct.Mu.RUnlock()
                relateIdx := r.Intn(len(chosenRelates))
                relateCall := chosenRelates[relateIdx].Relate
                // 先插 relate (skip if not generatable)
                if relateCall.Attrs.Disabled || relateCall.Attrs.NoGenerate {
                    // skip this special pair insertion and fall through to normal generation
                    continue
                }
                calls := r.generateParticularCall(s, relateCall)
                for _, c := range calls {
                    s.analyze(c)
                    p.Calls = append(p.Calls, c)
                }
                // 再插 target
                if targetCall.Attrs.Disabled || targetCall.Attrs.NoGenerate {
                    // skip this special pair insertion and fall through to normal generation
                    continue
                }
                calls = r.generateParticularCall(s, targetCall)
                for _, c := range calls {
                    s.analyze(c)
                    p.Calls = append(p.Calls, c)
                }
                continue
            }
        }
        // 其他情况，走原逻辑
        calls := r.generateCall(s, p, len(p.Calls))
        for _, c := range calls {
            s.analyze(c)
            p.Calls = append(p.Calls, c)
        }
    }
    for len(p.Calls) > ncalls {
        p.RemoveCall(ncalls - 1)
    }
    p.sanitizeFix()
    p.debugValidate()
    return p
}

func GenerateSeedFromSyscallPair(target *Target, choiceTable *ChoiceTable, targetCall *Syscall, relateCall *Syscall, rnd *rand.Rand) (*Prog, error){
    p := &Prog{Target: target}
    r := newRand(target, rnd)
    s := newState(target, choiceTable, nil)

    // 把relate_syscall包含进种子
    var calls []*Call
    if relateCall.Attrs.Disabled || relateCall.Attrs.NoGenerate {
        // Fallback to a normal generated call sequence if the requested relateCall can't be generated.
        calls = r.generateCall(s, p, len(p.Calls))
    } else {
        calls = r.generateParticularCall(s, relateCall)
    }
    for _, c := range calls {
        s.analyze(c)
        p.Calls = append(p.Calls, c)
    }

    // 把target_syscall包含进种子
    if targetCall.Attrs.Disabled || targetCall.Attrs.NoGenerate {
        calls = r.generateCall(s, p, len(p.Calls))
    } else {
        calls = r.generateParticularCall(s, targetCall)
    }
    for _, c := range calls {
        s.analyze(c)
        p.Calls = append(p.Calls, c)
    }

	for len(p.Calls) < 7 {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}

    // 检查语义及有效性
    p.sanitizeFix()
    p.debugValidate()

    return p, nil
}