// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
)

func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
    p := &Prog{
        Target: target,
    }
    r := newRand(target, rs)
    s := newState(target, ct, nil)
    for len(p.Calls) < ncalls {
        // 新增：在 1/3 ~ 2/3 区间内，优先插入pair(只有40%的机会进入这个特殊逻辑)
        if ct != nil && len(p.Calls) > ncalls/3 && len(p.Calls) <= ncalls*2/3 && r.Intn(10) < 6 {
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
                // 先插 relate
                calls := r.generateParticularCall(s, relateCall)
                for _, c := range calls {
                    s.analyze(c)
                    p.Calls = append(p.Calls, c)
                }
                // 再插 target
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
    calls := r.generateParticularCall(s, relateCall)
    for _, c := range calls {
        s.analyze(c)
        p.Calls = append(p.Calls, c)
    }

    // 把target_syscall包含进种子
    calls = r.generateParticularCall(s, targetCall)
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