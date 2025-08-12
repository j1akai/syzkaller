// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
    "fmt"
	"github.com/google/syzkaller/pkg/log"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}

// 输入:target_syscall和relate_syscall
// 输出:包含target_syscall和relate_syscall的一个种子
func GenerateSeedFromSyscallPair_debug(target *Target, choiceTable *ChoiceTable, targetCall *Syscall, relateCall *Syscall, rnd *rand.Rand) (*Prog, error) {
    if targetCall == nil || relateCall == nil {
        return nil, fmt.Errorf("Invalid target or relate syscall")
    }

    p := &Prog{Target: target}
    r := newRand(target, rnd)
    s := newState(target, choiceTable, nil)

    // 把relate_syscall包含进种子
	log.Logf(0, "Generating relate syscall: \n%s", relateCall.Name)
    calls := r.generateParticularCall(s, relateCall)
    for _, c := range calls {
        s.analyze(c)
        p.Calls = append(p.Calls, c)
    }

    // 把target_syscall包含进种子
	log.Logf(0, "Generating target syscall: \n%s", targetCall.Name)
    calls = r.generateParticularCall(s, targetCall)
    for _, c := range calls {
        s.analyze(c)
        p.Calls = append(p.Calls, c)
    }

    // 检查语义及有效性
	log.Logf(0, "SanitizeFix and debugValidate ...")
    p.sanitizeFix()
    p.debugValidate()

	// 打印依据的target、relate和addr
    var addr uint32 = 0
    // 查找addr（如果choiceTable有SyscallPair信息）
    if choiceTable != nil && targetCall != nil {
        if infos, ok := choiceTable.SyscallPair[targetCall]; ok {
            for _, info := range infos {
                if info.Relate == relateCall {
                    addr = info.Addr
                    break
                }
            }
        }
    }
    log.Logf(0, "Seed generated from <Target: %s, Relate: %s>, Addr: %d", targetCall.Name, relateCall.Name, addr)

	log.Logf(0, "Final seed program:\n%s", p.Serialize())

    return p, nil
}