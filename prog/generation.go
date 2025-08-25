// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
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