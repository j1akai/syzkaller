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

    // 先生成一半以上的调用
    firstHalf := ncalls/2 + 1
    for len(p.Calls) < firstHalf {
        calls := r.generateCall(s, p, len(p.Calls))
        for _, c := range calls {
            s.analyze(c)
            p.Calls = append(p.Calls, c)
        }
    }

    // 40%概率使用隐式依赖信息
    if r.rand(100) < 40 && ct != nil && ct.SyscallPair != nil {
        searchStart := len(p.Calls) - 1 // 从末尾开始搜索
        
        // 尝试3次根据隐式依赖添加系统调用
        for attempt := 0; attempt < 3 && len(p.Calls) < ncalls && searchStart >= 0; attempt++ {
            // 从searchStart向前查找作为target的系统调用
            foundTarget := false
            for i := searchStart; i >= 0; i-- {
                currCall := p.Calls[i].Meta
                if pairs, exists := ct.SyscallPair[currCall]; exists && len(pairs) > 0 {
                    // 在其relate中随机选择一个
                    relate := pairs[r.rand(len(pairs))].Relate
                    if relate == nil {
                        continue
                    }

                    // 生成选中的relate调用
                    newCalls := r.generateParticularCall(s, relate) 
                    if len(newCalls) == 0 {
                        continue
                    }

                    // 随机选择插入位置(target之前)
                    insertPos := r.rand(i + 1)
                    
                    // 插入新调用
                    p.Calls = append(p.Calls[:insertPos], append(newCalls, p.Calls[insertPos:]...)...)
                    
                    // 分析新加入的调用
                    for _, c := range newCalls {
                        s.analyze(c)
                    }

                    // 更新下一轮搜索的起始位置
                    searchStart = i - 1
                    foundTarget = true
                    break
                }
            }
            
            // 如果没找到target就退出循环
            if !foundTarget {
                break
            }
        }
    }

    // 继续生成剩余的调用直到达到ncalls
    for len(p.Calls) < ncalls {
        calls := r.generateCall(s, p, len(p.Calls))
        for _, c := range calls {
            s.analyze(c)
            p.Calls = append(p.Calls, c)
        }
    }

    // 处理可能超出ncalls的情况
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