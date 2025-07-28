package prog

import (
	"fmt"
	"bytes"
)

// 打印选择表中的信息(支持哪些系统调用以及系统调用间的优先级值)
func (ct *ChoiceTable) PrintChoiceTable_debug() string {
    var buf bytes.Buffer
    buf.WriteString("ChoiceTable Debug Info:\n")
    buf.WriteString("Enabled Syscalls:\n")
    for _, call := range ct.calls {
        buf.WriteString(fmt.Sprintf("  - %s (ID: %d)\n", call.Name, call.ID))
    }
    buf.WriteString("\nRuns Matrix:\n")
    for i, run := range ct.runs {
        if run == nil {
            continue
        }
        buf.WriteString(fmt.Sprintf("  Syscall ID %d: %v\n", i, run))
    }
    return buf.String()
}