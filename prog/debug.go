package prog

import (
	"fmt"
	"bytes"
)

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