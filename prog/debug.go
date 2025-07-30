package prog

import (
	"fmt"
	"bytes"
	"os"
	stdlog "log"
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

// InitLogFile 初始化日志输出到指定文件
// logPath: 日志文件路径（如 "/home/debug/triageInput.log"）
// 返回可能的错误（如文件创建失败）
func InitLogFile_debug(logPath string) error {
    file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return fmt.Errorf("failed to open log file: %v", err)
    }
    // 设置标准库log的输出目标
    stdlog.SetOutput(file)
    return nil
}