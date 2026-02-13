import re
import sys
from collections import defaultdict

# VMExit Reasons Mapping based on ia32.hpp
VMX_EXIT_REASONS = {
    0: "EXCEPTION_OR_NMI",
    1: "EXTERNAL_INTERRUPT",
    2: "TRIPLE_FAULT",
    3: "INIT_SIGNAL",
    4: "STARTUP_IPI",
    5: "IO_SMI",
    6: "SMI",
    7: "INTERRUPT_WINDOW",
    8: "NMI_WINDOW",
    9: "TASK_SWITCH",
    10: "EXECUTE_CPUID",
    11: "EXECUTE_GETSEC",
    12: "EXECUTE_HLT",
    13: "EXECUTE_INVD",
    14: "EXECUTE_INVLPG",
    15: "EXECUTE_RDPMC",
    16: "EXECUTE_RDTSC",
    17: "EXECUTE_RSM_IN_SMM",
    18: "EXECUTE_VMCALL",
    19: "EXECUTE_VMCLEAR",
    20: "EXECUTE_VMLAUNCH",
    21: "EXECUTE_VMPTRLD",
    22: "EXECUTE_VMPTRST",
    23: "EXECUTE_VMREAD",
    24: "EXECUTE_VMRESUME",
    25: "EXECUTE_VMWRITE",
    26: "EXECUTE_VMXOFF",
    27: "EXECUTE_VMXON",
    28: "MOV_CR",
    29: "MOV_DR",
    30: "EXECUTE_IO_INSTRUCTION",
    31: "EXECUTE_RDMSR",
    32: "EXECUTE_WRMSR",
    33: "ERROR_INVALID_GUEST_STATE",
    34: "ERROR_MSR_LOAD",
    36: "EXECUTE_MWAIT",
    37: "MONITOR_TRAP_FLAG",
    39: "EXECUTE_MONITOR",
    40: "EXECUTE_PAUSE",
    41: "ERROR_MACHINE_CHECK",
    43: "TPR_BELOW_THRESHOLD",
    44: "APIC_ACCESS",
    45: "VIRTUALIZED_EOI",
    46: "GDTR_IDTR_ACCESS",
    47: "LDTR_TR_ACCESS",
    48: "EPT_VIOLATION",
    49: "EPT_MISCONFIGURATION",
    50: "EXECUTE_INVEPT",
    51: "EXECUTE_RDTSCP",
    52: "VMX_PREEMPTION_TIMER_EXPIRED",
    53: "EXECUTE_INVVPID",
    54: "EXECUTE_WBINVD",
    55: "EXECUTE_XSETBV",
    56: "APIC_WRITE",
    57: "EXECUTE_RDRAND",
    58: "EXECUTE_INVPCID",
    59: "EXECUTE_VMFUNC",
    60: "EXECUTE_ENCLS",
    61: "EXECUTE_RDSEED",
    62: "PAGE_MODIFICATION_LOG_FULL",
    63: "EXECUTE_XSAVES",
    64: "EXECUTE_XRSTORS",
    65: "EXECUTE_PCONFIG",
    66: "SPP_RELATED_EVENT",
    67: "EXECUTE_UMWAIT",
    68: "EXECUTE_TPAUSE",
    69: "EXECUTE_LOADIWKEY",
    70: "EXECUTE_ENCLV",
    72: "EXECUTE_ENQCMD",
    73: "EXECUTE_ENQCMDS",
    74: "BUS_LOCK_ASSERTION",
    75: "INSTRUCTION_TIMEOUT",
    76: "EXECUTE_SEAMCALL",
    77: "EXECUTE_TDCALL",
    78: "EXECUTE_RDMSRLIST",
    79: "EXECUTE_WRMSRLIST"
}

def analyze_logs(log_text):
    # Stats storage
    total_kernel = 0
    total_user = 0
    reason_counts = defaultdict(int)
    window_count = 0

    # Regex patterns
    window_pattern = re.compile(r"\[VMExit-Stats\] Window=(\d+) Kernel=(\d+) User=(\d+)")
    reason_pattern = re.compile(r"\[VMExit-Stats\] Reason=(\d+) Count=(\d+)")

    lines = log_text.strip().split('\n')
    
    for line in lines:
        window_match = window_pattern.search(line)
        if window_match:
            window_count += 1
            total_kernel += int(window_match.group(2))
            total_user += int(window_match.group(3))
            continue
        
        reason_match = reason_pattern.search(line)
        if reason_match:
            r_id = int(reason_match.group(1))
            count = int(reason_match.group(2))
            reason_counts[r_id] += count

    # Output Results
    print("="*60)
    print(f"VMExit Analysis Report (Total Windows: {window_count})")
    print("="*60)
    print(f"Mode Distribution:")
    print(f"  Kernel (CPL 0): {total_kernel:,}")
    print(f"  User (CPL >0):  {total_user:,}")
    print("-" * 60)
    print(f"{'Reason ID':<10} | {'Count':<10} | {'Percentage':<12} | {'Name'}")
    print("-" * 60)
    
    total_exits = sum(reason_counts.values())
    if total_exits == 0:
        print("No Reason data found.")
        return

    # Sort by count descending
    sorted_reasons = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)
    
    for r_id, count in sorted_reasons:
        name = VMX_EXIT_REASONS.get(r_id, "UNKNOWN_REASON")
        percentage = (count / total_exits) * 100
        print(f"{r_id:<10} | {count:<10,} | {percentage:>10.2f}% | {name}")
    
    print("-" * 60)
    print(f"Total Logged Exits: {total_exits:,}")
    print("="*60)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Read from file if path provided
        try:
            with open(sys.argv[1], 'r') as f:
                content = f.read()
                analyze_logs(content)
        except Exception as e:
            print(f"Error reading file: {e}")
    else:
        # Otherwise, check for piped input or instructions
        print("Usage: python analyze_vmexit.py <logfile.txt>")
        print("Or paste your log data here (Ctrl+D / Ctrl+Z to finish):")
        content = sys.stdin.read()
        if content:
            analyze_logs(content)
