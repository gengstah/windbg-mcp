#!/usr/bin/env python3
"""
windbg_mcp.py — MCP server exposing pybag Windows debugger capabilities

This is an MCP (Model Context Protocol) server that exposes every pybag debugger
function as an MCP tool. Run this on your Windows machine with pybag installed.

SETUP:
    pip install pybag mcp
    python windbg_mcp.py

The server communicates via stdio using the MCP protocol.
Any MCP-compatible client (Claude Desktop, Claude Code, etc.) can call these
tools directly — no curl / HTTP required.

AVAILABLE TOOLS (47 total):
    Session:    status, list_processes, create, attach, kernel_attach, load_dump,
                connect, detach, terminate
    Execution:  go, step_into, step_over, step_out, goto, trace
    Breakpoints:bp, hw_bp, list_bps, remove_bp, enable_bp, disable_bp
    Captures:   get_captures, clear_captures, capture_state
    Memory:     read_mem, write_mem, read_ptr, poi, read_str, dump_mem,
                mem_info, mem_list
    Registers:  get_regs, get_reg, set_reg, get_pc, get_sp
    Symbols:    resolve, find_symbols, addr_to_symbol, disasm, whereami
    Modules:    list_modules, module_info, get_exports, get_imports
    Threads:    list_threads, get_thread, set_thread, get_stack, get_teb, get_peb
    Process:    get_handles, get_bitness
    Utility:    raw
"""

import sys
import threading
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# MCP SDK import
# ---------------------------------------------------------------------------
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print(
        "ERROR: mcp package not found.\n"
        "  Install with: pip install mcp\n"
        "  Then re-run: python windbg_mcp.py",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# pybag import (Windows only)
# ---------------------------------------------------------------------------
try:
    from pybag import UserDbg, KernelDbg, CrashDbg, DbgEng
    PYBAG_AVAILABLE = True
except ImportError:
    PYBAG_AVAILABLE = False
    print(
        "WARNING: pybag not available.\n"
        "  1. Install: pip install pybag\n"
        "  2. Install Microsoft Debugging Tools for Windows (Windows SDK)\n"
        "  3. Run this script on Windows, not inside a Linux VM",
        file=sys.stderr,
    )

# ---------------------------------------------------------------------------
# MCP server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "windbg_mcp",
    instructions=(
        "Windows debugger MCP powered by pybag (WinDBG/DbgEng wrapper). "
        "Provides full control over user-mode, kernel, and crash-dump debugging sessions. "
        "Call 'status' first to check if a session is active. "
        "Call 'create', 'attach', 'kernel_attach', or 'load_dump' to start a session."
    ),
)

# ---------------------------------------------------------------------------
# Shared debugger state
# ---------------------------------------------------------------------------

class DebuggerState:
    """Persistent state for the active debugging session."""

    def __init__(self):
        self.dbg = None          # Active debugger instance
        self.dbg_type = None     # 'user' | 'kernel' | 'crash'
        self.captures: list[dict] = []
        self.bp_map: dict[int, dict] = {}
        self._bp_counter = 0
        self.lock = threading.Lock()

    def reset(self):
        if self.dbg:
            try:
                self.dbg.Release()
            except Exception:
                pass
        self.__init__()

    def next_bp_id(self) -> int:
        bp_id = self._bp_counter
        self._bp_counter += 1
        return bp_id

    def make_handler(self, bp_info: dict):
        """
        Build a breakpoint callback that auto-captures full debugger state
        (registers, stack, context memory) when the breakpoint fires.

        bp_info["action"] controls post-capture behaviour:
          "go"    → DEBUG_STATUS_GO    (continue running)
          "break" → DEBUG_STATUS_BREAK (stay broken in)
        """
        state = self

        def handler(bp, dbg):
            capture: dict[str, Any] = {
                "timestamp": datetime.now().isoformat(),
                "bp_id": bp_info.get("id"),
                "expr": bp_info.get("expr", "?"),
                "registers": {},
                "stack": [],
                "context_memory": {},
                "instruction": None,
                "symbol_at_rip": None,
            }

            # Registers
            try:
                reg_dict = {}
                for name in dbg.regs:
                    try:
                        reg_dict[name] = hex(dbg.regs[name])
                    except Exception:
                        pass
                capture["registers"] = reg_dict
            except Exception as e:
                capture["registers"] = {"error": str(e)}

            # PC / instruction / nearest symbol
            try:
                pc = dbg.pc()
                capture["rip"] = hex(pc)
                capture["symbol_at_rip"] = dbg.get_name_by_offset(pc)
                capture["instruction"] = dbg.instruction_at(pc)
            except Exception as e:
                capture["rip_error"] = str(e)

            # Call stack (top 10 frames)
            try:
                frames = dbg.backtrace_list()
                capture["stack"] = [
                    {
                        "frame": i,
                        "addr": hex(f.InstructionOffset) if hasattr(f, "InstructionOffset") else str(f),
                        "return_addr": hex(f.ReturnOffset) if hasattr(f, "ReturnOffset") else None,
                    }
                    for i, f in enumerate(frames[:10])
                ]
            except Exception as e:
                capture["stack_error"] = str(e)

            # Memory at RSP (64 bytes of stack context)
            try:
                sp = dbg.regs.get_sp()
                data = dbg.read(sp, 64)
                capture["context_memory"]["stack_at_rsp"] = {
                    "addr": hex(sp),
                    "hex": data.hex(),
                    "formatted": " ".join(f"{b:02x}" for b in data),
                    "ascii": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data),
                }
            except Exception as e:
                capture["context_memory"]["stack_error"] = str(e)

            # Memory at RIP (32 bytes of code context)
            try:
                pc = dbg.pc()
                data = dbg.read(pc, 32)
                capture["context_memory"]["code_at_rip"] = {
                    "addr": hex(pc),
                    "hex": data.hex(),
                    "formatted": " ".join(f"{b:02x}" for b in data),
                }
            except Exception as e:
                capture["context_memory"]["code_error"] = str(e)

            with state.lock:
                state.captures.append(capture)

            action = bp_info.get("action", "go")
            return DbgEng.DEBUG_STATUS_BREAK if action == "break" else DbgEng.DEBUG_STATUS_GO

        return handler


STATE = DebuggerState()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_session():
    if STATE.dbg is None:
        raise RuntimeError(
            "No active session. Call create, attach, kernel_attach, or load_dump first."
        )


def _parse_addr(addr: Any) -> int:
    if addr is None:
        raise ValueError("addr is required")
    if isinstance(addr, int):
        return addr
    addr = str(addr).strip()
    if addr.startswith(("0x", "0X")):
        return int(addr, 16)
    try:
        return int(addr, 16)
    except ValueError:
        return int(addr)


def _fmt_bytes(data: bytes) -> dict:
    return {
        "hex": data.hex(),
        "formatted": " ".join(f"{b:02x}" for b in data),
        "ascii": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data),
    }


# ===========================================================================
#  MCP TOOLS — Session management
# ===========================================================================

@mcp.tool()
def status() -> dict:
    """
    Return the current debugger session status.

    Returns: {connected, type, pid (user only), bitness}
    """
    if STATE.dbg is None:
        return {"connected": False, "type": None}
    try:
        info: dict[str, Any] = {"connected": True, "type": STATE.dbg_type}
        info["bitness"] = STATE.dbg.bitness()
        if STATE.dbg_type == "user":
            info["pid"] = STATE.dbg.pid
        return info
    except Exception as e:
        return {"connected": True, "type": STATE.dbg_type, "error": str(e)}


@mcp.tool()
def list_processes() -> list:
    """
    List all running processes on the system. Does not require an active session.

    Returns: [{pid, name, description}]
    """
    tmp = UserDbg()
    procs = tmp.proc_list()
    tmp.Release()
    return [{"pid": p[0], "name": p[1], "description": p[2]} for p in procs]


@mcp.tool()
def create(path: str, args: str = "", initial_break: bool = True) -> dict:
    """
    Launch a new process under the debugger.

    Args:
        path: Full path to the executable (e.g. C:/target/vuln.exe)
        args: Optional command-line arguments
        initial_break: Break at process entry point (default True)

    Returns: {status, pid, bitness}
    """
    if not path:
        raise ValueError("path is required")
    STATE.reset()
    dbg = UserDbg()
    cmd_line = f'"{path}" {args}' if args else f'"{path}"'
    dbg.create(cmd_line, initial_break=initial_break)
    STATE.dbg = dbg
    STATE.dbg_type = "user"
    return {"status": "created", "pid": dbg.pid, "bitness": dbg.bitness()}


@mcp.tool()
def attach(pid: int = None, name: str = None, initial_break: bool = True) -> dict:
    """
    Attach to a running process by PID or process name. Provide pid OR name, not both.

    Args:
        pid: Process ID to attach to
        name: Process name to attach to (e.g. "target.exe")
        initial_break: Break immediately after attaching (default True)

    Returns: {status, pid, bitness}
    """
    STATE.reset()
    dbg = UserDbg()
    if name and not pid:
        pids = UserDbg.pids_by_name(name)
        if not pids:
            raise ValueError(f"Process '{name}' not found")
        pid = pids[0]
    if not pid:
        raise ValueError("Provide pid (int) or name (str)")
    dbg.attach(int(pid), initial_break=initial_break)
    STATE.dbg = dbg
    STATE.dbg_type = "user"
    return {"status": "attached", "pid": int(pid), "bitness": dbg.bitness()}


@mcp.tool()
def kernel_attach(connect_string: str, initial_break: bool = False) -> dict:
    """
    Attach to a remote kernel debugger.

    Args:
        connect_string: KD connection string (e.g. "net:port=55000,key=1.2.3.4")
        initial_break: Break immediately on connect (default False)

    Returns: {status, type, connect_string}
    """
    if not connect_string:
        raise ValueError("connect_string is required, e.g. 'net:port=55000,key=1.2.3.4'")
    STATE.reset()
    k = KernelDbg()
    k.attach(connect_string, initial_break=initial_break)
    STATE.dbg = k
    STATE.dbg_type = "kernel"
    return {"status": "attached", "type": "kernel", "connect_string": connect_string}


@mcp.tool()
def load_dump(path: str) -> dict:
    """
    Open a crash dump (.dmp) file for post-mortem analysis.

    Args:
        path: Path to the .dmp file (e.g. C:/crashes/crash.dmp)

    Returns: {status, bitness, rip, symbol_at_rip}
    """
    if not path:
        raise ValueError("path is required")
    STATE.reset()
    c = CrashDbg()
    c.load_dump(path)
    STATE.dbg = c
    STATE.dbg_type = "crash"
    pc = c.pc()
    return {
        "status": "loaded",
        "bitness": c.bitness(),
        "rip": hex(pc),
        "symbol_at_rip": c.get_name_by_offset(pc),
    }


@mcp.tool()
def connect(options: str) -> dict:
    """
    Connect to a process server for remote user-mode debugging.

    Args:
        options: Connection string (e.g. "tcp:server=192.168.1.10,port=5555")

    Returns: {status, options}
    """
    if not options:
        raise ValueError("options is required, e.g. 'tcp:server=192.168.1.10,port=5555'")
    if STATE.dbg is None:
        STATE.reset()
        STATE.dbg = UserDbg()
        STATE.dbg_type = "user"
    STATE.dbg.connect(options)
    return {"status": "connected", "options": options}


@mcp.tool()
def detach() -> dict:
    """
    Detach from the current process (process keeps running).

    Returns: {status}
    """
    if STATE.dbg is None:
        return {"status": "no_session"}
    STATE.dbg.detach()
    STATE.dbg = None
    return {"status": "detached"}


@mcp.tool()
def terminate() -> dict:
    """
    Terminate the debugged process and end the session.

    Returns: {status}
    """
    if STATE.dbg is None:
        return {"status": "no_session"}
    STATE.dbg.terminate()
    STATE.dbg = None
    return {"status": "terminated"}


# ===========================================================================
#  MCP TOOLS — Execution control
# ===========================================================================

@mcp.tool()
def go(timeout: int = 30000) -> dict:
    """
    Continue execution until the next debug event (breakpoint, exception, etc.).

    Args:
        timeout: Maximum wait time in milliseconds (default 30000 = 30s)

    Returns: {status, rip, symbol, new_captures, captures}
    """
    _require_session()
    prev_len = len(STATE.captures)
    STATE.dbg.go(timeout=timeout)
    new_captures = STATE.captures[prev_len:]
    pc = STATE.dbg.pc()
    return {
        "status": "stopped",
        "rip": hex(pc),
        "symbol": STATE.dbg.get_name_by_offset(pc),
        "new_captures": len(new_captures),
        "captures": new_captures,
    }


@mcp.tool()
def step_into(count: int = 1) -> dict:
    """
    Step into the next instruction(s) — follows calls into functions.

    Args:
        count: Number of instructions to step (default 1)

    Returns: {rip, instruction, symbol}
    """
    _require_session()
    STATE.dbg.stepi(count=count)
    pc = STATE.dbg.pc()
    return {
        "rip": hex(pc),
        "instruction": STATE.dbg.instruction_at(pc),
        "symbol": STATE.dbg.get_name_by_offset(pc),
    }


@mcp.tool()
def step_over(count: int = 1) -> dict:
    """
    Step over the next instruction(s) — treats calls as a single step.

    Args:
        count: Number of instructions to step (default 1)

    Returns: {rip, instruction, symbol}
    """
    _require_session()
    STATE.dbg.stepo(count=count)
    pc = STATE.dbg.pc()
    return {
        "rip": hex(pc),
        "instruction": STATE.dbg.instruction_at(pc),
        "symbol": STATE.dbg.get_name_by_offset(pc),
    }


@mcp.tool()
def step_out() -> dict:
    """
    Run until the current function returns (step out / finish).

    Returns: {rip, instruction, symbol}
    """
    _require_session()
    STATE.dbg.stepout()
    pc = STATE.dbg.pc()
    return {
        "rip": hex(pc),
        "instruction": STATE.dbg.instruction_at(pc),
        "symbol": STATE.dbg.get_name_by_offset(pc),
    }


@mcp.tool()
def goto(expr: str) -> dict:
    """
    Continue execution until the given symbol or address is reached.

    Args:
        expr: Symbol name or hex address (e.g. "Kernel32!ExitProcess" or "0x7fff1234")

    Returns: {rip, symbol}
    """
    _require_session()
    if not expr:
        raise ValueError("expr is required")
    STATE.dbg.goto(expr)
    pc = STATE.dbg.pc()
    return {"rip": hex(pc), "symbol": STATE.dbg.get_name_by_offset(pc)}


@mcp.tool()
def trace(count: int = 10) -> dict:
    """
    Single-step N instructions and record each one (instruction trace).

    Args:
        count: Number of instructions to trace (default 10)

    Returns: {instructions: [{rip, instruction, symbol}], count}
    """
    _require_session()
    instructions = []
    for _ in range(count):
        pc = STATE.dbg.pc()
        instructions.append({
            "rip": hex(pc),
            "instruction": STATE.dbg.instruction_at(pc),
            "symbol": STATE.dbg.get_name_by_offset(pc),
        })
        STATE.dbg.stepi(count=1)
    return {"instructions": instructions, "count": len(instructions)}


# ===========================================================================
#  MCP TOOLS — Breakpoints
# ===========================================================================

@mcp.tool()
def bp(
    expr: str,
    capture: bool = True,
    action: str = "go",
    oneshot: bool = False,
    passcount: int = None,
) -> dict:
    """
    Set a software (code) breakpoint at a symbol or address.

    Args:
        expr: Symbol name or hex address (e.g. "ntdll!NtCreateFile" or "0x7ff812340000")
        capture: Auto-capture full state (registers/stack/memory) when hit (default True)
        action: After capture, "go" to continue or "break" to halt (default "go")
        oneshot: Remove the breakpoint after it fires once (default False)
        passcount: Fire only after N passes through the location

    Returns: {id, expr, addr, capture}
    """
    _require_session()
    if not expr:
        raise ValueError("expr is required (symbol name or hex address)")
    bp_id = STATE.next_bp_id()
    bp_info = {
        "id": bp_id,
        "expr": expr,
        "type": "software",
        "capture": capture,
        "action": action,
        "oneshot": oneshot,
    }
    handler = STATE.make_handler(bp_info) if capture else None
    STATE.dbg.bp(expr, handler=handler, oneshot=oneshot, passcount=passcount)
    STATE.bp_map[bp_id] = bp_info
    addr = None
    try:
        addr = hex(STATE.dbg.symbol(expr))
    except Exception:
        try:
            addr = hex(int(expr, 16))
        except Exception:
            pass
    return {"id": bp_id, "expr": expr, "addr": addr, "capture": capture}


@mcp.tool()
def hw_bp(
    addr: str,
    size: int = 4,
    access: str = "w",
    capture: bool = True,
    action: str = "go",
    oneshot: bool = False,
) -> dict:
    """
    Set a hardware / data breakpoint (watch) at an address.

    Args:
        addr: Hex address to watch (e.g. "0x1001F000")
        size: Watch width in bytes — 1, 2, 4, or 8 (default 4)
        access: "e" = execute, "w" = write, "r" = read/write (default "w")
        capture: Auto-capture state when triggered (default True)
        action: "go" to continue or "break" to halt after capture (default "go")
        oneshot: Remove after first hit (default False)

    Returns: {id, addr, size, access}
    """
    _require_session()
    if addr is None:
        raise ValueError("addr is required")
    parsed_addr = _parse_addr(addr)
    bp_id = STATE.next_bp_id()
    bp_info = {
        "id": bp_id,
        "expr": hex(parsed_addr),
        "type": "hardware",
        "size": size,
        "access": access,
        "capture": capture,
        "action": action,
        "oneshot": oneshot,
    }
    handler = STATE.make_handler(bp_info) if capture else None
    STATE.dbg.ba(hex(parsed_addr), handler=handler, oneshot=oneshot, size=size, access=access)
    STATE.bp_map[bp_id] = bp_info
    return {"id": bp_id, "addr": hex(parsed_addr), "size": size, "access": access}


@mcp.tool()
def list_bps() -> list:
    """
    List all currently set breakpoints.

    Returns: [{id, expr, type, capture, action, ...}]
    """
    _require_session()
    return list(STATE.bp_map.values())


@mcp.tool()
def remove_bp(id: int) -> dict:
    """
    Remove a breakpoint by its ID (from list_bps or bp/hw_bp return value).

    Args:
        id: Breakpoint ID to remove

    Returns: {status, id}
    """
    _require_session()
    if id is None:
        raise ValueError("id is required")
    STATE.dbg.bc(id)
    STATE.bp_map.pop(id, None)
    return {"status": "removed", "id": id}


@mcp.tool()
def enable_bp(id: int) -> dict:
    """
    Re-enable a disabled breakpoint.

    Args:
        id: Breakpoint ID to enable

    Returns: {status, id}
    """
    _require_session()
    if id is None:
        raise ValueError("id is required")
    STATE.dbg.be(id)
    return {"status": "enabled", "id": id}


@mcp.tool()
def disable_bp(id: int) -> dict:
    """
    Disable a breakpoint without removing it.

    Args:
        id: Breakpoint ID to disable

    Returns: {status, id}
    """
    _require_session()
    if id is None:
        raise ValueError("id is required")
    STATE.dbg.bd(id)
    return {"status": "disabled", "id": id}


# ===========================================================================
#  MCP TOOLS — State captures
# ===========================================================================

@mcp.tool()
def get_captures() -> dict:
    """
    Return all breakpoint state captures collected so far.

    Captures are automatically saved when a breakpoint with capture=True fires.
    Each capture includes: bp_id, expr, registers, rip, symbol_at_rip, instruction,
    stack, context_memory (stack_at_rsp + code_at_rip), timestamp.

    For exploit research: check captures[0].registers.rip for RIP control
    (e.g. "0x4141414141414141" means you control the instruction pointer).

    Returns: {count, captures: [...]}
    """
    with STATE.lock:
        captures = list(STATE.captures)
    return {"count": len(captures), "captures": captures}


@mcp.tool()
def clear_captures() -> dict:
    """
    Clear all collected breakpoint captures from the buffer.

    Returns: {status}
    """
    with STATE.lock:
        STATE.captures.clear()
    return {"status": "cleared"}


@mcp.tool()
def capture_state() -> dict:
    """
    Take an immediate full snapshot of the current debugger state.

    Captures: registers, rip + symbol + instruction, disasm (5 insns),
    stack_at_rsp (64 bytes), call_stack (top 10 frames), timestamp.

    Use this when already broken in. Use get_captures() to retrieve state
    that was auto-saved when breakpoints fired during go().

    Returns: {timestamp, registers, rip, symbol_at_rip, instruction,
              disasm_5, stack_at_rsp, call_stack}
    """
    _require_session()
    snap: dict[str, Any] = {"timestamp": datetime.now().isoformat()}

    try:
        reg_dict = {}
        for name in STATE.dbg.regs:
            try:
                reg_dict[name] = hex(STATE.dbg.regs[name])
            except Exception:
                pass
        snap["registers"] = reg_dict
    except Exception as e:
        snap["registers"] = {"error": str(e)}

    try:
        pc = STATE.dbg.pc()
        snap["rip"] = hex(pc)
        snap["symbol_at_rip"] = STATE.dbg.get_name_by_offset(pc)
        snap["instruction"] = STATE.dbg.instruction_at(pc)
        snap["disasm_5"] = str(STATE.dbg.disasm(pc, count=5))
    except Exception as e:
        snap["rip_error"] = str(e)

    try:
        sp = STATE.dbg.regs.get_sp()
        data = STATE.dbg.read(sp, 64)
        snap["stack_at_rsp"] = {"addr": hex(sp), **_fmt_bytes(data)}
    except Exception as e:
        snap["stack_error"] = str(e)

    try:
        frames = STATE.dbg.backtrace_list()
        snap["call_stack"] = [
            {
                "frame": i,
                "addr": hex(f.InstructionOffset) if hasattr(f, "InstructionOffset") else str(f),
                "return_addr": hex(f.ReturnOffset) if hasattr(f, "ReturnOffset") else None,
            }
            for i, f in enumerate(frames[:10])
        ]
    except Exception as e:
        snap["call_stack_error"] = str(e)

    return snap


# ===========================================================================
#  MCP TOOLS — Memory
# ===========================================================================

@mcp.tool()
def read_mem(addr: str, size: int = 16) -> dict:
    """
    Read raw bytes from a memory address.

    Args:
        addr: Hex address to read from (e.g. "0x7fff12340000")
        size: Number of bytes to read (default 16)

    Returns: {addr, size, hex, formatted, ascii}
    """
    _require_session()
    parsed = _parse_addr(addr)
    data = STATE.dbg.read(parsed, size)
    return {"addr": hex(parsed), "size": size, **_fmt_bytes(data)}


@mcp.tool()
def write_mem(addr: str, data: str) -> dict:
    """
    Write bytes to a memory address.

    Args:
        addr: Hex address to write to (e.g. "0x7fff12340000")
        data: Bytes as a hex string (e.g. "90909090" or "\\x90\\x90\\x90\\x90")

    Returns: {status, addr, bytes_written}
    """
    _require_session()
    parsed = _parse_addr(addr)
    if not data:
        raise ValueError("data is required as a hex string, e.g. '90909090'")
    raw = bytes.fromhex(data.replace(" ", "").replace("\\x", ""))
    STATE.dbg.write(parsed, raw)
    return {"status": "written", "addr": hex(parsed), "bytes_written": len(raw)}


@mcp.tool()
def read_ptr(addr: str, count: int = 1) -> dict:
    """
    Read one or more pointer-sized values from an address.

    Args:
        addr: Starting hex address
        count: Number of pointers to read (default 1)

    Returns: {addr, values: [hex_string, ...]}
    """
    _require_session()
    parsed = _parse_addr(addr)
    ptrs = STATE.dbg.readptr(parsed, count=count)
    return {"addr": hex(parsed), "values": [hex(p) for p in ptrs]}


@mcp.tool()
def poi(addr: str) -> dict:
    """
    Read the pointer value at an address (pointer-of-interest).

    Args:
        addr: Hex address to dereference

    Returns: {addr, value}
    """
    _require_session()
    parsed = _parse_addr(addr)
    value = STATE.dbg.poi(parsed)
    return {"addr": hex(parsed), "value": hex(value)}


@mcp.tool()
def read_str(addr: str, wide: bool = False) -> dict:
    """
    Read a null-terminated string from a memory address.

    Args:
        addr: Hex address of the string
        wide: True for Unicode (UTF-16LE / WCHAR), False for ASCII/ANSI (default False)

    Returns: {addr, value, wide}
    """
    _require_session()
    parsed = _parse_addr(addr)
    result = STATE.dbg.readstr(parsed, wchar=wide)
    return {"addr": hex(parsed), "value": result, "wide": wide}


@mcp.tool()
def dump_mem(addr: str, count: int = 8) -> dict:
    """
    Formatted dword/pointer dump, similar to the 'dd'/'dp' commands in WinDbg.

    Args:
        addr: Starting hex address
        count: Number of dwords/pointers to display (default 8)

    Returns: {addr, output}
    """
    _require_session()
    parsed = _parse_addr(addr)
    output = STATE.dbg.dd(parsed, count=count)
    return {"addr": hex(parsed), "output": str(output)}


@mcp.tool()
def mem_info(addr: str) -> dict:
    """
    Query information about the virtual memory region containing an address.
    Returns region base, size, type, and protection flags.

    Args:
        addr: Any hex address within the region

    Returns: {addr, info}
    """
    _require_session()
    parsed = _parse_addr(addr)
    info = STATE.dbg.address(parsed)
    return {"addr": hex(parsed), "info": str(info)}


@mcp.tool()
def mem_list() -> list:
    """
    List all virtual memory regions in the target process address space.

    Returns: [region_description_strings]
    """
    _require_session()
    return [str(r) for r in STATE.dbg.memory_list()]


# ===========================================================================
#  MCP TOOLS — Registers
# ===========================================================================

@mcp.tool()
def get_regs() -> dict:
    """
    Return all register values as a dict of {register_name: hex_string}.

    Returns: {rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip, r8-r15, eflags, ...}
    """
    _require_session()
    result = {}
    for name in STATE.dbg.regs:
        try:
            result[name] = hex(STATE.dbg.regs[name])
        except Exception:
            pass
    return result


@mcp.tool()
def get_reg(name: str) -> dict:
    """
    Get the value of a single register.

    Args:
        name: Register name (e.g. "rax", "rip", "rbp", "eflags")

    Returns: {name, value}
    """
    _require_session()
    if not name:
        raise ValueError("name is required, e.g. 'rax'")
    return {"name": name, "value": hex(STATE.dbg.regs[name])}


@mcp.tool()
def set_reg(name: str, value: str) -> dict:
    """
    Set a register to a new value.

    Args:
        name: Register name (e.g. "rax")
        value: New value as hex string (e.g. "0x1234") or decimal integer string

    Returns: {status, name, value}
    """
    _require_session()
    if not name or value is None:
        raise ValueError("name and value are required")
    int_value = int(value, 16) if str(value).startswith("0x") else int(value)
    STATE.dbg.regs[name] = int_value
    return {"status": "set", "name": name, "value": hex(int_value)}


@mcp.tool()
def get_pc() -> dict:
    """
    Get the current instruction pointer (RIP/EIP) with symbol resolution
    and the instruction text at that address.

    Returns: {value, symbol, instruction}
    """
    _require_session()
    pc = STATE.dbg.pc()
    return {
        "value": hex(pc),
        "symbol": STATE.dbg.get_name_by_offset(pc),
        "instruction": STATE.dbg.instruction_at(pc),
    }


@mcp.tool()
def get_sp() -> dict:
    """
    Get the current stack pointer (RSP/ESP).

    Returns: {value}
    """
    _require_session()
    return {"value": hex(STATE.dbg.regs.get_sp())}


# ===========================================================================
#  MCP TOOLS — Symbols & disassembly
# ===========================================================================

@mcp.tool()
def resolve(name: str) -> dict:
    """
    Resolve a symbol name to its virtual address.

    Args:
        name: Symbol in Module!Function format (e.g. "Kernel32!WriteFile",
              "ntdll!NtCreateFile")

    Returns: {name, addr} or {name, addr: null, error}
    """
    _require_session()
    if not name:
        raise ValueError("name is required, e.g. 'Kernel32!WriteFile'")
    try:
        addr = STATE.dbg.symbol(name)
        return {"name": name, "addr": hex(addr)}
    except Exception as e:
        return {"name": name, "addr": None, "error": str(e)}


@mcp.tool()
def find_symbols(pattern: str) -> list:
    """
    Find all symbols matching a wildcard pattern.

    Args:
        pattern: Wildcard pattern (e.g. "ntdll!*Alloc*", "kernel32!*File*")

    Returns: [symbol_string, ...]
    """
    _require_session()
    if not pattern:
        raise ValueError("pattern is required, e.g. 'ntdll!*Alloc*'")
    results = STATE.dbg.find_symbol(pattern)
    return [str(r) for r in results]


@mcp.tool()
def addr_to_symbol(addr: str) -> dict:
    """
    Resolve a virtual address to the nearest symbol name.

    Args:
        addr: Hex address to look up

    Returns: {addr, symbol}
    """
    _require_session()
    parsed = _parse_addr(addr)
    name = STATE.dbg.get_name_by_offset(parsed)
    return {"addr": hex(parsed), "symbol": name}


@mcp.tool()
def disasm(addr: str = None, count: int = 10) -> dict:
    """
    Disassemble instructions starting at an address.

    Args:
        addr: Hex address to disassemble from (default: current RIP)
        count: Number of instructions to disassemble (default 10)

    Returns: {addr, output}
    """
    _require_session()
    parsed = _parse_addr(addr) if addr else STATE.dbg.pc()
    output = STATE.dbg.disasm(parsed, count=count)
    return {"addr": hex(parsed), "output": str(output)}


@mcp.tool()
def whereami(addr: str = None) -> dict:
    """
    Return a heuristic description of the current or given address
    (module, function, offset).

    Args:
        addr: Hex address to describe (default: current RIP)

    Returns: {description}
    """
    _require_session()
    parsed = _parse_addr(addr) if addr else None
    result = STATE.dbg.whereami(parsed)
    return {"description": str(result)}


# ===========================================================================
#  MCP TOOLS — Modules
# ===========================================================================

@mcp.tool()
def list_modules() -> list:
    """
    List all modules loaded in the target process.

    Returns: [{name, base, size}]
    """
    _require_session()
    modules = []
    for name, mp in STATE.dbg.module_list():
        entry: dict[str, Any] = {"name": name}
        try:
            entry["base"] = hex(mp.Base)
            entry["size"] = hex(mp.Size)
        except Exception:
            entry["info"] = str(mp)
        modules.append(entry)
    return modules


@mcp.tool()
def module_info(name: str) -> dict:
    """
    Get entry point and section list for a loaded module.

    Args:
        name: Module name (e.g. "kernel32.dll", "ntdll.dll")

    Returns: {name, entry_point, sections}
    """
    _require_session()
    if not name:
        raise ValueError("name is required, e.g. 'kernel32.dll'")
    mod = STATE.dbg.modules[name]
    result: dict[str, Any] = {"name": name}
    try:
        result["entry_point"] = hex(mod.entry_point())
    except Exception as e:
        result["entry_point_error"] = str(e)
    try:
        result["sections"] = [str(s) for s in mod.section_list()]
    except Exception as e:
        result["sections_error"] = str(e)
    return result


@mcp.tool()
def get_exports(name: str) -> list:
    """
    Get the export list of a loaded module.

    Args:
        name: Module name (e.g. "kernel32.dll")

    Returns: [export_string, ...]
    """
    _require_session()
    if not name:
        raise ValueError("name is required")
    return [str(e) for e in STATE.dbg.exports(name)]


@mcp.tool()
def get_imports(name: str) -> list:
    """
    Get the import list of a loaded module.

    Args:
        name: Module name (e.g. "target.exe")

    Returns: [import_string, ...]
    """
    _require_session()
    if not name:
        raise ValueError("name is required")
    return [str(i) for i in STATE.dbg.imports(name)]


# ===========================================================================
#  MCP TOOLS — Threads & stack
# ===========================================================================

@mcp.tool()
def list_threads() -> list:
    """
    List all threads in the target process.

    Returns: [thread_description_string, ...]
    """
    _require_session()
    return [str(t) for t in STATE.dbg.thread_list()]


@mcp.tool()
def get_thread() -> dict:
    """
    Get the currently active thread.

    Returns: {current_thread}
    """
    _require_session()
    return {"current_thread": STATE.dbg.get_thread()}


@mcp.tool()
def set_thread(id: int) -> dict:
    """
    Switch the current thread context.

    Args:
        id: Thread ID to switch to (from list_threads)

    Returns: {status, thread}
    """
    _require_session()
    if id is None:
        raise ValueError("id is required")
    STATE.dbg.set_thread(int(id))
    return {"status": "switched", "thread": int(id)}


@mcp.tool()
def get_stack(frames: int = 20) -> dict:
    """
    Return the current call stack as structured data.

    Args:
        frames: Maximum number of frames to return (default 20)

    Returns: {frames: [{frame, addr, return_addr, frame_ptr}], count}
    """
    _require_session()
    result = []
    for i, frame in enumerate(STATE.dbg.backtrace_list()[:frames]):
        try:
            result.append({
                "frame": i,
                "addr": hex(frame.InstructionOffset) if hasattr(frame, "InstructionOffset") else str(frame),
                "return_addr": hex(frame.ReturnOffset) if hasattr(frame, "ReturnOffset") else None,
                "frame_ptr": hex(frame.FrameOffset) if hasattr(frame, "FrameOffset") else None,
            })
        except Exception:
            result.append({"frame": i, "info": str(frame)})
    return {"frames": result, "count": len(result)}


@mcp.tool()
def get_teb() -> dict:
    """
    Get the Thread Environment Block (TEB) address for the current thread.

    Returns: {addr}
    """
    _require_session()
    return {"addr": hex(STATE.dbg.teb_addr())}


@mcp.tool()
def get_peb() -> dict:
    """
    Get the Process Environment Block (PEB) address.

    Returns: {addr}
    """
    _require_session()
    return {"addr": hex(STATE.dbg.peb_addr())}


# ===========================================================================
#  MCP TOOLS — Process & utility
# ===========================================================================

@mcp.tool()
def get_handles() -> list:
    """
    Get all open handles in the target process.

    Returns: [handle_description_string, ...]
    """
    _require_session()
    return [str(h) for h in STATE.dbg.handle_list()]


@mcp.tool()
def get_bitness() -> dict:
    """
    Get the bitness (32 or 64) of the current debugging session.

    Returns: {bits}
    """
    _require_session()
    return {"bits": STATE.dbg.bitness()}


@mcp.tool()
def raw(cmd: str) -> dict:
    """
    Execute any raw WinDbg command string and return its output.

    Use this as an escape hatch for anything not covered by the other tools:
    e.g. "!heap -stat", "dt _PEB @$peb", "!locks", "lm", "!address @rsp".

    Tip — set symbol path:
        .sympath srv*C:\\symbols*https://msdl.microsoft.com/download/symbols

    Args:
        cmd: WinDbg command string to execute

    Returns: {output}
    """
    _require_session()
    if not cmd:
        raise ValueError("cmd is required")
    output = STATE.dbg.cmd(cmd)
    return {"output": str(output)}


# ===========================================================================
#  Entry point
# ===========================================================================

if __name__ == "__main__":
    if not PYBAG_AVAILABLE:
        print(
            "ERROR: pybag is not installed. Run:\n"
            "  pip install pybag\n"
            "Then run this script again on your Windows machine.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("WinDbg MCP server starting (stdio transport)...", file=sys.stderr)
    print("Connect your MCP client to this process via stdio.", file=sys.stderr)
    mcp.run()
