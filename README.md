# WinDbg MCP

An MCP (Model Context Protocol) server that exposes every pybag Windows debugger
function as a native MCP tool. It gives any MCP-compatible client (Claude Desktop,
Claude Code, Cowork, OpenAI Codex CLI, Cursor, and custom agents) full control over
user-mode processes, kernel sessions, and crash dump analysis — all through typed
tool calls with structured JSON responses.

---

## Requirements

- **Windows only** — pybag requires Microsoft Debugging Tools for Windows
- Python 3.10+
- Microsoft Debugging Tools for Windows (part of the Windows SDK)

---

## Installation

### 1. Clone the repository

```bat
git clone https://github.com/your-username/windbg-mcp.git
cd windbg-mcp
```

### 2. Install Python dependencies

```bat
pip install pybag mcp
```

### 3. Install Microsoft Debugging Tools

Download the Windows SDK and select **Debugging Tools for Windows** during setup:
https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/

---

## Connecting to LLM IDEs and Clients

The server runs as a local stdio process. All clients below launch it the same way —
`python <path-to>/windbg_mcp.py` — but each has its own config format.

---

### Claude Desktop

Edit the Claude Desktop configuration file and add the `windbg-mcp` entry:

**Config file location:**
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "windbg-mcp": {
      "command": "python",
      "args": ["C:\\path\\to\\windbg-mcp\\windbg_mcp.py"]
    }
  }
}
```

Restart Claude Desktop. All 55 debugger tools will appear automatically.

---

### Claude Code (CLI)

Run the following command once to register the server. Claude Code stores the entry
in its own MCP config and makes the tools available in every subsequent session.

```bash
claude mcp add windbg-mcp python C:\path\to\windbg-mcp\windbg_mcp.py
```

To verify the server was registered:

```bash
claude mcp list
```

To remove it later:

```bash
claude mcp remove windbg-mcp
```

---

### Claude Cowork

There are two ways to add WinDbg MCP to Cowork: via JSON configuration (quick) or
by installing it as a `.mcpb` plugin bundle (portable, shareable).

#### Option A — JSON Configuration

1. Open the Claude desktop app and go to **Settings → MCP Servers**.
2. Click **Add Server** and paste the following:

```json
{
  "windbg-mcp": {
    "command": "python",
    "args": ["C:\\path\\to\\windbg-mcp\\windbg_mcp.py"]
  }
}
```

3. Save and restart Cowork. The tools will be available in your next session.

#### Option B — Install as a `.mcpb` Plugin Bundle

A `.mcpb` file is a zip archive of the plugin directory that Cowork can install
directly. This is the recommended approach when sharing the server with a team or
across machines.

**Step 1 — Build the `.mcpb` file**

From the root of the cloned repository, run:

```bat
powershell -Command "Compress-Archive -Path '.\*' -DestinationPath 'windbg-mcp.zip'; Rename-Item 'windbg-mcp.zip' 'windbg-mcp.mcpb'"
```

This creates `windbg-mcp.mcpb` in the current directory, bundling `windbg_mcp.py`,
`manifest.json`, and any other project files.

**Step 2 — Install in Cowork**

1. Open the Claude desktop app.
2. Go to **Settings → Plugins** (or **Extensions**).
3. Click **Install Plugin** and select `windbg-mcp.mcpb`.
4. Cowork reads `manifest.json` from the bundle, registers the MCP server, and
   makes all tools available immediately — no manual path configuration required.

The `manifest.json` bundled in this repo is already configured correctly:

```json
{
  "manifest_version": "0.2",
  "name": "windbg-mcp",
  "version": "1.0.0",
  "description": "WinDbg MCP — full Windows debugger control via MCP tools",
  "server": {
    "type": "python",
    "entry_point": "windbg_mcp.py",
    "mcp_config": {
      "command": "python",
      "args": ["${__dirname}/windbg_mcp.py"]
    }
  }
}
```

`${__dirname}` is resolved at install time to the directory where Cowork unpacked
the bundle, so you do not need to hard-code any paths.

---

### OpenAI Codex CLI

Add the server to your Codex CLI configuration file. The file is typically located at
`~/.codex/config.json` (Linux/macOS) or `%USERPROFILE%\.codex\config.json` (Windows).

```json
{
  "mcpServers": {
    "windbg-mcp": {
      "command": "python",
      "args": ["C:\\path\\to\\windbg-mcp\\windbg_mcp.py"]
    }
  }
}
```

Once saved, start a new Codex session. The WinDbg tools will be available for the
model to call.

---

### Cursor

1. Open **Cursor → Preferences → Cursor Settings**.
2. Navigate to the **MCP** tab.
3. Click **Add new global MCP server** and use this configuration:

```json
{
  "windbg-mcp": {
    "command": "python",
    "args": ["C:\\path\\to\\windbg-mcp\\windbg_mcp.py"]
  }
}
```

4. Save. Cursor will connect to the server on its next Composer session.

---

### Continue.dev

Add the following to your `~/.continue/config.json` (or the workspace-level
`.continue/config.json`):

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "python",
          "args": ["C:\\path\\to\\windbg-mcp\\windbg_mcp.py"]
        }
      }
    ]
  }
}
```

Reload the Continue extension. The 55 debugger tools will appear in the tool list.

---

### Custom Agents and the MCP SDK

If you are building your own agent or automation pipeline, connect to WinDbg MCP
over the standard MCP stdio transport. The server speaks JSON-RPC 2.0 over stdin/stdout.

#### Python (using the `mcp` SDK)

```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

server_params = StdioServerParameters(
    command="python",
    args=[r"C:\path\to\windbg-mcp\windbg_mcp.py"],
)

async def main():
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List all available tools
            tools = await session.list_tools()
            print([t.name for t in tools.tools])

            # Load a crash dump
            result = await session.call_tool(
                "load_dump",
                arguments={"path": r"C:\crashes\crash.dmp"},
            )
            print(result.content)

            # Read 64 bytes at RSP
            result = await session.call_tool(
                "read_mem",
                arguments={"addr": "0x00000000001FF000", "size": 64},
            )
            print(result.content)

asyncio.run(main())
```

#### TypeScript / Node.js (using the `@modelcontextprotocol/sdk` package)

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "python",
  args: ["C:\\path\\to\\windbg-mcp\\windbg_mcp.py"],
});

const client = new Client({ name: "my-agent", version: "1.0.0" }, {});
await client.connect(transport);

// Call a tool
const result = await client.callTool({
  name: "load_dump",
  arguments: { path: "C:\\crashes\\crash.dmp" },
});
console.log(result.content);

await client.close();
```

#### LangChain / LangGraph

```python
from langchain_mcp_adapters.tools import load_mcp_tools
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

server_params = StdioServerParameters(
    command="python",
    args=[r"C:\path\to\windbg-mcp\windbg_mcp.py"],
)

async def get_tools():
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await load_mcp_tools(session)
```

#### Direct JSON-RPC over stdio (language-agnostic)

The server communicates via newline-delimited JSON-RPC 2.0 messages. You can drive
it from any language by writing to the process's stdin and reading from stdout:

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"my-client","version":"1.0"}}}
← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{...},"serverInfo":{"name":"WinDbg MCP","version":"1.0.0"}}}

→ {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"load_dump","arguments":{"path":"C:\\crashes\\crash.dmp"}}}
← {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"status\": \"ok\", ...}"}]}}
```

---

## Available Tools (55 total)

### Session Management

| Tool | Parameters | Returns |
|------|-----------|---------|
| `status` | — | `{connected, type, pid, bitness}` |
| `list_processes` | — | `[{pid, name, description}]` |
| `create` | `path` (required), `args`, `initial_break` | `{status, pid, bitness}` |
| `attach` | `pid` **or** `name` (not both), `initial_break` | `{status, pid, bitness}` |
| `kernel_attach` | `connect_string` (required), `initial_break` | `{status, type, connect_string}` |
| `load_dump` | `path` (required) | `{status, bitness, rip, symbol_at_rip}` |
| `connect` | `options` (required) | `{status, options}` |
| `detach` | — | `{status}` |
| `terminate` | — | `{status}` |

**`create`** — Launches a new process under the debugger. Set `initial_break=True` (default) to break at the process entry point.

**`attach`** — Attaches to a running process. Provide either `pid` (integer) or `name` (process filename). Do not provide both.

**`kernel_attach`** — Connects to a remote kernel debugger. `connect_string` uses KD syntax, e.g. `"net:port=55000,key=1.2.3.4"`.

**`load_dump`** — Opens a `.dmp` file for post-mortem analysis. Returns the crash address and nearest symbol immediately.

**`connect`** — Connects to a process server for remote user-mode debugging. `options` uses DbgEng connection syntax, e.g. `"tcp:server=192.168.1.10,port=5555"`.

---

### Execution Control

| Tool | Parameters | Returns |
|------|-----------|---------|
| `go` | `timeout` (ms, default 30000) | `{status, rip, symbol, new_captures, captures}` |
| `step_into` | `count` (default 1) | `{rip, instruction, symbol}` |
| `step_over` | `count` (default 1) | `{rip, instruction, symbol}` |
| `step_out` | — | `{rip, instruction, symbol}` |
| `goto` | `expr` (required) | `{rip, symbol}` |
| `trace` | `count` (default 10) | `{instructions: [{rip, instruction, symbol}], count}` |

**`go`** — Resumes execution and blocks until the next debug event (breakpoint, exception, or timeout). Returns the new RIP and any captures collected while running.

**`step_into`** — Steps into the next instruction, following calls into called functions.

**`step_over`** — Steps over the next instruction, treating calls as a single step.

**`step_out`** — Runs until the current function returns.

**`goto`** — Runs until a specific symbol or hex address is reached, e.g. `"Kernel32!ExitProcess"` or `"0x7fff12340000"`.

**`trace`** — Performs N single-step iterations and records each instruction visited.

---

### Breakpoints

| Tool | Parameters | Returns |
|------|-----------|---------|
| `bp` | `expr` (required), `capture`, `action`, `oneshot`, `passcount` | `{id, expr, addr, capture}` |
| `hw_bp` | `addr` (required), `size`, `access`, `capture`, `action`, `oneshot` | `{id, addr, size, access}` |
| `list_bps` | — | `[{id, expr, type, capture, action, ...}]` |
| `remove_bp` | `id` (required) | `{status, id}` |
| `enable_bp` | `id` (required) | `{status, id}` |
| `disable_bp` | `id` (required) | `{status, id}` |

**`bp`** — Sets a software (code) breakpoint at a symbol or address.
- `expr`: symbol (`"ntdll!NtCreateFile"`) or hex address (`"0x7ff800001234"`)
- `capture`: when `true` (default), automatically saves full state — registers, stack, memory — to the capture buffer each time this breakpoint fires
- `action`: `"go"` (default) continues execution after capture; `"break"` halts
- `oneshot`: removes the breakpoint after it fires once
- `passcount`: fires only after N passes through the location

**`hw_bp`** — Sets a hardware / data breakpoint (watchpoint).
- `addr`: hex address to watch
- `size`: watch width in bytes — `1`, `2`, `4`, or `8` (default `4`)
- `access`: `"e"` execute, `"w"` write (default), `"r"` read/write
- `capture`, `action`, `oneshot`: same semantics as `bp`

**`list_bps`** — Returns all currently active breakpoints with their IDs, expressions, types, and settings.

**`remove_bp` / `enable_bp` / `disable_bp`** — Manage breakpoints by the `id` returned from `bp` or `hw_bp`.

---

### State Captures

Breakpoints with `capture: true` (the default) automatically save a full debugger
snapshot every time they fire. The snapshot includes all registers, the call stack,
64 bytes of stack memory at RSP, and 32 bytes of code at RIP. Snapshots accumulate
in a buffer and can be retrieved at any time with `get_captures`.

| Tool | Parameters | Returns |
|------|-----------|---------|
| `get_captures` | — | `{count, captures: [{bp_id, expr, timestamp, registers, rip, symbol_at_rip, instruction, stack, context_memory}]}` |
| `clear_captures` | — | `{status}` |
| `capture_state` | — | `{timestamp, registers, rip, symbol_at_rip, instruction, disasm_5, stack_at_rsp, call_stack}` |

**`get_captures`** — Returns all captures collected since the last `clear_captures`. Each capture contains:
- `registers` — all register values as `{name: "0x..."}` hex strings
- `rip` — instruction pointer at the moment of capture
- `symbol_at_rip` — nearest symbol to RIP
- `instruction` — disassembly of the instruction at RIP
- `stack` — top 10 call stack frames with addresses and return addresses
- `context_memory.stack_at_rsp` — 64 bytes at RSP as hex, formatted, and ASCII
- `context_memory.code_at_rip` — 32 bytes at RIP as hex and formatted

**`clear_captures`** — Clears the capture buffer. Useful before starting a new run.

**`capture_state`** — Takes an immediate on-demand snapshot of the current state. Use this when already broken in, rather than waiting for a breakpoint to fire.

---

### Memory

| Tool | Parameters | Returns |
|------|-----------|---------|
| `read_mem` | `addr` (required), `size` (default 16) | `{addr, size, hex, formatted, ascii}` |
| `write_mem` | `addr` (required), `data` (required, hex string) | `{status, addr, bytes_written}` |
| `read_ptr` | `addr` (required), `count` (default 1) | `{addr, values: ["0x..."]}` |
| `poi` | `addr` (required) | `{addr, value}` |
| `read_str` | `addr` (required), `wide` (default false) | `{addr, value, wide}` |
| `dump_mem` | `addr` (required), `count` (default 8) | `{addr, output}` |
| `mem_info` | `addr` (required) | `{addr, info}` |
| `mem_list` | — | `[region_description_strings]` |

**`read_mem`** — Reads `size` raw bytes from `addr`. Returns the data as `hex` (compact), `formatted` (space-separated bytes), and `ascii` (printable characters, `.` for non-printable).

**`write_mem`** — Writes bytes to memory. `data` is a hex string — spaces and `\x` prefixes are stripped automatically, e.g. `"90909090"`, `"\\x90\\x90\\x90\\x90"`, or `"90 90 90 90"`.

**`read_ptr`** — Reads `count` consecutive pointer-sized values (4 bytes on 32-bit, 8 bytes on 64-bit) starting at `addr`.

**`poi`** — Dereferences a single pointer at `addr` (pointer-of-interest).

**`read_str`** — Reads a null-terminated string. Set `wide=true` for UTF-16LE (Windows WCHAR).

**`dump_mem`** — Formatted dword/pointer dump, equivalent to `dd`/`dp` in WinDbg.

**`mem_info`** — Returns the memory region properties for the page containing `addr`: base address, size, type, state, and protection flags.

**`mem_list`** — Lists all virtual memory regions in the target process address space.

---

### Registers

| Tool | Parameters | Returns |
|------|-----------|---------|
| `get_regs` | — | `{rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip, r8–r15, eflags, ...}` |
| `get_reg` | `name` (required) | `{name, value}` |
| `set_reg` | `name` (required), `value` (required) | `{status, name, value}` |
| `get_pc` | — | `{value, symbol, instruction}` |
| `get_sp` | — | `{value}` |

**`get_regs`** — Returns every available register as `{name: "0x..."}`. The exact set depends on the target architecture (x86 vs x64).

**`get_reg`** — Returns a single register, e.g. `name="rax"`, `name="eflags"`.

**`set_reg`** — Overwrites a register. `value` accepts hex strings (`"0x1234"`) or decimal integer strings.

**`get_pc`** — Returns the instruction pointer with symbol resolution and the decoded instruction text at that address.

**`get_sp`** — Returns the current stack pointer value.

---

### Symbols & Disassembly

| Tool | Parameters | Returns |
|------|-----------|---------|
| `resolve` | `name` (required) | `{name, addr}` or `{name, addr: null, error}` |
| `find_symbols` | `pattern` (required) | `[symbol_strings]` |
| `addr_to_symbol` | `addr` (required) | `{addr, symbol}` |
| `disasm` | `addr` (default: current RIP), `count` (default 10) | `{addr, output}` |
| `whereami` | `addr` (optional, default: current RIP) | `{description}` |

**`resolve`** — Resolves a symbol name to its virtual address. Use `Module!Function` format, e.g. `"Kernel32!WriteFile"`, `"ntdll!NtCreateFile"`.

**`find_symbols`** — Wildcard symbol search, e.g. `"ntdll!*Alloc*"`, `"kernel32!*File*"`. Returns all matching symbol strings.

**`addr_to_symbol`** — Reverse-resolves a virtual address to the nearest symbol name.

**`disasm`** — Disassembles `count` instructions starting at `addr`. Defaults to the current RIP if no address is given.

**`whereami`** — Returns a human-readable description of the module, function, and offset at the given address.

---

### Modules

| Tool | Parameters | Returns |
|------|-----------|---------|
| `list_modules` | — | `[{name, base, size}]` |
| `module_info` | `name` (required) | `{name, entry_point, sections}` |
| `get_exports` | `name` (required) | `[export_strings]` |
| `get_imports` | `name` (required) | `[import_strings]` |

**`list_modules`** — Lists all modules loaded in the target, with their base address and size.

**`module_info`** — Returns the entry point and section list (name, virtual address, size) for a specific module, e.g. `"kernel32.dll"`, `"ntdll.dll"`.

**`get_exports`** — Returns the full export table of a module as a list of strings.

**`get_imports`** — Returns the full import table of a module as a list of strings.

---

### Threads & Stack

| Tool | Parameters | Returns |
|------|-----------|---------|
| `list_threads` | — | `[thread_description_strings]` |
| `get_thread` | — | `{current_thread}` |
| `set_thread` | `id` (required) | `{status, thread}` |
| `get_stack` | `frames` (default 20) | `{frames: [{frame, addr, return_addr, frame_ptr}], count}` |
| `get_teb` | — | `{addr}` |
| `get_peb` | — | `{addr}` |

**`list_threads`** — Lists all threads in the target process.

**`get_thread`** — Returns the currently active thread context.

**`set_thread`** — Switches the active thread context by thread ID (from `list_threads`).

**`get_stack`** — Returns the call stack as structured data. Each frame includes the instruction address, return address, and frame pointer.

**`get_teb`** — Returns the address of the Thread Environment Block for the current thread.

**`get_peb`** — Returns the address of the Process Environment Block.

---

### Process & Utility

| Tool | Parameters | Returns |
|------|-----------|---------|
| `get_handles` | — | `[handle_description_strings]` |
| `get_bitness` | — | `{bits}` |
| `raw` | `cmd` (required) | `{output}` |

**`get_handles`** — Lists all open handles in the target process.

**`get_bitness`** — Returns `32` or `64` depending on the target architecture.

**`raw`** — Executes any WinDbg command string and returns the output as text. Use this as an escape hatch for anything not covered by the other tools:
```
raw(cmd="!heap -stat")
raw(cmd="dt _PEB @$peb")
raw(cmd="!locks")
raw(cmd="lm")
raw(cmd="!address @rsp")
```

---

## Typical Workflows

### Exploit verification

```
1. create(path="C:/target/vuln.exe", args="exploit_input.bin")
2. bp(expr="vuln!processInput+0x2A", action="break")
3. go(timeout=15000)
4. get_captures()
```

In `get_captures`, inspect `captures[0].registers.rip`:
- `"0x4141414141414141"` — you control RIP with 'A' bytes
- Any value matching your pattern — controlled
- A valid-looking address — crash but not yet controlled

Check `captures[0].context_memory.stack_at_rsp.formatted` to see padding, return addresses, or shellcode bytes on the stack.

---

### Crash dump analysis

```
1. load_dump(path="C:/crashes/crash.dmp")
2. get_regs()             → full register state at crash time
3. get_stack(frames=30)   → call stack at crash
4. get_sp()               → read RSP value
5. read_mem(addr=<rsp>, size=64) → stack contents
6. disasm()               → instructions at the crash address
```

---

### Heap spray verification

```
1. attach(name="target.exe")
2. hw_bp(addr="0x1001F000", size=8, access="w", action="break")
3. go()
4. get_captures()                            → see what wrote to the spray address
5. read_mem(addr="0x1001EFC0", size=128)     → surrounding memory context
```

---

### ASLR check

```
1. create(path="C:/target/target.exe")
2. resolve(name="kernel32!WriteFile")   → record base address
3. terminate()
4. create(path="C:/target/target.exe")
5. resolve(name="kernel32!WriteFile")   → compare: changed = ASLR on, same = ASLR off
```

---

### Remote kernel debugging

```
1. kernel_attach(connect_string="net:port=55000,key=1.2.3.4")
2. list_modules()                        → all loaded kernel modules
3. module_info(name="ntoskrnl.exe")      → entry point and sections
4. raw(cmd="!process 0 0")              → list all processes from kernel context
5. raw(cmd="!pcr")                       → processor control region
```

---

### Thread inspection

```
1. attach(pid=1234)
2. list_threads()          → all thread IDs
3. set_thread(id=2)        → switch context
4. get_stack(frames=20)    → call stack for that thread
5. get_regs()              → registers for that thread
6. get_teb()               → TEB address
```

---

## Tips

**Symbol path** — If symbol resolution returns no results, configure the Microsoft symbol server:
```
raw(cmd=".sympath srv*C:\\symbols*https://msdl.microsoft.com/download/symbols")
raw(cmd=".reload")
```

**Timeout tuning** — `go()` defaults to 30 seconds. For targets that run longer before hitting a breakpoint:
```
go(timeout=120000)   # 2 minutes
go(timeout=300000)   # 5 minutes
```

**Address format** — All `addr` parameters accept hex strings (`"0x1234abcd"`, `"7fff12340000"`) or plain integers. The `0x` prefix is optional for hex values.

**Shellcode verification** — After a capture, use `read_mem` and `disasm` on the address where your shellcode should land. If `disasm` shows your intended instructions, the payload arrived intact.

**After `terminate` or `detach`** — All captures and breakpoints are cleared automatically. Call `create` or `attach` to begin a new session.

**`capture_state` vs `get_captures`** — Use `capture_state` for an on-demand snapshot when already stopped at a breakpoint. Use `get_captures` to retrieve state that was automatically saved each time a breakpoint fired during a `go` call.

**Kernel `raw` commands** — Common kernel debugging extensions that work well through `raw`:
```
raw(cmd="!process 0 0")       → list all processes
raw(cmd="!thread")            → current thread details
raw(cmd="!irql")              → current IRQL
raw(cmd="!pcr")               → processor control region
raw(cmd="!pte <addr>")        → page table entry for an address
raw(cmd="dt nt!_EPROCESS @$proc")  → dump EPROCESS structure
```

---

## License

MIT
