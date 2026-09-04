# pe

Read, write, and link PE/COFF — relocatable objects, archives (`.lib`/`.a`) and import libraries, module-definition (`.def`) files, compiled resources (`.res`), and images (`.exe`, `.dll`, `.sys`, `.efi`).

## Install

```sh
go get github.com/vertex-language/pe
```

Machine-specific codegen lives in its own backend package and registers itself via blank import, so a build only pays for the backends it uses:

```go
import _ "github.com/vertex-language/pe/x64" // registers AMD64
```

## Contents

- [Package map](#package-map)
- [Quick start](#quick-start)
  - [Identify a file](#identify-a-file)
  - [Read a COFF object](#read-a-coff-object)
  - [Write a COFF object](#write-a-coff-object)
  - [Read an archive and pull a member](#read-an-archive-and-pull-a-member)
  - [Parse a .def file](#parse-a-def-file)
  - [Write an import library](#write-an-import-library)
  - [Link objects into an executable](#link-objects-into-an-executable)
  - [Link a DLL with exports](#link-a-dll-with-exports)
  - [Build a resource tree](#build-a-resource-tree)
- [How it's put together](#how-its-put-together)
- [Known limitations](#known-limitations)
- [License](#license)

## Package map

| Package | Purpose |
|---|---|
| `pe` | Shared identity types: `Machine`, `Target`, `Width`, `SecKind`/`SecProt`, base relocations, data directory indices. No I/O. |
| `pe/coff` | Read and write relocatable COFF objects (`.obj`), including bigobj, COMDATs, `.drectve`, weak externals. |
| `pe/ar` | Read and write COFF archives: MSVC-layout `.lib` (read/write) and MinGW `.dll.a` (read). |
| `pe/implib` | Read and write import libraries (short-import members). |
| `pe/def` | Parse module-definition (`.def`) files. |
| `pe/rsrc` | Parse `.res` files and build the three-level `.rsrc` resource tree. |
| `pe/image` | The linked-side output model: sections, chunks, views, data directories, layout phases. |
| `pe/backend` | The interface a machine backend implements (`Classify`, `Scan`, `Apply`, base-reloc mapping, import thunks). |
| `pe/x64` | The AMD64 backend. Import for its side effect to link AMD64 targets. |
| `pe/link` | The linker: takes objects/archives/import libs/resources, produces an `*image.Image`. |

`pe/internal/*` (`binio`, `format`, `strtab`) are implementation details and not part of the public API.

## Quick start

### Identify a file

```go
head := make([]byte, pe.KindPrefix)
if _, err := f.ReadAt(head, 0); err != nil {
    log.Fatal(err)
}

switch pe.KindOf(head) {
case pe.KindObject, pe.KindBigObj:
    fmt.Println("relocatable object")
case pe.KindImage:
    fmt.Println("linked image")
case pe.KindArchive:
    fmt.Println("archive")
case pe.KindShortImport:
    fmt.Println("import library member")
default:
    fmt.Println("unknown")
}
```

### Read a COFF object

```go
f, err := coff.Open("hello.obj")
if err != nil {
    log.Fatal(err)
}
defer f.Close()

fmt.Println("machine:", f.Machine)

for _, sec := range f.Sections {
    data, err := sec.Data()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%-10s %6d bytes  kind=%s prot=%s\n",
        sec.Name, len(data), sec.Kind(), sec.Prot())
}

syms, err := f.Symbols()
if err != nil {
    log.Fatal(err)
}
for _, s := range syms {
    fmt.Println(s.Name, s.Class, s.Section)
}
```

### Write a COFF object

```go
target, err := pe.ParseTarget("x86_64-pc-windows-msvc")
if err != nil {
    log.Fatal(err)
}

var buf bytes.Buffer
w := coff.NewWriter(&buf, coff.Options{Target: target})

text := w.Section(coff.SectionHeader{
    Name:  ".text",
    Kind:  pe.SecCode,
    Prot:  pe.SecExecute | pe.SecRead,
    Align: 16,
})
text.Write([]byte{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3}) // mov eax, 42; ret

w.Symbol(coff.SymbolDef{
    Name:    "Answer",
    Section: text,
    Value:   0,
    Class:   pe.ClassExternal,
    Type:    pe.PackSymType(pe.BaseNull, pe.DerivedFunction),
})

if err := w.Close(); err != nil {
    log.Fatal(err)
}
os.WriteFile("answer.obj", buf.Bytes(), 0o644)
```

### Read an archive and pull a member

```go
f, err := ar.Open("libfoo.lib")
if err != nil {
    log.Fatal(err)
}
defer f.Close()

m, err := f.Lookup("MyExportedFunc")
if err != nil {
    log.Fatal(err) // ar.ErrNoIndex, or not found
}
data, err := m.Data()
```

### Parse a .def file

```go
mod, err := def.Parse(defBytes)
if err != nil {
    log.Fatal(err)
}
fmt.Println(mod.Module(), "->", mod.DLLName())
for _, e := range mod.Exports {
    fmt.Println(" ", e.Exported())
}
```

### Write an import library

```go
target, err := pe.ParseTarget("x86_64-pc-windows-msvc")
if err != nil {
    log.Fatal(err)
}

exports := []pe.Export{
    {Name: "Add"},
    {Name: "Sub"},
}

var buf bytes.Buffer
if err := implib.Write(&buf, implib.Options{
    Target: target,
    DLL:    "mymath.dll",
}, exports); err != nil {
    log.Fatal(err)
}
os.WriteFile("mymath.lib", buf.Bytes(), 0o644)
```

### Link objects into an executable

```go
package main

import (
    "log"
    "os"

    "github.com/vertex-language/pe"
    "github.com/vertex-language/pe/link"
    _ "github.com/vertex-language/pe/x64" // registers the AMD64 backend
)

func main() {
    target, err := pe.ParseTarget("x86_64-pc-windows-msvc")
    if err != nil {
        log.Fatal(err)
    }

    l, err := link.New(target)
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    mainObj, err := os.ReadFile("main.obj")
    if err != nil {
        log.Fatal(err)
    }
    if err := l.AddObject("main.obj", mainObj); err != nil {
        log.Fatal(err)
    }

    l.SetLibPath(`C:\VC\lib\x64`, `C:\Windows Kits\10\Lib\um\x64`)
    l.DefaultLib("kernel32")
    l.DefaultLib("msvcrt")
    l.SetSubsystem(pe.SubsystemConsole)
    l.SetEntry("mainCRTStartup")
    l.SetOutputKind(link.OutputEXE)

    img, err := l.Link()
    if err != nil {
        log.Fatal(err)
    }
    out, err := img.Bytes()
    if err != nil {
        log.Fatal(err)
    }
    if err := os.WriteFile("main.exe", out, 0o755); err != nil {
        log.Fatal(err)
    }
}
```

### Link a DLL with exports

```go
l.SetOutputKind(link.OutputDLL)
l.Export(pe.Export{Name: "Add"})
l.Export(pe.Export{Name: "Sub"})
```

### Build a resource tree

```go
res, err := rsrc.ParseRes(resBytes)
if err != nil {
    log.Fatal(err)
}

tree := rsrc.NewTree()
if err := tree.AddAll(res); err != nil {
    log.Fatal(err)
}

data, fixups, err := tree.Build()
if err != nil {
    log.Fatal(err)
}
// fixups need the section's final RVA added at layout time —
// l.AddResources(resBytes) handles this automatically inside a normal link.
_ = data
_ = fixups
```

## How it's put together

- **Backends are pluggable, not switched on.** `pe/link` never contains per-architecture logic directly; it resolves against whatever registered itself via `backend.Register` from a blank import (e.g. `pe/x64`). An unregistered target fails fast with `backend.NoBackendError` rather than failing partway through a link.
- **`pe/internal/*`** (`binio`, `format`, `strtab`) hold the shared low-level plumbing used by every reader/writer pair and are not part of the public API.

## Known limitations

**Architecture support.** Seeded machines are `I386`, `AMD64`, `ARM64`, `ARM64EC` (object-only), and `ARM64X` (object-only), but only `pe/x64` ships as a registered, linkable backend in this module — linking for anything but AMD64 needs a backend this module doesn't provide yet.

**SafeSEH is not implemented, and is blocked on the gap above rather than merely unwritten.** `/SAFESEH` is x86-only — AMD64 uses table-based (not registration-based) exception handling and has no SafeSEH table to build — so implementing it has no way to be exercised end to end, let alone verified against a real linker's output, until an `I386` backend exists. `Options.SafeSEH` and `loadConfig.safeSEH` are placeholders for that future work, not a reachable feature today.

**MinGW/GNU import libraries** are now read *and* written for AMD64. `implib.Write` produces dlltool-shaped archives (`writegnu.go`) — a head object, one object per export, and a tail object, each a real COFF object contributing real `.idata` sections rather than the short-import pseudo-objects the MS shape uses — verified by linking against them with this package's own linker and checking the result with `pefile`. A `.dll.a` built by dlltool itself round-trips the same way (`TestLinkWithGNUImportLibrary`). i386 is not implemented: dlltool's i386 objects follow a different internal convention (a double-underscore head symbol, a thunk relocated directly against the IAT slot's section symbol rather than a separate `__imp_` symbol) that `writegnu.go` does not reproduce, and — as above — there is no `I386` backend to link the result with anyway. ARM64/ARM64EC have no GNU toolchain that consumes this shape at all.

The multi-symbol ordering hazard this section used to describe — GNU import contributions merging in resolution order rather than the head/real-entries/terminator order dlltool assumes — is fixed (`chunkRank` in `link/merge.go` now orders `.idata$4`/`.idata$5` contributions by role, not by when each object happened to be pulled into the link).

**Delay-loaded imports work when driven by a GNU delay-import archive** (`dlltool -y`), which needs no new machinery here: dlltool's `.didat$2` through `.didat$7` are the exact same convention as `.idata$2` through `.idata$7` one letter over, merged by the identical `$`-group pipeline — including the identical ordering hazard, which `chunkRank` now handles for `.didat$4`/`.didat$5` the same way it does for `.idata$4`/`.idata$5`. The one piece that was actually missing was telling the loader where the result is; `imports.Dirs()`'s GNU fallback now registers `DirDelayImport` for a `.didat` section the same way it already did `DirImport`/`DirIAT` for `.idata`. This package still does not generate the actual resolver — the code a delay-load thunk calls into (`__delayLoadHelper2`) is CRT-supplied on both toolchains (`delayimp.lib` for MSVC, `libdelayimp.a` for MinGW), not something a linker emits — which is unchanged from how `/DELAYLOAD` has always worked with `link.exe` and requires no equivalent here. `Linker.SetDelayLoad`, the MS-format request that would need this package to generate the descriptor table and the per-function thunks itself rather than reading them from an archive, still fails the link outright rather than silently shipping an image that doesn't delay-load anything — and so does `Linker.SetDelayUnload` on its own, since it only means anything as a field of that same unbuilt MS-format descriptor.

**Debug data directory support** now covers `IMAGE_DEBUG_TYPE_CODEVIEW` (a CodeView record naming a PDB — this package never writes one, but the record is there for a debugger to follow), `IMAGE_DEBUG_TYPE_REPRO` (a SHA-256 of the finished image, computed and patched in after `emit` and the dynamic relocations, for reproducible-build verification), and `/CETCOMPAT` (`Options.CETCompat`, an `IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS` entry carrying `IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT` — recent toolchains record CET shadow-stack compatibility there rather than as an optional-header bit, since `DllCharacteristics` ran out of bits).

## License

MIT