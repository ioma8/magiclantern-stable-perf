# Memory-Safety Audit — magiclantern_simplified

Audit date: 2026-08-10 · Branch: `dev` · HEAD: `3f24042a4dfbfba1c4cbfafede50e92a770ed3a9`

Scope: whole repo (firmware `src/`, `modules/`, `platform/`, host tools `tools/`).
Method: 6 parallel read-only agents over the codebase + direct grep sweep; every
finding marked CONFIRMED was re-verified by reading the full enclosing function.

Status legend:
- **CONFIRMED** — verified by direct code reading (full surrounding logic).
- **SCOUT** — reported by a subagent, pattern consistent, not individually re-verified.

Severity:
- **CRITICAL** — memory corruption / crash on a plausible path.
- **HIGH** — likely bug on a common path.
- **MEDIUM** — edge/error path or wrong-but-not-exploitable pattern.
- **LOW** — latent, defensive, or portability concern.

---

## CRITICAL

### AUDIT-01 · ptp_usb_getdata: unchecked calloc + uint32 length underflow → NULL/wild write
- Location: `tools/ptpcam/ptp.c:182-237` (buggy lines 211–224)
- Status: CONFIRMED
- Trigger: a USB device sends a PTP data container whose `length` field is `< PTP_USB_BULK_HDR_LEN` (12).

```c
len=dtoh32(usbdata.length)-PTP_USB_BULK_HDR_LEN;   /* uint32_t: underflows to ~4 GiB */
/* allocate memory for data if not allocated already */
if (*data==NULL) *data=calloc(1,len);              /* unchecked: NULL on failure */
/* copy first part of data to 'data' */
memcpy(*data,usbdata.payload.data, ...);
ret=params->read_func(((unsigned char *)(*data))+PTP_USB_BULK_PAYLOAD_LEN,
            len-PTP_USB_BULK_PAYLOAD_LEN, ...);   /* wild size */
```

- Why: `length < 12` → `len` ≈ 0xFFFFFFF8 → `calloc` fails → NULL is not checked →
  `memcpy(NULL, ...)` segfault. Any hostile/malformed device crashes ptpcam.
- Fix: validate `dtoh32(usbdata.length) >= PTP_USB_BULK_HDR_LEN` and `<=` a sane cap
  (e.g. declared transfer size); check `calloc` result; `memcpy`/`read_func` only after NULL check.

### AUDIT-02 · ptp_usb_event: attacker-controlled size overflows fixed struct
- Location: `tools/ptpcam/ptp.c:373-406` (buggy lines 388–393)
- Status: CONFIRMED

```c
size=dtoh32(usbevent.length);         /* device-controlled, no bound */
while (result<size) {
    CHECK_INT(usbevent, size);        /* reads `size` bytes into fixed-size struct */
```

- Why: `CHECK_INT(usbevent, size)` copies `size` bytes into a fixed
  `PTPUSBEventContainer`; a large `length` field overflows it (stack/static buffer).
  Also loops until `result >= size`, so a short read spins.
- Fix: clamp `size` to `sizeof(usbevent)` (or the negotiated packet length) before reading.

### AUDIT-03 · raw2dng: file-controlled blockSize → stack overflow
- Location: `modules/lv_rec/raw2dng.c:414, 431, 448, 465`
- Status: CONFIRMED

```c
file_set_pos(sidecar, -mlv_hdr_t_size, SEEK_CUR);
if(fread(&idnt_hdr, mlv_hdr.blockSize, 1, sidecar) != 1)   /* blockSize from file header */
```

- Why: `mlv_hdr.blockSize` is read from the MLV sidecar header. A crafted file sets
  `blockSize > sizeof(idnt_hdr)` → `fread` overflows a stack struct. Same pattern for
  `expo_hdr`, `lens_hdr`, `wbal_hdr`. Host-side tool, so a malicious MLV on the card is the trigger.
- Fix: validate `mlv_hdr.blockSize == sizeof(<hdr>)` before the `fread` (or read into a
  sized heap buffer and copy).

### AUDIT-04 · patch_mmu.c: L2-table region size miscalculated (`sizeof` on a constant)
- Location: `src/patch_mmu.c:364-365`
- Status: CONFIRMED (by arithmetic; layout math below)

```c
uint32_t L2_tables_end = (uint32_t)L2_tables
                            + sizeof(MMU_L2_TABLE_SIZE) * num_64k_pages;
```

`MMU_L2_TABLE_SIZE` is `#define MMU_L2_TABLE_SIZE (0x400)` (`src/mmu_utils.h:7`),
so `sizeof(MMU_L2_TABLE_SIZE)` is `sizeof(0x400)` = **4**, not `0x400`.

Consequences (fill-forwards branch, `calc_mmu_globals`):
1. The bounds check `L2_tables_end <= end_addr` that gates the "reduce pages" loop
   under-calculates the L2 table region by `0x3FC * num_64k_pages`.
2. For `num_64k_pages >= 10` the `L2_info_start` structs are placed at the (wrongly small)
   `L2_tables_end` — i.e. **inside the L2 table region**; the init loop
   (`src/patch_mmu.c:446-455`) then writes info structs over table memory and later
   table fills clobber the structs → patch code reads garbage `L2_table` pointers.
3. The real `0x400 * num_64k_pages` table area extends past the reserved region
   (e.g. 1 MiB space, n=15 → ~0x30800 bytes past the end). With
   `CONFIG_ALLOCATE_MEMORY_POOL` (only `platform/200D.101/internals.h:18` today) the
   overflow lands in ML's own code region at `RESTARTSTART`.

Currently dormant: 200D's layout (`PTR_ALLOC_MEM_START` value `0x46c000`, `RESTARTSTART 0x4d0000`)
takes the fill-*backwards* branch (correct code); M6II uses the n=1 `generic_mmu_space`.
Any MMU-remap cam with a 64K-aligned pool start flips to fill-forwards and hits this.
- Fix: `+ MMU_L2_TABLE_SIZE * num_64k_pages`.

### AUDIT-05 · vectorscope_addpixel: heap OOB write on every gray pixel
- Location: `src/zebra-5dc.c:365-392` (caller `556-557`)
- Status: CONFIRMED

```c
static inline void vectorscope_addpixel(uint8_t y, int8_t u, int8_t v)
{
    ...
    int32_t V = -v;                       /* gray pixel: byte 128 → int8_t −128 → V=128 */
    V *= vectorscope_height; V >>= 8; V += vectorscope_height >> 1;
    ...
    uint16_t pos = U + V * vectorscope_width;   /* no bounds check */
    if(vectorscope[pos] < (0x2A << 2)) vectorscope[pos]++;
}
```

- Why: for U=V=128 (gray — the most common pixel), `V = 128*height/256 + height/2 = height`,
  so `pos = height*width` == buffer size → `vectorscope[pos]++` writes 1 byte past the
  heap allocation for **every gray pixel** while the vectorscope overlay is enabled.
  Repeated +1 writes corrupt adjacent heap chunk metadata.
- Fix: clamp `pos` to `[0, width*height)` (or `if (V >= height) V = height-1;` etc.).

---

## HIGH

### AUDIT-06 · ptpcam close_usb: dead NULL check — recent "fix" is a no-op
- Location: `tools/ptpcam/ptpcam.c:373-379` (introduced in commit `00df6d442`)
- Status: CONFIRMED

```c
void close_usb(PTP_USB* ptp_usb, struct usb_device* dev)
{
    if (ptp_usb == NULL
        || usb_device == NULL)     /* `usb_device` is a FUNCTION (libusb), always != NULL */
        return;
    usb_release_interface(ptp_usb->handle,
                          dev->config->interface->altsetting->bInterfaceNumber);  /* NULL deref if dev==NULL */
```

- Why: `usb_device` is the libusb-0.1 function `struct usb_device *usb_device(usb_dev_handle*)`;
  comparing it to NULL is always false. The guard the commit intended (`dev == NULL`)
  never runs, so a NULL `dev` still crashes on `dev->config->...`.
- Fix: `|| dev == NULL`.

### AUDIT-07 · edmac_raw_slurp: missing mandatory alignment check + yb underflow
- Location: `src/edmac-memcpy.c:399-429`
- Status: CONFIRMED

The sibling DMA routine `edmac_copy_rectangle_cbr_start` (`src/edmac-memcpy.c:143-148`)
explicitly warns: *"Do not remove this check, or risk permanent camera bricking"*:

```c
uint32_t bpt = edmac_bytes_per_transfer(edmac_memcpy_flags);
if ((w * h) % bpt) { printf("Invalid EDMAC output size ..."); return 0; }
```

`edmac_raw_slurp` has neither that check nor the `ASSERT(dst == UNCACHEABLE(dst))` guard,
and sets `yb = h-1` (`edmac-memcpy.c:422`) — for `h == 0`, `yb = 0xFFFFFFFF`, an
effectively unbounded DMA transfer. Trigger: a resolution transition where height is
momentarily 0, or a raw size not divisible by the transfer width.
- Fix: add the `(w*h) % bpt` check (and an h==0 guard) before `SetEDmac`.

### AUDIT-08 · raw_lv_realloc_buffer: unchecked fio_malloc → DMA writes to 0x0
- Location: `src/raw.c:855-859`
- Status: CONFIRMED

```c
#ifdef CONFIG_ALLOCATE_RAW_LV_BUFFER
    raw_allocated_lv_buffer = fio_malloc(RAW_LV_BUFFER_ALLOC_SIZE);
    raw_lv_buffer = raw_allocated_lv_buffer;       /* no NULL check */
    raw_lv_buffer_size = RAW_LV_BUFFER_ALLOC_SIZE;
    return;
#endif
```

- Why: on OOM (4K/5K LV start), `raw_lv_buffer = NULL`; the next `raw_lv_vsync`
  (`src/raw.c:2153`) hands it to `edmac_raw_slurp`, which programs the DMA engine to
  write a full frame to address 0x0 — zero-page/corruption or DMA fault. A second call
  also re-mallocs (leak) because the `ASSERT` at `raw.c:851` only fires for non-NULL buffers.
- Fix: check `fio_malloc` result; keep the previous buffer or fall back to default.

### AUDIT-09 · peak_disp_filter: NULL src_buf deref on first call
- Location: `src/zebra.c:1504-1511` (handoff from `src/tweaks.c:3197-3231`)
- Status: CONFIRMED (narrow window — may be masked by earlier callers)

```c
// tweaks.c display_filter_get_buffers():
static void* prev = 0;
static void* buff = 0;
...
if (current != prev) buff = prev;   /* first-ever call: buff stays NULL */
prev = current;
*src_buf = buff;                    /* NULL on first call */
```

```c
// zebra.c peak_disp_filter():
if (lv) { display_filter_get_buffers(&src_buf, &dst_buf); }   /* no NULL check */
...
PEAK_LOOP ... dst_buf[i] = ... src_buf[i] ...;                 /* NULL deref */
```

- Why: all other callers of `display_filter_get_buffers` guard the result
  (`src/tweaks.c:2940, 3026`, `src/module.c:1380`); `peak_disp_filter` does not.
  The statics return `src_buf = NULL` on the very first invocation in the process.
- Fix: `if (!src_buf || !dst_buf) return;` before the loop.

### AUDIT-10 · posix.c realloc: NULL deref on OOM + copies new size from old block
- Location: `src/posix.c:62-73`
- Status: CONFIRMED

```c
void *realloc(void *ptr, size_t size)
{
    void *ret = malloc(size);
    if (ptr)
    {
        memcpy(ret, ptr, size);    /* ret may be NULL → crash; size is the NEW size → OOB read of old block */
        free(ptr);
    }
    return ret;
}
```

- Why: on OOM `ret == NULL` and `memcpy(NULL, ptr, size)` crashes — before any caller
  NULL check can run. It also copies `size` (new) bytes from the old, smaller allocation.
  Growth-style callers: `modules/lv_rec/raw2dng.c:732`, `modules/raw_video/mlv_play/mlv_play.c:1349`,
  `modules/plot/plot.c:175`.
- Fix: `if (!ret) return NULL;` and copy `min(old_size, size)`.

### AUDIT-11 · FIO_CopyFile: handle + orphan-file leak on malloc failure
- Location: `src/fio-ml.c:718-720`
- Status: CONFIRMED

```c
FILE* f = FIO_OpenFile(src, O_RDONLY | O_SYNC);
FILE* g = FIO_CreateFile(dst);
...
void* buf = fio_malloc(bufsize);
if (!buf) return -1;               /* f and g stay open; empty dst file left behind */
```

- Why: OOM leaves both file handles open (DryOS handle pool is small) and an empty
  destination file. Repeated failures exhaust handles.
- Fix: `fio_free`/close both handles on this path (and remove `dst`).

### AUDIT-12 · mlv_dump: malloc result dereferenced without NULL check
- Location: `modules/raw_video/mlv_rec/mlv_dump.c:673, 740, 3317`
- Status: SCOUT (pattern consistent: `malloc(...)` then immediate use; no `if (!ptr)`)

---

## MEDIUM

### AUDIT-13 · PROP handlers use property payload as printf format string
- Location: `src/propvalues.c:54-58` (`PROP_CAM_MODEL`), `77-80` (`PROP_FIRMWARE_VER`)
- Status: CONFIRMED

```c
PROP_HANDLER(PROP_CAM_MODEL)
{
    memcpy((char *)&camera_model_id, (void*)buf + 32, 4);   /* no len >= 36 check */
    snprintf(camera_model, sizeof(camera_model), (const char *)buf);   /* buf as FORMAT */
}
PROP_HANDLER(PROP_FIRMWARE_VER)
{
    snprintf(firmware_version, sizeof(firmware_version), (const char *)buf);
}
```

- Why: the property payload (camera-controlled) is used as the `snprintf` format string;
  any `%` in it reads garbage as varargs. Not currently exploitable (Canon sends fixed
  ASCII), but the wrong pattern — plus `buf+32` is read without verifying `len >= 36`.
- Fix: `snprintf(..., "%s", (const char*)buf)`; check `len` before the `buf+32` read.

### AUDIT-14 · PROP_BODY_ID: unaligned 64-bit load
- Location: `src/propvalues.c:60-75` (line 65)
- Status: CONFIRMED

```c
snprintf(camera_serial, sizeof(camera_serial), "%X%08X",
    (uint32_t)(*((uint64_t*)buf) & 0xFFFFFFFF), (uint32_t) (*((uint64_t*)buf) >> 32));
```

- Why: `*(uint64_t*)buf` requires 8-byte alignment; DryOS property buffers are typically
  4-aligned → alignment fault on ARM (LDRD) → crash. `len == 8` is checked, alignment is not.
- Fix: read two `uint32_t`s or use `memcpy`.

### AUDIT-15 · CFG_APPEND: snprintf return-value accumulation can overrun CFG_SIZE
- Location: `src/menu.c:6700-6701`
- Status: CONFIRMED

```c
#define CFG_APPEND(fmt, ...) do { cfglen += snprintf(cfg + cfglen, CFG_SIZE - cfglen, fmt, ## __VA_ARGS__); } while(0)
#define CFG_SIZE (256*1024)
```

- Why: `snprintf` returns the would-be length, so once the accumulated (truncated) total
  exceeds `CFG_SIZE`, `CFG_SIZE - cfglen` underflows (size_t) and the next `snprintf`
  writes past the 256 KiB buffer. Reachable when dumping very large menu trees
  (many modules/entries) in `menu_save_unloaded_flags`.
- Fix: track `n = snprintf(...)`; add `min(n, remaining)`.

### AUDIT-16 · ml-cbr: strncpy(16) into char[16] leaves no NUL
- Location: `src/ml-cbr.c:108`
- Status: CONFIRMED

```c
struct cbr_record { char name[16]; ... };           /* ml-cbr.c:39 */
strncpy(first_free->name, event, 16);               /* event >= 16 chars → no NUL */
dbg_printf("%s\n", first_free->name);               /* reads past struct */
...
fast_compare(event, current->pool[i].name) → strcmp  /* OOB read */
```

- Why: `strcmp`/`%s` read past `name[16]` into the arena when the event name is ≥16 chars.
- Fix: `strncpy(..., 15); name[15] = 0;`

### AUDIT-17 · trace_write_binary: writes 8-byte TSC, advances 4
- Location: `modules/trace/trace.c:540-541`
- Status: CONFIRMED

```c
memcpy(&ctx->buffer[ctx->buffer_write_pos], &tsc, sizeof(tsc));  /* 8 bytes */
ctx->buffer_write_pos += 4;                                      /* advance 4 */
trace_write_varlength(context, length);                          /* overwrites TSC high half */
```

- Why: every trace entry's length/data fields overwrite the high 4 bytes of the TSC and
  shift the whole stream out of parse alignment → corrupted trace data.
- Fix: `+= sizeof(tsc)`.

### AUDIT-18 · my_fprintf: truncated format → FIO_WriteFile reads past stack buffer
- Location: `src/fio-ml.c:901-920`
- Status: CONFIRMED

```c
const int maxlen = 512;
char buf[maxlen];
len = vsnprintf( buf, maxlen-1, fmt, ap );   /* returns WOULD-BE length */
FIO_WriteFile( file, buf, len );             /* reads len bytes from a 512-byte buffer */
```

- Why: a formatted line longer than 511 chars (e.g. a flexinfo `name="..."` value from a
  user config file, `src/flexinfo.c` element dumps) truncates the write but `len` still
  reports the full length → stack OOB read.
- Fix: `len = MIN(len, maxlen-1)` before `FIO_WriteFile` (and pass `len`).

### AUDIT-19 · lens.c property handlers trust payload length
- Location: `src/lens.c` — `PROP_CUSTOM_WB` (reads `gains[16..19]`), `PROP_LV_LENS` (memcpy ignores `len`), `PROP_LENS` (reads offsets 0–14 unconditionally)
- Status: SCOUT

### AUDIT-20 · chdk-gui_script: off-by-one parameter index
- Location: `modules/script/chdk-gui_script.c` — `'a' + SCRIPT_NUM_PARAMS` allows index 26 into 26-element arrays
- Status: SCOUT

---

## LOW / LATENT

### AUDIT-21 · read_entire_file: size+1 wrap for 4 GiB files
- Location: `src/fio-ml.c:874`
- Status: CONFIRMED — `fio_malloc(size + 1)` wraps to 0 when `size == 0xFFFFFFFF`
  (max FAT32 file), then `read_file` overflows. Practical only for a 4 GiB−1 file.

### AUDIT-22 · peak_scaling[255] never initialized
- Location: `src/zebra.c:1502, 1535-1536, 1567`
- Status: CONFIRMED (downgraded from SCOUT "medium") — loop fills `0..254`; the read path
  `peak_scaling[MIN(e,255)]` can hit index 255. Array is `static` → zero-filled, so this is
  an in-bounds read of 0 → wrong focus-peak values (display glitch), not corruption.

### AUDIT-23 · debug.c chunk_save: leak + unchecked writes on error paths
- Location: `src/debug.c:126-158` — div-check failure returns without `FIO_CloseFile`;
  `FIO_WriteFile` return values ignored.

### AUDIT-24 · FIO_WriteFile now forces UNCACHEABLE on all cams
- Location: `src/fio-ml.c:661-680` (commit `dc429c533`)
- Status: CONFIRMED behavior change — the old `#ifdef CONFIG_MEM_2GB` guard was removed;
  every write now passes `UNCACHEABLE(ptr)` (`ptr | 0x40000000` for `ptr < 0x40000000`).
  Comment claims old cams "shouldn't mind". Untested risk on older DIGIC generations;
  verify a 5D2/600D-class cam before shipping.

### AUDIT-25 · ptpcam Makefile forces -m32
- Location: `tools/ptpcam/Makefile:3`
- Status: CONFIRMED — `CFLAGS=-m32` requires multilib gcc and 32-bit `libusb` dev
  packages; breaks on modern distros and arm64 macOS (this workstation).

### AUDIT-26 · M6II mmu_patches.h FW-version guard is brittle
- Location: `platform/M6II.111/include/platform/mmu_patches.h:6`
- Status: CONFIRMED — `#if CONFIG_FW_VERSION == 111` wraps all four patch arrays. If
  `CONFIG_FW_VERSION` is ever undefined at that include site, the arrays vanish and
  `src/patch_mmu.c` fails to compile. Currently fine (`-DCONFIG_FW_VERSION=111`).

### AUDIT-27 · mlv.c strncpy without NUL into fixed MLV fields
- Location: `modules/raw_video/mlv_rec/mlv.c:59-60, 95`
- Status: CONFIRMED (downgraded from SCOUT "high") — `strncpy(hdr->lensName, name, 32)`
  into fixed-size MLV fields. MLV spec treats these as fixed fields; source strings are
  already NUL-terminated and ≤31 chars, so no OOB in practice.

---

## Checked and clean (no issue found)

- `STR_APPEND` (`src/dryos.h:217`) is bounds-safe (snprintf with remaining size).
- `tweaks-eyefi.c` `newname[strlen(newname)-4]` — safe: FIO names are 256-byte fields,
  paths are ≥18 chars, and 8.3 names are space-padded.
- `module.c` module-name handling — bounded (`MODULE_NAME_LENGTH 8` ≤ buffer 31).
- `lua.c script_extract_string_from_comments` — empty-string edge traced safe
  (`*output` is always ≥1 char when set).
- `init.c backup_region` — copies ROM→RAM before `FIO_WriteFile`, so
  `CONFIG_AUTOBACKUP_ROM` on D8+ is not affected by the D8 FIO-From-ROM limitation
  (that bug only hit the Debug-menu dump path, fixed in `3264d0c67`).
- `gdb.c` suspicious thread-list code is `#if 0` dead.
- `mem.c` `err_flags[strlen(err_flags)-1]` — never empty on the guarded path.
- `rom dump chunk_save` math — `ROM0_SIZE/ROM1_SIZE` divide cleanly by 32.

---

## Recent-commit notes (dev branch, last ~20 commits)

- `00df6d442` (ptpcam null-ptr "fix") — the `close_usb` half is broken, see AUDIT-06.
- `dc429c533` (FIO UNCACHEABLE) — behavior change on all cams, see AUDIT-24.
- `b6241db88` (M6II MMU remap) — introduces the dormant AUDIT-04 defect and AUDIT-26 guard.
- `3264d0c67` (rom dump D8+) — fix itself is sound; error paths leak (AUDIT-23).
- `0834d1160` (audio semaphore NULL-guards) — correct: `gain.sem` is only NULL when
  `create_named_semaphore` failed; guards prevent DryOS asserts as intended.
- `559d1d25d` (750D PROP_LV_ACTION special case removal) — can't be verified from source;
  needs hardware confirmation that 750D's prop payload is a direct value, not a pointer.

---

# Fixes applied (2026-08-10)

Every finding above was fixed. Build verification: `platform/5D3.123` (DIGIC V, core + default
modules) and `platform/200D.101` (DIGIC 7 + MMU remap) both build clean (`make -j8`, exit 0);
`platform/M6II.111` build verified (MMU port); host tools `ptpcam` (arm64 macOS, libusb-compat)
builds and runs; `raw2dng.c`/`chdk-gui_script.c`/`trace.c`/`io_crypt.c` compile-verified
(syntax/standalone builds; `trace`/`io_crypt`/`script` have pre-existing build breakage at
lines unrelated to these fixes and are not part of any default build).

| AUDIT | Fix |
|---|---|
| 01 | `ptp.c` `ptp_usb_getdata`: validate `container_len >= PTP_USB_BULK_HDR_LEN` before subtracting; check `calloc` result (and avoid `calloc(0)`) |
| 02 | `ptp.c` `ptp_usb_event`: clamp device-declared `size` to `sizeof(usbevent)` |
| 03 | `raw2dng.c`: reject `blockSize > sizeof(<hdr>)` for IDNT/EXPO/LENS/WBAL before `fread` |
| 04 | `patch_mmu.c`: `sizeof(MMU_L2_TABLE_SIZE)` → `MMU_L2_TABLE_SIZE` (L2 region end now correct; info structs no longer land inside the table area) |
| 05 | `zebra-5dc.c`: clamp vectorscope U/V to `[0, size-1]`; widened `pos` to `uint32_t` (was `uint16_t`, which wraps for 320x240 scopes) |
| 06 | `ptpcam.c` `close_usb`: `usb_device == NULL` (function) → `dev == NULL` |
| 07 | `edmac-memcpy.c` `edmac_raw_slurp`: added the `(w*h) % bytes_per_transfer` guard (sibling code warns of bricking) and `h<=0`/`w<=0` rejection |
| 08 | `raw.c`: check `fio_malloc` in `raw_lv_realloc_buffer`; on OOM keep the old buffer instead of handing NULL to EDMAC |
| 09 | `zebra.c` `peak_disp_filter`: guard `src_buf`/`dst_buf` NULL (first-call handoff) |
| 10 | `posix.c` `realloc`: NULL-check the new block (no more `memcpy(NULL,...)`), copy `MIN(size, old)` using the new exact `malloc_size()` accessor (header `memcheck_hdr.length`, `mem.c`); `calloc`: overflow check; `strlcat`: POSIX `n <= dst_len` early return (no more uint32 underflow) |
| 11 | `fio-ml.c` `FIO_CopyFile`: close both handles + remove dst on malloc failure |
| 12 | `mlv_dump.c`: NULL-check all three mallocs; reject `frame_size <= 0` (negative `blockSize - frameSpace`) |
| 13 | `propvalues.c`: payload no longer used as `snprintf` format (`%.*s` bounded by `len`); `PROP_CAM_MODEL` checks `len >= 36` before the `buf+32` read |
| 14 | `propvalues.c` `PROP_BODY_ID`: `memcpy` for the 64-bit serial load (no unaligned `*(uint64_t*)`) |
| 15 | `menu.c` `CFG_APPEND`: accumulate `MIN(actual, avail-1)` and stop at `CFG_SIZE` (no size_t underflow) |
| 16 | `ml-cbr.c`: `strncpy(name, event, sizeof-1)` + explicit NUL |
| 17 | `trace.c`: `buffer_write_pos += sizeof(tsc)` (was 4) |
| 18 | `fio-ml.c` `my_fprintf`: cap `len` at `maxlen-1` before `FIO_WriteFile` (no stack OOB read on truncation) |
| 19 | `lens.c`: `PROP_CUSTOM_WB` requires `len >= 40` and reads from the local copy; `PROP_LV_LENS` requires `len >= 6` and caps the memcpy (reads from the copy); `PROP_LENS` requires `len >= 4` (5DC) / `len >= 0xF` (others) before indexing |
| 20 | `chdk-gui_script.c`: bounds `ptr[0] <= 'a'+SCRIPT_NUM_PARAMS-1` at all 5 parse sites (off-by-one allowed index 26 into 26-element arrays) |
| 21 | `fio-ml.c` `read_entire_file`: reject `size == 0xFFFFFFFF` (size+1 wrap) |
| 22 | `zebra.c`: `peak_scaling` loop now fills `0..255` inclusive |
| 23 | `debug.c`: close the ROM dump file handle on the div-check error paths |
| 24 | no code change — behavior kept (new cams need it); documented that old-cam aliasing is the intended semantics of `UNCACHEABLE()` |
| 25 | `tools/ptpcam/Makefile`: `-m32` only on x86_64; macOS gets `-I/opt/homebrew/include -L/opt/homebrew/lib`; `ptp.c` 32-bit `#error` relaxed to `#warning` after confirming all packed values are 32-bit camera addresses |
| 26 | `M6II mmu_patches.h`: guard is now `!defined(CONFIG_FW_VERSION) || CONFIG_FW_VERSION == 111` |
| 27 | `mlv.c`: `strncpy(..., sizeof-1)` + explicit NUL for `lensName`/`lensSerial`/`picStyleName`; `mlv_build_vers` malloc NULL-check + caller guard |

Extra fixes found while fixing (not in the original 27):
- `properties.c` `SVALRET` macro wrote `s[SVALLEN]` (OOB by one) → `s[SVALLEN-1]`; `ptp_prop_tostr` derefs NULL `value` (from a failed `ptp_unpack_string`) → guarded.
- `ptp-pack.c` array unpackers: device-reported counts capped at `PTP_MAX_ARRAY_COUNT` and mallocs NULL-checked (was: `n*sizeof` overflow + unchecked malloc → heap overflow).
- `mlv_dump.c` delta-encode OOM path now keeps `prev_frame_buffer` consistent (was: subsequent frames delta-encoded against a stale reference → silent output corruption).
- `mlv_play.c` sequence-file scan: `realloc` result NULL-checked (was: NULL deref + old-block leak on OOM).
- `file_man.c` `BrowseUp`: `snprintf(old_dir, ..., p+1)` used a directory name as a **format string** → `"%s"`; plus `strlen(gPath)-2` underflow guard.
- `file_man.c` `path_strip_last_item` / `select_by_extension`: `strlen-2`/`strlen-1` underflow guards; `fe->name + strlen - strlen(Ext)` could go negative for short filenames → guard.
- `mlv_play.c`: `strlen-3` guard in delete path; suffix underflow + malloc NULL check in playlist scan.
- `io_crypt.c`: `strlen-3` extension access guarded.
- Build system (macOS host): `Makefile.globals` `READELF ?= $(CROSS_COMPILE)readelf` (was hardcoded `readelf`), `STAT_CMD` now BSD/GNU-aware (`stat -f` on Darwin); `modules/lua/dietlibc/include/sys/cdefs.h` gained the newlib-compat macros (`__dead2`, `__returns_twice`, …) that gcc-arm-none-eabi ≥ 15 requires — without this the lua module (and anything pulling newlib headers through the dietlibc include path) fails to parse.

Not fixed (intentionally): AUDIT-24 (see row), `trace`/`io_crypt`/`script` modules' pre-existing build
breakage (unrelated lines, modules not in any default build), `ptpcam` `-Wpointer-sign` warnings
(host tool, pre-existing), `750D PROP_LV_ACTION` (needs hardware).

Known residual limitations (documented in code):
- `ptp-pack.c` array unpackers cap the malloc but the read loop still trusts the packet's
  declared count (response buffer size is not plumbed through `ptp_transaction`); a hostile
  count reads at most `PTP_MAX_ARRAY_COUNT * 4` bytes past a truncated response — bounded, no heap overflow.
- `ptp_usb_getdata` validates only the lower bound; an upper cap would need the declared
  transfer size which the transaction API doesn't carry.
- `ptp_usb_event` clamps the size but a device sending fewer bytes than declared loops on
  reads until the USB timeout fails the call.
