#pragma once

#include <Windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace sunrise::client::hooks::fov {

/** Process-memory reader used by the signature resolvers. */
using read_fn = bool (*)(std::uintptr_t, void*, std::size_t);
/** Optional sink for one complete resolver diagnostic. */
using log_fn = void (*)(const char*);

namespace detail {

/** Only the first two resolver signatures provide the keys used by FOV decryption. */
inline constexpr int kFovKeyPairCount = 2;

/** Formats one bounded resolver diagnostic when a sink is present. */
inline void logf(log_fn log, char* buf, std::size_t cap, const char* fmt, ...) {
    if (!log) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
    log(buf);
}

/**
 * Copies one current-process range behind an exception boundary.
 * @param va First virtual address to read.
 * @param out Destination storage.
 * @param n Byte count.
 * @return True when the complete range was readable.
 */
inline bool scan_read(std::uintptr_t va, void* out, std::size_t n) {
    __try {
        std::memmove(out, reinterpret_cast<const void*>(va), n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

/**
 * Resolves the global-value RVA pairs used to construct pointer-decryption keys.
 * @param base Main executable image base.
 * @param rd Reader for image headers, sections and instructions.
 * @param out_pairs Receives both module-relative source pairs in signature order.
 * @param log Optional diagnostic sink.
 * @return Number of complete pairs resolved.
 */
inline int
key_resolve(std::uintptr_t base,
            read_fn rd,
            std::uint32_t out_pairs[kFovKeyPairCount][2],
            log_fn log) noexcept {
    char lbuf[192];
    // Signature order is part of the output contract: pair zero is k1 and pair one is k2.
    static const char* sig_strs[kFovKeyPairCount] = {
        "E8 ? ? ? ? 8B D8 E8 ? ? ? ? 31 44 24 ? 41 33 DE",
        "E8 ? ? ? ? 31 44 24 ? 41 33 DE",
    };
    // The shared buffer keeps four megabytes off the resolver thread's stack.
    static std::uint8_t buf[4 * 1024 * 1024];

    std::uint8_t hdr[0x400];
    if (!rd(base, hdr, sizeof(hdr))) {
        logf(log, lbuf, sizeof(lbuf), "keys: pe header read fail");
        return 0;
    }
    std::uint32_t peoff;
    std::memcpy(&peoff, hdr + 0x3C, 4);
    std::uint8_t pe[0x400];
    if (!rd(base + peoff, pe, sizeof(pe))) {
        logf(log, lbuf, sizeof(lbuf), "keys: pe read fail off=%x", peoff);
        return 0;
    }
    std::uint16_t nsec, optsz;
    std::memcpy(&nsec, pe + 6, 2);
    std::memcpy(&optsz, pe + 0x14, 2);
    const std::uintptr_t sec = base + peoff + 0x18 + optsz;
    logf(log, lbuf, sizeof(lbuf), "keys: %d sections base=%p", nsec, reinterpret_cast<void*>(base));

    int found = 0;
    for (int i = 0; i < kFovKeyPairCount && found < kFovKeyPairCount; ++i) {
        // Permit a caller to retain pairs from an earlier partial resolution attempt.
        if (out_pairs[i][0]) {
            ++found;
            continue;
        }

        std::uint8_t pat[64], mask[64];
        int plen = 0;
        const char* p = sig_strs[i];
        while (*p && plen < 64) {
            while (*p == ' ') {
                ++p;
            }
            if (!*p) {
                break;
            }
            if (p[0] == '?') {
                pat[plen] = 0;
                mask[plen] = 0;
                p += (p[1] == '?' ? 2 : 1);
            } else {
                const auto nib = [](char c) -> int {
                    if (c >= '0' && c <= '9') {
                        return c - '0';
                    }
                    if (c >= 'A' && c <= 'F') {
                        return c - 'A' + 10;
                    }
                    if (c >= 'a' && c <= 'f') {
                        return c - 'a' + 10;
                    }
                    return -1;
                };
                const int hi = nib(p[0]);
                const int lo = nib(p[1]);
                if (hi < 0 || lo < 0) {
                    break;
                }
                pat[plen] = static_cast<std::uint8_t>((hi << 4) | lo);
                mask[plen] = 1;
                p += 2;
            }
            ++plen;
        }
        if (plen < 4) {
            logf(log, lbuf, sizeof(lbuf), "sig%d: parse fail len=%d", i, plen);
            continue;
        }
        const int aoff = plen - 3;

        // Key signatures describe instructions, so non-executable sections cannot contain a hit.
        for (std::uint16_t s = 0; s < nsec && !out_pairs[i][0]; ++s) {
            std::uint8_t sh[0x28];
            if (!rd(sec + static_cast<std::uint64_t>(s) * 0x28, sh, sizeof(sh))) {
                continue;
            }
            std::uint32_t chars, va, vsz;
            std::memcpy(&chars, sh + 0x24, 4);
            std::memcpy(&va, sh + 0x0C, 4);
            std::memcpy(&vsz, sh + 0x08, 4);
            if (!(chars & 0x20000000u)) {
                continue;
            }
            const std::uintptr_t lo = base + va, hi = base + va + vsz;

            std::uint8_t tail[128];
            std::size_t tail_len = 0;
            std::uintptr_t cur = lo;
            std::uintptr_t hit = 0;
            while (cur < hi && !hit) {
                const std::size_t want =
                    static_cast<std::size_t>(hi - cur < sizeof(buf) ? hi - cur : sizeof(buf));
                const std::size_t start = tail_len < want ? tail_len : want;
                // The prior tail keeps a signature split across read windows visible.
                std::memcpy(buf, tail, tail_len);
                if (!rd(cur, buf + start, want - start)) {
                    logf(log,
                         lbuf,
                         sizeof(lbuf),
                         "sig%d: read fail @%p",
                         i,
                         reinterpret_cast<void*>(cur));
                    cur += want - start;
                    tail_len = 0;
                    continue;
                }
                const std::uintptr_t adj = cur - tail_len;
                const std::size_t total = start + (want - start);
                // The exact three-byte suffix rejects most positions before the masked comparison.
                for (std::size_t j = static_cast<std::size_t>(aoff); j + 3 <= total && !hit; ++j) {
                    if (std::memcmp(buf + j, pat + aoff, 3) != 0) {
                        continue;
                    }
                    if (j < static_cast<std::size_t>(aoff) || j + (plen - aoff) > total) {
                        continue;
                    }
                    const std::size_t m = j - aoff;
                    bool ok = true;
                    for (int k = 0; k < plen; ++k) {
                        if (mask[k] && buf[m + k] != pat[k]) {
                            ok = false;
                            break;
                        }
                    }
                    if (ok) {
                        hit = adj + m;
                    }
                }
                tail_len = static_cast<std::size_t>(plen - 1) < sizeof(tail)
                               ? static_cast<std::size_t>(plen - 1)
                               : sizeof(tail);
                std::memcpy(tail, buf + total - tail_len, tail_len);
                cur += want - start;
            }
            if (!hit) {
                logf(log, lbuf, sizeof(lbuf), "sig%d: section %d no match", i, s);
                continue;
            }
            logf(log,
                 lbuf,
                 sizeof(lbuf),
                 "sig%d: hit @%p (rva %x)",
                 i,
                 reinterpret_cast<void*>(hit),
                 static_cast<unsigned>(hit - base));

            std::uint32_t a = 0, b = 0;
            int jumps = 0, calls = 0;
            std::uintptr_t q = hit;
            // The bounds stop malformed code or a false signature from walking indefinitely.
            for (int step = 0; step < 256 && !(a && b); ++step) {
                std::uint8_t op;
                if (!rd(q, &op, 1)) {
                    logf(log,
                         lbuf,
                         sizeof(lbuf),
                         "sig%d: follow read fail @%p step %d",
                         i,
                         reinterpret_cast<void*>(q),
                         step);
                    break;
                }
                if (op == 0xE9 || op == 0xE8) {
                    std::int32_t disp;
                    if (!rd(q + 1, &disp, 4)) {
                        logf(log,
                             lbuf,
                             sizeof(lbuf),
                             "sig%d: follow disp read fail @%p",
                             i,
                             reinterpret_cast<void*>(q + 1));
                        break;
                    }
                    logf(log,
                         lbuf,
                         sizeof(lbuf),
                         "sig%d: follow %s @%x -> %x",
                         i,
                         op == 0xE9 ? "jmp" : "call",
                         static_cast<unsigned>(q - base),
                         static_cast<unsigned>(q + 5 + disp - base));
                    if (op == 0xE9 && ++jumps > 8) {
                        break;
                    }
                    if (op == 0xE8 && ++calls > 4) {
                        break;
                    }
                    q += 5 + disp;
                    continue;
                }
                if (op == 0xEB) {
                    std::int8_t disp;
                    if (!rd(q + 1, &disp, 1)) {
                        break;
                    }
                    if (++jumps > 8) {
                        break;
                    }
                    q += 2 + disp;
                    continue;
                }
                if (op == 0xC3) {
                    logf(log,
                         lbuf,
                         sizeof(lbuf),
                         "sig%d: follow ret @%x",
                         i,
                         static_cast<unsigned>(q - base));
                    break;
                }
                if (op == 0x8B || op == 0x33) {
                    std::uint8_t modrm;
                    if (!rd(q + 1, &modrm, 1)) {
                        break;
                    }
                    if (modrm == 0x05 || modrm == 0x0D || modrm == 0x1D || modrm == 0x15) {
                        std::int32_t disp;
                        if (!rd(q + 2, &disp, 4)) {
                            break;
                        }
                        // The pair stores RVAs so its values remain valid across image relocation.
                        const std::uintptr_t tgt = q + 6 + disp - base;
                        logf(log,
                             lbuf,
                             sizeof(lbuf),
                             "sig%d: follow %s @%x -> %x",
                             i,
                             op == 0x8B ? "mov" : "xor",
                             static_cast<unsigned>(q - base),
                             static_cast<unsigned>(tgt));
                        if (tgt > 0x10000 && tgt < 0x10000000
                            && static_cast<std::uint32_t>(tgt) != a) {
                            if (!a) {
                                a = static_cast<std::uint32_t>(tgt);
                            } else {
                                b = static_cast<std::uint32_t>(tgt);
                            }
                        }
                        logf(log,
                             lbuf,
                             sizeof(lbuf),
                             "sig%d: collect chk tgt=%x rangeok=%d neq=%d a=%x b=%x",
                             i,
                             static_cast<unsigned>(tgt),
                             (tgt > 0x10000 && tgt < 0x10000000) ? 1 : 0,
                             (static_cast<std::uint32_t>(tgt) != a) ? 1 : 0,
                             a,
                             b);
                        q += 6;
                        continue;
                    }
                }
                ++q;
            }
            if (a && b) {
                logf(log, lbuf, sizeof(lbuf), "sig%d: follow ok a=%x b=%x", i, a, b);
                out_pairs[i][0] = a;
                out_pairs[i][1] = b;
                ++found;
            } else {
                logf(log, lbuf, sizeof(lbuf), "sig%d: follow dead a=%x b=%x", i, a, b);
            }
        }
    }
    logf(log, lbuf, sizeof(lbuf), "keys: resolve done found=%d", found);
    return found;
}

/**
 * Resolves the encrypted display-settings global from its referencing instruction.
 * @param base Main executable image base.
 * @param rd Reader for image headers and executable sections.
 * @param out Receives the encrypted global's module-relative address.
 * @param log Optional diagnostic sink.
 * @return True when a matching global falls inside the expected image-data range.
 */
inline bool
fov_global_rva(std::uintptr_t base, read_fn rd, std::uint32_t& out, log_fn log) noexcept {
    char lbuf[192];
    // The RIP displacement begins at byte 11 and is relative to the instruction end at byte 15.
    static const char* sig = "74 24 10 57 48 83 EC 20 48 8B 1D ? ? ? ? 48 8B FA 48 8B F1 "
                             "48 85 DB 0F 84 ? ? ? ? 48 89 5C 24";

    std::uint8_t hdr[0x400];
    if (!rd(base, hdr, sizeof(hdr))) {
        logf(log, lbuf, sizeof(lbuf), "fovsig: pe header read fail");
        return false;
    }
    std::uint32_t peoff;
    std::memcpy(&peoff, hdr + 0x3C, 4);
    std::uint8_t pe[0x400];
    if (!rd(base + peoff, pe, sizeof(pe))) {
        logf(log, lbuf, sizeof(lbuf), "fovsig: pe read fail");
        return false;
    }
    std::uint16_t nsec, optsz;
    std::memcpy(&nsec, pe + 6, 2);
    std::memcpy(&optsz, pe + 0x14, 2);
    const std::uintptr_t sec = base + peoff + 0x18 + optsz;

    std::uint8_t pat[64], mask[64];
    int plen = 0;
    const char* p = sig;
    while (*p && plen < 64) {
        while (*p == ' ') {
            ++p;
        }
        if (!*p) {
            break;
        }
        if (p[0] == '?') {
            pat[plen] = 0;
            mask[plen] = 0;
            p += (p[1] == '?' ? 2 : 1);
        } else {
            const auto nib = [](char c) -> int {
                if (c >= '0' && c <= '9') {
                    return c - '0';
                }
                if (c >= 'A' && c <= 'F') {
                    return c - 'A' + 10;
                }
                if (c >= 'a' && c <= 'f') {
                    return c - 'a' + 10;
                }
                return -1;
            };
            const int hi = nib(p[0]);
            const int lo = nib(p[1]);
            if (hi < 0 || lo < 0) {
                break;
            }
            pat[plen] = static_cast<std::uint8_t>((hi << 4) | lo);
            mask[plen] = 1;
            p += 2;
        }
        ++plen;
    }
    if (plen < 4) {
        logf(log, lbuf, sizeof(lbuf), "fovsig: parse fail len=%d", plen);
        return false;
    }
    const int aoff = plen - 3;
    logf(log, lbuf, sizeof(lbuf), "fovsig: parsed len=%d, %d sections", plen, nsec);

    for (std::uint16_t s = 0; s < nsec; ++s) {
        std::uint8_t sh[0x28];
        if (!rd(sec + static_cast<std::uint64_t>(s) * 0x28, sh, sizeof(sh))) {
            continue;
        }
        std::uint32_t chars, va, vsz;
        std::memcpy(&chars, sh + 0x24, 4);
        std::memcpy(&va, sh + 0x0C, 4);
        std::memcpy(&vsz, sh + 0x08, 4);
        if (!(chars & 0x20000000u)) {
            continue;
        }
        const std::uintptr_t lo = base + va, hi = base + va + vsz;
        static std::uint8_t buf[4 * 1024 * 1024];
        std::uint8_t tail[128];
        std::size_t tail_len = 0;
        std::uintptr_t cur = lo;
        while (cur < hi) {
            const std::size_t want =
                static_cast<std::size_t>(hi - cur < sizeof(buf) ? hi - cur : sizeof(buf));
            const std::size_t start = tail_len < want ? tail_len : want;
            // The prior tail keeps a signature split across read windows visible.
            std::memcpy(buf, tail, tail_len);
            if (!rd(cur, buf + start, want - start)) {
                logf(
                    log, lbuf, sizeof(lbuf), "fovsig: read fail @%p", reinterpret_cast<void*>(cur));
                cur += want - start;
                tail_len = 0;
                continue;
            }
            const std::uintptr_t adj = cur - tail_len;
            const std::size_t total = start + (want - start);
            // The exact three-byte suffix rejects most positions before the masked comparison.
            for (std::size_t j = static_cast<std::size_t>(aoff); j + 3 <= total; ++j) {
                if (std::memcmp(buf + j, pat + aoff, 3) != 0) {
                    continue;
                }
                if (j < static_cast<std::size_t>(aoff) || j + (plen - aoff) > total) {
                    continue;
                }
                const std::size_t m = j - aoff;
                bool ok = true;
                for (int k = 0; k < plen; ++k) {
                    if (mask[k] && buf[m + k] != pat[k]) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    std::int32_t disp;
                    std::memcpy(&disp, buf + m + 11, 4);
                    const std::uintptr_t hit = adj + m;
                    out = static_cast<std::uint32_t>(hit + 15 + disp - base);
                    logf(log,
                         lbuf,
                         sizeof(lbuf),
                         "fovsig: hit @%p disp=%x -> rva %x",
                         reinterpret_cast<void*>(hit),
                         disp,
                         out);
                    // A signature collision cannot name a slot outside the known image-data range.
                    if (out < 0x2165000 || out >= 0x42A9000) {
                        logf(log, lbuf, sizeof(lbuf), "fovsig: implausible global %x", out);
                        out = 0;
                        continue;
                    }
                    return true;
                }
            }
            tail_len = static_cast<std::size_t>(plen - 1) < sizeof(tail)
                           ? static_cast<std::size_t>(plen - 1)
                           : sizeof(tail);
            std::memcpy(tail, buf + total - tail_len, tail_len);
            cur += want - start;
        }
        logf(log, lbuf, sizeof(lbuf), "fovsig: section %d no match", s);
    }
    logf(log, lbuf, sizeof(lbuf), "fovsig: all sections miss");
    return false;
}

} // namespace detail

} // namespace sunrise::client::hooks::fov
