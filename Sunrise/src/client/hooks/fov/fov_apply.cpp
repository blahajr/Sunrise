#include "fov_apply.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <thread>

#include "../../../core/logging/log.h"
#include "../../fov/fov_settings_store.h"
#include "../../runtime/internal.h"
#include "fov_resolver.h"

namespace sunrise::client::hooks::fov {
namespace {

/**
 * Known prefix of the game's display-settings object. Width and height validate the decrypted
 * owner before `fieldOfView` is read or written. Unmapped members retain their byte ranges so the
 * documented field offsets stay tied to the native layout.
 */
struct GameDisplaySettings {
    std::array<std::byte, 0x04> unknown00;
    std::uint32_t width;
    std::uint32_t height;
    std::array<std::byte, 0x10> unknown0C;
    std::uint16_t fieldOfView;
};

static_assert(offsetof(GameDisplaySettings, width) == 0x04);
static_assert(offsetof(GameDisplaySettings, height) == 0x08);
static_assert(offsetof(GameDisplaySettings, fieldOfView) == 0x1C);

/** Poll interval that keeps a game-side settings rewrite from replacing the persisted override. */
constexpr std::chrono::milliseconds kMaintainInterval{500};
/** Short wait slices let shutdown wake the maintenance loop promptly. */
constexpr std::chrono::milliseconds kWorkerWaitSlice{100};
/** Resolver retry interval while the game is still publishing its executable state. */
constexpr std::chrono::milliseconds kResolveRetryInterval{2000};
/** Number of delayed resolver attempts after the first pass. */
constexpr int kResolveRetryCount = 30;

/** Main executable image used as the base for every resolved RVA. */
std::byte* g_moduleBase{nullptr};
/** Serializes capture, enforcement and restoration across UI and maintenance calls. */
SRWLOCK g_applyLock{SRWLOCK_INIT};
/** True after both decryption keys and the encrypted global slot resolve. */
std::atomic_bool g_initialized{false};
/** Key-source RVA pairs in resolver signature order. */
std::uint32_t g_keyPairs[detail::kFovKeyPairCount][2]{};
/** Encrypted display-settings slot relative to the main image. */
std::uint32_t g_fovGlobalRva{0};
/** Game-owned FOV captured before the first override. */
std::atomic<std::uint16_t> g_originalFov{0};
/** Display-settings object that owns `g_originalFov`. */
std::atomic<GameDisplaySettings*> g_originalOwner{nullptr};
/** True after `g_originalFov` holds a plausible game value. */
std::atomic_bool g_haveOriginal{false};
/** Last FOV value successfully written by Sunrise. */
std::atomic<std::uint16_t> g_lastFov{0};
/** Whether the last applied configuration owned the live FOV. */
std::atomic_bool g_lastEnabled{false};
/** Most recent requested FOV, including an in-progress UI drag. */
std::atomic<std::uint16_t> g_requestedFov{client::fov::kDefaultFov};
/** Most recent requested ownership state. */
std::atomic_bool g_requestedEnabled{false};
/** Requests the resolver and maintenance worker to leave. */
std::atomic_bool g_stopRequested{false};
/** Joinable owner of asynchronous resolution and maintenance. */
std::thread g_worker;

/** @param reason Key naming the apply step that failed. */
void report_fail(const char* reason) noexcept {
    std::array<char, 96> line{};
    const int written =
        std::snprintf(line.data(), line.size(), "ev=fov stage=apply result=fail reason=%s", reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** @return True when the main Client hook stage currently accepts feature work. */
[[nodiscard]] bool main_stage_active() noexcept {
    if (TryAcquireSRWLockShared(&runtime::g_lock) == FALSE) {
        return false;
    }
    const bool active = runtime::g_mainStage == runtime::StageState::active;
    ReleaseSRWLockShared(&runtime::g_lock);
    return active;
}

/** Reads the native two-byte FOV field from one validated settings object. */
[[nodiscard]] bool read_fov(GameDisplaySettings* settings, std::uint16_t& value) noexcept {
    if (settings == nullptr) {
        return false;
    }
    const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(settings)
                                   + offsetof(GameDisplaySettings, fieldOfView);
    return detail::scan_read(address, &value, sizeof(value));
}

/** Writes the native two-byte FOV field in one validated settings object. */
[[nodiscard]] bool write_fov(GameDisplaySettings* settings, std::uint16_t value) noexcept {
    if (settings == nullptr) {
        return false;
    }
    SIZE_T written = 0;
    return WriteProcessMemory(GetCurrentProcess(),
                              &settings->fieldOfView,
                              &value,
                              sizeof(value),
                              &written)
               != FALSE
           && written == sizeof(value);
}

/**
 * Reads and combines one resolver pair into a pointer-decryption key.
 * @param idx Pair index.
 * @param out Receives the XOR of both source values.
 * @return True after the key is read.
 */
[[nodiscard]] bool key_value(int idx, std::uint32_t& out) noexcept {
    if (idx < 0 || idx >= 2 || g_moduleBase == nullptr || g_keyPairs[idx][0] == 0
        || g_keyPairs[idx][1] == 0) {
        return false;
    }
    std::uint32_t first = 0;
    std::uint32_t second = 0;
    if (!detail::scan_read(reinterpret_cast<std::uintptr_t>(g_moduleBase) + g_keyPairs[idx][0],
                           &first,
                           sizeof(first))
        || !detail::scan_read(reinterpret_cast<std::uintptr_t>(g_moduleBase) + g_keyPairs[idx][1],
                              &second,
                              sizeof(second))) {
        return false;
    }
    out = first ^ second;
    return true;
}

/** @param stored Encrypted pointer bits. @return Decrypted pointer bits, or zero on failure. */
[[nodiscard]] std::uint64_t decrypt_ptr(std::uint64_t stored) noexcept {
    if (!stored) {
        return 0;
    }
    std::uint32_t k1 = 0, k2 = 0;
    if (!key_value(0, k1) || !key_value(1, k2) || !k1 || !k2) {
        return 0;
    }
    const std::uint64_t key64 =
        static_cast<std::uint64_t>(k1) | (static_cast<std::uint64_t>(k2) << 32);
    const std::uint64_t v1 = stored ^ key64;
    const std::uint32_t a = static_cast<std::uint32_t>(v1 >> 32);
    const std::uint32_t b = static_cast<std::uint32_t>(v1);
    return (static_cast<std::uint64_t>(a ^ 0x09465C5Cu) << 32) | (a ^ b ^ 0x267949FFu);
}

/** @return Validated display-settings object, or null before the object is usable. */
[[nodiscard]] GameDisplaySettings* settings_base() noexcept {
    if (g_moduleBase == nullptr || g_fovGlobalRva == 0) {
        return nullptr;
    }
    std::uint64_t stored = 0;
    if (!detail::scan_read(reinterpret_cast<std::uintptr_t>(g_moduleBase) + g_fovGlobalRva,
                           &stored,
                           sizeof(stored))
        || stored == 0) {
        return nullptr;
    }
    const std::uint64_t ptr = decrypt_ptr(stored);
    if (ptr < 0x100000000 || ptr >= 0x800000000000) {
        return nullptr;
    }
    auto* settings = reinterpret_cast<GameDisplaySettings*>(ptr);
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    const bool widthRead =
        detail::scan_read(ptr + offsetof(GameDisplaySettings, width), &width, sizeof(width));
    const bool heightRead =
        detail::scan_read(ptr + offsetof(GameDisplaySettings, height), &height, sizeof(height));
    if (!widthRead || !heightRead) {
        return nullptr;
    }
    if (width < 640 || width > 7680 || height < 480 || height > 4320) {
        return nullptr;
    }
    return settings;
}

/**
 * Captures the current object's game-owned value and enforces one FOV override.
 * @param value FOV value to apply.
 * @param written Set when game memory changed.
 * @return True when a valid settings object accepted the write.
 */
[[nodiscard]] bool apply_fov(std::uint16_t value, bool& written) noexcept {
    written = false;
    GameDisplaySettings* const settings = settings_base();
    if (settings == nullptr) {
        report_fail("settings");
        return false;
    }
    std::uint16_t current = 0;
    if (!read_fov(settings, current)) {
        report_fail("read");
        return false;
    }
    if (!g_haveOriginal.load(std::memory_order_acquire)
        || g_originalOwner.load(std::memory_order_relaxed) != settings) {
        if (current < client::fov::kMinimumFov || current > 170) {
            report_fail("original_range");
            return false;
        }
        g_originalFov.store(current, std::memory_order_relaxed);
        g_originalOwner.store(settings, std::memory_order_relaxed);
        g_haveOriginal.store(true, std::memory_order_release);
    }
    if (current == value) {
        return true;
    }
    if (!write_fov(settings, value)) {
        report_fail("write");
        return false;
    }
    written = true;
    return true;
}

/** One-way latch preventing more than one resolver thread. */
std::atomic_bool g_resolve_started{false};

/** Forwards resolver diagnostics to the Client log. */
void resolver_log(const char* line) {
    core::log::write(core::log::Channel::client, core::log::Level::info, line);
}

/** @return True when both key pairs and the encrypted display-settings slot resolve. */
bool resolve_now() noexcept {
    core::log::write(
        core::log::Channel::client, core::log::Level::info, "ev=fov stage=resolve result=start");
    if (detail::key_resolve(reinterpret_cast<std::uintptr_t>(g_moduleBase),
                            detail::scan_read,
                            g_keyPairs,
                            &resolver_log)
        < 2) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=fov stage=init result=fail reason=key_sig");
        return false;
    }
    if (!detail::fov_global_rva(reinterpret_cast<std::uintptr_t>(g_moduleBase),
                                detail::scan_read,
                                g_fovGlobalRva,
                                &resolver_log)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=fov stage=init result=fail reason=fov_sig");
        return false;
    }
    g_initialized.store(true, std::memory_order_release);
    core::log::write(
        core::log::Channel::client, core::log::Level::info, "ev=fov stage=resolve result=ok");
    return true;
}

/** Starts asynchronous address resolution once the Client hook stage becomes active. */
void initialize() noexcept {
    if (g_initialized.load(std::memory_order_acquire)
        || g_resolve_started.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    g_moduleBase = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (g_moduleBase == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=fov stage=init result=fail reason=no_module");
        return;
    }
    g_stopRequested.store(false, std::memory_order_release);
    g_worker = std::thread([] {
        // Startup owns the runtime lock while hooks attach, so the worker waits without
        // blocking it.
        while (!g_stopRequested.load(std::memory_order_acquire) && !main_stage_active()) {
            std::this_thread::sleep_for(kWorkerWaitSlice);
        }
        if (g_stopRequested.load(std::memory_order_acquire)) {
            return;
        }
        bool resolved = resolve_now();
        for (int retry = 0; retry < kResolveRetryCount && !resolved
                            && !g_stopRequested.load(std::memory_order_acquire);
             ++retry) {
            std::this_thread::sleep_for(kResolveRetryInterval);
            if (!g_stopRequested.load(std::memory_order_acquire)) {
                resolved = resolve_now();
            }
        }
        while (resolved && !g_stopRequested.load(std::memory_order_acquire)) {
            ::sunrise::client::fov::Settings requested{};
            requested.enabled = g_requestedEnabled.load(std::memory_order_acquire);
            requested.fov = g_requestedFov.load(std::memory_order_relaxed);
            apply(requested);
            for (auto waited = std::chrono::milliseconds::zero();
                 waited < kMaintainInterval && !g_stopRequested.load(std::memory_order_acquire);
                 waited += kWorkerWaitSlice) {
                std::this_thread::sleep_for(kWorkerWaitSlice);
            }
        }
    });
}

/** @return True when the captured game-owned FOV is restored or belongs to an expired object. */
[[nodiscard]] bool restore_original() noexcept {
    if (!g_haveOriginal.load(std::memory_order_acquire)) {
        report_fail("original_missing");
        return false;
    }
    GameDisplaySettings* const settings = settings_base();
    if (settings == nullptr) {
        report_fail("restore_settings");
        return false;
    }
    if (g_originalOwner.load(std::memory_order_relaxed) != settings) {
        // A replacement object has not received our override, so it owns its current FOV already.
        g_originalOwner.store(nullptr, std::memory_order_relaxed);
        g_haveOriginal.store(false, std::memory_order_release);
        return true;
    }
    const std::uint16_t original = g_originalFov.load(std::memory_order_relaxed);
    std::uint16_t current = 0;
    if (!read_fov(settings, current)) {
        report_fail("restore_read");
        return false;
    }
    if (current != original && !write_fov(settings, original)) {
        report_fail("restore_write");
        return false;
    }
    g_lastFov.store(original, std::memory_order_relaxed);
    g_originalOwner.store(nullptr, std::memory_order_relaxed);
    g_haveOriginal.store(false, std::memory_order_release);
    return true;
}

} // namespace

/** Applies one FOV snapshot without changing the persisted configuration. */
void apply(const ::sunrise::client::fov::Settings& settings) noexcept {
    if (settings.fov < client::fov::kMinimumFov
        || settings.fov > client::fov::kMaximumFov) {
        report_fail("range");
        return;
    }
    g_requestedFov.store(settings.fov, std::memory_order_relaxed);
    g_requestedEnabled.store(settings.enabled, std::memory_order_release);

    if (!main_stage_active()) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=fov stage=apply result=skip reason=stage_inactive");
        return;
    }

    initialize();

    if (!g_initialized.load(std::memory_order_acquire)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         "ev=fov stage=apply result=skip reason=not_ready");
        return;
    }

    AcquireSRWLockExclusive(&g_applyLock);
    if (!settings.enabled) {
        // The enabled-to-disabled edge hands the field back to the value captured from the game.
        if ((g_lastEnabled.load(std::memory_order_relaxed)
            || g_haveOriginal.load(std::memory_order_acquire))
            && !restore_original()) {
            ReleaseSRWLockExclusive(&g_applyLock);
            return;
        }
        g_lastEnabled.store(false, std::memory_order_relaxed);
        ReleaseSRWLockExclusive(&g_applyLock);
        return;
    }

    const std::uint16_t value = settings.fov;
    bool written = false;
    if (apply_fov(value, written)) {
        g_lastFov.store(value, std::memory_order_relaxed);
        g_lastEnabled.store(true, std::memory_order_relaxed);

        if (written) {
            std::array<char, 128> line{};
            const int formatted = std::snprintf(line.data(),
                                                line.size(),
                                                "ev=fov stage=apply result=ok fov=%u",
                                                static_cast<unsigned>(value));
            if (formatted > 0) {
                core::log::write(core::log::Channel::client,
                                 core::log::Level::info,
                                 {line.data(), static_cast<std::size_t>(formatted)});
            }
        }
        ReleaseSRWLockExclusive(&g_applyLock);
        return;
    }
    ReleaseSRWLockExclusive(&g_applyLock);
}

/** Applies the current persisted FOV configuration. */
void apply() noexcept {
    apply(client::fov::get());
}

/** Restores the game-owned value and clears every process-local resolver result. */
void shutdown() noexcept {
    g_stopRequested.store(true, std::memory_order_release);
    if (g_worker.joinable()) {
        g_worker.join();
    }
    AcquireSRWLockExclusive(&g_applyLock);
    if (g_lastEnabled.load(std::memory_order_relaxed)) {
        (void)restore_original();
    }
    g_initialized.store(false, std::memory_order_release);
    g_resolve_started.store(false, std::memory_order_release);
    g_lastEnabled.store(false, std::memory_order_relaxed);
    g_lastFov.store(0, std::memory_order_relaxed);
    g_requestedFov.store(client::fov::kDefaultFov, std::memory_order_relaxed);
    g_requestedEnabled.store(false, std::memory_order_release);
    g_originalFov.store(0, std::memory_order_relaxed);
    g_originalOwner.store(nullptr, std::memory_order_relaxed);
    g_haveOriginal.store(false, std::memory_order_release);
    g_fovGlobalRva = 0;
    g_keyPairs[0][0] = g_keyPairs[0][1] = 0;
    g_keyPairs[1][0] = g_keyPairs[1][1] = 0;
    g_moduleBase = nullptr;
    ReleaseSRWLockExclusive(&g_applyLock);
}

} // namespace sunrise::client::hooks::fov
