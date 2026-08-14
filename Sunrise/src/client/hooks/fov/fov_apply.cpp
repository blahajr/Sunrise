/**
 * FOV hook
 */

#include "fov_apply.h"

#include <Windows.h>

#include <array>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../fov/fov_settings_store.h"
#include "../../runtime/internal.h"

namespace sunrise::client::hooks::fov {
namespace {

/** Base address of the main game module*/
std::byte* g_moduleBase{nullptr};

/** Whether init succeeded. */
std::atomic_bool g_initialized{false};
constexpr std::uintptr_t kFovPointerOffset = 0x026BEC50;
constexpr std::uintptr_t kFovValueOffset = 0x63C;

std::atomic<float> g_lastFov{0.0F};
/** Last enabled state. */
std::atomic_bool g_lastEnabled{false};

/**
 * Checks whether game hook activation finished without blocking the render thread. Startup holds
 * this lock while waiting for presentation, so FOV must skip instead of waiting behind it.
 * @return True when the main client hook stage is active.
 */
[[nodiscard]] bool main_stage_active() noexcept {
    if (TryAcquireSRWLockShared(&runtime::g_lock) == FALSE) {
        return false;
    }
    const bool active = runtime::g_mainStage == runtime::StageState::active;
    ReleaseSRWLockShared(&runtime::g_lock);
    return active;
}

/** @param fov Field of view from the UI. @return Two-byte FOV value written to the game field. */
[[nodiscard]] std::uint16_t encoded_fov(float fov) noexcept {
    const float clamped = (std::clamp)(fov, client::fov::kMinimumFov, client::fov::kMaximumFov);
    return static_cast<std::uint16_t>(clamped + 0.5F);
}

/**
 * Writes the FOV value to the calculated address.
 * @param address Target memory address.
 * @param value Two-byte FOV value to write.
 * @return True when the write succeeded.
 */
[[nodiscard]] bool write_fov(std::byte* address, std::uint16_t value) noexcept {
    if (address == nullptr) {
        return false;
    }
    SIZE_T written = 0;
    return WriteProcessMemory(GetCurrentProcess(), address, &value, sizeof(value), &written)
               != FALSE
           && written == sizeof(value);
}

/**
 * Resolves the module-relative pointer path and writes the FOV value at the final field offset.
 * @param value Two-byte FOV value to write.
 * @return True when the path resolved and the write succeeded.
 */
[[nodiscard]] bool apply_fov(std::uint16_t value) noexcept {
    std::byte* base = nullptr;
    SIZE_T read = 0;
    if (ReadProcessMemory(GetCurrentProcess(),
                          g_moduleBase + kFovPointerOffset,
                          &base,
                          sizeof(base),
                          &read)
            == FALSE
        || read != sizeof(base) || base == nullptr) {
        return false;
    }
    return write_fov(base + kFovValueOffset, value);
}

/** Initializes the module base address */
void initialize() noexcept {
    if (g_initialized.load(std::memory_order_acquire)) {
        return;
    }
    g_moduleBase = reinterpret_cast<std::byte*>(GetModuleHandleW(L"destiny2.exe"));
    if (g_moduleBase == nullptr) {
        std::array<char, 96> line{};
        const int written = std::snprintf(
            line.data(), line.size(), "ev=fov stage=init result=fail reason=no_module");
        if (written > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::warn,
                             {line.data(), static_cast<std::size_t>(written)});
        }
        return;
    }
    g_initialized.store(true, std::memory_order_release);
}

} // namespace

/** Applies one FOV value to memory without persisting for slider. */
void apply(const ::sunrise::client::fov::Settings& settings) noexcept {
    if (!main_stage_active()) {
        return;
    }

    if (!g_initialized.load(std::memory_order_acquire)) {
        initialize();
        if (!g_initialized.load(std::memory_order_acquire)) {
            return;
        }
    }

    if (!settings.enabled) {
        g_lastEnabled.store(false, std::memory_order_relaxed);
        return;
    }

    const float lastFov = g_lastFov.load(std::memory_order_relaxed);
    const bool lastEnabled = g_lastEnabled.load(std::memory_order_relaxed);

    if (lastEnabled && settings.fov == lastFov) {
        return;
    }

    const std::uint16_t value = encoded_fov(settings.fov);
    if (apply_fov(value)) {
        g_lastFov.store(settings.fov, std::memory_order_relaxed);
        g_lastEnabled.store(settings.enabled, std::memory_order_relaxed);

        std::array<char, 128> line{};
        const int written = std::snprintf(
            line.data(),
            line.size(),
            "ev=fov stage=apply result=ok fov=%.1f",
            static_cast<double>(settings.fov));
        if (written > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
}

/** Applies the configed FOV. */
void apply() noexcept {
    apply(client::fov::get());
}

} // namespace sunrise::client::hooks::fov
