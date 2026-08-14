#pragma once

#include <cstdint>

namespace sunrise::client::fov {

/** FOV used when no valid persisted value exists. */
inline constexpr std::uint16_t kDefaultFov = 85;
/** Lowest FOV accepted by the game and settings file. */
inline constexpr std::uint16_t kMinimumFov = 55;
/** Highest FOV accepted by the game and settings file. */
inline constexpr std::uint16_t kMaximumFov = 157;

/** Complete persisted FOV configuration. */
struct Settings {
    /** Whether Sunrise owns the live game FOV. */
    bool enabled{false};
    /** Whole-number FOV written to the display-settings object. */
    std::uint16_t fov{kDefaultFov};
};

/** Resolves the configuration path and loads a saved FOV document when present. */
void initialize(void* module) noexcept;

/** Drops the active configuration and resolved file path. */
void shutdown() noexcept;

/** @return One lock-consistent copy of the active FOV configuration. */
[[nodiscard]] Settings get() noexcept;

/**
 * Persists and publishes one configuration as a single state change.
 * @param settings Candidate configuration.
 * @return True when the configuration is valid and its complete document reached disk.
 */
bool publish(const Settings& settings) noexcept;

} // namespace sunrise::client::fov
