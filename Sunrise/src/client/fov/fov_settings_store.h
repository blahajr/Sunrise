#pragma once

namespace sunrise::client::fov {

inline constexpr float kDefaultFov = 75.0F;
inline constexpr float kMinimumFov = 55.0F;
inline constexpr float kMaximumFov = 150.0F;


struct Settings {
    bool enabled{false};
    float fov{kDefaultFov};
};

/**
 * Resolves the configuration file and loads it when one exists.
 * @param module Loaded DLL used to resolve the owned artifact directory.
 */
void initialize(void* module) noexcept;

/** Drops the runtime configuration and the file path. */
void shutdown() noexcept;

/** @return One lock-consistent copy of the current configuration. */
[[nodiscard]] Settings get() noexcept;

/**
 * Publishes one configuration and writes it.
 * @param settings Configuration to publish, refused when a field is out of range.
 * @return True when the value was published. A failed write is logged, not returned.
 */
bool publish(const Settings& settings) noexcept;

} // namespace sunrise::client::fov
