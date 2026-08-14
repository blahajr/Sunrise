#pragma once

namespace sunrise::client::fov {

struct Settings;

} // namespace sunrise::client::fov

namespace sunrise::client::hooks::fov {

/** Applies the persisted FOV configuration to the current display-settings object. */
void apply() noexcept;

/**
 * Applies one FOV snapshot without changing the persisted configuration.
 * @param settings Configuration to apply.
 */
void apply(const ::sunrise::client::fov::Settings& settings) noexcept;

/** Restores the captured game FOV and clears every resolved runtime address. */
void shutdown() noexcept;

} // namespace sunrise::client::hooks::fov
