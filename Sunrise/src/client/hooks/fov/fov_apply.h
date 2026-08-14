#pragma once

namespace sunrise::client::fov {

struct Settings;

} // namespace sunrise::client::fov

namespace sunrise::client::hooks::fov {

/** Applies the config FOV to the player */
void apply() noexcept;

/**
 * Applies one FOV value to memory without reading the persistent.
 * @param settings Settings to apply.
 */
void apply(const ::sunrise::client::fov::Settings& settings) noexcept;

} // namespace sunrise::client::hooks::fov
