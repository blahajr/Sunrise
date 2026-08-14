#include "client_ui_module_runtime.h"

#include <string_view>

#include "../../../core/ui/modules/registry/ui_module_registry.h"
#include "../../../core/ui/modules/ui_module_descriptor.h"
#include "../fov/fov_panel.h"
#include "../teleport/teleport_panel.h"

namespace sunrise::client::ui::runtime {
namespace {

/** Namespaced stable ID(s) prevents Client modules from colliding with Server modules. */
constexpr std::string_view kTeleportStableId = "client.teleport";
constexpr std::string_view kFovStableId = "client.fov";

/** Short menu label for the teleport page & fov */
constexpr std::string_view kTeleportDisplayName = "Teleport";
constexpr std::string_view kFovDisplayName = "FOV";

core::ui::modules::registry::PageRegistration g_teleportPage;
core::ui::modules::registry::PageRegistration g_fovPage;

} // namespace

/** @return True when the Client module owns its Core UI registry slot. */
bool initialize() noexcept {
    if (!g_teleportPage.acquire(core::ui::modules::Owner::client,
                                kTeleportStableId,
                                kTeleportDisplayName,
                                &teleport::draw)) {
        return false;
    }
    if (!g_fovPage.acquire(
            core::ui::modules::Owner::client, kFovStableId, kFovDisplayName, &fov::draw)) {
        g_teleportPage.release();
        return false;
    }
    return true;
}

/** Removes the Client module from the Core UI registry. */
void shutdown() noexcept {
    g_fovPage.release();
    g_teleportPage.release();
}

} // namespace sunrise::client::ui::runtime