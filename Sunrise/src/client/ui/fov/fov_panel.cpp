/**
 * FOV module interface.
 */

#include "fov_panel.h"

#include <imgui.h>

#include "../../../core/ui/components/toggle/ui_toggle_component.h"
#include "../../fov/fov_settings_store.h"
#include "../../hooks/fov/fov_apply.h"

namespace sunrise::client::ui::fov {
namespace {

/** True while the slider owns an unpublished draft value. */
bool g_draggingFov{};
/** Live slider value, persisted only when editing finishes. */
std::uint16_t g_draftFov{client::fov::kDefaultFov};

} // namespace

/** Draws the FOV module into the current Dear ImGui panel. */
void draw() noexcept {
    client::fov::Settings settings = client::fov::get();
    bool applyNow = false;
    bool persistNow = false;

    ImGui::TextUnformatted("Field of View");
    ImGui::Spacing();
    ImGui::TextWrapped("Sets the player field of view.");
    ImGui::Spacing();

    if (core::ui::components::toggle::control("Enabled", settings.enabled)) {
        applyNow = true;
        persistNow = true;
    }

    ImGui::Spacing();
    const float labelWidth = ImGui::CalcTextSize("FOV").x + ImGui::GetStyle().ItemSpacing.x * 2;
    const float controlWidth = ImGui::GetContentRegionAvail().x - labelWidth;

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("FOV");
    ImGui::SameLine(labelWidth);
    ImGui::SetNextItemWidth(controlWidth);

    if (!g_draggingFov) {
        g_draftFov = settings.fov;
    }
    int value = g_draftFov;
    if (ImGui::SliderInt("##fov", &value, client::fov::kMinimumFov, client::fov::kMaximumFov)) {
        g_draggingFov = true;
        g_draftFov = static_cast<std::uint16_t>(value);
        settings.fov = g_draftFov;
        applyNow = true;
    }
    if (ImGui::IsItemDeactivatedAfterEdit()) {
        g_draggingFov = false;
        settings.fov = g_draftFov;
        persistNow = true;
    }

    // Slider movement applies immediately, but only the final released value reaches disk.
    if (persistNow && !client::fov::publish(settings)) {
        // A failed commit returns the maintenance path to the last durable snapshot.
        client::hooks::fov::apply(client::fov::get());
        ImGui::Spacing();
        ImGui::TextUnformatted("failed to save settings");
        return;
    }
    if (applyNow) {
        client::hooks::fov::apply(settings);
    }
}

} // namespace sunrise::client::ui::fov
