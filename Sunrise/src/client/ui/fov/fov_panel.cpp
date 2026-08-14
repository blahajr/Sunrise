/**
 * fov module interface
 */

#include "fov_panel.h"

#include <imgui.h>

#include "../../../core/ui/components/toggle/ui_toggle_component.h"
#include "../../fov/fov_settings_store.h"
#include "../../hooks/fov/fov_apply.h"

namespace sunrise::client::ui::fov {
namespace {

bool g_draggingFov{};
float g_draftFov{client::fov::kDefaultFov};

} // namespace

void draw() noexcept {
    client::fov::Settings settings = client::fov::get();
    bool applyNow = false;
    bool persistNow = false;

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
    float value = g_draftFov;
    if (ImGui::SliderFloat(
            "##fov", &value, client::fov::kMinimumFov, client::fov::kMaximumFov, "%.0f")) {
        g_draggingFov = true;
        g_draftFov = value;
        settings.fov = value;
        applyNow = true;
    }
    if (ImGui::IsItemDeactivatedAfterEdit()) {
        g_draggingFov = false;
        settings.fov = g_draftFov;
        persistNow = true;
    }

    if (persistNow && !client::fov::publish(settings)) {
        ImGui::Spacing();
        ImGui::TextUnformatted("value is out of range D:");
        return;
    }
    if (applyNow) {
        client::hooks::fov::apply(settings);
    }
}

} // namespace sunrise::client::ui::fov
