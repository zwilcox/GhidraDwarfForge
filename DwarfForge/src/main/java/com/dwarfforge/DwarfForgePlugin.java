package com.zwilcox.dwarfforge;

import com.sun.jna.ptr.LongByReference;
import docking.action.*;
import docking.widgets.dialogs.MessageDialog;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.PluginInfo;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

/**
 * Simple demo plugin showing a call into native libdwarf via {@link LibdwarfLibrary}.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "DwarfForge",
    category = PluginCategoryNames.COMMON,
    shortDescription = "DWARF Forge demo",
    description = "Shows that libdwarf can be called from Java inside Ghidra."
)
public class DwarfForgePlugin extends Plugin {

    private DockingAction demoAction;

    public DwarfForgePlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    private void createActions() {
        demoAction = new DockingAction("DwarfForge: libdwarf version", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                // Example: call libdwarf to get its package version symbol
                String version = LibdwarfLibrary.cString(
                        LibdwarfLibrary.INSTANCE.dwarf_errmsg(null)); // returns static string
                MessageDialog.showInfoDialog(tool.getActiveWindow(),
                        "libdwarf says:", "libdwarf version: " + version);
            }
        };

        demoAction.setMenuBarData(
            new MenuData(new String[] { "Tools", "DwarfForge", "libdwarf Version" }, null, "dwarfforge"));
        demoAction.setHelpLocation(new HelpLocation(getName(), "DwarfForge"));
        tool.addAction(demoAction);
    }

    @Override
    protected void dispose() {
        tool.removeAction(demoAction);
    }
}
