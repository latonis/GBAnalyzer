/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package gameboy;

//import java.awt.BorderLayout;
//
//import javax.swing.*;


import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Assist in the analysis of Game Boy games",
	description = "This plugin assists in reverse engineering Game Boy games by aiding in header analysis and more."
)
//@formatter:on
public class GameboyPlugin extends ProgramPlugin {

	GameboyProvider provider;
	FlatProgramAPI api;
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GameboyPlugin(PluginTool tool) {
		super(tool);

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new GameboyProvider(this, pluginName);
		
		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}
	
    @Override
    public void programActivated(Program program) {
		super.programActivated(program);
		
		api = new FlatProgramAPI(this.currentProgram);
		GameboyHelper.init(tool, api);
		
		System.out.println(api.getCurrentProgram().getImageBase());
        System.out.println(GameboyHelper.getProgName());
        GameboyHelper.getHeader();

    }
}
