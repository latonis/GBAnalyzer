package gameboy;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.mem.MemoryAccessException;

public class GameboyHelper {
	private static PluginTool tool = null;
	private static FlatProgramAPI api = null;
	private static boolean useNewLicenseeCode = false;
	
	private static LinkedHashMap<String, Integer> headerEntries = new LinkedHashMap<String, Integer>();
//	{{
//		put("Entry Point", 0x103);
//		put("Nintendo Logo", 0x133);
//		put("Title", 0x143);
////		put("Manufacturer Code", 0x142) 
////		put("New Licensee Code", 0x145); 
//		put("SGB Flag",0x146);
//		put("Cartridge Type", 0x147);
//		put("ROM Size", 0x148);
//		put("RAM Size", 0x149);
//		put("Destination Code", 0x014A);
//		put("Old Licensee Code", 0x14B);
//		put("Mask ROM Version", 0x14C);
//		put("Header Checksum", 0x14D);
//		put("Global Checksum", 0x14F);		
//	}};
	
	public static void init(PluginTool tool2, FlatProgramAPI api2) {
		// TODO Auto-generated method stub
		GameboyHelper.tool = tool2;
		GameboyHelper.api = api2;
	}
	
	private static void buildMap() {
		headerEntries.put("Entry Point", 0x103);
		headerEntries.put("Nintendo Logo", 0x133);
		headerEntries.put("Title", 0x143);
		
		try {
			if (api.getByte(api.toAddr(0x14B)) == 33) {
//				put("Manufacturer Code", 0x142) // need to determine if this is same case
				headerEntries.put("New Licensee Code", 0x145); 
			}
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		headerEntries.put("SGB Flag",0x146);
		headerEntries.put("Cartridge Type", 0x147);
		headerEntries.put("ROM Size", 0x148);
		headerEntries.put("RAM Size", 0x149);
		headerEntries.put("Destination Code", 0x014A);
		headerEntries.put("Old Licensee Code", 0x14B);
		headerEntries.put("Mask ROM Version", 0x14C);
		headerEntries.put("Header Checksum", 0x14D);
		headerEntries.put("Global Checksum", 0x14F);
	}
	
	public static String getProgName() {
		return api.getCurrentProgram().getDomainFile().getName();
	}
	
	public static void getHeader() {
		
		buildMap();
		
		Integer pointer = 0x100;
		try {
			for (Map.Entry<String, Integer> entry : headerEntries.entrySet()) {
				System.out.print(entry.getKey() + ": ");
				while (pointer <= entry.getValue()) {
					System.out.print(String.format("%02X ", api.getByte(api.toAddr(pointer))));
					pointer++;
				}
				System.out.println();
			}
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}