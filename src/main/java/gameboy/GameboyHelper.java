package gameboy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.mem.MemoryAccessException;

public class GameboyHelper {
	private static PluginTool tool = null;
	private static FlatProgramAPI api = null;
	
	public static LinkedHashMap<String, Integer> headerEntries = new LinkedHashMap<String, Integer>();
	public static int headerChecksum = 0;
	
	public static void init(PluginTool tool2, FlatProgramAPI api2) {
		// TODO Auto-generated method stub
		GameboyHelper.tool = tool2;
		GameboyHelper.api = api2;
		buildMap();
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
	
	public static int calcHeaderChecksum() {
		int checksum = 0;
		try {
			for (int addr = 0x134; addr <= 0x14C; addr++) {
				checksum = checksum - api.getByte(api.toAddr(addr)) - 1;
			}
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		headerChecksum = checksum & 0xFF;
		return headerChecksum;
	}
	
	public static byte getHeaderChecksum() {
		byte checksum = 0;
		
		try {
			checksum = api.getByte(api.toAddr(headerEntries.get("Header Checksum")));
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return checksum;
	}
	
	public static LinkedHashMap<String, byte[]> getHeader() {
		Integer pointer = 0x100;
		LinkedHashMap<String, byte[]> headerBytes = new LinkedHashMap<>();
		
		try {
			for (Map.Entry<String, Integer> entry : headerEntries.entrySet()) {
				ArrayList<Byte> curBytes = new ArrayList<Byte>();
				
				while (pointer <= entry.getValue()) {
					curBytes.add(api.getByte(api.toAddr(pointer)));
					pointer++;
				}
				
				headerBytes.put(entry.getKey(), ArrayUtils.toPrimitive(curBytes.toArray(new Byte[0])));
			}
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return headerBytes;
		
	}
}