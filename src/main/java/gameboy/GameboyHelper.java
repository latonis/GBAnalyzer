package gameboy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.MemoryAccessException;

public class GameboyHelper {
	private static PluginTool tool = null;
	private static FlatProgramAPI api = null;
	
	public static LinkedHashMap<String, Integer> headerEntries = new LinkedHashMap<String, Integer>();
	public static LinkedHashMap<Integer, String> ioEntries = new LinkedHashMap<Integer, String>();

	public static int headerChecksum = 0;
	
	public static void init(PluginTool tool_, FlatProgramAPI api_) {
		GameboyHelper.tool = tool_;
		GameboyHelper.api = api_;
		buildMap();
		setComments();
	}
	
	
	private static void setComments() {
		ioEntries.put(0xFF00, "P1/JOYP: Joypad");
		ioEntries.put(0xFF01, "SB: Serial transfer data");
		ioEntries.put(0xFF02, "SC: Serial transfer control");
		ioEntries.put(0xFF04, "DIV: Divider register");
		ioEntries.put(0xFF05, "TIMA: Timer counter");
		ioEntries.put(0xFF06, "TMA: Timer modulo");
		ioEntries.put(0xFF07, "TAC: Timer control");
		ioEntries.put(0xFF0F, "IF: Interrupt flag");
		ioEntries.put(0xFF10, "NR10: Sound channel 1 sweep");
		ioEntries.put(0xFF11, "NR11: Sound channel 1 length timer & duty cycle");
		ioEntries.put(0xFF12, "NR12: Sound channel 1 volume & envelope");
		ioEntries.put(0xFF13, "NR13: Sound channel 1 period low");
		ioEntries.put(0xFF14, "NR14: Sound channel 1 period high & control");
		ioEntries.put(0xFF16, "NR21: Sound channel 2 length timer & duty cycle");
		ioEntries.put(0xFF17, "NR22: Sound channel 2 volume & envelope");
		ioEntries.put(0xFF18, "NR23: Sound channel 2 period low");
		ioEntries.put(0xFF19, "NR24: Sound channel 2 period high & control");
		ioEntries.put(0xFF1A, "NR30: Sound channel 3 DAC enable");
		ioEntries.put(0xFF1B, "NR31: Sound channel 3 length timer");
		ioEntries.put(0xFF1C, "NR32: Sound channel 3 output level");
		ioEntries.put(0xFF1D, "NR33: Sound channel 3 period low");
		ioEntries.put(0xFF1E, "NR34: Sound channel 3 period high & control");
		ioEntries.put(0xFF20, "NR41: Sound channel 4 length timer");
		ioEntries.put(0xFF21, "NR42: Sound channel 4 volume & envelope");
		ioEntries.put(0xFF22, "NR43: Sound channel 4 frequency & randomness");
		ioEntries.put(0xFF23, "NR44: Sound channel 4 control");
		ioEntries.put(0xFF24, "NR50: Master volume & VIN panning");
		ioEntries.put(0xFF25, "NR51: Sound panning");
		ioEntries.put(0xFF26, "NR52: Sound on/off");
		ioEntries.put(0xFF30, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF31, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF32, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF33, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF34, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF35, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF36, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF37, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF38, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF39, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF3A, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF3B, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF3C, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF3D, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF3F, "Wave RAM: Storage for one of the sound channels’ waveform");
		ioEntries.put(0xFF40, "LCDC: LCD control");
		ioEntries.put(0xFF41, "STAT: LCD status");
		ioEntries.put(0xFF42, "SCY: Viewport Y position");
		ioEntries.put(0xFF43, "SCX: Viewport X position");
		ioEntries.put(0xFF44, "LY: LCD Y coordinate");
		ioEntries.put(0xFF45, "LYC: LY compare");
		ioEntries.put(0xFF46, "DMA: OAM DMA source address & start");
		ioEntries.put(0xFF47, "BGP: BG palette data");
		ioEntries.put(0xFF48, "OBP0: OBJ palette 0 data");
		ioEntries.put(0xFF49, "OBP1: OBJ palette 1 data");
		ioEntries.put(0xFF4A, "WY: Window Y position");
		ioEntries.put(0xFF4B, "WX: Window X position plus 7");
		ioEntries.put(0xFF4D, "KEY1: Prepare speed switch");
		ioEntries.put(0xFF4F, "VBK: VRAM bank");
		ioEntries.put(0xFF51, "HDMA1: VRAM DMA source high");
		ioEntries.put(0xFF52, "HDMA2: VRAM DMA source low");
		ioEntries.put(0xFF53, "HDMA3: VRAM DMA destination high");
		ioEntries.put(0xFF54, "HDMA4: VRAM DMA destination low");
		ioEntries.put(0xFF55, "HDMA5: VRAM DMA length/mode/start");
		ioEntries.put(0xFF56, "RP: Infrared communications port");
		ioEntries.put(0xFF68, "BCPS/BGPI: Background color palette specification / Background palette index");
		ioEntries.put(0xFF69, "BCPD/BGPD: Background color palette data / Background palette data");
		ioEntries.put(0xFF6A, "OCPS/OBPI: OBJ color palette specification / OBJ palette index");
		ioEntries.put(0xFF6B, "OCPD/OBPD: OBJ color palette data / OBJ palette data");
		ioEntries.put(0xFF6C, "OPRI: Object priority mode");
		ioEntries.put(0xFF70, "SVBK: WRAM bank");
		ioEntries.put(0xFF76, "PCM12: Audio digital outputs 1 & 2");
		ioEntries.put(0xFF77, "PCM34: Audio digital outputs 3 & 4");
		ioEntries.put(0xFFFF, "IE: Interrupt enable");
		
		
		var id = api.getCurrentProgram().startTransaction("Set line comment from Kernel");
		
		for (Map.Entry<Integer, String> entry: ioEntries.entrySet() ) {
			CodeUnit cu = api.getCurrentProgram().getListing().getCodeUnitContaining(api.toAddr(entry.getKey()));
			cu.setComment(CodeUnit.EOL_COMMENT, entry.getValue());
		}
		
		api.getCurrentProgram().endTransaction(id, true);	
	}
	
	private static void buildMap() {
		headerEntries.put("Entry Point", 0x103);
		headerEntries.put("Nintendo Logo", 0x133);
		headerEntries.put("Title", 0x143);
		
		try {
			if (api.getByte(api.toAddr(0x14B)) == 33) {
				headerEntries.put("Manufacturer Code", 0x142); // need to determine if this is same case
				headerEntries.put("New Licensee Code", 0x145); 
			}
		} catch (MemoryAccessException e) {
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
	
	public static String getPath() {
		return api.getCurrentProgram().getExecutablePath();
	}
	
	public static String getSHA256() {
		return api.getCurrentProgram().getExecutableSHA256();
	}
	
	public static String getMD5() {
		return api.getCurrentProgram().getExecutableMD5();
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
			e.printStackTrace();
		}
		
		return headerBytes;
		
	}
}