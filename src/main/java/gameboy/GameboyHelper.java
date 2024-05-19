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
	private static LinkedHashMap<Integer, String> oldLicensees = new LinkedHashMap<Integer, String>();
	private static LinkedHashMap<String, String> newLicensees = new LinkedHashMap<String, String>();

	public static int headerChecksum = 0;

	public static void init(PluginTool tool_, FlatProgramAPI api_) {
		GameboyHelper.tool = tool_;
		GameboyHelper.api = api_;
		buildMap();
		setComments();
		buildLicensees();
	}

	private static void buildLicensees() {
		oldLicensees.put(0x00, "None");
		oldLicensees.put(0x01, "Nintendo");
		oldLicensees.put(0x08, "Capcom");
		oldLicensees.put(0x09, "HOT-B");
		oldLicensees.put(0x0A, "Jaleco");
		oldLicensees.put(0x0B, "Coconuts Japan");
		oldLicensees.put(0x0C, "Elite Systems");
		oldLicensees.put(0x13, "EA (Electronic Arts)");
		oldLicensees.put(0x18, "Hudson Soft");
		oldLicensees.put(0x19, "ITC Entertainment");
		oldLicensees.put(0x1A, "Yanoman");
		oldLicensees.put(0x1D, "Japan Clary");
		oldLicensees.put(0x1F, "Virgin Games Ltd.");
		oldLicensees.put(0x24, "PCM Complete");
		oldLicensees.put(0x25, "San-X");
		oldLicensees.put(0x28, "Kemco");
		oldLicensees.put(0x29, "SETA Corporation");
		oldLicensees.put(0x30, "Infogrames");
		oldLicensees.put(0x31, "Nintendo");
		oldLicensees.put(0x32, "Bandai");
		oldLicensees.put(0x33, "Indicates that the New licensee code should be used instead.");
		oldLicensees.put(0x34, "Konami");
		oldLicensees.put(0x35, "HectorSoft");
		oldLicensees.put(0x38, "Capcom");
		oldLicensees.put(0x39, "Banpresto");
		oldLicensees.put(0x3C, ".Entertainment i");
		oldLicensees.put(0x3E, "Gremlin");
		oldLicensees.put(0x41, "Ubi Soft");
		oldLicensees.put(0x42, "Atlus");
		oldLicensees.put(0x44, "Malibu Interactive");
		oldLicensees.put(0x46, "Angel");
		oldLicensees.put(0x47, "Spectrum Holoby");
		oldLicensees.put(0x49, "Irem");
		oldLicensees.put(0x4A, "Virgin Games Ltd.");
		oldLicensees.put(0x4D, "Malibu Interactive");
		oldLicensees.put(0x4F, "U.S. Gold");
		oldLicensees.put(0x50, "Absolute");
		oldLicensees.put(0x51, "Acclaim Entertainment");
		oldLicensees.put(0x52, "Activision");
		oldLicensees.put(0x53, "Sammy USA Corporation");
		oldLicensees.put(0x54, "GameTek");
		oldLicensees.put(0x55, "Park Place");
		oldLicensees.put(0x56, "LJN");
		oldLicensees.put(0x57, "Matchbox");
		oldLicensees.put(0x59, "Milton Bradley Company");
		oldLicensees.put(0x5A, "Mindscape");
		oldLicensees.put(0x5B, "Romstar");
		oldLicensees.put(0x5C, "Naxat Soft");
		oldLicensees.put(0x5D, "Tradewest");
		oldLicensees.put(0x60, "Titus Interactive");
		oldLicensees.put(0x61, "Virgin Games Ltd.");
		oldLicensees.put(0x67, "Ocean Software");
		oldLicensees.put(0x69, "EA (Electronic Arts)");
		oldLicensees.put(0x6E, "Elite Systems");
		oldLicensees.put(0x6F, "Electro Brain");
		oldLicensees.put(0x70, "Infogrames5");
		oldLicensees.put(0x71, "Interplay Entertainment");
		oldLicensees.put(0x72, "Broderbund");
		oldLicensees.put(0x73, "Sculptured Software6");
		oldLicensees.put(0x75, "The Sales Curve Limited7");
		oldLicensees.put(0x78, "THQ");
		oldLicensees.put(0x79, "Accolade");
		oldLicensees.put(0x7A, "Triffix Entertainment");
		oldLicensees.put(0x7C, "Microprose");
		oldLicensees.put(0x7F, "Kemco");
		oldLicensees.put(0x80, "Misawa Entertainment");
		oldLicensees.put(0x83, "Lozc");
		oldLicensees.put(0x86, "Tokuma Shoten");
		oldLicensees.put(0x8B, "Bullet-Proof Software2");
		oldLicensees.put(0x8C, "Vic Tokai");
		oldLicensees.put(0x8E, "Ape");
		oldLicensees.put(0x8F, "I’Max");
		oldLicensees.put(0x91, "Chunsoft Co.8");
		oldLicensees.put(0x92, "Video System");
		oldLicensees.put(0x93, "Tsubaraya Productions");
		oldLicensees.put(0x95, "Varie");
		oldLicensees.put(0x96, "Yonezawa/S’Pal");
		oldLicensees.put(0x97, "Kemco");
		oldLicensees.put(0x99, "Arc");
		oldLicensees.put(0x9A, "Nihon Bussan");
		oldLicensees.put(0x9B, "Tecmo");
		oldLicensees.put(0x9C, "Imagineer");
		oldLicensees.put(0x9D, "Banpresto");
		oldLicensees.put(0x9F, "Nova");
		oldLicensees.put(0xA1, "Hori Electric");
		oldLicensees.put(0xA2, "Bandai");
		oldLicensees.put(0xA4, "Konami");
		oldLicensees.put(0xA6, "Kawada");
		oldLicensees.put(0xA7, "Takara");
		oldLicensees.put(0xA9, "Technos Japan");
		oldLicensees.put(0xAA, "Broderbund");
		oldLicensees.put(0xAC, "Toei Animation");
		oldLicensees.put(0xAD, "Toho");
		oldLicensees.put(0xAF, "Namco");
		oldLicensees.put(0xB0, "Acclaim Entertainment");
		oldLicensees.put(0xB1, "ASCII Corporation or Nexsoft");
		oldLicensees.put(0xB2, "Bandai");
		oldLicensees.put(0xB4, "Square Enix");
		oldLicensees.put(0xB6, "HAL Laboratory");
		oldLicensees.put(0xB7, "SNK");
		oldLicensees.put(0xB9, "Pony Canyon");
		oldLicensees.put(0xBA, "Culture Brain");
		oldLicensees.put(0xBB, "Sunsoft");
		oldLicensees.put(0xBD, "Sony Imagesoft");
		oldLicensees.put(0xBF, "Sammy Corporation");
		oldLicensees.put(0xC0, "Taito");
		oldLicensees.put(0xC2, "Kemco");
		oldLicensees.put(0xC3, "Square");
		oldLicensees.put(0xC4, "Tokuma Shoten");
		oldLicensees.put(0xC5, "Data East");
		oldLicensees.put(0xC6, "Tonkinhouse");
		oldLicensees.put(0xC8, "Koei");
		oldLicensees.put(0xC9, "UFL");
		oldLicensees.put(0xCA, "Ultra");
		oldLicensees.put(0xCB, "Vap");
		oldLicensees.put(0xCC, "Use Corporation");
		oldLicensees.put(0xCD, "Meldac");
		oldLicensees.put(0xCE, "Pony Canyon");
		oldLicensees.put(0xCF, "Angel");
		oldLicensees.put(0xD0, "Taito");
		oldLicensees.put(0xD1, "Sofel");
		oldLicensees.put(0xD2, "Quest");
		oldLicensees.put(0xD3, "Sigma Enterprises");
		oldLicensees.put(0xD4, "ASK Kodansha Co.");
		oldLicensees.put(0xD6, "Naxat Soft");
		oldLicensees.put(0xD7, "Copya System");
		oldLicensees.put(0xD9, "Banpresto");
		oldLicensees.put(0xDA, "Tomy");
		oldLicensees.put(0xDB, "LJN");
		oldLicensees.put(0xDD, "NCS");
		oldLicensees.put(0xDE, "Human");
		oldLicensees.put(0xDF, "Altron");
		oldLicensees.put(0xE0, "Jaleco");
		oldLicensees.put(0xE1, "Towa Chiki");
		oldLicensees.put(0xE2, "Yutaka");
		oldLicensees.put(0xE3, "Varie");
		oldLicensees.put(0xE5, "Epcoh");
		oldLicensees.put(0xE7, "Athena");
		oldLicensees.put(0xE8, "Asmik Ace Entertainment");
		oldLicensees.put(0xE9, "Natsume");
		oldLicensees.put(0xEA, "King Records");
		oldLicensees.put(0xEB, "Atlus");
		oldLicensees.put(0xEC, "Epic/Sony Records");
		oldLicensees.put(0xEE, "IGS");
		oldLicensees.put(0xF0, "A Wave");
		oldLicensees.put(0xF3, "Extreme Entertainment");
		oldLicensees.put(0xFF, "LJN");

		newLicensees.put("00", "None");
		newLicensees.put("01", "Nintendo Research & Development 1");
		newLicensees.put("08", "Capcom");
		newLicensees.put("13", "EA (Electronic Arts)");
		newLicensees.put("18", "Hudson Soft");
		newLicensees.put("19", "B-AI");
		newLicensees.put("20", "KSS");
		newLicensees.put("22", "Planning Office WADA");
		newLicensees.put("24", "PCM Complete");
		newLicensees.put("25", "San-X");
		newLicensees.put("28", "Kemco");
		newLicensees.put("29", "SETA Corporation");
		newLicensees.put("30", "Viacom");
		newLicensees.put("31", "Nintendo");
		newLicensees.put("32", "Bandai");
		newLicensees.put("33", "Ocean Software/Acclaim Entertainment");
		newLicensees.put("34", "Konami");
		newLicensees.put("35", "HectorSoft");
		newLicensees.put("37", "Taito");
		newLicensees.put("38", "Hudson Soft");
		newLicensees.put("39", "Banpresto");
		newLicensees.put("41", "Ubi Soft");
		newLicensees.put("42", "Atlus");
		newLicensees.put("44", "Malibu Interactive");
		newLicensees.put("46", "Angel");
		newLicensees.put("47", "Bullet-Proof Software");
		newLicensees.put("49", "Irem");
		newLicensees.put("50", "Absolute");
		newLicensees.put("51", "Acclaim Entertainment");
		newLicensees.put("52", "Activision");
		newLicensees.put("53", "Sammy USA Corporation");
		newLicensees.put("54", "Konami");
		newLicensees.put("55", "Hi Tech Expressions");
		newLicensees.put("56", "LJN");
		newLicensees.put("57", "Matchbox");
		newLicensees.put("58", "Mattel");
		newLicensees.put("59", "Milton Bradley Company");
		newLicensees.put("60", "Titus Interactive");
		newLicensees.put("61", "Virgin Games Ltd.");
		newLicensees.put("64", "Lucasfilm Games");
		newLicensees.put("67", "Ocean Software");
		newLicensees.put("69", "EA (Electronic Arts)");
		newLicensees.put("70", "Infogrames");
		newLicensees.put("71", "Interplay Entertainment");
		newLicensees.put("72", "Broderbund");
		newLicensees.put("73", "Sculptured Software");
		newLicensees.put("75", "The Sales Curve Limited");
		newLicensees.put("78", "THQ");
		newLicensees.put("79", "Accolade");
		newLicensees.put("80", "Misawa Entertainment");
		newLicensees.put("83", "lozc");
		newLicensees.put("86", "Tokuma Shoten");
		newLicensees.put("87", "Tsukuda Original");
		newLicensees.put("91", "Chunsoft Co.");
		newLicensees.put("92", "Video System");
		newLicensees.put("93", "Ocean Software/Acclaim Entertainment");
		newLicensees.put("95", "Varie");
		newLicensees.put("96", "Yonezawa/s’pal");
		newLicensees.put("97", "Kaneko");
		newLicensees.put("99", "Pack-In-Video");
		newLicensees.put("9H", "Bottom Up");
		newLicensees.put("A4", "Konami (Yu-Gi-Oh!)");
		newLicensees.put("BL", "MTO");
		newLicensees.put("DK", "Kodansha");

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

		for (Map.Entry<Integer, String> entry : ioEntries.entrySet()) {
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

		headerEntries.put("SGB Flag", 0x146);
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

	public static String getLicensee() {
		try {
			int addr_val = api.getByte(api.toAddr(headerEntries.get("Old Licensee Code")));
			if (addr_val == 0x33) {
				String licenseeCode = String.format("%c%c", (char) api.getByte(api.toAddr(0x144)),
						(char) api.getByte(api.toAddr(0x145)));
				System.out.println(licenseeCode);
				return newLicensees.get(licenseeCode);
			}
			return oldLicensees.get(addr_val);
		} catch (MemoryAccessException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String getDestination() {
		try {
			if (api.getByte(api.toAddr(headerEntries.get("Destination Code"))) == 0) {
				return "Japan (and possibly overseas)";
			}
			return "Overseas only";
		} catch (MemoryAccessException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String getRomSize() {
//		32 KiB × (1 << <value>)
		try {
			int value = api.getByte(api.toAddr(headerEntries.get("ROM Size")));
			if (value < 5) {
				return String.format("%d KiB", (32000 * (1 << value)) / 1000);
			}
			return String.format("%d MiB", (32000 * (1 << value)) / (1024 * 1000));
		} catch (MemoryAccessException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static int calcHeaderChecksum() {
		int checksum = 0;
		try {
			for (int addr = 0x134; addr <= 0x14C; addr++) {
				checksum = checksum - api.getByte(api.toAddr(addr)) - 1;
			}
		} catch (MemoryAccessException e) {
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