package gameboy;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

import org.kordamp.ikonli.evaicons.Evaicons;
import org.kordamp.ikonli.swing.FontIcon;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import java.awt.FlowLayout;

class SimpleNumberLinePanel extends JPanel {

	private static final int PREF_W = 800;
	private static final int PREF_H = 300;
	private static final int GAP = 10;
	private static final int START = 256;
	private static final int END = 335; // 4F
	private static final int VERT_LINE_HEIGHT = 20;
	private static final Font FONT = new Font(Font.MONOSPACED, Font.BOLD, 14);
	private static final int TEXT_GAP = 2;

	private static Map<String, Integer> headerEntries = Map.of(

	);

	@Override
	protected void paintComponent(Graphics g) {
		// call super method
		super.paintComponent(g);

		int width = getWidth();
		int height = getHeight();

		// initialize these guys each time paintComponent is called
		int x1 = GAP;
		int y1 = height / 2;
		int x2 = width - 2 * GAP;
		int y2 = y1;
		g.drawLine(x1, y1, x2, y2);

		for (int i = START; i < END; i++) {
			int x = (i * (x2 - x1)) / (END - START) + GAP;
			drawNumberAndLine(g, i, x, y1, VERT_LINE_HEIGHT);
		}
	}

	private void drawNumberAndLine(Graphics g, int number, int x, int y, int vertLineHeight) {
		int x1 = x;
		int y1 = y;
		int x2 = x;
		int y2 = y - vertLineHeight;
		g.drawLine(x1, y1, x2, y2);

		String text = String.valueOf(number);
		g.setFont(FONT);
		FontMetrics fontMetrics = g.getFontMetrics();
		int textX = x - fontMetrics.stringWidth(text) / 2;
		int textY = y + fontMetrics.getHeight() + TEXT_GAP;
		g.drawString(text, textX, textY);
	}

	@Override // make GUI bigger
	public Dimension getPreferredSize() {
		if (isPreferredSizeSet()) {
			return super.getPreferredSize();
		}
		return new Dimension(PREF_W, PREF_H);
	}
}

public class GameboyProvider extends ComponentProvider {
	private final static HelpLocation HELP = new HelpLocation("GameBoyHelp", "HELPME");
	private JPanel panel;
	private final PluginTool tool;

	public GameboyProvider(GameboyPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.tool = plugin.getTool();
		buildPanel();
		setHelpLocation(HELP);
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setTitle("Game Boy Game Analysis");
		setVisible(true);
		createActions();
	}
	
	public void addDetailsPanel() {		
		JLabel lblFile = new JLabel("File:");
		lblFile.setBounds(12, 24, 70, 15);
		panel.add(lblFile);
		
		JLabel lblFileName = new JLabel(GameboyHelper.getProgName());
		lblFileName.setBounds(94, 24, 70, 15);
		panel.add(lblFileName);
		
		emptyLine();
		
		JLabel lblPath = new JLabel("File Path:");
		lblPath.setBounds(12, 24, 70, 15);
		panel.add(lblPath);
		
		JLabel lblPathName = new JLabel(GameboyHelper.getPath());
		lblPathName.setBounds(94, 24, 70, 15);
		panel.add(lblPathName);
		
		emptyLine();
		
		JLabel lblSHA256 = new JLabel("SHA256:");
		lblSHA256.setBounds(12, 24, 70, 15);
		panel.add(lblSHA256);

		JLabel lblSHA256Value = new JLabel(GameboyHelper.getSHA256());
		lblSHA256Value.setBounds(94, 24, 70, 15);
		panel.add(lblSHA256Value);
		
		emptyLine();

		JLabel lblMD5 = new JLabel("MD5:");
		lblMD5.setBounds(12, 24, 70, 15);
		panel.add(lblMD5);

		JLabel lblMD5Value = new JLabel(GameboyHelper.getMD5());
		lblMD5Value.setBounds(94, 24, 70, 15);
		panel.add(lblMD5Value);
		
		emptyLine();
//
//		JTextArea textArea = new JTextArea(5, 25);
//		textArea.setEditable(false);
	}

	private void emptyLine() {
		JLabel empty_line = new JLabel("");   // <--- empty label to effect next row
		empty_line.setPreferredSize(new Dimension(3000,0));
		panel.add(empty_line);
	}
	
	// Customize GUI
	private void buildPanel() {
		panel = new JPanel();
		panel.setPreferredSize(new Dimension(250, 200));
		setVisible(true);
	}

	// TODO: Customize actions
	private void createActions() {
		DockingAction parseHeaderAction = new DockingAction("Parse Header", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				LinkedHashMap<String, byte[]> entries = GameboyHelper.getHeader();

				for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
					System.out.print(entry.getKey() + ": ");
					for (byte a : entry.getValue()) {
						System.out.print(String.format("%02X ", a));
					}
					System.out.println();
				}
				tool.showDialog(new HeaderDialog("Gameboy Header Information"));
			}
		};

		parseHeaderAction.setToolBarData(new ToolBarData(FontIcon.of(Evaicons.FILE_TEXT), null));
		parseHeaderAction.setEnabled(true);
		parseHeaderAction.markHelpUnnecessary();
		parseHeaderAction.setHelpLocation(HELP);
		dockingTool.addLocalAction(this, parseHeaderAction);

		DockingAction checksumAction = new DockingAction("Calculate and Verify Checksums", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				int checksum = GameboyHelper.calcHeaderChecksum();
				System.out.println("Calculated Checksum: " + checksum);
				System.out.println("Given Checksum: " + Byte.toUnsignedInt(GameboyHelper.getHeaderChecksum()));
				System.out.println(
						"Checksum Valid? - " + (checksum == Byte.toUnsignedInt(GameboyHelper.getHeaderChecksum())));
				tool.showDialog(new ChecksumDialog("Gameboy Checksum Information"));
			}
		};

		checksumAction.setToolBarData(new ToolBarData(FontIcon.of(Evaicons.HASH), null));
		checksumAction.setEnabled(true);
		checksumAction.markHelpUnnecessary();
		checksumAction.setHelpLocation(HELP);
		dockingTool.addLocalAction(this, checksumAction);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}