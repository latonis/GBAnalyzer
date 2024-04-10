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

   private void drawNumberAndLine(Graphics g, int number, int x, int y,
         int vertLineHeight) {
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

//   private static void createAndShowGui() {
//      frame.getContentPane().add();
//      frame.pack();
//      frame.setLocationRelativeTo(null);
//      frame.setVisible(true);
//   }
}

public class GameboyProvider extends ComponentProvider {
    private final static HelpLocation HELP =
            new HelpLocation("GameBoyHelp", "HELPME");
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
    
    private Object[][] buildTable(String[] columns) {
    	Object[][] data = new Object[2][columns.length];
   
    	for (int x = 0; x < data.length; x++) {
	    	for (int i = 0; i < columns.length; i++) {
	    		data[x][i] = "test" + i;
	    	}
    	}
    	
    	return data;
    }
    
    // Customize GUI
    private void buildPanel() {
    	
    	String[] columnNames = {"Entry Point", "Nintendo Logo", "Title", "Manufacturer Code", "CGB Flag", "New Licensee Code", "SGB Flag", "Cartridge Type", "ROM Size", "RAM Size", "Destination Code", "Old Licensee Code", "Mask ROM Version number", "Header Checksum", "Global Checksum"};
    	Object[][] data = buildTable(columnNames);
    	JTable table = new JTable(data, columnNames);
    	
        panel = new JPanel(new BorderLayout());
        
        JTextArea textArea = new JTextArea(5, 25);
        textArea.setEditable(false);
        
        JScrollPane scrollPane = new JScrollPane(new SimpleNumberLinePanel());
        table.setFillsViewportHeight(true);
        
        panel.add(scrollPane);
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
        			for (byte a: entry.getValue()) {
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
        		System.out.println("Calculated Checksum: " +  checksum);
        		System.out.println("Given Checksum: " +   Byte.toUnsignedInt(GameboyHelper.getHeaderChecksum()));
        		System.out.println("Checksum Valid? - " + (checksum == Byte.toUnsignedInt(GameboyHelper.getHeaderChecksum())));
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