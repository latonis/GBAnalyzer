package gameboy;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import docking.DialogComponentProvider;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.SwingConstants;
import javax.swing.JComboBox;
import javax.swing.Box;
import javax.swing.JProgressBar;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.JSeparator;
import javax.swing.JFormattedTextField;
import javax.swing.JTextField;
import java.awt.GridLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import javax.swing.SpringLayout;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;

public class ChecksumDialog extends DialogComponentProvider {

	private final JPanel contentPanel = new JPanel();

	/**
	 * Create the dialog.
	 */
	public ChecksumDialog(String title)   {
		super(title);
		this.setPreferredSize(500, 250);
		
		String[] columns = {"Calculated Checksum", "Given Checksum"}; 
		int calc_checksum = GameboyHelper.calcHeaderChecksum();
		int given_checksum = Byte.toUnsignedInt(GameboyHelper.getHeaderChecksum());
		
		addWorkPanel(contentPanel);
		
		String validText = "VALID";
		Color validColor = new Color(0, 153, 0);
		
		if (calc_checksum != given_checksum) {
			validText = "INVALID";
			validColor = new Color(153, 0, 0);
		}
		
		contentPanel.setLayout(null);
		
		JPanel panel = new JPanel();
		panel.setBackground(validColor);
		panel.setBounds(12, 120, 476, 69);
		contentPanel.add(panel);
		panel.setLayout(new BorderLayout(0, 0));
		
		JLabel lblNewLabel = new JLabel(validText);
		panel.add(lblNewLabel, BorderLayout.CENTER);
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		
		JLabel lblGivenChecksum = new JLabel("Given Checksum");
		lblGivenChecksum.setBounds(78, 12, 119, 15);
		contentPanel.add(lblGivenChecksum);
		
		JLabel lblCalculatedChecksum = new JLabel("Calculated Checksum");
		lblCalculatedChecksum.setBounds(268, 12, 150, 15);
		contentPanel.add(lblCalculatedChecksum);
		
		JPanel panel_1 = new JPanel();
		panel_1.setBackground(Color.GRAY);
		panel_1.setBounds(78, 39, 119, 55);
		contentPanel.add(panel_1);
		panel_1.setLayout(new GridLayout(0, 1, 0, 0));
		
		JLabel lblAa = new JLabel(String.format("0x%02X ", given_checksum));
		lblAa.setHorizontalAlignment(SwingConstants.CENTER);
		panel_1.add(lblAa);
		
		JPanel panel_1_1 = new JPanel();
		panel_1_1.setBackground(Color.GRAY);
		panel_1_1.setBounds(278, 39, 119, 55);
		contentPanel.add(panel_1_1);
		panel_1_1.setLayout(new GridLayout(0, 1, 0, 0));
		
		JLabel lblBb = new JLabel(String.format("0x%02X ", calc_checksum));
		lblBb.setHorizontalAlignment(SwingConstants.CENTER);
		panel_1_1.add(lblBb);
	}
}
