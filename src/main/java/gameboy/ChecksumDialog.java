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

public class ChecksumDialog extends DialogComponentProvider {

	private static final long serialVersionUID = 1L;
	private final JPanel contentPanel = new JPanel();
	private final JLabel lblComputedChecksum = new JLabel("Given Checksum");
	private final JLabel lblComputedChecksum_1 = new JLabel("Computed Checksum");

	/**
	 * Create the dialog.
	 */
	public ChecksumDialog(String title)   {
		super(title);
		this.setPreferredSize(535, 300);
		
		String[] columns = {"Calculated Checksum", "Given Checksum"}; 
		Object[][] data = {{GameboyHelper.calcHeaderChecksum(), Byte.toUnsignedInt(GameboyHelper.getHeaderChecksum())}};

		addWorkPanel(contentPanel);
		GridBagLayout gbl_contentPanel = new GridBagLayout();
		gbl_contentPanel.columnWidths = new int[]{150, 150, 150, 0};
		gbl_contentPanel.rowHeights = new int[]{100, 100, 100, 0};
		gbl_contentPanel.columnWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
		gbl_contentPanel.rowWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
		contentPanel.setLayout(gbl_contentPanel);
		
		JLabel label = new JLabel("");
		GridBagConstraints gbc_label = new GridBagConstraints();
		gbc_label.fill = GridBagConstraints.BOTH;
		gbc_label.insets = new Insets(0, 0, 5, 5);
		gbc_label.gridx = 0;
		gbc_label.gridy = 0;
		contentPanel.add(label, gbc_label);
		JLabel lblNewLabel = new JLabel("Gameboy Checksum Information");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
		gbc_lblNewLabel.fill = GridBagConstraints.BOTH;
		gbc_lblNewLabel.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel.gridx = 1;
		gbc_lblNewLabel.gridy = 0;
		contentPanel.add(lblNewLabel, gbc_lblNewLabel);
		
		JLabel label_1 = new JLabel("");
		GridBagConstraints gbc_label_1 = new GridBagConstraints();
		gbc_label_1.fill = GridBagConstraints.BOTH;
		gbc_label_1.insets = new Insets(0, 0, 5, 0);
		gbc_label_1.gridx = 2;
		gbc_label_1.gridy = 0;
		contentPanel.add(label_1, gbc_label_1);
		lblComputedChecksum.setHorizontalAlignment(SwingConstants.CENTER);
		
		GridBagConstraints gbc_lblComputedChecksum = new GridBagConstraints();
		gbc_lblComputedChecksum.fill = GridBagConstraints.BOTH;
		gbc_lblComputedChecksum.insets = new Insets(0, 0, 5, 5);
		gbc_lblComputedChecksum.gridx = 0;
		gbc_lblComputedChecksum.gridy = 1;
		contentPanel.add(lblComputedChecksum, gbc_lblComputedChecksum);
		lblComputedChecksum_1.setHorizontalAlignment(SwingConstants.CENTER);
		
		GridBagConstraints gbc_lblComputedChecksum_1 = new GridBagConstraints();
		gbc_lblComputedChecksum_1.fill = GridBagConstraints.BOTH;
		gbc_lblComputedChecksum_1.insets = new Insets(0, 0, 5, 0);
		gbc_lblComputedChecksum_1.gridx = 2;
		gbc_lblComputedChecksum_1.gridy = 1;
		contentPanel.add(lblComputedChecksum_1, gbc_lblComputedChecksum_1);
		
		JLabel lblGiven = new JLabel("" + String.format("0x%02X ", Byte.toUnsignedInt(GameboyHelper.getHeaderChecksum())));
		lblGiven.setHorizontalAlignment(SwingConstants.CENTER);
		GridBagConstraints gbc_lblGiven = new GridBagConstraints();
		gbc_lblGiven.insets = new Insets(0, 0, 0, 5);
		gbc_lblGiven.gridx = 0;
		gbc_lblGiven.gridy = 2;
		contentPanel.add(lblGiven, gbc_lblGiven);
		
		String validText = "VALID";
		Color validColor = new Color(0, 153, 0);
		
		if (Byte.toUnsignedInt(GameboyHelper.getHeaderChecksum()) != GameboyHelper.calcHeaderChecksum()) {
			validText = "INVALID";
			validColor = new Color(153, 0, 0);
		}
		
		JPanel panel = new JPanel();
		GridBagConstraints gbc_panel = new GridBagConstraints();
		gbc_panel.fill = GridBagConstraints.BOTH;
		gbc_panel.insets = new Insets(0, 0, 0, 5);
		gbc_panel.gridx = 1;
		gbc_panel.gridy = 2;
		contentPanel.add(panel, gbc_panel);
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{150, 0};
		gbl_panel.rowHeights = new int[]{100, 0};
		gbl_panel.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, Double.MIN_VALUE};
		panel.setLayout(gbl_panel);
		JLabel lblValid = new JLabel(validText);
		GridBagConstraints gbc_lblValid = new GridBagConstraints();
		gbc_lblValid.fill = GridBagConstraints.BOTH;
		gbc_lblValid.gridx = 0;
		gbc_lblValid.gridy = 0;
		panel.add(lblValid, gbc_lblValid);
		lblValid.setHorizontalAlignment(SwingConstants.CENTER);
		panel.setBackground(validColor);
		
		JLabel lblNewLabel_1 = new JLabel("" + String.format("0x%02X ", GameboyHelper.calcHeaderChecksum()));
		GridBagConstraints gbc_lblNewLabel_1 = new GridBagConstraints();
		gbc_lblNewLabel_1.gridx = 2;
		gbc_lblNewLabel_1.gridy = 2;
		contentPanel.add(lblNewLabel_1, gbc_lblNewLabel_1);
	}
}
