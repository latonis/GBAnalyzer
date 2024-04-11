package gameboy;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import docking.DialogComponentProvider;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;
import javax.swing.JTextArea;
import javax.swing.DropMode;
import java.awt.Font;
import java.util.LinkedHashMap;
import java.util.Map;

public class HeaderDialog extends DialogComponentProvider {

	private static final long serialVersionUID = 1L;
	private final JPanel contentPanel = new JPanel();

	/**
	 * Create the dialog.
	 */
	public HeaderDialog(String title) {
		super(title);
		this.setPreferredSize(500, 250);
		contentPanel.setLayout(null);
		contentPanel.setLayout(null);
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		addWorkPanel(contentPanel);
		
//		Color validColor = new Color((0*12) + 12 % 255, 153, 0);
//		JPanel panel = new JPanel(new BorderLayout());
//		panel.setBounds(12, 89, 44, 105);
//
//		panel.setBackground(validColor);
//		String text = "<html><p>" + String.valueOf((char) (44 + 0)) + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa" + "</p></html>";
//		JTextArea lblNewLabel = new JTextArea(7,8);
//		lblNewLabel.setBounds(104, 70, 44, 105);
//		contentPanel.add(lblNewLabel);
//		lblNewLabel.setFont(new Font("Dialog", Font.PLAIN, 12));
//		lblNewLabel.setDropMode(DropMode.ON);
//		lblNewLabel.setText(text);
//		lblNewLabel.setLineWrap(true);
//		lblNewLabel.setEditable(false);
//		lblNewLabel.setBorder(null);
//		contentPanel.add(panel);
		

		
		LinkedHashMap<String, byte[]> header = GameboyHelper.getHeader();
		int start = 12;
		int i = 0;
		for (Map.Entry<String, byte[]> entry : header.entrySet()) {
			int width = 82;
			int height = 150;
			Color validColor = new Color((i*12) + start % 255, 153, 0);
			JPanel panel = new JPanel(new BorderLayout());
			panel.setBackground(validColor);
			panel.setBounds((i*12) + start + (i*width), 100, width, height);
			String chars = "";
			for (byte b: entry.getValue()) {
				chars += String.format("%02X ", b);
			}
			JTextArea textArea = new JTextArea(7,8);
			textArea.setOpaque(false);
			textArea.setText(chars);
			textArea.setLineWrap(true);
			textArea.setEditable(false);
			textArea.setBorder(null);
			textArea.setHighlighter(null);
			textArea.setBackground(validColor);
	        panel.add(textArea, BorderLayout.NORTH);
			contentPanel.add(panel);
			
			JLabel lblNewLabel_1 = new JLabel(entry.getKey());
			lblNewLabel_1.setHorizontalAlignment(SwingConstants.CENTER);
			lblNewLabel_1.setBounds((i*12) + start + (i*width), 250, 70, 15);
			contentPanel.add(lblNewLabel_1);
			
			i++;
		}
	}
}
