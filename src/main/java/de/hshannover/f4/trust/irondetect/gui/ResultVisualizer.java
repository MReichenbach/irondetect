/*
 * #%L
 * =====================================================
 *   _____                _     ____  _   _       _   _
 *  |_   _|_ __ _   _ ___| |_  / __ \| | | | ___ | | | |
 *    | | | '__| | | / __| __|/ / _` | |_| |/ __|| |_| |
 *    | | | |  | |_| \__ \ |_| | (_| |  _  |\__ \|  _  |
 *    |_| |_|   \__,_|___/\__|\ \__,_|_| |_||___/|_| |_|
 *                             \____/
 * 
 * =====================================================
 * 
 * Hochschule Hannover
 * (University of Applied Sciences and Arts, Hannover)
 * Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de
 * Website: http://trust.f4.hs-hannover.de/
 * 
 * This file is part of irondetect, version 0.0.8,
 * implemented by the Trust@HsH research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2010 - 2015 Trust@HsH
 * %%
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
 * #L%
 */
package de.hshannover.f4.trust.irondetect.gui;



import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.util.Vector;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;

import org.apache.log4j.Logger;

import de.hshannover.f4.trust.irondetect.Main;
import de.hshannover.f4.trust.irondetect.util.event.Event;
import de.hshannover.f4.trust.irondetect.util.event.EventReceiver;
import de.hshannover.f4.trust.irondetect.util.event.EventType;
import de.hshannover.f4.trust.irondetect.util.event.ResultUpdateEvent;

public class ResultVisualizer implements EventReceiver {

	class ResultTableModel extends AbstractTableModel {

		private static final long serialVersionUID = -3297226482363924926L;

		private Vector<ResultObject> resultObjects;
		
		public ResultTableModel() {
			this.resultObjects = new Vector<ResultObject>();
			
		}
		
		public void addRow(ResultObject ro) {
			ro.setIndex(this.getRowCount() + 1);
			this.resultObjects.add(0, ro);	// insert at FIRST index in vector
			fireTableDataChanged();
		}
		
		@Override
		public String getColumnName(int col) {
			switch (col) {
			case 0:
				return "#";
			case 1:
				return "Device";
			case 2:
				return "ID";
			case 3:
				return "Value";
			case 4:
				return "Timestamp";
			default:
				return "";
			}
	    }
		
		/*
		 * JTable uses this method to determine the default renderer/ editor for
		 * each cell. If we didn't implement this method, then the last column
		 * would contain text ("true"/"false"), rather than a check box.
		 */
		@Override
		public Class<? extends Object> getColumnClass(int c) {
			return getValueAt(0, c).getClass();
		}

		@Override
		public int getColumnCount() {
			return 5;
		}

		@Override
		public int getRowCount() {
			return this.resultObjects.size();
		}

		@Override
		public Object getValueAt(int row, int col) {
			ResultObject tmp = this.resultObjects.get(row);
			switch (col) {
			case 0:
				return tmp.getIndex();
			case 1:
				return tmp.getDevice();
			case 2:
				return tmp.getId();
			case 3:
				return tmp.getValue();
			case 4:
				return tmp.getTimeStamp();
			default:
				return null;
			}
		}
	}

	private static final int RULE = 0;
	private static final int SIGNATURE = 1;
	private static final int ANOMALY = 2;
	private static final int CONDITION = 3;
	private static final String[] TYPES = new String[]{"Rules", "Signatures", "Anomalies", "Conditions"};

	private Logger logger = Logger.getLogger(ResultVisualizer.class);

	private JTable[] tables;

	private JScrollPane[] scrollPanes;

	private ResultTableModel[] tableModels;

	private JPanel[] panels;
	private Dimension screenSize;
	private JLabel[] labels;

	public ResultVisualizer() {
		this.tables = new JTable[4];
		this.scrollPanes = new JScrollPane[4];
		this.tableModels = new ResultTableModel[4];
		this.panels = new JPanel[4];
		this.labels = new JLabel[4];
		
		this.screenSize = Toolkit.getDefaultToolkit().getScreenSize();
		
		initComponentsForType(RULE);
		initComponentsForType(SIGNATURE);
		initComponentsForType(ANOMALY);
		initComponentsForType(CONDITION);
		
		initFrame();

		logger.info(ResultVisualizer.class.getSimpleName() + " has started.");
	}

	private void initFrame() {
		// Create and set up the window.
		JFrame frame = new JFrame("irondetect (v" + Main.VERSION + ")");
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setPreferredSize(new Dimension((int) (this.screenSize.width * 0.5), (int) (this.screenSize.height * 0.5)));

		Container contentPane = frame.getContentPane();
		contentPane.setLayout(new GridLayout(4, 1));	// TODO variabel?
		
		// Create and set up the content pane.
		for (JPanel panel : this.panels) {
			panel.setOpaque(true); // content panes must be opaque
			contentPane.add(panel);
		}

		// Display the window.
		frame.pack();
		frame.setVisible(true);
		
	}
	
	private void initComponentsForType(final int type) {
		this.panels[type] = new JPanel();
		this.tableModels[type] = new ResultTableModel();
		this.tables[type] = new JTable(this.tableModels[type]);
		this.tables[type].setEnabled(false);
		this.scrollPanes[type] = new JScrollPane(this.tables[type]);
		this.tables[type].setFillsViewportHeight(true);
		this.tables[type].setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		this.panels[type].setLayout(new BorderLayout());
		this.panels[type].add(this.scrollPanes[type], BorderLayout.CENTER);
		this.labels[type] = new JLabel(TYPES[type]);
		this.panels[type].add(this.labels[type], BorderLayout.NORTH);
	}

	private boolean checkResultObjectType(ResultObjectType type) {
		switch (type) {
			case RULE:
			case SIGNATURE:
			case ANOMALY:
			case CONDITION:
				return true;
			default:
				return false;
		}
	}

	private int typeToInt(ResultObjectType type) {
		switch (type) {
			case RULE:
				return RULE;
			case SIGNATURE:
				return SIGNATURE;
			case ANOMALY:
				return ANOMALY;
			case CONDITION:
				return CONDITION;
			default:
				return -1;
		}
	}
	
	@Override
	public void submitNewEvent(Event e) {
		if (e.getType() == EventType.RESULT_UPDATE) {
			ResultObject ro = ((ResultUpdateEvent) e).getPayload();
			if (checkResultObjectType(ro.getType())) {
				logger.trace("Received result update: device==" + ro.getDevice()
						+ ", type==" + ro.getType() + ", id==" + ro.getId()
						+ ", value==" + ro.getValue() + ", timestamp==" + ro.getTimeStamp());

				final int type = typeToInt(ro.getType());
				this.tableModels[type].addRow(ro);
				this.scrollPanes[type].revalidate();
			}
		}
	}
}
