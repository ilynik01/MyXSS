import glob
import os
import re
import sys
from threading import Thread

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtWidgets import QApplication, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QFileDialog, QGridLayout, QHeaderView, QHBoxLayout
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt

from lib.crawler import *
from lib.log import *
from lib.scanner import *





def resource_path(relative_path):
	""" Get absolute path to resource, works for dev and for PyInstaller """
	try:
		base_path = sys._MEIPASS
	except Exception:
		base_path = os.path.abspath(".")

	return os.path.join(base_path, relative_path)


payloads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'payloads')
payloads_files = glob.glob(os.path.join(payloads_dir, '*'))


class Application(QWidget):
	scan_finished = pyqtSignal()

	def __init__(self):
		super().__init__()
		self.setWindowTitle('MyXSS Scanner')
		self.setGeometry(100, 100, 800, 700)
		self.setStyleSheet("background-color: white;")
		self.create_initial_widgets()
		self.scan_finished.connect(self.generate_report)

	def clear_layout(self, layout):
		while layout.count():
			child = layout.takeAt(0)
			widget = child.widget()
			if widget:
				widget.deleteLater()
			else:
				self.clear_layout(child.layout())

	def create_initial_widgets(self):
		Log.clear_log()

		layout = self.layout()
		if layout is not None:
			self.clear_layout(layout)
		else:
			layout = QVBoxLayout()

		image_label = QLabel()
		image_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'images/MyXSS.png')
		pixmap = QPixmap(image_path)
		pixmap = pixmap.scaled(800, 800, Qt.KeepAspectRatio)

		image_label.setPixmap(pixmap)
		layout.addWidget(image_label)

		self.url_label = QLabel("URL:")
		font = self.url_label.font()
		font.setPointSize(20)
		self.url_label.setFont(font)
		layout.addWidget(self.url_label)

		self.url_entry = QLineEdit()	
		self.url_entry.setStyleSheet("background-color: #fbfce6; padding: 10px; border: 2px solid #dbdb46;")
		self.url_entry.setFixedHeight(40)
		layout.addWidget(self.url_entry)

		self.fast_scan_button = QPushButton("Fast Scan")
		self.fast_scan_button.setStyleSheet("background-color: #e3f5ff; padding: 10px; border-radius: 10px; border: 2px solid #d3d3d3;")
		self.fast_scan_button.setFixedHeight(50)
		font = self.fast_scan_button.font()
		font.setPointSize(20)
		font.setFamily("Roboto")
		self.fast_scan_button.setFont(font)
		self.fast_scan_button.clicked.connect(self.fast_scan)
		layout.addWidget(self.fast_scan_button)

		self.normal_scan_button = QPushButton("Normal Scan")
		self.normal_scan_button.setStyleSheet("background-color: #baddff; padding: 10px; border-radius: 10px; border: 2px solid #d3d3d3;")
		self.normal_scan_button.setFixedHeight(50)
		font = self.normal_scan_button.font()
		font.setPointSize(20)
		font.setFamily("Roboto")
		self.normal_scan_button.setFont(font)
		self.normal_scan_button.clicked.connect(self.normal_scan)
		layout.addWidget(self.normal_scan_button)

		layout.setAlignment(Qt.AlignCenter)
		self.setLayout(layout)


	def fast_scan(self):
		url = self.url_entry.text()
		if url:
			Thread(target=self.start_scan, args=(url, True)).start()

	def normal_scan(self):
		url = self.url_entry.text()
		if url:
			Thread(target=self.start_scan, args=(url, False)).start()




	def start_scan(self, url, is_fast_scan):
		layout = self.layout()
		if layout is not None:
			self.clear_layout(layout)
		else:
			layout = QVBoxLayout()

		if is_fast_scan:
			scanner.main(url, payloads_files, callback=self.on_crawl_finished)
		else:
			scanner.main(url, payloads_files)
			crawler.crawl(url, payloads_files, callback=self.on_crawl_finished)
		


	def on_crawl_finished(self):
		self.scan_finished.emit()



	def generate_report(self):
		layout = self.layout()
		self.clear_layout(layout)

		title_label = QLabel("Scanning report")
		title_label.setFont(QFont('Arial', 30))
		layout.addWidget(title_label)

		log_dict = Log.log_dict
		vulnerability_logs = log_dict["VULNERABILITY"]

		vulnerabilities = []

		for i in range(0, len(vulnerability_logs), 3):
			if i + 2 >= len(vulnerability_logs):
				break
			vulnerabilities.append((vulnerability_logs[i], vulnerability_logs[i+1], vulnerability_logs[i+2]))

		data = []
		for vulnerability in vulnerabilities:
			type_of_vulnerability = re.search(r"Payload file: (.*)", vulnerability[2])
			type_of_vulnerability = type_of_vulnerability.group(1) if type_of_vulnerability else "Unknown"

			method = re.search(r"Vulnerability\. (\w+)", vulnerability[0])
			method = method.group(1) if method else "Unknown"

			url = re.search(r"At url (http[s]?://.*)", vulnerability[0])
			url = url.group(1) if url else "Unknown"

			payload_used = re.search(r"Payload sent: (.*)", vulnerability[1])
			payload_used = payload_used.group(1) if payload_used else "Unknown"

			if method == "POST":
				payload_used = "\">" + payload_used

			data.append([type_of_vulnerability, method, url, payload_used])

		status_text_label = QLabel("Website XSS Vulnerability Status: ")
		status_text_label.setFont(QFont('Arial', 14))
		status_text_label.setStyleSheet("color: black")
		layout.addWidget(status_text_label)

		status_label = QLabel("Vulnerable" if data else "Safe")
		status_label.setFont(QFont('Arial', 14))
		status_label.setStyleSheet("color: red" if data else "color: green")
		layout.addWidget(status_label)

		status_label = QLabel("\n Threat assesment for the detected payload types: \n" if data else "")
		status_label.setFont(QFont('Arial', 10))
		status_label.setStyleSheet("color: darkred; font-weight: bold;")
		layout.addWidget(status_label)

		payloads_dict = {os.path.splitext(os.path.basename(f))[0]: f for f in payloads_files}
		vuln_percentage = {}

		for record in data:
			vulnerability_type = record[0]
			payload_used = record[3]
			if payload_used.startswith('">'):
				payload_used = payload_used[2:]
			payload_file = payloads_dict[vulnerability_type]

			if payload_file is None:
				continue

			with open(payload_file, 'r') as f:
				payloads = [line.strip() for line in f.readlines()]
			try:
				payload_position = payloads.index(payload_used)
				percentage = 100 * (len(payloads) - payload_position) / len(payloads)
				vuln_percentage[tuple(record)] = percentage
			except ValueError:
				print(f"Payload used: '{payload_used}' not found in payloads for vulnerability type: {vulnerability_type}")

		pie_chart_layout = QGridLayout()
		row, col = 0, 0

		for record, percentage in vuln_percentage.items():
			fig, ax = plt.subplots(figsize=(1, 1))
			wedges, _ = ax.pie([percentage, 100 - percentage], colors=['red', 'green'], startangle=90)

			for wedge in wedges:
				wedge.set_edgecolor('white')
				wedge.set_radius(0.5)

			ax.set_title(f"{record[0]}", y=0.7)
			canvas = FigureCanvas(fig)
			pie_chart_layout.addWidget(canvas, row, col)

			col += 1
			if col > 3:
				col = 0
				row += 1

		layout.addLayout(pie_chart_layout)


		status_label = QLabel("\n Detailed table of found vulnerabilities: \n" if data else "")
		status_label.setFont(QFont('Arial', 10))
		status_label.setStyleSheet("color: darkred; font-weight: bold;")
		layout.addWidget(status_label)

		self.table = QTableWidget()
		layout.addWidget(self.table)


		button_width = int(self.width() * 0.4)

		self.export_button = QPushButton("Save report as text file")
		self.export_button.setStyleSheet("background-color: #add8e6; padding: 10px; border-radius: 10px;")
		self.export_button.setFixedWidth(button_width)
		self.export_button.clicked.connect(self.export_report)

		self.scan_again_button = QPushButton("Scan Again")
		self.scan_again_button.setStyleSheet("background-color: #add8e6; padding: 10px; border-radius: 10px;")
		self.scan_again_button.setFixedWidth(button_width)
		self.scan_again_button.clicked.connect(self.create_initial_widgets)

		button_layout = QHBoxLayout()
		button_layout.addWidget(self.export_button)
		button_layout.addWidget(self.scan_again_button)
		button_layout.setAlignment(Qt.AlignCenter)

		layout.addLayout(button_layout)


		self.setLayout(layout)

		if data:
			self.table.setRowCount(len(data))
			self.table.setColumnCount(len(data[0]) + 1)
			self.table.setHorizontalHeaderLabels(["Type of vulnerability", "Method", "URL", "Payload used", "Info"])
			self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
			self.table.horizontalHeader().setSectionResizeMode(len(data[0]), QHeaderView.Interactive)
			self.table.setColumnWidth(len(data[0]), 100)
			self.table.setColumnWidth(3, 100)


			for i, row_data in enumerate(data):
				for j, column_data in enumerate(row_data):
					self.table.setItem(i, j, QTableWidgetItem(str(column_data)))
				
				link_label = QLabel('<a href="http://example.com">Learn more...</a>'.format(data[i][0]))
				link_label.setOpenExternalLinks(True)
				self.table.setCellWidget(i, len(row_data), link_label)
	
		else:
			no_vulnerabilities_label = QLabel("No vulnerabilities found!")
			no_vulnerabilities_label.setFont(QFont('Arial', 10))
			no_vulnerabilities_label.setStyleSheet("color: green")
			layout.addWidget(no_vulnerabilities_label)




	def export_report(self):
		file_name, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "Text Files (*.txt)")

		if file_name:
			with open(file_name, 'w') as file:
				file.write("_______________________________________ MyXSS scanning report _______________________________________\n")
				for log in Log.log_dict["VULNERABILITY"]:
					file.write(log + "\n")





def main():
    app = QApplication(sys.argv)
    ex = Application()
    ex.show() 
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

