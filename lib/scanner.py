from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import os
import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from lib.log import *
from lib.mysession import MySession
from threading import Thread
from queue import Queue





class scanner:
	detected_vulnerabilities = []

	@classmethod
	def scan_get(cls, payloads):
		source_code = BeautifulSoup(cls.body, "html.parser")
		links = source_code.find_all("a", href=True)

		link_data = []
		for a in links:
			url = a["href"]
			if not url.startswith("mailto:"):
				base = urljoin(cls.url, a["href"])
				query = urlparse(base).query

				if query:
					link_data.append((base, query))

		results = Queue()

		def scan_payloads(payload_list, base, query):
			payload_group_name = payload_list[0]
			for payload in payload_list[1:]:
				query_payload = query.replace(query[query.find("=")+1:], payload, 1)
				test = base.replace(query, query_payload, 1)
				query_all = base.replace(query, urlencode({x: payload for x in parse_qs(query)}))

				request = cls.session.get(test, verify=False)
				if payload in request.text or payload in cls.session.get(query_all).text:
					Log.alert(f"Vulnerability. GET query. At url {request.url}")
					Log.alert(f"Vulnerability. GET query. Payload sent: {payload}")
					Log.alert(f"Vulnerability. GET query. Payload file: {payload_group_name}")

					vulnerability_info = {
						"HTTP Method": "GET",
						"URL": request.url,
						"Payload": payload,
						"Payload file": payload_group_name
					}
					cls.detected_vulnerabilities.append(vulnerability_info)
					results.put(True)
					return
				else:
					results.put(False)

		threads = []
		for payload_list in payloads:
			for base, query in link_data:
				t = Thread(target=scan_payloads, args=(payload_list, base, query))
				t.start()
				threads.append(t)

		for t in threads:
			t.join()

		while not results.empty():
			if results.get():
				return True

		return False


	@classmethod
	def scan_post(cls, payloads):
		source_code = BeautifulSoup(cls.body, "html.parser")
		forms = source_code.find_all("form")
		method_forms = [form for form in forms if form.get('method')]
		form_data = []

		for form in method_forms:
			action = form.get("action", cls.url)

			if form.get("method", "").lower().strip() == "post":
				keys = []
				for key in form.find_all(["input", "textarea"]):
					try:
						if key.get("type") == "submit":
							keys.append(key["name"])
						else:
							keys.append(key["name"])
					except Exception as e:
						Log.error(f"POST form. Error in key processing: {str(e)}")

				form_data.append((action, keys))

		results = Queue()

		def scan_payloads(payload_list, action, keys):
			payload_group_name = payload_list[0]
			for payload in payload_list[1:]:
				data = {}
				for key in keys:
					quote_type = "'" if "'" in str(key) else '"'
					payload_quote = quote_type + ">" + payload
					data[key] = payload_quote

				request = cls.session.post(urljoin(cls.url, action), data=data)
				if payload in request.text:
					Log.alert(f"Vulnerability. POST form. At url {urljoin(cls.url, request.url)}")
					Log.alert(f"Vulnerability. POST form. Payload sent: {payload}")
					Log.alert(f"Vulnerability. POST form. Payload file: {payload_group_name}")

					vulnerability_info = {
						"HTTP Method": "POST",
						"URL": urljoin(cls.url, request.url),
						"Payload": payload,
						"Payload file": payload_group_name
					}
					cls.detected_vulnerabilities.append(vulnerability_info)
					results.put(True)
					return
				else:
					results.put(False)

		threads = []
		for payload_list in payloads:
			for action, keys in form_data:
				t = Thread(target=scan_payloads, args=(payload_list, action, keys))
				t.start()
				threads.append(t)

		for t in threads:
			t.join()

		while not results.empty():
			if results.get():
				return True

		return False



	@classmethod
	def scan_get_form(cls, payloads):
		source_code = BeautifulSoup(cls.body, "html.parser")
		forms = source_code.find_all("form")
		method_forms = [form for form in forms if form.get('method')]
		form_data = []

		for form in method_forms:
			action = form.get("action", cls.url)

			if form.get("method", "").lower().strip() == "get":
				keys = []
				for key in form.find_all(["input", "textarea"]):
					if key.has_attr("name"):
						try:
							keys.append(key["name"])
						except Exception as e:
							Log.error(f"GET form. Error in key processing: {str(e)}")

				form_data.append((action, keys))

		results = Queue()

		def scan_payloads(payload_list, action, keys):
			payload_group_name = payload_list[0]
			for payload in payload_list[1:]:
				data = {}
				for key in keys:
					quote_type = "'" if "'" in str(key) else '"'
					payload_quote = quote_type + ">" + payload
					data[key] = payload_quote

				request = cls.session.get(urljoin(cls.url, action), data=data)
				if payload in request.text:
					Log.alert(f"Vulnerability. GET form. At url {urljoin(cls.url, request.url)}")
					Log.alert(f"Vulnerability. GET form. Payload sent: {payload}")
					Log.alert(f"Vulnerability. GET form. Payload file: {payload_group_name}")
					
					vulnerability_info = {
						"HTTP Method": "GET",
						"URL": urljoin(cls.url, request.url),
						"Payload": payload,
						"Payload file": payload_group_name
					}
					cls.detected_vulnerabilities.append(vulnerability_info)
					results.put(True)
					return
				else:
					results.put(False)

		threads = []
		for payload_list in payloads:
			for action, keys in form_data:
				t = Thread(target=scan_payloads, args=(payload_list, action, keys))
				t.start()
				threads.append(t)

		for t in threads:
			t.join()

		while not results.empty():
			if results.get():
				return True

		return False


	@classmethod
	def check_connection(self, url):
		self.url = url
		self.session = MySession()
		Log.info("URL Connection. Connecting to " + url)
		try:
			response = self.session.request('GET', url)
			self.body = response.content.decode('utf-8')
		except Exception as e:
			Log.error("URL Connection. Error: " + str(e))
			return False

		if not response.ok:
			Log.error("URL Connection. Error: " + str(response.status_code))
			return False

		Log.info("URL Connection. Connection successful")
		return True


	@classmethod
	def main(self, url, files, callback=None):
		if not self.check_connection(url):
			return

		payloads = []
		for file in files:
			with open(file, 'r') as f:
				file_name = os.path.splitext(os.path.basename(file))[0]
				payload_list = [line.strip() for line in f]
				payload_list.insert(0, file_name)
				payloads.append(payload_list)

		threads = []
		methods = [self.scan_post, self.scan_get, self.scan_get_form]
		results = {method.__name__: None for method in methods}

		for method in methods:
			def target_method(payloads):
				result = method(payloads)
				results[method.__name__] = result
				if result:
					Log.alert(f"___URL {url} scanning conclusion: Found XSS with {method.__name__} ___")
				else:
					Log.info(f"___URL {url} scanning conclusion: No XSS found with {method.__name__} ___")

			t = Thread(target=target_method, args=(payloads,))
			t.start()
			threads.append(t)

		for t in threads:
			t.join()

		if callback is not None:
			callback()

		return



