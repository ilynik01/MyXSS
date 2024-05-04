from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from lib.log import *
from lib.mysession import MySession
from threading import Thread



class scanner:
	@classmethod
	def get_payloads_from_files(self, files):

		payloads = []
		for file in files:
			with open(file, 'r') as f:
				payloads.append([line.strip() for line in f])
		return payloads



	@classmethod
	def post_method(self):
		bsObj = BeautifulSoup(self.body, "html.parser")
		forms = bsObj.find_all("form", method=True)

		for form in forms:
			action = form.get("action", self.url)

			if form.get("method", "").lower().strip() == "post":
				Log.warning(f"Found. POST method form: {urljoin(self.url, action)}")
				Log.info("POST method form: Gathering input keys")

				keys = {}
				for key in form.find_all(["input", "textarea"]):
					try:
						if key.get("type") == "submit":
							Log.info(f"POST form. Submit button key name: {key['name']} Assigned value: <Submit Confirm>")
							keys[key["name"]] = key["name"]
						else:
							quote_type = "'" if "'" in str(key) else '"'
							payload_with_quote = quote_type + ">" + self.payload
							Log.info(f"POST form. Key name: {key['name']} Assigned payload: {payload_with_quote}")
							keys[key["name"]] = payload_with_quote
					except Exception as e:
						Log.info(f"POST form. Error in key processing: {str(e)}")

				Log.info("POST method form: Payload sending ")
				req = self.session.post(urljoin(self.url, action), data=keys, allow_redirects=False)
				if self.payload in req.text:
					Log.alert(f"Vulnerability. POST form. At url {urljoin(self.url, req.url)}")
					Log.alert(f"Vulnerability. POST form. Payload sent: {self.payload}")
					return True
				else:
					Log.info("POST method form. No XSS detected")
		return False



	@classmethod
	def get_method_form(self):
		bsObj = BeautifulSoup(self.body, "html.parser")
		forms = bsObj.find_all("form", method=True)

		for form in forms:
			action = form.get("action", self.url)

			if form.get("method", "").lower().strip() == "get":
				Log.warning(f"Found. GET method form: {urljoin(self.url, action)}")
				Log.info("GET method form: Gathering input keys")

				keys = {}
				for key in form.find_all(["input", "textarea"]):
					try:
						if key.get("type") == "submit":
							Log.info(f"GET form. Submit button key name: {key['name']} Assigned value: <Submit Confirm>")
							keys[key["name"]] = key["name"]
						else:
							Log.info(f"GET form. Key name: {key['name']} Assigned payload: {self.payload}")
							keys[key["name"]] = self.payload
					except Exception as e:
						Log.info(f"GET form. Error in key processing: {str(e)}")
						try:
							Log.info(f"GET form. Key name: {key['name']} Assigned payload: {self.payload}")
							keys[key["name"]] = self.payload
						except KeyError as e:
							Log.info(f"GET form. Error in key processing: {str(e)}")

				Log.info("GET method form: Payload sending ")
				req = self.session.get(urljoin(self.url, action), params=keys, allow_redirects=False)

				if self.payload in req.text:
					Log.alert(f"Vulnerability. GET form. At url {urljoin(self.url, req.url)}")
					Log.alert(f"Vulnerability. GET form. Payload sent: {self.payload}")
					return True
				else:
					Log.info("GET method form. No XSS detected")
		return False

	@classmethod
	def get_method(self):
		bsObj = BeautifulSoup(self.body, "html.parser")
		links = bsObj.find_all("a", href=True)

		for a in links:
			url = a["href"]
			if not (url.startswith("http://") or url.startswith("https://") or url.startswith("mailto:")):
				base = urljoin(self.url, a["href"])
				query = urlparse(base).query

				if query:
					Log.warning(f"Found. GET Link with query: {query}")

					query_payload = query.replace(query[query.find("=")+1:], self.payload, 1)
					test = base.replace(query, query_payload, 1)

					query_all = base.replace(query, urlencode({x: self.payload for x in parse_qs(query)}))

					Log.info(f"GET Link with query. Payload injected query: {test}")
					Log.info(f"GET Link with query. Payload injected in all parameters: {query_all}")

					if not (url.startswith("mailto:") or url.startswith("tel:")):
						_respon = self.session.get(test, verify=False, allow_redirects=False)
						if self.payload in _respon.text or self.payload in self.session.get(query_all, allow_redirects=False).text:
							Log.alert(f"Vulnerability. GET query. At url {_respon.url}")
							Log.alert(f"Vulnerability. GET query. Payload sent: {self.payload}")
							return True
						else:
							Log.info("GET Link with query. No XSS detected")
					else:
						Log.info("GET Link with query. URL ignored. Reason: not HTTP")
		return False



	@classmethod
	def main(self, url, files, callback=None):
		
		print("____New scanning thread____")
		self.url=url

		self.session=MySession()
		Log.info("URL Connection. Connecting to "+url)    
		try:
			ctr = self.session.get(url, allow_redirects=False)
			self.body=ctr.text
		except Exception as e:
			Log.error("URL Connection. Internal error: "+str(e))
			return

		if ctr.status_code > 400:
			Log.error("URL Connection. Connection failed: "+str(ctr.status_code))
			return 
		else:
			Log.info("URL Connection. Connection estabilished: "+str(ctr.status_code))

		payloads = self.get_payloads_from_files(files)
		vulnerabilities_found = {file: False for file in files}

		def scan_payloads(payload_list, file):
			for payload in payload_list:
				self.payload = payload
				if self.post_method():
					Log.alert("Vulnerability. POST form. Payload file: " + file)
					vulnerabilities_found[file] = True
					break
				elif self.get_method():
					Log.alert("Vulnerability. GET query. Payload file: " + file)
					vulnerabilities_found[file] = True
					break
				elif self.get_method_form():
					Log.alert("Vulnerability. GET form. Payload file: " + file)
					vulnerabilities_found[file] = True
					break

		threads = []
		for i, payload_list in enumerate(payloads):
			t = Thread(target=scan_payloads, args=(payload_list, files[i]))
			t.start()
			threads.append(t)

		for t in threads:
			t.join()

		if all(vulnerabilities_found.values()):
			Log.alert("____Scanning thread conclusion: Vulnerabilities found with payloads from all files____")
		elif any(vulnerabilities_found.values()):
			Log.alert("____Scanning thread conclusion: Vulnerabilities found with payloads from some files____")
		else:
			Log.info("____Scanning thread conclusion: No vulnerabilities found with payloads from any files____")

		if callback is not None:
			callback()

		return



