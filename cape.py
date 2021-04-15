import requests, json, time
from requests.auth import HTTPBasicAuth

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT


class CapeClientV1():
	def __init__(self, host="", username="", password="", version=1):
		self.host = host
		self.version = version

		if version == 1:
			self.auth = HTTPBasicAuth(username, password)
			self.api_version = "/api"
		elif version == 2:
			r = requests.post(self.host + "/apiv2/api-token-auth/", data={"username": username, "password": password})
			self.headers = {"Authorization": "Token " + r.json()["token"]}
			self.api_version = "/apiv2"

	def sha256_check(self, sha256):
		"""Check in CAPE if an analysis already exist for the corresponding sha256
			- If an analysis already exist, we set the ID of the analysis and return true
			- If not, we just return false
		"""
		if self.version == 1:
			r = requests.get(self.host + self.api_version + "/tasks/search/sha256/" + sha256 + "/", auth=self.auth)
		else:
			r = requests.get(self.host + self.api_version + "/tasks/search/sha256/" + sha256 + "/", headers=self.headers)

		if r.json()["data"]:
			self.id = r.json()["data"][0]["id"]
			print("SHA256 OK")
			return True
		else:
			print("SHA256 NOK")
			return False

	def submit(self, filename):
		"""Takes a file and submit it to CAPE for analysis
		After submitting, we set the ID of the analysis to be able to check its status
		"""
		with open(filename, "rb") as f:
			file = {"file": (str(filename), f)}
			if self.version == 1:
				r = requests.post(self.host + self.api_version + "/tasks/create/file/", files=file, auth=self.auth)
			else:
				r = requests.post(self.host + self.api_version + "/tasks/create/file/", files=file, headers=self.headers)
		self.id = r.json()["data"]["task_ids"][0]

	def check_status(self):
		"""As long as the report status is different from "reported" and "failed_processing", we just wait.
		After having a result (or a failed result), we return true if the analysis is successful !
		"""
		if self.version == 1:
			r = requests.get(self.host + self.api_version + "/tasks/status/" + str(self.id) + "/", auth=self.auth)
		else:
			r = requests.get(self.host + self.api_version + "/tasks/status/" + str(self.id) + "/", headers=self.headers)

		while r.json()["data"] != "reported" and r.json()["data"] != "failed_processing" and not r.json()["error"]:
			print("Error ?", r.json()["error"], "- Value :", r.json()["data"])
			time.sleep(5)
			if self.version == 1:
				r = requests.get(self.host + self.api_version + "/tasks/status/" + str(self.id) + "/", auth=self.auth)
			else:
				r = requests.get(self.host + self.api_version + "/tasks/status/" + str(self.id) + "/", headers=self.headers)

		if r.json()["data"] == "reported" and not r.json()["error"]:
			return True
		else:
			return False

	def get_report(self):
		"""Takes an id and get the report of the corresponding analysis
		"""
		if self.version == 1:
			print("GET REPORT V1")
			r = requests.get(self.host + self.api_version + "/tasks/get/report/" + str(self.id) + "/json/", auth=self.auth)
		else:
			print("GET REPORT V2")
			r = requests.get(self.host + self.api_version + "/tasks/get/report/" + str(self.id) + "/json/", headers=self.headers)

		return r.json()

class Cape(ServiceBase):
	def __init__(self, config=None):
		super(Cape, self).__init__(config)

	def start(self):
		self.log.debug("Cape service started")

	def stop(self):
		self.log.debug("Cape service ended")

	def parse_list_of_dict(self, section_name, dict_list, parent):
		i = 0
		for e in dict_list:
			ResultSection(section_name + " " + str(i), body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(e), parent=parent)
			i += 1

	def parse_dict_of_dict(self, section_name, dict_dict, parent):
		for k in dict_dict:
			ResultSection(section_name + " " + k, body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(dict_dict[k]), parent=parent)

	def execute(self, request):
		result = Result()
		print("START")
		sha256 = request.sha256
		file = request.file_path
		host = request.get_param("host")
		username = request.get_param("username")
		password = request.get_param("password")
		version = request.get_param("version")
		report = None

		client = CapeClientV1(host=host, username=username, password=password, version=version)
		print("CLIENT CREATED")

		already_exist = client.sha256_check(sha256)
		# If the file has already been analyzed, we can get the report instantly
		if already_exist:
			print("ALREADY EXIST")
			report = client.get_report()
		# If not, we submit the file for dynamic analysis to CAPE sandbox
		else:
			print("SUBMITTING")
			client.submit(file)
			if client.check_status():
				report = client.get_report()

		print("PARSING")
		if report:
			# We pop each part of the report
			report_statistics = report.pop("statistics")
			report_cape = report.pop("CAPE")
			report_info = report.pop("info")
			report_behavior = report.pop("behavior")
			report_debug = report.pop("debug")
			report_deduplicated_shots = report.pop("deduplicated_shots")
			report_dropped = report.pop("dropped")
			report_network = report.pop("network")
			report_procdump = report.pop("procdump")
			try:
				report_static = report.pop("static")
			except KeyError:
				report_static = None
			report_strings = report.pop("strings")
			report_suricata = report.pop("suricata")
			report_target = report.pop("target")
			report_vt = report.pop("virustotal")
			report_procmemory = report.pop("procmemory")
			report_signatures = report.pop("signatures")
			report_ttps = report.pop("ttps")

			main_kv_section = ResultSection("Cape analysis report", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report))
			if report["malscore"] >= 2:
				main_kv_section.set_heuristic(2)
			elif report["malscore"] >= 1:
				main_kv_section.set_heuristic(1)

			# Statistics parsing
			self.parse_list_of_dict("Statistics processing", report_statistics["processing"], main_kv_section)
			self.parse_list_of_dict("Statistics signatures", report_statistics["signatures"], main_kv_section)
			self.parse_list_of_dict("Statistics reporting", report_statistics["reporting"], main_kv_section)

			# CAPE parsing
			self.parse_list_of_dict("CAPE subanalysis", report_cape, main_kv_section)

			# Info parsing
			report_info_machine = report_info.pop("machine")
			info_kv_section = ResultSection("Info", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_info), parent=main_kv_section)
			ResultSection("Machine info", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_info_machine), parent=info_kv_section)

			# Behavior parsing
			""" KEY_VALUE
			report_behavior_processes = report_behavior.pop("processes")
			report_behavior_anomaly = report_behavior.pop("anomaly")
			report_behavior_processtree = report_behavior.pop("processtree")
			report_behavior_summary = report_behavior.pop("summary")
			report_behavior_enhanced = report_behavior.pop("enhanced")
			report_behavior_encryptedbuffers = report_behavior.pop("encryptedbuffers")

			for process in report_behavior_processes:
				report_behavior_processes_calls = process.pop("calls")
				report_behavior_processes_threads = process.pop("threads")
				report_behavior_processes_environ = process.pop("environ")
				report_behavior_processes_kv_section = ResultSection("Behavior process " + str(process["process_id"]), body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(process), parent=main_kv_section)
				i = 0
				for call in report_behavior_processes_calls:
					report_behavior_processes_calls_arguments = call.pop("arguments")
					report_behavior_processes_calls_kv_section = ResultSection("Call " + str(i), body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(call), parent=report_behavior_processes_kv_section)
					self.parse_list_of_dict("Argument", report_behavior_processes_calls_arguments, report_behavior_processes_calls_kv_section)
					i += 1
				ResultSection("Threads", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_behavior_processes_threads), parent=report_behavior_processes_kv_section)
				ResultSection("Environ", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_behavior_processes_environ), parent=report_behavior_processes_kv_section)

			ResultSection("Behavior anomaly", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_behavior_anomaly), parent=main_kv_section)

			i = 0
			for process in report_behavior_processtree:
				report_behavior_processtree_environ = process.pop("environ")
				report_behavior_processtree_kv_section = ResultSection("Behavior processtree " + str(i), body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(process), parent=main_kv_section)
				ResultSection("Environ", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_behavior_processtree_environ), parent=report_behavior_processtree_kv_section)
				i += 1

			ResultSection("Behavior summary", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_behavior_summary), parent=main_kv_section)
			i = 0
			for e in report_behavior_enhanced:
				report_behavior_enhanced_data = e.pop("data")
				report_behavior_enhanced_kv_section = ResultSection("Behavior enhanced " + str(i), body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(e), parent=main_kv_section)
				ResultSection("Data", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_behavior_enhanced_data), parent=report_behavior_enhanced_kv_section)
				i += 1

			ResultSection("Encryptedbuffers", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_behavior_encryptedbuffers), parent=main_kv_section)
			"""
			ResultSection("Behavior", body_format=BODY_FORMAT.JSON, body=json.dumps(report_behavior), parent=main_kv_section)

			# Debug parsing
			ResultSection("Debug", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_debug), parent=main_kv_section)

			# Deduplicated_shots parsing
			ResultSection("Deduplicated shots", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_deduplicated_shots), parent=main_kv_section)

			# Dropped parsing
			self.parse_list_of_dict("Dropper analysis", report_dropped, main_kv_section)

			# Network parsing
			report_network_hosts = report_network.pop("hosts")
			report_network_udp = report_network.pop("udp")
			report_network_dns = report_network.pop("dns")
			network_kv_section = ResultSection("Network", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_deduplicated_shots), parent=main_kv_section)
			self.parse_list_of_dict("Hosts", report_network_hosts, network_kv_section)
			self.parse_list_of_dict("Udp", report_network_udp, network_kv_section)
			self.parse_list_of_dict("Dns", report_network_dns, network_kv_section)

			# Procdump parsing
			ResultSection("Procdump", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_procdump), parent=main_kv_section)

			# Static parsing
			report_static_values = ["pe", "dotnet"]
			if report_static:
				for k in report_static:
					if k not in report_static_values:
						ResultSection("Static " + k, body_format=BODY_FORMAT.JSON, body=json.dumps(report_static[k]), parent=main_kv_section)
					elif k == "pe":
						report_static_pe_imports = report_static[k].pop("imports")
						report_static_pe_exports = report_static[k].pop("exports")
						report_static_pe_dirents = report_static[k].pop("dirents")
						report_static_pe_sections = report_static[k].pop("sections")
						report_static_pe_resources = report_static[k].pop("resources")
						report_static_pe_versioninfo = report_static[k].pop("versioninfo")
						report_static_pe_digital_signers = report_static[k].pop("digital_signers")
						report_static_pe_guest_signers = report_static[k].pop("guest_signers")
						report_static_pe_kv_section = ResultSection("Static" + k, body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_static[k]), parent=main_kv_section)
						i = 0
						for dll in report_static_pe_imports:
							dll_imports = dll.pop("imports")
							dll_kv_section = ResultSection("DLL " + str(i), body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(dll), parent=report_static_pe_kv_section)
							self.parse_list_of_dict("Import", dll_imports, dll_kv_section)
							i += 1
						ResultSection("Exports", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_static_pe_exports), parent=report_static_pe_kv_section)
						self.parse_list_of_dict("Dirents", report_static_pe_dirents, parent=report_static_pe_kv_section)
						self.parse_list_of_dict("Sections", report_static_pe_sections, parent=report_static_pe_kv_section)
						self.parse_list_of_dict("Resources", report_static_pe_resources, parent=report_static_pe_kv_section)
						ResultSection("Versioninfo", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_static_pe_versioninfo), parent=report_static_pe_kv_section)
						ResultSection("Digital signers", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_static_pe_digital_signers), parent=report_static_pe_kv_section)
						ResultSection("Guest signers", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_static_pe_guest_signers), parent=report_static_pe_kv_section)
					elif k == "dotnet":
						self.parse_list_of_dict("Dotnet - typerefs", report_static[k]["typerefs"], main_kv_section)
						self.parse_list_of_dict("Dotnet - assemblyrefs", report_static[k]["assemblyrefs"], main_kv_section)
						ResultSection("Dotnet - assemblyinfo", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_static[k]["assemblyinfo"]), parent=main_kv_section)
						self.parse_list_of_dict("Dotnet - customattrs", report_static[k]["customattrs"], main_kv_section)


			# Strings parsing
			ResultSection("Strings analysis", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_strings), parent=main_kv_section)

			# Suricata analysis parsing
			ResultSection("Suricata analysis", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_suricata), parent=main_kv_section)

			# Target parsing
			report_target.update(report_target.pop("file", {}))
			ResultSection("Target analysis", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_target), parent=main_kv_section)

			# VirusTotal parsing
			try:
				report_vt_scans = report_vt.pop("scans")
				report_vt_results = report_vt.pop("results")
			except KeyError:
				report_vt_scans = None
				report_vt_results = None
			report_vt_kv_section = ResultSection("VirusTotal", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_vt), parent=main_kv_section)
			if report_vt_scans:
				self.parse_dict_of_dict("Scans", report_vt_scans, report_vt_kv_section)
			if report_vt_results:
				self.parse_list_of_dict("Results", report_vt_results, report_vt_kv_section)

			# Procmemory parsing
			ResultSection("Procmemory", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_procmemory), parent=main_kv_section)

			# Signatures parsing
			i = 0
			for signature in report_signatures:
				datas = signature.pop("data")
				signatures_kv_section = ResultSection("Signatures " + str(i), body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(signature), parent=main_kv_section)
				self.parse_list_of_dict("Data", datas, signatures_kv_section)
				i += 1

			# Ttps parsing
			ResultSection("Ttps", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(report_ttps), parent=main_kv_section)

			result.add_section(main_kv_section)

		request.result = result
