# SOC-Analyst Toolkit: Detecção, Análise e Resposta a Incidentes com Python

> **SIEM-friendly • MITRE-based • Log-Powered Detection Engine**

![Badge](https://img.shields.io/badge/Feito%20por-uma%20aspirante%20a%20analista%20de%20SOC-%23blueviolet)

## 📊 Visão Geral do Projeto

O **SOC-Analyst Toolkit** é uma ferramenta interativa em Python para auxiliar analistas de segurança na detecção de ameaças com base em logs reais e simulados, utilizando a base de conhecimento do [MITRE ATT&CK](https://attack.mitre.org/).

Funciona como um mini SIEM com funcionalidades essenciais de:
- Normalização de logs diversos
- Detecção baseada em regras (MITRE)
- Visualização e exportação de alertas
- Mini playbook de resposta

## ⚖️ Tecnologias Usadas

- **Python 3.10+**
- Bibliotecas: `json`, `pandas`, `datetime`, `rich`, `argparse`
- Formatos suportados: `.json`, `.pcap`
- Logs compatíveis: Windows, Linux (Syslog), Firewall, Suricata/Snort

## 🚀 Como Rodar o Projeto

```bash
# Clone o repositório
$ git clone https://github.com/seu-usuario/soc-analyst-toolkit
$ cd soc-analyst-toolkit

# Instale dependências
$ pip install -r requirements.txt

# Execute o painel interativo
$ python main.py
```

## 🎨 Prints do CLI

![Exemplo CLI](print-cli.png)


## 🔒 Regras de Detecção (MITRE ATT&CK)

As regras estão no arquivo `rules.json`, com correspondência direta aos IDs do [MITRE ATT&CK](https://attack.mitre.org/techniques/):

| ID      | Descrição                                    | Severidade |
|---------|-----------------------------------------------|------------|
| T1566   | Phishing via email suspeito                  | Medium     |
| T1059   | PowerShell malicioso                         | High       |
| T1068   | Escalonamento de privilégios (SeDebug)        | High       |
| T1078   | Acesso root via SSH externo                  | High       |
| T1021   | Lateral Movement via RDP                     | Medium     |
| T1105   | Transferência de dados suspeita               | Medium     |
| T1219   | Reverse Shell (Meterpreter) detectado        | High       |

## 📢 Dataset de Ataques Simulados

O projeto inclui um conjunto de logs simulando uma cadeia realista de ataque:

1. ✉️ **Phishing**: abertura de anexo malicioso via Outlook
2. 🔧 **Execução de PowerShell** com payload suspeito
3. 🔑 **Escalada de privilégios** usando SeDebugPrivilege
4. 📡 **Acesso remoto** via SSH e RDP
5. 🛡️ **Beaconing e shell reversa** (Suricata)
6. 💾 **Exfiltração de dados** via Firewall

Os arquivos estão em `/logs/` e prontos para serem normalizados e analisados.

## 📊 Exportação

Os alertas podem ser exportados via:
- `.json`
- `.csv`
- `.html` com cores por severidade e botão de download interativo

---

Feito com ❤️ e muita cafeína por uma futura analista de SOC.

Se gostou, deixa uma estrelinha no repositório e compartilha! ✨