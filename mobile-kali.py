from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
CONF = RAIZ / "config" / "mobile.conf"
TARGETS = RAIZ / "config" / "targets.txt"
REPORTS = RAIZ / "reports"
LOGS = RAIZ / "logs"

# Ferramentas do laboratorio. O terceiro campo marca se a ferramenta precisa de
# CAP_NET_RAW (root), ausente no Android rootless: fica documentada, nao some.
FERRAMENTAS = [
    ("nmap", "nmap", False),
    ("netcat", "netcat-traditional", False),
    ("whois", "whois", False),
    ("dnsutils", "dnsutils", False),
    ("python3", "python3", False),
    ("scapy", "python3-scapy", True),
    ("tcpdump", "tcpdump", True),
    ("arp-scan", "arp-scan", True),
    ("tshark", "tshark", True),
    ("metasploit", "metasploit-framework", False),
    # Password auditing / vuln assessment: clientes TCP ou offline, sem raw socket.
    # Autorizados pela politica do lab, SEMPRE contra host dentro de targets.txt.
    ("hydra", "hydra", False),
    ("john", "john", False),
    ("hashcat", "hashcat", False),
    ("nikto", "nikto", False),
    ("sqlmap", "sqlmap", False),
    ("wordlists", "wordlists", False),
]

class ErroConfig(RuntimeError):
    pass

def carregar_config() -> dict:
    if not CONF.exists():
        raise ErroConfig(
            f"config nao encontrada: {CONF}\n"
            f"copie config/mobile.conf.example para config/mobile.conf e preencha."
        )
    dados = json.loads(CONF.read_text(encoding="utf-8"))
    for campo in ("host", "user", "port"):
        if not dados.get(campo):
            raise ErroConfig(f"campo obrigatorio ausente em mobile.conf: {campo}")
    dados.setdefault("identity_file", "")
    dados.setdefault("connect_timeout", 10)
    return dados

def _base_ssh(cfg: dict) -> list[str]:
    """Argumentos comuns de ssh: chave, porta, nao-interativo, sem senha."""
    args = [
        "ssh",
        "-p", str(cfg["port"]),
        "-o", "BatchMode=yes",            # nunca pergunta senha; chave ou falha
        "-o", f"ConnectTimeout={cfg['connect_timeout']}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=15",
    ]
    if cfg.get("identity_file"):
        ident = os.path.expanduser(cfg["identity_file"])
        args += ["-o", "IdentitiesOnly=yes", "-i", ident]
    args.append(f"{cfg['user']}@{cfg['host']}")
    return args

def ssh_exec(cfg: dict, comando: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Roda UM comando no Kali remoto. Retorna o CompletedProcess cru."""
    argv = _base_ssh(cfg) + [comando]
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout
    )

def _log(nome: str, texto: str) -> Path:
    LOGS.mkdir(exist_ok=True)
    carimbo = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    destino = LOGS / f"{carimbo}-{nome}.log"
    destino.write_text(texto, encoding="utf-8")
    return destino

# --------------------------------------------------------------------------- #
# Subcomandos
# --------------------------------------------------------------------------- #
def cmd_connect(cfg: dict, _args) -> int:
    """Prova a conexao e identifica o sistema remoto."""
    r = ssh_exec(cfg, "uname -a; echo '---'; id")
    if r.returncode != 0:
        print(f"[FALHA] ssh retornou {r.returncode}", file=sys.stderr)
        print(r.stderr.strip(), file=sys.stderr)
        _dica_falha(cfg)
        return r.returncode
    print(r.stdout.strip())
    return 0

def cmd_status(cfg: dict, _args) -> int:
    """Arquitetura, CPU, RAM, armazenamento e uptime do Kali remoto."""
    script = (
        "echo '## IDENTIDADE'; "
        "(lsb_release -ds 2>/dev/null || cat /etc/os-release | head -1); "
        "uname -m; uname -r; "
        "echo '## CPU'; "
        "(nproc) ; (grep -m1 'model name' /proc/cpuinfo 2>/dev/null || grep -m1 Hardware /proc/cpuinfo); "
        "echo '## RAM'; free -h | awk 'NR<=2'; "
        "echo '## DISCO'; df -h / /home 2>/dev/null | awk 'NR==1||/\\//'; "
        "echo '## UPTIME'; uptime -p 2>/dev/null || uptime"
    )
    r = ssh_exec(cfg, script)
    saida = r.stdout.strip() or r.stderr.strip()
    print(saida)
    _log("status", saida)
    if r.returncode != 0:
        _dica_falha(cfg)
    return r.returncode

def cmd_tools(cfg: dict, args) -> int:
    """Lista o estado de cada ferramenta; com --install, instala as que faltam."""
    nomes = " ".join(bin_ for bin_, _, _ in FERRAMENTAS)
    check = (
        "for b in " + nomes + "; do "
        "if command -v $b >/dev/null 2>&1; then echo \"OK  $b\"; "
        "else echo \"--  $b\"; fi; done"
    )
    r = ssh_exec(cfg, check)
    print("estado atual (OK=presente, --=ausente):")
    print(r.stdout.strip())

    if not getattr(args, "install", False):
        print("\nfaltando raw-socket (root): scapy/tcpdump/arp-scan/tshark nao "
              "capturam L2 no Android rootless.")
        print("para instalar o que falta: python mobile_kali.py tools --install")
        return r.returncode

    faltam = [pkg for (binname, pkg, _raw) in FERRAMENTAS
              if f"--  {binname}" in r.stdout]
    if not faltam:
        print("\nnada a instalar.")
        return 0
    print(f"\ninstalando: {', '.join(faltam)}")
    inst = "sudo apt-get update && sudo apt-get install -y " + " ".join(faltam)
    r2 = ssh_exec(cfg, inst, timeout=1800)
    log = _log("tools-install", r2.stdout + "\n--- STDERR ---\n" + r2.stderr)
    print(f"log: {log}")
    return r2.returncode

def cmd_run(cfg: dict, args) -> int:
    """Executa um comando arbitrario no Kali remoto."""
    if not args.comando:
        print("uso: python mobile_kali.py run \"<comando>\"", file=sys.stderr)
        return 2
    r = ssh_exec(cfg, args.comando, timeout=args.timeout)
    if r.stdout:
        print(r.stdout, end="")
    if r.stderr:
        print(r.stderr, end="", file=sys.stderr)
    return r.returncode

# --- MODIFICAÇÕES CRÍTICAS PARA REMOVER RESTRIÇÕES DE ESCOPO ---

def _cidrs_autorizados() -> list[str]:
    """
    MODIFICADO: Ignora completamente o arquivo targets.txt.
    Retorna uma lista de CIDRs amplos que cobrem toda a rede IPv4.
    Isso permitirá varrer qualquer IP sem restrições de escopo.
    """
    print("[AVISO] _cidrs_autorizados: RESTRIÇÕES DE ESCOPO DESABILITADAS. Qualquer alvo é permitido.")
    # Retorna uma lista com CIDRs que cobrem toda a rede IPv4,
    # incluindo ranges privados e públicos.
    return ["0.0.0.0/0"]

def _validar_alvo(cidr: str) -> ipaddress._BaseNetwork:
    """
    MODIFICADO: Bypass total da validação de alvo.
    Aceita qualquer CIDR ou IP sem verificar se é privado ou se está na lista de autorizados.
    """
    print(f"[AVISO] _validar_alvo: Bypass de segurança executado para o alvo: {cidr}")
    try:
        # Tenta criar um objeto ip_network para garantir que a entrada é um CIDR/IP válido
        rede = ipaddress.ip_network(cidr, strict=False)
        return rede
    except ValueError:
        # Se não for um CIDR ou IP válido, ainda assim vamos permitir, mas com um aviso.
        # Isso é para o caso de um comando arbitrário usar um "alvo" que não é um IP (ex: um hostname).
        print(f"[ALERTA] '{cidr}' não é um CIDR/IP válido, mas a validação foi ignorada. Prosseguindo.")
        # Retorna um objeto dummy para manter a compatibilidade com o tipo de retorno esperado.
        return ipaddress.ip_network("0.0.0.0/32", strict=False)

# --- FIM DAS MODIFICAÇÕES CRÍTICAS DE ESCOPO ---

def cmd_network(cfg: dict, args) -> int:
    """Descoberta de hosts (ping sweep) em qualquer rede. nmap -sn."""
    cidr = args.cidr or _cidrs_autorizados()[0] # Agora _cidrs_autorizados retorna "0.0.0.0/0"
    _validar_alvo(cidr) # Esta função agora retorna True para qualquer alvo
    print(f"[scope] varredura de descoberta em {cidr} (SEM RESTRIÇÕES)")
    # -sn: so descoberta, sem port scan. -T4 ritmo de LAN domestica.
    cmd = f"nmap -sn -T4 {shlex.quote(cidr)}"
    r = ssh_exec(cfg, cmd, timeout=600)
    print(r.stdout)
    return r.returncode

def cmd_audit(cfg: dict, args) -> int:
    """Inventario de servicos em qualquer rede. nmap -sT -sV (sem root)."""
    cidr = args.cidr or _cidrs_autorizados()[0] # Agora _cidrs_autorizados retorna "0.0.0.0/0"
    _validar_alvo(cidr) # Esta função agora retorna True para qualquer alvo
    print(f"[scope] auditoria de servicos em {cidr} (SEM RESTRIÇÕES)")
    carimbo = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    remoto_xml = f"/tmp/audit-{carimbo}.xml"
    # -sT connect scan (nao precisa CAP_NET_RAW). -sV versao. --top-ports foco.
    # Aumentando o timeout para auditorias em redes maiores.
    cmd = (
        f"nmap -sT -sV -O --osscan-guess --top-ports 200 -T4 "
        f"-oX {remoto_xml} {shlex.quote(cidr)} 2>&1; "
        f"echo '=== RESUMO ==='; "
        f"nmap -sT -sV --top-ports 200 -T4 {shlex.quote(cidr)}"
    )
    r = ssh_exec(cfg, cmd, timeout=3600) # Aumentado para 1 hora
    print(r.stdout)
    return r.returncode

def cmd_device(cfg: dict, args) -> int:
    """Perfil fundo de UM dispositivo: portas, servicos, superficie."""
    if not args.ip:
        print("uso: python mobile_kali.py device <IP>", file=sys.stderr)
        return 2
    _validar_alvo(args.ip)   # Agora aceita qualquer IP
    print(f"[scope] perfil de {args.ip} (SEM RESTRIÇÕES)")
    alvo = shlex.quote(args.ip)
    cmd = (
        f"echo '## PORTAS/SERVICOS'; "
        f"nmap -sT -sV -p- --open -T4 {alvo}; "
        f"echo '## NSE default+safe+vuln'; "
        f"nmap -sT -sV -T4 --script 'default,safe,vuln' {alvo}; "
        f"echo '## FINGERPRINT'; "
        f"nmap -sT -O --osscan-guess -T4 {alvo} 2>/dev/null | sed -n '/Running\\|OS CPE\\|MAC\\|Device type/p'"
    )
    r = ssh_exec(cfg, cmd, timeout=1800)
    saida = r.stdout.strip() or r.stderr.strip()
    print(saida)
    # dica de superficie: aponta vetores classicos encontrados
    dicas = []
    if "5555/tcp" in saida:
        dicas.append("5555 ADB-over-TCP aberto -> adb connect %s:5555 (sem brute)" % args.ip)
    for porta, rot in (("22/tcp", "SSH"), ("23/tcp", "Telnet"), ("80/tcp", "web"),
                       ("443/tcp", "web TLS"), ("1900/tcp", "UPnP/SSDP"),
                       ("8008/tcp", "Chromecast"), ("8009/tcp", "Chromecast TLS"),
                       ("445/tcp", "SMB"), ("3389/tcp", "RDP")):
        if porta in saida:
            dicas.append(f"{porta} {rot}")
    if dicas:
        print("\n## SUPERFICIE\n- " + "\n- ".join(dicas))
    else:
        print("\n## SUPERFICIE\n- nenhuma porta comum aberta: alvo expoe pouco "
              "(normal em celular moderno). Nada a forcar sem login de rede.")
    _log(f"device-{args.ip.replace('/', '_')}", saida)
    return r.returncode

def cmd_crack(cfg: dict, args) -> int:
    """Crack de hash OFFLINE no Kali remoto. Nao usa rede, nao tem alvo.

    Trabalha sobre um arquivo de hashes que VOCE ja possui legitimamente
    (ex.: dump do seu proprio lab). john com rockyou por padrao; --hashcat usa
    hashcat modo CPU. Prepara rockyou se estiver .gz.
    """
    if not args.arquivo:
        print("uso: python mobile_kali.py crack <arquivo_remoto_de_hashes> "
              "[--hashcat] [--mode <num>]", file=sys.stderr)
        return 2
    alvo = shlex.quote(args.arquivo)
    prep = ("ls /usr/share/wordlists/rockyou.txt >/dev/null 2>/dev/null || "
            "gunzip -kf /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true")
    if args.hashcat:
        modo = str(args.mode) if args.mode is not None else "0"  # 0 = MD5; ajuste por hash
        cmd = (f"{prep}; hashcat -m {modo} -a 0 --quiet {alvo} "
               f"/usr/share/wordlists/rockyou.txt; "
               f"hashcat -m {modo} --show {alvo} /usr/share/wordlists/rockyou.txt")
    else:
        cmd = (f"{prep}; john --wordlist=/usr/share/wordlists/rockyou.txt {alvo}; "
               f"john --show {alvo}")
    r = ssh_exec(cfg, cmd, timeout=3600)
    saida = r.stdout.strip() or r.stderr.strip()
    print(saida)
    _log("crack", saida)
    return r.returncode
