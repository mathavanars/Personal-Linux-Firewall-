#!/usr/bin/env python3
"""
Personal Firewall + Suricata IDS/IPS Monitor  (Linux, single file)

* Detects the active network interface and this machine's IP only.
* Rules are host-only: they live in their own iptables chains hooked into
  INPUT/OUTPUT for that interface and that IP. FORWARD is never touched, so
  the rest of the network is unaffected.
* Logs allowed traffic (DNS, DHCP, allowed inbound ports) and blocked traffic.
* Starts Suricata (passive IDS, or inline IPS via NFQUEUE) and shows live
  alerts: port scans, payloads, DoS/DDoS, other signatures.
* Pop-up toasts for every action and alert, Start/Stop button in the UI.

Requirements : python3-tk, iptables, suricata (apt install python3-tk iptables suricata)
Run          : sudo -E python3 personal_firewall.py
"""

import atexit
import json
import os
import queue
import re
import shlex
import shutil
import signal
import socket  # noqa: F401  (kept for easy extension)
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk

APP = "Personal Firewall"
CHAIN_IN, CHAIN_OUT = "PFW_IN", "PFW_OUT"
QUEUE_NUM = 0
BASE_DIR = "/var/log/personal_firewall"
SURI_DIR = os.path.join(BASE_DIR, "suricata")
RULES_FILE = os.path.join(SURI_DIR, "pfw-local.rules")
BPF_FILE = os.path.join(SURI_DIR, "host.bpf")
EVE_FILE = os.path.join(SURI_DIR, "eve.json")
SURI_OUT = os.path.join(SURI_DIR, "suricata.out")
LOG_FILE = os.path.join(BASE_DIR, "pfw.log")
MAX_ROWS = 2000


# --------------------------------------------------------------------------- helpers
def now():
    return datetime.now().strftime("%H:%M:%S")


def run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as exc:  # noqa: BLE001
        return 1, str(exc)


def stop_proc(p, timeout=10):
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout)
        except subprocess.TimeoutExpired:
            p.kill()


def detect_network():
    """Return (interface, ip) of the active default-route interface, or (None, None)."""
    rc, out = run(["ip", "-4", "route", "get", "1.1.1.1"])
    dev, src = re.search(r"\bdev\s+(\S+)", out), re.search(r"\bsrc\s+(\S+)", out)
    if rc == 0 and dev and src:
        return dev.group(1), src.group(1)
    rc, out = run(["ip", "-4", "route", "show", "default"])
    dev = re.search(r"\bdev\s+(\S+)", out)
    if dev:
        _, o2 = run(["ip", "-4", "-o", "addr", "show", "dev", dev.group(1)])
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", o2)
        if m:
            return dev.group(1), m.group(1)
    return None, None


def parse_ports(text):
    ports = []
    for p in re.split(r"[,\s]+", text.strip()):
        if not p:
            continue
        if not p.isdigit() or not 1 <= int(p) <= 65535:
            raise ValueError(p)
        ports.append(p)
    return ports


def ep(ip, port):
    return f"{ip}:{port}" if port else (ip or "-")


# --------------------------------------------------------------------------- firewall
class Firewall:
    """Host-only iptables rules in dedicated chains (never touches FORWARD)."""

    def __init__(self):
        self.ipt = shutil.which("iptables")

    def _i(self, *a):
        return run([self.ipt, "-w", "5", *a])

    def remove(self):
        if not self.ipt:
            return
        for hook, chain in (("INPUT", CHAIN_IN), ("OUTPUT", CHAIN_OUT)):
            _, out = self._i("-S", hook)
            for line in out.splitlines():
                if line.endswith(f"-j {chain}"):
                    self._i(*shlex.split(line.replace("-A", "-D", 1)))
            self._i("-F", chain)
            self._i("-X", chain)

    def apply(self, iface, ip, ports, ips_mode):
        if not self.ipt:
            return False, "iptables not found"
        self.remove()
        acc = (["NFQUEUE", "--queue-num", str(QUEUE_NUM), "--queue-bypass"]
               if ips_mode else ["ACCEPT"])
        lim = ["-m", "limit", "--limit", "10/s", "--limit-burst", "20"]

        def log(prefix, *pre):
            return [*pre, "-j", "LOG", "--log-prefix", prefix]

        rin = [
            # DHCP replies (no IP match: lease traffic uses 0.0.0.0/broadcast)
            log("PFW-ALLOW-DHCP-IN ", "-p", "udp", "--sport", "67", "--dport", "68"),
            ["-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT"],
            ["!", "-d", ip, "-j", "RETURN"],          # only evaluate traffic to MY ip
            log("PFW-BLOCK-INVALID ", *lim, "-m", "conntrack", "--ctstate", "INVALID"),
            ["-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"],
            ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", *acc],
        ]
        for p in ports:
            rin.append(log("PFW-ALLOW-IN ", "-p", "tcp", "--dport", p,
                           "-m", "conntrack", "--ctstate", "NEW"))
            rin.append(["-p", "tcp", "--dport", p, "-j", *acc])
        rin += [log("PFW-BLOCK-IN ", *lim), ["-j", "DROP"]]

        rout = [
            log("PFW-ALLOW-DHCP-OUT ", "-p", "udp", "--sport", "68", "--dport", "67"),
            ["-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"],
            ["!", "-s", ip, "-j", "RETURN"],          # only evaluate traffic from MY ip
            log("PFW-ALLOW-DNS ", "-m", "limit", "--limit", "20/s", "--limit-burst", "40",
                "-p", "udp", "--dport", "53"),
            log("PFW-ALLOW-DNS ", "-m", "limit", "--limit", "20/s", "--limit-burst", "40",
                "-p", "tcp", "--dport", "53", "-m", "conntrack", "--ctstate", "NEW"),
            ["-j", *acc],
        ]

        steps = [("-N", CHAIN_IN), ("-N", CHAIN_OUT)]
        steps += [("-A", CHAIN_IN, *r) for r in rin]
        steps += [("-A", CHAIN_OUT, *r) for r in rout]
        steps += [("-I", "INPUT", "1", "-i", iface, "-j", CHAIN_IN),
                  ("-I", "OUTPUT", "1", "-o", iface, "-j", CHAIN_OUT)]
        for s in steps:
            rc, out = self._i(*s)
            if rc != 0:
                self.remove()
                return False, f"iptables {' '.join(s)} failed: {out}"
        return True, "ok"


# --------------------------------------------------------------------------- kernel log reader
KV = re.compile(r"(\w+)=(\S*)")


def parse_fw(line):
    m = re.search(r"PFW-([A-Z0-9-]+)\s", line)
    if not m:
        return None
    kv = dict(KV.findall(line[m.end():]))
    return {"tag": m.group(1), "src": kv.get("SRC", "-"), "dst": kv.get("DST", "-"),
            "proto": kv.get("PROTO", "-"), "spt": kv.get("SPT", ""), "dpt": kv.get("DPT", ""),
            "in": kv.get("IN", ""), "out": kv.get("OUT", "")}


class FwLogReader(threading.Thread):
    def __init__(self, ev):
        super().__init__(daemon=True)
        self.ev, self.proc, self.halt = ev, None, False

    def run(self):
        for cmd in (["journalctl", "-k", "-f", "-n", "0", "-o", "cat", "--no-pager"],
                    ["dmesg", "--follow-new"]):
            if not shutil.which(cmd[0]):
                continue
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL, text=True, bufsize=1)
            except OSError:
                continue
            for line in self.proc.stdout:
                d = parse_fw(line)
                if d:
                    self.ev.put(("fw", d))
            if self.halt:
                return
        if not self.halt:
            self.ev.put(("log", "error", "Cannot read kernel log (journalctl/dmesg).", True))

    def stop(self):
        self.halt = True
        stop_proc(self.proc, 3)


# --------------------------------------------------------------------------- suricata
LOCAL_RULES = r"""
@A@ tcp any any -> $HOME_NET any (msg:"PFW Port scan (many SYNs from one source)"; flags:S,12; threshold:type both, track by_src, count 25, seconds 10; classtype:attempted-recon; sid:9000001; rev:1;)
@A@ tcp any any -> $HOME_NET any (msg:"PFW Xmas scan"; flags:FPU,12; classtype:attempted-recon; sid:9000006; rev:1;)
@A@ tcp any any -> $HOME_NET any (msg:"PFW NULL scan"; flags:0; classtype:attempted-recon; sid:9000007; rev:1;)
@A@ icmp any any -> $HOME_NET any (msg:"PFW ICMP flood (DoS/DDoS)"; itype:8; threshold:type both, track by_dst, count 100, seconds 5; classtype:attempted-dos; sid:9000002; rev:1;)
@A@ tcp any any -> $HOME_NET any (msg:"PFW SYN flood (DoS/DDoS)"; flags:S,12; threshold:type both, track by_dst, count 200, seconds 5; classtype:attempted-dos; sid:9000003; rev:1;)
@A@ udp any any -> $HOME_NET any (msg:"PFW UDP flood (DoS/DDoS)"; threshold:type both, track by_dst, count 200, seconds 5; classtype:attempted-dos; sid:9000004; rev:1;)
@A@ tcp any any -> $HOME_NET any (msg:"PFW Suspicious payload: /bin/sh"; content:"/bin/sh"; nocase; classtype:shellcode-detect; sid:9000010; rev:1;)
@A@ tcp any any -> $HOME_NET any (msg:"PFW Suspicious payload: cmd.exe"; content:"cmd.exe"; nocase; classtype:shellcode-detect; sid:9000011; rev:1;)
@A@ tcp any any -> $HOME_NET any (msg:"PFW Suspicious payload: path traversal /etc/passwd"; content:"/etc/passwd"; nocase; classtype:web-application-attack; sid:9000012; rev:1;)
@A@ tcp any any -> $HOME_NET any (msg:"PFW Suspicious payload: SQL injection"; content:"union select"; nocase; classtype:web-application-attack; sid:9000013; rev:1;)
"""


class Suricata:
    def __init__(self, ev):
        self.ev, self.proc, self.outf = ev, None, None
        self.halt = threading.Event()

    def start(self, iface, ip, ips_mode):
        exe = shutil.which("suricata")
        if not exe:
            return False, "Suricata not found (sudo apt install suricata)"
        cfg = next((p for p in ("/etc/suricata/suricata.yaml",
                                "/usr/local/etc/suricata/suricata.yaml") if os.path.exists(p)), None)
        if not cfg:
            return False, "suricata.yaml not found"
        os.makedirs(SURI_DIR, mode=0o750, exist_ok=True)
        with open(RULES_FILE, "w") as f:
            f.write(LOCAL_RULES.replace("@A@", "drop" if ips_mode else "alert"))
        with open(BPF_FILE, "w") as f:
            f.write(f"host {ip}\n")
        for p in (EVE_FILE, os.path.join(SURI_DIR, "suricata.pid")):
            if os.path.exists(p):
                os.remove(p)
        cmd = [exe, "-c", cfg, "-l", SURI_DIR, "-k", "none", "-s", RULES_FILE,
               "--pidfile", os.path.join(SURI_DIR, "suricata.pid"),
               "--set", f"vars.address-groups.HOME_NET=[{ip}/32]"]
        cmd += ["-q", str(QUEUE_NUM)] if ips_mode else ["-i", iface, "-F", BPF_FILE]
        self.outf = open(SURI_OUT, "w")
        try:
            self.proc = subprocess.Popen(cmd, stdout=self.outf, stderr=subprocess.STDOUT)
        except OSError as exc:
            return False, str(exc)
        self.halt.clear()
        threading.Thread(target=self._watch, daemon=True).start()
        threading.Thread(target=self._tail_eve, daemon=True).start()
        return True, "starting"

    def _watch(self):
        ready, t0 = False, time.time()
        while not self.halt.is_set():
            rc = self.proc.poll()
            if rc is not None:
                try:
                    tail = " | ".join(open(SURI_OUT).read().strip().splitlines()[-4:])
                except OSError:
                    tail = ""
                self.ev.put(("log", "error", f"Suricata exited (code {rc}). {tail[:300]}", True))
                return
            if not ready:
                try:
                    if "engine started" in open(SURI_OUT).read():
                        ready = True
                        self.ev.put(("log", "ok", "Suricata engine started - monitoring live", True))
                except OSError:
                    pass
                if not ready and time.time() - t0 > 180:
                    self.ev.put(("log", "warn", "Suricata is taking long to load rules...", True))
                    t0 = time.time() + 10 ** 6
            time.sleep(1)

    def _tail_eve(self):
        while not self.halt.is_set() and not os.path.exists(EVE_FILE):
            time.sleep(0.5)
        if self.halt.is_set():
            return
        with open(EVE_FILE, "r") as f:
            while not self.halt.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.3)
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if d.get("event_type") == "alert":
                    a = d.get("alert", {})
                    self.ev.put(("alert", {
                        "sig": a.get("signature", "?"), "sev": a.get("severity", 3),
                        "action": a.get("action", "alert"), "cat": a.get("category", ""),
                        "src": d.get("src_ip", "-"), "spt": d.get("src_port", ""),
                        "dst": d.get("dest_ip", "-"), "dpt": d.get("dest_port", ""),
                        "proto": d.get("proto", "-")}))

    def stop(self):
        self.halt.set()
        stop_proc(self.proc, 12)
        if self.outf:
            try:
                self.outf.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- toast pop-ups
class Toaster:
    COL = {"info": "#3b82f6", "ok": "#22c55e", "warn": "#f59e0b", "alert": "#ef4444",
           "error": "#ef4444"}
    W, H, GAP, MAX = 380, 78, 8, 5

    def __init__(self, root):
        self.root, self.items = root, []

    def show(self, title, msg, level="info", ms=6000):
        if len(self.items) >= self.MAX:
            self._close(self.items[0])
        col = self.COL.get(level, self.COL["info"])
        top = tk.Toplevel(self.root)
        top.overrideredirect(True)
        try:
            top.attributes("-topmost", True)
        except tk.TclError:
            pass
        frm = tk.Frame(top, bg="#111827", highlightbackground=col, highlightthickness=2)
        frm.pack(fill="both", expand=True)
        tk.Label(frm, text=title, bg="#111827", fg=col, anchor="w",
                 font=("TkDefaultFont", 10, "bold")).pack(fill="x", padx=10, pady=(6, 0))
        tk.Label(frm, text=msg[:130], bg="#111827", fg="white", anchor="w", justify="left",
                 wraplength=self.W - 24).pack(fill="x", padx=10, pady=(0, 6))
        for w in (top, frm, *frm.winfo_children()):
            w.bind("<Button-1>", lambda e, t=top: self._close(t))
        self.items.append(top)
        self._layout()
        top.after(ms, lambda t=top: self._close(t))

    def _close(self, top):
        if top in self.items:
            self.items.remove(top)
        try:
            top.destroy()
        except tk.TclError:
            pass
        self._layout()

    def _layout(self):
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        y = sh - 60
        for t in reversed(self.items):
            y -= self.H + self.GAP
            try:
                t.geometry(f"{self.W}x{self.H}+{sw - self.W - 20}+{y}")
            except tk.TclError:
                pass


# --------------------------------------------------------------------------- GUI
class App:
    def __init__(self, root):
        self.root = root
        root.title(APP + " + Suricata IDS/IPS")
        root.geometry("1100x660")
        self.ev = queue.Queue()
        self.fw = Firewall()
        self.suri = Suricata(self.ev)
        self.reader = None
        self.running = False
        self.last = {}
        self.cnt = {"allowed": 0, "blocked": 0, "alerts": 0}
        self.toaster = Toaster(root)
        self.iface = self.ip = None

        self.ips_var = tk.BooleanVar(value=False)
        self.allowed_var = tk.BooleanVar(value=False)
        self.ports_var = tk.StringVar(value="")
        self.net_var = tk.StringVar()
        self.status_var = tk.StringVar(value="STOPPED")
        self.stats_var = tk.StringVar()
        self._build()
        self.refresh_net()
        self._stats()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(200, self._poll)

    # ---- layout
    def _build(self):
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill="x")
        ttk.Label(top, textvariable=self.net_var, font=("TkDefaultFont", 11, "bold")).pack(side="left")
        ttk.Button(top, text="Refresh", command=self.refresh_net).pack(side="left", padx=8)
        self.btn = ttk.Button(top, text="▶ Start Monitoring", command=self.toggle)
        self.btn.pack(side="right")
        self.status_lbl = ttk.Label(top, textvariable=self.status_var, foreground="#dc2626",
                                    font=("TkDefaultFont", 11, "bold"))
        self.status_lbl.pack(side="right", padx=12)

        opt = ttk.Frame(self.root, padding=(8, 0))
        opt.pack(fill="x")
        self.opt_widgets = [
            ttk.Checkbutton(opt, text="IPS mode (inline NFQUEUE, drops attacks)", variable=self.ips_var),
            ttk.Label(opt, text="   Allow inbound TCP ports:"),
            ttk.Entry(opt, textvariable=self.ports_var, width=18),
        ]
        for w in self.opt_widgets:
            w.pack(side="left")
        ttk.Checkbutton(opt, text="   Pop-ups for allowed traffic (DNS/DHCP)",
                        variable=self.allowed_var).pack(side="left")
        ttk.Label(opt, textvariable=self.stats_var).pack(side="right")

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.fw_tree = self._tree(nb, "Firewall Log",
                                  ("Time", "Action", "Type", "Proto", "Source", "Destination", "Iface"),
                                  (80, 80, 130, 60, 200, 200, 120))
        self.fw_tree.tag_configure("ALLOWED", background="#dcfce7")
        self.fw_tree.tag_configure("BLOCKED", background="#fee2e2")
        self.al_tree = self._tree(nb, "Suricata Alerts",
                                  ("Time", "Sev", "Action", "Signature", "Source", "Destination", "Proto"),
                                  (80, 50, 70, 380, 170, 170, 60))
        self.al_tree.tag_configure("high", background="#fecaca")
        self.al_tree.tag_configure("med", background="#fed7aa")
        self.al_tree.tag_configure("low", background="#fef9c3")
        frame = ttk.Frame(nb)
        nb.add(frame, text="Activity")
        self.act = tk.Text(frame, state="disabled", wrap="word", height=10)
        sb = ttk.Scrollbar(frame, command=self.act.yview)
        self.act.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.act.pack(fill="both", expand=True)
        for lvl, col in (("info", "#1d4ed8"), ("ok", "#15803d"), ("warn", "#b45309"),
                         ("alert", "#b91c1c"), ("error", "#b91c1c")):
            self.act.tag_configure(lvl, foreground=col)

    def _tree(self, nb, title, cols, widths):
        frame = ttk.Frame(nb)
        nb.add(frame, text=title)
        tree = ttk.Treeview(frame, columns=cols, show="headings")
        for c, w in zip(cols, widths):
            tree.heading(c, text=c)
            tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        return tree

    # ---- helpers
    def refresh_net(self):
        if self.running:
            return
        self.iface, self.ip = detect_network()
        self.net_var.set(f"Interface: {self.iface}    IP: {self.ip}" if self.iface
                         else "No active network interface detected")

    def _stats(self):
        self.stats_var.set(f"Allowed: {self.cnt['allowed']}   Blocked: {self.cnt['blocked']}   "
                           f"Alerts: {self.cnt['alerts']}")

    def log(self, level, msg):
        line = f"[{now()}] {msg}\n"
        self.act.configure(state="normal")
        self.act.insert("end", line, level)
        self.act.see("end")
        self.act.configure(state="disabled")
        try:
            os.makedirs(BASE_DIR, mode=0o750, exist_ok=True)
            with open(LOG_FILE, "a") as f:
                f.write(f"{datetime.now().isoformat(timespec='seconds')} {level.upper()} {msg}\n")
        except OSError:
            pass

    def notify(self, title, msg, level="info"):
        self.toaster.show(title, msg, level)

    def throttle(self, key, secs):
        t = time.time()
        if t - self.last.get(key, 0) < secs:
            return False
        self.last[key] = t
        if len(self.last) > 5000:
            self.last = {k: v for k, v in self.last.items() if t - v < secs}
        return True

    def _add(self, tree, values, tag):
        iid = tree.insert("", "end", values=values, tags=(tag,))
        tree.see(iid)
        kids = tree.get_children()
        if len(kids) > MAX_ROWS:
            tree.delete(*kids[:len(kids) - MAX_ROWS])

    # ---- start / stop
    def toggle(self):
        self.stop() if self.running else self.start()

    def start(self):
        self.refresh_net()
        if not self.iface or not self.ip:
            messagebox.showerror(APP, "No active network interface found.")
            return
        try:
            ports = parse_ports(self.ports_var.get())
        except ValueError as exc:
            messagebox.showerror(APP, f"Invalid port: {exc}")
            return
        ips = self.ips_var.get()
        ok, msg = self.fw.apply(self.iface, self.ip, ports, ips)
        if not ok:
            self.log("error", msg)
            self.notify("Firewall failed", msg, "error")
            return
        self.log("ok", f"Firewall active on {self.iface} ({self.ip}) - host-only rules, "
                       f"inbound allowed ports: {','.join(ports) or 'none'}")
        self.notify("Firewall enabled", f"{self.iface} / {self.ip} - host-only rules", "ok")

        self.reader = FwLogReader(self.ev)
        self.reader.start()

        ok, msg = self.suri.start(self.iface, self.ip, ips)
        if ok:
            mode = "IPS (inline NFQUEUE)" if ips else "IDS (passive)"
            self.log("info", f"Starting Suricata in {mode} mode, loading rules...")
            self.notify("Suricata starting", f"{mode} mode - loading rules", "info")
        else:
            self.log("error", f"Suricata: {msg}")
            self.notify("Suricata not started", msg, "warn")

        self.running = True
        self.btn.configure(text="■ Stop Monitoring")
        self.status_var.set("MONITORING")
        self.status_lbl.configure(foreground="#16a34a")
        for w in self.opt_widgets:
            w.state(["disabled"]) if hasattr(w, "state") else None

    def stop(self):
        self.fw.remove()
        self.log("info", "Firewall rules removed")
        self.notify("Firewall disabled", "Host firewall rules removed", "warn")
        if self.reader:
            self.reader.stop()
            self.reader = None
        self.running = False
        self.btn.configure(text="▶ Start Monitoring", state="disabled")
        self.status_var.set("STOPPING...")
        self.status_lbl.configure(foreground="#d97706")

        def worker():
            self.suri.stop()
            self.ev.put(("stopped",))
        threading.Thread(target=worker, daemon=True).start()

    def on_close(self):
        try:
            self.fw.remove()
            if self.reader:
                self.reader.stop()
            self.suri.stop()
        finally:
            self.root.destroy()

    # ---- events
    def _poll(self):
        try:
            for _ in range(300):
                self._handle(self.ev.get_nowait())
        except queue.Empty:
            pass
        self.root.after(200, self._poll)

    def _handle(self, e):
        kind = e[0]
        if kind == "log":
            _, level, msg, toast = e
            self.log(level, msg)
            if toast:
                self.notify("Suricata" if "uricata" in msg else APP, msg, level)
        elif kind == "stopped":
            self.log("info", "Suricata stopped")
            self.notify("Monitoring stopped", "Firewall and Suricata are off", "info")
            self.btn.configure(state="normal")
            self.status_var.set("STOPPED")
            self.status_lbl.configure(foreground="#dc2626")
            for w in self.opt_widgets:
                if hasattr(w, "state"):
                    w.state(["!disabled"])
        elif kind == "fw":
            self._fw_event(e[1])
        elif kind == "alert":
            self._alert_event(e[1])

    def _fw_event(self, d):
        allowed = d["tag"].startswith("ALLOW")
        label = "ALLOWED" if allowed else "BLOCKED"
        self.cnt["allowed" if allowed else "blocked"] += 1
        self._stats()
        iface = d["in"] or d["out"]
        self._add(self.fw_tree, (now(), label, d["tag"], d["proto"], ep(d["src"], d["spt"]),
                                 ep(d["dst"], d["dpt"]), iface), label)
        self.log("ok" if allowed else "warn",
                 f"{label} {d['tag']} {d['proto']} {ep(d['src'], d['spt'])} -> {ep(d['dst'], d['dpt'])}")
        key = ("fw", d["tag"], d["src"], d["dst"], d["dpt"])
        if allowed:
            if self.allowed_var.get() and self.throttle(key, 5):
                self.notify(f"Allowed {d['tag']}", f"{ep(d['src'], d['spt'])} -> {ep(d['dst'], d['dpt'])}", "ok")
        elif self.throttle(key, 15):
            self.notify(f"Blocked {d['tag']}", f"{d['proto']} {ep(d['src'], d['spt'])} -> "
                                               f"{ep(d['dst'], d['dpt'])}", "warn")

    def _alert_event(self, d):
        self.cnt["alerts"] += 1
        self._stats()
        sev = d["sev"]
        tag = "high" if sev == 1 else "med" if sev == 2 else "low"
        self._add(self.al_tree, (now(), sev, d["action"], d["sig"], ep(d["src"], d["spt"]),
                                 ep(d["dst"], d["dpt"]), d["proto"]), tag)
        self.log("alert", f"ALERT [{d['action']}] {d['sig']} {ep(d['src'], d['spt'])} -> "
                          f"{ep(d['dst'], d['dpt'])}")
        if self.throttle(("al", d["sig"], d["src"]), 10):
            self.notify("Suricata: " + ("DROPPED" if d["action"] == "blocked" else "ALERT"),
                        f"{d['sig']}\n{d['src']} -> {d['dst']}", "alert" if sev <= 2 else "warn")


# --------------------------------------------------------------------------- main
def main():
    if not sys.platform.startswith("linux"):
        sys.exit("This tool supports Linux only (iptables + Suricata).")
    if os.geteuid() != 0:
        if shutil.which("sudo"):
            print("Root is required - re-launching with sudo...")
            os.execvp("sudo", ["sudo", "-E", sys.executable, *sys.argv])
        sys.exit("Please run as root: sudo -E python3 personal_firewall.py")
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        sys.exit(f"Cannot open display ({exc}). If running with sudo on X11, try: "
                 "xhost +SI:localuser:root")
    app = App(root)
    atexit.register(app.fw.remove)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: app.on_close())
    root.mainloop()


if __name__ == "__main__":
    main()
