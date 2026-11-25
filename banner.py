from utils import C

VERSION = "1.0"

BANNER = rf"""{C.CY}{C.BOLD}
  ___        __        ____       _   _
 |_ _|_ __  / _| ___  / ___| __ _| |_| |__   ___ _ __
  | || '_ \| |_ / _ \| |  _ / _` | __| '_ \ / _ \ '__|
  | || | | |  _| (_) | |_| | (_| | |_| | | |  __/ |
 |___|_| |_|_|  \___/ \____|\__,_|\__|_| |_|\___|_|
{C.END}{C.W}   Information Gathering Framework v{VERSION}
   MCA (Cyber Security & Forensics) Project{C.END}
{C.Y}   [!] Use only on targets you own or are authorised to test.{C.END}
"""


def show():
    print(BANNER)
