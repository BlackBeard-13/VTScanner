import json


CYAN = "\033[96m"
GREEN = "\033[92m"
RESET = "\033[0m"

#fun banner create by claude cause i couldn't be bothered
def print_banner():
    logo = [
        r"__     __  _____ ",
        r"\ \   / / |_   _|",
        r" \ \ / /    | |  ",
        r"  \ V /     | |  ",
        r"   \_/      |_|  ",
    ]
    text = [
        "",
        "S C A N N E R",
        "-------------",
        "file & URL checker",
        "powered by VirusTotal",
    ]

    rows = [f"   {art}   {label}" for art, label in zip(logo, text)]
    width = max(len(row) for row in rows) + 3
    border = "+" + "-" * width + "+"
    blank = "|" + " " * width + "|"

    print()
    print(CYAN + border)
    print(blank)
    for row in rows:
        print("|" + row.ljust(width) + "|")
    print(blank)
    print(border + RESET)
    print(GREEN + "  Drop a file or URL in. Let's see what's lurking." + RESET)




#probably unnessary but this is a safegaurd to avoid decode errors in the program
def safe_json(response):
    try:
        return response.json()
    except ValueError:
        return {}