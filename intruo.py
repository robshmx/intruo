########################################################################################
#   Roberto Salas Hernández
#   Maestría en Seguridad Informática
#   Trabajo de Investigación para Innovar en Seguridad Informática
#   01-01-2022
#
#   MIT License
#   Copyright (c) 2021 Roberto Salas Hernández
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#
#   Credits to the python modules of respective authors
########################################################################################


from __future__ import annotations
import re
import sys
import os
import socket
import requests
import base64
import time
import webbrowser
import json
import platform
import pprint
import whois
import dns.resolver
import base64
from io import BytesIO
from PIL import Image
from enum import Enum
from typing import Any
from datetime import date, datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from Wappalyzer import Wappalyzer, WebPage
from urllib.parse import urlparse

class IntruoConstants(Enum):
    """
    Defining Intruo constants. Usage in main class.
    """
    INTRUO_COMMON_PORTS = {
        '21': 'ftp',
        '22': 'ssh',
        '23': 'telnet',
        '25': 'smtp',
        '53': 'domain name system',
        '80': 'http',
        '110': 'pop3',
        '111': 'rpcbind',
        '135': 'msrpc',
        '139': 'netbios-ssn',
        '143': 'imap',
        '443': 'https',
        '445': 'microsoft-ds',
        '993': 'imaps',
        '995': 'pop3s',
        '1723': 'pptp',
        '3306': 'mysql',
        '3389': 'ms-wbt-server',
        '5900': 'vnc',
        '8080': 'http-proxy',
    }

    INTRUO_GOOGLE_DROKS = {
        'Publicly exposed documents': 'https://www.google.com/search?q=site:!!DOMAIN!!+ext:doc+|+ext:docx+|+ext:odt+|+ext:rtf+|+ext:sxw+|+ext:psw+|+ext:ppt+|+ext:pptx+|+ext:pps+|+ext:csv',
        'Directory listing vulnerabilities': 'https://www.google.com/search?q=site:!!DOMAIN!!+intitle:index.o',
        'Configuration files exposed': 'https://www.google.com/search?q=site:!!DOMAIN!!+ext:xml+|+ext:conf+|+ext:cnf+|+ext:reg+|+ext:inf+|+ext:rdp+|+ext:cfg+|+ext:txt+|+ext:ora+|+ext:ini+|+ext:env',
        'Database files exposed': 'https://www.google.com/search?q=site:!!DOMAIN!!+ext:sql+|+ext:dbf+|+ext:mdb',
        'Log files exposed': 'https://www.google.com/search?q=site:!!DOMAIN!!+ext:log',
        'Backup and old files': 'f+q=site:!!DOMAIN!!ext:bkf+|+ext:bkp+|+ext:bak+|+ext:old+|+ext:backup',
        'Login pages': 'https://www.google.com/search?q=site:!!DOMAIN!!+inurl:login+|+inurl:signin+|+intitle:Login+|+intitle:"sign+in"+|+inurl:auth',
        'SQL errors': 'https://www.google.com/search?q=site:!!DOMAIN!!+intext:"sql+syntax+near"+|+intext:"syntax+error+has+occurred"+|+intext:"incorrect+syntax+near"+|+intext:"unexpected+end+of+SQL+command"+|+intext:"Warning:+mysql_connect()"+|+intext:"Warning:+mysql_query()"+|+intext:"Warning:+pg_connect()"',
        'PHP errors / warning': 'https://www.google.com/search?q=site:!!DOMAIN!!+"PHP+Parse+error"+|+"PHP+Warning"+|+"PHP+Error"',
        'phpinfo()': 'https://www.google.com/search?q=site:!!DOMAIN!!+ext:php+intitle:phpinfo+"published+by+the+PHP+Group"',
        'Search pastebin.com / pasting sites': 'https://www.google.com/search?site:pastebin.com%20|%20site:paste2.org%20|%20site:pastehtml.com%20|%20site:slexy.org%20|%20site:snipplr.com%20|%20site:snipt.net%20|%20site:textsnip.com%20|%20site:bitpaste.app%20|%20site:justpaste.it%20|%20site:heypasteit.com%20|%20site:hastebin.com%20|%20site:dpaste.org%20|%20site:dpaste.com%20|%20site:codepad.org%20|%20site:jsitor.com%20|%20site:codepen.io%20|%20site:jsfiddle.net%20|%20site:dotnetfiddle.net%20|%20site:phpfiddle.org%20|%20site:ide.geeksforgeeks.org%20|%20site:repl.it%20|%20site:ideone.com%20|%20site:paste.debian.net%20|%20site:paste.org%20|%20site:paste.org.ru%20|%20site:codebeautify.org%20%20|%20site:codeshare.io%20|%20site:trello.com%20"!!DOMAIN!!"',
        'Search github.com and gitlab.com': 'https://www.google.com/search?q=site:github.com%20|%20site:gitlab.com%20"!!DOMAIN!!"',
        'Search stackoverflow.com': 'https://www.google.com/search?q=site:stackoverflow.com%20"!!DOMAIN!!"+',
        'Signup pages': 'https://www.google.com/search?q=site:!!DOMAIN!!+inurl:signup+|+inurl:register+|+intitle:Signup',
    }

    INTRUO_OWASP_SECURE_HEADERS_PROJECT = {
        'Strict-Transport-Security': {
            'admited_values': {
                'max-age': { 'secure': True, 'desc': 'The time, in seconds, that the browser should remember that this site is only to be accessed using HTTPS.' },
                'includeSubDomains': { 'secure': True, 'desc': 'If this optional parameter is specified, this rule applies to all of the site’s subdomains as well.' },
            },
            'deprecated': False,
            'desc': 'HTTP Strict Transport Security (also named HSTS) is a web security policy mechanism which helps to protect websites against protocol downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers (or other complying user agents) should only interact with it using secure HTTPS connections, and never via the insecure HTTP protocol. HSTS is an IETF standards track protocol and is specified in RFC 6797. A server implements an HSTS policy by supplying a header (Strict-Transport-Security) over an HTTPS connection (HSTS headers over HTTP are ignored).',
            'refs': [
                'https://tools.ietf.org/html/rfc6797',
                'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
                'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security.html',
                'https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security',
                'https://www.chromium.org/hsts',
                'https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security',
                'https://raymii.org/s/tutorials/HTTP_Strict_Transport_Security_for_Apache_NGINX_and_Lighttpd.html',
                'https://blogs.windows.com/msedgedev/2015/06/09/http-strict-transport-security-comes-to-internet-explorer-11-on-windows-8-1-and-windows-7/',
            ]
        },

        'X-Frame-Options': {
            'admited_values': {
                'deny': { 'secure': True, 'desc': 'No rendering within a frame.' },
                'sameorigin': { 'secure': True, 'desc': 'No rendering if origin mismatch.' },
                'allow-from': { 'secure': True, 'desc': 'Allows rendering if framed by frame loaded from DOMAIN.' },
            },
            'deprecated': False,
            'desc': 'The X-Frame-Options response header (also named XFO) improves the protection of web applications against clickjacking. It instructs the browser whether the content can be displayed within frames. The CSP frame-ancestors directive obsoletes the X-Frame-Options header. If a resource has both policies, the CSP frame-ancestors policy will be enforced and the X-Frame-Options policy will be ignored.',
            'refs': [
                'https://tools.ietf.org/html/rfc7034',
                'https://tools.ietf.org/html/draft-ietf-websec-x-frame-options-01',
                'https://tools.ietf.org/html/draft-ietf-websec-frame-options-00',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/X-Frame-Options',
                'https://owasp.org/www-community/attacks/Clickjacking',
                'https://blogs.msdn.microsoft.com/ieinternals/2010/03/30/combating-clickjacking-with-x-frame-options/',
            ]
        },

        'X-Content-Type-Options': {
            'admited_values': {
                'nosniff': { 'secure': True, 'desc': 'Will prevent the browser from MIME-sniffing a response away from the declared content-type.' }
            },
            'deprecated': False,
            'desc': 'Setting this header will prevent the browser from interpreting files as a different MIME type to what is specified in the Content-Type HTTP header (e.g. treating text/plain as text/css).',
            'refs': [
                'https://msdn.microsoft.com/en-us/library/gg622941%28v=vs.85%29.aspx',
                'https://blogs.msdn.microsoft.com/ie/2008/09/02/ie8-security-part-vi-beta-2-update/',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
            ]
        },

        'Content-Security-Policy': {
            'admited_values': {
                'base-uri': { 'secure': True, 'desc': 'Define  the base URI for relative URIs.'},
                'default-src': { 'secure': True, 'desc': 'Define loading policy for all resources type in case a resource type’s dedicated directive is not defined (fallback).'},
                'script-src': { 'secure': True, 'desc': 'Define which scripts the protected resource can execute.'},
                'object-src': { 'secure': True, 'desc': 'Define from where the protected resource can load plugins.'},
                'style-src': { 'secure': True, 'desc': 'Define which styles (CSS) can be applied to the protected resource.'},
                'img-src': { 'secure': True, 'desc': 'Define from where the protected resource can load images.'},
                'media-src': { 'secure': True, 'desc': 'Define from where the protected resource can load video and audio.'},
                'frame-src': { 'secure': True, 'desc': '(Deprecated and replaced by child-src) Define from where the protected resource can embed frames.'},
                'child-src': { 'secure': True, 'desc': 'Define from where the protected resource can embed frames.'},
                'frame-ancestors': { 'secure': True, 'desc': 'Define from where the protected resource can be embedded in frames.'},
                'font-src': { 'secure': True, 'desc': 'Define from where the protected resource can load fonts.'},
                'connect-src': { 'secure': True, 'desc': 'Define which URIs the protected resource can load using script interfaces.'},
                'manifest-src': { 'secure': True, 'desc': 'Define from where the protected resource can load manifests.'},
                'form-action': { 'secure': True, 'desc': 'Define which URIs can be used as the action of HTML form elements.'},
                'sandbox': { 'secure': True, 'desc': 'Specifies an HTML sandbox policy that the user agent applies to the protected resource.'},
                'script-nonce': { 'secure': True, 'desc': 'Define script execution by requiring the presence of the specified nonce on script elements.'},
                'plugin-types': { 'secure': True, 'desc': 'Define the set of plugins that can be invoked by the protected resource by limiting the types of resources that can be embedded.'},
                'reflected-xss': { 'secure': True, 'desc': 'Instruct the user agent to activate or deactivate any heuristics used to filter or block reflected cross-site scripting attacks, equivalent to the effects of the non-standard X-XSS-Protection header.'},
                'block-all-mixed-content': { 'secure': True, 'desc': 'Prevent the user agent from loading mixed content.'},
                'upgrade-insecure-requests': { 'secure': True, 'desc': 'Instruct the user agent to download insecure HTTP resources using HTTPS.'},
                'referrer': { 'secure': True, 'desc': '(Deprecated) Define information the user agent can send in the Referer header.'},
                'report-uri': { 'secure': True, 'desc': '(Deprecated and replaced by report-to) Specifies a URI to which the user agent sends reports about policy violation.'},
                'report-to': { 'secure': True, 'desc': 'Specifies a group (defined in the Report-To header) to which the user agent sends reports about policy violation.'},
            },
            'deprecated': False,
            'desc': 'A Content Security Policy (also named CSP) requires careful tuning and precise definition of the policy. If enabled, CSP has significant impact on the way browsers render pages (e.g., inline JavaScript is disabled by default and must be explicitly allowed in the policy). CSP prevents a wide range of attacks, including cross-site scripting and other cross-site injections.',
            'refs': [
                'https://www.w3.org/TR/CSP/',
                'https://developer.mozilla.org/en-US/docs/Web/Security/CSP',
                'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
                'https://scotthelme.co.uk/content-security-policy-an-introduction/',
                'https://report-uri.io',
                'https://content-security-policy.com',
                'https://report-uri.com/home/generate',
                'https://csp-evaluator.withgoogle.com/',
            ]
        },

        'X-Permitted-Cross-Domain-Policies': {
            'admited_values': {
                'none': { 'secure': False, 'desc': 'No policy files are allowed anywhere on the target server, including this master policy file.' },
                'master-only': { 'secure': True, 'desc': 'Only this master policy file is allowed.' },
                'by-content-type': { 'secure': True, 'desc': '[HTTP/HTTPS only] Only policy files served with Content-Type: text/x-cross-domain-policy are allowed.' },
                'by-ftp-filename': { 'secure': True, 'desc': '[FTP only] Only policy files whose file names are crossdomain.xml (i.e. URLs ending in /crossdomain.xml) are allowed.' },
                'all': { 'secure': True, 'desc': 'All policy files on this target domain are allowed.' },
            },
            'deprecated': False,
            'desc': 'A cross-domain policy file is an XML document that grants a web client, such as Adobe Flash Player or Adobe Acrobat (though not necessarily limited to these), permission to handle data across domains. When clients request content hosted on a particular source domain and that content makes requests directed towards a domain other than its own, the remote domain needs to host a cross-domain policy file that grants access to the source domain, allowing the client to continue the transaction. Normally a meta-policy is declared in the master policy file, but for those who can’t write to the root directory, they can also declare a meta-policy using the X-Permitted-Cross-Domain-Policies HTTP response header.',
            'refs': [
                'https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html',
                'https://danielnixon.org/http-security-headers/',
                'https://rorsecurity.info/portfolio/new-http-headers-for-more-security',
                'https://github.com/twitter/secureheaders/issues/88',
                'https://gf.dev/cross-domain-policy-test',
            ]
        },

        'Referrer-Policy': {
            'admited_values': {
                'no-referrer': { 'secure': True, 'desc': 'The Referer header will be omitted entirely. No referrer information is sent along with requests.'},
                'no-referrer-when-downgrade': { 'secure': True, 'desc': 'This is the user agent’s default behavior if no policy is specified. The origin is sent as referrer to a-priori as-much-secure destination (HTTPS → HTTPS), but isn’t sent to a less secure destination (HTTPS → HTTP).'},
                'origin': { 'secure': True, 'desc': 'Only send the origin of the document as the referrer in all cases. (e.g. the document https://example.com/page.html will send the referrer https://example.com/.)'},
                'origin-when-cross-origin': { 'secure': True, 'desc': 'Send a full URL when performing a same-origin request, but only send the origin of the document for other cases.'},
                'same-origin': { 'secure': True, 'desc': 'A referrer will be sent for same-site origins, but cross-origin requests will contain no referrer information.'},
                'strict-origin': { 'secure': True, 'desc': 'Only send the origin of the document as the referrer to a-priori as-much-secure destination (HTTPS → HTTPS), but don’t send it to a less secure destination (HTTPS → HTTP).'},
                'strict-origin-when-cross-origin': { 'secure': True, 'desc': 'Send a full URL when performing a same-origin request, only send the origin of the document to a-priori as-much-secure destination (HTTPS → HTTPS), and send no header to a less secure destination (HTTPS → HTTP).'},
                'unsafe-url': { 'secure': True, 'desc': 'Send a full URL (stripped from parameters) when performing a a same-origin or cross-origin request.'},
            },
            'deprecated': False,
            'desc': 'The Referrer-Policy HTTP header governs which referrer information, sent in the Referer header, should be included with requests made.',
            'refs': [
                'https://www.w3.org/TR/referrer-policy/',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
            ]
        },

        'Clear-Site-Data': {
            'admited_values': {
                'cache': { 'secure': True, 'desc': 'Indicates that the server wishes to remove locally cached data for the origin of the response URL.' },
                'cookies': { 'secure': True, 'desc': 'Indicates that the server wishes to remove all cookies for the origin of the response URL. HTTP authentication credentials are also cleared out. This affects the entire registered domain, including subdomains.' },
                'storage': { 'secure': True, 'desc': 'Indicates that the server wishes to remove all DOM storage for the origin of the response URL.' },
                'executionContexts': { 'secure': True, 'desc': 'Indicates that the server wishes to reload all browsing contexts for the origin of the response. Currently, this value is only supported by a small subset of browsers.' },
                '*': { 'secure': True, 'desc': 'Indicates that the server wishes to clear all types of data for the origin of the response. If more data types are added in future versions of this header, they will also be covered by it.' },
            },
            'deprecated': False,
            'desc': 'The Clear-Site-Data header clears browsing data (cookies, storage, cache) associated with the requesting website. It allows web developers to have more control over the data stored locally by a browser for their origins (source Mozilla MDN). This header is useful for example, during a logout process, in order to ensure that all stored content on the client side like cookies, storage and cache are removed.',
            'refs': [
                'https://w3c.github.io/webappsec-clear-site-data/',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data',
                'https://www.chromestatus.com/feature/4713262029471744',
                'https://github.com/w3c/webappsec-clear-site-data',
                'https://github.com/w3c/webappsec-clear-site-data/tree/master/demo',
            ]
        },

        'Cross-Origin-Embedder-Policy': {
            'admited_values': {
                'unsafe-none': { 'secure': False, 'desc': 'Allows the document to fetch cross-origin resources without giving explicit permission through the CORS protocol or the Cross-Origin-Resource-Policy header (it is the default value).'},
                'require-corp': { 'secure': True, 'desc': 'A document can only load resources from the same origin, or resources explicitly marked as loadable from another origin.'},
            },
            'deprecated': False,
            'desc': 'This response header (also named COEP) prevents a document from loading any cross-origin resources that don’t explicitly grant the document permission (source Mozilla MDN).',
            'refs': [
                'https://html.spec.whatwg.org/multipage/origin.html#coep',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy',
                'https://caniuse.com/?search=Cross-Origin-Embedder-Policy',
                'https://web.dev/coop-coep/',
                'https://web.dev/why-coop-coep/',
                'https://web.dev/cross-origin-isolation-guide/',
            ]
        },

        'Cross-Origin-Opener-Policy': {
            'admited_values': {
                'unsafe-none': { 'secure': False, 'desc': 'Allows the document to be added to its opener’s browsing context group unless the opener itself has a COOP of same-origin or same-origin-allow-popups (it is the default value).'},
                'same-origin-allow-popups': { 'secure': True, 'desc': 'Retains references to newly opened windows or tabs which either don’t set COOP or which opt out of isolation by setting a COOP of unsafe-none.'},
                'same-origin': { 'secure': True, 'desc': 'Isolates the browsing context exclusively to same-origin documents. Cross-origin documents are not loaded in the same browsing context.'},
            },
            'deprecated': False,
            'desc': 'This response header (also named COOP) allows you to ensure a top-level document does not share a browsing context group with cross-origin documents. COOP will process-isolate your document and potential attackers can’t access to your global object if they were opening it in a popup, preventing a set of cross-origin attacks dubbed XS-Leaks (source Mozilla MDN).',
            'refs': [
                'https://html.spec.whatwg.org/multipage/origin.html#cross-origin-opener-policies',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy',
                'https://web.dev/coop-coep/',
                'https://web.dev/why-coop-coep/',
                'https://github.com/xsleaks/xsleaks',
                'https://portswigger.net/daily-swig/xs-leak',
                'https://portswigger.net/research/xs-leak-detecting-ids-using-portal',
                'https://web.dev/cross-origin-isolation-guide/',
            ]
        },

        'Cross-Origin-Resource-Policy': {
            'admited_values': {
                'same-site': { 'secure': True, 'desc': 'Only requests from the same Site can read the resource.'},
                'same-origin': { 'secure': True, 'desc': 'Only requests from the same Origin (i.e. scheme + host + port) can read the resource.'},
                'cross-origin': { 'secure': False, 'desc': 'Requests from any Origin (both same-site and cross-site) can read the resource. Browsers are using this policy when an CORP header is not specified.'},
            },
            'deprecated': False,
            'desc': 'This response header (also named CORP) allows to define a policy that lets web sites and applications opt in to protection against certain requests from other origins (such as those issued with elements like <script> and <img>), to mitigate speculative side-channel attacks, like Spectre, as well as Cross-Site Script Inclusion (XSSI) attacks (source Mozilla MDN).',
            'refs': [
                'https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy',
                'https://resourcepolicy.fyi/',
                'https://web.dev/cross-origin-isolation-guide/',
            ]
        },

        'Cache-Control': {
            'admited_values': {
                'no-cache': { 'secure': True, 'desc': 'The response may be stored by any cache, even if the response is normally non-cacheable. However, the stored response MUST always go through validation with the origin server first before using it.'},
                'no-store': { 'secure': True, 'desc': 'The response may not be stored in any cache.'},
                'no-transform': { 'secure': True, 'desc': 'An intermediate cache or proxy cannot edit the response body, Content-Encoding, Content-Range, or Content-Type.'},
                'public': { 'secure': True, 'desc': 'The response may be stored by any cache, even if the response is normally non-cacheable.'},
                'private': { 'secure': True, 'desc': 'The response may be stored only by a browser’s cache, even if the response is normally non-cacheable.'},
                'proxy-revalidate': { 'secure': True, 'desc': 'Like must-revalidate, but only for shared caches (e.g., proxies). Ignored by private caches.'},
                'max-age': { 'secure': True, 'desc': 'The maximum amount of time a resource is considered fresh. Unlike Expires, this directive is relative to the time of the request.'},
                's-maxage': { 'secure': True, 'desc': 'Overrides max-age or the Expires header, but only for shared caches (e.g., proxies). Ignored by private caches.'},
            },
            'deprecated': False,
            'desc': 'This header holds directives (instructions) for caching in both requests and responses. If a given directive is in a request, it does not mean this directive is in the response (source Mozilla MDN). Specify the capability of a resource to be cached is important to prevent exposure of information via the cache. The headers named Expires and Pragma can be used in addition to the Cache-Control header. Pragma header can be used for backwards compatibility with the HTTP/1.0 caches. However, Cache-Control is the recommanded way to define the caching policy.',
            'refs': [
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching',
                'https://datatracker.ietf.org/doc/html/rfc7234',
                'https://cwe.mitre.org/data/definitions/524.html',
                'https://cwe.mitre.org/data/definitions/525.html',
                'https://portswigger.net/web-security/web-cache-poisoning',
                'https://portswigger.net/research/practical-web-cache-poisoning',
                'https://portswigger.net/research/web-cache-entanglement',
            ]
        },

        'Permissions-Policy': {
            'admited_values': {
                'accelerometer': { 'secure': True, 'desc': 'Controls whether the current document is allowed to gather information about the acceleration of the device through the Accelerometer interface.'},
                'ambient-light-sensor': { 'secure': True, 'desc': 'Controls whether the current document is allowed to gather information about the amount of light in the environment around the device through the AmbientLightSensor interface.'},
                'autoplay': { 'secure': True, 'desc': 'Controls whether the current document is allowed to autoplay media requested through the HTMLMediaElement interface.'},
                'battery': { 'secure': True, 'desc': 'Controls whether the use of the Battery Status API is allowed.'},
                'camera': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use video input devices.'},
                'display-capture': { 'secure': True, 'desc': 'Controls whether or not the current document is permitted to use the getDisplayMedia() method to capture screen contents.'},
                'document-domain': { 'secure': True, 'desc': 'Controls whether the current document is allowed to set document.domain.'},
                'encrypted-media': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use the Encrypted Media Extensions API (EME).'},
                'execution-while-not-rendered': { 'secure': True, 'desc': 'Controls whether tasks should execute in frames while they’re not being rendered (e.g. if an iframe is hidden or display: none).'},
                'execution-while-out-of-viewport': { 'secure': True, 'desc': 'Controls whether tasks should execute in frames while they’re outside of the visible viewport.'},
                'fullscreen': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use Element.requestFullScreen().'},
                'geolocation': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use the Geolocation Interface.'},
                'gyroscope': { 'secure': True, 'desc': 'Controls whether the current document is allowed to gather information about the orientation of the device through the Gyroscope interface.'},
                'layout-animations': { 'secure': True, 'desc': 'Controls whether the current document is allowed to show layout animations.'},
                'legacy-image-formats': { 'secure': True, 'desc': 'Controls whether the current document is allowed to display images in legacy formats.'},
                'magnetometer': { 'secure': True, 'desc': 'Controls whether the current document is allowed to gather information about the orientation of the device through the Magnetometer interface.'},
                'microphone': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use audio input devices.'},
                'midi': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use the Web MIDI API.'},
                'navigation-override': { 'secure': True, 'desc': 'Controls the availability of mechanisms that enables the page author to take control over the behavior of spatial navigation, or to cancel it outright.'},
                'oversized-images': { 'secure': True, 'desc': 'Controls whether the current document is allowed to download and display large images.'},
                'payment': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use the Payment Request API.'},
                'picture-in-picture': { 'secure': True, 'desc': 'Controls whether the current document is allowed to play a video in a Picture-in-Picture mode via the corresponding API.'},
                'publickey-credentials-get': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use the Web Authentication API to retrieve already stored public-key credentials, i.e. via navigator.credentials.get().'},
                'sync-xhr': { 'secure': True, 'desc': 'Controls whether the current document is allowed to make synchronous XMLHttpRequest requests.'},
                'usb': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use the WebUSB API.'},
                'vr': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use the WebVR API.'},
                'wake-lock': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use Wake Lock API to indicate that device should not enter power-saving mode.'},
                'screen-wake-lock': { 'secure': True, 'desc': 'Controls whether the current document is allowed to use Screen Wake Lock API to indicate that device should not turn off or dim the screen.'},
                'web-share': { 'secure': True, 'desc': 'Controls whether or not the current document is allowed to use the Navigator.share() of Web Share API to share text, links, images, and other content to arbitrary destinations of user’s choice, e.g. mobile apps.'},
                'xr-spatial-tracking': { 'secure': True, 'desc': 'Controls whether or not the current document is allowed to use the WebXR Device API to interact with a WebXR session.'},
            },
            'deprecated': False,
            'desc': 'The Permissions-Policy header replaces the existing Feature-Policy header for controlling delegation of permissions and powerful features. The header uses a structured syntax, and allows sites to more tightly restrict which origins can be granted access to features (source Chrome platform status).',
            'refs': [
                'https://github.com/w3c/webappsec-permissions-policy/blob/main/permissions-policy-explainer.md',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy#directives',
                'https://caniuse.com/permissions-policy',
                'https://www.w3.org/TR/permissions-policy-1/',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy',
                'https://www.chromestatus.com/feature/5745992911552512',
            ]
        },

        'Feature-Policy': {
            'admited_values': {
                'accelerometer': { 'secure': True, 'desc': 'Controls access to accelerometer sensors on the device.'},
                'ambient-light-sensor': { 'secure': True, 'desc': 'Controls access to ambient light sensors on the device.'},
                'autoplay': { 'secure': True, 'desc': 'Controls access to autoplay through play() and the autoplay attribute.'},
                'battery': { 'secure': True, 'desc': 'Controls access to the BatteryManager API.'},
                'camera': { 'secure': True, 'desc': 'Controls access to video input devices.'},
                'display-capture': { 'secure': True, 'desc': 'Controls access to capturing the display output.'},
                'document-domain': { 'secure': True, 'desc': 'Controls access to setting document.domain.'},
                'encrypted-media': { 'secure': True, 'desc': 'Controls whether requestMediaKeySystemAccess() is allowed.'},
                'fullscreen': { 'secure': True, 'desc': 'Controls whether requestFullscreen() is allowed.'},
                'geolocation': { 'secure': True, 'desc': 'Controls access to the Geolocation interface.'},
                'gyroscope': { 'secure': True, 'desc': 'Controls access to gyroscope sensors on the device.'},
                'magnetometer': { 'secure': True, 'desc': 'Controls access to magnetometer sensors on the device.'},
                'microphone': { 'secure': True, 'desc': 'Controls access to audio input devices.'},
                'midi': { 'secure': True, 'desc': 'Controls access to requestMIDIAccess() method.'},
                'navigation-override': { 'secure': True, 'desc': 'Controls access to override of the spatial navigation API.'},
                'payment': { 'secure': True, 'desc': 'Controls access to the PaymentRequest interface.'},
                'picture-in-picture': { 'secure': True, 'desc': 'Controls access to picture-in-picture.'},
                'speaker': { 'secure': True, 'desc': 'Controls access to audio output devices.'},
                'usb': { 'secure': True, 'desc': 'Controls access to USB devices.'},
                'vibrate': { 'secure': True, 'desc': '(deprecated) Controls access to the vibrate() method.'},
                'vr': { 'secure': True, 'desc': '(deprecated) Controls access to VR displays.'},
            },
            'deprecated': True,
            'deprecated_desc': 'The Feature-Policy header is an experimental feature that allows developers to selectively enable and disable use of various browser features and APIs. The two most well supported values are microphone and camera. For all the other ones, please consult this page.',
            'desc': 'The Permissions-Policy header replaces the existing Feature-Policy header for controlling delegation of permissions and powerful features. The header uses a structured syntax, and allows sites to more tightly restrict which origins can be granted access to features (source Chrome platform status).',
            'refs': [
                'https://w3c.github.io/webappsec-feature-policy/',
                'https://scotthelme.co.uk/a-new-security-header-feature-policy/',
                'https://github.com/w3c/webappsec-feature-policy/blob/master/features.md',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy',
                'https://caniuse.com/permissions-policy',
            ]
        },

        'Public-Key-Pins': {
            'admited_values': {
                'pin-sha25': {'secure': True, 'desc': 'The quoted string is the Base64 encoded Subject Public Key Information (SPKI) fingerprint. It is possible to specify multiple pins for different public keys. Some browsers might allow other hashing algorithms than SHA-256 in the future.'},
                'max-age': {'secure': True, 'desc': 'The time, in seconds, that the browser should remember that this site is only to be accessed using one of the pinned keys.'},
                'includeSubDomains': {'secure': True, 'desc': 'If this optional parameter is specified, this rule applies to all of the site’s subdomains as well.'},
                'report-uri': {'secure': True, 'desc': 'If this optional parameter is specified, pin validation failures are reported to the given URL.'},
            },
            'deprecated': True,
            'deprecated_desc': 'Criticism and concern revolved around malicious or human error scenarios known as HPKP Suicide and Ransom PKP. In such scenarios, a website owner would have their ability to publish new contents to their domain severely hampered by either losing access to their own keys or having new keys announced by a malicious attacker.',
            'desc': 'HTTP Public Key Pinning (HPKP) is a security mechanism which allows HTTPS websites to resist impersonation by attackers using mis-issued or otherwise fraudulent certificates. (For example, sometimes attackers can compromise certificate authorities, and then can mis-issue certificates for a web origin.). The HTTPS web server serves a list of public key hashes, and on subsequent connections clients expect that server to use one or more of those public keys in its certificate chain. Deploying HPKP safely will require operational and organizational maturity due to the risk that hosts may make themselves unavailable by pinning to a set of public key hashes that becomes invalid. With care, host operators can greatly reduce the risk of man-in-the-middle (MITM) attacks and other false authentication problems for their users without incurring undue risk.',
            'refs': [
                'https://tools.ietf.org/html/rfc7469',
                'https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning#HTTP_pinning',
                'https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning',
                'https://developer.mozilla.org/en-US/docs/Web/Security/Public_Key_Pinning',
                'https://raymii.org/s/articles/HTTP_Public_Key_Pinning_Extension_HPKP.html',
                'https://labs.detectify.com/2016/07/05/what-hpkp-is-but-isnt/',
                'https://blog.qualys.com/ssllabs/2016/09/06/is-http-public-key-pinning-dead',
                'https://scotthelme.co.uk/im-giving-up-on-hpkp/',
                'https://groups.google.com/a/chromium.org/forum/m/#!msg/blink-dev/he9tr7p3rZ8/eNMwKPmUBAAJ',
            ]
        },

        'X-XSS-Protection': {
            'admited_values': {
                '0': {'secure': False, 'desc': 'Filter disabled.'},
                '1': {'secure': True, 'desc': 'Filter enabled. If a cross-site scripting attack is detected, in order to stop the attack, the browser will sanitize the page.'},
                '1; mode=block': {'secure': True, 'desc': 'Filter enabled. Rather than sanitize the page, when a XSS attack is detected, the browser will prevent rendering of the page.'},
                '1; report=': {'secure': True, 'desc': 'Filter enabled. The browser will sanitize the page and report the violation. This is a Chromium function utilizing CSP violation reports to send details to a URI of your choice.'},
            },
            'deprecated': True,
            'deprecated_desc': 'The X-XSS-Protection header has been deprecated by modern browsers and its use can introduce additional security issues on the client side. As such, it is recommended to set the header as X-XSS-Protection: 0 in order to disable the XSS Auditor, and not allow it to take the default behavior of the browser handling the response. Please use Content-Security-Policy instead.',
            'desc': 'The X-XSS-Protection header has been deprecated by modern browsers and its use can introduce additional security issues on the client side. As such, it is recommended to set the header as X-XSS-Protection: 0 in order to disable the XSS Auditor, and not allow it to take the default behavior of the browser handling the response. Please use Content-Security-Policy instead.',
            'refs': [
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
                'https://www.chromestatus.com/feature/5021976655560704',
                'https://bugzilla.mozilla.org/show_bug.cgi?id=528661',
                'https://blogs.windows.com/windowsexperience/2018/07/25/announcing-windows-10-insider-preview-build-17723-and-build-18204/',
                'https://github.com/zaproxy/zaproxy/issues/5849',
                'https://scotthelme.co.uk/security-headers-updates/#removing-the-x-xss-protection-header',
                'https://portswigger.net/daily-swig/google-chromes-xss-auditor-goes-back-to-filter-mode',
                'https://owasp.org/www-community/attacks/xss/',
                'https://www.virtuesecurity.com/blog/understanding-xss-auditor/',
                'https://www.veracode.com/blog/2014/03/guidelines-for-setting-security-headers',
                'http://zinoui.com/blog/security-http-headers#x-xss-protection',
            ]
        },
    }

    INTRUO_DNS_RECORDS = [
        'NONE',
        'A',
        'NS',
        'MD',
        'MF',
        'CNAME',
        'SOA',
        'MB',
        'MG',
        'MR',
        'NULL',
        'WKS',
        'PTR',
        'HINFO',
        'MINFO',
        'MX',
        'TXT',
        'RP',
        'AFSDB',
        'X25',
        'ISDN',
        'RT',
        'NSAP',
        'NSAP-PTR',
        'SIG',
        'KEY',
        'PX',
        'GPOS',
        'AAAA',
        'LOC',
        'NXT',
        'SRV',
        'NAPTR',
        'KX',
        'CERT',
        'A6',
        'DNAME',
        'OPT',
        'APL',
        'DS',
        'SSHFP',
        'IPSECKEY',
        'RRSIG',
        'NSEC',
        'DNSKEY',
        'DHCID',
        'NSEC3',
        'NSEC3PARAM',
        'TLSA',
        'HIP',
        'CDS',
        'CDNSKEY',
        'CSYNC',
        'SPF',
        'UNSPEC',
        'EUI48',
        'EUI64',
        'TKEY',
        'TSIG',
        'IXFR',
        'AXFR',
        'MAILB',
        'MAILA',
        'ANY',
        'URI',
        'CAA',
        'TA',
        'DLV',
    ]

class IntruoModules(Enum):
    """
    Defining Intruo available modules. Later for make prettiers API respones.
    """

    HTTPS = 'INTRUO__HTTPS'
    IP_ADDRESS = 'INTRUO__IP_ADDRESS'
    WHO_IS = 'INTRUO__WHO_IS'
    DNS_RECORDS = 'INTRUO__DNS_RECORDS'
    SERVER_LOCATION = 'INTRUO__SERVER_LOCATION'
    PORTS_OPEN = 'INTRUO__PORTS_OPEN'
    PAGE_TECHNOLOGIES_INVOLVED = 'INTRUO__PAGE_TECHNOLOGIES_INVOLVED'
    EMAILS_FOUND = 'INTRUO__EMAILS_FOUND'
    GOOGLE_DORKS = 'INTRUO__GOOGLE_DORKS'
    PAGE_STRUCTURE_FINDER = 'INTRUO__PAGE_STRUCTURE_FINDER'
    PAGE_OWASP_SECURITY_HEADERS = 'INTRUO__PAGE_OWASP_SECURITY_HEADERS'

class IntruoConfiguration:
    
    @staticmethod
    def check_configuration():
        result = {
            'chromedriver': {
                'result': os.path.exists(os.path.join(os.getcwd(), 'utils', 'chromedriver.exe')),
                'error': 'No se encuentra instalado el controlador de Chrome Driver. Esta aplicación es necesaria para que INTRUO pueda funcionar correctamente.<br>Visitar: <a href="https://chromedriver.chromium.org/downloads" target="_blank">https://chromedriver.chromium.org/downloads</a>'
            }
        }

        return result


class Intruo:
    """
    Intruo main class.
    """
    def __init__(self, domain: str, debug: bool = False) -> None:
        self.debug = debug
        try:
            self.parsed_domain = urlparse(domain)
            self.domain = self.parsed_domain.netloc
            self.action_debug(f'[INIT] Target domain: {str(self.domain)}')
        except Exception as e:
            print(f'[-] Error: Unable to parse URL. {str(e)}')
            quit()

        self.isBrowserDriverInstalled = os.path.exists(os.path.join(os.getcwd(), 'utils', 'chromedriver.exe'))

        # Setting time execution information
        self.time_execution = {
            'init': datetime.now(),
            'end': None,
            'total_time': None,
        }

        # Result
        self.result = {}
        self.result['time_execution'] = {
            'init': datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            'end': None,
            'total_time': None,
        }
        
        self.action_debug(f'[INIT] Time initialization: {self.time_execution["init"].strftime("%d/%m/%Y %H:%M:%S")}')

        # Setting computer information
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self.result['computer_information'] = {
            'local_ip': str(s.getsockname()[0]),
            'hostname': str(platform.uname()[1]),
            'os_info': platform.platform(),
            'debug_information': {
                'ptyhon_version': platform.python_version(),
                'machine': platform.machine(),
                'architecture': platform.architecture(),
                'none': platform.node(),
                'processor': platform.processor(),
            }
        }
        s.close()

        # Setting computer information
        self.result['target_domain'] = self.domain
        
        # Settings modules dict
        self.result['result'] = {}

    def set_module_result(self, module_name: str, val: Any, start_time_execution: datetime) -> Intruo:
        self.result['result'][module_name] = {
            'result': val
        }

        self.result['result'][module_name]['time_execution'] = str(datetime.now() - start_time_execution)
        self.action_debug(f'[{module_name}]: {str(val)}')

        return self

    def get_module_result(self, module_name: str) -> Any:
        if module_name in self.result['result']:
            return self.result['result'][module_name]['result']

        return None

    ## Modules
    def module__https(self) -> bool:
        NOW = datetime.now()
        MODULE_NAME: str = IntruoModules.HTTPS.value
        VAL = False

        r = requests.get(f'http://{self.domain}')

        if 'https' in r.url:
            VAL = True
        self.set_module_result(module_name=MODULE_NAME, val=VAL, start_time_execution=NOW)

        return True

    def module__ip_address(self) -> bool:
        NOW = datetime.now()
        MODULE_NAME: str = IntruoModules.IP_ADDRESS.value
        VAL = None

        VAL = socket.gethostbyname(self.domain)

        self.set_module_result(module_name=MODULE_NAME, val=VAL, start_time_execution=NOW)

        return True

    def module__who_is(self) -> bool:
        NOW = datetime.now()
        MODULE_NAME: str = IntruoModules.WHO_IS.value

        if self.get_module_result(IntruoModules.HTTPS.value) is None:
            self.module__https()

        domain = self.domain
        if self.get_module_result(IntruoModules.HTTPS.value):
            domain = f'https://{self.domain}'

        VAL = whois.whois(domain)

        self.set_module_result(module_name=MODULE_NAME, val=VAL, start_time_execution=NOW)

        return True

    def module__dns_records(self) -> bool:
        NOW = datetime.now()
        MODULE_NAME: str = IntruoModules.DNS_RECORDS.value
        VAL = {}

        for record in IntruoConstants.INTRUO_DNS_RECORDS.value:
            try:
                resolve = dns.resolver.query(self.domain, record)
                for rdata in resolve:
                    VAL[record] = rdata.to_text()
            except Exception as e:
                pass

        self.set_module_result(module_name=MODULE_NAME, val=VAL, start_time_execution=NOW)

        return True

    def module__server_location(self) -> bool:
        NOW = datetime.now()
        MODULE_NAME: str = IntruoModules.SERVER_LOCATION.value
        VAL = {}

        if self.get_module_result(IntruoModules.IP_ADDRESS.value) is None:
            self.module__ip_address()

        VAL = requests.get(f'https://geolocation-db.com/json/{self.get_module_result(IntruoModules.IP_ADDRESS.value)}&position=true').json()
        del VAL['IPv4']
        self.set_module_result(module_name=MODULE_NAME, val=VAL, start_time_execution=NOW)

        return True

    def module__ports_open(self, ports_list: list = [], port_from: int = 0, port_to: int = 0, common_ports: bool = True, timeout: float = 0.5) -> bool:
        NOW = datetime.now()
        MODULE_NAME: str = IntruoModules.PORTS_OPEN.value
        VAL = {}

        ports_to_scan = []
        if len(ports_list) > 0:
            ports_to_scan = [str(port) for port in ports_list]

        if port_from > 0 and port_to > 0:
            ports_to_scan = [str(port) for port in range(port_from, port_to + 1)]

        if common_ports:
            ports_to_scan = [str(port) for port in IntruoConstants.INTRUO_COMMON_PORTS.value]
        
        for port in ports_to_scan:
            port_common_use_name = IntruoConstants.INTRUO_COMMON_PORTS.value[port] if port in IntruoConstants.INTRUO_COMMON_PORTS.value else 'unknown'
            port = int(port)

            if self.get_module_result(IntruoModules.IP_ADDRESS.value) is None:
                self.module__ip_address()
            
            try:
                s = socket.socket()
                s.settimeout(timeout)
                s.connect((self.get_module_result(IntruoModules.IP_ADDRESS.value), port))
                VAL[str(port)] = {
                    'common_use_name': port_common_use_name,
                    'status': 'open'
                }
            except Exception as e:
                VAL[str(port)] = {
                    'common_use_name': port_common_use_name,
                    'status': 'closed',
                    'exception': str(e)
                }
            
        self.set_module_result(module_name=MODULE_NAME, val=VAL, start_time_execution=NOW)

        return True

    def module__page_technologies_involved(self) -> bool:
        NOW = datetime.now()
        MODULE_NAME: str = IntruoModules.PAGE_TECHNOLOGIES_INVOLVED.value
        VAL = {}

        if self.get_module_result(IntruoModules.HTTPS.value) is None:
            self.module__https()

        domain = self.domain
        if self.get_module_result(IntruoModules.HTTPS.value):
            domain = f'https://{self.domain}'

        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(domain)
        analyze = wappalyzer.analyze_with_versions_and_categories(webpage)

        page_info = {}
        for tech in analyze:
            categories = analyze[tech]
            for category in categories['categories']:
                if category not in page_info:
                    page_info[category] = []
                page_info[category].append({
                    'software': tech,
                    'version': categories['versions'][0] if len(categories['versions']) > 0 else 'Unknown'
                })

        VAL = page_info
            
        self.set_module_result(module_name=MODULE_NAME, val=VAL, start_time_execution=NOW)

        return True

    def module__emails_found(self) -> bool:
        if not self.isBrowserDriverInstalled:
            return False

        NOW = datetime.now()
        MODULE_NAME: str = IntruoModules.EMAILS_FOUND.value
        VAL = {}

        domain = self.domain
        if self.get_module_result(IntruoModules.HTTPS.value):
            domain = f'https://{self.domain}'

        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_experimental_option("excludeSwitches", ["enable-logging"])

        driver = webdriver.Chrome(os.path.join(os.getcwd(), 'utils', 'chromedriver.exe'), options=options)
        driver.get(domain)
        page_source = driver.page_source
        VAL = re.findall(r'[\w\.-]+@[\w\.-]+', page_source)
        VAL = list(dict.fromkeys(VAL))
        driver.close()

        self.set_module_result(module_name=MODULE_NAME, val=VAL, start_time_execution=NOW)

        return True

    def module__google_dorks(self, open_in_browser_tabs: bool = False) -> bool:
        NOW = datetime.now()
        MODULE_NAME: str = IntruoModules.GOOGLE_DORKS.value
        VAL = {}

        for dork in IntruoConstants.INTRUO_GOOGLE_DROKS.value:
            VAL[dork] = IntruoConstants.INTRUO_GOOGLE_DROKS.value[dork].replace('!!DOMAIN!!', self.domain)

        self.set_module_result(module_name=MODULE_NAME, val=VAL, start_time_execution=NOW)

        return True

    def module__page_structure_finder(self, word_list: str = 'dir_finder_example.txt') -> bool:
        NOW = datetime.now()
        MODULE_NAME: str = IntruoModules.PAGE_STRUCTURE_FINDER.value
        VAL = {}

        domain = self.domain
        if self.get_module_result(IntruoModules.HTTPS.value):
            domain = f'https://{self.domain}'

        try:
            with open(os.path.join(os.getcwd(), 'utils', word_list), 'r', encoding='utf-8') as f:
                for word in f.readlines():
                    domain_url_check = f'{domain}/{word.rstrip()}'
                    r = requests.get(domain_url_check)
                    self.action_debug(f'DIR FINDER: URL: {domain_url_check}, STATUS: {r.status_code == 200}')
                    if str(r.status_code) not in VAL:
                        VAL[str(r.status_code)] = []
                    VAL[str(r.status_code)].append(domain_url_check)
        except Exception as e:
            print(e)
            return False

        self.set_module_result(module_name=MODULE_NAME, val=VAL, start_time_execution=NOW)

        return True

    def module__page_owasp_security_headers(self, main_response_only: bool = True) -> bool:
        if not self.isBrowserDriverInstalled:
            return False

        NOW = datetime.now()
        MODULE_NAME: str = IntruoModules.PAGE_OWASP_SECURITY_HEADERS.value
        VAL = {}

        domain = self.domain
        if self.get_module_result(IntruoModules.HTTPS.value):
            domain = f'https://{self.domain}'

        from seleniumwire import webdriver
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_experimental_option("excludeSwitches", ["enable-logging"])

        driver = webdriver.Chrome(os.path.join(os.getcwd(), 'utils', 'chromedriver.exe'), options=options)
        driver.get(domain)
        headers_response_list = []
        for request in driver.requests:
            if main_response_only:
                if domain + '/' == request.url:
                    headers_response_list.append({
                        'url': request.url,
                        'response': request.response.headers
                    })
                    break
            else:
                headers_response_list.append({
                    'url': request.url,
                    'response': request.response.headers
                })

        driver.close()

        TEMP_LIST_OWASP_SECURE_HEADERS_PROJECT = []
        for s_header in IntruoConstants.INTRUO_OWASP_SECURE_HEADERS_PROJECT.value:
            TEMP_LIST_OWASP_SECURE_HEADERS_PROJECT.append(s_header)


        for idx, header in enumerate(headers_response_list):
            headers_response_list[idx]['headers_list'] = [h for h in header['response']]

        for idx, header in enumerate(headers_response_list):
            headers_list = header['headers_list']
            headers_response_list[idx]['header_owasp_not_found'] = []
            for oh in TEMP_LIST_OWASP_SECURE_HEADERS_PROJECT:
                if oh.lower() not in [h.lower() for h in headers_list]:
                    headers_response_list[idx]['header_owasp_not_found'].append(oh)

        for response in headers_response_list:
            response_url = response['url']
            response_header_owasp_not_found = response['header_owasp_not_found']
            VAL[response_url] = {}
            for h in response_header_owasp_not_found:
                VAL[response_url][h] = IntruoConstants.INTRUO_OWASP_SECURE_HEADERS_PROJECT.value[h]

        self.set_module_result(module_name=MODULE_NAME, val=VAL, start_time_execution=NOW)

        return True


    ## Actions
    def action_debug(self, msg: str) -> None:
        if self.debug:
            NOW = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            print(f'[D] [{NOW}] - {msg}')

    def action_get_screenshoot(self) -> str:
        if self.get_module_result(IntruoModules.HTTPS.value) is None:
            self.module__https()
        domain = f'https://{self.domain}' if self.get_module_result(IntruoModules.HTTPS.value) else f'http://{self.domain}'


        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_experimental_option("excludeSwitches", ["enable-logging"])
        options.add_argument("--window-size=1366,768")

        driver = webdriver.Chrome(os.path.join(os.getcwd(), 'utils', 'chromedriver.exe'), options=options)
        driver.get(domain)
        time.sleep(2)
        filename = f'{self.domain}___{self.time_execution["init"].strftime("%d_%m_%Y__%H_%M_%S")}.png'
        image_path = os.path.join(os.getcwd(), 'web', 'static', 'results', 'screenshot', filename)
        driver.save_screenshot(image_path)
        driver.close()

        return filename

    def action_save_result_as_json(self) -> str:
        self.action_end_execution_timer()

        filename = f'{self.domain}___{self.time_execution["init"].strftime("%d_%m_%Y__%H_%M_%S")}.json'
        json_file_path = os.path.join(os.getcwd(), 'web', 'static', 'results', 'json', filename)
        with open(json_file_path, 'w') as json_file:
            json.dump(self.result, json_file, indent=4, default=str)

        return filename

    def action_save_result_as_js(self) -> str:
        self.action_end_execution_timer()

        filename = f'{self.domain}___{self.time_execution["init"].strftime("%d_%m_%Y__%H_%M_%S")}.js'
        js_file_path = os.path.join(os.getcwd(), 'web', 'static', 'results', 'js', filename)
        with open(js_file_path, 'w') as js_file:
            json.dump(self.result, js_file, indent=4, default=str)

        js_file = open(js_file_path, 'r')
        js_const_append = 'const intruo_result = '
        js_file_lines = js_file.readlines()
        js_file_lines.insert(0, js_const_append)
        js_file.close()
        js_file = open(js_file_path, 'w')
        js_file.writelines(js_file_lines)
        js_file.close()

        return filename

    def action_end_execution_timer(self) -> None:
        self.time_execution['end'] = datetime.now()
        self.result['time_execution']['end'] = self.time_execution['end'].strftime("%d/%m/%Y %H:%M:%S")
        self.time_execution['total_time'] = self.time_execution['end'] - self.time_execution['init']
        self.result['time_execution']['total_time'] = str(self.time_execution['total_time'])

        return None

    def action_generate_results(self) -> dict:

        screenshot = self.action_get_screenshoot()
        json = self.action_save_result_as_json()
        js = self.action_save_result_as_js()
        html = self.action_generate_html(js, screenshot, f'{self.domain}___{self.time_execution["init"].strftime("%d_%m_%Y__%H_%M_%S")}')
        return {
            'screenshot': screenshot,
            'json': json,
            'js': js,
            'html': html
        }

    def action_generate_html(self, intruo_js_file, intruo_screenshot_file, intruo_final_file_name) -> str:       
        #css
        css_files = [
            'materialdesignicons.cdn.min.css',
            'buefy.min.css',
            'animate.min.css',
            'intruo.css',
        ]
        css_path_files = os.path.join(os.getcwd(), 'web', 'static', 'css')
        css_output = os.path.join(os.getcwd(), 'temp', 'intruo_css.compiled.css')
        with open(css_output, 'w', encoding='utf-8') as css_final_file:
            for css_file in css_files:
                try:
                    with open(os.path.join(css_path_files, css_file), 'r', encoding='utf-8') as css_open_file:
                        css_final_file.write(css_open_file.read() + '\n')
                except Exception as e:
                    print(Exception, e)


        ## js
        js_files = [
            'vue.min.js',
            'buefy.min.js'
        ]
        js_path_files = os.path.join(os.getcwd(), 'web', 'static', 'js')
        js_output = os.path.join(os.getcwd(), 'temp', 'intruo_js.compiled.js')
        js_intruo_file = os.path.join(os.getcwd(), 'web', 'static', 'results', 'js', intruo_js_file)
        with open(js_output, 'w') as js_final_file:
            for js_file in js_files:
                try:
                    with open(os.path.join(js_path_files, js_file), 'r', encoding='utf-8') as js_open_file:
                        js_final_file.write(f'// INTRUO: {js_file} \n' + js_open_file.read() + '\n')
                except Exception as e:
                    print(Exception, e)
            
            with open(js_intruo_file, 'r', encoding='utf-8') as js_intruo_open_file:
                try:
                    js_final_file.write(f'// INTRUO: INTRUO RESULT \n' + js_intruo_open_file.read() + '\n')
                except Exception as e:
                    print(Exception, e)

        # screenshot

        # Thumbnail 500 x 281
        image_path = os.path.join(os.getcwd(), 'web', 'static', 'results', 'screenshot', intruo_screenshot_file)

        im = Image.open(image_path)
        rgb_im = im.convert('RGB')
        intruo_screenshot = rgb_im.resize((500, 281))
        # intruo_screenshot.save(os.path.join(os.getcwd(), 'temp', 'screenshot.jpg'))

        buffered = BytesIO()
        intruo_screenshot.save(buffered, format="jpeg")
        intruo_screenshot = buffered.getvalue()
        intruo_screenshot = "data:image/jpeg;base64," + base64.b64encode(intruo_screenshot).decode("utf-8") 


        ## Generate html minified
        intruo_final_file_name = f'{intruo_final_file_name}.html'
        intruo_final = os.path.join(os.getcwd(), 'web', 'static', 'results', 'html', intruo_final_file_name)
        intruo_downloadable_file = os.path.join(os.getcwd(), 'web', 'templates', 'downloadable.html')
        intruo_css = os.path.join(os.getcwd(), 'temp', 'intruo_css.compiled.css')
        intruo_js = os.path.join(os.getcwd(), 'temp', 'intruo_js.compiled.js')
        with open(intruo_final, 'w', encoding='utf-8') as intruo_final_file_to_save:
            intruo_downloadable_file_open = open(intruo_downloadable_file, 'r', encoding='utf-8')
            intruo_css_open = open(intruo_css, 'r', encoding='utf-8')
            intruo_js_open = open(intruo_js, 'r', encoding='utf-8')

            intruo_downloadable_file_txt = intruo_downloadable_file_open.read()
            intruo_downloadable_file_txt = intruo_downloadable_file_txt.replace('[*__CSS_COMPILED__*]', intruo_css_open.read())
            intruo_downloadable_file_txt = intruo_downloadable_file_txt.replace('[*__JS_COMPILED__*]', intruo_js_open.read())
            intruo_downloadable_file_txt = intruo_downloadable_file_txt.replace('[*__SCREENSHOT__*]', intruo_screenshot)

            intruo_final_file_to_save.write(intruo_downloadable_file_txt)

            intruo_downloadable_file_open.close()
            intruo_css_open.close()
            intruo_js_open.close()

        return intruo_final_file_name
            

    @staticmethod
    def action_open_browser(url: str) -> bool:
        webbrowser.open_new(url)

        return True
