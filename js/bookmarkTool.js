// Bookmark Tools Helper Functions

// Create a namespace to avoid global scope pollution
var BookmarkTools = (function() {
    /**
     * Format javascript code to make it more readable
     * @param {string} code - The raw javascript code
     * @return {string} - Formatted code
     */
    function formatJavaScriptCode(code) {
        // Remove javascript: prefix
        let formattedCode = code.replace('javascript:', '');
        
        // Add line breaks and indentation for better readability
        formattedCode = formattedCode
            .replace(/^\(function\(\)\{/, '(function() {\n  ')
            .replace(/\}\)\(\);$/, '\n})();')
            .replace(/;/g, ';\n  ')
            .replace(/\}\);/g, '});\n  ')
            .replace(/\n  \n/, '\n')
            .replace(/document\.querySelectorAll/g, '\n  document.querySelectorAll');
        
        return formattedCode;
    }

    /**
     * Copy text to clipboard with fallback
     * @param {string} text - The text to copy
     * @param {function} successCallback - Function to call on success
     * @param {function} errorCallback - Function to call on error
     */
    function copyToClipboard(text, successCallback, errorCallback) {
        // Use Clipboard API if available
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text)
                .then(() => {
                    if (successCallback) successCallback();
                })
                .catch((err) => {
                    console.error('Could not copy text: ', err);
                    // Fall back to execCommand
                    fallbackCopyToClipboard(text, successCallback, errorCallback);
                });
        } else {
            // Fallback for browsers that don't support Clipboard API
            fallbackCopyToClipboard(text, successCallback, errorCallback);
        }
    }

    /**
     * Fallback method to copy text to clipboard
     * @param {string} text - The text to copy
     * @param {function} successCallback - Function to call on success
     * @param {function} errorCallback - Function to call on error
     */
    function fallbackCopyToClipboard(text, successCallback, errorCallback) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                if (successCallback) successCallback();
            } else {
                if (errorCallback) errorCallback('Command was unsuccessful');
            }
        } catch (err) {
            if (errorCallback) errorCallback(err);
        }    
        document.body.removeChild(textArea);
    }
      /**
     * Extract potential API endpoints from scripts and page content
     * @param {Document} doc - The document object to extract endpoints from
     * @return {Set} - Set of unique endpoints found
     */
    function extractEndpoints(doc) {
        var scripts = doc.getElementsByTagName("script");
        var regex = /(?=(\"|\%27|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\\'|\%60))/g;
        const results = new Set();
        
        // Search in external scripts
        for (var i = 0; i < scripts.length; i++) {
            var scriptSrc = scripts[i].src;
            if (scriptSrc != "") {
                fetch(scriptSrc)
                    .then(function(response) {
                        return response.text();
                    })
                    .then(function(text) {
                        var matches = text.matchAll(regex);
                        for (let match of matches) {
                            results.add(match[0]);
                        }
                    })
                    .catch(function(error) {
                        console.log("An error occurred: ", error);
                    });
            }
        }
        
        // Search in page content
        var pageContent = doc.documentElement.outerHTML;
        var matches = pageContent.matchAll(regex);
        for (const match of matches) {
            results.add(match[0]);
        }
        
        return results;
    }

    // Return public methods
    return {
        formatCode: formatJavaScriptCode,
        copyText: copyToClipboard,
        getEndpoints: extractEndpoints
    };
})();
