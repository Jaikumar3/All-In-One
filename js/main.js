// Main JavaScript for Security Payload Repository

// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the page
    initializePage();
    
    // Set up event listeners
    setupEventListeners();
});

// Initialize the page with data
function initializePage() {
    // Populate all tables with data
    populateTable('wordlists-table', wordlistsData, createWordlistRow);
    
    // Populate XSS tables with categorized data
    populateTable('xss-basic-table', xssData.basicPayloads, createPayloadRow);
    populateTable('xss-tags-table', xssData.tagsBypass, createPayloadRow);
    populateTable('xss-attributes-table', xssData.attributesBypass, createPayloadRow);
    populateTable('xss-encoded-table', xssData.htmlEncoded, createPayloadRow);
    populateTable('xss-dom-table', xssData.domBasedXSS, createPayloadRow);
    populateTable('xss-evasion-table', xssData.filterEvasion, createPayloadRow);
    populateTable('xss-events-table', xssData.eventHandlers, createPayloadRow);
    populateTable('xss-waf-table', xssData.wafBypass, createPayloadRow);
    populateTable('xss-polyglots-table', xssData.polyglots, createPayloadRow);
    populateTable('xss-context-table', xssData.contextSpecific, createBrowserSpecificRow);
    populateTable('xss-browser-table', xssData.browserSpecific, createBrowserSpecificRow);
    populateTable('xss-css-table', xssData.cssBased, createBrowserSpecificRow);
    // Add HTML-specific and Angular payloads tables
    populateTable('xss-html-specific-table', xssData.htmlSpecific, createPayloadRow);
    populateTable('xss-angular-table', xssData.angularPayloads, createPayloadRow);
    
    // Populate separate HTML payloads table (not part of XSS)
    populateTable('html-payloads-table', htmlPayloadsData, createPayloadRow);
    
    populateTable('lfi-table', lfiData, createPayloadRow);
    populateTable('cmd-table', cmdInjectionData, createPayloadRow);
    populateTable('sql-table', sqlInjectionData, createPayloadRow);
    populateTable('regex-table', regexData, createRegexRow);
    populateTable('resources-table', resourcesData, createResourceRow);
    
    // Create the notification element for copy operations
    createCopyNotification();
}

// Set up event listeners for the page
function setupEventListeners() {
    // Set up search functionality
    const searchInput = document.getElementById('search-input');
    const searchButton = document.getElementById('search-button');
    
    searchButton.addEventListener('click', function() {
        performSearch(searchInput.value);
    });
    
    searchInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            performSearch(searchInput.value);
        }
    });
    
    // Set up theme toggle
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
        
        // Set initial theme based on user preference
        initializeTheme();
    }
    
    // Set up smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// Initialize theme based on user preference or saved setting
function initializeTheme() {
    // Check if user has saved a theme preference
    const savedTheme = localStorage.getItem('theme');
    
    if (savedTheme === 'dark') {
        enableDarkMode();
    } else if (savedTheme === 'light') {
        enableLightMode();
    } else {
        // Check user's system preference
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            enableDarkMode();
        } else {
            enableLightMode();
        }
    }
}

// Toggle between light and dark themes
function toggleTheme() {
    const html = document.documentElement;
    const themeToggle = document.getElementById('theme-toggle');
    
    if (html.getAttribute('data-bs-theme') === 'dark') {
        enableLightMode();
    } else {
        enableDarkMode();
    }
}

// Enable dark mode
function enableDarkMode() {
    const html = document.documentElement;
    const themeToggle = document.getElementById('theme-toggle');
    
    html.setAttribute('data-bs-theme', 'dark');
    if (themeToggle) {
        themeToggle.innerHTML = '<i class="fas fa-sun text-white"></i>';
    }
    localStorage.setItem('theme', 'dark');
}

// Enable light mode
function enableLightMode() {
    const html = document.documentElement;
    const themeToggle = document.getElementById('theme-toggle');
    
    html.setAttribute('data-bs-theme', 'light');
    if (themeToggle) {
        themeToggle.innerHTML = '<i class="fas fa-moon text-white"></i>';
    }
    localStorage.setItem('theme', 'light');
}

// Populate a table with data
function populateTable(tableId, data, rowCreatorFunc) {
    const tableBody = document.getElementById(tableId);
    if (!tableBody) return;
    
    // Clear existing table rows
    tableBody.innerHTML = '';
    
    // Add each row of data
    data.forEach(item => {
        const row = rowCreatorFunc(item);
        tableBody.appendChild(row);
    });
}

// Create a row for wordlist items
function createWordlistRow(wordlist) {
    const row = document.createElement('tr');
    
    // Name cell
    const nameCell = document.createElement('td');
    nameCell.textContent = wordlist.name;
    row.appendChild(nameCell);
    
    // Description cell
    const descriptionCell = document.createElement('td');
    descriptionCell.textContent = wordlist.description;
    row.appendChild(descriptionCell);
    
    // Link cell with open and copy content buttons
    const linkCell = document.createElement('td');
    
    // Create button group div for better styling
    const btnGroup = document.createElement('div');
    btnGroup.className = 'btn-group';
    
    // Open link button
    const link = document.createElement('a');
    link.href = wordlist.link;
    link.target = '_blank';
    link.className = 'btn btn-sm btn-primary';
    link.innerHTML = '<i class="fas fa-external-link-alt"></i> Open';
    
    // Copy content button
    const copyContentBtn = document.createElement('button');
    copyContentBtn.className = 'btn btn-sm btn-success';
    copyContentBtn.innerHTML = '<i class="fas fa-file-download"></i> Copy Content';
    copyContentBtn.addEventListener('click', function() {
        fetchAndCopyWordlistContent(wordlist.link, wordlist.name);
    });
    
    // Add buttons to group and cell
    btnGroup.appendChild(link);
    btnGroup.appendChild(copyContentBtn);
    linkCell.appendChild(btnGroup);
    row.appendChild(linkCell);
    
    return row;
}

// Create a row for payload items (XSS, LFI, Command Injection, SQL Injection)
function createPayloadRow(payload) {
    const row = document.createElement('tr');
    
    // Payload cell
    const payloadCell = document.createElement('td');
    const payloadText = document.createElement('code');
    payloadText.className = 'payload-text';
    payloadText.textContent = payload.payload;
    payloadCell.appendChild(payloadText);
    row.appendChild(payloadCell);
    
    // Description cell
    const descriptionCell = document.createElement('td');
    descriptionCell.textContent = payload.description;
    row.appendChild(descriptionCell);
    
    // Action cell (copy button)
    const actionCell = document.createElement('td');
    const copyButton = document.createElement('button');
    copyButton.className = 'btn btn-sm btn-primary btn-copy';
    copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
    copyButton.addEventListener('click', function() {
        copyToClipboard(payload.payload);
    });
    actionCell.appendChild(copyButton);
    row.appendChild(actionCell);
    
    return row;
}

// Create a row for browser-specific XSS payloads with browser compatibility info
function createBrowserSpecificRow(payload) {
    const row = document.createElement('tr');
    
    // Payload cell
    const payloadCell = document.createElement('td');
    const payloadText = document.createElement('code');
    payloadText.className = 'payload-text';
    payloadText.textContent = payload.payload;
    payloadCell.appendChild(payloadText);
    row.appendChild(payloadCell);
    
    // Description cell with browser compatibility
    const descriptionCell = document.createElement('td');
    const descriptionText = document.createTextNode(payload.description);
    descriptionCell.appendChild(descriptionText);
    
    // Add browser compatibility badge if available
    if (payload.browser) {
        const br = document.createElement('br');
        descriptionCell.appendChild(br);
        
        const badge = document.createElement('span');
        badge.className = 'badge bg-secondary mt-2';
        badge.textContent = `Compatible: ${payload.browser}`;
        descriptionCell.appendChild(badge);
    }
    
    row.appendChild(descriptionCell);
    
    // Action cell (copy button)
    const actionCell = document.createElement('td');
    const copyButton = document.createElement('button');
    copyButton.className = 'btn btn-sm btn-primary btn-copy';
    copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
    copyButton.addEventListener('click', function() {
        copyToClipboard(payload.payload);
    });
    actionCell.appendChild(copyButton);
    row.appendChild(actionCell);
    
    return row;
}

// Create a row for regex patterns
function createRegexRow(regex) {
    const row = document.createElement('tr');
    
    // Pattern cell
    const patternCell = document.createElement('td');
    const patternText = document.createElement('code');
    patternText.className = 'payload-text';
    patternText.textContent = regex.pattern;
    patternCell.appendChild(patternText);
    row.appendChild(patternCell);
    
    // Description cell
    const descriptionCell = document.createElement('td');
    descriptionCell.textContent = regex.description;
    row.appendChild(descriptionCell);
    
    // Action cell (copy button)
    const actionCell = document.createElement('td');
    const copyButton = document.createElement('button');
    copyButton.className = 'btn btn-sm btn-primary btn-copy';
    copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
    copyButton.addEventListener('click', function() {
        copyToClipboard(regex.pattern);
    });
    actionCell.appendChild(copyButton);
    row.appendChild(actionCell);
    
    return row;
}

// Create a row for external resources
function createResourceRow(resource) {
    const row = document.createElement('tr');
    
    // Name cell
    const nameCell = document.createElement('td');
    nameCell.textContent = resource.name;
    row.appendChild(nameCell);
    
    // Description cell
    const descriptionCell = document.createElement('td');
    descriptionCell.textContent = resource.description;
    row.appendChild(descriptionCell);
    
    // Link cell with open button
    const linkCell = document.createElement('td');
    
    // Open link button
    const link = document.createElement('a');
    link.href = resource.link;
    link.target = '_blank';
    link.className = 'btn btn-sm btn-primary';
    link.innerHTML = '<i class="fas fa-external-link-alt"></i> Open';
    
    // Add button to cell
    linkCell.appendChild(link);
    row.appendChild(linkCell);
    
    return row;
}

// Copy text to clipboard
function copyToClipboard(text) {
    // Create a temporary textarea element to copy from
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'absolute';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    
    // Select and copy the text
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    
    // Show copy notification
    showCopyNotification();
}

// Create the copy notification element
function createCopyNotification() {
    // Check if notification already exists
    if (document.querySelector('.copy-notification')) return;
    
    const notification = document.createElement('div');
    notification.className = 'copy-notification';
    notification.id = 'copyNotification';
    notification.textContent = 'Copied to clipboard!';
    document.body.appendChild(notification);
}

// Show the copy notification
function showCopyNotification(message = 'Copied to clipboard!') {
    const notification = document.getElementById('copyNotification');
    if (!notification) return;
    
    // Update notification text
    notification.textContent = message;
    
    // Show the notification
    notification.style.display = 'block';
    notification.classList.add('fade-in-out');
    
    // Hide it after animation completes
    setTimeout(function() {
        notification.style.display = 'none';
        notification.classList.remove('fade-in-out');
    }, 2000);
}

// Fetch and copy wordlist content
async function fetchAndCopyWordlistContent(url, name) {
    try {
        // Show loading notification
        showCopyNotification('Fetching wordlist content...');
        
        // Fetch the content
        const response = await fetch(url);
        
        // Check if the fetch was successful
        if (!response.ok) {
            throw new Error(`Failed to fetch wordlist: ${response.status} ${response.statusText}`);
        }
        
        // Get the text content
        const content = await response.text();
        
        // Copy the content to clipboard
        copyToClipboard(content);
        
        // Show success notification
        showCopyNotification(`Copied ${name} content to clipboard!`);
        
    } catch (error) {
        console.error('Error fetching wordlist:', error);
        showCopyNotification(`Error: Failed to copy wordlist content. ${error.message}`);
    }
}

// Perform search across all payloads and data
function performSearch(query) {
    // If query is empty, show all
    if (!query || query.trim() === '') {
        resetSearch();
        return;
    }
    
    query = query.toLowerCase();
    
    // Arrays to store search results
    const matchingWordlists = wordlistsData.filter(item => 
        item.name.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    // Search within all XSS categories
    const matchingXssBasic = xssData.basicPayloads.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingXssTags = xssData.tagsBypass.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingXssAttributes = xssData.attributesBypass.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingXssEncoded = xssData.htmlEncoded.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingXssDom = xssData.domBasedXSS.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingXssEvasion = xssData.filterEvasion.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingXssEvents = xssData.eventHandlers.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingXssWaf = xssData.wafBypass.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingXssPolyglots = xssData.polyglots.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingXssContext = xssData.contextSpecific.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query) ||
        (item.browser && item.browser.toLowerCase().includes(query))
    );
    
    const matchingXssBrowser = xssData.browserSpecific.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query) ||
        (item.browser && item.browser.toLowerCase().includes(query))
    );
    
    const matchingXssCss = xssData.cssBased.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query) ||
        (item.browser && item.browser.toLowerCase().includes(query))
    );
    
    // Add search for HTML-specific and Angular payloads
    const matchingXssHtmlSpecific = xssData.htmlSpecific.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingXssAngular = xssData.angularPayloads.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    // Search in HTML payloads (separate from XSS)
    const matchingHtmlPayloads = htmlPayloadsData.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingLfi = lfiData.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingCmd = cmdInjectionData.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingSql = sqlInjectionData.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingRegex = regexData.filter(item => 
        item.pattern.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    const matchingResources = resourcesData.filter(item => 
        item.name.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );
    
    // Update tables with matched results
    populateTable('wordlists-table', matchingWordlists, createWordlistRow);
    
    // Update XSS tables with filtered results
    populateTable('xss-basic-table', matchingXssBasic, createPayloadRow);
    populateTable('xss-tags-table', matchingXssTags, createPayloadRow);
    populateTable('xss-attributes-table', matchingXssAttributes, createPayloadRow);
    populateTable('xss-encoded-table', matchingXssEncoded, createPayloadRow);
    populateTable('xss-dom-table', matchingXssDom, createPayloadRow);
    populateTable('xss-evasion-table', matchingXssEvasion, createPayloadRow);
    populateTable('xss-events-table', matchingXssEvents, createPayloadRow);
    populateTable('xss-waf-table', matchingXssWaf, createPayloadRow);
    populateTable('xss-polyglots-table', matchingXssPolyglots, createPayloadRow);
    populateTable('xss-context-table', matchingXssContext, createBrowserSpecificRow);
    populateTable('xss-browser-table', matchingXssBrowser, createBrowserSpecificRow);
    populateTable('xss-css-table', matchingXssCss, createBrowserSpecificRow);
    populateTable('xss-html-specific-table', matchingXssHtmlSpecific, createPayloadRow);
    populateTable('xss-angular-table', matchingXssAngular, createPayloadRow);
    
    // Update HTML payloads table (separate from XSS)
    populateTable('html-payloads-table', matchingHtmlPayloads, createPayloadRow);
    
    populateTable('lfi-table', matchingLfi, createPayloadRow);
    populateTable('cmd-table', matchingCmd, createPayloadRow);
    populateTable('sql-table', matchingSql, createPayloadRow);
    populateTable('regex-table', matchingRegex, createRegexRow);
    populateTable('resources-table', matchingResources, createResourceRow);
    
    // Show no results message if no matches found
    const totalResults = matchingWordlists.length + 
                         matchingXssBasic.length + matchingXssTags.length + 
                         matchingXssAttributes.length + matchingXssEncoded.length +
                         matchingXssDom.length + matchingXssEvasion.length +
                         matchingXssEvents.length + matchingXssWaf.length +
                         matchingXssPolyglots.length + matchingXssContext.length +
                         matchingXssBrowser.length + matchingXssCss.length +
                         matchingXssHtmlSpecific.length + matchingXssAngular.length +
                         matchingHtmlPayloads.length +
                         matchingLfi.length + matchingCmd.length + 
                         matchingSql.length + matchingRegex.length + 
                         matchingResources.length;
    
    if (totalResults === 0) {
        showNoResultsMessage();
    } else {
        // If any XSS results found, highlight the tab with results
        const xssTabHasResults = matchingXssBasic.length > 0 || matchingXssTags.length > 0 || 
                                 matchingXssAttributes.length > 0 || matchingXssEncoded.length > 0 ||
                                 matchingXssDom.length > 0 || matchingXssEvasion.length > 0 ||
                                 matchingXssEvents.length > 0 || matchingXssWaf.length > 0 ||
                                 matchingXssPolyglots.length > 0 || matchingXssContext.length > 0 ||
                                 matchingXssBrowser.length > 0 || matchingXssCss.length > 0 ||
                                 matchingXssHtmlSpecific.length > 0 || matchingXssAngular.length > 0;
                                 
        if (xssTabHasResults) {
            // Activate the first tab that has results
            const tabsToCheck = [
                { id: 'basic-tab', results: matchingXssBasic },
                { id: 'tags-tab', results: matchingXssTags },
                { id: 'attributes-tab', results: matchingXssAttributes },
                { id: 'encoded-tab', results: matchingXssEncoded },
                { id: 'dom-tab', results: matchingXssDom },
                { id: 'evasion-tab', results: matchingXssEvasion },
                { id: 'events-tab', results: matchingXssEvents },
                { id: 'waf-tab', results: matchingXssWaf },
                { id: 'polyglots-tab', results: matchingXssPolyglots },
                { id: 'context-tab', results: matchingXssContext },
                { id: 'browser-tab', results: matchingXssBrowser },
                { id: 'css-tab', results: matchingXssCss },
                { id: 'html-specific-tab', results: matchingXssHtmlSpecific },
                { id: 'angular-tab', results: matchingXssAngular }
            ];
            
            for (const tab of tabsToCheck) {
                if (tab.results.length > 0) {
                    document.getElementById(tab.id).click();
                    break;
                }
            }
        }
    }
}

// Reset search to show all data
function resetSearch() {
    // Clear any no results messages
    document.querySelectorAll('.no-results').forEach(el => el.remove());
    
    // Repopulate all tables with complete data
    populateTable('wordlists-table', wordlistsData, createWordlistRow);
    
    // Repopulate XSS tables
    populateTable('xss-basic-table', xssData.basicPayloads, createPayloadRow);
    populateTable('xss-tags-table', xssData.tagsBypass, createPayloadRow);
    populateTable('xss-attributes-table', xssData.attributesBypass, createPayloadRow);
    populateTable('xss-encoded-table', xssData.htmlEncoded, createPayloadRow);
    populateTable('xss-dom-table', xssData.domBasedXSS, createPayloadRow);
    populateTable('xss-evasion-table', xssData.filterEvasion, createPayloadRow);
    populateTable('xss-events-table', xssData.eventHandlers, createPayloadRow);
    populateTable('xss-waf-table', xssData.wafBypass, createPayloadRow);
    populateTable('xss-polyglots-table', xssData.polyglots, createPayloadRow);
    populateTable('xss-context-table', xssData.contextSpecific, createBrowserSpecificRow);
    populateTable('xss-browser-table', xssData.browserSpecific, createBrowserSpecificRow);
    populateTable('xss-css-table', xssData.cssBased, createBrowserSpecificRow);
    populateTable('xss-html-specific-table', xssData.htmlSpecific, createPayloadRow);
    populateTable('xss-angular-table', xssData.angularPayloads, createPayloadRow);
    
    // Repopulate HTML payloads table
    populateTable('html-payloads-table', htmlPayloadsData, createPayloadRow);
    
    populateTable('lfi-table', lfiData, createPayloadRow);
    populateTable('cmd-table', cmdInjectionData, createPayloadRow);
    populateTable('sql-table', sqlInjectionData, createPayloadRow);
    populateTable('regex-table', regexData, createRegexRow);
    populateTable('resources-table', resourcesData, createResourceRow);
}

// Show a message when no search results are found
function showNoResultsMessage() {
    const tables = ['wordlists-table', 'xss-table', 'lfi-table', 'cmd-table', 
                    'sql-table', 'regex-table', 'resources-table'];
    
    tables.forEach(tableId => {
        const table = document.getElementById(tableId);
        if (!table) return;
        
        if (table.children.length === 0) {
            const tableParent = table.parentElement;
            
            // Only add if no message exists yet
            if (!tableParent.querySelector('.no-results')) {
                const noResults = document.createElement('div');
                noResults.className = 'no-results';
                noResults.textContent = 'No matching results found';
                tableParent.appendChild(noResults);
            }
        }
    });
}
