// Main JavaScript for Security Payload Repository

// Application version
const APP_VERSION = 'v1.0.0';

// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the page
    initializePage();
    
    // Set up event listeners
    setupEventListeners();
    
    // Add mobile-specific event handlers
    setupMobileInteractions();
    
    // Initialize favorite payloads
    initializeFavorites();
    
    // Initialize recent payloads view
    initializeRecentPayloads();
    
    // Initialize tab scrolling system
    initializeTabScrolling();
    
    // Display version information
    displayVersionInfo();
});

// Display version information in the footer
function displayVersionInfo() {
    const footerText = document.querySelector('footer p');
    
    if (footerText) {
        // Add version info to the footer text
        footerText.innerHTML += ` | ${APP_VERSION}`;
    } else {
        // If no footer paragraph exists, create a version element elsewhere
        const versionElement = document.createElement('div');
        versionElement.className = 'version-info text-end small text-muted me-2 mb-2';
        versionElement.textContent = APP_VERSION;
        
        // Add to the bottom of the main container
        const mainContainer = document.querySelector('main.container-fluid') || document.querySelector('main.container');
        if (mainContainer) {
            mainContainer.appendChild(versionElement);
        }
    }
    
    // Also add version to page title (optional)
    const pageTitle = document.title;
    if (pageTitle && !pageTitle.includes(APP_VERSION)) {
        document.title = `${pageTitle} | ${APP_VERSION}`;
    }
}

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
    populateTable('xss-html-specific-table', xssData.htmlSpecific, createPayloadRow);
    populateTable('xss-angular-table', xssData.angularPayloads, createPayloadRow);
    
    // Populate HTML payloads table
    populateTable('html-payloads-table', htmlPayloadsData, createPayloadRow);
    
    populateTable('lfi-table', lfiData, createPayloadRow);
    populateTable('cmd-table', cmdInjectionData, createPayloadRow);
    populateTable('sql-table', sqlInjectionData, createPayloadRow);
    populateTable('csv-table', csvInjectionData, createPayloadRow);
    populateTable('regex-table', regexData, createRegexRow);
    populateTable('resources-table', resourcesData, createResourceRow);
    
    // Populate Windows and Linux Privilege Escalation tables
    populateTable('windows-privesc-table', windowsPrivescData, createPayloadRow);
    populateTable('windows-privesc-resources-table', windowsPrivescResourcesData, createResourceRow);
    populateTable('linux-privesc-table', linuxPrivescData, createPayloadRow);
    populateTable('linux-privesc-resources-table', linuxPrivescResourcesData, createResourceRow);
    
    // Create the notification element for copy operations
    createCopyNotification();
    
    // Initialize skeleton loading state
    showSkeletonLoaders();
    
    // Initialize tab persistence
    initializeTabPersistence();
    
    // Simulate loading data (remove in production if data is loaded immediately)
    setTimeout(() => {
        hideSkeletonLoaders();
    }, 800);
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
    
    // Add animation effect for theme transition
    document.body.classList.add('theme-transition');
    setTimeout(() => {
        document.body.classList.remove('theme-transition');
    }, 1000);
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
    
    // If wordlist has a link, add Open button
    if (wordlist.link) {
        // Open link button
        const link = document.createElement('a');
        link.href = wordlist.link;
        link.target = '_blank';
        link.className = 'btn btn-sm btn-primary';
        link.innerHTML = '<i class="fas fa-external-link-alt"></i> Open';
        btnGroup.appendChild(link);
        
        // Copy content button for linked wordlists
        const copyContentBtn = document.createElement('button');
        copyContentBtn.className = 'btn btn-sm btn-success';
        copyContentBtn.innerHTML = '<i class="fas fa-file-download"></i> Copy Content';
        copyContentBtn.addEventListener('click', function() {
            fetchAndCopyWordlistContent(wordlist.link, wordlist.name);
        });
        btnGroup.appendChild(copyContentBtn);
    } 
    // If wordlist has direct content
    else if (wordlist.content) {
        // View content button
        const viewContentBtn = document.createElement('button');
        viewContentBtn.className = 'btn btn-sm btn-primary';
        viewContentBtn.innerHTML = '<i class="fas fa-eye"></i> View';
        viewContentBtn.addEventListener('click', function() {
            showContentModal(wordlist.name, wordlist.content);
        });
        btnGroup.appendChild(viewContentBtn);
        
        // Copy content button for direct content
        const copyContentBtn = document.createElement('button');
        copyContentBtn.className = 'btn btn-sm btn-success';
        copyContentBtn.innerHTML = '<i class="fas fa-copy"></i> Copy';
        copyContentBtn.addEventListener('click', function() {
            copyToClipboard(wordlist.content);
        });
        btnGroup.appendChild(copyContentBtn);
    }
    
    // Add buttons to group and cell
    linkCell.appendChild(btnGroup);
    row.appendChild(linkCell);
    
    return row;
}

// Function to show a modal with wordlist content
function showContentModal(title, content) {
    // Check if modal container exists, create if not
    let modalContainer = document.getElementById('content-modal-container');
    if (!modalContainer) {
        modalContainer = document.createElement('div');
        modalContainer.id = 'content-modal-container';
        document.body.appendChild(modalContainer);
    }
    
    // Create modal HTML
    modalContainer.innerHTML = `
        <div class="modal fade" id="contentModal" tabindex="-1" aria-labelledby="contentModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg modal-dialog-scrollable">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="contentModalLabel">${title}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <pre class="content-pre"><code>${escapeHtml(content)}</code></pre>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-primary" id="copyModalContentBtn">
                            <i class="fas fa-copy"></i> Copy Content
                        </button>
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Initialize the modal
    const contentModal = new bootstrap.Modal(document.getElementById('contentModal'));
    contentModal.show();
    
    // Add copy button functionality
    document.getElementById('copyModalContentBtn').addEventListener('click', function() {
        copyToClipboard(content);
    });
}

// Helper function to escape HTML entities
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
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
    
    // Action cell (copy button and favorite button)
    const actionCell = document.createElement('td');
    const buttonGroup = document.createElement('div');
    buttonGroup.className = 'btn-group';
    
    // Copy button with enhanced animation
    const copyButton = document.createElement('button');
    copyButton.className = 'btn btn-sm btn-primary btn-copy';
    copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
    copyButton.addEventListener('click', function() {
        copyToClipboard(payload.payload);
        
        // Add the copied class for animation
        this.classList.add('copied');
        setTimeout(() => {
            this.classList.remove('copied');
        }, 1500);
    });
    
    // Favorite button
    const favoriteButton = document.createElement('button');
    favoriteButton.className = 'btn btn-sm btn-secondary btn-favorite';
    favoriteButton.innerHTML = '<i class="far fa-star"></i>';
    favoriteButton.dataset.payload = payload.payload;
    favoriteButton.dataset.description = payload.description;
    favoriteButton.title = "Add to favorites";
    
    // Check if this payload is already in favorites
    if (isPayloadFavorited(payload.payload)) {
        favoriteButton.classList.add('active');
        favoriteButton.innerHTML = '<i class="fas fa-star"></i>';
    }
    
    favoriteButton.addEventListener('click', function() {
        toggleFavoritePayload(payload.payload, payload.description);
        
        if (this.classList.contains('active')) {
            this.classList.remove('active');
            this.innerHTML = '<i class="far fa-star"></i>';
        } else {
            this.classList.add('active');
            this.innerHTML = '<i class="fas fa-star"></i>';
            
            // Add animation effect
            this.animate([
                { transform: 'scale(1)' },
                { transform: 'scale(1.3)' },
                { transform: 'scale(1)' }
            ], {
                duration: 300,
                easing: 'ease-in-out'
            });
        }
    });
    
    buttonGroup.appendChild(copyButton);
    buttonGroup.appendChild(favoriteButton);
    actionCell.appendChild(buttonGroup);
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

// Copy text to clipboard with enhanced feedback
function copyToClipboard(text) {
    // Try to use the modern clipboard API first
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
            .then(() => {
                showCopyNotification();
                trackRecentPayload(text);
            })
            .catch(err => {
                console.error('Failed to copy: ', err);
                fallbackCopyToClipboard(text);
            });
    } else {
        // Fall back to the older method
        fallbackCopyToClipboard(text);
        trackRecentPayload(text);
    }
}

// Fallback copy method using execCommand
function fallbackCopyToClipboard(text) {
    // Create a temporary textarea element to copy from
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'absolute';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    
    // For iOS devices
    if (navigator.userAgent.match(/ipad|ipod|iphone/i)) {
        // Create a range and selection
        const range = document.createRange();
        range.selectNodeContents(textarea);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        textarea.setSelectionRange(0, 999999);
    } else {
        // Select the text for other devices
        textarea.select();
    }
    
    // Execute copy command
    const successful = document.execCommand('copy');
    document.body.removeChild(textarea);
    
    // Show copy notification
    if (successful) {
        showCopyNotification();
    } else {
        showCopyNotification('Copy failed. Please try again.');
    }
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

// Show the copy notification with improved styling
function showCopyNotification(message = 'Copied to clipboard!') {
    const notification = document.getElementById('copyNotification');
    if (!notification) return;
    
    // Update notification text
    notification.textContent = message;
    
    // Show the notification with improved animation
    notification.style.display = 'block';
    notification.classList.add('fade-in-out');
    
    // Add slide-in animation
    notification.animate([
        { transform: 'translateY(-20px)', opacity: 0 },
        { transform: 'translateY(0)', opacity: 1 }
    ], {
        duration: 300,
        easing: 'ease-out'
    });
    
    // Hide it after animation completes with slide-out
    setTimeout(function() {
        notification.animate([
            { transform: 'translateY(0)', opacity: 1 },
            { transform: 'translateY(-20px)', opacity: 0 }
        ], {
            duration: 300,
            easing: 'ease-in'
        }).onfinish = () => {
            notification.style.display = 'none';
            notification.classList.remove('fade-in-out');
        };
    }, 1700);
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

    // Windows and Linux privilege escalation
    const matchingWindowsPrivesc = windowsPrivescData.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );

    const matchingWindowsPrivescResources = windowsPrivescResourcesData.filter(item => 
        item.name.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );

    const matchingLinuxPrivesc = linuxPrivescData.filter(item => 
        item.payload.toLowerCase().includes(query) || 
        item.description.toLowerCase().includes(query)
    );

    const matchingLinuxPrivescResources = linuxPrivescResourcesData.filter(item => 
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
    populateTable('windows-privesc-table', matchingWindowsPrivesc, createPayloadRow);
    populateTable('windows-privesc-resources-table', matchingWindowsPrivescResources, createResourceRow);
    populateTable('linux-privesc-table', matchingLinuxPrivesc, createPayloadRow);
    populateTable('linux-privesc-resources-table', matchingLinuxPrivescResources, createResourceRow);
    
    // Define sections and their matching results
    const sections = [
        { id: 'wordlists', results: matchingWordlists },
        { id: 'xss', results: [
            ...matchingXssBasic, ...matchingXssTags, ...matchingXssAttributes, 
            ...matchingXssEncoded, ...matchingXssDom, ...matchingXssEvasion,
            ...matchingXssEvents, ...matchingXssWaf, ...matchingXssPolyglots,
            ...matchingXssContext, ...matchingXssBrowser, ...matchingXssCss,
            ...matchingXssHtmlSpecific, ...matchingXssAngular
        ]},
        { id: 'html-payloads', results: matchingHtmlPayloads },
        { id: 'lfi', results: matchingLfi },
        { id: 'cmd-injection', results: matchingCmd },
        { id: 'sql-injection', results: matchingSql },
        { id: 'regex', results: matchingRegex },
        { id: 'resources', results: matchingResources },
        { id: 'windows-privesc', results: [...matchingWindowsPrivesc, ...matchingWindowsPrivescResources] },
        { id: 'linux-privesc', results: [...matchingLinuxPrivesc, ...matchingLinuxPrivescResources] }
    ];
    
    // Hide sections with no matches
    sections.forEach(section => {
        const sectionEl = document.getElementById(section.id);
        if (sectionEl) {
            if (section.results.length === 0) {
                sectionEl.classList.add('d-none');
            } else {
                sectionEl.classList.remove('d-none');
            }
        }
    });
    
    // Show no results message if no matches found
    const totalResults = sections.reduce((sum, section) => sum + section.results.length, 0);
    
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

        // Add a summary indicator showing search is filtered
        const searchInput = document.getElementById('search-input');
        if (searchInput && searchInput.nextElementSibling && searchInput.nextElementSibling.nextElementSibling) {
            let clearSearchButton = document.getElementById('clear-search-button');
            if (clearSearchButton) {
                clearSearchButton.classList.remove('d-none');
                clearSearchButton.addEventListener('click', function() {
                    searchInput.value = '';
                    resetSearch();
                    this.classList.add('d-none');
                });
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

// Set up mobile-specific interactions
function setupMobileInteractions() {
    // Close navbar when clicking a link (mobile)
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    const navbarCollapse = document.querySelector('.navbar-collapse');
    
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            if (window.innerWidth < 992) {  // Only on mobile/tablet
                navbarCollapse.classList.remove('show');
            }
        });
    });
    
    // Better touch handling for copy buttons on mobile
    const copyButtons = document.querySelectorAll('.btn-copy');
    copyButtons.forEach(button => {
        button.addEventListener('touchstart', function(e) {
            // Add a visual feedback on touch
            this.classList.add('active');
            // Prevent double-tap zoom on iOS
            e.preventDefault();
        });
        
        button.addEventListener('touchend', function(e) {
            // Remove the visual feedback
            this.classList.remove('active');
        });
    });
    
    // Adjust notification position based on screen size
    window.addEventListener('resize', adjustNotificationPosition);
    adjustNotificationPosition();
    
    // Enable horizontal scrolling for tabs on mobile with touch events
    setupTabsScrolling();
    
    // Improve mobile performance by debouncing scroll events
    setupScrollOptimization();
    
    // Setup double-tap prevention for buttons
    setupDoubleTapPrevention();
    
    // Add orientation change handler to fix layout issues
    window.addEventListener('orientationchange', handleOrientationChange);
    
    // Add hover simulation for mobile
    simulateTouchHover();
    
    // Add sticky search for mobile
    setupMobileStickySearch();
    
    // Setup tag filtering
    setupTagFiltering();
}

// Handle orientation changes
function handleOrientationChange() {
    // Force layout recalculation
    setTimeout(() => {
        // Adjust notification position
        adjustNotificationPosition();
        
        // Fix iOS viewport height issue on orientation change
        const vh = window.innerHeight * 0.01;
        document.documentElement.style.setProperty('--vh', `${vh}px`);
        
        // Scroll to current position to fix rendering issues
        window.scrollTo(window.scrollX, window.scrollY);
    }, 300);
}

// Optimize scrolling performance on mobile
function setupScrollOptimization() {
    let scrollTimeout;
    const body = document.body;
    
    window.addEventListener('scroll', function() {
        if (!body.classList.contains('is-scrolling')) {
            body.classList.add('is-scrolling');
        }
        
        clearTimeout(scrollTimeout);
        scrollTimeout = setTimeout(function() {
            body.classList.remove('is-scrolling');
        }, 200);
    }, { passive: true });
}

// Prevent unwanted double-tap zooming on buttons and interactive elements
function setupDoubleTapPrevention() {
    const interactiveElements = document.querySelectorAll('button, .btn, .nav-link, .card-header');
    
    interactiveElements.forEach(element => {
        element.addEventListener('touchend', function(e) {
            // Prevent default only for touchend events that might trigger zoom
            if (e.cancelable) {
                e.preventDefault();
            }
        });
    });
}

// Adjust notification position based on screen size
function adjustNotificationPosition() {
    const notification = document.getElementById('copyNotification');
    if (!notification) return;
    
    // Set viewport-relative positioning for better mobile display
    if (window.innerWidth < 576) {
        notification.style.top = '10px';
        notification.style.right = '10px';
        notification.style.left = '10px';
        notification.style.width = 'auto';
        notification.style.maxWidth = 'calc(100vw - 20px)';
        notification.style.textAlign = 'center';
        notification.style.fontSize = '14px';
        notification.style.padding = '8px';
    } else {
        notification.style.top = '20px';
        notification.style.right = '20px';
        notification.style.left = 'auto';
        notification.style.width = 'auto';
        notification.style.maxWidth = '300px';
        notification.style.fontSize = '16px';
        notification.style.padding = '10px 15px';
    }
    
    // Fix for notch displays and safe areas on modern phones
    if ('CSS' in window && CSS.supports('padding-bottom: env(safe-area-inset-bottom)')) {
        notification.style.paddingRight = 'calc(15px + env(safe-area-inset-right))';
    }
}

// Setup improved touch scrolling for tabs on mobile
function setupTabsScrolling() {
    const tabLists = document.querySelectorAll('.nav-tabs');
    
    tabLists.forEach(tabList => {
        // Make tab list scrollable on mobile
        if (window.innerWidth < 768) {
            tabList.style.overflowX = 'auto';
            tabList.style.flexWrap = 'nowrap';
            tabList.style.scrollBehavior = 'smooth';
            tabList.style.webkitOverflowScrolling = 'touch';
        }
        
        let isDown = false;
        let startX;
        let scrollLeft;
        
        tabList.addEventListener('touchstart', (e) => {
            isDown = true;
            tabList.style.scrollBehavior = 'auto'; // Disable smooth scrolling during touch movement
            startX = e.touches[0].pageX - tabList.offsetLeft;
            scrollLeft = tabList.scrollLeft;
        }, { passive: true });
        
        tabList.addEventListener('touchend', () => {
            isDown = false;
            tabList.style.scrollBehavior = 'smooth'; // Re-enable smooth scrolling
        });
        
        tabList.addEventListener('touchmove', (e) => {
            if (!isDown) return;
            const x = e.touches[0].pageX - tabList.offsetLeft;
            const walk = (x - startX) * 1.5; // Scroll speed multiplier
            tabList.scrollLeft = scrollLeft - walk;
        }, { passive: true });
    });
    
    // Add scroll indicators for tabs on mobile
    addTabScrollIndicators();
}

// Add visual indicators that tabs are scrollable on mobile
function addTabScrollIndicators() {
    const tabContainers = document.querySelectorAll('.nav-tabs-container, .tab-container');
    
    tabContainers.forEach(container => {
        // Remove any existing indicators
        const existingIndicators = container.querySelectorAll('.tab-scroll-indicator');
        existingIndicators.forEach(el => el.remove());
        
        if (window.innerWidth < 768) {
            const tabList = container.querySelector('.nav-tabs');
            if (!tabList) return;
            
            // Only add indicators if content is scrollable
            if (tabList.scrollWidth > tabList.clientWidth) {
                // Add left and right indicators
                const leftIndicator = document.createElement('div');
                leftIndicator.className = 'tab-scroll-indicator tab-scroll-left';
                leftIndicator.innerHTML = '<i class="fas fa-chevron-left"></i>';
                
                const rightIndicator = document.createElement('div');
                rightIndicator.className = 'tab-scroll-indicator tab-scroll-right';
                rightIndicator.innerHTML = '<i class="fas fa-chevron-right"></i>';
                
                container.appendChild(leftIndicator);
                container.appendChild(rightIndicator);
                
                // Show/hide indicators based on scroll position
                updateScrollIndicators(tabList, leftIndicator, rightIndicator);
                
                tabList.addEventListener('scroll', () => {
                    updateScrollIndicators(tabList, leftIndicator, rightIndicator);
                });
                
                // Add click handlers to scroll tabs
                leftIndicator.addEventListener('click', () => {
                    tabList.scrollBy({ left: -100, behavior: 'smooth' });
                });
                
                rightIndicator.addEventListener('click', () => {
                    tabList.scrollBy({ left: 100, behavior: 'smooth' });
                });
            }
        }
    });
}

// Update scroll indicators visibility based on scroll position
function updateScrollIndicators(tabList, leftIndicator, rightIndicator) {
    if (tabList.scrollLeft <= 10) {
        leftIndicator.style.opacity = '0';
    } else {
        leftIndicator.style.opacity = '1';
    }
    
    if (tabList.scrollLeft + tabList.clientWidth >= tabList.scrollWidth - 10) {
        rightIndicator.style.opacity = '0';
    } else {
        rightIndicator.style.opacity = '1';
    }
}

// Fix iOS 100vh issue for full-height elements
function setupViewportHeightFix() {
    // Set the value of --vh to 1% of the viewport height
    const setVh = () => {
        const vh = window.innerHeight * 0.01;
        document.documentElement.style.setProperty('--vh', `${vh}px`);
    };
    
    // Set initial value
    setVh();
    
    // Update on resize and orientation change
    window.addEventListener('resize', setVh);
    window.addEventListener('orientationchange', setVh);
}

// Initialize favorites system
function initializeFavorites() {
    // Create favorites container if it doesn't exist
    if (!document.getElementById('favorites-container')) {
        const mainContainer = document.querySelector('.container-fluid') || document.querySelector('.container');
        if (!mainContainer) return;
        
        const favoritesSection = document.createElement('div');
        favoritesSection.id = 'favorites-container';
        favoritesSection.className = 'row mb-4 d-none';
        
        const favoritesTitleRow = document.createElement('div');
        favoritesTitleRow.className = 'col-12';
        favoritesTitleRow.innerHTML = `
            <div class="d-flex justify-content-between align-items-center">
                <h3><i class="fas fa-star text-warning"></i> Favorite Payloads</h3>
                <button id="clear-favorites" class="btn btn-sm btn-outline-danger">
                    <i class="fas fa-trash-alt"></i> Clear All
                </button>
            </div>
            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead>
                        <tr>
                            <th>Payload</th>
                            <th>Description</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="favorites-table"></tbody>
                </table>
            </div>
        `;
        
        favoritesSection.appendChild(favoritesTitleRow);
        
        // Insert after search but before main content
        const searchRow = document.querySelector('.row:has(#search-input)');
        if (searchRow) {
            mainContainer.insertBefore(favoritesSection, searchRow.nextSibling);
        } else {
            mainContainer.insertBefore(favoritesSection, mainContainer.firstChild);
        }
        
        // Add event listener for clear favorites button
        document.getElementById('clear-favorites').addEventListener('click', clearAllFavorites);
    }
    
    // Load and display favorites
    loadFavorites();
}

// Check if a payload is in favorites
function isPayloadFavorited(payload) {
    const favorites = JSON.parse(localStorage.getItem('favoritePayloads') || '[]');
    return favorites.some(item => item.payload === payload);
}

// Toggle a payload in favorites
function toggleFavoritePayload(payload, description) {
    let favorites = JSON.parse(localStorage.getItem('favoritePayloads') || '[]');
    
    const existingIndex = favorites.findIndex(item => item.payload === payload);
    
    if (existingIndex >= 0) {
        // Remove from favorites
        favorites.splice(existingIndex, 1);
    } else {
        // Add to favorites
        favorites.push({
            payload: payload,
            description: description,
            dateAdded: new Date().toISOString()
        });
    }
    
    // Save to localStorage
    localStorage.setItem('favoritePayloads', JSON.stringify(favorites));
    
    // Update the favorites display
    loadFavorites();
}

// Load favorites from localStorage and display them
function loadFavorites() {
    const favoritesTable = document.getElementById('favorites-table');
    const favoritesContainer = document.getElementById('favorites-container');
    
    if (!favoritesTable || !favoritesContainer) return;
    
    const favorites = JSON.parse(localStorage.getItem('favoritePayloads') || '[]');
    
    // Show or hide favorites section based on content
    if (favorites.length === 0) {
        favoritesContainer.classList.add('d-none');
        return;
    } else {
        favoritesContainer.classList.remove('d-none');
    }
    
    // Clear existing table
    favoritesTable.innerHTML = '';
    
    // Add each favorite
    favorites.forEach(favorite => {
        const row = document.createElement('tr');
        
        // Payload cell
        const payloadCell = document.createElement('td');
        const payloadText = document.createElement('code');
        payloadText.className = 'payload-text';
        payloadText.textContent = favorite.payload;
        payloadCell.appendChild(payloadText);
        row.appendChild(payloadCell);
        
        // Description cell
        const descriptionCell = document.createElement('td');
        descriptionCell.textContent = favorite.description;
        row.appendChild(descriptionCell);
        
        // Action cell
        const actionCell = document.createElement('td');
        const buttonGroup = document.createElement('div');
        buttonGroup.className = 'btn-group';
        
        // Copy button
        const copyButton = document.createElement('button');
        copyButton.className = 'btn btn-sm btn-primary btn-copy';
        copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
        copyButton.addEventListener('click', function() {
            copyToClipboard(favorite.payload);
            
            // Add the copied class for animation
            this.classList.add('copied');
            setTimeout(() => {
                this.classList.remove('copied');
            }, 1500);
        });
        
        // Remove favorite button
        const removeButton = document.createElement('button');
        removeButton.className = 'btn btn-sm btn-danger';
        removeButton.innerHTML = '<i class="fas fa-trash-alt"></i>';
        removeButton.addEventListener('click', function() {
            toggleFavoritePayload(favorite.payload, favorite.description);
            
            // Remove row with animation
            row.style.transition = 'opacity 0.3s ease';
            row.style.opacity = '0';
            setTimeout(() => {
                row.remove();
                
                // If no favorites left, hide the container
                if (favoritesTable.children.length === 0) {
                    favoritesContainer.classList.add('d-none');
                }
            }, 300);
        });
        
        buttonGroup.appendChild(copyButton);
        buttonGroup.appendChild(removeButton);
        actionCell.appendChild(buttonGroup);
        row.appendChild(actionCell);
        
        favoritesTable.appendChild(row);
    });
}

// Clear all favorites
function clearAllFavorites() {
    if (confirm('Are you sure you want to clear all favorite payloads?')) {
        localStorage.removeItem('favoritePayloads');
        
        const favoritesContainer = document.getElementById('favorites-container');
        if (favoritesContainer) {
            favoritesContainer.classList.add('d-none');
        }
    }
}

// Track payload usage for recent payloads feature
function trackRecentPayload(payload) {
    // Function disabled - Recently Used Payloads feature removed
    return;
}

// Load and display recent payloads
function loadRecentPayloads() {
    // Function disabled - Recently Used Payloads feature removed
    return;
}

// Initialize recent payloads tracking
function initializeRecentPayloads() {
    // Function disabled - Recently Used Payloads feature removed
    return;
}

// Show skeleton loaders during initial data load
function showSkeletonLoaders() {
    const tables = document.querySelectorAll('.table tbody');
    
    tables.forEach(table => {
        if (table.children.length === 0) {
            const skeletonLoader = document.createElement('div');
            skeletonLoader.className = 'skeleton-loader';
            
            // Create 3 skeleton rows
            for (let i = 0; i < 3; i++) {
                const skeletonRow = document.createElement('div');
                skeletonRow.className = 'skeleton-row';
                
                // Create cells for each row
                const payloadCell = document.createElement('div');
                payloadCell.className = 'skeleton-cell';
                payloadCell.style.width = '40%';
                
                const descCell = document.createElement('div');
                descCell.className = 'skeleton-cell';
                descCell.style.width = '45%';
                
                const actionCell = document.createElement('div');
                actionCell.className = 'skeleton-cell';
                actionCell.style.width = '15%';
                
                skeletonRow.appendChild(payloadCell);
                skeletonRow.appendChild(descCell);
                skeletonRow.appendChild(actionCell);
                
                skeletonLoader.appendChild(skeletonRow);
            }
            
            table.parentNode.insertBefore(skeletonLoader, table);
        }
    });
}

// Hide skeleton loaders after data is loaded
function hideSkeletonLoaders() {
    document.querySelectorAll('.skeleton-loader').forEach(loader => {
        loader.animate([
            { opacity: 1 },
            { opacity: 0 }
        ], {
            duration: 300,
            easing: 'ease-out'
        }).onfinish = () => loader.remove();
    });
}

// Initialize scrollable tabs functionality
function initializeTabScrolling() {
    const tabsLists = document.querySelectorAll('.nav-tabs, [role="tablist"]');
    
    tabsLists.forEach(tabsList => {
        // Skip if already in a scrollable container
        if (tabsList.closest('.scrollable-tabs')) return;
        
        // Create container for scrollable tabs
        const tabsContainer = document.createElement('div');
        tabsContainer.className = 'tabs-container';
        
        // Create the scrollable tabs wrapper
        const scrollableTabs = document.createElement('div');
        scrollableTabs.className = 'scrollable-tabs';
        
        // Move the tabs into the scrollable container
        tabsList.parentNode.insertBefore(tabsContainer, tabsList);
        scrollableTabs.appendChild(tabsList);
        tabsContainer.appendChild(scrollableTabs);
        
        // Add left and right scroll indicators
        const leftIndicator = document.createElement('div');
        leftIndicator.className = 'tabs-scroll-indicator left-indicator';
        leftIndicator.innerHTML = '<i class="fas fa-chevron-left"></i>';
        
        const rightIndicator = document.createElement('div');
        rightIndicator.className = 'tabs-scroll-indicator right-indicator';
        rightIndicator.innerHTML = '<i class="fas fa-chevron-right"></i>';
        
        tabsContainer.appendChild(leftIndicator);
        tabsContainer.appendChild(rightIndicator);
        
        // Add scroll event handler
        scrollableTabs.addEventListener('scroll', () => {
            updateTabScrollIndicators(scrollableTabs, leftIndicator, rightIndicator);
        });
        
        // Add click handlers
        leftIndicator.addEventListener('click', () => {
            scrollableTabs.scrollBy({ left: -200, behavior: 'smooth' });
        });
        
        rightIndicator.addEventListener('click', () => {
            scrollableTabs.scrollBy({ left: 200, behavior: 'smooth' });
        });
        
        // Initialize indicators state
        updateTabScrollIndicators(scrollableTabs, leftIndicator, rightIndicator);
        
        // Update on window resize
        window.addEventListener('resize', () => {
            updateTabScrollIndicators(scrollableTabs, leftIndicator, rightIndicator);
        });
    });
}

// Update tab scroll indicators visibility
function updateTabScrollIndicators(scrollContainer, leftIndicator, rightIndicator) {
    // Show/hide left indicator
    if (scrollContainer.scrollLeft <= 5) {
        leftIndicator.classList.remove('show');
    } else {
        leftIndicator.classList.add('show');
    }
    
    // Show/hide right indicator
    if (scrollContainer.scrollLeft + scrollContainer.clientWidth >= scrollContainer.scrollWidth - 5) {
        rightIndicator.classList.remove('show');
    } else {
        rightIndicator.classList.add('show');
    }
}

// Setup tag filtering functionality
function setupTagFiltering() {
    // Function is now empty - tag container functionality removed
    return;
}

// Setup mobile sticky search
function setupMobileStickySearch() {
    if (window.innerWidth < 992) {
        const searchRow = document.querySelector('.row:has(#search-input)');
        if (searchRow) {
            searchRow.classList.add('mobile-search-container');
        }
    }
}

// Simulate hover effects for mobile devices
function simulateTouchHover() {
    const interactiveElements = document.querySelectorAll('.btn, .tag-badge, .nav-link');
    
    interactiveElements.forEach(element => {
        element.addEventListener('touchstart', function() {
            this.classList.add('touch-hover');
        });
        
        element.addEventListener('touchend', function() {
            setTimeout(() => {
                this.classList.remove('touch-hover');
            }, 300);
        });
        
        element.addEventListener('touchcancel', function() {
            this.classList.remove('touch-hover');
        });
    });
}

// Initialize tab persistence to remember last active tab
function initializeTabPersistence() {
    // Set up tab click handler to save active tab state
    document.querySelectorAll('.nav-tabs .nav-link').forEach(tab => {
        tab.addEventListener('click', function() {
            // Get the parent tab container to identify which section this belongs to
            const tabContainer = this.closest('.nav-tabs');
            if (!tabContainer || !tabContainer.id) return;
            
            // Get section ID from the tab container or its parent
            const sectionId = tabContainer.dataset.section || 
                             tabContainer.closest('section')?.id || 
                             tabContainer.closest('.card')?.closest('section')?.id;
            
            if (sectionId) {
                // Save the active tab ID for this section
                localStorage.setItem(`activeTab-${sectionId}`, this.id);
            }
        });
    });
    
    // Restore active tabs for each section
    document.querySelectorAll('section').forEach(section => {
        if (!section.id) return;
        
        const savedTabId = localStorage.getItem(`activeTab-${section.id}`);
        if (savedTabId) {
            const savedTab = document.getElementById(savedTabId);
            if (savedTab) {
                // Delay slightly to ensure tabs are initialized
                setTimeout(() => {
                    // Use bootstrap's tab API to show the saved tab
                    const bsTab = new bootstrap.Tab(savedTab);
                    bsTab.show();
                }, 50);
            }
        }
    });
    
    // Set data-section attribute on tab containers for easier reference
    document.querySelectorAll('.nav-tabs').forEach(tabList => {
        const sectionEl = tabList.closest('section');
        if (sectionEl && sectionEl.id) {
            tabList.dataset.section = sectionEl.id;
        }
    });
}
