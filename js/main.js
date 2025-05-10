// Main JavaScript for Security Payload Repository

// Application version
const APP_VERSION = 'v2.0.0';

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
    
    // Initialize tab scrolling system
    initializeTabScrolling();

    // Set up cloud CLI command copy buttons
    setupCloudCliCopyButtons();
    
    // Initialize encoder functionality
    setupEncoderFunctionality();
    
    // Display version information
    displayVersionInfo();
    
    // Set up home button to refresh the page
    setupHomeButton();
});

// Function to set up home button refresh functionality
function setupHomeButton() {
    const homeButton = document.querySelector('.nav-link[href="#"]');
    if (homeButton) {
        homeButton.addEventListener('click', function(e) {
            e.preventDefault();
            window.location.reload();
        });
    }
}

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
    
    // Populate Cloud Security tables
    // AWS
    populateTable('aws-cli-table', awsSecurityCliData, createCloudCliRow);
    
    // Azure - populate all Azure tables
    populateTable('azure-tools-table', cloudSecurityData.azure.tools, createResourceRow);
    populateTable('azure-privesc-table', cloudSecurityData.azure.privEscTechniques, createCloudPrivEscRow);
    populateTable('azure-cli-table', azureSecurityCliData, createCloudCliRow);
    
    // GCP
    populateTable('gcp-cli-table', gcpSecurityCliData, createCloudCliRow);
    
    // Populate OSINT resources table
    populateTable('osint-table', osintResourcesData, createResourceRow);
    
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

// Create a row for a wordlist item
function createWordlistRow(wordlist) {
    const row = document.createElement('tr');
    
    // Name cell
    const nameCell = document.createElement('td');
    nameCell.textContent = wordlist.name;
    row.appendChild(nameCell);
    
    // Description cell
    const descCell = document.createElement('td');
    descCell.textContent = wordlist.description;
    row.appendChild(descCell);
    
    // Link cell
    const linkCell = document.createElement('td');
    
    // Visit button
    const link = document.createElement('a');
    link.href = wordlist.link;
    link.target = '_blank';
    link.className = 'btn btn-sm btn-primary me-2';
    link.innerHTML = '<i class="fas fa-external-link-alt"></i> Visit';
    linkCell.appendChild(link);
    
    // Copy content button
    const copyButton = document.createElement('button');
    copyButton.className = 'btn btn-sm btn-success';
    copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
    copyButton.addEventListener('click', function() {
        // Fetch content from the link and copy it
        fetch(wordlist.link)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.text();
            })
            .then(content => {
                copyToClipboard(content);
                showCopyNotification('Wordlist content copied to clipboard!');
                
                // Visual feedback
                this.innerHTML = '<i class="fas fa-check"></i> Copied';
                setTimeout(() => {
                    this.innerHTML = '<i class="fas fa-copy"></i> Copy';
                }, 2000);
            })
            .catch(error => {
                console.error('Error fetching wordlist content:', error);
                showNotification('Failed to copy wordlist content. The wordlist might be too large or the server doesn\'t allow direct access.', 'error');
            });
    });
    linkCell.appendChild(copyButton);
    
    row.appendChild(linkCell);
    
    return row;
}

// Create a row for a payload item
function createPayloadRow(payload) {
    const row = document.createElement('tr');
    
    // Payload cell
    const payloadCell = document.createElement('td');
    const payloadCode = document.createElement('code');
    payloadCode.className = 'payload-text';
    payloadCode.textContent = payload.payload;
    payloadCell.appendChild(payloadCode);
    row.appendChild(payloadCell);
    
    // Description cell
    const descCell = document.createElement('td');
    descCell.textContent = payload.description;
    row.appendChild(descCell);
    
    // Action cell (copy button and dropdown)
    const actionCell = document.createElement('td');
    
    // Action button group
    const buttonGroup = document.createElement('div');
    buttonGroup.className = 'btn-group';
    
    // Copy button
    const copyButton = document.createElement('button');
    copyButton.className = 'btn btn-sm btn-success';
    copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
    copyButton.addEventListener('click', function() {
        copyToClipboard(payload.payload);
        showCopyNotification('Payload copied to clipboard!');
        
        // Visual feedback
        this.innerHTML = '<i class="fas fa-check"></i> Copied';
        setTimeout(() => {
            this.innerHTML = '<i class="fas fa-copy"></i> Copy';
        }, 2000);
    });
    
    // Encode dropdown button
    const encodeButton = document.createElement('button');
    encodeButton.className = 'btn btn-sm btn-primary dropdown-toggle';
    encodeButton.innerHTML = '<i class="fas fa-code"></i> Encode';
    encodeButton.setAttribute('type', 'button');
    encodeButton.setAttribute('data-bs-toggle', 'dropdown');
    encodeButton.setAttribute('aria-expanded', 'false');
    
    // Dropdown menu
    const dropdownMenu = document.createElement('ul');
    dropdownMenu.className = 'dropdown-menu';
    
    // Add dropdown items for encoding options
    const encodingOptions = [
        { value: 'html', name: 'HTML Entity' },
        { value: 'url', name: 'URL Encode' },
        { value: 'base64', name: 'Base64 Encode' },
        { value: 'hex', name: 'Hex Encode' },
        { value: 'js_escape', name: 'JS Escape' }
    ];
    
    encodingOptions.forEach(option => {
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.className = 'dropdown-item';
        a.href = '#';
        a.textContent = option.name;
        a.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Switch to encoder tab
            const encoderTab = document.getElementById('encoder-tab');
            if (encoderTab) {
                // Show the XSS tab first if we're in a different section
                const xssTab = document.querySelector('a[href="#xss"]');
                if (xssTab) {
                    xssTab.click();
                }
                
                // Now show the encoder tab within XSS
                const triggerEl = new bootstrap.Tab(encoderTab);
                triggerEl.show();
                
                // Set payload in encoder textarea
                const payloadInput = document.getElementById('payload-to-encode');
                if (payloadInput) {
                    payloadInput.value = payload.payload;
                    
                    // Set encoding method
                    const encodingSelect = document.getElementById('encoding-method-select');
                    if (encodingSelect) {
                        encodingSelect.value = option.value;
                    }
                    
                    // Trigger encoding
                    const encodeButton = document.getElementById('encode-payload-btn');
                    if (encodeButton) {
                        encodeButton.click();
                    }
                    
                    // Scroll to encoder section
                    const encoderSection = document.querySelector('#encoder');
                    if (encoderSection) {
                        encoderSection.scrollIntoView({ behavior: 'smooth' });
                    }
                }
            }
        });
        
        li.appendChild(a);
        dropdownMenu.appendChild(li);
    });
    
    // Add "All Encodings" option
    const allLi = document.createElement('li');
    const allA = document.createElement('a');
    allA.className = 'dropdown-item';
    allA.href = '#';
    allA.textContent = 'All Encodings';
    allA.addEventListener('click', function(e) {
        e.preventDefault();
        
        // Same logic as above but with 'all' encoding option
        const encoderTab = document.getElementById('encoder-tab');
        if (encoderTab) {
            const xssTab = document.querySelector('a[href="#xss"]');
            if (xssTab) xssTab.click();
            
            const triggerEl = new bootstrap.Tab(encoderTab);
            triggerEl.show();
            
            const payloadInput = document.getElementById('payload-to-encode');
            if (payloadInput) {
                payloadInput.value = payload.payload;
                
                const encodingSelect = document.getElementById('encoding-method-select');
                if (encodingSelect) encodingSelect.value = 'all';
                
                const encodeButton = document.getElementById('encode-payload-btn');
                if (encodeButton) encodeButton.click();
                
                const encoderSection = document.querySelector('#encoder');
                if (encoderSection) encoderSection.scrollIntoView({ behavior: 'smooth' });
            }
        }
    });
    
    allLi.appendChild(allA);
    dropdownMenu.appendChild(allLi);
    
    // Assemble button group
    buttonGroup.appendChild(copyButton);
    buttonGroup.appendChild(encodeButton);
    buttonGroup.appendChild(dropdownMenu);
    actionCell.appendChild(buttonGroup);
    row.appendChild(actionCell);
    
    return row;
}

// Create a row for a browser-specific payload
function createBrowserSpecificRow(payload) {
    const row = document.createElement('tr');
    
    // Payload cell
    const payloadCell = document.createElement('td');
    const payloadCode = document.createElement('code');
    payloadCode.className = 'payload-text';
    payloadCode.textContent = payload.payload;
    payloadCell.appendChild(payloadCode);
    row.appendChild(payloadCell);
    
    // Description cell
    const descCell = document.createElement('td');
    descCell.textContent = payload.description;
    row.appendChild(descCell);
    
    // Browser cell (if exists)
    if (payload.browser) {
        const browserCell = document.createElement('td');
        browserCell.textContent = payload.browser;
        row.appendChild(browserCell);
    }
    
    // Action cell (copy button)
    const actionCell = document.createElement('td');
    const copyButton = document.createElement('button');
    copyButton.className = 'btn btn-sm btn-success btn-copy';
    copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
    copyButton.addEventListener('click', function() {
        copyToClipboard(payload.payload);
        showCopyNotification('Payload copied to clipboard!');
        
        // Visual feedback
        this.innerHTML = '<i class="fas fa-check"></i> Copied';
        setTimeout(() => {
            this.innerHTML = '<i class="fas fa-copy"></i> Copy';
        }, 2000);
    });
    actionCell.appendChild(copyButton);
    row.appendChild(actionCell);
    
    return row;
}

// Create a row for a regex pattern
function createRegexRow(regex) {
    const row = document.createElement('tr');
    
    // Pattern cell
    const patternCell = document.createElement('td');
    const patternCode = document.createElement('code');
    patternCode.className = 'payload-text';
    patternCode.textContent = regex.pattern;
    patternCell.appendChild(patternCode);
    row.appendChild(patternCell);
    
    // Description cell
    const descCell = document.createElement('td');
    descCell.textContent = regex.description;
    row.appendChild(descCell);
    
    // Action cell (copy button)
    const actionCell = document.createElement('td');
    const copyButton = document.createElement('button');
    copyButton.className = 'btn btn-sm btn-success btn-copy';
    copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
    copyButton.addEventListener('click', function() {
        copyToClipboard(regex.pattern);
        showCopyNotification('Regex pattern copied to clipboard!');
        
        // Visual feedback
        this.innerHTML = '<i class="fas fa-check"></i> Copied';
        setTimeout(() => {
            this.innerHTML = '<i class="fas fa-copy"></i> Copy';
        }, 2000);
    });
    actionCell.appendChild(copyButton);
    row.appendChild(actionCell);
    
    return row;
}

// Create a row for a resource item
function createResourceRow(resource) {
    const row = document.createElement('tr');
    
    // Name cell
    const nameCell = document.createElement('td');
    nameCell.textContent = resource.name;
    row.appendChild(nameCell);
    
    // Description cell
    const descCell = document.createElement('td');
    descCell.textContent = resource.description;
    row.appendChild(descCell);
    
    // Link cell
    const linkCell = document.createElement('td');
    const link = document.createElement('a');
    link.href = resource.link;
    link.target = '_blank';
    link.className = 'btn btn-sm btn-primary';
    link.innerHTML = '<i class="fas fa-external-link-alt"></i> Visit';
    linkCell.appendChild(link);
    row.appendChild(linkCell);
    
    return row;
}

// Create a row for cloud CLI command
function createCloudCliRow(cli) {
    const row = document.createElement('tr');
    
    // Command cell
    const commandCell = document.createElement('td');
    const commandCode = document.createElement('code');
    commandCode.className = 'cli-command';
    commandCode.textContent = cli.command;
    commandCell.appendChild(commandCode);
    row.appendChild(commandCell);
    
    // Description cell
    const descCell = document.createElement('td');
    descCell.textContent = cli.description;
    row.appendChild(descCell);
    
    // Action cell (copy button)
    const actionCell = document.createElement('td');
    const copyButton = document.createElement('button');
    copyButton.className = 'btn btn-sm btn-success btn-copy';
    copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
    copyButton.addEventListener('click', function() {
        copyToClipboard(cli.command);
        showCopyNotification('Command copied to clipboard!');
        
        // Visual feedback
        this.innerHTML = '<i class="fas fa-check"></i> Copied';
        setTimeout(() => {
            this.innerHTML = '<i class="fas fa-copy"></i> Copy';
        }, 2000);
    });
    actionCell.appendChild(copyButton);
    row.appendChild(actionCell);
    
    return row;
}

// Create a row for cloud privilege escalation techniques
function createCloudPrivEscRow(technique) {
    const row = document.createElement('tr');
    
    // Misconfiguration cell
    const misconfigCell = document.createElement('td');
    misconfigCell.textContent = technique.misconfiguration;
    row.appendChild(misconfigCell);
    
    // Description cell
    const descCell = document.createElement('td');
    descCell.textContent = technique.description;
    row.appendChild(descCell);
    
    // Detection Method cell
    const methodCell = document.createElement('td');
    const methodCode = document.createElement('code');
    methodCode.textContent = technique.detectionMethod;
    methodCell.appendChild(methodCode);
    row.appendChild(methodCell);
    
    return row;
}

// Set up cloud CLI copy buttons for AWS, Azure, and GCP sections
function setupCloudCliCopyButtons() {
    // Find all cloud CLI copy buttons
    const copyButtons = document.querySelectorAll('#aws-cli-tab .btn-copy, #azure-cli-tab .btn-copy, #gcp-cli-tab .btn-copy');
    
    // Add click event listener to each button
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Get the command text from the previous sibling (the <code> element)
            const commandCell = this.closest('tr').querySelector('td:first-child');
            const command = commandCell ? commandCell.querySelector('code').textContent : '';
            
            // Copy the command to clipboard
            copyToClipboard(command);
            
            // Show a notification that the command was copied
            showCopyNotification('Command copied to clipboard!');
            
            // Change button text temporarily to indicate success
            const originalHTML = this.innerHTML;
            this.innerHTML = '<i class="fas fa-check"></i> Copied';
            
            // Revert button text after a short delay
            setTimeout(() => {
                this.innerHTML = originalHTML;
            }, 2000);
        });
    });
}

// Copy text to clipboard
function copyToClipboard(text) {
    // Create a temporary textarea element
    const textarea = document.createElement('textarea');
    textarea.value = text;
    
    // Make the textarea non-editable and invisible
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'absolute';
    textarea.style.left = '-9999px';
    
    // Append the textarea to the DOM
    document.body.appendChild(textarea);
    
    // Select and copy the text
    textarea.select();
    document.execCommand('copy');
    
    // Remove the textarea from the DOM
    document.body.removeChild(textarea);
}

// Create and show a notification when content is copied
function createCopyNotification() {
    // Check if notification element already exists
    if (document.getElementById('copy-notification')) return;
    
    // Create notification element
    const notification = document.createElement('div');
    notification.id = 'copy-notification';
    notification.className = 'copy-notification';
    notification.style.display = 'none';
    
    // Add the notification to the DOM
    document.body.appendChild(notification);
}

// Show a notification with a message
function showCopyNotification(message) {
    const notification = document.getElementById('copy-notification');
    if (!notification) return;
    
    // Set notification text
    notification.textContent = message;
    
    // Show the notification with animation
    notification.style.display = 'block';
    notification.classList.add('show');
    
    // Hide after a delay
    setTimeout(() => {
        notification.classList.remove('show');
        
        // After fade out animation completes
        setTimeout(() => {
            notification.style.display = 'none';
        }, 500);
    }, 2000);
}

// Show skeleton loaders while data is loading
function showSkeletonLoaders() {
    // Get all tables that will have data
    const tables = document.querySelectorAll('table.table');
    
    tables.forEach(table => {
        // Get the table body
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        
        // Add skeleton loader class to the table
        table.classList.add('loading');
        
        // Add skeleton rows (3 per table)
        for (let i = 0; i < 3; i++) {
            const row = document.createElement('tr');
            row.className = 'skeleton-row';
            
            // Add 3 cells per row
            for (let j = 0; j < 3; j++) {
                const cell = document.createElement('td');
                const skeleton = document.createElement('div');
                skeleton.className = 'skeleton-loader';
                cell.appendChild(skeleton);
                row.appendChild(cell);
            }
            
            tbody.appendChild(row);
        }
    });
}

// Hide skeleton loaders when data is loaded
function hideSkeletonLoaders() {
    // Get all tables with loading class
    const tables = document.querySelectorAll('table.table.loading');
    
    tables.forEach(table => {
        // Remove loading class
        table.classList.remove('loading');
        
        // Remove skeleton rows
        const skeletonRows = table.querySelectorAll('.skeleton-row');
        skeletonRows.forEach(row => row.remove());
    });
}

// Initialize mobile-specific interactions
function setupMobileInteractions() {
    // Handle collapsible navigation on mobile
    const navbarToggler = document.querySelector('.navbar-toggler');
    const navbarCollapse = document.querySelector('.navbar-collapse');
    
    if (navbarToggler && navbarCollapse) {
        // Close the navbar when a nav link is clicked on mobile
        const navLinks = navbarCollapse.querySelectorAll('.nav-link');
        navLinks.forEach(link => {
            link.addEventListener('click', () => {
                if (window.innerWidth < 992) {  // Bootstrap lg breakpoint
                    navbarToggler.click();  // Auto-close the navbar
                }
            });
        });
    }
    
    // Back-to-top functionality has been removed
}

// Initialize favorites system
function initializeFavorites() {
    // Load favorites from localStorage
    const favorites = JSON.parse(localStorage.getItem('favorites')) || [];
    
    // Add favorite toggle to all payload cards
    document.querySelectorAll('.payload-card').forEach(card => {
        // Create favorite button if it doesn't exist
        if (!card.querySelector('.favorite-toggle')) {
            const favoriteBtn = document.createElement('button');
            favoriteBtn.className = 'favorite-toggle';
            favoriteBtn.innerHTML = '<i class="far fa-star"></i>';
            
            // Check if this payload is in favorites
            const payloadId = card.dataset.payloadId;
            if (payloadId && favorites.includes(payloadId)) {
                favoriteBtn.classList.add('active');
                favoriteBtn.innerHTML = '<i class="fas fa-star"></i>';
            }
            
            // Add click handler
            favoriteBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                
                const isFavorite = this.classList.contains('active');
                const payloadId = card.dataset.payloadId;
                
                if (isFavorite) {
                    // Remove from favorites
                    this.classList.remove('active');
                    this.innerHTML = '<i class="far fa-star"></i>';
                    
                    const index = favorites.indexOf(payloadId);
                    if (index > -1) {
                        favorites.splice(index, 1);
                    }
                } else {
                    // Add to favorites
                    this.classList.add('active');
                    this.innerHTML = '<i class="fas fa-star"></i>';
                    
                    if (payloadId && !favorites.includes(payloadId)) {
                        favorites.push(payloadId);
                    }
                }
                
                // Save updated favorites
                localStorage.setItem('favorites', JSON.stringify(favorites));
            });
            
            // Add to card
            card.appendChild(favoriteBtn);
        }
    });
}

// Initialize tab scrolling system for better navigation
function initializeTabScrolling() {
    // Handle tab navigation for sections with many tabs
    const tabContainers = document.querySelectorAll('.nav-tabs');
    
    tabContainers.forEach(container => {
        // Add scroll buttons if needed
        if (container.scrollWidth > container.clientWidth) {
            // Add scroll control buttons
            const controls = document.createElement('div');
            controls.className = 'tab-scroll-controls';
            
            const leftBtn = document.createElement('button');
            leftBtn.className = 'tab-scroll-btn tab-scroll-left';
            leftBtn.innerHTML = '<i class="fas fa-chevron-left"></i>';
            
            const rightBtn = document.createElement('button');
            rightBtn.className = 'tab-scroll-btn tab-scroll-right';
            rightBtn.innerHTML = '<i class="fas fa-chevron-right"></i>';
            
            controls.appendChild(leftBtn);
            controls.appendChild(rightBtn);
            
            container.parentNode.insertBefore(controls, container);
            
            // Add event listeners
            leftBtn.addEventListener('click', () => {
                container.scrollBy({
                    left: -100,
                    behavior: 'smooth'
                });
            });
            
            rightBtn.addEventListener('click', () => {
                container.scrollBy({
                    left: 100,
                    behavior: 'smooth'
                });
            });
        }
    });
}

// Initialize tab persistence (remember selected tabs between page loads)
function initializeTabPersistence() {
    // Get all tabs
    const tabs = document.querySelectorAll('[role="tab"]');
    
    // Check for saved tab preferences
    const savedTabs = JSON.parse(localStorage.getItem('activeTabs')) || {};
    
    // Set up active tabs based on saved preferences
    for (const [tabGroupId, activeTabId] of Object.entries(savedTabs)) {
        const tabElement = document.getElementById(activeTabId);
        if (tabElement) {
            const triggerEl = new bootstrap.Tab(tabElement);
            triggerEl.show();
        }
    }
    
    // Add event listeners to save tab selections
    tabs.forEach(tab => {
        tab.addEventListener('shown.bs.tab', function(e) {
            // Get the id of this tab's group
            const tabGroupId = this.closest('.nav-tabs').id;
            
            // Get saved tabs
            const savedTabs = JSON.parse(localStorage.getItem('activeTabs')) || {};
            
            // Update with current tab
            savedTabs[tabGroupId] = this.id;
            
            // Save back to localStorage
            localStorage.setItem('activeTabs', JSON.stringify(savedTabs));
        });
    });
}

// Show a notification with message and type (success, warning, error)
function showNotification(message, type = 'info') {
    // Create notification if it doesn't exist yet
    let notification = document.getElementById('notification');
    if (!notification) {
        notification = document.createElement('div');
        notification.id = 'notification';
        notification.className = 'notification';
        document.body.appendChild(notification);
    }
    
    // Set notification content and type
    notification.textContent = message;
    notification.className = `notification notification-${type}`;
    
    // Add appropriate icon based on notification type
    let icon = 'info-circle';
    if (type === 'success') icon = 'check-circle';
    if (type === 'warning') icon = 'exclamation-triangle';
    if (type === 'error') icon = 'exclamation-circle';
    
    notification.innerHTML = `<i class="fas fa-${icon}"></i> ${message}`;
    
    // Show the notification with animation
    notification.style.display = 'block';
    notification.classList.add('show');
    
    // Hide after a delay
    setTimeout(() => {
        notification.classList.remove('show');
        
        // After fade out animation completes
        setTimeout(() => {
            notification.style.display = 'none';
        }, 500);
    }, 3000);
}

// Setup encoder functionality for XSS payloads
function setupEncoderFunctionality() {
    const encodeButton = document.getElementById('encode-payload-btn');
    const clearButton = document.getElementById('clear-encoded-btn');
    const payloadInput = document.getElementById('payload-to-encode');
    const resultsTable = document.getElementById('encoded-results-table');
    const encodingSelect = document.getElementById('encoding-method-select');
    
    if (encodeButton && clearButton && payloadInput && resultsTable) {
        // Add encoding method options if the select exists
        if (encodingSelect) {
            const encodingMethods = [
                { value: 'all', name: 'All Methods' },
                { value: 'html', name: 'HTML Entity' },
                { value: 'url', name: 'URL Encode' },
                { value: 'base64', name: 'Base64 Encode' },
                { value: 'hex', name: 'Hex Encode' },
                { value: 'decimal', name: 'Decimal HTML Entity' },
                { value: 'js_escape', name: 'JS Escape' },
                { value: 'unicode', name: 'Unicode Escape' },
                { value: 'js_unicode', name: 'JS Unicode Escape' }
            ];
            
            encodingMethods.forEach(method => {
                const option = document.createElement('option');
                option.value = method.value;
                option.textContent = method.name;
                encodingSelect.appendChild(option);
            });
        }
        
        encodeButton.addEventListener('click', function() {
            const userput = payloadInput.value.trim();
            if (!userput) {
                showNotification('Please enter a payload to encode', 'warning');
                return;
            }
            
            // Clear previous results
            resultsTable.innerHTML = '';
            
            let encodings = [];
            
            // Check if we're using the new XSS encoding methods
            if (xssData && xssData.encodeMethods) {
                const selectedMethod = encodingSelect ? encodingSelect.value : 'all';
                
                if (selectedMethod === 'all') {
                    const allEncodings = xssData.encodeMethods.getAllEncodings(userput);
                    
                    // Convert the result object to an array of objects
                    encodings = Object.entries(allEncodings).map(([method, result]) => {
                        const methodName = method.charAt(0).toUpperCase() + method.slice(1).replace('_', ' ');
                        return { name: methodName, result: result };
                    });
                    
                    // Add double URL encode as it's not in the encodeMethods
                    encodings.push({ 
                        name: 'Double URL Encode', 
                        result: encodeURIComponent(encodeURIComponent(userput)) 
                    });
                } else {                    // Just encode with the selected method
                    const result = xssData.encodeMethods.encodePayload(userput, selectedMethod);
                    const methodName = selectedMethod.charAt(0).toUpperCase() + selectedMethod.slice(1).replace('_', ' ');
                    encodings = [{ name: methodName, result: result }];
                }
            } else {
                // Fallback to original method if the new methods aren't available
                encodings = [
                    { name: 'HTML Entity', result: htmlEntityEncode(userput) },
                    { name: 'URL Encode', result: encodeURIComponent(userput) },
                    { name: 'Double URL Encode', result: encodeURIComponent(encodeURIComponent(userput)) },
                    { name: 'Base64 Encode', result: btoa(unescape(encodeURIComponent(userput))) },
                    { name: 'Hex Encode', result: stringToHex(userput) },
                    { name: 'Unicode Escape', result: unicodeEscape(userput) },
                    { name: 'Decimal HTML Entity', result: decimalHTMLEntityEncode(userput) },
                    { name: 'Hexadecimal HTML Entity', result: hexHTMLEntityEncode(userput) },
                    { name: 'JS Escape', result: jsEscape(userput) },
                    { name: 'JS String', result: jsString(userput) }
                ];
            }
            
            // Add each encoding to the table
            encodings.forEach(encoding => {
                const row = document.createElement('tr');
                
                // Encoding Type cell
                const typeCell = document.createElement('td');
                typeCell.textContent = encoding.name;
                row.appendChild(typeCell);
                
                // Result cell
                const resultCell = document.createElement('td');
                const resultText = document.createElement('code');
                resultText.className = 'payload-text';
                resultText.textContent = encoding.result;
                resultCell.appendChild(resultText);
                row.appendChild(resultCell);
                
                // Action cell (copy button)
                const actionCell = document.createElement('td');
                const copyButton = document.createElement('button');                copyButton.className = 'btn btn-sm btn-success btn-copy';
                copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
                copyButton.addEventListener('click', function() {
                    copyToClipboard(encoding.result);
                    showCopyNotification(`${encoding.name} encoded payload copied to clipboard!`);
                    
                    // Visual feedback
                    this.innerHTML = '<i class="fas fa-check"></i> Copied';
                    setTimeout(() => {
                        this.innerHTML = '<i class="fas fa-copy"></i> Copy';
                        this.classList.remove('copied');
                    }, 2000);
                });
                actionCell.appendChild(copyButton);
                row.appendChild(actionCell);
                
                resultsTable.appendChild(row);
            });
            
            // Show success notification
            showNotification('Payload encoded successfully', 'success');
        });
        
        clearButton.addEventListener('click', function() {
            payloadInput.value = '';
            resultsTable.innerHTML = '';
        });
    }
}

// HTML Entity Encoding
function htmlEntityEncode(str) {
    return str.replace(/[\u00A0-\u9999<>\&]/g, function(i) {
        return '&#'+i.charCodeAt(0)+';';
    }).replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Decimal HTML Entity Encoding
function decimalHTMLEntityEncode(str) {
    let result = '';
    for (let i = 0; i < str.length; i++) {
        result += '&#' + str.charCodeAt(i) + ';';
    }
    return result;
}

// Hexadecimal HTML Entity Encoding
function hexHTMLEntityEncode(str) {
    let result = '';
    for (let i = 0; i < str.length; i++) {
        result += '&#x' + str.charCodeAt(i).toString(16) + ';';
    }
    return result;
}

// String to Hex
function stringToHex(str) {
    let hex = '';
    for (let i = 0; i < str.length; i++) {
        const charCode = str.charCodeAt(i);
        hex += '\\x' + ('0' + charCode.toString(16)).slice(-2);
    }
    return hex;
}

// Unicode Escape
function unicodeEscape(str) {
    let result = '';
    for (let i = 0; i < str.length; i++) {
        const hex = ('0000' + str.charCodeAt(i).toString(16)).slice(-4);
        result += '\\u' + hex;
    }
    return result;
}

// JavaScript String Escape
function jsEscape(str) {
    return str
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t')
        .replace(/\b/g, '\\b')
        .replace(/\f/g, '\\f');
}

// JavaScript String Format
function jsString(str) {
    return "'" + jsEscape(str) + "'";
}
