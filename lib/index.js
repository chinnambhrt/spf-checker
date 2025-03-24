const dns = require('dns');
const { promisify } = require('util');
const net = require('net');

// Promisify DNS lookup functions
const resolveTxt = promisify(dns.resolveTxt);
const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveMx = promisify(dns.resolveMx);
const resolvePtr = promisify(dns.resolvePtr);

/**
 * SPF Validator implementing RFC 6652
 * @class SPFValidator
 */
class SPFValidator {
    constructor() {
        this.mechanisms = {
            'all': this.mechanismAll,
            'ip4': this.mechanismIp4,
            'ip6': this.mechanismIp6,
            'a': this.mechanismA,
            'mx': this.mechanismMx,
            'include': this.mechanismInclude,
            'exists': this.mechanismExists,
            'ptr': this.mechanismPtr
        };

        this.modifiers = {
            'redirect': this.modifierRedirect,
            'exp': this.modifierExp
        };

        // Max DNS lookups allowed per RFC
        this.MAX_DNS_LOOKUPS = 10;
        this.dnsLookups = 0;
        this.redirectsFollowed = 0;
        this.MAX_REDIRECTS = 5; // Prevent infinite redirect loops
    }

    /**
     * Validate if an IP is authorized to send email for a domain
     * @param {string} ip - The IP address sending the email
     * @param {string} domain - The domain to check against
     * @param {string} sender - The email address of the sender
     * @param {string} helo - The HELO/EHLO domain used in SMTP
     * @returns {Promise<Object>} - Result object with status and explanation
     */
    async validateSPF(ip, domain, sender = null, helo = null) {
        try {
            // Reset counters
            this.dnsLookups = 0;
            this.redirectsFollowed = 0;

            // Get SPF record for the domain
            const spfRecord = await this.getSPFRecord(domain);

            if (!spfRecord) {
                return { result: 'none', explanation: 'No SPF record found for the domain' };
            }

            // Parse and evaluate the SPF record
            const result = await this.evaluateSPF(ip, domain, spfRecord, sender, helo);

            return result;
        } catch (error) {
            if (error.message === 'permerror') {
                return { result: 'permerror', explanation: 'Permanent error in processing' };
            } else if (error.message === 'temperror') {
                return { result: 'temperror', explanation: 'Temporary error in processing' };
            } else if (error.message === 'dns_limit_exceeded') {
                return { result: 'permerror', explanation: 'DNS lookup limit exceeded' };
            } else if (error.message === 'redirect_limit_exceeded') {
                return { result: 'permerror', explanation: 'Too many redirect modifiers' };
            }

            return { result: 'error', explanation: error.message };
        }
    }

    /**
     * Get the SPF record for a domain
     * @param {string} domain - The domain to get the SPF record for
     * @returns {Promise<string|null>} - The SPF record or null if not found
     */
    async getSPFRecord(domain) {
        try {
            this.dnsLookups++;

            if (this.dnsLookups > this.MAX_DNS_LOOKUPS) {
                throw new Error('dns_limit_exceeded');
            }

            const records = await resolveTxt(domain);

            // Find the SPF record (should start with "v=spf1")
            for (const recordSet of records) {
                const record = recordSet.join('');
                if (record.toLowerCase().startsWith('v=spf1')) {
                    return record;
                }
            }

            return null;
        } catch (error) {
            if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
                return null;
            }

            if (error.code === 'ETIMEOUT' || error.code === 'ECONNREFUSED') {
                throw new Error('temperror');
            }

            throw error;
        }
    }

    /**
     * Parse and evaluate an SPF record
     * @param {string} ip - The IP address to check
     * @param {string} domain - The domain the SPF record belongs to
     * @param {string} spfRecord - The SPF record to evaluate
     * @param {string} sender - The email address of the sender
     * @param {string} helo - The HELO/EHLO domain used in SMTP
     * @returns {Promise<Object>} - Result object with status and explanation
     */
    async evaluateSPF(ip, domain, spfRecord, sender, helo) {
        // Remove "v=spf1" prefix and split into terms
        const terms = spfRecord.substring(6).trim().split(' ').filter(term => term.length > 0);

        let redirectDomain = null;
        let explanation = null;

        // Process each term in the SPF record
        for (const term of terms) {
            // Skip empty terms
            if (!term) continue;

            // Check if it's a modifier
            if (term.includes('=')) {
                const [modifier, value] = term.split('=');

                if (modifier === 'redirect') {
                    redirectDomain = value;
                    continue;
                }

                if (modifier === 'exp') {
                    explanation = value;
                    continue;
                }

                // Unknown modifier, ignore
                continue;
            }

            // Otherwise, it's a mechanism
            let qualifier = '+'; // Default qualifier is "+"
            let mechanism = term;

            // Extract qualifier if present
            if (['+', '-', '~', '?'].includes(term[0])) {
                qualifier = term[0];
                mechanism = term.substring(1);
            }

            // Split mechanism name and value
            const [mechanismName, ...params] = mechanism.split(':');
            const mechanismParam = params.join(':');

            // Check if the mechanism is supported
            if (!this.mechanisms[mechanismName]) {
                // Unknown mechanism, ignore
                continue;
            }

            // Evaluate the mechanism
            const match = await this.mechanisms[mechanismName].call(
                this,
                ip,
                domain,
                mechanismParam,
                sender,
                helo
            );

            if (match) {
                // Return result based on qualifier
                switch (qualifier) {
                    case '+': // Pass
                        return { result: 'pass', explanation: `Matched mechanism: ${mechanism}` };
                    case '-': // Fail
                        return { result: 'fail', explanation: await this.getExplanation(domain, explanation, sender) };
                    case '~': // SoftFail
                        return { result: 'softfail', explanation: `Soft fail on mechanism: ${mechanism}` };
                    case '?': // Neutral
                        return { result: 'neutral', explanation: `Neutral on mechanism: ${mechanism}` };
                }
            }
        }

        // If we have a redirect, follow it
        if (redirectDomain) {
            this.redirectsFollowed++;

            if (this.redirectsFollowed > this.MAX_REDIRECTS) {
                throw new Error('redirect_limit_exceeded');
            }

            try {
                const redirectRecord = await this.getSPFRecord(redirectDomain);

                if (!redirectRecord) {
                    return { result: 'permerror', explanation: `Redirect domain ${redirectDomain} has no SPF record` };
                }

                return await this.evaluateSPF(ip, redirectDomain, redirectRecord, sender, helo);
            } catch (error) {
                if (error.message === 'dns_limit_exceeded' || error.message === 'redirect_limit_exceeded') {
                    throw error;
                }
                return { result: 'permerror', explanation: `Error processing redirect to ${redirectDomain}: ${error.message}` };
            }
        }

        // If we get here, no mechanisms matched
        return { result: 'neutral', explanation: 'No matching mechanisms found' };
    }

    /**
     * Get explanation for a fail result
     * @param {string} domain - The domain
     * @param {string} explanation - The explanation domain
     * @param {string} sender - The sender email
     * @returns {Promise<string>} - The explanation string
     */
    async getExplanation(domain, explanation, sender) {
        if (!explanation || !sender) {
            return 'SPF authentication failed';
        }

        try {
            // Replace macros in the explanation domain
            const expDomain = this.expandMacros(explanation, domain, sender);

            // Look up the explanation TXT record
            this.dnsLookups++;
            if (this.dnsLookups > this.MAX_DNS_LOOKUPS) {
                throw new Error('dns_limit_exceeded');
            }

            const records = await resolveTxt(expDomain);
            if (records && records.length > 0) {
                return records[0].join('');
            }
        } catch (error) {
            // Ignore errors, just return default explanation
        }

        return 'SPF authentication failed';
    }

    /**
     * Expands macros in a string according to SPF rules
     * @param {string} str - The string containing macros
     * @param {string} domain - The domain
     * @param {string} sender - The sender email
     * @param {string} ip - The IP address
     * @returns {string} - The expanded string
     */
    expandMacros(str, domain, sender, ip = '') {
        if (!str) return str;

        let result = str;
        const [localPart = '', senderDomain = ''] = sender ? sender.split('@') : ['', ''];

        // Basic macro expansions
        result = result
            .replace(/%{s}/g, sender || '')
            .replace(/%{l}/g, localPart)
            .replace(/%{o}/g, senderDomain)
            .replace(/%{d}/g, domain)
            .replace(/%{i}/g, ip)
            .replace(/%{p}/g, 'unknown')  // Validated domain name of IP
            .replace(/%{v}/g, net.isIPv4(ip) ? 'in-addr' : 'ip6')
            .replace(/%{h}/g, domain); // HELO/EHLO domain

        // Handle more complex macros with transformers
        const macroRegex = /%{([slodiphcrtv])([0-9]*)([pr]*)}/g;
        let match;

        while ((match = macroRegex.exec(str)) !== null) {
            const [fullMatch, letter, digits, transformers] = match;

            let value = '';
            switch (letter) {
                case 's': value = sender || ''; break;
                case 'l': value = localPart; break;
                case 'o': value = senderDomain; break;
                case 'd': value = domain; break;
                case 'i': value = ip; break;
                case 'p': value = 'unknown'; break;
                case 'v': value = net.isIPv4(ip) ? 'in-addr' : 'ip6'; break;
                case 'h': value = domain; break;
                default: value = '';
            }

            // Apply transformers
            if (transformers.includes('r')) {
                value = value.split('.').reverse().join('.');
            }

            // Apply digit limitation
            if (digits && !isNaN(parseInt(digits))) {
                value = value.split('.').slice(0, parseInt(digits)).join('.');
            }

            result = result.replace(fullMatch, value);
        }

        return result;
    }

    /**
     * Reverse an IP address for PTR lookup
     * @param {string} ip - The IP address
     * @returns {string} - Reversed IP for PTR lookup
     */
    reverseIp(ip) {
        if (net.isIPv4(ip)) {
            return ip.split('.').reverse().join('.') + '.in-addr.arpa';
        } else if (net.isIPv6(ip)) {
            // Expand IPv6 address to full form
            const parts = ip.split(':');
            let expanded = '';

            for (let i = 0; i < parts.length; i++) {
                if (parts[i] === '') {
                    // Expand the ::
                    const missing = 8 - (parts.length - 1);
                    for (let j = 0; j < missing; j++) {
                        expanded += '0000';
                    }
                } else {
                    // Pad each part to 4 characters
                    expanded += parts[i].padStart(4, '0');
                }
            }

            // Reverse and add arpa suffix
            return expanded.split('').reverse().join('.') + '.ip6.arpa';
        }

        return '';
    }

    /**
     * Check if an IP address is within a CIDR range
     * @param {string} ip - The IP to check
     * @param {string} cidr - The CIDR range
     * @returns {boolean} - True if the IP is in the range
     */
    isIpInCidr(ip, cidr) {
        // Handle IPv4
        if (net.isIPv4(ip)) {
            const [range, bits = '32'] = cidr.split('/');
            const mask = ~(2 ** (32 - parseInt(bits)) - 1);

            const ipNum = ip.split('.').reduce((sum, octet) => (sum << 8) + parseInt(octet), 0);
            const rangeNum = range.split('.').reduce((sum, octet) => (sum << 8) + parseInt(octet), 0);

            return (ipNum & mask) === (rangeNum & mask);
        }

        // Handle IPv6 (simplified)
        if (net.isIPv6(ip)) {
            const [range, bits = '128'] = cidr.split('/');

            // Convert IPv6 addresses to binary strings
            const ipBin = this.ipv6ToBinary(ip);
            const rangeBin = this.ipv6ToBinary(range);

            // Compare only the specified number of bits
            return ipBin.substring(0, parseInt(bits)) === rangeBin.substring(0, parseInt(bits));
        }

        return false;
    }

    /**
     * Convert IPv6 address to binary string
     * @param {string} ip - The IPv6 address
     * @returns {string} - Binary representation
     */
    ipv6ToBinary(ip) {
        // Normalize IPv6 address
        const normalized = ip.toLowerCase();

        // Split by : and expand :: if present
        const parts = normalized.split(':');
        let expandedParts = [];

        let doubleColonIndex = parts.indexOf('');
        if (doubleColonIndex !== -1) {
            // Handle :: expansion
            const beforeDoubleColon = parts.slice(0, doubleColonIndex);
            let afterDoubleColon = [];

            // Find the next non-empty part
            for (let i = doubleColonIndex + 1; i < parts.length; i++) {
                if (parts[i] !== '') {
                    afterDoubleColon = parts.slice(i);
                    break;
                }
            }

            // Calculate how many 0000 blocks to insert
            const missingBlocks = 8 - (beforeDoubleColon.length + afterDoubleColon.length);

            // Create the expanded parts array
            expandedParts = [
                ...beforeDoubleColon,
                ...Array(missingBlocks).fill('0'),
                ...afterDoubleColon
            ];
        } else {
            expandedParts = parts;
        }

        // Convert each part to binary
        let binary = '';
        for (const part of expandedParts) {
            // Convert hex to decimal, then to binary, padding to 16 bits
            const decimal = parseInt(part || '0', 16);
            const bin = decimal.toString(2).padStart(16, '0');
            binary += bin;
        }

        return binary;
    }

    // SPF Mechanisms implementations

    /**
     * "all" mechanism - always matches
     * @returns {boolean} - Always true
     */
    async mechanismAll() {
        return true;
    }

    /**
     * "ip4" mechanism - checks if IP is in an IPv4 range
     * @param {string} ip - The IP to check
     * @param {string} domain - The domain
     * @param {string} param - The IP4 parameter (CIDR)
     * @returns {Promise<boolean>} - True if IP matches
     */
    async mechanismIp4(ip, domain, param) {
        if (!net.isIPv4(ip)) return false;

        // Add default mask if not specified
        const cidr = param.includes('/') ? param : `${param}/32`;

        return this.isIpInCidr(ip, cidr);
    }

    /**
     * "ip6" mechanism - checks if IP is in an IPv6 range
     * @param {string} ip - The IP to check
     * @param {string} domain - The domain
     * @param {string} param - The IP6 parameter (CIDR)
     * @returns {Promise<boolean>} - True if IP matches
     */
    async mechanismIp6(ip, domain, param) {
        if (!net.isIPv6(ip)) return false;

        // Add default mask if not specified
        const cidr = param.includes('/') ? param : `${param}/128`;

        return this.isIpInCidr(ip, cidr);
    }

    /**
     * "a" mechanism - checks if IP matches A records
     * @param {string} ip - The IP to check
     * @param {string} domain - The domain
     * @param {string} param - Optional domain for A lookup
     * @returns {Promise<boolean>} - True if IP matches
     */
    async mechanismA(ip, domain, param) {
        try {
            // Parse domain and CIDR
            let checkDomain = param || domain;
            let cidrMask = '';

            if (param && param.includes('/')) {
                const parts = param.split('/');
                checkDomain = parts[0] || domain;
                cidrMask = '/' + parts[1];
            }

            // Handle macros in domain
            if (checkDomain.includes('%')) {
                checkDomain = this.expandMacros(checkDomain, domain, null, ip);
            }

            this.dnsLookups++;
            if (this.dnsLookups > this.MAX_DNS_LOOKUPS) {
                throw new Error('dns_limit_exceeded');
            }

            // If IP is IPv4, check A records
            if (net.isIPv4(ip)) {
                const aRecords = await resolve4(checkDomain);

                // Direct match check
                if (aRecords.includes(ip)) {
                    return true;
                }

                // CIDR match check if specified
                if (cidrMask) {
                    for (const record of aRecords) {
                        if (this.isIpInCidr(ip, record + cidrMask)) {
                            return true;
                        }
                    }
                }
            }

            // If IP is IPv6, check AAAA records
            if (net.isIPv6(ip)) {
                const aaaaRecords = await resolve6(checkDomain);

                // Direct match check
                if (aaaaRecords.includes(ip)) {
                    return true;
                }

                // CIDR match check if specified
                if (cidrMask) {
                    for (const record of aaaaRecords) {
                        if (this.isIpInCidr(ip, record + cidrMask)) {
                            return true;
                        }
                    }
                }
            }

            return false;
        } catch (error) {
            if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
                return false;
            }

            throw error;
        }
    }

    /**
     * "mx" mechanism - checks if IP matches MX records
     * @param {string} ip - The IP to check
     * @param {string} domain - The domain
     * @param {string} param - Optional domain for MX lookup
     * @returns {Promise<boolean>} - True if IP matches
     */
    async mechanismMx(ip, domain, param) {
        try {
            // Parse domain and CIDR
            let checkDomain = param || domain;
            let cidrMask = '';

            if (param && param.includes('/')) {
                const parts = param.split('/');
                checkDomain = parts[0] || domain;
                cidrMask = '/' + parts[1];
            }

            // Handle macros in domain
            if (checkDomain.includes('%')) {
                checkDomain = this.expandMacros(checkDomain, domain, null, ip);
            }

            this.dnsLookups++;
            if (this.dnsLookups > this.MAX_DNS_LOOKUPS) {
                throw new Error('dns_limit_exceeded');
            }

            // Get MX records
            const mxRecords = await resolveMx(checkDomain);

            // Check each MX record
            for (const { exchange } of mxRecords) {
                // For IPv4
                if (net.isIPv4(ip)) {
                    try {
                        const aRecords = await resolve4(exchange);

                        // Direct match check
                        if (aRecords.includes(ip)) {
                            return true;
                        }

                        // CIDR match check if specified
                        if (cidrMask) {
                            for (const record of aRecords) {
                                if (this.isIpInCidr(ip, record + cidrMask)) {
                                    return true;
                                }
                            }
                        }
                    } catch (error) {
                        // Ignore errors for individual MX records
                        continue;
                    }
                }

                // For IPv6
                if (net.isIPv6(ip)) {
                    try {
                        const aaaaRecords = await resolve6(exchange);

                        // Direct match check
                        if (aaaaRecords.includes(ip)) {
                            return true;
                        }

                        // CIDR match check if specified
                        if (cidrMask) {
                            for (const record of aaaaRecords) {
                                if (this.isIpInCidr(ip, record + cidrMask)) {
                                    return true;
                                }
                            }
                        }
                    } catch (error) {
                        // Ignore errors for individual MX records
                        continue;
                    }
                }
            }

            return false;
        } catch (error) {
            if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
                return false;
            }

            throw error;
        }
    }

    /**
     * "include" mechanism - recursive SPF check
     * @param {string} ip - The IP to check
     * @param {string} domain - The domain
     * @param {string} param - Domain to include
     * @param {string} sender - Sender email
     * @returns {Promise<boolean>} - True if included domain passes
     */
    async mechanismInclude(ip, domain, param, sender) {
        if (!param) return false;

        try {
            // Handle macros in domain
            let includeDomain = param;
            if (param.includes('%')) {
                includeDomain = this.expandMacros(param, domain, sender, ip);
            }

            const includeRecord = await this.getSPFRecord(includeDomain);

            if (!includeRecord) {
                return false;
            }

            const result = await this.evaluateSPF(ip, includeDomain, includeRecord, sender, null);

            // Only "pass" result counts as a match for include
            return result.result === 'pass';
        } catch (error) {
            if (error.message === 'dns_limit_exceeded' || error.message === 'redirect_limit_exceeded') {
                throw error;
            }
            return false;
        }
    }

    /**
     * "exists" mechanism - checks if domain exists
     * @param {string} ip - The IP to check
     * @param {string} domain - The domain
     * @param {string} param - Domain to check existence
     * @param {string} sender - Sender email
     * @returns {Promise<boolean>} - True if domain exists
     */
    async mechanismExists(ip, domain, param, sender) {
        if (!param) return false;

        try {
            // Handle macros in domain
            let existsDomain = param;
            if (param.includes('%')) {
                existsDomain = this.expandMacros(param, domain, sender, ip);
            }

            this.dnsLookups++;
            if (this.dnsLookups > this.MAX_DNS_LOOKUPS) {
                throw new Error('dns_limit_exceeded');
            }

            const records = await resolve4(existsDomain);
            return records.length > 0;
        } catch (error) {
            if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
                return false;
            }

            throw error;
        }
    }

    /**
     * "ptr" mechanism - checks reverse DNS records
     * @param {string} ip - The IP to check
     * @param {string} domain - The domain
     * @param {string} param - Domain to validate against (or empty for current domain)
     * @returns {Promise<boolean>} - True if PTR record matches
     */
    async mechanismPtr(ip, domain, param) {
        // Note: ptr mechanism is officially discouraged due to performance/reliability concerns
        try {
            // Determine the domain to check against
            const checkDomain = param || domain;

            // Get the reverse DNS lookup name
            const reverseDns = this.reverseIp(ip);
            if (!reverseDns) return false;

            this.dnsLookups++;
            if (this.dnsLookups > this.MAX_DNS_LOOKUPS) {
                throw new Error('dns_limit_exceeded');
            }

            // Lookup the hostnames for this IP
            const hostnames = await resolvePtr(reverseDns);

            // For each hostname, check if it matches or is a subdomain of the check domain
            for (const hostname of hostnames) {
                if (hostname === checkDomain || hostname.endsWith('.' + checkDomain)) {
                    return true;
                }
            }

            return false;
        } catch (error) {
            if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
                return false;
            }

            throw error;
        }
    }

    // SPF Modifiers implementations

    /**
     * "redirect" modifier - redirect to another domain's SPF
     * @param {string} ip - The IP to check
     * @param {string} domain - The domain
     * @param {string} param - Redirect domain
     * @param {string} sender - Sender email
     * @returns {Promise<Object>} - Result object
     */
    async modifierRedirect(ip, domain, param, sender) {
        if (!param) {
            return { result: 'permerror', explanation: 'Redirect modifier without domain' };
        }

        try {
            this.redirectsFollowed++;

            if (this.redirectsFollowed > this.MAX_REDIRECTS) {
                throw new Error('redirect_limit_exceeded');
            }

            // Handle macros in domain
            let redirectDomain = param;
            if (param.includes('%')) {
                redirectDomain = this.expandMacros(param, domain, sender, ip);
            }

            const redirectRecord = await this.getSPFRecord(redirectDomain);

            if (!redirectRecord) {
                return { result: 'permerror', explanation: `Redirect domain ${redirectDomain} has no SPF record` };
            }

            // Check for redirect loops
            if (redirectDomain === domain) {
                return { result: 'permerror', explanation: 'Redirect loop detected' };
            }

            return await this.evaluateSPF(ip, redirectDomain, redirectRecord, sender, null);
        } catch (error) {
            if (error.message === 'dns_limit_exceeded' || error.message === 'redirect_limit_exceeded') {
                throw error;
            }
            return { result: 'permerror', explanation: `Error processing redirect to ${param}: ${error.message}` };
        }
    }

    /**
     * "exp" modifier - get explanation for failures
     * @param {string} domain - The domain
     * @param {string} param - Explanation domain
     * @param {string} sender - Sender email
     * @param {string} ip - Sender IP
     * @returns {Promise<string>} - Explanation text
     */
    async modifierExp(domain, param, sender, ip) {
        try {
            // Handle macros in domain
            let expDomain = param;
            if (param.includes('%')) {
                expDomain = this.expandMacros(param, domain, sender, ip);
            }

            this.dnsLookups++;
            if (this.dnsLookups > this.MAX_DNS_LOOKUPS) {
                throw new Error('dns_limit_exceeded');
            }

            const records = await resolveTxt(expDomain);

            if (records && records.length > 0) {
                const explanation = records[0].join('');

                // Handle macros in the explanation text
                if (explanation.includes('%')) {
                    return this.expandMacros(explanation, domain, sender, ip);
                }

                return explanation;
            }

            return 'SPF authentication failed';
        } catch (error) {
            return 'SPF authentication failed';
        }
    }
}

/**
 * Validate an IP against a domain's SPF record
 * @param {string} ip - The IP address to validate
 * @param {string} domain - The domain to check
 * @param {string} sender - Optional sender email address
 * @param {string} helo - Optional HELO/EHLO domain
 * @returns {Promise<Object>} - Result object
 */
async function validateSPF(ip, domain, sender = null, helo = null) {
    const validator = new SPFValidator();
    return await validator.validateSPF(ip, domain, sender, helo);
}

module.exports = {
    validateSPF,
    SPFValidator
};

// validateSPF('35.190.247.16', 'gmail.com').then(console.log).catch(console.error);