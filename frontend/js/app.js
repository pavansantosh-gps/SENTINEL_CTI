/* =========================================================
   SENTINEL CTI
   Frontend application logic
========================================================= */


// =========================================================
// API CONFIGURATION
// =========================================================

const API_BASE = "http://127.0.0.1:5000";


// =========================================================
// GENERAL HELPERS
// =========================================================

async function fetchJSON(url, options = {}) {

    const response = await fetch(
        `${API_BASE}${url}`,
        options
    );

    if (!response.ok) {

        let errorMessage = `Request failed: ${response.status}`;

        try {

            const errorData = await response.json();

            if (errorData.message) {
                errorMessage = errorData.message;
            }

        } catch (error) {
            // Keep default error message
        }

        throw new Error(errorMessage);
    }

    return response.json();
}


function setText(id, value) {

    const element = document.getElementById(id);

    if (element) {
        element.textContent = value;
    }
}


function formatNumber(value) {

    return Number(value || 0).toLocaleString("en-IN");
}


function formatBytes(bytes) {

    const value = Number(bytes || 0);

    if (value < 1024) {
        return `${value} B`;
    }

    if (value < 1024 * 1024) {
        return `${(value / 1024).toFixed(2)} KB`;
    }

    if (value < 1024 * 1024 * 1024) {
        return `${(value / (1024 * 1024)).toFixed(2)} MB`;
    }

    return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}


function escapeHTML(value) {

    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function showLoading(containerId, message = "Loading...") {

    const container = document.getElementById(containerId);

    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="loading">
            ${escapeHTML(message)}
        </div>
    `;
}


function showError(containerId, message) {

    const container = document.getElementById(containerId);

    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="status-message error">
            ${escapeHTML(message)}
        </div>
    `;
}


function showEmpty(containerId, title, message) {

    const container = document.getElementById(containerId);

    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="empty-state">

            <div class="empty-icon">
                ◌
            </div>

            <h3>
                ${escapeHTML(title)}
            </h3>

            <p>
                ${escapeHTML(message)}
            </p>

        </div>
    `;
}


// =========================================================
// NAVIGATION
// =========================================================

const sectionInformation = {

    dashboard: {
        title: "Security Operations Dashboard",
        description:
            "A simple view of threats, indicators, reports and database activity."
    },

    iocs: {
        title: "Threat Indicators",
        description:
            "Search suspicious IP addresses, domains, URLs and file hashes."
    },

    threats: {
        title: "Threat Intelligence",
        description:
            "View the threat entities stored in the SENTINEL database."
    },

    vulnerabilities: {
        title: "Vulnerability Intelligence",
        description:
            "Multi-Source Vulnerability Intelligence Consolidation."
    },

    reports: {
        title: "Security Reports",
        description:
            "Search annual cybersecurity reports collected from 2020 to 2026."
    },

    classification: {
        title: "Identify a Threat",
        description:
            "Describe suspicious activity and receive an explainable threat classification."
    },

    schema: {
        title: "How Our Data Is Designed",
        description:
            "Understand which information is stored together and which is stored separately."
    },

    monitoring: {
        title: "Database Performance",
        description:
            "See active test data and how MongoDB is using memory."
    },

    "live-monitor": {
        title: "Live Report Monitoring",
        description:
            "Monitor report-source checks and current MongoDB activity."
    }

};


function activateSection(sectionId) {

    document
        .querySelectorAll(".content-section")
        .forEach(section => {

            section.classList.remove("active");

        });


    document
        .querySelectorAll(".nav-item")
        .forEach(item => {

            item.classList.remove("active");

        });


    const section = document.getElementById(sectionId);

    if (section) {
        section.classList.add("active");
    }


    const navigationButton =
        document.querySelector(
            `.nav-item[data-section="${sectionId}"]`
        );

    if (navigationButton) {
        navigationButton.classList.add("active");
    }


    const information =
        sectionInformation[sectionId];

    if (information) {

        setText(
            "page-title",
            information.title
        );

        setText(
            "page-description",
            information.description
        );

    }


    // Load section-specific information

    if (sectionId === "dashboard") {
        loadDashboard();
    }

    if (sectionId === "iocs") {
        loadIOCs();
    }

    if (sectionId === "threats") {
        loadThreats();
    }

    if (sectionId === "reports") {
        loadReports();
    }

    if (sectionId === "schema") {
        loadSchema();
    }

    if (sectionId === "monitoring") {
        loadMonitoring();
    }

    if (sectionId === "live-monitor") {
        loadLiveMonitor();
    }

}


document
    .querySelectorAll(".nav-item")
    .forEach(button => {

        button.addEventListener(
            "click",
            () => {

                const section =
                    button.dataset.section;

                activateSection(section);

            }
        );

    });


// =========================================================
// VULNERABILITY INTELLIGENCE
// =========================================================

async function searchVulnerability() {

    const input =
        document.getElementById(
            "vulnerability-cve-input"
        );

    const status =
        document.getElementById(
            "vulnerability-status"
        );

    const result =
        document.getElementById(
            "vulnerability-result"
        );

    const searchButton =
        document.getElementById(
            "vulnerability-search-btn"
        );


    if (!input) {
        return;
    }


    const cveId =
        input.value
            .trim()
            .toUpperCase();


    if (!cveId) {

        if (status) {
            status.textContent =
                "Enter a CVE ID to search.";
        }

        if (result) {
            result.hidden = true;
        }

        return;
    }


    if (status) {
        status.textContent =
            `Searching vulnerability data for ${cveId}...`;
    }

    if (result) {
        result.hidden = true;
    }

    if (searchButton) {
        searchButton.disabled = true;
    }


    try {

        const response =
            await fetchJSON(
                `/api/vulnerabilities/${encodeURIComponent(cveId)}`
            );


        if (!response?.success || !response.data) {
            throw new Error(
                response?.message ||
                "No vulnerability data was returned for that CVE."
            );
        }


        const data =
            response.data;

        const cvss =
            data.cvss || {};

        const provenance =
            Array.isArray(data.source_provenance)
                ? data.source_provenance
                : [];

        const vendors =
            Array.isArray(data.vendors)
                ? data.vendors.join(", ")
                : data.vendors;

        const products =
            Array.isArray(data.products)
                ? data.products.join(", ")
                : data.products;

        const sourceCount =
            Number.isFinite(Number(data.source_count))
                ? Number(data.source_count)
                : provenance.length;


        setText(
            "vulnerability-cve",
            data.cve_id || cveId
        );

        setText(
            "vulnerability-title",
            data.title || "—"
        );

        setText(
            "vulnerability-description",
            data.description || "—"
        );

        setText(
            "vulnerability-description-text",
            data.description || "—"
        );

        setText(
            "vulnerability-severity",
            data.severity || "—"
        );

        setText(
            "vulnerability-cvss",
            cvss.score ?? "—"
        );

        setText(
            "vulnerability-cvss-version",
            cvss.version || "—"
        );

        setText(
            "vulnerability-cvss-vector",
            cvss.vector || "—"
        );

        setText(
            "vulnerability-epss",
            data.epss ?? "—"
        );

        setText(
            "vulnerability-vendor",
            vendors || "—"
        );

        setText(
            "vulnerability-product",
            products || "—"
        );

        setText(
            "vulnerability-product-detail",
            products || "—"
        );

        setText(
            "vulnerability-source-count",
            `Sources Integrated: ${sourceCount}`
        );

        setText(
            "vulnerability-sources",
            sourceCount
        );


        const sourceList =
            document.getElementById(
                "vulnerability-source-list"
            );


        if (sourceList) {

            const sourceNames = {
                osv: "OSV.dev",
                euvd: "EUVD / ENISA",
                circl: "CIRCL Vulnerability-Lookup"
            };

            sourceList.innerHTML =
                provenance.length
                    ? provenance.map(source => {

                        const sourceKey =
                            String(source.source || "")
                                .trim()
                                .toLowerCase();

                        const sourceName =
                            sourceNames[sourceKey] ||
                            source.source ||
                            "Unknown source";

                        const recordId =
                            source.record_id || "—";

                        let sourceUrl = null;

                        try {

                            const parsedUrl =
                                new URL(source.url);

                            if (
                                parsedUrl.protocol === "http:" ||
                                parsedUrl.protocol === "https:"
                            ) {
                                sourceUrl =
                                    parsedUrl.href;
                            }

                        } catch (error) {
                            sourceUrl = null;
                        }

                        const urlContent =
                            sourceUrl
                                ? `<a href="${escapeHTML(sourceUrl)}" target="_blank" rel="noopener noreferrer">${escapeHTML(sourceUrl)}</a>`
                                : escapeHTML(source.url || "—");

                        return `
                            <div class="source-card">
                                <h5>${escapeHTML(sourceName)}</h5>
                                <p>Record ID: ${escapeHTML(recordId)}</p>
                                <p>Source URL: ${urlContent}</p>
                            </div>
                        `;

                    }).join("")
                    : `
                        <div class="source-card">
                            No source provenance is available for this CVE.
                        </div>
                    `;

        }


        if (result) {
            result.hidden = false;
        }

        if (status) {
            status.textContent =
                `Vulnerability data loaded for ${data.cve_id || cveId}.`;
        }


    } catch (error) {

        console.error(
            "Vulnerability search error:",
            error
        );

        if (status) {
            status.textContent =
                error.message ||
                "Unable to load vulnerability data.";
        }


    } finally {

        if (searchButton) {
            searchButton.disabled = false;
        }

    }

}


document
    .getElementById("vulnerability-search-btn")
    ?.addEventListener(
        "click",
        searchVulnerability
    );


document
    .getElementById("vulnerability-cve-input")
    ?.addEventListener(
        "keydown",
        event => {

            if (event.key === "Enter") {
                searchVulnerability();
            }

        }
    );


// =========================================================
// DASHBOARD
// =========================================================

async function loadDashboard() {

    try {

        const overview =
            await fetchJSON(
                "/api/analytics/overview"
            );


        const data = overview.data;


        setText(
            "stat-iocs",
            formatNumber(data.iocs)
        );


        setText(
            "stat-threats",
            formatNumber(data.threats)
        );


        setText(
            "stat-cti-reports",
            formatNumber(data.cti_reports)
        );


        setText(
            "stat-security-reports",
            formatNumber(data.security_reports)
        );


        setText(
            "stat-working-set",
            formatNumber(data.working_set_documents)
        );


    } catch (error) {

        console.error(
            "Dashboard overview error:",
            error
        );

    }


    await loadIOCChart();
    await loadSeverityChart();
    await loadYearChart();

}


async function loadIOCChart() {

    showLoading(
        "ioc-chart",
        "Loading indicator data..."
    );


    try {

        const response =
            await fetchJSON(
                "/api/analytics/iocs-by-type"
            );


        const data =
            response.data || [];


        renderHorizontalChart(
            "ioc-chart",
            data,
            "type"
        );


    } catch (error) {

        showError(
            "ioc-chart",
            error.message
        );

    }

}


async function loadSeverityChart() {

    showLoading(
        "severity-chart",
        "Loading threat data..."
    );


    try {

        const response =
            await fetchJSON(
                "/api/analytics/threats-by-severity"
            );


        const data =
            response.data || [];


        renderHorizontalChart(
            "severity-chart",
            data,
            "severity"
        );


    } catch (error) {

        showError(
            "severity-chart",
            error.message
        );

    }

}


async function loadYearChart() {

    showLoading(
        "year-chart",
        "Loading report history..."
    );


    try {

        const response =
            await fetchJSON(
                "/api/analytics/reports-by-year"
            );


        const data =
            response.data || [];


        renderYearChart(
            "year-chart",
            data
        );


    } catch (error) {

        showError(
            "year-chart",
            error.message
        );

    }

}


// =========================================================
// CHART RENDERING
// =========================================================

function renderHorizontalChart(
    containerId,
    data,
    labelKey
) {

    const container =
        document.getElementById(containerId);


    if (!container) {
        return;
    }


    if (!data.length) {

        showEmpty(
            containerId,
            "No data available",
            "There are currently no records to display."
        );

        return;
    }


    const maximum =
        Math.max(
            ...data.map(
                item => Number(item.count || 0)
            )
        );


    container.innerHTML = `

        <div class="monitor-bars">

            ${data.map(item => {

                const count =
                    Number(item.count || 0);

                const percentage =
                    maximum
                        ? (count / maximum) * 100
                        : 0;

                return `

                    <div class="monitor-bar-row">

                        <div class="monitor-bar-label">
                            ${escapeHTML(
                                item[labelKey]
                            )}
                        </div>

                        <div class="monitor-bar-track">

                            <div
                                class="monitor-bar-fill"
                                style="width: ${percentage}%">
                            </div>

                        </div>

                        <div class="monitor-bar-value">
                            ${formatNumber(count)}
                        </div>

                    </div>

                `;

            }).join("")}

        </div>

    `;

}


function renderYearChart(
    containerId,
    data
) {

    const container =
        document.getElementById(containerId);


    if (!container) {
        return;
    }


    if (!data.length) {

        showEmpty(
            containerId,
            "No report history",
            "No security report data is available."
        );

        return;
    }


    const maximum =
        Math.max(
            ...data.map(
                item => Number(item.count || 0)
            )
        );


    container.innerHTML = `

        <div class="monitor-bars">

            ${data.map(item => {

                const count =
                    Number(item.count || 0);

                const percentage =
                    maximum
                        ? (count / maximum) * 100
                        : 0;

                return `

                    <div class="monitor-bar-row">

                        <div class="monitor-bar-label">
                            ${escapeHTML(item.year)}
                        </div>

                        <div class="monitor-bar-track">

                            <div
                                class="monitor-bar-fill"
                                style="width: ${percentage}%">
                            </div>

                        </div>

                        <div class="monitor-bar-value">
                            ${formatNumber(count)}
                        </div>

                    </div>

                `;

            }).join("")}

        </div>

    `;

}


// =========================================================
// IOC INTELLIGENCE
// =========================================================

async function loadIOCs() {

    const search =
        document
            .getElementById("ioc-search")
            ?.value
            .trim() || "";


    const type =
        document
            .getElementById("ioc-type-filter")
            ?.value || "";


    const parameters =
        new URLSearchParams();


    if (search) {
        parameters.set("search", search);
    }


    if (type) {
        parameters.set("type", type);
    }


    showLoading(
        "ioc-table-body",
        "Loading indicators..."
    );


    try {

        const response =
            await fetchJSON(
                `/api/iocs?${parameters.toString()}`
            );


        const data =
            response.data || [];


        setText(
            "ioc-count",
            formatNumber(response.total)
        );


        renderIOCTable(data);


    } catch (error) {

        const body =
            document.getElementById(
                "ioc-table-body"
            );

        if (body) {

            body.innerHTML = `
                <tr>
                    <td colspan="6">
                        <div class="status-message error">
                            ${escapeHTML(error.message)}
                        </div>
                    </td>
                </tr>
            `;

        }

    }

}


function renderIOCTable(data) {

    const body =
        document.getElementById(
            "ioc-table-body"
        );


    if (!body) {
        return;
    }


    if (!data.length) {

        body.innerHTML = `
            <tr>
                <td colspan="6">

                    <div class="empty-state">
                        <div class="empty-icon">◎</div>
                        <h3>No indicators found</h3>
                        <p>
                            Try changing the search text or indicator type.
                        </p>
                    </div>

                </td>
            </tr>
        `;

        return;
    }


    body.innerHTML =
        data.map(ioc => `

            <tr>

                <td>
                    ${escapeHTML(ioc.ioc_id)}
                </td>

                <td class="table-indicator">
                    ${escapeHTML(ioc.indicator)}
                </td>

                <td>
                    ${escapeHTML(ioc.type)}
                </td>

                <td>
                    ${escapeHTML(ioc.category)}
                </td>

                <td>
                    ${escapeHTML(ioc.confidence)}%
                </td>

                <td>
                    ${escapeHTML(ioc.first_seen)}
                </td>

            </tr>

        `).join("");

}


document
    .getElementById("ioc-search-button")
    ?.addEventListener(
        "click",
        loadIOCs
    );


document
    .getElementById("ioc-search")
    ?.addEventListener(
        "keydown",
        event => {

            if (event.key === "Enter") {
                loadIOCs();
            }

        }
    );


// =========================================================
// THREAT INTELLIGENCE
// =========================================================

async function loadThreats() {

    const search =
        document
            .getElementById("threat-search")
            ?.value
            .trim() || "";


    const severity =
        document
            .getElementById(
                "threat-severity-filter"
            )
            ?.value || "";


    const parameters =
        new URLSearchParams();


    if (search) {
        parameters.set(
            "search",
            search
        );
    }


    if (severity) {
        parameters.set(
            "severity",
            severity
        );
    }


    try {

        const response =
            await fetchJSON(
                `/api/threats?${parameters.toString()}`
            );


        const data =
            response.data || [];


        setText(
            "threat-count",
            formatNumber(response.total)
        );


        renderThreats(data);


    } catch (error) {

        showError(
            "threat-grid",
            error.message
        );

    }

}


function renderThreats(data) {

    const container =
        document.getElementById(
            "threat-grid"
        );


    if (!container) {
        return;
    }


    if (!data.length) {

        showEmpty(
            "threat-grid",
            "No threats found",
            "Try changing your search or severity filter."
        );

        return;
    }


    container.innerHTML =
        data.map(threat => {

            const severity =
                String(
                    threat.severity || ""
                ).toLowerCase();


            const severityClass =
                `severity-${severity}`;


            const aliases =
                Array.isArray(
                    threat.aliases
                )
                    ? threat.aliases.join(", ")
                    : "No aliases available";


            return `

                <div class="threat-card">

                    <div class="threat-card-top">

                        <span class="threat-id">
                            ${escapeHTML(
                                threat.threat_id
                            )}
                        </span>

                        <span
                            class="severity-badge ${severityClass}">

                            ${escapeHTML(
                                threat.severity
                            )}

                        </span>

                    </div>


                    <h3>
                        ${escapeHTML(
                            threat.name
                        )}
                    </h3>


                    <p class="threat-type">
                        ${escapeHTML(
                            threat.type
                        )}
                    </p>


                    <p class="threat-aliases">
                        Also known as:
                        ${escapeHTML(aliases)}
                    </p>

                </div>

            `;

        }).join("");

}


document
    .getElementById(
        "threat-search-button"
    )
    ?.addEventListener(
        "click",
        loadThreats
    );


document
    .getElementById("threat-search")
    ?.addEventListener(
        "keydown",
        event => {

            if (event.key === "Enter") {
                loadThreats();
            }

        }
    );


// =========================================================
// SECURITY REPORTS
// =========================================================

async function loadReports() {

    const search =
        document
            .getElementById("report-search")
            ?.value
            .trim() || "";


    const year =
        document
            .getElementById(
                "report-year-filter"
            )
            ?.value || "";


    const parameters =
        new URLSearchParams();


    if (search) {
        parameters.set(
            "search",
            search
        );
    }


    if (year) {
        parameters.set(
            "year",
            year
        );
    }


    parameters.set(
        "limit",
        "50"
    );


    showLoading(
        "reports-list",
        "Loading security reports..."
    );


    try {

        const response =
            await fetchJSON(
                `/api/reports?${parameters.toString()}`
            );


        const data =
            response.data || [];


        setText(
            "report-count",
            formatNumber(response.total)
        );


        renderReports(data);


    } catch (error) {

        showError(
            "reports-list",
            error.message
        );

    }

}


function renderReports(data) {

    const container =
        document.getElementById(
            "reports-list"
        );


    if (!container) {
        return;
    }


    if (!data.length) {

        showEmpty(
            "reports-list",
            "No reports found",
            "Try changing the search text or year."
        );

        return;
    }


    container.innerHTML =
        data.map(report => {

            const title =
                report.title ||
                "Untitled security report";


            const organization =
                report.organization ||
                "Unknown organization";


            const description =
                report.description ||
                "No description available.";


            const repositoryURL =
                report.repository_report_url || "";


            const sourceURL =
                report.source_url || "";


            return `

                <article class="report-card">

                    <div class="report-card-top">

                        <div>

                            <h3>
                                ${escapeHTML(title)}
                            </h3>

                            <p class="report-organization">
                                ${escapeHTML(
                                    organization
                                )}
                            </p>

                        </div>


                        <span class="report-year">
                            ${escapeHTML(
                                report.year
                            )}
                        </span>

                    </div>


                    <p class="report-description">
                        ${escapeHTML(
                            description
                        )}
                    </p>


                    <div class="report-meta">

                        ${
                            report.report_type
                                ? `
                                    <span>
                                        ${escapeHTML(
                                            report.report_type
                                        )}
                                    </span>
                                  `
                                : ""
                        }


                        ${
                            report.category
                                ? `
                                    <span>
                                        ${escapeHTML(
                                            report.category
                                        )}
                                    </span>
                                  `
                                : ""
                        }


                        ${
                            repositoryURL
                                ? `
                                    <a
                                        class="report-link"
                                        href="${escapeHTML(
                                            repositoryURL
                                        )}"
                                        target="_blank"
                                        rel="noopener noreferrer">
                                        View report
                                    </a>
                                  `
                                : ""
                        }


                        ${
                            sourceURL
                                ? `
                                    <a
                                        class="report-link"
                                        href="${escapeHTML(
                                            sourceURL
                                        )}"
                                        target="_blank"
                                        rel="noopener noreferrer">
                                        Source
                                    </a>
                                  `
                                : ""
                        }

                    </div>

                </article>

            `;

        }).join("");

}


document
    .getElementById(
        "report-search-button"
    )
    ?.addEventListener(
        "click",
        loadReports
    );


document
    .getElementById(
        "report-search"
    )
    ?.addEventListener(
        "keydown",
        event => {

            if (event.key === "Enter") {
                loadReports();
            }

        }
    );


// =========================================================
// THREAT CLASSIFICATION
// =========================================================

async function classifyThreat() {

    const input =
        document
            .getElementById(
                "classification-input"
            );


    const iocTypeElement =
        document
            .getElementById(
                "classification-ioc-type"
            );


    const resultContainer =
        document
            .getElementById(
                "classification-result"
            );


    const text =
        input?.value.trim() || "";


    const iocType =
        iocTypeElement?.value || null;


    if (!text) {

        resultContainer.innerHTML = `

            <div class="status-message error">

                Please enter a threat description first.

            </div>

        `;

        return;
    }


    resultContainer.innerHTML = `

        <div class="loading">
            Analyzing threat activity...
        </div>

    `;


    try {

        const response =
            await fetchJSON(
                "/api/classify",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        text: text,
                        ioc_type: iocType
                    })
                }
            );


        const result =
            response.result;


        renderClassificationResult(
            result
        );


    } catch (error) {

        resultContainer.innerHTML = `

            <div class="status-message error">

                ${escapeHTML(
                    error.message
                )}

            </div>

        `;

    }

}


function renderClassificationResult(result) {

    const container =
        document.getElementById(
            "classification-result"
        );


    if (!container) {
        return;
    }


    const severity =
        String(
            result.severity || ""
        ).toLowerCase();


    const severityClass =
        `severity-${severity}`;


    const keywords =
        Array.isArray(
            result.matched_keywords
        )
            ? result.matched_keywords
            : [];


    container.innerHTML = `

        <div class="result-header">

            <div>

                <p class="eyebrow">
                    DETECTED THREAT TYPE
                </p>

                <div class="result-category">
                    ${escapeHTML(
                        result.category
                    )}
                </div>

                <div class="result-score">
                    Match score:
                    ${escapeHTML(
                        result.score
                    )}
                </div>

            </div>


            <span
                class="result-severity severity-badge ${severityClass}">

                ${escapeHTML(
                    result.severity
                )}

            </span>

        </div>


        <div class="result-box">

            <div class="result-box-title">
                Why was it classified this way?
            </div>

            <p class="result-explanation">
                ${escapeHTML(
                    result.explanation
                )}
            </p>

        </div>


        <div class="result-box">

            <div class="result-box-title">
                Matching clues
            </div>

            <div class="keyword-list">

                ${
                    keywords.length
                        ? keywords.map(
                            keyword => `
                                <span class="keyword">
                                    ${escapeHTML(
                                        keyword
                                    )}
                                </span>
                            `
                        ).join("")
                        : `
                            <span class="keyword">
                                No direct clues found
                            </span>
                          `
                }

            </div>

        </div>

    `;

}


document
    .getElementById(
        "classify-button"
    )
    ?.addEventListener(
        "click",
        classifyThreat
    );


// =========================================================
// SCHEMA ANALYZER
// =========================================================

async function loadSchema() {

    try {

        const response =
            await fetchJSON(
                "/api/schema"
            );


        const data =
            response.data;


        const bson =
            data.bson_statistics;


        setText(
            "schema-status",
            data.status
        );


        setText(
            "schema-documents",
            formatNumber(
                bson.document_count
            )
        );


        setText(
            "schema-average",
            formatBytes(
                bson.average_size
            )
        );


        setText(
            "schema-maximum",
            formatBytes(
                bson.maximum_size
            )
        );


        setText(
            "schema-limit-percent",
            `${bson.largest_percent_of_limit}%`
        );


        renderSchemaDecisions(
            data.schema_decisions
        );


    } catch (error) {

        showError(
            "schema-decisions",
            error.message
        );

    }

}


function renderSchemaDecisions(
    decisions
) {

    const container =
        document.getElementById(
            "schema-decisions"
        );


    if (!container) {
        return;
    }


    if (!decisions?.length) {

        showEmpty(
            "schema-decisions",
            "No schema information",
            "Schema analysis data is currently unavailable."
        );

        return;
    }


    container.innerHTML =
        decisions.map(decision => {

            const strategy =
                String(
                    decision.strategy || ""
                ).toUpperCase();


            const strategyClass =
                strategy === "EMBED"
                    ? "strategy-embed"
                    : "strategy-reference";


            const easyLabel =
                strategy === "EMBED"
                    ? "STORED TOGETHER"
                    : "STORED SEPARATELY";


            return `

                <div class="schema-item">

                    <div class="schema-relationship">
                        ${escapeHTML(
                            decision.relationship
                        )}
                    </div>


                    <div>

                        <span
                            class="
                                schema-strategy
                                ${strategyClass}
                            ">

                            ${easyLabel}

                        </span>

                    </div>


                    <div class="schema-reason">

                        ${escapeHTML(
                            decision.reason
                        )}

                    </div>

                </div>

            `;

        }).join("");

}


// =========================================================
// DATABASE PERFORMANCE / WORKING SET
// =========================================================

async function loadMonitoring() {

    try {

        const response =
            await fetchJSON(
                "/api/monitoring"
            );


        renderMonitoring(
            response.data
        );


    } catch (error) {

        console.error(
            "Monitoring error:",
            error
        );

    }

}


function renderMonitoring(
    data
) {

    const workingSet =
        data.working_set || {};


    const cache =
        data.wiredTiger_cache || {};


    setText(
        "monitor-documents",
        formatNumber(
            workingSet.documents
        )
    );


    setText(
        "monitor-object-size",
        formatBytes(
            workingSet.average_object_size_bytes
        )
    );


    setText(
        "monitor-logical-size",
        formatBytes(
            workingSet.logical_size_bytes
        )
    );


    setText(
        "monitor-storage-size",
        formatBytes(
            workingSet.storage_size_bytes
        )
    );


    setText(
        "monitor-cache-fill",
        `${cache.cache_fill_percent}%`
    );


    setText(
        "monitor-current-cache",
        formatBytes(
            cache.current_cache_bytes
        )
    );


    setText(
        "monitor-pages-requested",
        formatNumber(
            cache.pages_requested
        )
    );


    setText(
        "monitor-pages-evicted",
        formatNumber(
            cache.pages_evicted
        )
    );


    const updated =
        new Date();


    setText(
        "monitor-last-updated",
        `Updated ${updated.toLocaleTimeString()}`
    );


    renderMonitoringBars(
        cache
    );

}


function renderMonitoringBars(
    cache
) {

    const container =
        document.getElementById(
            "monitor-bars"
        );


    if (!container) {
        return;
    }


    const values = [

        {
            label: "Cache fill",
            value:
                Number(
                    cache.cache_fill_percent || 0
                ),
            max: 100,
            display:
                `${cache.cache_fill_percent || 0}%`
        },

        {
            label: "Pages requested",
            value:
                Number(
                    cache.pages_requested || 0
                ),
            max:
                Math.max(
                    Number(
                        cache.pages_requested || 1
                    ),
                    1
                ),
            display:
                formatNumber(
                    cache.pages_requested
                )
        },

        {
            label: "Pages read into memory",
            value:
                Number(
                    cache.pages_read_into_cache || 0
                ),
            max:
                Math.max(
                    Number(
                        cache.pages_requested || 1
                    ),
                    1
                ),
            display:
                formatNumber(
                    cache.pages_read_into_cache
                )
        },

        {
            label: "Pages written",
            value:
                Number(
                    cache.pages_written || 0
                ),
            max:
                Math.max(
                    Number(
                        cache.pages_requested || 1
                    ),
                    1
                ),
            display:
                formatNumber(
                    cache.pages_written
                )
        },

        {
            label: "Pages removed from memory",
            value:
                Number(
                    cache.pages_evicted || 0
                ),
            max:
                Math.max(
                    Number(
                        cache.pages_requested || 1
                    ),
                    1
                ),
            display:
                formatNumber(
                    cache.pages_evicted
                )
        }

    ];


    container.innerHTML = `

        <div class="monitor-bars">

            ${
                values.map(item => {

                    const width =
                        item.max
                            ? Math.min(
                                100,
                                (
                                    item.value /
                                    item.max
                                ) * 100
                            )
                            : 0;


                    return `

                        <div
                            class="monitor-bar-row">

                            <div
                                class="monitor-bar-label">

                                ${escapeHTML(
                                    item.label
                                )}

                            </div>


                            <div
                                class="monitor-bar-track">

                                <div
                                    class="monitor-bar-fill"
                                    style="width: ${width}%">
                                </div>

                            </div>


                            <div
                                class="monitor-bar-value">

                                ${escapeHTML(
                                    item.display
                                )}

                            </div>

                        </div>

                    `;

                }).join("")
            }

        </div>

    `;

}


// =========================================================
// LIVE MONITOR
// =========================================================

async function loadLiveMonitor() {

    const container =
        document.getElementById(
            "live-monitor-status"
        );


    if (!container) {
        return;
    }


    try {

        // Get normal MongoDB monitoring data
        const monitoringResponse =
            await fetchJSON(
                "/api/monitoring"
            );


        // Get live report monitoring data
        const liveResponse =
            await fetchJSON(
                "/api/live-reports"
            );


        const monitoringData =
            monitoringResponse.data || {};


        const liveData =
            liveResponse.data || {};


        const workingSet =
            monitoringData.working_set || {};


        const cache =
            monitoringData.wiredTiger_cache || {};


        const latest =
            liveData.latest || {};


        const randomReads =
            latest.random_reads || {};


        const cacheAfter =
            latest.cache_after || {};


        const sourceChanged =
            latest.source_status ||
            "No source status available";


        const reportStatus =
            latest.report_status ||
            "No report status available";


        const sourceReportCount =
            latest.source_report_count || 0;


        const databaseReportCount =
            latest.database_report_count || 0;


        const newReportCount =
            latest.new_report_count || 0;


        const requestedReads =
            randomReads.requested_reads || 0;


        const documentsRead =
            randomReads.documents_read || 0;


        const elapsedSeconds =
            randomReads.elapsed_seconds || 0;


        const readsPerSecond =
            randomReads.reads_per_second || 0;


        const pagesRequested =
            cacheAfter.pages_requested ||
            cache.pages_requested ||
            0;


        const pagesRead =
            cacheAfter.pages_read_into_cache ||
            cache.pages_read_into_cache ||
            0;


        const pagesWritten =
            cacheAfter.pages_written ||
            cache.pages_written ||
            0;


        const pagesEvicted =
            cacheAfter.pages_evicted ||
            cache.pages_evicted ||
            0;


        const cacheFill =
            latest.cache_fill_percent ??
            cache.cache_fill_percent ??
            0;


        const residency =
            latest.derived_read_residency_estimate_percent ??
            0;


        const timestamp =
            latest.timestamp
                ? new Date(
                    latest.timestamp
                ).toLocaleString()
                : "Not available";


        container.innerHTML = `

            <div class="monitor-activity">


                <div class="activity-item">

                    <div class="activity-item-label">
                        Report Monitoring
                    </div>

                    <div class="activity-item-value">
                        ${escapeHTML(
                            sourceChanged
                        )}
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Source Reports
                    </div>

                    <div class="activity-item-value">
                        ${formatNumber(
                            sourceReportCount
                        )}
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Database Reports
                    </div>

                    <div class="activity-item-value">
                        ${formatNumber(
                            databaseReportCount
                        )}
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        New Reports
                    </div>

                    <div class="activity-item-value">
                        ${formatNumber(
                            newReportCount
                        )}
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Report Status
                    </div>

                    <div class="activity-item-value">
                        ${escapeHTML(
                            reportStatus
                        )}
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Active Test Records
                    </div>

                    <div class="activity-item-value">
                        ${formatNumber(
                            workingSet.documents || 0
                        )}
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Random Reads
                    </div>

                    <div class="activity-item-value">
                        ${formatNumber(
                            documentsRead
                        )} / ${formatNumber(
                            requestedReads
                        )}
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Read Throughput
                    </div>

                    <div class="activity-item-value">
                        ${formatNumber(
                            readsPerSecond
                        )} docs/s
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Read Time
                    </div>

                    <div class="activity-item-value">
                        ${elapsedSeconds} s
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        MongoDB Memory Used
                    </div>

                    <div class="activity-item-value">
                        ${cacheFill}%
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Pages Requested
                    </div>

                    <div class="activity-item-value">
                        ${formatNumber(
                            pagesRequested
                        )}
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Pages Read Into Memory
                    </div>

                    <div class="activity-item-value">
                        ${formatNumber(
                            pagesRead
                        )}
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Pages Written
                    </div>

                    <div class="activity-item-value">
                        ${formatNumber(
                            pagesWritten
                        )}
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Pages Removed From Memory
                    </div>

                    <div class="activity-item-value">
                        ${formatNumber(
                            pagesEvicted
                        )}
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Derived Read Residency
                    </div>

                    <div class="activity-item-value">
                        ${residency}%
                    </div>

                </div>


                <div class="activity-item">

                    <div class="activity-item-label">
                        Last Monitor Record
                    </div>

                    <div class="activity-item-value">
                        ${escapeHTML(
                            timestamp
                        )}
                    </div>

                </div>


            </div>

        `;


    } catch (error) {

        console.error(
            "Live monitoring error:",
            error
        );


        container.innerHTML = `

            <div class="status-message error">

                Live monitoring data could not be loaded:
                ${escapeHTML(
                    error.message
                )}

            </div>

        `;

    }

}