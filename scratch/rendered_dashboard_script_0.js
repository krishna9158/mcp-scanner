
        // 1. Navigation Switcher
        window.switchNav = function(sectionId) {
            if (!sectionId) return;
            const views = document.querySelectorAll('.section-view');
            views.forEach(function(el) {
                if (el.id === sectionId) {
                    el.classList.add('active');
                    el.style.setProperty('display', 'block', 'important');
                } else {
                    el.classList.remove('active');
                    el.style.setProperty('display', 'none', 'important');
                }
            });

            // Update nav item active states
            const navItems = document.querySelectorAll('.nav-item');
            navItems.forEach(function(btn) {
                const oc = btn.getAttribute('onclick') || '';
                if (oc.indexOf("'" + sectionId + "'") !== -1) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });

            if (typeof window.scrollTo === 'function') {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        };

        // 1b. Project Switcher
        window.switchProject = function(projectId) {
            if (!projectId) return;
            window.location.href = '/scan?project_id=' + encodeURIComponent(projectId);
        };

        // 2. Scan Results Sub-Tab Switcher
        window.openSubTab = function(evtOrEl, tabId) {
            if (!tabId) return;

            const target = document.getElementById(tabId);
            if (!target) return;

            const panes = document.querySelectorAll('.tab-pane');
            panes.forEach(function(pane) {
                pane.classList.remove('active');
                pane.style.setProperty('display', 'none', 'important');
            });

            target.classList.add('active');
            target.style.setProperty('display', 'block', 'important');

            const btns = document.querySelectorAll('.tab-btn');
            btns.forEach(function(btn) {
                const btnTab = btn.getAttribute('data-tab');
                if (btnTab === tabId) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });
        };

        // 3. Scan Mode Toggle
        window.setDashboardScanMode = function(mode) {
            const lblWeb = document.getElementById('lbl-web');
            const lblRepo = document.getElementById('lbl-repo');
            const lblMcp = document.getElementById('lbl-mcp');
            const input = document.getElementById('dash-target-input');
            const submit = document.getElementById('dash-submit-btn');

            if (lblWeb) lblWeb.classList.remove('active');
            if (lblRepo) lblRepo.classList.remove('active');
            if (lblMcp) lblMcp.classList.remove('active');

            if (mode === 'website') {
                if (lblWeb) lblWeb.classList.add('active');
                if (input) input.placeholder = 'https://example.com';
                if (submit) submit.innerText = 'Audit Website';
            } else if (mode === 'mcp') {
                if (lblMcp) lblMcp.classList.add('active');
                if (input) input.placeholder = 'https://github.com/modelcontextprotocol/servers';
                if (submit) submit.innerText = 'Scan MCP Server';
            } else {
                if (lblRepo) lblRepo.classList.add('active');
                if (input) input.placeholder = 'https://github.com/owner/repository';
                if (submit) submit.innerText = 'Scan Repository';
            }
        };

        // 4. Stored Scan Findings Data
        var scanFindings = [];
        var currentFinding = null;
        var isEli5Mode = false;

        window.showFindingModalByIndex = function(idx) {
            if (scanFindings && scanFindings[idx]) {
                showFindingModal(scanFindings[idx]);
            }
        };

        window.showFindingModal = function(finding) {
            if (!finding) return;
            currentFinding = finding;
            isEli5Mode = false;
            const eliBtn = document.getElementById("eli5ToggleBtn");
            if (eliBtn) eliBtn.innerText = "👶 Explain Like I'm New to Security (ELI5)";

            document.getElementById("modalTitle").innerText = finding.title || "Untitled Finding";
            const sev = (finding.severity || "MEDIUM").toUpperCase();
            document.getElementById("modalSeverityBadge").className = "badge badge-" + sev;
            document.getElementById("modalSeverityBadge").innerText = sev;

            const conf = (finding.confidence || "LIKELY").toUpperCase();
            const confBadge = document.getElementById("modalConfidenceBadge");
            if (confBadge) {
                confBadge.className = "badge badge-conf-" + conf;
                confBadge.innerText = conf + " CONFIDENCE";
            }

            document.getElementById("modalCategoryBadge").innerText = (finding.category || "web").toUpperCase();
            
            const engines = finding.scanners && finding.scanners.length ? finding.scanners.join(", ") : (finding.scanner || "trustaudit");
            document.getElementById("modalEngineBadge").innerText = engines;
            
            const location = finding.file || finding.url || finding.target || "";
            document.getElementById("modalTargetLocation").innerText = location ? "Primary Location: " + location + (finding.line ? ":" + finding.line : "") : "";
            
            // Multi-Location Deduplication list
            const locSec = document.getElementById("modalLocationsSection");
            const locList = document.getElementById("modalLocationsList");
            if (finding.locations && finding.locations.length > 1) {
                locSec.style.display = "block";
                locList.innerHTML = finding.locations.map(function(l) {
                    return '<li><code>' + l.file + (l.line ? ':' + l.line : '') + '</code>' + (l.evidence ? ' — <small style="color: #64748b;">' + l.evidence.substring(0, 50) + '...</small>' : '') + '</li>';
                }).join('');
            } else {
                locSec.style.display = "none";
            }

            document.getElementById("modalDesc").innerText = finding.description || "No description provided.";
            
            const impactSec = document.getElementById("modalImpactSection");
            if (finding.business_impact || finding.impact) {
                impactSec.style.display = "block";
                document.getElementById("modalImpact").innerText = finding.business_impact || finding.impact;
            } else {
                impactSec.style.display = "none";
            }
            
            document.getElementById("modalEvidence").innerText = finding.evidence || "No raw detection evidence captured.";
            document.getElementById("modalRemediation").innerText = finding.remediation || "Review and remediate according to standard security practices.";
            document.getElementById("findingModal").classList.add("active");
        };

        window.toggleEli5Mode = function() {
            if (!currentFinding) return;
            isEli5Mode = !isEli5Mode;
            const btn = document.getElementById("eli5ToggleBtn");
            const descEl = document.getElementById("modalDesc");

            if (isEli5Mode) {
                if (btn) btn.innerText = "Switch to Technical View";
                if (descEl) descEl.innerHTML = '<span style="color: var(--text-dim);">Translating into founder plain-English...</span>';

                fetch('/api/findings/eli5', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(currentFinding)
                }).then(r => r.json()).then(d => {
                    if (descEl) descEl.innerHTML = (d.eli5_explanation || '').split('\n').join('<br>');
                }).catch(e => {
                    if (descEl) descEl.innerText = currentFinding.description || "No description available.";
                });
            } else {
                if (btn) btn.innerText = "👶 Explain Like I'm New to Security (ELI5)";
                if (descEl) descEl.innerText = currentFinding.description || "No description provided.";
            }
        };

        function safeCopyText(text, successMsg) {
            if (!text) return;
            if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(() => {
                    if (successMsg) alert(successMsg);
                }).catch(() => {
                    if (window.prompt) window.prompt("Copy to clipboard:", text);
                });
            } else {
                if (window.prompt) window.prompt("Copy to clipboard:", text);
            }
        }

        window.copyAiFixPrompt = function() {
            if (!currentFinding) return;
            fetch('/api/findings/ai-prompt', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(currentFinding)
            }).then(r => r.json()).then(d => {
                const promptText = d.ai_fix_prompt || ('Ask Cursor / Claude: Fix security vulnerability in ' + (currentFinding.file || 'the codebase') + ' for ' + (currentFinding.title || ''));
                safeCopyText(promptText, "✓ Ready-to-use AI Fix Prompt copied to clipboard!\n\n" + promptText);
            }).catch(e => {
                const fallback = 'Ask Cursor / Claude: Fix security vulnerability in ' + (currentFinding.file || 'the codebase') + ' for ' + (currentFinding.title || '');
                safeCopyText(fallback, "✓ AI Fix Prompt copied!");
            });
        };

        window.closeModal = function() {
            document.getElementById("findingModal").classList.remove("active");
        };

        window.copyModalEvidence = function() {
            if (!currentFinding || !currentFinding.evidence) {
                alert("No evidence text to copy.");
                return;
            }
            safeCopyText(currentFinding.evidence, "✓ Evidence copied to clipboard!");
        };

        window.copyPrompt = function(findingId) {
            const promptText = "Fix security issue: " + findingId + " in the codebase. Please apply safe defensive programming and input validation.";
            safeCopyText(promptText, "✓ AI Coding Prompt copied! Paste into Cursor, Claude Code, or Copilot.");
        };

        window.triggerFixVerification = function(findingId, target) {
            if (!confirm("Trigger live verification scan to confirm this vulnerability was resolved?")) return;
            const targetInput = document.getElementById('dash-target-input');
            const actualTarget = target || (targetInput ? targetInput.value : '');

            fetch('/api/finding/' + encodeURIComponent(findingId) + '/verify', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({finding_id: findingId, target: actualTarget})
            }).then(r => r.json()).then(data => {
                if (data.is_fixed) {
                    alert('🎉 VERIFIED CLEAN! The vulnerability is no longer detected. Posture Score: ' + data.score + '/100');
                    window.location.reload();
                } else {
                    alert('⚠️ Still Vulnerable: ' + (data.message || 'The vulnerability was still detected during rescan.'));
                }
            }).catch(e => alert('Verification error: ' + e));
        };

        window.markFindingStatus = function(status) {
            if (!currentFinding) return;
            const findingId = currentFinding.id || currentFinding.finding_id || "FIND-GEN";
            fetch('/api/finding/' + encodeURIComponent(findingId) + '/status', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({status: status})
            }).then(r => r.json()).then(data => {
                alert('Finding status updated to: ' + status);
                closeModal();
            }).catch(e => alert('Error updating finding: ' + e));
        };

        window.copyBadgeSnippet = function() {
            const el = document.getElementById("readmeBadgeSnippet");
            if (!el) return;
            safeCopyText(el.value, "✓ README Markdown badge snippet copied to clipboard!\n\n" + el.value);
        };

        window.previewWeeklyDigest = function() {
            const previewBox = document.getElementById("weeklyDigestPreview");
            if (!previewBox) return;
            previewBox.style.display = "block";
            previewBox.innerHTML = "<em>Generating weekly digest preview...</em>";

            fetch('/api/digest/weekly')
                .then(r => r.json())
                .then(d => {
                    previewBox.innerHTML = 
                        '<div style="font-weight: 700; color: #fff; font-size: 15px; margin-bottom: 6px;">' + (d.headline || 'Weekly Security Digest') + '</div>' +
                        '<div style="color: #94a3b8; font-size: 12px; margin-bottom: 10px;">Date: ' + d.date + ' &bull; Average Posture Score: <b style="color: #22c55e;">' + d.average_score + '/100</b></div>' +
                        '<div style="background: #0b1120; padding: 10px; border-radius: 6px; margin-bottom: 10px;">' + d.status_narrative + '</div>' +
                        '<div style="display: flex; gap: 14px; font-size: 12px; color: #64748b;">' +
                        '<span>Scans: <b>' + d.scans_executed_this_week + '</b></span>' +
                        '<span>Active Projects: <b>' + d.total_projects + '</b></span>' +
                        '<span>Open Risks: <b>' + d.open_findings + '</b></span>' +
                        '</div>';
                }).catch(e => {
                    previewBox.innerText = "Error loading digest preview: " + e;
                });
        };

        window.quickAudit = function(targetUrl, scanType) {
            const input = document.getElementById('dash-target-input');
            if (input) input.value = targetUrl;
            setDashboardScanMode(scanType || 'website');
            switchNav('dash-scans');
            const form = document.getElementById('dash-scan-form');
            if (form) form.submit();
        };

        // 5. Findings Search & Filter
        window.filterFindingsTable = function() {
            const searchVal = (document.getElementById('finding-search').value || '').toLowerCase();
            const sevVal = document.getElementById('filter-severity').value;
            const rows = document.querySelectorAll('#findings-table tbody tr');

            rows.forEach(function(row) {
                const rowSev = row.getAttribute('data-severity') || '';
                const rowTitle = row.getAttribute('data-title') || '';
                const matchesSev = (sevVal === 'ALL' || rowSev === sevVal);
                const matchesSearch = (!searchVal || rowTitle.indexOf(searchVal) !== -1);
                row.style.display = (matchesSev && matchesSearch) ? '' : 'none';
            });
        };

        // 6. AI Copilot Query
        window.sendAdvisorPrompt = function(q) {
            const input = document.getElementById('advisor-query-input');
            if (input) input.value = q;
            submitAdvisorQuery();
        };

        window.submitAdvisorQuery = function() {
            const input = document.getElementById('advisor-query-input');
            const btn = document.getElementById('advisor-send-btn');
            const box = document.getElementById('advisor-response-box');
            const text = document.getElementById('advisor-response-text');
            const query = input ? input.value.trim() : '';
            if (!query) return;

            if (btn) btn.innerText = 'Analyzing...';
            if (box) box.style.display = 'block';
            if (text) text.innerText = 'Grounding query against deterministic scan findings...';

            fetch('/api/advisor/query', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({query: query})
            }).then(r => r.json()).then(data => {
                if (btn) btn.innerText = 'Ask Copilot';
                if (text) text.innerText = data.answer || 'No response returned.';
            }).catch(e => {
                if (btn) btn.innerText = 'Ask Copilot';
                if (text) text.innerText = 'Copilot query error: ' + e;
            });
        };

        // 7. Integrations & Schedule
        window.saveIntegrations = function() {
            const slackUrl = document.getElementById('slack-webhook-input').value;
            fetch('/api/integrations', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({slack_webhook_url: slackUrl})
            }).then(r => r.json()).then(data => {
                alert('✓ Integration settings saved successfully!');
            }).catch(e => alert('Error saving settings: ' + e));
        };

        window.testIntegrationAlert = function() {
            const slackUrl = document.getElementById('slack-webhook-input').value;
            fetch('/api/integrations/test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target_url: slackUrl})
            }).then(r => r.json()).then(data => {
                alert('✓ Test alert dispatched! Check your notification channel.');
            }).catch(e => alert('Error dispatching test alert: ' + e));
        };

        window.saveMonitoringSchedule = function() {
            const freq = document.getElementById('monitoring-cadence-select').value;
            alert('✓ Continuous monitoring schedule updated to: ' + freq);
        };

        window.triggerInstantSweep = function() {
            if (!confirm("Run immediate continuous security sweep across all monitored assets?")) return;
            fetch('/api/monitoring/trigger-all', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            }).then(r => r.json()).then(data => {
                alert('✓ Sweep triggered for ' + data.triggered_count + ' asset(s)!');
                switchNav('dash-main');
            }).catch(e => alert('Error triggering sweep: ' + e));
        };

        window.promptAddTeamMember = function() {
            const name = prompt("Enter team member name:");
            if (!name) return;
            const email = prompt("Enter team member email:");
            if (!email) return;
            fetch('/api/team/members', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name: name, email: email, role: 'member'})
            }).then(r => r.json()).then(data => {
                alert('✓ Team member ' + name + ' invited!');
                window.location.reload();
            }).catch(e => alert('Error inviting member: ' + e));
        };

        // 8. Live Progress Simulation
        let dashProgressIv = null;
        window.cancelActiveScan = function(prefix) {
            if (dashProgressIv) clearInterval(dashProgressIv);
            const overlay = document.getElementById(prefix + '-progress');
            if (overlay) overlay.style.display = 'none';
            const btn = document.getElementById(prefix + '-submit-btn');
            if (btn) {
                btn.disabled = false;
                btn.innerText = 'Run Security Scan';
            }
        };

        window.showProgress = function(prefix) {
            const overlay = document.getElementById(prefix + '-progress');
            const btn = document.getElementById(prefix + '-submit-btn');
            if (overlay) overlay.style.display = 'block';
            if (btn) {
                btn.disabled = true;
                btn.innerText = 'Scanning...';
            }
            const bar = document.getElementById(prefix + '-bar');
            const stageText = document.getElementById(prefix + '-stage');

            const stages = [
                {pct: 15, text: 'Normalizing target URL & resolving DNS (IPv4/IPv6)...'},
                {pct: 35, text: 'Probing HTTP/HTTPS connectivity & security headers...'},
                {pct: 55, text: 'Inspecting TLS certificate validity & SSL protocol...'},
                {pct: 70, text: 'Auditing cookie flags (Secure, HttpOnly) & CORS...'},
                {pct: 85, text: 'Testing public file exposure & API endpoints...'},
                {pct: 95, text: 'Calculating security posture score & generating report...'}
            ];

            let i = 0;
            const t0 = Date.now();
            if (dashProgressIv) clearInterval(dashProgressIv);
            dashProgressIv = setInterval(() => {
                const elapsed = Math.floor((Date.now() - t0) / 1000);
                if (btn) btn.innerText = 'Scanning (' + elapsed + 's)...';
                if (i < stages.length) {
                    if (bar) bar.style.width = stages[i].pct + '%';
                    if (stageText) stageText.innerText = stages[i].text;
                    i++;
                }
            }, 1200);
        };

        // 9. Vulnerability Intelligence Drawer & Actions
        let currentIntelVuln = null;

        window.showIntelModal = function(vuln) {
            if (!vuln) return;
            currentIntelVuln = vuln;

            const modal = document.getElementById('intelModal');
            const title = document.getElementById('intelModalTitle');
            const ids = document.getElementById('intelModalIds');
            const sevBadge = document.getElementById('intelModalSevBadge');
            const kevBadge = document.getElementById('intelModalKevBadge');
            const sourceBadge = document.getElementById('intelModalSourceBadge');
            const desc = document.getElementById('intelModalDesc');
            const kevSection = document.getElementById('intelModalKevSection');
            const kevDesc = document.getElementById('intelModalKevDesc');
            const ranges = document.getElementById('intelModalRanges');
            const fixed = document.getElementById('intelModalFixed');
            const why = document.getElementById('intelModalWhy');
            const whySection = document.getElementById('intelModalWhySection');
            const remediation = document.getElementById('intelModalRemediation');

            if (title) title.innerText = vuln.title || 'Vulnerability Advisory';
            if (ids) ids.innerText = 'ID: ' + (vuln.cve_id || vuln.source_id || vuln.id) + ' | Ecosystem: ' + (vuln.ecosystem || 'N/A') + ' | CVSS: ' + (vuln.cvss_score || 'N/A');
            
            if (sevBadge) {
                sevBadge.innerText = vuln.severity || 'MEDIUM';
                sevBadge.className = 'badge badge-' + (vuln.severity || 'MEDIUM');
            }

            if (kevBadge) {
                kevBadge.style.display = (vuln.is_known_exploited || vuln.kev_status) ? 'inline-block' : 'none';
            }

            if (sourceBadge) {
                sourceBadge.innerText = vuln.source || 'OSV / NVD';
            }

            if (desc) desc.innerText = vuln.description || vuln.summary || 'No detailed description available.';

            if (kevSection) {
                if (vuln.is_known_exploited || vuln.kev_status) {
                    kevSection.style.display = 'block';
                    const kd = vuln.kev_details || vuln.kev_status || {};
                    if (kevDesc) kevDesc.innerText = (kd.required_action ? 'Required Action: ' + kd.required_action + ' (Due: ' + (kd.due_date || 'ASAP') + '). ' : '') + (kd.short_description || 'Active in-the-wild exploitation verified by CISA.');
                } else {
                    kevSection.style.display = 'none';
                }
            }

            if (ranges) ranges.innerText = (vuln.affected_version_ranges && vuln.affected_version_ranges.length) ? vuln.affected_version_ranges.join(', ') : 'All prior unpatched versions';
            if (fixed) fixed.innerText = (vuln.fixed_versions && vuln.fixed_versions.length) ? vuln.fixed_versions.join(', ') : 'Latest secure release';

            if (whySection && why) {
                if (vuln.why_prioritized) {
                    whySection.style.display = 'block';
                    why.innerText = vuln.why_prioritized;
                } else {
                    whySection.style.display = 'none';
                }
            }

            if (remediation) remediation.innerText = vuln.remediation || 'Upgrade package to the latest secure version.';

            if (modal) modal.style.display = 'flex';
        };

        window.closeIntelModal = function() {
            const modal = document.getElementById('intelModal');
            if (modal) modal.style.display = 'none';
            currentIntelVuln = null;
        };

        window.copyIntelPrompt = function() {
            if (!currentIntelVuln) return;
            const prompt = currentIntelVuln.ai_prompt || ('Fix vulnerability ' + (currentIntelVuln.cve_id || currentIntelVuln.id) + ' in ' + currentIntelVuln.package_name + ' by upgrading to ' + ((currentIntelVuln.fixed_versions || [])[0] || 'latest version') + '.');
            navigator.clipboard.writeText(prompt);
            alert('✓ Copied remediation prompt for Cursor / Claude / Copilot to clipboard!');
        };

        window.recheckFromModal = function() {
            if (!currentIntelVuln) return;
            recheckFinding(currentIntelVuln.id, currentIntelVuln.package_name, currentIntelVuln.installed_version);
        };

        window.recheckFinding = function(findingId, pkgName, currentVer) {
            const newVer = prompt('Enter the newly upgraded version of package "' + pkgName + '" (currently: ' + currentVer + '):', currentVer);
            if (!newVer) return;

            fetch('/api/intel/recheck/' + encodeURIComponent(findingId), {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    package_name: pkgName,
                    new_version: newVer,
                    ecosystem: 'npm',
                    project_id: 'proj-demo-1'
                })
            }).then(r => r.json()).then(data => {
                if (data.verified_fixed_count > 0) {
                    alert('✓ Verified! Finding has been confirmed resolved and moved to VERIFIED_FIXED.');
                } else {
                    alert('⚠️ Recheck complete: Installed version ' + newVer + ' is still within the vulnerable range (' + data.remaining_open_count + ' open finding(s)).');
                }
                window.location.reload();
            }).catch(e => alert('Recheck error: ' + e));
        };

        window.triggerIntelSync = function() {
            const btn = document.getElementById('btn-intel-sync');
            if (btn) {
                btn.disabled = true;
                btn.innerText = 'Syncing...';
            }
            fetch('/api/intel/sync', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            }).then(r => r.json()).then(data => {
                if (btn) {
                    btn.disabled = false;
                    btn.innerText = '⚡ Sync Intelligence Now';
                }
                alert('✓ Vulnerability Intelligence synchronized! ' + (data.kev_sync ? data.kev_sync.count : 0) + ' KEV records indexed.');
                window.location.reload();
            }).catch(e => {
                if (btn) {
                    btn.disabled = false;
                    btn.innerText = '⚡ Sync Intelligence Now';
                }
                alert('Sync error: ' + e);
            });
        };

        window.filterIntelTable = function() {
            const q = (document.getElementById('intel-search-input').value || '').toLowerCase();
            const sev = (document.getElementById('intel-sev-filter').value || '').toUpperCase();
            const rows = document.querySelectorAll('.intel-row');

            rows.forEach(function(row) {
                const rowSev = (row.getAttribute('data-sev') || '').toUpperCase();
                const rowText = (row.getAttribute('data-text') || '').toLowerCase();
                const rowCve = (row.getAttribute('data-cve') || '').toLowerCase();

                const matchesSev = !sev || rowSev === sev;
                const matchesQ = !q || rowText.indexOf(q) !== -1 || rowCve.indexOf(q) !== -1;

                if (matchesSev && matchesQ) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        };

        // 10. MCP Intelligence Helpers
        window.searchMcpReputation = function() {
            const pkg = document.getElementById('mcp-rep-input').value.trim();
            if (!pkg) return;
            fetch('/api/mcp/reputation-lookup?package=' + encodeURIComponent(pkg))
                .then(r => r.json())
                .then(data => {
                    const resDiv = document.getElementById('mcp-rep-result');
                    resDiv.style.display = 'block';
                    document.getElementById('mcp-rep-pkg-name').innerText = data.package || pkg;
                    const tierBadge = document.getElementById('mcp-rep-tier-badge');
                    const catEl = document.getElementById('mcp-rep-category');
                    const concernsEl = document.getElementById('mcp-rep-concerns');
                    const remEl = document.getElementById('mcp-rep-remediation');

                    if (data.flagged) {
                        tierBadge.innerText = 'CONCERNS DOCUMENTED';
                        tierBadge.className = 'badge badge-fail';
                        catEl.style.display = 'block';
                        catEl.innerText = data.owasp_mcp_category || 'OWASP MCP Security Advisory';
                        concernsEl.innerHTML = (data.concerns || []).map(c => '<p style="margin-bottom: 4px;">• ' + c + '</p>').join('');
                        remEl.style.display = 'block';
                        remEl.innerHTML = '<b>Remediation:</b> ' + (data.remediation || 'Review tool permissions.');
                    } else {
                        tierBadge.innerText = 'CLEAN';
                        tierBadge.className = 'badge badge-pass';
                        catEl.style.display = 'none';
                        concernsEl.innerHTML = '<span style="color: #4ade80;">✓ No known issues found in curated database.</span>';
                        remEl.style.display = 'none';
                    }
                })
                .catch(e => alert('Lookup error: ' + e));
        };

        window.checkMcpTyposquat = function() {
            const pkg = document.getElementById('mcp-typo-input').value.trim();
            if (!pkg) return;
            fetch('/api/mcp/typosquat', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({packages: [pkg]})
            })
                .then(r => r.json())
                .then(data => {
                    const resDiv = document.getElementById('mcp-typo-result');
                    resDiv.style.display = 'block';
                    const statusEl = document.getElementById('mcp-typo-status');
                    const detailEl = document.getElementById('mcp-typo-detail');
                    if (data.findings && data.findings.length > 0) {
                        const f = data.findings[0];
                        statusEl.innerHTML = '<span style="color: #f87171;">🚨 TYPOSQUATTING DETECTED (' + f.attack_type + ')</span>';
                        detailEl.innerText = f.reason + ' Official Package: ' + f.resembles;
                    } else {
                        statusEl.innerHTML = '<span style="color: #4ade80;">✓ CLEAN — No typosquatting or homoglyph signals detected.</span>';
                        detailEl.innerText = 'Package name does not masquerade as any known official MCP server.';
                    }
                })
                .catch(e => alert('Typosquat check error: ' + e));
        };

        window.runMcpPermissionDiff = function() {
            let bJson, cJson;
            try {
                bJson = JSON.parse(document.getElementById('mcp-diff-baseline').value);
                cJson = JSON.parse(document.getElementById('mcp-diff-current').value);
            } catch (err) {
                alert('Invalid JSON in baseline or current tool definition.');
                return;
            }
            fetch('/api/mcp/diff-permissions', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({baseline_tool: bJson, current_tool: cJson})
            })
                .then(r => r.json())
                .then(data => {
                    const resDiv = document.getElementById('mcp-diff-result');
                    resDiv.style.display = 'block';
                    document.getElementById('mcp-diff-tool-name').innerText = data.tool_name;
                    const badge = document.getElementById('mcp-diff-risk-badge');
                    badge.innerText = data.risk_rating + ' RISK';
                    badge.className = 'badge ' + (data.is_critical_escalation ? 'badge-CRITICAL' : (data.has_permission_drift ? 'badge-HIGH' : 'badge-pass'));

                    let html = '<p><b>Added Capabilities:</b> ' + (data.added_capabilities.length ? '<span style="color: #f87171;">' + data.added_capabilities.join(', ') + '</span>' : 'None') + '</p>';
                    html += '<p><b>Removed Capabilities:</b> ' + (data.removed_capabilities.length ? data.removed_capabilities.join(', ') : 'None') + '</p>';
                    html += '<p><b>Description Changed:</b> ' + (data.description_changed ? 'Yes (Prompt updated)' : 'No') + '</p>';
                    if (data.escalation_alerts && data.escalation_alerts.length) {
                        html += '<div style="margin-top: 8px; color: #fca5a5;"><b>🚨 High-Risk Escalation Alerts:</b><ul style="margin: 4px 0 0 16px;">';
                        data.escalation_alerts.forEach(function(a) {
                            html += '<li>' + a.risk + '</li>';
                        });
                        html += '</ul></div>';
                    }
                    document.getElementById('mcp-diff-details').innerHTML = html;
                })
                .catch(e => alert('Permission diff error: ' + e));
        };
    