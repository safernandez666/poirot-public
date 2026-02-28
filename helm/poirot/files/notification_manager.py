#!/usr/bin/env python3
"""
Notification Manager - Envia notificaciones por SMTP, Slack, Teams, Webhook y TheHive
tras cada scan de hawk-scanner.
"""

import json
import smtplib
import os
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.request import Request, urlopen
from urllib.error import URLError
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import yaml
from email_template_cyber import generate_cyber_email_html
from email_template_dark_cyber import generate_dark_cyber_email_html

CONFIG_PATH = os.environ.get('CONNECTION_PATH', 'connection.yml')


class NotificationManager:
    def __init__(self, config_path=None):
        self.channels = {}
        self.ollama_config = {}
        path = config_path or CONFIG_PATH
        try:
            with open(path, 'r') as f:
                config = yaml.safe_load(f) or {}
            notify_config = config.get('notify', {})
            self.channels = notify_config.get('channels', {})
            self.ollama_config = notify_config.get('ollama', {})
        except Exception as e:
            print(f"[notifications] Could not read config: {e}")

    def send_fast_channels(self, summary, stats, new_alerts):
        """Send to all enabled channels EXCEPT TheHive (fast path, called before 'done' event)."""
        results = {}
        if not self.channels:
            return results
        text = self._build_text(summary, stats, new_alerts)
        for name, cfg in self.channels.items():
            if name == 'thehive':
                continue  # handled separately in background
            if not cfg.get('enabled'):
                continue
            severity_filter = cfg.get('severity_filter', [])
            if severity_filter and not self._has_matching_severity(summary, severity_filter):
                results[name] = {'status': 'skipped', 'reason': 'no matching severity'}
                continue
            if not new_alerts:
                results[name] = {'status': 'skipped', 'reason': 'no new alerts'}
                continue
            try:
                if name == 'smtp':
                    self._send_smtp(cfg, text, summary)
                elif name == 'slack':
                    self._send_slack(cfg, text, summary)
                elif name == 'teams':
                    self._send_teams(cfg, text, summary)
                elif name == 'webhook':
                    self._send_webhook(cfg, summary, stats, new_alerts)
                results[name] = {'status': 'sent'}
                print(f"[notifications] {name}: sent OK")
            except Exception as e:
                results[name] = {'status': 'error', 'error': str(e)}
                print(f"[notifications] {name}: error - {e}")
        return results

    def send_thehive_channel(self, summary, stats, new_alerts, alert_mgr=None):
        """Send to TheHive only (called in background after 'done' event)."""
        cfg = self.channels.get('thehive', {})
        if not cfg.get('enabled'):
            return 0
        severity_filter = cfg.get('severity_filter', [])
        if severity_filter and not self._has_matching_severity(summary, severity_filter):
            print("[thehive] Skipped: no matching severity")
            return 0
        try:
            cases = self._send_thehive(cfg, new_alerts, alert_mgr)
            print(f"[notifications] thehive: {cases} cases created")
            return cases
        except Exception as e:
            print(f"[notifications] thehive: error - {e}")
            return 0

    def send_all(self, summary, stats, new_alerts, alert_mgr=None):
        """Send notifications through all enabled channels."""
        results = {}
        if not self.channels:
            print("[notifications] No channels configured")
            return results

        text = self._build_text(summary, stats, new_alerts)

        for name, cfg in self.channels.items():
            if not cfg.get('enabled'):
                continue
            severity_filter = cfg.get('severity_filter', [])
            if severity_filter and not self._has_matching_severity(summary, severity_filter):
                results[name] = {'status': 'skipped', 'reason': 'no matching severity'}
                continue
            try:
                if name == 'thehive':
                    # TheHive always runs (syncs existing cases too)
                    cases_created = self._send_thehive(cfg, new_alerts, alert_mgr)
                    results[name] = {'status': 'sent', 'cases_created': cases_created}
                    print(f"[notifications] thehive: {cases_created} cases created")
                    continue
                # For other channels, only notify if there are new alerts
                if not new_alerts:
                    results[name] = {'status': 'skipped', 'reason': 'no new alerts'}
                    continue
                if name == 'smtp':
                    self._send_smtp(cfg, text, summary)
                elif name == 'slack':
                    self._send_slack(cfg, text, summary)
                elif name == 'teams':
                    self._send_teams(cfg, text, summary)
                elif name == 'webhook':
                    self._send_webhook(cfg, summary, stats, new_alerts)
                results[name] = {'status': 'sent'}
                print(f"[notifications] {name}: sent OK")
            except Exception as e:
                results[name] = {'status': 'error', 'error': str(e)}
                print(f"[notifications] {name}: error - {e}")
        return results

    def send_test(self, channel_name, channel_config):
        """Send a test notification with fake data."""
        fake_summary = {
            'total_findings': 10,
            'by_severity': {'CRITICAL': 2, 'HIGH': 3, 'MEDIUM': 4, 'LOW': 1},
            'by_pattern': {'Private Key': 5, 'SSN': 3, 'Email Address': 2},
        }
        fake_stats = {
            'critical_pending': 2,
            'reopened_alerts': 1,
            'total_reopens': 1,
            'by_severity': {'CRITICAL': 2, 'HIGH': 3},
        }
        fake_alerts = [
            {'finding': {'pattern_name': 'Private Key', 'severity': 'CRITICAL'}, 'is_new': True},
            {'finding': {'pattern_name': 'SSN', 'severity': 'HIGH'}, 'is_new': True},
        ]
        text = self._build_text(fake_summary, fake_stats, fake_alerts)
        text = "[TEST] " + text

        try:
            if channel_name == 'smtp':
                self._send_smtp(channel_config, text, fake_summary)
            elif channel_name == 'slack':
                self._send_slack(channel_config, text, fake_summary)
            elif channel_name == 'teams':
                self._send_teams(channel_config, text, fake_summary)
            elif channel_name == 'webhook':
                self._send_webhook(channel_config, fake_summary, fake_stats, fake_alerts)
            elif channel_name == 'thehive':
                from thehive_integration import TheHiveIntegration
                url = channel_config.get('url', 'http://thehive:9000')
                api_key = channel_config.get('api_key', '')
                thehive = TheHiveIntegration(url=url, api_key=api_key)
                if not thehive.test_connection():
                    raise ConnectionError(f'Could not connect to TheHive at {url}')
            return {'status': 'sent'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    # ---- Internal methods ----

    def _has_matching_severity(self, summary, severity_filter):
        by_sev = summary.get('by_severity', {})
        for sev in severity_filter:
            if by_sev.get(sev, 0) > 0:
                return True
        return False

    def _build_text(self, summary, stats, new_alerts):
        by_sev = summary.get('by_severity', {})
        sev_parts = []
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = by_sev.get(s, 0)
            if count > 0:
                sev_parts.append(f"{count} {s}")

        new_count = len(new_alerts) if new_alerts else 0
        reopened = stats.get('reopened_alerts', 0)
        critical_pending = stats.get('critical_pending', 0)

        top_patterns = sorted(
            summary.get('by_pattern', {}).items(),
            key=lambda x: x[1], reverse=True
        )[:5]

        lines = [
            "Poirot DSPM - Scan Report",
            "=" * 40,
            "  " + " | ".join(sev_parts) if sev_parts else "  No findings",
        ]

        detail_parts = []
        if new_count > 0:
            detail_parts.append(f"{new_count} new alerts")
        if reopened > 0:
            detail_parts.append(f"{reopened} reopened")
        if detail_parts:
            lines.append("  " + " | ".join(detail_parts))

        if critical_pending > 0:
            lines.append(f"  {critical_pending} critical pending")

        if top_patterns:
            lines.append("")
            lines.append("Top findings:")
            for pattern, count in top_patterns:
                lines.append(f"  - {pattern}: {count} detections")

        return "\n".join(lines)

    def _send_smtp(self, cfg, text, summary=None):
        msg = MIMEMultipart('alternative')
        
        # Build From header with optional display name/alias
        from_address = cfg.get('from_address', '')
        from_name = cfg.get('from_name', '').strip()
        if from_name:
            # Format: "Display Name" <email@domain.com>
            msg['From'] = f'"{from_name}" <{from_address}>'
        else:
            msg['From'] = from_address
            
        msg['To'] = cfg.get('to_addresses', '')
        msg['Subject'] = 'Poirot DSPM - Scan Report'

        # Always attach plain text as fallback
        msg.attach(MIMEText(text, 'plain'))

        # If Ollama enabled, generate and attach HTML
        if self.ollama_config.get('enabled') and summary:
            try:
                email_theme = os.environ.get('SMTP_EMAIL_THEME', cfg.get('email_theme', 'dark_cyber'))
                html = self._generate_html_with_ollama(text, summary, email_theme)
                msg.attach(MIMEText(html, 'html'))
            except Exception as e:
                print(f"[ollama] HTML generation failed, using plain text: {e}")

        host = cfg.get('host', 'localhost')
        port = int(cfg.get('port', 587))
        use_tls = cfg.get('use_tls', True)

        server = smtplib.SMTP(host, port, timeout=10)
        if use_tls:
            server.starttls()
        username = cfg.get('username', '')
        password = cfg.get('password', '')
        if username and password:
            server.login(username, password)
        to_list = [a.strip() for a in msg['To'].split(',') if a.strip()]
        server.sendmail(msg['From'], to_list, msg.as_string())
        server.quit()

    def _generate_html_with_ollama(self, plain_text, summary, email_theme='light'):
        """Generate HTML email with Ollama analysis. Theme: 'light' or 'dark_cyber'."""
        analysis_text = self._get_ollama_analysis(summary)
        analysis, recommendations = self._parse_ollama_response(analysis_text)
        kwargs = dict(
            summary=summary,
            analysis_text=analysis,
            recommendations_html=recommendations,
            dashboard_url=os.environ.get('DASHBOARD_URL', 'http://localhost:8080'),
        )
        if email_theme == 'dark_cyber':
            return generate_dark_cyber_email_html(**kwargs)
        return generate_cyber_email_html(**kwargs)

    def _get_ollama_analysis(self, summary):
        """Ask Ollama to generate only the analysis paragraph."""
        ollama_cfg = self.ollama_config
        url = ollama_cfg.get('url', 'http://host.docker.internal:11434')
        model = ollama_cfg.get('model', 'llama3.2')

        by_sev = summary.get('by_severity', {})
        by_src = summary.get('by_source', {})
        by_pat = summary.get('by_pattern', {})
        top_patterns = sorted(by_pat.items(), key=lambda x: x[1], reverse=True)[:7]

        src_labels = {'mysql': 'MySQL database', 's3': 'S3 bucket',
                      'gdrive': 'Google Drive', 'onedrive': 'OneDrive'}
        source_lines = [f"- {src_labels.get(s, s)}: {c} findings" for s, c in by_src.items()]
        pattern_lines = [f"- {p}: {c} detections" for p, c in top_patterns]

        prompt = f"""You are an information security consultant. Perform a security posture analysis based on the results of a vulnerability scan in a test environment.

CONTEXT: This is a defensive scan (Data Security Posture Management) to identify sensitive data exposed in controlled testing environments. The detected data is synthetic/fictitious.

SCAN RESULTS:
- Total findings: {summary.get('total_findings', 0)}
- Severity: CRITICAL={by_sev.get('CRITICAL', 0)}, HIGH={by_sev.get('HIGH', 0)}, MEDIUM={by_sev.get('MEDIUM', 0)}, LOW={by_sev.get('LOW', 0)}

Analyzed sources:
{chr(10).join(source_lines)}

Data categories:
{chr(10).join(pattern_lines[:5])}

Provide your assessment in this format:

ANALYSIS:
Risk assessment and exposure of identified sensitive data.

RECOMMENDATIONS:
- Mitigation measure 1
- Mitigation measure 2
- Mitigation measure 3"""

        resp = requests.post(
            f"{url}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            },
            timeout=120,
        )
        resp.raise_for_status()
        analysis = resp.json()["message"]["content"].strip()

        # Clean up: remove "Nota:" disclaimers the model sometimes appends
        import re
        for marker in ['Nota:', 'Note:', 'Disclaimer:', 'NOTA:']:
            idx = analysis.find(marker)
            if idx > 0:
                analysis = analysis[:idx].strip()

        # Remove any HTML tags the model might inject
        analysis = re.sub(r'<[^>]+>', '', analysis)
        print(f"[ollama] Analysis generated ({len(analysis)} chars)")
        return analysis

    def _get_ollama_analysis_for_slack(self, summary):
        """Get Ollama analysis formatted for Slack (short and emoji-friendly)."""
        if not self.ollama_config.get('enabled'):
            return None
        
        try:
            # Reuse existing analysis method
            analysis_text = self._get_ollama_analysis(summary)
            analysis, recommendations = self._parse_ollama_response_for_slack(analysis_text)
            
            return {
                'analysis': analysis,
                'recommendations': recommendations
            }
        except Exception as e:
            print(f"[ollama] Slack analysis failed: {e}")
            return None
    
    def _is_refusal_response(self, text):
        """Detect if Ollama refused to answer due to safety concerns."""
        refusal_phrases = [
            'lo siento', 'no puedo', 'sorry', 'i cannot', 'i can\'t',
            'no puedo proporcionar', 'no puedo ayudar', 'disculpa',
            'i\'m sorry', 'i am sorry', 'cannot provide', 'unable to',
            'ataques ciberneticos', 'ciberataques', 'actividades maliciosas',
            'i\'m not able', 'i am not able',
        ]
        text_lower = text.lower()
        return any(phrase in text_lower for phrase in refusal_phrases)

    def _parse_ollama_response_for_slack(self, text):
        """Parse Ollama response for Slack format."""
        import re

        # Check if model refused to answer
        if self._is_refusal_response(text):
            return None, []

        # Remove markdown formatting
        text = re.sub(r'\*\*\*?(.+?)\*\*\*?', r'\1', text)
        text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
        text = re.sub(r'\*(.+?)\*', r'\1', text)

        analysis = ""
        recommendations = []

        # Try multiple patterns for ANALYSIS section (English + Spanish fallback)
        analisis_patterns = [
            r'ANALYSIS:\s*(.*?)(?=RECOMMENDATIONS:|$)',
            r'ANÁLISIS:\s*(.*?)(?=RECOMENDACIONES:|$)',
            r'ANALISIS:\s*(.*?)(?=RECOMENDACIONES:|$)',
            r'ANALYSIS\s+(.*?)(?=RECOMMENDATIONS|$)',
            r'ANÁLISIS\s+(.*?)(?=RECOMENDACIONES|$)',
            r'ANALISIS\s+(.*?)(?=RECOMENDACIONES|$)',
        ]
        for pattern in analisis_patterns:
            analisis_match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if analisis_match:
                analysis = analisis_match.group(1).strip()
                break

        # Try multiple patterns for RECOMMENDATIONS section
        rec_patterns = [
            r'RECOMMENDATIONS:\s*(.*)',
            r'RECOMENDACIONES:\s*(.*)',
            r'RECOMMENDATIONS\s+(.*)',
            r'RECOMENDACIONES\s+(.*)',
        ]
        for pattern in rec_patterns:
            rec_match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if rec_match:
                rec_text = rec_match.group(1).strip()
                for line in rec_text.split('\n'):
                    line = line.strip()
                    if line.startswith(('-', '*')) and not line.startswith('**'):
                        rec = line[1:].strip()
                        if rec and len(rec) > 5:
                            recommendations.append(rec)
                    elif line and len(line) > 10 and not line.upper().startswith(
                        ('ANALYSIS', 'RECOMMENDATIONS', 'ANALISIS', 'RECOMENDACIONES')
                    ):
                        recommendations.append(line)
                break

        # Fallback: if no clear sections found
        if not analysis and not recommendations:
            split_markers = ['RECOMMENDATIONS', 'RECOMENDACIONES', 'TO ADDRESS', 'MITIGATION']
            for marker in split_markers:
                idx = text.upper().find(marker)
                if idx > 0:
                    analysis = text[:idx].strip()
                    rec_text = text[idx:].strip()
                    for line in rec_text.split('\n'):
                        line = line.strip()
                        if line and len(line) > 10 and not line.upper().startswith(marker):
                            recommendations.append(line)
                    break
            if not analysis:
                analysis = text

        # Clean up analysis
        for marker in ['RECOMMENDATIONS', 'RECOMENDACIONES', 'TO ADDRESS', 'MITIGATION']:
            idx = analysis.upper().find(marker)
            if idx > 0:
                analysis = analysis[:idx].strip()

        return analysis, recommendations[:5]  # Limit to 5 recommendations

    def _parse_ollama_response(self, text):
        """Parse Ollama response into analysis and recommendations HTML."""
        import re

        # Check if model refused to answer
        if self._is_refusal_response(text):
            fallback_analysis = "Security findings were detected that require attention. Review the critical data identified in the scanned sources and prioritize remediation by severity."
            fallback_html = '<li>Prioritize review of CRITICAL and HIGH findings</li>\n<li>Implement access controls on affected data sources</li>\n<li>Regularly audit sensitive data exposure</li>'
            return fallback_analysis, fallback_html

        # Remove markdown bold/italic that Ollama adds
        text = re.sub(r'\*\*\*?(.+?)\*\*\*?', r'\1', text)
        text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
        text = re.sub(r'\*(.+?)\*', r'\1', text)

        analysis = ""
        recommendations = []

        # Try multiple patterns for ANALYSIS section (English + Spanish fallback)
        analisis_patterns = [
            r'ANALYSIS:\s*(.*?)(?=RECOMMENDATIONS:|$)',
            r'ANÁLISIS:\s*(.*?)(?=RECOMENDACIONES:|$)',
            r'ANALISIS:\s*(.*?)(?=RECOMENDACIONES:|$)',
            r'ANALYSIS\s+(.*?)(?=RECOMMENDATIONS|$)',
            r'ANÁLISIS\s+(.*?)(?=RECOMENDACIONES|$)',
            r'ANALISIS\s+(.*?)(?=RECOMENDACIONES|$)',
        ]
        for pattern in analisis_patterns:
            analisis_match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if analisis_match:
                analysis = analisis_match.group(1).strip()
                break

        # Try multiple patterns for RECOMMENDATIONS section
        rec_patterns = [
            r'RECOMMENDATIONS:\s*(.*)',
            r'RECOMENDACIONES:\s*(.*)',
            r'RECOMMENDATIONS\s+(.*)',
            r'RECOMENDACIONES\s+(.*)',
        ]
        for pattern in rec_patterns:
            rec_match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if rec_match:
                rec_text = rec_match.group(1).strip()
                for line in rec_text.split('\n'):
                    line = line.strip()
                    if line.startswith('*') and not line.startswith('**'):
                        line = line[1:].strip()
                    elif line.startswith('-'):
                        line = line[1:].strip()
                    elif re.match(r'^\d+\.', line):
                        line = re.sub(r'^\d+\.', '', line).strip()
                    if line and len(line) > 5 and not line.upper().startswith(
                        ('ANALYSIS', 'RECOMMENDATIONS', 'ANALISIS', 'RECOMENDACIONES')
                    ):
                        recommendations.append(line)
                break

        # Fallback: if no clear sections found
        if not analysis and not recommendations:
            split_markers = ['RECOMMENDATIONS', 'RECOMENDACIONES', 'TO ADDRESS', 'MITIGATION']
            found = False
            for marker in split_markers:
                idx = text.upper().find(marker)
                if idx > 0:
                    analysis = text[:idx].strip()
                    rec_text = text[idx:].strip()
                    for line in rec_text.split('\n'):
                        line = line.strip()
                        if line and len(line) > 10 and not line.upper().startswith(marker):
                            recommendations.append(line)
                    found = True
                    break
            if not found:
                analysis = text

        # Clean up analysis
        for marker in ['RECOMMENDATIONS', 'RECOMENDACIONES', 'TO ADDRESS', 'MITIGATION']:
            idx = analysis.upper().find(marker)
            if idx > 0:
                analysis = analysis[:idx].strip()

        # Convert newlines to HTML breaks for email
        if analysis:
            analysis = analysis.replace('\n', '<br>\n')

        # Build HTML for recommendations (limit to top 5)
        if recommendations:
            unique_recs = []
            seen = set()
            for rec in recommendations[:5]:
                if rec not in seen:
                    unique_recs.append(rec)
                    seen.add(rec)
            recommendations_html = '\n'.join([f'<li>{rec}</li>' for rec in unique_recs])
        else:
            recommendations_html = '<li>Prioritize review of CRITICAL and HIGH findings</li>\n<li>Implement access controls on affected data sources</li>\n<li>Regularly audit sensitive data exposure</li>'

        return analysis, recommendations_html

    def _send_slack(self, cfg, text, summary):
        by_sev = summary.get('by_severity', {})
        by_src = summary.get('by_source', {})
        total = summary.get('total_findings', 0)
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        # Get Ollama analysis
        slack_analysis = self._get_ollama_analysis_for_slack(summary)

        critical = by_sev.get('CRITICAL', 0)
        high     = by_sev.get('HIGH', 0)
        medium   = by_sev.get('MEDIUM', 0)
        low      = by_sev.get('LOW', 0)

        # Dynamic header based on worst severity
        if critical > 0:
            header_emoji, header_text = "🚨", "CRITICAL SECURITY ALERT"
        elif high > 0:
            header_emoji, header_text = "⚠️", "HIGH SEVERITY ALERT"
        elif medium > 0:
            header_emoji, header_text = "🔶", "MEDIUM SEVERITY ALERT"
        else:
            header_emoji, header_text = "✅", "SCAN COMPLETED"

        # Severity bar with emoji blocks
        max_val = max(total, 1)
        bar_len = 20
        severity_bar = (
            "🟥" * int((critical / max_val) * bar_len) +
            "🟧" * int((high    / max_val) * bar_len) +
            "🟨" * int((medium  / max_val) * bar_len) +
            "🟩" * int((low     / max_val) * bar_len)
        ) or "▪️ No findings"

        # Source fields (pairs)
        src_icons = {'mysql': '🗄️', 's3': '☁️', 'gdrive': '📁', 'onedrive': '📁', 'kafka': '📡'}
        source_fields = [
            {"type": "mrkdwn", "text": f"{src_icons.get(src.lower(), '📂')} *{src.upper()}:*\n`{count}` findings"}
            for src, count in list(by_src.items())[:4]
        ]

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"{header_emoji} {header_text}", "emoji": True}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*🔴 Critical:*\n`{critical}`"},
                    {"type": "mrkdwn", "text": f"*🟠 High:*\n`{high}`"},
                    {"type": "mrkdwn", "text": f"*🟡 Medium:*\n`{medium}`"},
                    {"type": "mrkdwn", "text": f"*🟢 Low:*\n`{low}`"},
                ]
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*📊 Total Findings:* `{total}`"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Severity Distribution:*\n{severity_bar}"}},
            {"type": "divider"},
        ]

        # Sources
        if source_fields:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*📁 Data Sources Scanned:*"}})
            for i in range(0, len(source_fields), 2):
                blocks.append({"type": "section", "fields": source_fields[i:i+2]})
            blocks.append({"type": "divider"})

        # Ollama analysis
        if slack_analysis and slack_analysis.get('analysis'):
            analysis_text = slack_analysis['analysis'].replace('*', '•')[:300]
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*🔍 AI Security Analysis:*\n>{analysis_text}..."}
            })
            if slack_analysis.get('recommendations'):
                recs = "\n".join(f"• {r}" for r in slack_analysis['recommendations'][:3])
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*💡 Top Recommendations:*\n{recs}"}
                })
            blocks.append({"type": "divider"})

        # Action buttons
        blocks.append({
            "type": "actions",
            "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "🔍 View Full Report", "emoji": True},
                 "url": dashboard_url, "style": "primary"},
                {"type": "button", "text": {"type": "plain_text", "text": "⚙️ Settings", "emoji": True},
                 "url": f"{dashboard_url}/settings"},
            ]
        })

        # Footer
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"🤖 Poirot DSPM • {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}"}]
        })

        payload = json.dumps({"blocks": blocks}).encode('utf-8')
        req = Request(cfg['webhook_url'], data=payload, headers={'Content-Type': 'application/json'})
        urlopen(req, timeout=10)

    def _send_teams(self, cfg, text, summary):
        by_sev = summary.get('by_severity', {})
        by_src = summary.get('by_source', {})
        total = summary.get('total_findings', 0)
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        # Get Ollama analysis
        teams_analysis = self._get_ollama_analysis_for_teams(summary)

        critical = by_sev.get('CRITICAL', 0)
        high     = by_sev.get('HIGH', 0)
        medium   = by_sev.get('MEDIUM', 0)
        low      = by_sev.get('LOW', 0)

        # Dynamic theme based on worst severity
        if critical > 0:
            theme_color, title, subtitle = "d63939", "🚨 CRITICAL SECURITY ALERT", "Immediate attention required"
        elif high > 0:
            theme_color, title, subtitle = "f76707", "⚠️ HIGH SEVERITY ALERT",     "Review recommended"
        elif medium > 0:
            theme_color, title, subtitle = "eab308", "🔶 MEDIUM SEVERITY ALERT",   "Standard review"
        else:
            theme_color, title, subtitle = "16a34a", "✅ SCAN COMPLETED",           "No critical issues found"

        # Facts: severity counts + separator + sources
        facts = [
            {"name": "🔴 Critical", "value": str(critical)},
            {"name": "🟠 High",     "value": str(high)},
            {"name": "🟡 Medium",   "value": str(medium)},
            {"name": "🟢 Low",      "value": str(low)},
            {"name": "📊 Total",    "value": str(total)},
            {"name": "─" * 15,      "value": "─" * 15},
        ]
        for src, count in by_src.items():
            facts.append({"name": f"📁 {src.upper()}", "value": f"{count} findings"})

        sections = [{
            "activityTitle": title,
            "activitySubtitle": f"{subtitle} • {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "facts": facts[:12],
            "markdown": True,
        }]

        # Ollama analysis
        if teams_analysis and teams_analysis.get('analysis'):
            analysis_clean = teams_analysis['analysis'].replace('*', '').replace('_', '')[:400]
            sections.append({"title": "🔍 AI Security Analysis", "text": analysis_clean})
            if teams_analysis.get('recommendations'):
                recs = "\n\n".join(f"{i+1}. {r}" for i, r in enumerate(teams_analysis['recommendations'][:5]))
                sections.append({"title": "💡 Recommendations", "text": recs})

        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": f"Poirot DSPM - {total} findings detected",
            "sections": sections,
            "potentialAction": [
                {"@type": "OpenUri", "name": "🔍 View Full Report",
                 "targets": [{"os": "default", "uri": dashboard_url}]},
                {"@type": "OpenUri", "name": "⚙️ Dashboard Settings",
                 "targets": [{"os": "default", "uri": f"{dashboard_url}/settings"}]},
            ]
        }

        payload = json.dumps(card).encode('utf-8')
        req = Request(cfg['webhook_url'], data=payload, headers={'Content-Type': 'application/json'})
        urlopen(req, timeout=10)

    def _get_ollama_analysis_for_teams(self, summary):
        """Get Ollama analysis formatted for Teams (similar to Slack)."""
        if not self.ollama_config.get('enabled'):
            return None
        
        try:
            # Reuse existing analysis method
            analysis_text = self._get_ollama_analysis(summary)
            analysis, recommendations = self._parse_ollama_response_for_slack(analysis_text)
            
            return {
                'analysis': analysis,
                'recommendations': recommendations
            }
        except Exception as e:
            print(f"[ollama] Teams analysis failed: {e}")
            return None

    def _send_webhook(self, cfg, summary, stats, new_alerts):
        payload_data = {
            'source': 'poirot-dspm',
            'event': 'scan_complete',
            'summary': summary,
            'stats': stats,
            'new_alerts_count': len(new_alerts) if new_alerts else 0,
        }
        url = cfg.get('url', '')
        method = cfg.get('method', 'POST').upper()
        headers = cfg.get('headers', {'Content-Type': 'application/json'})

        payload = json.dumps(payload_data, default=str).encode('utf-8')
        req = Request(url, data=payload, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        urlopen(req, timeout=10)

    def _send_thehive(self, cfg, new_alerts, alert_mgr):
        """Create TheHive cases for each new alert using TheHiveIntegration."""
        from thehive_integration import TheHiveIntegration

        url = cfg.get('url', 'http://thehive:9000')
        api_key = cfg.get('api_key', '')
        create_cases = cfg.get('create_cases', True)
        severity_filter = cfg.get('severity_filter', [])

        thehive = TheHiveIntegration(url=url, api_key=api_key)

        print("[thehive] Connecting to TheHive...")
        if not thehive.test_connection():
            raise ConnectionError(f'Could not connect to TheHive at {url}')

        # Sync existing case statuses
        if alert_mgr:
            print("[thehive] Syncing case statuses...")
            synced = thehive.sync_cases_status(alert_mgr)
            print(f"[notifications] thehive: sync - open={synced.get('open', 0)}, resolved={synced.get('resolved', 0)}")

        if not create_cases:
            print("[notifications] thehive: create_cases=false, sync only")
            return 0

        if not new_alerts:
            return 0

        # Filter alerts by severity
        eligible = [a for a in new_alerts
                    if not severity_filter or a['finding'].get('severity') in severity_filter]

        total = len(eligible)
        if total == 0:
            print("[thehive] No new cases created")
            return 0

        print(f"[thehive] Creating {total} cases in TheHive (parallel)...")

        def _create_one(alert):
            finding   = alert['finding']
            is_reopen = alert.get('is_reopen', False)
            a_hash    = alert['alert_hash']
            case_id   = thehive.create_case(finding, a_hash, is_reopen)
            if case_id and alert_mgr:
                alert_mgr.update_thehive_case(a_hash, case_id, 'New')
                return 1
            return 0

        cases_created = 0
        with ThreadPoolExecutor(max_workers=min(5, total)) as pool:
            futures = [pool.submit(_create_one, a) for a in eligible]
            for i, fut in enumerate(as_completed(futures), 1):
                cases_created += fut.result()
                print(f"[thehive] Case {i}/{total}")

        return cases_created
