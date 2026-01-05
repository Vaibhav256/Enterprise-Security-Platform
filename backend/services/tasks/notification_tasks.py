"""
Notification Tasks

RQ (Redis Queue) tasks for sending notifications and alerts.

Author: NTRO Security Team
Date: 2025-10-26
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def send_scan_notification(
    scan_id: str, status: str, recipients: Optional[List[str]] = None
):
    """
    Send scan completion notification

    Args:
        scan_id: Unique scan identifier
        status: Scan status (completed, failed, etc.)
        recipients: List of recipient email addresses

    Returns:
        Notification status
    """
    try:
        logger.info(f"Sending notification for scan {scan_id} with status {status}")

        # Import email/webhook configuration
        from config.config import get_config
        config = get_config()

        # Check if notification settings are configured
        email_configured = hasattr(config, 'SMTP_HOST') and config.SMTP_HOST
        webhook_configured = hasattr(config, 'WEBHOOK_URL') and config.WEBHOOK_URL

        notification_result: Dict[str, Any] = {
            "sent": False,
            "scan_id": scan_id,
            "status": status,
            "recipients": recipients or [],
            "methods": []
        }

        # Send email notification if configured
        if email_configured and recipients:
            try:
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart

                msg = MIMEMultipart()
                msg['From'] = config.SMTP_FROM
                msg['To'] = ', '.join(recipients)
                msg['Subject'] = f'Scan {status}: {scan_id}'

                body = f"""
                Security Scan Notification

                Scan ID: {scan_id}
                Status: {status.upper()}
                Timestamp: {datetime.now().isoformat()}

                View details at: {config.APP_URL}/scans/{scan_id}
                """

                msg.attach(MIMEText(body, 'plain'))

                with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
                    if config.SMTP_USE_TLS:
                        server.starttls()
                    if hasattr(config, 'SMTP_USERNAME') and config.SMTP_USERNAME:
                        server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                    server.send_message(msg)

                notification_result["sent"] = True
                notification_result["methods"].append("email")
                logger.info(f"Email notification sent to {len(recipients)} recipients")

            except Exception as e:
                logger.warning(f"Failed to send email notification: {e}")

        # Send webhook notification if configured
        if webhook_configured:
            try:
                import requests

                payload = {
                    "event": "scan_notification",
                    "scan_id": scan_id,
                    "status": status,
                    "timestamp": datetime.now().isoformat(),
                    "recipients": recipients or []
                }

                response = requests.post(
                    config.WEBHOOK_URL,
                    json=payload,
                    timeout=10,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    notification_result["sent"] = True
                    notification_result["methods"].append("webhook")
                    logger.info(f"Webhook notification sent to {config.WEBHOOK_URL}")
                else:
                    logger.warning(f"Webhook returned status {response.status_code}")

            except Exception as e:
                logger.warning(f"Failed to send webhook notification: {e}")

        # If no notification methods configured, just log
        if not email_configured and not webhook_configured:
            logger.info(f"No notification methods configured. Scan {scan_id}: {status}")
            notification_result["sent"] = True
            notification_result["methods"].append("log_only")

        return notification_result

    except Exception as e:
        logger.error(f"Failed to send notification for scan {scan_id}: {str(e)}")
        raise


def send_alert(
    alert_type: str,
    message: str,
    severity: str = "info",
    data: Optional[Dict[str, Any]] = None,
):
    """
    Send alert notification

    Args:
        alert_type: Type of alert (vulnerability, system, etc.)
        message: Alert message
        severity: Alert severity level
        data: Additional alert data

    Returns:
        Alert status
    """
    try:
        logger.info(f"Sending {severity} alert: {alert_type}")

        # Import configuration
        from config.config import get_config
        config = get_config()

        # Check if alert methods are configured
        email_configured = hasattr(config, 'ALERT_EMAIL') and config.ALERT_EMAIL
        webhook_configured = hasattr(config, 'ALERT_WEBHOOK_URL') and config.ALERT_WEBHOOK_URL

        alert_result: Dict[str, Any] = {
            "sent": False,
            "type": alert_type,
            "severity": severity,
            "message": message,
            "methods": []
        }

        # Send email alert if configured
        if email_configured:
            try:
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart

                msg = MIMEMultipart()
                msg['From'] = config.SMTP_FROM
                msg['To'] = config.ALERT_EMAIL
                msg['Subject'] = f'[{severity.upper()}] {alert_type}'

                body = f"""
                Security Alert

                Type: {alert_type}
                Severity: {severity.upper()}
                Time: {datetime.now().isoformat()}

                Message:
                {message}

                Additional Data:
                {data or 'None'}
                """

                msg.attach(MIMEText(body, 'plain'))

                with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
                    if config.SMTP_USE_TLS:
                        server.starttls()
                    if hasattr(config, 'SMTP_USERNAME') and config.SMTP_USERNAME:
                        server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                    server.send_message(msg)

                alert_result["sent"] = True
                alert_result["methods"].append("email")
                logger.info(f"Email alert sent to {config.ALERT_EMAIL}")

            except Exception as e:
                logger.warning(f"Failed to send email alert: {e}")

        # Send webhook alert if configured
        if webhook_configured:
            try:
                import requests

                payload = {
                    "event": "security_alert",
                    "type": alert_type,
                    "severity": severity,
                    "message": message,
                    "timestamp": datetime.now().isoformat(),
                    "data": data or {}
                }

                response = requests.post(
                    config.ALERT_WEBHOOK_URL,
                    json=payload,
                    timeout=10,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    alert_result["sent"] = True
                    alert_result["methods"].append("webhook")
                    logger.info(f"Webhook alert sent to {config.ALERT_WEBHOOK_URL}")
                else:
                    logger.warning(f"Alert webhook returned status {response.status_code}")

            except Exception as e:
                logger.warning(f"Failed to send webhook alert: {e}")

        # If no alert methods configured, just log
        if not email_configured and not webhook_configured:
            logger.warning(f"ALERT [{severity.upper()}] {alert_type}: {message}")
            if data:
                logger.warning(f"Alert data: {data}")
            alert_result["sent"] = True
            alert_result["methods"].append("log_only")

        return alert_result

    except Exception as e:
        logger.error(f"Failed to send alert: {str(e)}")
        raise
