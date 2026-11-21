"""Détection de la connexion réseau depuis Android / Termux."""

import json
import subprocess
import ipaddress


def _run_api(command):
    try:
        result = subprocess.run(
            [command],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        return json.loads(result.stdout)
    except (
        FileNotFoundError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ):
        return None


def _getprop(name):
    try:
        result = subprocess.run(
            ["getprop", name],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return result.stdout.strip() or None
    except (FileNotFoundError, subprocess.SubprocessError):
        return None


def detect_connection():
    wifi = _run_api("termux-wifi-connectioninfo")
    mobile = _run_api("termux-telephony-deviceinfo")

    if isinstance(mobile, list):
        mobile = mobile[0] if mobile else {}

    if not isinstance(mobile, dict):
        mobile = {}

    if not isinstance(wifi, dict):
        wifi = {}

    wifi_state = str(
        wifi.get("supplicant_state", "")
    ).upper()

    wifi_ip = wifi.get("ip")
    wifi_connected = wifi_state == "COMPLETED"

    if wifi_ip:
        try:
            wifi_connected = (
                wifi_connected
                and ipaddress.ip_address(wifi_ip).is_global is False
                and wifi_ip != "0.0.0.0"
            )
        except ValueError:
            wifi_connected = False

    data_state = str(
        mobile.get("data_state", "")
    ).lower()

    mobile_connected = data_state == "connected"

    network_type = (
        mobile.get("network_type")
        or _getprop("gsm.network.type")
        or "unknown"
    )

    operator_code = mobile.get("network_operator")

    evidence = {
        "wifi_state": wifi_state or "unknown",
        "wifi_connected": wifi_connected,
        "mobile_data_state": data_state or "unknown",
        "mobile_data_connected": mobile_connected,
        "mobile_data_enabled": str(
            mobile.get("data_enabled", "")
        ).lower() == "true",
        "data_activity": mobile.get("data_activity", "unknown"),
        "network_type": str(network_type),
        "operator_code": operator_code,
        "operator_name": mobile.get("network_operator_name"),
        "phone_count": mobile.get("phone_count"),
        "network_roaming": mobile.get("network_roaming"),
    }

    if wifi_connected:
        connection = "wifi"
        confidence = "system_detected"
        explanation = "Android signale une connexion Wi-Fi active."

    elif mobile_connected:
        connection = "mobile_data"
        confidence = "probable"
        explanation = (
            "Wi-Fi non associé et données mobiles connectées. "
            "La route réseau effective reste à confirmer."
        )

    else:
        connection = "unknown"
        confidence = "unknown"
        explanation = (
            "Le type de connexion active ne peut pas être confirmé."
        )

    return {
        "connection_type": connection,
        "confidence": confidence,
        "network_generation": str(network_type),
        "operator_code": operator_code,
        "explanation": explanation,
        "evidence": evidence,
    }
