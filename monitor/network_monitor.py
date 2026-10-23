import psutil
import time

from models import (
    db,
    NetworkLog,
    Log,
    NetworkTraffic
)

from security.behavior_engine import (
    detect_behavior
)

from security.risk_scoring import (
    get_risk_level
)


def start_network_monitor(socketio):

    print("Network monitor started")

    seen_connections = set()

    while True:

        try:

            connections = psutil.net_connections()

            active_count = len(connections)

            # Save traffic metrics

            traffic = NetworkTraffic(

                connections=active_count

            )

            db.session.add(traffic)

            for conn in connections:

                if not conn.raddr:
                    continue

                ip = conn.raddr.ip
                port = conn.raddr.port

                connection_id = f"{ip}:{port}"

                if connection_id in seen_connections:
                    continue

                seen_connections.add(connection_id)

                message = detect_behavior(
                    "network_connection"
                )

                risk_level = get_risk_level()

                # Save detailed log

                network_record = NetworkLog(

                    ip_address=ip,
                    port=port,
                    status="Connected"

                )

                db.session.add(network_record)

                # Save security log

                security_log = Log(

                    event_type="Network",

                    description=f"Connection detected: {ip}:{port}",

                    risk_level=risk_level

                )

                db.session.add(security_log)

                socketio.emit(

                    "live_update",

                    {

                        "alert": message,

                        "connections": active_count,

                        "risk_level": risk_level

                    }

                )

            db.session.commit()

        except Exception as e:

            print(
                "Network monitor error:",
                e
            )

            db.session.rollback()

        time.sleep(5)