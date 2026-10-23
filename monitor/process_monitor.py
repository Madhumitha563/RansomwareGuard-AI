import time
import psutil
from datetime import datetime


def start_process_monitor(socketio, db):

    print("Process monitor started")

    # Initialize CPU baseline
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(None)
        except Exception:
            pass

    time.sleep(1)

    while True:

        try:

            process_list = []
            suspicious_count = 0

            for proc in psutil.process_iter(
                ["pid", "name"]
            ):

                try:

                    cpu = proc.cpu_percent(
                        interval=None
                    )

                    name = proc.info["name"]
                    pid = proc.info["pid"]

                    status = "Normal"

                    if cpu > 50:

                        status = "Suspicious"
                        suspicious_count += 1

                    process_list.append({

                        "time":
                        datetime.now()
                        .strftime("%H:%M:%S"),

                        "name": name,
                        "pid": pid,
                        "cpu": round(cpu, 2),
                        "status": status

                    })

                except Exception:

                    pass

            total = len(process_list)

            socketio.emit(

                "process_update",

                {
                    "total": total,
                    "suspicious": suspicious_count,
                    "processes": process_list[:10]
                }

            )

            time.sleep(2)

        except Exception as e:

            print(
                "Process monitor error:",
                e
            )