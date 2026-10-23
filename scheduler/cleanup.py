import os

from datetime import (
    datetime,
    timedelta
)

from models import (
    db,
    QuarantineFile
)

from config import (
    QUARANTINE_FOLDER
)


def cleanup_old_files():

    cutoff = (
        datetime.utcnow()
        - timedelta(days=7)
    )

    files = QuarantineFile.query.filter(

        QuarantineFile.quarantined_at
        < cutoff

    ).all()

    for file in files:

        path = os.path.join(

            QUARANTINE_FOLDER,

            file.filename

        )

        if os.path.exists(path):

            os.remove(path)

        db.session.delete(file)

    db.session.commit()

    print(
        "Old quarantine files deleted"
    )