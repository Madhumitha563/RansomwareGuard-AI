from models import (
    db,
    RiskHistory
)

current_risk = 25


def increase_risk(value):

    global current_risk

    current_risk += value

    if current_risk > 100:
        current_risk = 100

    save_risk()


def decrease_risk(value):

    global current_risk

    current_risk -= value

    if current_risk < 0:
        current_risk = 0

    save_risk()


def get_risk_level():

    if current_risk >= 85:
        return "Critical"

    if current_risk >= 60:
        return "High"

    if current_risk >= 30:
        return "Medium"

    return "Low"


def get_risk_score():

    return current_risk


def save_risk():

    try:

        record = RiskHistory(

            risk_score=current_risk,

            risk_level=get_risk_level()

        )

        db.session.add(record)

        db.session.commit()

        print(
            "Risk history saved:",
            current_risk
        )

    except Exception as e:

        print(
            "Risk history error:",
            e
        )

        db.session.rollback()