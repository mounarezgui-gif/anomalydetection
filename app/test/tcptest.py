import json

from app.detector.rules.tcp import analyser_conversations_tcp


def load_capture_json(filepath):

    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)



if __name__ == "__main__":

    capture = load_capture_json(
        "../samples/test.analysis.json"
    )


    alertes = analyser_conversations_tcp(capture)


    print(f"{len(alertes)} alerte(s) générée(s) :\n")


    for a in alertes:
        print(
            f"[{a['severite']}] "
            f"{a['rule_id']} -> "
            f"{a['description']}"
        )