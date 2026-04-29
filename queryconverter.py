import json
from pathlib import Path
from typing import Any


INPUT_FILE = "raw.json"
OUTPUT_FILE = "queryconverted.txt"


def to_graphql(value: Any, indent: int = 0) -> str:
    space = " " * indent
    next_space = " " * (indent + 2)

    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, str):
        return json.dumps(value)

    if isinstance(value, int):
        return str(value)

    if isinstance(value, list):
        if not value:
            return "[]"
        return "[\n" + ",\n".join(
            f"{next_space}{to_graphql(item, indent + 2)}"
            for item in value
        ) + f"\n{space}]"

    if isinstance(value, dict):
        if not value:
            return "{}"
        return "{\n" + ",\n".join(
            f"{next_space}{key}: {to_graphql(item, indent + 2)}"
            for key, item in value.items()
        ) + f"\n{space}}}"

    raise TypeError(f"Unsupported type: {type(value)}")


raw = json.loads(Path(INPUT_FILE).read_text(encoding="utf-8"))

mutation = f"""mutation {{
  sendZkapp(input: {to_graphql({"zkappCommand": raw["zkappCommand"]}, 2)}) {{
    zkapp {{
      hash
      id
      failureReason {{
        failures
        index
      }}
      zkappCommand {{
        memo
        feePayer {{
          body {{
            publicKey
          }}
        }}
        accountUpdates {{
          body {{
            publicKey
            useFullCommitment
            incrementNonce
          }}
        }}
      }}
    }}
  }}
}}
"""

Path(OUTPUT_FILE).write_text(mutation, encoding="utf-8")
print(f"Generated {OUTPUT_FILE}")