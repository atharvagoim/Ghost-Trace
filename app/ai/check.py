"""`npm run ai:check`: confirm GROQ_API_KEY works with one tiny request (no project data is sent)."""

import asyncio
import sys

from ..config import get_settings
from .groq import AIError, GroqClient

SCHEMA = {"type": "object", "properties": {"status": {"type": "string"}}, "required": ["status"], "additionalProperties": False}


async def main() -> int:
    s = get_settings()
    if not s.ai_enabled:
        print("GROQ_API_KEY is not set. Add it to .env (get one at https://console.groq.com/keys).")
        return 1
    print(f"Calling Groq with model {s.groq_model} …")
    try:
        res = await GroqClient().chat_json(
            [{"role": "system", "content": "Reply with JSON."}, {"role": "user", "content": 'Return {"status": "ok"} as JSON.'}],
            SCHEMA, "health_check", max_tokens=200,
        )
    except AIError as exc:
        print(f"Failed ({exc.status_code}): {exc.message}")
        return 1
    print(f"OK: {res.data} via {res.model} in {res.latency_ms} ms ({res.usage.get('total_tokens', '?')} tokens)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
