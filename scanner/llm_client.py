import os
import json
import urllib.request
import urllib.error

DEFAULT_API_KEY = "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"
DEFAULT_MODEL = "anthropic/claude-3.5-sonnet"

class OpenRouterClient:
    """
    OpenRouter API Client for Challenge 2 LLM Integration.
    Uses standard urllib to avoid external network dependencies.
    """
    def __init__(self, api_key: str = None, model: str = DEFAULT_MODEL):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY", DEFAULT_API_KEY)
        self.model = model
        self.api_url = "https://openrouter.ai/api/v1/chat/completions"

    def complete(self, prompt: str, system_prompt: str = None, max_tokens: int = 1000) -> str | None:
        if not self.api_key:
            return None

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.1
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/LordPercival241/GSC26-Challenge2-147",
            "X-Title": "GSC26 Challenge 2 Team 147"
        }

        try:
            req = urllib.request.Request(
                self.api_url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status == 200:
                    res_body = json.loads(response.read().decode("utf-8"))
                    return res_body["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"[!] OpenRouter API call note: {e}")
            return None

    def explain_patch(self, vulnerability_desc: str, diff_content: str) -> str:
        """Generates a detailed natural language explanation of a patch via LLM."""
        system_prompt = (
            "You are a cybersecurity expert analyzing GitHub Actions code injection fixes. "
            "Provide a concise, precise technical explanation of how the patch remediates the flaw."
        )
        prompt = f"Vulnerability: {vulnerability_desc}\n\nDiff Patch:\n{diff_content}"
        res = self.complete(prompt, system_prompt=system_prompt, max_tokens=300)
        return res or "Sanitized untrusted input context using step-level environment variables."
