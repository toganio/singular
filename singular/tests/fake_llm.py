"""A scripted OpenAI-compatible model: first turn calls the memory tool, second turn answers. No network, no keys."""
import json, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT_CONTENT = "Client Acme prefers short answers."
requests_seen = []
tool_results = []   # what the agent loop sent back to the model as tool output

def completion(body):
    messages = body.get("messages", [])
    tools = [t["function"]["name"] for t in body.get("tools", []) if t.get("type") == "function"]
    used_tool = any(m.get("role") == "tool" for m in messages)
    tool_results.extend(str(m.get("content")) for m in messages if m.get("role") == "tool")
    base = {"id": "chatcmpl-fake", "object": "chat.completion", "created": int(time.time()), "model": body.get("model", "fake"),
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
    if not used_tool and "memory" in tools:
        msg = {"role": "assistant", "content": None, "tool_calls": [{"id": "call_mem_1", "type": "function", "function": {
            "name": "memory", "arguments": json.dumps({"action": "add", "target": "memory", "content": SCRIPT_CONTENT})}}]}
        return {**base, "choices": [{"index": 0, "message": msg, "finish_reason": "tool_calls"}]}
    return {**base, "choices": [{"index": 0, "message": {"role": "assistant", "content": "Noted."}, "finish_reason": "stop"}]}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, payload):
        data = json.dumps(payload).encode(); self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self._json(200, {"object": "list", "data": [{"id": "fake-model", "object": "model", "owned_by": "test"}]})
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        requests_seen.append({"path": self.path, "stream": body.get("stream"), "tools": len(body.get("tools", []))})
        result = completion(body)
        if body.get("stream"):
            self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
            choice = result["choices"][0]; msg = choice["message"]
            delta = {"role": "assistant"}
            if msg.get("tool_calls"):
                delta["tool_calls"] = [{"index": 0, **msg["tool_calls"][0]}]
            else:
                delta["content"] = msg["content"]
            for chunk in ({**result, "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                          {**result, "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": choice["finish_reason"]}]}):
                chunk.pop("usage", None)
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
        else:
            self._json(200, result)

def serve(port=0):
    server = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server

if __name__ == "__main__":
    s = serve(int(sys.argv[1])); print("FAKE LLM", s.server_address[1], flush=True)
    while True: time.sleep(3600)
