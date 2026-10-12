"""Shared pieces for the mock DBS APIs.

Each module in this package mirrors one API from the DBS developer catalogue (dbs.com/dbsdevelopers) by name and
purpose (the fields are our own; the real specifications aren't public). A module exposes TOOLS: the agent tools
backed by that API. To add an API, add a module and list it in __init__.py; nobody else's file changes.

Every tool has a tier, which decides what the agent may do with it (agent/tools.py shrinks the set by risk/phase):
  read     look things up                                     (balances, payees, limits, GIRO, standing orders)
  draft    prepare something the customer must sign            (payments, standing orders, new payee, higher limit)
  control  protective actions that apply at once, and are logged (lower the limit, cancel a GIRO or standing order)
Optional `group`: the tool is only offered to the model when the conversation is about it (fewer tools = fewer
mistakes for a small model).
"""
from __future__ import annotations

from typing import Callable

from pydantic import BaseModel


MISHEARD_DESC = ("Only if speech recognition clearly misheard the AMOUNT: the user's words exactly as transcribed, "
                 "e.g. 'a grant' (else omit)")
MEANT_DESC = "What you're sure they meant, e.g. 'a grand'. The card shows both so the user can check."


class NoArgs(BaseModel):
    pass


class Tool:
    def __init__(self, name: str, tier: str, description: str, args: type[BaseModel], fn: Callable,
                 api: str = "", group: str = ""):
        self.name, self.tier, self.description, self.args, self.fn = name, tier, description, args, fn
        self.api, self.group = api, group

    def schema(self) -> dict:
        params = self.args.model_json_schema()
        params.pop("title", None)
        for p in params.get("properties", {}).values():
            p.pop("title", None)
        params.setdefault("properties", {})
        return {"type": "function", "function": {"name": self.name, "description": self.description,
                                                 "parameters": params}}


def bind(gw, tools: list[Tool]) -> list[Tool]:
    """Give each module-level handler fn(gw, s, args) access to the gateway (bank, kernel, verifier)."""
    out = []
    for t in tools:
        fn = t.fn
        out.append(Tool(t.name, t.tier, t.description, t.args, (lambda f: lambda s, a: f(gw, s, a))(fn), t.api, t.group))
    return out
