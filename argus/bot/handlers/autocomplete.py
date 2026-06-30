"""Autocomplete handler for Telegram bot."""
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton


COMMAND_SUGGESTIONS = [
    "/scan", "/help", "/investigations", "/settings",
    "/language", "/export", "/stats", "/history",
]

TARGET_TYPE_SUGGESTIONS = [
    "domain", "ip", "email", "username", "url", "phone", "image",
]


def get_suggestions(partial: str) -> list[str]:
    partial = partial.strip().lower()
    if not partial:
        return COMMAND_SUGGESTIONS[:5]
    results = [s for s in COMMAND_SUGGESTIONS if s.startswith(partial)]
    results += [s for s in TARGET_TYPE_SUGGESTIONS if s.startswith(partial)]
    return results[:5]


def build_suggestion_keyboard(suggestions: list[str]) -> ReplyKeyboardMarkup:
    keyboard = [[KeyboardButton(text=s)] for s in suggestions]
    keyboard.append([KeyboardButton(text="Cancel")])
    return ReplyKeyboardMarkup(keyboard=keyboard, resize_keyboard=True, one_time_keyboard=True)
